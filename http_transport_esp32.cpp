// ============================================================================
// http_transport_esp32.cpp -- ESP32/lwIP/mbedTLS-Implementierung des HttpTransport.
//
// Kern von Issue #6: eigener Socket, an die lokale IPv4 des gewaehlten Interface
// gebunden (bind), dann connect + mbedTLS ueber genau diesen fd. Nach dem bind()
// haengt die Quell-IP NICHT mehr an netif_default. KEIN esp_http_client/if_name,
// KEIN WiFiClientSecure als Transport, KEIN globales netif_set_default() als Bindung.
// TLS ist insecure (VERIFY_NONE) - Verhalten wie der bisherige DynDNS-Pfad; eine
// echte Zertifikats-Policy ist bewusst NICHT Teil dieser Stufe.
// ============================================================================
#include "weirdos_features.h"      // WEIRDOS_FEATURE_TLS_CLIENT -- der Schalter dieses Bausteins
#include "http_transport.h"   // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
#if WEIRDOS_FEATURE_TLS_CLIENT
// ============================================================================
// Echte Implementierung (WEIRDOS_FEATURE_TLS_CLIENT=1) -- interface-gebundener HTTPS-Client (mbedTLS, Root-Bundle)
// ============================================================================

#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <errno.h>

#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/inet.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/platform.h"   // 7.9.13: mbedtls_platform_set_calloc_free (Laufzeit-Allocator-Hook)
#include "mbedtls/x509_crt.h"   // mbedtls_x509_crt_verify_info (Klartext bei TLS-Pruef-Fehlern)
#include "esp_crt_bundle.h"     // esp_crt_bundle_attach: Root-CA-Bundle fuer verifyTls (ACME)
#include "esp_heap_caps.h"
#if __has_include(<psa/crypto.h>)
#include <psa/crypto.h>
#define WEIRDOS_HAS_PSA 1
#endif

namespace {

// 7.9.13: mbedTLS-Allocator zur Laufzeit auf PSRAM umlenken (kein Rebuild noetig). Der
// Arduino-Build ist CONFIG_MBEDTLS_INTERNAL_MEM_ALLOC + symmetrisch 2x16k -> ssl_setup
// braucht zwei ~16k-Bloecke AM STUECK im internen Heap. Bei Fragmentierung (z.B. 55k frei,
// groesster Block <32k) scheitert es mit ALLOC_FAILED (-32512) -> DynDNS-Update zieht nach
// Mobil-IP-Wechsel nicht. MBEDTLS_PLATFORM_MEMORY ist im ESP-Port definiert (esp_config.h),
// also duerfen wir mbedtls_calloc/-free zur Laufzeit ersetzen. Die grossen TLS-Recordbuffer
// gehen so in den PSRAM (CONFIG_SPIRAM_USE_MALLOC=y, ~7 MB frei, grosser Block); der knappe
// interne RAM bleibt fuer WireGuard/USB/lwIP. TLS hier ist weder zeit- noch durchsatz-
// kritisch (DynDNS = 1 kleiner GET), PSRAM-Latenz also egal. Fallback: intern, falls PSRAM leer.
void* tlsPsramCalloc(size_t n, size_t size) {
    void* p = heap_caps_calloc(n, size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!p) p = heap_caps_calloc(n, size, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    return p;
}
void tlsPsramFree(void* p) { heap_caps_free(p); }   // heap_caps_free bedient beide Regionen

struct ParsedUrl { String host; String path; int port; bool https; bool ok; };

ParsedUrl parseUrl(const String& url) {
    ParsedUrl p; p.port = 443; p.https = true; p.ok = false;
    String rest;
    if (url.startsWith("https://"))      { rest = url.substring(8); p.https = true;  p.port = 443; }
    else if (url.startsWith("http://"))  { rest = url.substring(7); p.https = false; p.port = 80;  }
    else return p;                       // nur http(s)
    int slash = rest.indexOf('/');
    String hostport = (slash < 0) ? rest : rest.substring(0, slash);
    p.path = (slash < 0) ? String("/") : rest.substring(slash);
    int colon = hostport.indexOf(':');
    if (colon < 0) { p.host = hostport; }
    else { p.host = hostport.substring(0, colon); p.port = hostport.substring(colon + 1).toInt(); }
    p.ok = p.host.length() > 0;
    return p;
}

// Socket erstellen, an egressIp binden, mit Timeout zu (remote) verbinden.
// Rueckgabe: fd >= 0 bei Erfolg; sonst -1 und err gesetzt.
int connectBound(const String& host, int port, const String& egressIp, String& err) {
    struct addrinfo hints; memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* ai = nullptr;
    char portbuf[8]; snprintf(portbuf, sizeof(portbuf), "%d", port);
    if (getaddrinfo(host.c_str(), portbuf, &hints, &ai) != 0 || !ai) { err = "DNS fehlgeschlagen"; return -1; }

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) { freeaddrinfo(ai); err = "socket()"; return -1; }

    struct timeval tv; tv.tv_sec = 8; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // *** Bindung an die lokale IPv4 des gewaehlten Interface ***
    struct sockaddr_in local; memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET; local.sin_port = 0;
    local.sin_addr.s_addr = inet_addr(egressIp.c_str());
    if (local.sin_addr.s_addr == 0 || local.sin_addr.s_addr == INADDR_NONE) {
        close(fd); freeaddrinfo(ai); err = "ungueltige Bind-IP " + egressIp; return -1;
    }
    if (bind(fd, (struct sockaddr*)&local, sizeof(local)) != 0) {
        close(fd); freeaddrinfo(ai); err = "bind(" + egressIp + ") errno " + String(errno); return -1;
    }

    // Non-blocking connect mit 8s-Timeout, danach zurueck auf blocking (fuer mbedTLS).
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int cr = connect(fd, ai->ai_addr, ai->ai_addrlen);
    freeaddrinfo(ai);
    if (cr < 0 && errno != EINPROGRESS) { close(fd); err = "connect errno " + String(errno); return -1; }
    if (cr < 0) {
        fd_set wset; FD_ZERO(&wset); FD_SET(fd, &wset);
        struct timeval ctv; ctv.tv_sec = 8; ctv.tv_usec = 0;
        int sr = select(fd + 1, nullptr, &wset, nullptr, &ctv);
        if (sr <= 0) { close(fd); err = "connect Timeout"; return -1; }
        int soerr = 0; socklen_t sl = sizeof(soerr);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
        if (soerr != 0) { close(fd); err = "connect SO_ERROR " + String(soerr); return -1; }
    }
    fcntl(fd, F_SETFL, flags);   // zurueck auf blocking
    return fd;
}

// Header-Wert (case-insensitiv) aus dem Header-Block holen; "" wenn nicht vorhanden.
String headerValue(const String& hdrs, const char* name) {
    String low = hdrs; low.toLowerCase();
    String key = String(name); key.toLowerCase(); key = "\r\n" + key + ":";
    int p = low.indexOf(key);
    if (p < 0) return String();
    int vs = p + key.length();
    int ve = low.indexOf("\r\n", vs);
    if (ve < 0) ve = hdrs.length();
    String v = hdrs.substring(vs, ve); v.trim();
    return v;
}

// "Transfer-Encoding: chunked" aufloesen (Groesse hex CRLF Daten CRLF ... 0 CRLF).
String dechunk(const String& in) {
    String out; out.reserve(in.length());
    size_t pos = 0, n = in.length();
    while (pos < n) {
        int eol = in.indexOf("\r\n", pos);
        if (eol < 0) break;
        long sz = strtol(in.substring(pos, eol).c_str(), nullptr, 16);
        if (sz <= 0) break;
        size_t ds = (size_t)eol + 2;
        if (ds + (size_t)sz > n) { out += in.substring(ds); break; }
        out += in.substring(ds, ds + (size_t)sz);
        pos = ds + (size_t)sz + 2;
    }
    return out;
}

// HTTP-Anfrage (GET/POST/HEAD) ueber eine bereits verbundene Verbindung (read/write per
// Funktionszeiger), Antwort in raw sammeln (bis Verbindungsende/Timeout, begrenzt), Status +
// ausgewaehlte Header + Body (chunked aufgeloest) fuellen.
void httpRequestOver(const String& host, const String& path, const HttpRequest& req,
                     int (*wr)(void*, const uint8_t*, size_t),
                     int (*rd)(void*, uint8_t*, size_t),
                     void* ctx, HttpResponse& res) {
    String method = req.method.length() ? req.method : String("GET");
    String reqStr = method + " " + path + " HTTP/1.1\r\nHost: " + host +
                    "\r\nUser-Agent: WeirdOS-Egress/1\r\nConnection: close\r\n";
    if (req.accept.length()) reqStr += "Accept: " + req.accept + "\r\n";
    if (req.body.length()) {
        reqStr += "Content-Type: " + (req.contentType.length() ? req.contentType : String("application/octet-stream")) + "\r\n";
        reqStr += "Content-Length: " + String(req.body.length()) + "\r\n";
    }
    reqStr += "\r\n";
    reqStr += req.body;
    const uint8_t* p = (const uint8_t*)reqStr.c_str();
    size_t total = reqStr.length(), sent = 0;
    while (sent < total) {
        int w = wr(ctx, p + sent, total - sent);
        if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (w <= 0) { res.error = "write"; return; }
        sent += (size_t)w;
    }
    String raw; raw.reserve(2048);
    uint8_t buf[512];
    size_t cap = req.maxBody + 2048;   // + Header-Block
    for (int guard = 0; guard < 512; guard++) {
        int r = rd(ctx, buf, sizeof(buf));
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (r <= 0) break;   // close_notify / peer close / Timeout / Fehler
        for (int i = 0; i < r; i++) raw += (char)buf[i];
        if (raw.length() > cap) break;
    }
    int sp = raw.indexOf(' ');
    if (sp > 0) res.status = raw.substring(sp + 1, sp + 4).toInt();
    int hdrEnd = raw.indexOf("\r\n\r\n");
    String hdrs = (hdrEnd >= 0) ? raw.substring(0, hdrEnd) : raw;
    res.replayNonce = headerValue(hdrs, "Replay-Nonce");
    res.location    = headerValue(hdrs, "Location");
    res.contentType = headerValue(hdrs, "Content-Type");
    res.retryAfter  = headerValue(hdrs, "Retry-After");
    String body = (hdrEnd >= 0) ? raw.substring(hdrEnd + 4) : String("");
    String te = headerValue(hdrs, "Transfer-Encoding"); te.toLowerCase();
    if (te.indexOf("chunked") >= 0) body = dechunk(body);
    res.body = body;
    res.body.trim();
}

// BIO-Adapter fuer mbedTLS ueber unseren fd.
int tlsWrite(void* ssl, const uint8_t* b, size_t l) { return mbedtls_ssl_write((mbedtls_ssl_context*)ssl, b, l); }
int tlsRead (void* ssl, uint8_t* b, size_t l)       { return mbedtls_ssl_read ((mbedtls_ssl_context*)ssl, b, l); }
int rawWrite(void* fd, const uint8_t* b, size_t l)  { return send(*(int*)fd, b, l, 0); }
int rawRead (void* fd, uint8_t* b, size_t l)        { int r = recv(*(int*)fd, b, l, 0); return r; }

class Esp32BoundHttpTransport : public HttpTransport {
public:
    HttpResponse get(const HttpRequest& req) override {
        HttpRequest g = req; g.method = "GET"; g.body = ""; return request(g);
    }
    HttpResponse request(const HttpRequest& req) override {
        HttpResponse res;
        if (!req.egress || req.egress->ip.length() == 0) { res.error = "egress ohne lokale IP"; return res; }

        ParsedUrl u = parseUrl(req.url);
        if (!u.ok) { res.error = "URL ungueltig"; return res; }

        String err;
        int fd = connectBound(u.host, u.port, req.egress->ip, err);
        if (fd < 0) { res.error = err; return res; }

        if (!u.https) {                       // Klartext (fuer diese Stufe nicht genutzt, aber sauber)
            httpRequestOver(u.host, u.path, req, rawWrite, rawRead, &fd, res);
            close(fd);
            return res;
        }

        // ---- mbedTLS ueber den gebundenen fd (insecure, wie bisher) ----
#ifdef WEIRDOS_HAS_PSA
        // PSA nur EINMAL initialisieren - pro-Request-Init leakt PSA-State (Heap sinkt,
        // ssl_setup schlaegt dann mit ALLOC_FAILED fehl). Wie der WiFi/TLS-Stack: 1x global.
        static bool s_psaInit = false;
        if (!s_psaInit) { psa_crypto_init(); s_psaInit = true; }
#endif
        mbedtls_ssl_context ssl; mbedtls_ssl_config conf;
        mbedtls_ctr_drbg_context drbg; mbedtls_entropy_context entropy;
        mbedtls_net_context net; net.fd = fd;
        mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&conf);
        mbedtls_ctr_drbg_init(&drbg); mbedtls_entropy_init(&entropy);

        bool tlsUp = false;
        int rc;
        do {
            const char* pers = "weirdos-egress";
            if ((rc = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                      (const unsigned char*)pers, strlen(pers))) != 0) { res.error = "drbg_seed " + String(rc); break; }
            if ((rc = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                            MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) { res.error = "config " + String(rc); break; }
            if (req.verifyTls) {
                // Echte Pruefung gegen das IDF-Root-CA-Bundle (CONFIG_MBEDTLS_CERTIFICATE_BUNDLE). Braucht
                // eine gueltige Systemzeit (modem_clock) -- sonst scheitert die Gueltigkeitspruefung.
                if ((rc = esp_crt_bundle_attach(&conf)) != 0) { res.error = "crt_bundle " + String(rc); break; }
                mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
            } else {
                mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);   // insecure - wie bisheriger DynDNS-Pfad
            }
            mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
            if ((rc = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
                res.error = "ssl_setup " + String(rc) + " heapInt " +
                    String((unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024)) + "k largest " +
                    String((unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) / 1024)) + "k";
                break;
            }
            if ((rc = mbedtls_ssl_set_hostname(&ssl, u.host.c_str())) != 0) { res.error = "SNI " + String(rc); break; }  // SNI = Original-Host
            mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, nullptr);

            int hs;
            while ((hs = mbedtls_ssl_handshake(&ssl)) != 0) {
                if (hs != MBEDTLS_ERR_SSL_WANT_READ && hs != MBEDTLS_ERR_SSL_WANT_WRITE) break;
            }
            if (hs != 0) { res.error = "tls_handshake " + String(hs); break; }
            tlsUp = true;
        } while (false);

        if (tlsUp) httpRequestOver(u.host, u.path, req, tlsWrite, tlsRead, &ssl, res);
        else if (req.verifyTls && res.error.startsWith("tls_handshake")) {
            uint32_t vf = mbedtls_ssl_get_verify_result(&ssl);
            if (vf) {   // Klartext-Grund fuer den Nutzer (z.B. Uhr falsch -> "expired"/"future")
                char vb[160]; mbedtls_x509_crt_verify_info(vb, sizeof(vb), "", vf);
                res.error += String(" verify: ") + vb;
            }
        }

        if (tlsUp) mbedtls_ssl_close_notify(&ssl);
        mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&drbg); mbedtls_entropy_free(&entropy);
        close(fd);
        return res;
    }
};

Esp32BoundHttpTransport g_transport;

// Per-Request-Worker (Stack nur waehrend des Aufrufs belegt). Ein PERSISTENTER Task
// wuerde 16k internen RAM dauerhaft binden und heapmin gefaehrlich druecken; der
// interne RAM ist hier ohnehin knapp (mbedTLS-Puffer = 2x16k, CONFIG_MBEDTLS_INTERNAL_
// MEM_ALLOC). Stack muss internal sein (PSRAM-Stacks im Build nicht erlaubt).
struct TaskCtx { const HttpRequest* req; HttpResponse res; SemaphoreHandle_t done; };

void transportTask(void* arg) {
    TaskCtx* c = (TaskCtx*)arg;
    c->res = g_transport.get(*c->req);
    xSemaphoreGive(c->done);
    vTaskDelete(nullptr);
}

}  // namespace

HttpTransport& esp32BoundHttpTransport() { return g_transport; }

void esp32BoundHttpTransportBegin() { /* nichts vorzuhalten - per-Request-Task */ }

// 7.9.14: Plattform-Speicher-Policy fuer mbedTLS. Der Hook mbedtls_platform_set_calloc_free()
// ist GLOBAL (nicht auf diesen Transport begrenzt) und wirkt fuer JEDEN mbedTLS-Nutzer -
// inkl. der kleinen Entropy/DRBG-Allocations, die auch der WireGuard-RNG (curve25519-Seed)
// ueber mbedTLS zieht. Das ist gewollt: auf dem S3 sind gerade die mbedTLS-Sachen die
// schlechtesten Kandidaten fuer den knappen internen RAM. Daher bewusst ALLES nach PSRAM
// (kein size-aware Hybrid) - ein Speicher-Backend pro Boot. usePsram=false laesst den
// Standard-Allocator (intern) unveraendert -> spaeter P4 kann per Schalter intern bleiben.
// Muss VOR jedem mbedTLS-Aufruf laufen (frueh in setup); kein Umschalten im Betrieb.
void esp32ApplyCryptoMemoryPolicy(bool usePsram) {
    if (usePsram && psramFound()) {
        int rc = mbedtls_platform_set_calloc_free(tlsPsramCalloc, tlsPsramFree);
        Serial.printf("[TLS] mbedtls-Speicher -> PSRAM: %s\n", rc == 0 ? "ok" : "FEHLER (bleibt intern)");
    } else {
        Serial.printf("[TLS] mbedtls-Speicher -> INTERNAL%s\n",
                      usePsram ? " (kein PSRAM gefunden)" : " (per Schalter)");
    }
}

HttpResponse esp32BoundHttpGet(const HttpRequest& req) {
    TaskCtx c; c.req = &req; c.done = xSemaphoreCreateBinary();
    if (!c.done) { HttpResponse e; e.error = "sem"; return e; }
    if (xTaskCreatePinnedToCore(transportTask, "egress_tx", 12288, &c, 5, nullptr, 1) != pdPASS) {
        vSemaphoreDelete(c.done); HttpResponse e; e.error = "task"; return e;
    }
    xSemaphoreTake(c.done, portMAX_DELAY);   // jeder Netzwerk-Schritt hat Timeouts -> Task endet garantiert
    vSemaphoreDelete(c.done);
    return c.res;
}
#else
// ============================================================================
// Stub (WEIRDOS_FEATURE_TLS_CLIENT=0): kein interface-gebundener HTTP(S)-Client im Build -- kein
// mbedTLS-Client-Kontext, kein Root-CA-Bundle, kein Worker-Task. Jede Header-Funktion bleibt
// definiert (ACME und DYNDNS brauchen TLS_CLIENT laut Regel; die Ipify-Diagnose in der .ino
// bekommt eine ehrliche Fehlerantwort).
// ============================================================================
namespace {
const char* kHttpClientNotBuilt = "HTTPS-Client nicht im Build enthalten (WEIRDOS_FEATURE_TLS_CLIENT=0)";
class StubHttpTransport : public HttpTransport {
public:
    HttpResponse get(const HttpRequest& req) override {
        (void)req;
        HttpResponse r; r.status = 0; r.error = kHttpClientNotBuilt;
        return r;
    }
};
StubHttpTransport s_stubTransport;
}  // namespace
HttpTransport& esp32BoundHttpTransport() { return s_stubTransport; }
void esp32BoundHttpTransportBegin() {}
void esp32ApplyCryptoMemoryPolicy(bool usePsram) { (void)usePsram; }
HttpResponse esp32BoundHttpGet(const HttpRequest& req) { return s_stubTransport.get(req); }
#endif // WEIRDOS_FEATURE_TLS_CLIENT
