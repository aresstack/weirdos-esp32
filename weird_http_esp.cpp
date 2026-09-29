// ============================================================================
// weird_http_esp.cpp  --  siehe weird_http_esp.h
// ============================================================================
#include "weird_http_esp.h"
#include "weirdos_features.h"     // WEIRDOS_FEATURE_TLS_SERVER: HTTPS-Zweig von begin()
#if WEIRDOS_FEATURE_TLS_SERVER
#include <esp_https_server.h>
#endif
#include <lwip/sockets.h>
#include <lwip/inet.h>
#include <list>
#include <utility>
#include <cstring>    // memcpy (Output-Coalescing)
#include <cstdlib>    // malloc/free (Fallback)
#include <esp_heap_caps.h>   // Coalesce-Puffer in PSRAM (nicht in den knappen internen DMA-Heap)

// ---------------------------------------------------------------------------
// Methoden-Mapping + Pfad-Helfer
// ---------------------------------------------------------------------------
static HttpMethod fromEsp(int m) {
    switch (m) {
        case HTTP_POST:   return HttpMethod::POST;
        case HTTP_PUT:    return HttpMethod::PUT;
        case HTTP_PATCH:  return HttpMethod::PATCH;
        case HTTP_DELETE: return HttpMethod::DEL;
        case HTTP_GET:    return HttpMethod::GET;
        default:          return HttpMethod::ANY;
    }
}

// "/dev/camera0?x=1" -> Segmente ["dev","camera0"] (Query wird ignoriert).
static std::vector<String> splitSegs(const String& uri) {
    std::vector<String> out;
    int q = uri.indexOf('?');
    int n = (q >= 0) ? q : uri.length();
    int i = 0;
    while (i < n) {
        if (uri[i] == '/') { i++; continue; }
        int j = uri.indexOf('/', i);
        if (j < 0 || j > n) j = n;
        out.push_back(uri.substring(i, j));
        i = j;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Request / Response (nur intern)
// ---------------------------------------------------------------------------
namespace {

class EspRequest : public WeirdHttpRequest {
public:
    EspRequest(httpd_req_t* req, const std::vector<std::pair<String,String>>* params)
        : req_(req), params_(params) {}

    HttpMethod method() const override { return fromEsp(req_->method); }

    String path() const override {
        String u(req_->uri);
        int q = u.indexOf('?');
        return (q >= 0) ? u.substring(0, q) : u;
    }

    bool hasArg(const char* name) const override {
        String v;
        return queryVal(name, v) || formVal(name, v);
    }

    String arg(const char* name) const override {
        // Wie beim Arduino-WebServer: "plain" = roher Body (fuer JSON-POSTs).
        if (strcmp(name, "plain") == 0) return body();
        String v;
        if (queryVal(name, v)) return weirdHttpUrlDecode(v);
        if (formVal(name, v))  return weirdHttpUrlDecode(v);
        return String();
    }

    String pathParam(const char* name) const override {
        if (!params_) return String();
        for (const auto& p : *params_) if (p.first == name) return p.second;
        return String();
    }

    String header(const char* name) const override {
        size_t len = httpd_req_get_hdr_value_len(req_, name);
        if (len == 0) return String();
        std::vector<char> buf(len + 1);
        if (httpd_req_get_hdr_value_str(req_, name, buf.data(), len + 1) == ESP_OK)
            return String(buf.data());
        return String();
    }

    String cookie(const char* name) const override {
        return weirdHttpParseCookie(header("Cookie"), name);
    }

    String body() const override {
        if (bodyLoaded_) return body_;
        bodyLoaded_ = true;
        int remaining = req_->content_len;
        char buf[513];
        int timeouts = 0;
        while (remaining > 0) {
            int want = remaining < 512 ? remaining : 512;
            int r = httpd_req_recv(req_, buf, want);
            // WICHTIG (Contract-Bug): ein transienter Receive-Timeout ist KEIN EOF. Bei
            // break bekaeme ein normaler Form-POST (z.B. /pin-login) ueber flakiges LTE einen
            // UNVOLLSTAENDIGEN Body -> Login schlaegt fehl. -> retry (wie der Upload-Pfad).
            if (r == HTTPD_SOCK_ERR_TIMEOUT) {
                if (++timeouts > 20) break;   // ~ recv_wait_timeout*20 Deckel gegen Endlos-Hang
                continue;
            }
            if (r <= 0) break;   // 0 = Verbindung zu (EOF), <0 = echter Socketfehler
            timeouts = 0;
            buf[r] = 0;
            body_ += buf;
            remaining -= r;
        }
        return body_;
    }

    String clientIp() const override {
        int fd = httpd_req_to_sockfd(req_);
        if (fd < 0) return String();
        struct sockaddr_in6 addr;
        socklen_t len = sizeof(addr);
        if (getpeername(fd, (struct sockaddr*)&addr, &len) < 0) return String();
        char ip[48] = {0};
        if (addr.sin6_family == AF_INET6) {
            inet_ntop(AF_INET6, &addr.sin6_addr, ip, sizeof(ip));
        } else {
            struct sockaddr_in* a4 = (struct sockaddr_in*)&addr;
            inet_ntop(AF_INET, &a4->sin_addr, ip, sizeof(ip));
        }
        // LWIP-Sockets sind dual-stack -> v4-Clients kommen als v4-mapped-v6
        // ("::FFFF:1.2.3.4") an. Auf reine v4 normalisieren, damit die WAN-/Auth-
        // Pruefung (Subnetz-Vergleich) mit dem Arduino-Adapter uebereinstimmt.
        String s(ip);
        if (s.indexOf('.') >= 0) {
            int c = s.lastIndexOf(':');
            if (c >= 0) s = s.substring(c + 1);
        }
        return s;
    }

private:
    httpd_req_t* req_;
    const std::vector<std::pair<String,String>>* params_;
    mutable bool   queryLoaded_ = false;
    mutable bool   bodyLoaded_  = false;
    mutable String query_;
    mutable String body_;

    void ensureQuery() const {
        if (queryLoaded_) return;
        queryLoaded_ = true;
        size_t len = httpd_req_get_url_query_len(req_);
        if (len == 0) return;
        std::vector<char> buf(len + 1);
        if (httpd_req_get_url_query_str(req_, buf.data(), len + 1) == ESP_OK)
            query_ = String(buf.data());
    }

    bool queryVal(const char* name, String& out) const {
        ensureQuery();
        if (query_.length() == 0) return false;
        std::vector<char> buf(query_.length() + 1);
        if (httpd_query_key_value(query_.c_str(), name, buf.data(), buf.size()) == ESP_OK) {
            out = String(buf.data());
            return true;
        }
        return false;
    }

    bool isForm() const {
        return header("Content-Type").indexOf("application/x-www-form-urlencoded") >= 0;
    }

    bool formVal(const char* name, String& out) const {
        if (!isForm()) return false;
        const String& b = body();
        if (b.length() == 0) return false;
        std::vector<char> buf(b.length() + 1);
        if (httpd_query_key_value(b.c_str(), name, buf.data(), buf.size()) == ESP_OK) {
            out = String(buf.data());
            return true;
        }
        return false;
    }
};

class EspResponse : public WeirdHttpResponse {
public:
    // Coalesce-Puffer auf dem Heap (NICHT Stack -> keine zusaetzliche httpd-Stack-Last waehrend
    // des tiefen Renders). Malloc-Fehler -> obuf_==nullptr -> Fallback auf Direkt-Send pro write.
    // Puffer bewusst in PSRAM (MALLOC_CAP_SPIRAM): der interne DMA-Heap ist auf dem P4 knapp
    // und wird von USB-Host/PPP/ECM gebraucht -> HTTP-Puffer duerfen ihn NICHT unter Druck setzen
    // (sonst verhungern die Modem-DMA-Buffer -> PPP droppt). Fallback: direkt senden.
    explicit EspResponse(httpd_req_t* req) : req_(req) {
        obuf_ = (char*)heap_caps_malloc(OBUF_CAP, MALLOC_CAP_SPIRAM);
        if (!obuf_) obuf_ = (char*)malloc(OBUF_CAP);   // notfalls intern; NULL -> Direkt-Send
    }
    ~EspResponse() { if (obuf_) heap_caps_free(obuf_); }

    void header(const char* name, const String& value) override {
        httpd_resp_set_hdr(req_, keep(String(name)), keep(value));
    }

    void send(int code, const char* contentType, const String& b) override {
        httpd_resp_set_status(req_, weirdHttpStatusText(code));
        httpd_resp_set_type(req_, keep(String(contentType)));
        httpd_resp_send(req_, b.c_str(), b.length());
    }

    void redirect(const String& location, int code) override {
        httpd_resp_set_status(req_, weirdHttpStatusText(code));
        httpd_resp_set_hdr(req_, "Location", keep(location));
        httpd_resp_send(req_, NULL, 0);
    }

    bool beginChunked(int code, const char* contentType) override {
        httpd_resp_set_status(req_, weirdHttpStatusText(code));
        httpd_resp_set_type(req_, keep(String(contentType)));
        return true;
    }

    // COALESCE (Contract-Bug-Fix): die UI besteht aus HUNDERTEN kleiner w.write()-Fragmente.
    // Jedes einzeln als httpd_resp_send_chunk() zu senden = hunderte Mini-Socket-Sends ueber
    // LTE, jeder blockierend bis send_wait_timeout -> "GET braucht 15s" + lange Task-Blockade.
    // Stattdessen: kleine Fragmente in obuf_ sammeln und in ~4-KB-Chunks senden.
    bool write(const char* data, size_t len) override {
        if (len == 0) return true;   // 0-Chunk waere der Terminator -> verwerfen
        if (!obuf_) return httpd_resp_send_chunk(req_, data, len) == ESP_OK;   // Fallback ohne Puffer
        // Grosse Fragmente (PAGE_STYLE/APP_STYLE/APP_SCRIPT) direkt senden, nicht doppelt kopieren.
        if (len >= OBUF_CAP) { if (!flushBuf()) return false; return httpd_resp_send_chunk(req_, data, len) == ESP_OK; }
        if (obuf_len_ + len > OBUF_CAP) { if (!flushBuf()) return false; }
        memcpy(obuf_ + obuf_len_, data, len);
        obuf_len_ += len;
        return true;
    }

    void end() override {
        flushBuf();                                 // Rest raus VOR dem Terminator
        httpd_resp_send_chunk(req_, NULL, 0);       // 0-Chunk = Antwort abschliessen
    }

private:
    static const size_t OBUF_CAP = 4096;
    httpd_req_t* req_;
    char*        obuf_ = nullptr;
    size_t       obuf_len_ = 0;
    std::list<String> keepAlive_;   // stabile Adressen: set_status/hdr/type kopieren NICHT

    bool flushBuf() {
        if (obuf_len_ == 0) return true;
        esp_err_t e = httpd_resp_send_chunk(req_, obuf_, obuf_len_);
        obuf_len_ = 0;
        return e == ESP_OK;
    }

    const char* keep(const String& s) {
        keepAlive_.push_back(s);
        return keepAlive_.back().c_str();
    }
};

} // namespace

// ---------------------------------------------------------------------------
// Wildcard-Trampolin: EIN Handler pro Methode, eigenes Routing in dispatch().
// ---------------------------------------------------------------------------
static esp_err_t weirdHttpEspTrampoline(httpd_req_t* req) {
    WeirdHttpEsp* self = (WeirdHttpEsp*)req->user_ctx;
    return self ? self->dispatch(req) : ESP_FAIL;
}

esp_err_t WeirdHttpEsp::dispatch(httpd_req_t* req) {
    HttpMethod m = fromEsp(req->method);
    std::vector<String> pathSegs = splitSegs(String(req->uri));

    for (const auto& r : routes_) {
        if (r.method != HttpMethod::ANY && r.method != m) continue;
        if (r.segs.size() != pathSegs.size()) continue;

        std::vector<std::pair<String,String>> params;
        bool ok = true;
        for (size_t i = 0; i < r.segs.size(); ++i) {
            const String& ps = r.segs[i];
            if (ps.length() >= 2 && ps[0] == '{' && ps[ps.length() - 1] == '}') {
                params.push_back({ ps.substring(1, ps.length() - 1),
                                   weirdHttpUrlDecode(pathSegs[i]) });
            } else if (ps != pathSegs[i]) {
                ok = false;
                break;
            }
        }
        if (!ok) continue;

        if (r.isUpload) {
            // Body gestreamt an onChunk liefern (kein Vollpuffer im RAM), dann onFinish.
            EspRequest reqObj(req, &params);
            WeirdHttpUpload wu; wu.phase = UploadPhase::Start;
            r.onChunk(reqObj, wu);

            size_t total = 0; bool aborted = false;
            char buf[1024];
            int remaining = req->content_len;
            int timeouts = 0;
            while (remaining > 0) {
                int want = remaining < (int)sizeof(buf) ? remaining : (int)sizeof(buf);
                int rlen = httpd_req_recv(req, buf, want);
                if (rlen == HTTPD_SOCK_ERR_TIMEOUT) {
                    // Transienter Timeout ist kein EOF (flakiges LTE) -> erneut versuchen, aber mit
                    // demselben Deckel wie body(): sonst haelt ein Client mit grossem Content-Length
                    // und ohne Daten den Management-Server beliebig lange (Slowloris) -- und das
                    // VOR jeder Authentifizierung, weil Upload-Routen selbst im Start-Chunk pruefen.
                    if (++timeouts > 20) { aborted = true; break; }   // ~ recv_wait_timeout*20
                    continue;
                }
                if (rlen <= 0) { aborted = true; break; }        // 0 = geschlossen, <0 = echter Fehler
                WeirdHttpUpload w; w.phase = UploadPhase::Write;
                w.data = (const uint8_t*)buf; w.len = (size_t)rlen;
                r.onChunk(reqObj, w);
                total += (size_t)rlen; remaining -= rlen;
            }
            WeirdHttpUpload we;
            we.phase = aborted ? UploadPhase::Abort : UploadPhase::End; we.total = total;
            r.onChunk(reqObj, we);

            EspResponse resObj(req);
            r.onFinish(reqObj, resObj);
            return ESP_OK;
        }

        EspRequest  reqObj(req, &params);
        EspResponse resObj(req);
        r.handler(reqObj, resObj);
        return ESP_OK;
    }

    EspRequest  reqObj(req, nullptr);
    EspResponse resObj(req);
    if (notFound_) notFound_(reqObj, resObj);
    else resObj.send(404, "text/plain", "Not Found");
    return ESP_OK;
}

// ---------------------------------------------------------------------------
// Routing-Registrierung + Lebenszyklus
// ---------------------------------------------------------------------------
void WeirdHttpEsp::route(HttpMethod method, const char* pattern, WeirdHttpHandler handler) {
    Route r;
    r.method  = method;
    r.segs    = splitSegs(String(pattern));
    r.handler = handler;
    routes_.push_back(r);
}

void WeirdHttpEsp::routeUpload(HttpMethod method, const char* pattern,
                              WeirdHttpUploadHandler onChunk, WeirdHttpHandler onFinish) {
    Route r;
    r.method   = method;
    r.segs     = splitSegs(String(pattern));
    r.isUpload = true;
    r.onChunk  = onChunk;
    r.onFinish = onFinish;
    routes_.push_back(r);
}

void WeirdHttpEsp::onNotFound(WeirdHttpHandler handler) {
    notFound_ = handler;
}

void WeirdHttpEsp::registerWildcards() {
    // Ein Wildcard-Handler pro HTTP-Methode; das eigene dispatch() macht das
    // Feinrouting. Alle registrieren (nicht genutzte Methoden landen in 404).
    const httpd_method_t methods[] = { HTTP_GET, HTTP_POST, HTTP_PUT, HTTP_PATCH, HTTP_DELETE };
    for (httpd_method_t hm : methods) {
        httpd_uri_t u = {};
        u.uri      = "/*";
        u.method   = hm;
        u.handler  = weirdHttpEspTrampoline;
        u.user_ctx = this;
        httpd_register_uri_handler(handle_, &u);
    }
}

void WeirdHttpEsp::begin() {
    if (handle_) return;

#if !WEIRDOS_FEATURE_TLS_SERVER
    // Baustein TLS_SERVER abgewaehlt: kein esp_https_server im Image. configure(443, true) ist dann
    // ein Konfigurationsfehler, kein Startfehler -- running() bleibt false, lastError_ nennt es, und
    // die .ino faellt wie bei jedem HTTPS-Fehlstart auf HTTP:80 zurueck (Zugang nie verlieren).
    if (tls_) { lastError_ = ESP_ERR_NOT_SUPPORTED; handle_ = nullptr; return; }
    if (false) {
#else
    if (tls_) {
        httpd_ssl_config_t c = HTTPD_SSL_CONFIG_DEFAULT();
        c.servercert     = (const uint8_t*)certPem_.c_str();
        c.servercert_len = certPem_.length() + 1;
        c.prvtkey_pem    = (const uint8_t*)keyPem_.c_str();
        c.prvtkey_len    = keyPem_.length() + 1;
        c.port_secure    = port_;
        c.httpd.uri_match_fn     = httpd_uri_match_wildcard;
        c.httpd.max_uri_handlers = 12;
        c.httpd.max_open_sockets = maxSockets_;
        c.httpd.stack_size       = 20480;   // TLS-Handshake + tiefer App-Render
        // Stack bleibt intern (KEIN PSRAM): dieselben Management-Handler (NVS/Preferences/OTA) laufen
        // auch hier -> PSRAM-Stack + Flash-cache-off = Crash. Siehe HTTP-Zweig / Issue #8.
        c.httpd.send_wait_timeout = 10;     // grosse App-Seite ueber (flakiges) LTE
        c.httpd.recv_wait_timeout = 10;
        // Prioritaet STRIKT UNTER den Echtzeit-Modem/USB/ECM/PPP-Tasks (Prio 5-6), damit
        // HTTP-Last sie nie verdraengt -- aber NICHT bis auf 1 (das verhungerte HTTP selbst).
        // Prio 4 = unter Modem (5), ueber loopTask (1). Kein Core-Pinning (Scheduler nutzt den
        // freien Kern; Core 0 + Prio 1 hatte HTTP durch die lwIP/System-Tasks ausgehungert).
        c.httpd.task_priority    = 4;
        c.httpd.ctrl_port        = ctrlPort_ ? ctrlPort_ : 32769;   // Mgmt-HTTPS interner UDP-Control-Port (Belegung: Mgmt 32768/9, Video 32770/1, Port-80-Hilfsserver 32772)
        if (stackSize_) c.httpd.stack_size = stackSize_;
        c.httpd.lru_purge_enable = true;
        lastError_ = httpd_ssl_start(&handle_, &c);
        if (lastError_ != ESP_OK) { handle_ = nullptr; return; }
#endif // WEIRDOS_FEATURE_TLS_SERVER
    } else {
        httpd_config_t c = HTTPD_DEFAULT_CONFIG();
        c.server_port      = port_;
        c.uri_match_fn     = httpd_uri_match_wildcard;
        c.max_uri_handlers = 12;
        c.max_open_sockets = maxSockets_;
        // KRITISCH: der esp_http_server-Handler laeuft in der httpd-Task, NICHT im
        // Arduino-loopTask (8192). Der Default-Stack 4096 laeuft beim tiefen App-Render
        // (sendAppPage -> Menue + 15 String-lastige Renderer) ueber -> die Antwort bricht
        // mitten im Chunked-Stream ab (kein end()/Terminator) -> weisse Seite, laedt endlos.
        // Die flache PIN-Gate passt noch in 4096, die App-Seite nicht. 10240 rendert die
        // Uebersicht, crasht aber offenbar in einem tieferen Renderer -> 16384 als Reserve
        // (der httpstage-Marker zeigt, ob es der Stack war: stage 99 = voll gerendert).
        c.stack_size       = 16384;
        // ACHTUNG: Stack NICHT nach PSRAM (task_caps). Dieser Management-Task fuehrt NVS-/Preferences-
        // Schreibvorgaenge und OTA aus. Bei Flash erase/write ist der Flash-Cache aus -> PSRAM ist
        // dann NICHT adressierbar -> ein PSRAM-Stack crasht mitten im Settings-Speichern/OTA. Stack
        // bleibt intern. (Rueckgewinn der 16 KB erst, wenn Flash/NVS/OTA auf einen dedizierten
        // Internal-Worker/Command-Queue ausgelagert sind -> Issue #8.)
        c.send_wait_timeout = 10;   // grosse App-Seite ueber (flakiges) LTE -> mehr Luft pro Chunk-Send
        c.recv_wait_timeout = 10;
        // Prioritaet STRIKT UNTER den Echtzeit-Modem/USB/ECM/PPP-Tasks (Prio 5-6), damit
        // schwerer HTTP-Load (App-Render, ~6 Poller/3s) sie nie verdraengt -> LTE bleibt stabil.
        // ABER nicht bis auf 1 (Core 0 + Prio 1 verhungerte HTTP selbst durch lwIP/System-Tasks:
        // POST /pin-login haengte, GET langsam). Prio 4 = unter Modem (5), ueber loopTask (1),
        // ohne Core-Pinning (Scheduler nutzt den freien Kern). Restauriert "HTTP unter Modem".
        c.task_priority    = 4;
        c.ctrl_port        = ctrlPort_ ? ctrlPort_ : 32768;   // Mgmt-HTTP interner UDP-Control-Port (Video 32770/1, Port-80-Hilfsserver 32772)
        if (stackSize_) c.stack_size = stackSize_;
        c.lru_purge_enable = true;
        lastError_ = httpd_start(&handle_, &c);
        if (lastError_ != ESP_OK) { handle_ = nullptr; return; }
    }

    registerWildcards();
}
