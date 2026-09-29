// ============================================================================
// acme_client.cpp -- siehe acme_client.h. RFC 8555, JWS ES256, HTTP-01.
// ============================================================================
#include "weirdos_features.h"      // WEIRDOS_FEATURE_ACME -- der Schalter dieses Bausteins
#include "acme_client.h"            // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
#if WEIRDOS_FEATURE_ACME
// ============================================================================
// Echte Implementierung (WEIRDOS_FEATURE_ACME=1)
// ============================================================================
#include "http_transport.h"
#include "network_registry.h"
#include "modem_clock.h"
#include <Preferences.h>
#include <cstring>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"

static const char* kNs = "acme";
static const char* kDirProd    = "https://acme-v02.api.letsencrypt.org/directory";
static const char* kDirStaging = "https://acme-staging-v02.api.letsencrypt.org/directory";

static AcmeConfig s_cfg;
static String     s_certPem, s_keyPem, s_accountKeyPem, s_accountUrl;
static time_t     s_notAfter = 0;
static String     s_subject;
static volatile bool s_running = false;
static bool       s_lastOk = false;
static String     s_lastError, s_state = "bereit";
static uint32_t   s_lastRunMs = 0;
static bool       s_restartPending = false;
static uint32_t   s_lastTickCheckMs = 0;
static uint32_t   s_lastAutoAttemptMs = 0;
// HTTP-01-Responder (ein Token zur Zeit)
static String     s_chalToken, s_chalKeyAuth;

// ---------------------------------------------------------------------------
// Helfer: base64url, JSON-Minimalparser, Fehlertext
// ---------------------------------------------------------------------------
static String b64url(const uint8_t* d, size_t n) {
    size_t olen = 0;
    mbedtls_base64_encode(nullptr, 0, &olen, d, n);
    String out; uint8_t* buf = (uint8_t*)malloc(olen + 1);
    if (!buf) return out;
    if (mbedtls_base64_encode(buf, olen + 1, &olen, d, n) == 0) {
        for (size_t i = 0; i < olen; i++) {
            char c = (char)buf[i];
            if (c == '+') c = '-'; else if (c == '/') c = '_'; else if (c == '=') continue;
            out += c;
        }
    }
    free(buf);
    return out;
}
static String b64url(const String& s) { return b64url((const uint8_t*)s.c_str(), s.length()); }

// Wert eines String-Feldes "key":"..." ab Position from; "" wenn nicht vorhanden.
static String jsonStr(const String& body, const char* key, int from = 0) {
    String k = String("\"") + key + "\"";
    int p = body.indexOf(k, from);
    if (p < 0) return String();
    int c = body.indexOf(':', p + k.length());
    if (c < 0) return String();
    int q1 = body.indexOf('"', c + 1);
    if (q1 < 0) return String();
    int q2 = q1 + 1;
    while (q2 < (int)body.length() && !(body[q2] == '"' && body[q2 - 1] != '\\')) q2++;
    return body.substring(q1 + 1, q2);
}
static String mbedErr(int rc) {
    char eb[96]; mbedtls_strerror(rc, eb, sizeof(eb));
    return String("-0x") + String((unsigned)(-rc), HEX) + " " + eb;
}
static void setState(const String& s) { s_state = s; Serial.println("[ACME] " + s); }

// ---------------------------------------------------------------------------
// NVS
// ---------------------------------------------------------------------------
static String nvsGetBlob(Preferences& p, const char* key) {
    size_t n = p.getBytesLength(key);
    if (n == 0) return String();
    char* b = (char*)malloc(n + 1);
    if (!b) return String();
    p.getBytes(key, b, n); b[n] = 0;
    String s(b); free(b); return s;
}
static void nvsPutBlob(Preferences& p, const char* key, const String& v) {
    if (v.length()) p.putBytes(key, v.c_str(), v.length()); else p.remove(key);
}

static bool parseCertInfo(const String& pem, time_t& notAfter, String& subject) {
    notAfter = 0; subject = "";
    if (pem.length() == 0) return false;
    mbedtls_x509_crt crt; mbedtls_x509_crt_init(&crt);
    int rc = mbedtls_x509_crt_parse(&crt, (const unsigned char*)pem.c_str(), pem.length() + 1);
    if (rc != 0) { mbedtls_x509_crt_free(&crt); return false; }
    // erstes Zertifikat der Kette = Leaf
    struct tm t = {};
    t.tm_year = crt.valid_to.year - 1900; t.tm_mon = crt.valid_to.mon - 1; t.tm_mday = crt.valid_to.day;
    t.tm_hour = crt.valid_to.hour; t.tm_min = crt.valid_to.min; t.tm_sec = crt.valid_to.sec;
    // timegm ohne libc-Abhaengigkeit: mktime rechnet Ortszeit -- Geraet laeuft auf UTC (kein TZ gesetzt)
    notAfter = mktime(&t);
    char dn[128]; if (mbedtls_x509_dn_gets(dn, sizeof(dn), &crt.subject) > 0) subject = dn;
    mbedtls_x509_crt_free(&crt);
    return true;
}

void acmeLoad() {
    Preferences p; p.begin(kNs, true);
    s_cfg.enabled = p.getBool("en", false);
    s_cfg.domain  = p.getString("dom", "");
    s_cfg.email   = p.getString("mail", "");
    s_cfg.staging = p.getBool("stg", false);
    s_cfg.tos     = p.getBool("tos", false);
    s_accountKeyPem = nvsGetBlob(p, "acckey");
    s_accountUrl    = p.getString("accurl", "");
    s_certPem = nvsGetBlob(p, "cert");
    s_keyPem  = nvsGetBlob(p, "key");
    p.end();
    parseCertInfo(s_certPem, s_notAfter, s_subject);
    Serial.printf("[ACME] Config: %s, Domain '%s', %s; Zertifikat: %s%s\n",
                  s_cfg.enabled ? "AN" : "aus", s_cfg.domain.c_str(), s_cfg.staging ? "Staging" : "Produktion",
                  s_certPem.length() ? "vorhanden" : "keins", s_subject.length() ? (" (" + s_subject + ")").c_str() : "");
}
const AcmeConfig& acmeConfig() { return s_cfg; }
void acmeSaveConfig(const AcmeConfig& c) {
    s_cfg = c;
    Preferences p; p.begin(kNs, false);
    p.putBool("en", c.enabled); p.putString("dom", c.domain); p.putString("mail", c.email);
    p.putBool("stg", c.staging); p.putBool("tos", c.tos);
    p.end();
}
bool   acmeHasCert()        { return s_certPem.length() > 0 && s_keyPem.length() > 0; }
const String& acmeCertPem() { return s_certPem; }
const String& acmeKeyPem()  { return s_keyPem; }
time_t acmeCertNotAfter()   { return s_notAfter; }
String acmeCertSubject()    { return s_subject; }
bool acmeCertUsable() {
    if (!acmeHasCert()) return false;
    if (s_cfg.domain.length() && s_subject.indexOf(s_cfg.domain) < 0) return false;   // Domain gewechselt
    if (systemClockValid() && s_notAfter && time(nullptr) > s_notAfter) return false;  // abgelaufen
    return true;
}
void acmeClearCert() {
    Preferences p; p.begin(kNs, false); p.remove("cert"); p.remove("key"); p.end();
    s_certPem = ""; s_keyPem = ""; s_notAfter = 0; s_subject = "";
}
bool acmeRunning()        { return s_running; }
String acmeStateText()    { return s_state; }
String acmeLastError()    { return s_lastError; }
bool acmeLastOk()         { return s_lastOk; }
uint32_t acmeLastRunMs()  { return s_lastRunMs; }
bool acmeRestartPending() { return s_restartPending; }
bool acmeChallengeLookup(const String& token, String& keyAuthOut) {
    if (s_chalToken.length() == 0 || token != s_chalToken) return false;
    keyAuthOut = s_chalKeyAuth; return true;
}

// ---------------------------------------------------------------------------
// Krypto: Schluessel, JWK, Thumbprint, ES256-Signatur
// ---------------------------------------------------------------------------
struct Rng {
    mbedtls_entropy_context entropy; mbedtls_ctr_drbg_context drbg; bool ok = false;
    Rng() {
        mbedtls_entropy_init(&entropy); mbedtls_ctr_drbg_init(&drbg);
        const char* pers = "weirdos-acme";
        ok = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers)) == 0;
    }
    ~Rng() { mbedtls_ctr_drbg_free(&drbg); mbedtls_entropy_free(&entropy); }
};

static bool genP256Pem(Rng& rng, String& pemOut, String& err) {
    mbedtls_pk_context k; mbedtls_pk_init(&k);
    int rc = mbedtls_pk_setup(&k, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (rc == 0) rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(k), mbedtls_ctr_drbg_random, &rng.drbg);
    unsigned char buf[512];
    if (rc == 0) rc = mbedtls_pk_write_key_pem(&k, buf, sizeof(buf));
    if (rc == 0) pemOut = String((const char*)buf); else err = "Schluessel: " + mbedErr(rc);
    mbedtls_pk_free(&k);
    return rc == 0;
}

static bool loadKey(Rng& rng, mbedtls_pk_context& k, const String& pem, String& err) {
    int rc = mbedtls_pk_parse_key(&k, (const unsigned char*)pem.c_str(), pem.length() + 1, nullptr, 0,
                                  mbedtls_ctr_drbg_random, &rng.drbg);
    if (rc != 0) err = "Schluessel laden: " + mbedErr(rc);
    return rc == 0;
}

// JWK (nur x/y, kanonische Reihenfolge crv,kty,x,y fuer den Thumbprint) aus dem Public Key.
static bool jwkFromKey(mbedtls_pk_context& k, String& jwkOut, String& err) {
    unsigned char der[160];
    int len = mbedtls_pk_write_pubkey_der(&k, der, sizeof(der));   // schreibt ans Ende
    if (len < 65) { err = "pubkey der"; return false; }
    const unsigned char* p = der + sizeof(der) - len;   // SubjectPublicKeyInfo; letzte 65 Byte = 04 X Y
    const unsigned char* xy = p + len - 65;
    if (xy[0] != 0x04) { err = "pubkey format"; return false; }
    jwkOut = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + b64url(xy + 1, 32) + "\",\"y\":\"" + b64url(xy + 33, 32) + "\"}";
    return true;
}
static String thumbprint(const String& jwk) {
    unsigned char h[32];
    mbedtls_sha256((const unsigned char*)jwk.c_str(), jwk.length(), h, 0);
    return b64url(h, 32);
}

// ES256 = ECDSA P-256/SHA-256, Signatur als rohes r||s (64 Byte), nicht DER.
static bool signEs256(Rng& rng, mbedtls_pk_context& k, const String& input, String& sigOut, String& err) {
    unsigned char hash[32];
    mbedtls_sha256((const unsigned char*)input.c_str(), input.length(), hash, 0);
    unsigned char der[80]; size_t dlen = 0;
    int rc = mbedtls_pk_sign(&k, MBEDTLS_MD_SHA256, hash, 32, der, sizeof(der), &dlen, mbedtls_ctr_drbg_random, &rng.drbg);
    if (rc != 0) { err = "Signatur: " + mbedErr(rc); return false; }
    // DER: 30 L 02 l1 R 02 l2 S -> R/S auf 32 Byte normieren
    unsigned char raw[64]; memset(raw, 0, sizeof(raw));
    size_t i = 2;
    if (der[1] & 0x80) i = 2 + (der[1] & 0x7f);
    for (int part = 0; part < 2; part++) {
        if (i >= dlen || der[i] != 0x02) { err = "Signatur-DER"; return false; }
        size_t l = der[i + 1]; const unsigned char* v = der + i + 2;
        while (l > 32 && *v == 0) { v++; l--; }
        if (l > 32) { err = "Signatur-Laenge"; return false; }
        memcpy(raw + part * 32 + (32 - l), v, l);
        i += 2 + der[i + 1];
    }
    sigOut = b64url(raw, 64);
    return true;
}

// ---------------------------------------------------------------------------
// ACME-Dialog
// ---------------------------------------------------------------------------
struct AcmeCtx {
    Rng rng;
    mbedtls_pk_context accKey;
    NetIface iface;
    String dirNewNonce, dirNewAccount, dirNewOrder;
    String nonce, jwk, thumb, kid;
    String err;
    AcmeCtx()  { mbedtls_pk_init(&accKey); }
    ~AcmeCtx() { mbedtls_pk_free(&accKey); }
};

static HttpResponse acmeHttp(AcmeCtx& c, const String& url, const String& method, const String& body,
                             const char* accept = nullptr) {
    HttpRequest rq; rq.url = url; rq.egress = &c.iface; rq.method = method; rq.body = body;
    if (body.length()) rq.contentType = "application/jose+json";
    if (accept) rq.accept = accept;
    rq.verifyTls = true; rq.maxBody = 12288;
    HttpResponse rp = esp32BoundHttpTransport().request(rq);
    if (rp.replayNonce.length()) c.nonce = rp.replayNonce;
    return rp;
}

static bool acmeNonce(AcmeCtx& c) {
    HttpResponse rp = acmeHttp(c, c.dirNewNonce, "HEAD", "");
    if (rp.error.length()) { c.err = "newNonce: " + rp.error; return false; }
    if (c.nonce.length() == 0) { c.err = "newNonce: keine Replay-Nonce (HTTP " + String(rp.status) + ")"; return false; }
    return true;
}

// Signierter POST (RFC 8555 6.2). payload "" = POST-as-GET. Bei badNonce einmal wiederholen.
static bool acmePost(AcmeCtx& c, const String& url, const String& payload, HttpResponse& rp, const char* accept = nullptr) {
    for (int attempt = 0; attempt < 2; attempt++) {
        if (c.nonce.length() == 0 && !acmeNonce(c)) return false;
        String prot = "{\"alg\":\"ES256\",";
        if (c.kid.length()) prot += "\"kid\":\"" + c.kid + "\","; else prot += "\"jwk\":" + c.jwk + ",";
        prot += "\"nonce\":\"" + c.nonce + "\",\"url\":\"" + url + "\"}";
        c.nonce = "";   // verbraucht
        String p64 = b64url(prot), pl64 = (payload.length() ? b64url(payload) : String(""));
        String sig;
        if (!signEs256(c.rng, c.accKey, p64 + "." + pl64, sig, c.err)) return false;
        String body = "{\"protected\":\"" + p64 + "\",\"payload\":\"" + pl64 + "\",\"signature\":\"" + sig + "\"}";
        rp = acmeHttp(c, url, "POST", body, accept);
        if (rp.error.length()) { c.err = "POST " + url + ": " + rp.error; return false; }
        if (rp.status == 400 && rp.body.indexOf("badNonce") >= 0 && attempt == 0) continue;
        return true;
    }
    c.err = "badNonce wiederholt"; return false;
}

static bool acmeFail(AcmeCtx& c, const String& what, const HttpResponse& rp) {
    String detail = jsonStr(rp.body, "detail");
    c.err = what + ": HTTP " + String(rp.status) + (detail.length() ? " -- " + detail : " " + rp.body.substring(0, 160));
    return false;
}

static bool acmeRun(AcmeCtx& c) {
    const AcmeConfig& cfg = s_cfg;
    if (cfg.domain.length() == 0) { c.err = "keine Domain konfiguriert"; return false; }
    if (!cfg.tos) { c.err = "Nutzungsbedingungen von Let's Encrypt nicht akzeptiert"; return false; }
    if (!systemClockValid()) { c.err = "Systemzeit unbekannt (Netzzeit noch nicht gesetzt) -> TLS-Pruefung unmoeglich"; return false; }
    if (!c.rng.ok) { c.err = "RNG"; return false; }
    if (!acmeAppResolveEgress(c.iface)) { c.err = "kein WAN-Interface"; return false; }

    // 1) Directory
    setState("Directory laden");
    HttpResponse rp = acmeHttp(c, cfg.staging ? kDirStaging : kDirProd, "GET", "");
    if (rp.error.length()) { c.err = "Directory: " + rp.error; return false; }
    if (rp.status != 200) return acmeFail(c, "Directory", rp);
    c.dirNewNonce = jsonStr(rp.body, "newNonce"); c.dirNewAccount = jsonStr(rp.body, "newAccount"); c.dirNewOrder = jsonStr(rp.body, "newOrder");
    if (!c.dirNewNonce.length() || !c.dirNewAccount.length() || !c.dirNewOrder.length()) { c.err = "Directory unvollstaendig"; return false; }

    // 2) Account-Key (persistent) + JWK/Thumbprint
    if (s_accountKeyPem.length() == 0) {
        setState("Account-Schluessel erzeugen");
        if (!genP256Pem(c.rng, s_accountKeyPem, c.err)) return false;
        Preferences p; p.begin(kNs, false); nvsPutBlob(p, "acckey", s_accountKeyPem); p.remove("accurl"); p.end();
        s_accountUrl = "";
    }
    if (!loadKey(c.rng, c.accKey, s_accountKeyPem, c.err)) return false;
    if (!jwkFromKey(c.accKey, c.jwk, c.err)) return false;
    c.thumb = thumbprint(c.jwk);

    // 3) Account (neu oder vorhanden)
    if (s_accountUrl.length() == 0 || (cfg.staging != s_accountUrl.startsWith("https://acme-staging"))) {
        setState("Account anlegen");
        String pl = "{\"termsOfServiceAgreed\":true";
        if (cfg.email.length()) pl += ",\"contact\":[\"mailto:" + cfg.email + "\"]";
        pl += "}";
        if (!acmePost(c, c.dirNewAccount, pl, rp)) return false;
        if (rp.status != 200 && rp.status != 201) return acmeFail(c, "newAccount", rp);
        if (rp.location.length() == 0) { c.err = "newAccount ohne Location"; return false; }
        s_accountUrl = rp.location;
        Preferences p; p.begin(kNs, false); p.putString("accurl", s_accountUrl); p.end();
    }
    c.kid = s_accountUrl;

    // 4) Order
    setState("Bestellung fuer " + cfg.domain);
    if (!acmePost(c, c.dirNewOrder, "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"" + cfg.domain + "\"}]}", rp)) return false;
    if (rp.status != 201 && rp.status != 200) return acmeFail(c, "newOrder", rp);
    String orderUrl = rp.location;
    String finalizeUrl = jsonStr(rp.body, "finalize");
    int ap = rp.body.indexOf("\"authorizations\"");
    String authzUrl;
    if (ap >= 0) { int q1 = rp.body.indexOf('"', rp.body.indexOf('[', ap)); int q2 = rp.body.indexOf('"', q1 + 1); if (q1 > 0 && q2 > q1) authzUrl = rp.body.substring(q1 + 1, q2); }
    if (!orderUrl.length() || !finalizeUrl.length() || !authzUrl.length()) { c.err = "newOrder unvollstaendig"; return false; }

    // 5) Authorization -> http-01-Challenge
    setState("Challenge holen");
    if (!acmePost(c, authzUrl, "", rp)) return false;
    if (rp.status != 200) return acmeFail(c, "authz", rp);
    int hp = rp.body.indexOf("\"http-01\"");
    if (hp < 0) { c.err = "keine http-01-Challenge angeboten"; return false; }
    int objStart = rp.body.lastIndexOf('{', hp);
    int objEnd   = rp.body.indexOf('}', hp);
    String chal = rp.body.substring(objStart, objEnd + 1);
    String chalUrl = jsonStr(chal, "url"), token = jsonStr(chal, "token");
    if (!chalUrl.length() || !token.length()) { c.err = "Challenge unvollstaendig"; return false; }
    s_chalToken = token; s_chalKeyAuth = token + "." + c.thumb;   // Responder scharf (Port 80)

    // 6) Challenge ausloesen + pollen
    setState("Challenge: Let's Encrypt prueft http://" + cfg.domain + "/.well-known/acme-challenge/...");
    if (!acmePost(c, chalUrl, "{}", rp)) return false;
    if (rp.status != 200) return acmeFail(c, "challenge", rp);
    bool valid = false;
    for (int i = 0; i < 20 && !valid; i++) {
        vTaskDelay(pdMS_TO_TICKS(3000));
        if (!acmePost(c, authzUrl, "", rp)) return false;
        String st = jsonStr(rp.body, "status");
        if (st == "valid") valid = true;
        else if (st == "invalid") {
            int ep = rp.body.indexOf("\"error\"");
            String detail = ep >= 0 ? jsonStr(rp.body, "detail", ep) : String("");
            c.err = "Challenge fehlgeschlagen: " + (detail.length() ? detail : rp.body.substring(0, 200))
                  + " (Port 80 von aussen erreichbar? DynDNS zeigt auf dieses Geraet?)";
            s_chalToken = ""; s_chalKeyAuth = "";
            return false;
        }
    }
    s_chalToken = ""; s_chalKeyAuth = "";
    if (!valid) { c.err = "Challenge nicht innerhalb 60 s bestaetigt"; return false; }

    // 7) Domain-Key + CSR
    setState("Zertifikatsanfrage (CSR)");
    String domKeyPem;
    if (!genP256Pem(c.rng, domKeyPem, c.err)) return false;
    mbedtls_pk_context domKey; mbedtls_pk_init(&domKey);
    if (!loadKey(c.rng, domKey, domKeyPem, c.err)) { mbedtls_pk_free(&domKey); return false; }
    mbedtls_x509write_csr csr; mbedtls_x509write_csr_init(&csr);
    mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_key(&csr, &domKey);
    int rc = mbedtls_x509write_csr_set_subject_name(&csr, ("CN=" + cfg.domain).c_str());
    mbedtls_x509_san_list san = {};
    san.node.type = MBEDTLS_X509_SAN_DNS_NAME;
    san.node.san.unstructured_name.tag = MBEDTLS_ASN1_IA5_STRING;
    san.node.san.unstructured_name.p   = (unsigned char*)cfg.domain.c_str();
    san.node.san.unstructured_name.len = cfg.domain.length();
    if (rc == 0) rc = mbedtls_x509write_csr_set_subject_alternative_name(&csr, &san);
    unsigned char* der = (unsigned char*)malloc(2048); int dlen = -1;
    if (rc == 0 && der) dlen = mbedtls_x509write_csr_der(&csr, der, 2048, mbedtls_ctr_drbg_random, &c.rng.drbg);
    mbedtls_x509write_csr_free(&csr); mbedtls_pk_free(&domKey);
    if (rc != 0 || dlen <= 0 || !der) { c.err = "CSR: " + mbedErr(rc != 0 ? rc : dlen); if (der) free(der); return false; }
    String csr64 = b64url(der + 2048 - dlen, (size_t)dlen); free(der);

    // 8) finalize + Order pollen
    setState("Zertifikat wird ausgestellt");
    if (!acmePost(c, finalizeUrl, "{\"csr\":\"" + csr64 + "\"}", rp)) return false;
    if (rp.status != 200) return acmeFail(c, "finalize", rp);
    String certUrl = jsonStr(rp.body, "certificate");
    for (int i = 0; i < 20 && certUrl.length() == 0; i++) {
        vTaskDelay(pdMS_TO_TICKS(3000));
        if (!acmePost(c, orderUrl, "", rp)) return false;
        String st = jsonStr(rp.body, "status");
        if (st == "valid") certUrl = jsonStr(rp.body, "certificate");
        else if (st == "invalid") return acmeFail(c, "order invalid", rp);
    }
    if (!certUrl.length()) { c.err = "Zertifikat nicht innerhalb 60 s ausgestellt"; return false; }

    // 9) Zertifikatskette holen + speichern
    setState("Zertifikat laden");
    if (!acmePost(c, certUrl, "", rp, "application/pem-certificate-chain")) return false;
    if (rp.status != 200 || rp.body.indexOf("-----BEGIN CERTIFICATE-----") < 0) return acmeFail(c, "certificate", rp);
    String chain = rp.body; chain.trim(); chain += "\n";
    time_t na = 0; String subj;
    if (!parseCertInfo(chain, na, subj)) { c.err = "Zertifikat unlesbar"; return false; }
    Preferences p; p.begin(kNs, false); nvsPutBlob(p, "cert", chain); nvsPutBlob(p, "key", domKeyPem); p.end();
    s_certPem = chain; s_keyPem = domKeyPem; s_notAfter = na; s_subject = subj;
    s_restartPending = true;
    return true;
}

static void acmeTask(void*) {
    s_lastOk = false; s_lastError = "";
    {
        AcmeCtx* c = new AcmeCtx();
        bool ok = c && acmeRun(*c);
        if (ok) {
            setState("fertig -- Zertifikat gespeichert, Neustart uebernimmt es");
            logEvent("ACME: Zertifikat fuer " + s_cfg.domain + " ausgestellt (" + (s_cfg.staging ? "Staging" : "Let's Encrypt") + ") -> Neustart");
        } else {
            s_lastError = c ? c->err : String("kein Speicher");
            setState("Fehler: " + s_lastError);
            logEvent("ACME fehlgeschlagen: " + s_lastError);
        }
        s_lastOk = ok;
        delete c;
    }
    s_lastRunMs = millis();
    s_running = false;
    vTaskDelete(nullptr);
}

bool acmeStart(const char* reason) {
    if (s_running) return false;
    s_running = true;
    Serial.printf("[ACME] Lauf gestartet (%s)\n", reason ? reason : "-");
    // Stack intern (mbedTLS/x509 auf dem Stack); nur waehrend des Laufs belegt.
    if (xTaskCreatePinnedToCore(acmeTask, "acme", 20480, nullptr, tskIDLE_PRIORITY + 3, nullptr, 1) != pdPASS) {
        s_running = false; s_lastError = "ACME-Task nicht anlegbar (interner Heap)"; setState("Fehler: " + s_lastError);
        return false;
    }
    return true;
}

void acmeTick(bool linkUp) {
    if (!s_cfg.enabled || s_running || !linkUp) return;
    uint32_t now = millis();
    if (now - s_lastTickCheckMs < 60000UL) return;   // einmal je Minute pruefen (billig)
    s_lastTickCheckMs = now;
    if (!systemClockValid()) return;
    bool need = false;
    if (!acmeHasCert() || !acmeCertUsable()) need = true;
    else if (s_notAfter && (s_notAfter - time(nullptr)) < 30L * 86400L) need = true;   // < 30 Tage Rest
    if (!need) return;
    // Automatische Versuche hoechstens alle 12 h (Rate-Limits von Let's Encrypt schonen); der
    // manuelle Start aus der UI ist davon unabhaengig.
    if (s_lastAutoAttemptMs && (now - s_lastAutoAttemptMs) < 12UL * 3600UL * 1000UL) return;
    s_lastAutoAttemptMs = now;
    acmeStart(acmeHasCert() ? "Erneuerung (< 30 Tage)" : "Erstbezug");
}
#else
// ============================================================================
// Stub (WEIRDOS_FEATURE_ACME=0): kein Let's-Encrypt-Client im Build. Jede Header-Funktion bleibt
// definiert, damit .ino / serial_console / cert_store / ui_system unveraendert linken. Kein mbedTLS-
// PK/CSR/Base64, kein Worker-Task, kein NVS-Zugriff -- gespeicherte ACME-Daten bleiben fuer einen
// spaeteren Build mit ACME erhalten. acmeAppResolveEgress()/logEvent() liefert weiterhin die .ino.
// ============================================================================
static const char* kAcmeNotBuilt = "Let's Encrypt nicht im Build enthalten (WEIRDOS_FEATURE_ACME=0)";
static AcmeConfig  s_cfgStub;                 // enabled=false -> cert_store/.ino sehen "ACME aus"
static const String s_emptyStub;

void   acmeLoad() {}
const  AcmeConfig& acmeConfig() { return s_cfgStub; }
void   acmeSaveConfig(const AcmeConfig& c) { (void)c; }   // bewusst nicht uebernehmen: enabled bleibt false
bool   acmeHasCert() { return false; }
const  String& acmeCertPem() { return s_emptyStub; }
const  String& acmeKeyPem() { return s_emptyStub; }
time_t acmeCertNotAfter() { return 0; }
String acmeCertSubject() { return String(); }
bool   acmeCertUsable() { return false; }
bool   acmeStart(const char* reason) { (void)reason; Serial.println(kAcmeNotBuilt); return false; }
bool   acmeRunning() { return false; }
String acmeStateText() { return String(kAcmeNotBuilt); }
String acmeLastError() { return String(); }
bool   acmeLastOk() { return false; }
uint32_t acmeLastRunMs() { return 0; }
void   acmeTick(bool linkUp) { (void)linkUp; }
bool   acmeRestartPending() { return false; }
void   acmeClearCert() {}
bool   acmeChallengeLookup(const String& token, String& keyAuthOut) { (void)token; keyAuthOut = ""; return false; }
#endif // WEIRDOS_FEATURE_ACME
