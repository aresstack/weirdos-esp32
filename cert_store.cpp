// cert_store.cpp -- siehe cert_store.h.
#include "cert_store.h"
#include "tls_selfsigned.h"
#include "acme_client.h"
#include <Preferences.h>
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include <esp_random.h>

// f_rng fuer mbedTLS 3.x (pk_parse_key/check_pair verlangen ein RNG): Hardware-TRNG, kein AES/DMA.
static int cs_rng(void* p, unsigned char* out, size_t len) { (void)p; esp_fill_random(out, len); return 0; }

extern String dyndnsDomain;          // Default-CN/Domain (in der .ino)
extern bool   webHttpsEnabled;

// ---- Zustand (Spiegel des NVS "cert") -------------------------------------
static CertSource s_src = CertSource::SelfSigned;
static bool       s_ssRenew = true;
static String     s_upCert, s_upKey;    // Upload-Zertifikat (Kette) + Schluessel
static String     s_ssCert, s_ssKey;    // persistiertes self-signed

// ---- mbedTLS-Helfer: Leaf-Subject + notAfter aus PEM lesen ----------------
static bool parseLeaf(const String& pem, String* subjectOut, time_t* notAfterOut) {
    if (pem.length() == 0) return false;
    mbedtls_x509_crt crt; mbedtls_x509_crt_init(&crt);
    int rc = mbedtls_x509_crt_parse(&crt, (const unsigned char*)pem.c_str(), pem.length() + 1);
    bool ok = false;
    if (rc == 0) {
        if (subjectOut) {
            char buf[128]; int n = mbedtls_x509_dn_gets(buf, sizeof(buf), &crt.subject);
            *subjectOut = (n > 0) ? String(buf) : String("");
        }
        if (notAfterOut) {
            struct tm t; memset(&t, 0, sizeof(t));
            t.tm_year = crt.valid_to.year - 1900; t.tm_mon = crt.valid_to.mon - 1; t.tm_mday = crt.valid_to.day;
            t.tm_hour = crt.valid_to.hour; t.tm_min = crt.valid_to.min; t.tm_sec = crt.valid_to.sec;
            *notAfterOut = mktime(&t);
        }
        ok = true;
    }
    mbedtls_x509_crt_free(&crt);
    return ok;
}
// Passen Zertifikat und privater Schluessel zusammen? (mbedTLS check_pair)
static bool certKeyMatch(const String& certPem, const String& keyPem) {
    mbedtls_x509_crt crt; mbedtls_x509_crt_init(&crt);
    mbedtls_pk_context pk; mbedtls_pk_init(&pk);
    bool ok = false;
    if (mbedtls_x509_crt_parse(&crt, (const unsigned char*)certPem.c_str(), certPem.length() + 1) == 0) {
        if (mbedtls_pk_parse_key(&pk, (const unsigned char*)keyPem.c_str(), keyPem.length() + 1, nullptr, 0, cs_rng, nullptr) == 0)
            ok = (mbedtls_pk_check_pair(&crt.pk, &pk, cs_rng, nullptr) == 0);
    }
    mbedtls_pk_free(&pk); mbedtls_x509_crt_free(&crt);
    return ok;
}

// ---- Persistenz -----------------------------------------------------------
void certStoreLoad() {
    Preferences p; p.begin("cert", true);
    s_src     = (CertSource)p.getUChar("src", (uint8_t)CertSource::SelfSigned);
    s_ssRenew = p.getBool("ssrenew", true);
    s_upCert  = p.getString("upcrt", "");
    s_upKey   = p.getString("upkey", "");
    s_ssCert  = p.getString("sscrt", "");
    s_ssKey   = p.getString("sskey", "");
    p.end();
}
static void saveField(const char* key, const String& v) { Preferences p; p.begin("cert", false); p.putString(key, v); p.end(); }

CertSource certSource() { return s_src; }
void certSetSource(CertSource s) {
    s_src = s;
    Preferences p; p.begin("cert", false); p.putUChar("src", (uint8_t)s); p.end();
    // ACME-Quelle mit dem acme_client koppeln (dessen Erneuerung/Challenge haengt an enabled).
    AcmeConfig ac = acmeConfig();
    bool wantAcme = (s == CertSource::Acme);
    if (ac.enabled != wantAcme) { ac.enabled = wantAcme; if (wantAcme && ac.domain.length() == 0) ac.domain = dyndnsDomain; acmeSaveConfig(ac); }
}

// ---- Upload ---------------------------------------------------------------
String certUploadSet(const String& certPem, const String& keyPem) {
    String crt = certPem.length() ? certPem : s_upCert;
    String key = keyPem.length()  ? keyPem  : s_upKey;
    if (crt.indexOf("-----BEGIN CERTIFICATE-----") < 0) return "Zertifikat ist kein PEM (-----BEGIN CERTIFICATE-----).";
    if (key.indexOf("-----BEGIN") < 0)                  return "Schluessel ist kein PEM (-----BEGIN ... PRIVATE KEY-----).";
    if (!parseLeaf(crt, nullptr, nullptr))              return "Zertifikat laesst sich nicht parsen (mbedTLS).";
    if (!certKeyMatch(crt, key))                        return "Zertifikat und privater Schluessel passen nicht zusammen.";
    s_upCert = crt; s_upKey = key;
    saveField("upcrt", crt); saveField("upkey", key);
    return "";
}
bool   certUploadPresent()  { return s_upCert.length() > 0 && s_upKey.length() > 0; }
String certUploadSubject()  { String s; parseLeaf(s_upCert, &s, nullptr); return s; }
time_t certUploadNotAfter() { time_t t = 0; parseLeaf(s_upCert, nullptr, &t); return t; }

// ---- Self-signed ----------------------------------------------------------
bool certSelfSignedRenew() { return s_ssRenew; }
void certSetSelfSignedRenew(bool on) { s_ssRenew = on; Preferences p; p.begin("cert", false); p.putBool("ssrenew", on); p.end(); }
String certSelfSignedSubject()  { String s; parseLeaf(s_ssCert, &s, nullptr); return s; }
time_t certSelfSignedNotAfter() { time_t t = 0; parseLeaf(s_ssCert, nullptr, &t); return t; }

bool certRegenerateSelfSigned(const char* cn) {
    String c, k;
    if (!weirdosGenSelfSignedCert(c, k, cn)) return false;
    s_ssCert = c; s_ssKey = k;
    saveField("sscrt", c); saveField("sskey", k);
    return true;
}
static bool ensureSelfSigned() {
    if (s_ssCert.length() && s_ssKey.length()) return true;
    return certRegenerateSelfSigned(dyndnsDomain.length() ? dyndnsDomain.c_str() : nullptr);
}

// ---- Aktives Zertifikat ---------------------------------------------------
bool certResolveActive(String& certOut, String& keyOut, String& srcText) {
    if (s_src == CertSource::Acme) {
        if (acmeCertUsable()) { certOut = acmeCertPem(); keyOut = acmeKeyPem(); srcText = "Let's Encrypt (" + acmeCertSubject() + ")"; return true; }
        if (ensureSelfSigned()) { certOut = s_ssCert; keyOut = s_ssKey; srcText = "self-signed (Let's-Encrypt-Zertifikat noch nicht vorhanden)"; return true; }
        return false;
    }
    if (s_src == CertSource::Upload) {
        if (certUploadPresent()) { certOut = s_upCert; keyOut = s_upKey; srcText = "eigenes Zertifikat (" + certUploadSubject() + ")"; return true; }
        if (ensureSelfSigned()) { certOut = s_ssCert; keyOut = s_ssKey; srcText = "self-signed (kein eigenes Zertifikat hinterlegt)"; return true; }
        return false;
    }
    if (!ensureSelfSigned()) return false;
    certOut = s_ssCert; keyOut = s_ssKey; srcText = "self-signed"; return true;
}

// ---- loop(): Auto-Erneuerung ----------------------------------------------
void certTick(bool linkUp) {
    (void)linkUp;
    // ACME erneuert acmeTick() selbst. Hier nur self-signed bei aktiver Auto-Erneuerung.
    if (s_src != CertSource::SelfSigned || !s_ssRenew) return;
    static uint32_t last = 0; uint32_t now = millis();
    if (last && now - last < 6UL * 3600UL * 1000UL) return;   // hoechstens alle 6 h pruefen
    last = now;
    time_t exp = certSelfSignedNotAfter();
    time_t nowUtc = time(nullptr);
    if (nowUtc > 100000 && exp > 0 && (exp - nowUtc) < 30L * 24 * 3600)
        certRegenerateSelfSigned(dyndnsDomain.length() ? dyndnsDomain.c_str() : nullptr);   // wirkt nach Neustart
}

String certStatusJson() {
    String j = "{";
    j += "\"source\":"; j += String((unsigned)(uint8_t)s_src); j += ",";
    j += "\"selfsigned\":{\"subject\":\"" + certSelfSignedSubject() + "\",\"notAfter\":" + String((long)certSelfSignedNotAfter()) + ",\"renew\":" + (s_ssRenew ? "true" : "false") + "},";
    j += "\"upload\":{\"present\":" + String(certUploadPresent() ? "true" : "false") + ",\"subject\":\"" + certUploadSubject() + "\",\"notAfter\":" + String((long)certUploadNotAfter()) + "}";
    j += "}";
    return j;
}
