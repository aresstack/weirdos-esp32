// ipsec_trust_store.cpp -- siehe Header.
//
// MBEDTLS_ALLOW_PRIVATE_ACCESS: das ESP-IDF-Bundle haengt sich per esp_crt_bundle_attach() an eine
// mbedtls_ssl_config (Verify-Callback + Dummy-CA-Kette). Wir lesen genau diese drei Felder wieder
// aus und geben sie dem WeirdIKE-Adapter als Host-Truststore -- derselbe Pfad, den esp-tls fuer
// jede HTTPS-Verbindung nutzt (gleiche Callback-Semantik, gleiche Kettenpruefung).
//
// Baustein IPSEC (weirdos_features.h): bei WEIRDOS_FEATURE_IPSEC=0 bleibt nur der Stub am Ende
// dieser Datei (kein Bundle-Attach, keine Zertifikatsinfo). Das MBEDTLS-Define bleibt VOR dem
// ersten mbedTLS-Include (der Header zieht crypto_mbedtls.h -> mbedtls/*.h ein).
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "weirdos_features.h"
#include "ipsec_trust_store.h"
#if WEIRDOS_FEATURE_IPSEC
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <esp_crt_bundle.h>
#include <string.h>

int ipsecTrustModeId(const String& mode) {
    if (mode == "public")      return (int)WEIRDIKE_TRUST_HOST_STORE;
    if (mode == "public-plus") return (int)WEIRDIKE_TRUST_HOST_STORE_PLUS_PEM;
    if (mode == "none")        return (int)WEIRDIKE_TRUST_NONE;
    return (int)WEIRDIKE_TRUST_ANCHOR_PEM;   // "own" und alles Unbekannte
}

const char* ipsecTrustModeLabel(const String& mode) {
    if (mode == "public")      return "Oeffentliche CAs (eingebautes Root-Bundle)";
    if (mode == "public-plus") return "Oeffentliche CAs + Zusatzzertifikate";
    if (mode == "none")        return "KEINE Vertrauenspruefung (nicht empfohlen; IKE-Signatur geprueft)";
    return "Eigener Vertrauensanker";
}

static mbedtls_ssl_config s_bundleConf;
static bool s_bundleInit = false, s_bundleOk = false;

bool ipsecHostTrustStore(weirdike_mbedtls_host_store_t& out) {
    memset(&out, 0, sizeof(out));
    if (!s_bundleInit) {
        mbedtls_ssl_config_init(&s_bundleConf);
        s_bundleOk = (esp_crt_bundle_attach(&s_bundleConf) == ESP_OK);
        s_bundleInit = true;
    }
    if (!s_bundleOk) return false;
    out.ca_chain = s_bundleConf.ca_chain;   // Dummy-Kette des Bundles (die Entscheidung trifft der Callback)
    out.f_vrfy   = s_bundleConf.f_vrfy;     // esp_crt_verify_callback: Aussteller im Bundle + Signatur
    out.p_vrfy   = s_bundleConf.p_vrfy;
    return out.f_vrfy != nullptr;
}

static String jesc(const char* s) {
    String o; o.reserve(strlen(s) + 8);
    for (const char* p = s; *p; ++p) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') { o += '\\'; o += (char)c; }
        else if (c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); o += b; }
        else o += (char)c;
    }
    return o;
}

static String dateStr(const mbedtls_x509_time& t) {
    char b[24]; snprintf(b, sizeof(b), "%04d-%02d-%02d", t.year, t.mon, t.day); return String(b);
}

// Ein PEM-Block -> ein JSON-Objekt. Fehler je Block, damit die Liste in der UI Positionen behaelt.
static String certInfoOne(const String& block) {
    mbedtls_x509_crt crt; mbedtls_x509_crt_init(&crt);
    String j;
    int rc = mbedtls_x509_crt_parse(&crt, (const unsigned char*)block.c_str(), block.length() + 1);
    if (rc != 0) {
        char e[40]; snprintf(e, sizeof(e), "PEM nicht lesbar (mbedtls -0x%04x)", (unsigned)(-rc));
        j = "{\"error\":\"" + jesc(e) + "\"}";
    } else {
        char subj[192], iss[192];
        if (mbedtls_x509_dn_gets(subj, sizeof(subj), &crt.subject) < 0) strcpy(subj, "?");
        if (mbedtls_x509_dn_gets(iss,  sizeof(iss),  &crt.issuer)  < 0) strcpy(iss,  "?");
        bool selfSigned = crt.subject_raw.len == crt.issuer_raw.len &&
                          memcmp(crt.subject_raw.p, crt.issuer_raw.p, crt.subject_raw.len) == 0;
        j  = "{\"subject\":\"" + jesc(subj) + "\",\"issuer\":\"" + jesc(iss) + "\"";
        j += String(",\"selfSigned\":") + (selfSigned ? "true" : "false");
        j += String(",\"ca\":") + (crt.ca_istrue ? "true" : "false");
        j += ",\"validFrom\":\"" + dateStr(crt.valid_from) + "\",\"validTo\":\"" + dateStr(crt.valid_to) + "\"}";
    }
    mbedtls_x509_crt_free(&crt);
    return j;
}

String ipsecCertInfoJson(const String& pem) {
    static const char* B = "-----BEGIN CERTIFICATE-----";
    static const char* E = "-----END CERTIFICATE-----";
    String out = "{\"certs\":[";
    int pos = 0, n = 0;
    while (n < 16) {
        int b = pem.indexOf(B, pos); if (b < 0) break;
        int e = pem.indexOf(E, b);   if (e < 0) break;
        e += (int)strlen(E);
        if (n++) out += ',';
        out += certInfoOne(pem.substring(b, e) + "\n");
        pos = e;
    }
    out += "]}";
    return out;
}

#else  // !WEIRDOS_FEATURE_IPSEC
// Stub: IPsec nicht im Build enthalten (WEIRDOS_FEATURE_IPSEC=0)
// Kein Host-Truststore, keine Zertifikatsinfo. Der Typ weirdike_mbedtls_host_store_t kommt weiter
// aus dem unveraenderten Header (nur Deklarationen) -- es wird KEIN WeirdIKE-Code referenziert.
#include <string.h>

int         ipsecTrustModeId(const String&) { return 0; }
const char* ipsecTrustModeLabel(const String&) { return "nicht im Build enthalten"; }
bool        ipsecHostTrustStore(weirdike_mbedtls_host_store_t& out) { memset(&out, 0, sizeof(out)); return false; }
String      ipsecCertInfoJson(const String&) { return "{\"ok\":false,\"builtIn\":false,\"certs\":[]}"; }

#endif // WEIRDOS_FEATURE_IPSEC
