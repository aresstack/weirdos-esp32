// ============================================================================
// tls_selfsigned.cpp  --  siehe tls_selfsigned.h
// ============================================================================
#include "weirdos_features.h"      // WEIRDOS_FEATURE_TLS_SERVER -- der Schalter dieses Bausteins
#include "tls_selfsigned.h"   // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
#if WEIRDOS_FEATURE_TLS_SERVER
// ============================================================================
// Echte Implementierung (WEIRDOS_FEATURE_TLS_SERVER=1) -- self-signed-Erzeugung (mbedTLS PK/X.509)
// ============================================================================

#include <cstring>
#include <cstdlib>

#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"

bool weirdosGenSelfSignedCert(String& certPemOut, String& keyPemOut, const char* cn) {
    int ret = 0;
    bool ok = false;

    // Alle Deklarationen VOR dem ersten goto (C++-Regel: kein Sprung ueber Init).
    mbedtls_pk_context       key;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr;
    mbedtls_x509write_cert   crt;

    const size_t  CERT_BUF = 2560;
    const size_t  KEY_BUF  = 2048;
    unsigned char* certBuf = nullptr;
    unsigned char* keyBuf  = nullptr;

    char        dn[96];
    const char* pers = "weirdos_tls_selfsigned";
    // Fest gewaehltes Gueltigkeitsfenster: das Geraet hat beim Boot evtl. keine
    // NTP-Zeit -> statische, weite Spanne statt "jetzt".
    const char* notBefore = "20240101000000";
    const char* notAfter  = "20440101000000";
    // Feste, ungerade Seriennummer (raw, nicht die deprecatete _set_serial-API).
    unsigned char serial[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

    mbedtls_pk_init(&key);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr);
    mbedtls_x509write_crt_init(&crt);

    snprintf(dn, sizeof(dn), "CN=%s", (cn && *cn) ? cn : "weirdos.local");

    ret = mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) goto done;

    // --- ECC-P-256-Schluessel erzeugen ---
    ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) goto done;
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key),
                              mbedtls_ctr_drbg_random, &ctr);
    if (ret != 0) goto done;

    // --- Zertifikatsfelder (self-signed: subject == issuer == eigener Key) ---
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt, &key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &key);

    ret = mbedtls_x509write_crt_set_subject_name(&crt, dn);
    if (ret != 0) goto done;
    ret = mbedtls_x509write_crt_set_issuer_name(&crt, dn);
    if (ret != 0) goto done;
    ret = mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial));
    if (ret != 0) goto done;
    ret = mbedtls_x509write_crt_set_validity(&crt, notBefore, notAfter);
    if (ret != 0) goto done;
    // CA=false, kein Pfadlaengen-Constraint.
    mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);

    // --- PEM ausschreiben ---
    certBuf = (unsigned char*)malloc(CERT_BUF);
    keyBuf  = (unsigned char*)malloc(KEY_BUF);
    if (!certBuf || !keyBuf) { ret = -1; goto done; }

    ret = mbedtls_x509write_crt_pem(&crt, certBuf, CERT_BUF,
                                    mbedtls_ctr_drbg_random, &ctr);
    if (ret != 0) goto done;
    ret = mbedtls_pk_write_key_pem(&key, keyBuf, KEY_BUF);
    if (ret != 0) goto done;

    certPemOut = String((const char*)certBuf);
    keyPemOut  = String((const char*)keyBuf);
    ok = true;

done:
    if (!ok) {
        char eb[128];
        mbedtls_strerror(ret, eb, sizeof(eb));
        Serial.printf("[tls] self-signed cert gen failed: -0x%04x %s\n",
                      (unsigned)(-ret), eb);
    }
    if (certBuf) free(certBuf);
    if (keyBuf)  free(keyBuf);
    mbedtls_x509write_crt_free(&crt);
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&key);
    return ok;
}
#else
// Stub (WEIRDOS_FEATURE_TLS_SERVER=0): keine Zertifikatserzeugung -> false. cert_store (Stub) und
// camera_server (HTTPS-MJPEG: "cert gen failed, TLS disabled") behandeln das bereits sauber.
bool weirdosGenSelfSignedCert(String& certPemOut, String& keyPemOut, const char* cn) {
    (void)cn; certPemOut = ""; keyPemOut = "";
    return false;
}
#endif // WEIRDOS_FEATURE_TLS_SERVER
