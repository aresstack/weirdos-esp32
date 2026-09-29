// ============================================================================
// tls_selfsigned.h  --  On-Device self-signed TLS-Zertifikat (ECC P-256, mbedTLS)
//
// Erzeugt beim Boot ein Wegwerf-Zertifikat + privaten Schluessel im RAM (PEM).
// Bewusst NICHT im Repo gehaltene Schluessel: kein privater Key im (public) Git.
// Zweck aktuell = Phase-1-TLS-PoC (HTTPS-MJPEG-Stream, Durchsatz-Benchmark).
// Spaeter wiederverwendbar als Key-Baustein fuer den ACME-/Let's-Encrypt-Pfad.
//
// Symbole in esp32p4_es-libs verifiziert (mbedtls_x509write_crt_pem /
// mbedtls_pk_write_key_pem / mbedtls_ecp_gen_key real in libmbedx509/-crypto.a).
// ============================================================================
#ifndef TLS_SELFSIGNED_H
#define TLS_SELFSIGNED_H

#include <Arduino.h>

// Erzeugt ein self-signed ECC-P-256-Zertifikat (SHA-256) samt privatem Schluessel.
// certPemOut/keyPemOut erhalten NUL-terminiertes PEM. cn = Common Name (nullptr ->
// "weirdos.local"). Rueckgabe false bei Fehler (Details via Serial).
bool weirdosGenSelfSignedCert(String& certPemOut, String& keyPemOut, const char* cn);

#endif // TLS_SELFSIGNED_H
