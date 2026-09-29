// ============================================================================
// ipsec_trust_store.h -- Host-Truststore + Zertifikatsinfo fuer das IPsec-Trust-Modell.
//
// WeirdIKE kennt keinen ESP-IDF-/Linux-Truststore: der Crypto-Adapter bekommt vom HOST eine
// Truststore-Funktion (weirdike_mbedtls_host_store_t). Auf dem P4 ist das das eingebaute
// ESP-IDF-Zertifikatsbundle (Mozilla-Root-Store, CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_FULL,
// offline im Produkt). Fehlt es, lehnt der Core die Host-Store-Modi beim Start ab -- kein stiller
// Rueckfall auf die PEM-Anker. Unter Linux liefert spaeter der System-Truststore dieselbe Funktion.
// ============================================================================
#ifndef IPSEC_TRUST_STORE_H
#define IPSEC_TRUST_STORE_H

#include <Arduino.h>
#include "src/weirdike/crypto_mbedtls.h"

// UI-/NVS-Kennung (public | public-plus | own | none) -> weirdike_trust_mode_t. Unbekannt -> own
// (die restriktivste PEM-Variante; der Core verlangt dann Anker und scheitert sonst ehrlich).
int ipsecTrustModeId(const String& mode);
// Kurztext fuer Status/Diagnose je Kennung.
const char* ipsecTrustModeLabel(const String& mode);

// Host-Truststore (ESP-IDF-Bundle) fuer die Modi public / public-plus. false = nicht verfuegbar.
bool ipsecHostTrustStore(weirdike_mbedtls_host_store_t& out);

// Zertifikatsinfo fuer die UI-Liste: JSON {"certs":[{subject,issuer,selfSigned,ca,validFrom,validTo}|{error}...]},
// ein Eintrag je PEM-Block in Reihenfolge des Textes. Keine Secrets (nur oeffentliche Zertifikate).
String ipsecCertInfoJson(const String& pem);

#endif // IPSEC_TRUST_STORE_H
