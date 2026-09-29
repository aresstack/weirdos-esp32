// ============================================================================
// acme_client.h -- On-Device-ACME (Let's Encrypt, RFC 8555) fuer das Management-HTTPS.
//
// HTTPS Phase 3: statt des self-signed Boot-Zertifikats holt sich das Geraet selbst ein
// oeffentlich gueltiges Zertifikat fuer seine DynDNS-Domain -- nativ auf der MCU, ohne
// VPS/TLS-Terminator davor (der waere Klartext ueber LTE). Ablauf (HTTP-01):
//   Directory -> newNonce -> newAccount (Account-Key P-256, im NVS) -> newOrder(dns:domain)
//   -> Authorization -> http-01-Challenge: das Geraet liefert auf PORT 80 unter
//   /.well-known/acme-challenge/<token> die Key-Authorization -> Challenge ausloesen -> pollen
//   -> CSR (frischer Domain-Key P-256, SAN) -> finalize -> Zertifikatskette (PEM) -> NVS.
// Voraussetzungen: oeffentliche IPv4 am Geraet (Telekom internet.t-d1.de), DynDNS zeigt auf
// die Domain, Port 80 von aussen erreichbar (Port-80-Listener der Control-Plane), gueltige
// Systemzeit (modem_clock: Zertifikatspruefung des ACME-Servers + Ablaufdatum).
// Alle Netzaufrufe laufen ueber den gebundenen Transport (http_transport.h) mit verifyTls.
//
// Erneuerung: acmeTick() prueft taeglich; < 30 Tage Restlaufzeit -> neuer Lauf. Ein neues
// Zertifikat wird beim naechsten Start des Management-Servers verwendet (esp_https_server kann
// nicht im Betrieb wechseln) -> acmeRestartPending() + geplanter Neustart, wenn kein Video-Client.
// ============================================================================
#ifndef ACME_CLIENT_H
#define ACME_CLIENT_H
#include <Arduino.h>
#include <time.h>

struct AcmeConfig {
    bool   enabled = false;   // Let's Encrypt statt self-signed
    String domain;            // z.B. angelworks.eu (Default: DynDNS-Domain)
    String email;             // Kontakt (mailto:) -- Ablaufwarnungen von Let's Encrypt
    bool   staging = false;   // Staging-CA (hohe Rate-Limits, Cert nicht browser-gueltig) zum Testen
    bool   tos     = false;   // Nutzungsbedingungen von Let's Encrypt akzeptiert (Pflicht)
};

void   acmeLoad();                          // NVS -> Config + gespeichertes Zertifikat (setup)
const  AcmeConfig& acmeConfig();
void   acmeSaveConfig(const AcmeConfig& c); // Config -> NVS (Zertifikat bleibt)

bool   acmeHasCert();                       // Zertifikat + Schluessel im NVS vorhanden
const  String& acmeCertPem();               // Kette (Leaf + Intermediate), PEM
const  String& acmeKeyPem();                // Domain-Schluessel, PEM
time_t acmeCertNotAfter();                  // Ablauf (UTC), 0 = keins/unparsbar
String acmeCertSubject();                   // "CN=..." aus dem Leaf, "" wenn keins
bool   acmeCertUsable();                    // vorhanden, Domain passt, nicht abgelaufen (falls Uhr gueltig)

bool   acmeStart(const char* reason);       // Lauf im Worker-Task starten; false = laeuft schon / kein Heap
bool   acmeRunning();
String acmeStateText();                     // Kurzstatus fuer UI/Konsole (Schritt / Fehler / ok)
String acmeLastError();
bool   acmeLastOk();
uint32_t acmeLastRunMs();                   // millis() des letzten Laufendes, 0 = nie
void   acmeTick(bool linkUp);               // loop(): Erneuerungspruefung (taeglich) + Auto-Erstbezug
bool   acmeRestartPending();                // neues Zertifikat gespeichert -> Neustart uebernimmt es
void   acmeClearCert();                     // Zertifikat + Schluessel loeschen (zurueck zu self-signed)

// HTTP-01-Responder (Route /.well-known/acme-challenge/{token} auf Port 80, PUBLIC):
bool   acmeChallengeLookup(const String& token, String& keyAuthOut);

// ---- Vom Sketch bereitgestellt (App-Hooks) ----
struct NetIface;
bool   acmeAppResolveEgress(NetIface& out);  // WAN-Interface fuer den gebundenen Transport (+ DNS-Route)
void   logEvent(const String& text);         // Ereignis-Ringpuffer

#endif // ACME_CLIENT_H
