// cert_store.h -- EINE Quelle der Wahrheit fuer das HTTPS-Zertifikat des Geraets.
//
// Der Benutzer waehlt die HERKUNFT (System > Sicherheit > Zertifikat, horizontale Radios):
//   SELFSIGNED : das Geraet erzeugt ein eigenes Zertifikat (kein Browser-Vertrauen, aber
//                verschluesselt). Persistiert -> stabil ueber Neustarts; optional Auto-Erneuerung.
//   UPLOAD     : eigenes Zertifikat (Kette + privater Schluessel) hochladen/eintragen. Wird geprueft
//                (mbedTLS-Parse) und im NVS gehalten.
//   ACME       : Let's Encrypt (acme_client) -- oeffentlich gueltig, automatische Erneuerung, One-Click.
//
// resolveActive() liefert dem HTTPS-Start das aktive Zertifikat+Schluessel + einen Quellentext.
// Faellt eine Quelle aus (Upload ungueltig / ACME-Cert noch nicht da), wird auf ein self-signed
// zurueckgefallen, damit HTTPS nie ohne Zertifikat dasteht.
#pragma once
#include <Arduino.h>
#include <time.h>

enum class CertSource : uint8_t { SelfSigned = 0, Upload = 1, Acme = 2 };

void        certStoreLoad();                 // NVS -> Quelle/Upload/Selfsigned-Flags
CertSource  certSource();
void        certSetSource(CertSource s);     // persistiert; ACME wird mit acmeConfig.enabled gekoppelt

// --- Eigenes Zertifikat (Upload/Eintragen) ---
// Prueft Kette+Schluessel (mbedTLS). "" = ok gespeichert, sonst Fehlertext. Leere Argumente behalten.
String      certUploadSet(const String& certPem, const String& keyPem);
bool        certUploadPresent();
String      certUploadSubject();             // "CN=..." des Leaf ("" wenn keins)
time_t      certUploadNotAfter();            // Ablauf (UTC), 0 = keins/unparsbar

// --- Selbst erstellt (self-signed) ---
bool        certSelfSignedRenew();           // Auto-Erneuerung an? (regeneriert bei < 30 Tagen)
void        certSetSelfSignedRenew(bool on);
String      certSelfSignedSubject();
time_t      certSelfSignedNotAfter();
bool        certRegenerateSelfSigned(const char* cn);   // jetzt neu erzeugen + persistieren

// Aktives Zertifikat fuer den HTTPS-Start bestimmen. certOut/keyOut = PEM. srcText = Klartext.
// Rueckgabe false nur, wenn selbst der self-signed-Fallback scheitert (dann kein HTTPS).
bool        certResolveActive(String& certOut, String& keyOut, String& srcText);

// loop(): Auto-Erneuerung (self-signed bei aktivem Renew; ACME macht acmeTick selbst).
void        certTick(bool linkUp);

String      certStatusJson();                // fuer die UI (Quelle, Ablaeufe, Subjects)
