// ipsec_crypto_caps.h -- EINE Quelle der Wahrheit fuer die IKEv2/IPsec-Algorithmen im Raster des
// LANCOM Advanced VPN Client (DH-Gruppen, PFS, IKE-SA-Verschluesselung/-Hash, Child-SA-Verschluesselung/
// -Hash, Authentifizierung). Jede Zeile traegt `supported` = WeirdIKE kann es HEUTE auf der Leitung.
// Alles andere zeigt die UI ausgegraut ("noch nicht implementiert") und der Dienst lehnt es beim
// Speichern ab. Wird ein Algorithmus in WeirdIKE fertig, wird hier nur das Flag umgestellt.
//
// Jede Zeile traegt ausserdem die IANA-Transform-IDs (RFC 7296 / IANA IKEv2-Register), mit denen
// ipsec_runtime.cpp die typisierte WeirdIKE-Policy (weirdike_ike_policy_t / weirdike_child_policy_t)
// baut. WeirdIKE sieht NIE die UI-Kennungen ("aes256cbc", "sha512"), nur diese IDs.
//   ENC : iana = ENCR-ID (AES-CBC 12, AES-GCM-16 20, 3DES 3, ChaCha20-Poly1305 28, NULL 11),
//         keyBits = KEY_LENGTH-Attribut (0 = keines)
//   Hash: IKE  -> iana = PRF-ID, iana2 = INTEG-ID (ein LANCOM-"Hash" setzt beide)
//         ESP  -> iana = INTEG-ID (NULL 0 nur mit AEAD)
//   DH  : iana = D-H-Gruppennummer
//
// HEUTE (WeirdIKE, PSK-Pfad, hardware-bewiesen gegen FRITZ!Box/strongSwan):
//   IKE-SA : AES-CBC-256 + SHA-256 oder SHA-512 (PRF+INTEG, unabhaengig kombinierbar) + DH14
//   Child  : ESP AES-CBC-256 + HMAC-SHA2-256-128
//   Auth   : PSK. EAP (Benutzer+Passwort = EAP-MSCHAPv2) und Zertifikat folgen als WeirdIKE-Slices.
//   PFS    : nein (CREATE_CHILD_SA mit KE noch nicht implementiert).
//   DH     : NUR eine Gruppe gleichzeitig, bis WeirdIKE INVALID_KE_PAYLOAD (KE-Retry) kann.
#pragma once
#include <Arduino.h>

enum class IpsecAlgoGroup : uint8_t { Dh, IkeEnc, IkeHash, EspEnc, EspHash };

struct IpsecAlgo {
    const char* id;         // stabile Kennung (Formular + NVS, CSV-Auswahl)
    const char* label;      // UI-Text (LANCOM-Bezeichnung)
    bool        supported;  // heute auf der Leitung nutzbar -- sonst ausgegraut
    uint16_t    iana;       // IANA-Transform-ID (ENCR / PRF / INTEG / DH, siehe oben)
    uint16_t    iana2;      // nur IKE-Hash: INTEG-ID zum PRF in `iana`
    uint16_t    keyBits;    // nur ENC: KEY_LENGTH-Attribut (0 = keines)
    bool        lancomDefault; // im LANCOM-Profil DEFAULT angehakt (Vorgabe fuer neue Konfigurationen)
};

const IpsecAlgo* ipsecAlgoTable(IpsecAlgoGroup g, int& count);
const IpsecAlgo* ipsecAlgoFind(IpsecAlgoGroup g, const String& id);
const char*      ipsecAlgoGroupName(IpsecAlgoGroup g);        // fuer Fehlermeldungen

bool ipsecPfsSupported();                       // false, bis CREATE_CHILD_SA+KE da ist
bool ipsecAuthSupported(const String& auth);    // "psk" ja; "eap"/"cert" noch nicht
bool ipsecProtoSupported(const String& proto);  // "ikev2" ja; "l2tp" noch nicht

// CSV-Auswahl ("dh14,dh15") pruefen: leer -> Fehlertext, unbekannte Kennung -> Fehlertext,
// nicht implementierte Kennung -> Fehlertext (nennt den Algorithmus). "" = in Ordnung.
String ipsecAlgoCheck(IpsecAlgoGroup g, const String& csv);
bool   ipsecAlgoListHas(const String& csv, const char* id);

// CSV-Auswahl in Tabellenzeilen aufloesen (fuer den Policy-Bau). Liefert die Anzahl gefundener
// Zeilen (max `cap`) oder -1 bei einer unbekannten Kennung (dann steht sie in `bad`).
int ipsecAlgoResolve(IpsecAlgoGroup g, const String& csv, const IpsecAlgo** out, int cap, String& bad);

// Menschenlesbare Namen fuer IANA-IDs (VPN-Status: "tatsaechlich ausgehandelt").
String ipsecEncrName(uint16_t encr, uint16_t keyBits);   // "AES-CBC-256"
String ipsecPrfName(uint16_t prf);                        // "PRF-SHA-512"
String ipsecIntegName(uint16_t integ);                    // "HMAC-SHA-512-256"
String ipsecDhName(uint16_t dh);                          // "DH14"
