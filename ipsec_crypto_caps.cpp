// ipsec_crypto_caps.cpp -- siehe Header. Reihenfolge = Anzeige-Reihenfolge (wie im LANCOM-Client).
#include "ipsec_crypto_caps.h"

//                id            label                              supp   iana iana2 bits
static const IpsecAlgo kDh[] = {
    {"dh2",  "DH2 - MODP-1024",       false,  2, 0, 0},
    {"dh5",  "DH5 - MODP-1536",       false,  5, 0, 0},
    {"dh14", "DH14 - MODP-2048",      true,  14, 0, 0, true},
    {"dh15", "DH15 - MODP-3072",      true,  15, 0, 0},
    {"dh16", "DH16 - MODP-4096",      true,  16, 0, 0},
    {"dh19", "DH19 - ECP-256",        true,  19, 0, 0},
    {"dh20", "DH20 - ECP-384",        true,  20, 0, 0},
    {"dh21", "DH21 - ECP-521",        true,  21, 0, 0},
    {"dh28", "DH28 - Brainpool-256",  true,  28, 0, 0},
    {"dh29", "DH29 - Brainpool-384",  true,  29, 0, 0},
    {"dh30", "DH30 - Brainpool-512",  true,  30, 0, 0},
    {"dh31", "DH31 - Curve25519",     true,  31, 0, 0},
    {"dh32", "DH32 - Curve448",       false, 32, 0, 0},
};
static const IpsecAlgo kIkeEnc[] = {
    {"aes128cbc", "AES-CBC-128",          true,  12, 0, 128},
    {"aes192cbc", "AES-CBC-192",          true,  12, 0, 192},
    {"aes256cbc", "AES-CBC-256",          true,  12, 0, 256, true},
    {"aes128gcm", "AES-GCM-128",          false, 20, 0, 128},
    {"aes192gcm", "AES-GCM-192",          false, 20, 0, 192},
    {"aes256gcm", "AES-GCM-256",          false, 20, 0, 256},
    {"3des",      "3DES",                 false,  3, 0, 0},
    {"chacha20",  "ChaCha20-Poly1305",    false, 28, 0, 0},
};
static const IpsecAlgo kIkeHash[] = {   // iana = PRF, iana2 = INTEG
    // SHA-1 (AP9): PRF-HMAC-SHA1 + HMAC-SHA1-96 -- WeirdIKE cd5ad88, CI-bewiesen gegen strongSwan
    // (IKE + Child) inkl. Negativtests (ohne Freigabe -> NO_PROPOSAL_CHOSEN, kein Downgrade).
    {"sha1",   "SHA-1",   true,  2,  2, 0, true},
    {"sha256", "SHA-256", true,  5, 12, 0, true},
    {"sha384", "SHA-384", true,  6, 13, 0},
    {"sha512", "SHA-512", true,  7, 14, 0},
    {"md5",    "MD5",     false, 1,  1, 0},
};
static const IpsecAlgo kEspEnc[] = {
    {"aes128cbc", "AES-CBC-128",          true,  12, 0, 128},
    {"aes192cbc", "AES-CBC-192",          true,  12, 0, 192},
    {"aes256cbc", "AES-CBC-256",          true,  12, 0, 256, true},
    {"aes128gcm", "AES-GCM-128",          false, 20, 0, 128},
    {"aes192gcm", "AES-GCM-192",          false, 20, 0, 192},
    {"aes256gcm", "AES-GCM-256",          false, 20, 0, 256},
    {"3des",      "3DES",                 false,  3, 0, 0},
    {"chacha20",  "ChaCha20-Poly1305",    false, 28, 0, 0},
    {"null",      "NULL (keine Verschluesselung)", false, 11, 0, 0},
};
static const IpsecAlgo kEspHash[] = {   // iana = INTEG
    // SHA-1 (AP9): ESP HMAC-SHA1-96 (12-B ICV) -- Kernel-ESP-Interop gegen strongSwan CI-bewiesen.
    {"sha1",   "SHA-1",   true,   2, 0, 0, true},
    {"sha256", "SHA-256", true,  12, 0, 0, true},
    {"sha384", "SHA-384", true,  13, 0, 0},
    {"sha512", "SHA-512", true,  14, 0, 0},
    {"md5",    "MD5",     false,  1, 0, 0},
    {"null",   "NULL (nur mit AEAD, z.B. AES-GCM)", false, 0, 0, 0},
};

const IpsecAlgo* ipsecAlgoTable(IpsecAlgoGroup g, int& count) {
    switch (g) {
        case IpsecAlgoGroup::Dh:      count = sizeof(kDh)/sizeof(kDh[0]);           return kDh;
        case IpsecAlgoGroup::IkeEnc:  count = sizeof(kIkeEnc)/sizeof(kIkeEnc[0]);   return kIkeEnc;
        case IpsecAlgoGroup::IkeHash: count = sizeof(kIkeHash)/sizeof(kIkeHash[0]); return kIkeHash;
        case IpsecAlgoGroup::EspEnc:  count = sizeof(kEspEnc)/sizeof(kEspEnc[0]);   return kEspEnc;
        case IpsecAlgoGroup::EspHash: count = sizeof(kEspHash)/sizeof(kEspHash[0]); return kEspHash;
    }
    count = 0; return nullptr;
}

const char* ipsecAlgoGroupName(IpsecAlgoGroup g) {
    switch (g) {
        case IpsecAlgoGroup::Dh:      return "DH-Gruppe";
        case IpsecAlgoGroup::IkeEnc:  return "IKE-SA-Verschluesselung";
        case IpsecAlgoGroup::IkeHash: return "IKE-SA-Hash";
        case IpsecAlgoGroup::EspEnc:  return "Child-SA-Verschluesselung";
        case IpsecAlgoGroup::EspHash: return "Child-SA-Hash";
    }
    return "?";
}

const IpsecAlgo* ipsecAlgoFind(IpsecAlgoGroup g, const String& id) {
    int n = 0; const IpsecAlgo* t = ipsecAlgoTable(g, n);
    for (int i = 0; i < n; i++) if (id == t[i].id) return &t[i];
    return nullptr;
}

// PFS (AP5.3): CREATE_CHILD_SA mit KE -- WeirdIKE ebaa901, CI-bewiesen gegen strongSwan (eigener Rekey
// mit DH14, KEYMAT aus g^ir | Ni | Nr; Pings durch die neue SA; alte SA per DELETE abgebaut).
bool ipsecPfsSupported()                       { return true; }
// EAP-MSCHAPv2 (AP7/AP8): Code komplett (WeirdIKE 4dd8a8c + Runtime/UI). Freischaltung NUR mit gruenem
// strongSwan-Interop-Job (interop-eap-strongswan); bis dahin bleibt der Schalter 0 und EAP ausgegraut.
#ifndef IPSEC_EAP_CI_PROVEN
#define IPSEC_EAP_CI_PROVEN 1   // WeirdIKE 2a37736: interop-eap-strongswan gruen (positiv + 3 Negativfaelle)
#endif
// Der Job prueft: Server-Zertifikat + Signatur
// werden VOR EAP geprueft (falsche CA / falsche Server-Identitaet -> Abbruch ohne Passwort), falsches
// Passwort -> sauberer Auth-Fehler; Configuration Payload (Tunnel-IP/DNS) inklusive.
bool ipsecAuthSupported(const String& auth)    { return auth == "psk" || (auth == "eap" && IPSEC_EAP_CI_PROVEN); }
bool ipsecProtoSupported(const String& proto)  { return proto == "ikev2"; }

bool ipsecAlgoListHas(const String& csv, const char* id) {
    int start = 0;
    while (start <= (int)csv.length()) {
        int c = csv.indexOf(',', start); if (c < 0) c = csv.length();
        String tok = csv.substring(start, c); tok.trim();
        if (tok.length() && tok == id) return true;
        start = c + 1;
    }
    return false;
}

String ipsecAlgoCheck(IpsecAlgoGroup g, const String& csv) {
    int kept = 0, start = 0;
    while (start <= (int)csv.length()) {
        int c = csv.indexOf(',', start); if (c < 0) c = csv.length();
        String tok = csv.substring(start, c); tok.trim();
        start = c + 1;
        if (!tok.length()) continue;
        const IpsecAlgo* a = ipsecAlgoFind(g, tok);
        if (!a) return String(ipsecAlgoGroupName(g)) + ": unbekannte Kennung '" + tok + "'.";
        if (!a->supported) return String(ipsecAlgoGroupName(g)) + ": " + a->label + " ist noch nicht implementiert (ausgegraut).";
        kept++;
    }
    if (!kept) return String(ipsecAlgoGroupName(g)) + ": mindestens einen Algorithmus waehlen.";
    return "";
}

int ipsecAlgoResolve(IpsecAlgoGroup g, const String& csv, const IpsecAlgo** out, int cap, String& bad) {
    int n = 0, start = 0;
    bad = "";
    while (start <= (int)csv.length()) {
        int c = csv.indexOf(',', start); if (c < 0) c = csv.length();
        String tok = csv.substring(start, c); tok.trim();
        start = c + 1;
        if (!tok.length()) continue;
        const IpsecAlgo* a = ipsecAlgoFind(g, tok);
        if (!a) { bad = tok; return -1; }
        if (n < cap) out[n++] = a;
    }
    return n;
}

String ipsecEncrName(uint16_t encr, uint16_t keyBits) {
    String base;
    switch (encr) {
        case 12: base = "AES-CBC"; break;
        case 20: base = "AES-GCM"; break;
        case 3:  base = "3DES"; break;
        case 28: base = "ChaCha20-Poly1305"; break;
        case 11: base = "NULL"; break;
        default: base = "ENCR-" + String(encr); break;
    }
    if (keyBits) base += "-" + String(keyBits);
    return base;
}
String ipsecPrfName(uint16_t prf) {
    switch (prf) {
        case 1: return "PRF-MD5";
        case 2: return "PRF-SHA-1";
        case 5: return "PRF-SHA-256";
        case 6: return "PRF-SHA-384";
        case 7: return "PRF-SHA-512";
        default: return "PRF-" + String(prf);
    }
}
String ipsecIntegName(uint16_t integ) {
    switch (integ) {
        case 0:  return "NULL";
        case 1:  return "HMAC-MD5-96";
        case 2:  return "HMAC-SHA-1-96";
        case 12: return "HMAC-SHA-256-128";
        case 13: return "HMAC-SHA-384-192";
        case 14: return "HMAC-SHA-512-256";
        default: return "INTEG-" + String(integ);
    }
}
String ipsecDhName(uint16_t dh) { return "DH" + String(dh); }
