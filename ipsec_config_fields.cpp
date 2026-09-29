// ============================================================================
// ipsec_config_fields.cpp -- siehe ipsec_config_fields.h (EIN Feld-Layer fuer Web + Konsole).
//
// Baustein IPSEC (weirdos_features.h): bei WEIRDOS_FEATURE_IPSEC=0 bleibt nur der Stub am Ende
// dieser Datei (leere Feldtabelle, jede Zuweisung lehnt ab).
// ============================================================================
#include "weirdos_features.h"
#include "ipsec_config_fields.h"
#if WEIRDOS_FEATURE_IPSEC

// Feldtabelle. Enum-Werte sind die gespeicherten Kennungen (identisch mit den Web-<option>-Werten).
// Identitaeten: Typ und Wert sind GETRENNTE Felder -- kein Erraten des Typs aus dem Text, auch seriell.
static const IpsecFieldDef kFields[] = {
    { "mode",            "mode",      IpsecFieldType::Enum,     IpsecFieldRole::Both,   nullptr, false, "client|server",                 IpsecAlgoGroup::Dh, 0, 0,     "Rolle: Client verbindet sich in ein fremdes VPN, Server stellt eines bereit" },
    { "active",          "active",    IpsecFieldType::Bool,     IpsecFieldRole::Both,   nullptr, true,  nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "Dienst freigeschaltet (0/1)" },
    { "autoconnect",     "autoconn",  IpsecFieldType::Bool,     IpsecFieldRole::Both,   "fv4",   true,  nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "Autostart beim Boot + Neuverbinden nach Aenderungen (0/1)" },
    { "underlay",        "underlay",  IpsecFieldType::Enum,     IpsecFieldRole::Both,   nullptr, false, "auto|modem|wifi",               IpsecAlgoGroup::Dh, 0, 0,     "Egress-Interface (Egress-Policy)" },
    { "proto",           "proto",     IpsecFieldType::Enum,     IpsecFieldRole::Both,   nullptr, false, "ikev2|l2tp",                    IpsecAlgoGroup::Dh, 0, 0,     "Protokoll (l2tp noch nicht implementiert -> wird beim Speichern abgelehnt)" },
    { "server",          "srvhost",   IpsecFieldType::Text,     IpsecFieldRole::Client, nullptr, false, nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "Gateway-Host oder -IP (z.B. FRITZ!Box-DynDNS)" },
    { "port",            "srvport",   IpsecFieldType::Int,      IpsecFieldRole::Client, nullptr, false, nullptr,                         IpsecAlgoGroup::Dh, 1, 65535, "IKE-Port (500; NAT-T wechselt selbst auf 4500)" },
    { "auth",            "auth",      IpsecFieldType::Enum,     IpsecFieldRole::Client, nullptr, false, "psk|eap|cert",                  IpsecAlgoGroup::Dh, 0, 0,     "Authentifizierung: psk | eap (EAP-MSCHAPv2: eap-user/eap-pass; Server-Vertrauen per trust-mode, ca-pem nur bei own/public-plus) | cert (noch nicht)" },
    { "psk",             "psk",       IpsecFieldType::Secret,   IpsecFieldRole::Client, nullptr, false, nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "Pre-Shared Key (nur setzen; nie angezeigt)" },
    { "eap-user",        "eapuser",   IpsecFieldType::Text,     IpsecFieldRole::Client, nullptr, false, nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "EAP-Benutzername (= IDi bei auth=eap, wenn local-id leer)" },
    { "eap-pass",        "eappass",   IpsecFieldType::Secret,   IpsecFieldRole::Client, nullptr, false, nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "EAP-Passwort (nur setzen; nie angezeigt)" },
    { "ca-pem",          "capem",     IpsecFieldType::Text,     IpsecFieldRole::Client, nullptr, false, nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "Vertrauensanker PEM: CA-Zertifikat, Zwischen-CA als expliziter Anker oder das exakte/selbstsignierte Serverzertifikat; Pflicht bei trust-mode=own, Zusatz-Anker bei public-plus. 'set ca-pem' ohne Wert = Einfuegemodus bis END" },
    { "extra-pem",       "extrapem",  IpsecFieldType::Text,     IpsecFieldRole::Client, nullptr, false, nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "Kettenmaterial PEM (Zwischenzertifikate), beendet NIE eine Kette; bei public-plus/own. 'set extra-pem' ohne Wert = Einfuegemodus bis END" },
    { "trust-mode",      "trust",     IpsecFieldType::Enum,     IpsecFieldRole::Client, "fv5",   false, "public|public-plus|own|none",   IpsecAlgoGroup::Dh, 0, 0,     "Vertrauensmodell fuer das Server-Zertifikat (auth=eap): public = eingebaute oeffentliche Root-CAs | public-plus = oeffentliche CAs + ca-pem (Zusatz-Anker) + extra-pem (Kettenmaterial) | own = nur eigene Vertrauensanker (ca-pem) | none = KEINE Vertrauenspruefung, nicht empfohlen (IKE-AUTH-Signatur wird weiter geprueft)" },
    { "natt",            "natt",      IpsecFieldType::Bool,     IpsecFieldRole::Client, "fv2",   true,  nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "NAT-Traversal (UDP-4500) zulassen (0/1)" },
    { "local-id-type",   "localidt",  IpsecFieldType::Enum,     IpsecFieldRole::Client, "fv2",   false, "sourceip|eapuser|keyid|fqdn|rfc822|ipv4", IpsecAlgoGroup::Dh, 0, 0, "Typ der eigenen Identitaet ('Senden als'); sourceip = eigene Uplink-IP (nur PSK), eapuser = EAP-Benutzername als IDi (nur auth=eap, kein Wert)" },
    { "local-id",        "localid",   IpsecFieldType::Text,     IpsecFieldRole::Client, nullptr, false, nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "Wert der eigenen Identitaet (FRITZ!Box: VPN-Benutzername als keyid)" },
    { "remote-id-type",  "remoteidt", IpsecFieldType::Enum,     IpsecFieldRole::Client, "fv2",   false, "none|keyid|fqdn|rfc822|ipv4",   IpsecAlgoGroup::Dh, 0, 0,     "Typ der erwarteten Server-Identitaet ('Erwarten als'); none = keine feste" },
    { "remote-id",       "remoteid",  IpsecFieldType::Text,     IpsecFieldRole::Client, nullptr, false, nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "Wert der erwarteten Server-Identitaet (leer = keine)" },
    { "local-tunnel-ip", "localtip",  IpsecFieldType::Text,     IpsecFieldRole::Client, "fv2",   false, nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "eigene Tunnel-/TSi-Adresse; leer = automatisch vom Gateway (CP)" },
    { "remote-subnets",  "rsubnets",  IpsecFieldType::Text,     IpsecFieldRole::Client, nullptr, false, nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "Zielnetze hinter dem Gateway (CIDR, mehrere kommagetrennt = mehrere TSr-Selektoren, bis 4); leer oder 0.0.0.0/0 = TSr any, das Gateway schraenkt ein. Geroutet wird auf ipsec0 nur das ERSTE Netz; eine Standardroute durch den Tunnel (Full Tunnel) wird NICHT installiert" },
    { "ike-enc",         "ikeenc",    IpsecFieldType::AlgoList, IpsecFieldRole::Client, "fv3",   false, nullptr,                         IpsecAlgoGroup::IkeEnc,  0, 0, "IKE-SA-Verschluesselung, Allowlist CSV" },
    { "ike-hash",        "ikehash",   IpsecFieldType::AlgoList, IpsecFieldRole::Client, "fv3",   false, nullptr,                         IpsecAlgoGroup::IkeHash, 0, 0, "IKE-SA-Hash (PRF + Integritaet), Allowlist CSV" },
    { "dh",              "ikedh",     IpsecFieldType::AlgoList, IpsecFieldRole::Client, "fv3",   false, nullptr,                         IpsecAlgoGroup::Dh,      0, 0, "DH-Gruppen (IKE_SA_INIT; erste = KE), Allowlist CSV" },
    { "esp-enc",         "espenc",    IpsecFieldType::AlgoList, IpsecFieldRole::Client, "fv3",   false, nullptr,                         IpsecAlgoGroup::EspEnc,  0, 0, "Child-SA-Verschluesselung (ESP), Allowlist CSV" },
    { "esp-hash",        "esphash",   IpsecFieldType::AlgoList, IpsecFieldRole::Client, "fv3",   false, nullptr,                         IpsecAlgoGroup::EspHash, 0, 0, "Child-SA-Integritaet (ESP), Allowlist CSV" },
    { "pfs",             "pfs",       IpsecFieldType::Bool,     IpsecFieldRole::Client, "fv3",   false, nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "PFS beim Child-Rekey (0/1)" },
    { "ike-lifetime",    "ikelt",     IpsecFieldType::Int,      IpsecFieldRole::Client, "fv6",   false, nullptr,                         IpsecAlgoGroup::Dh, 0, 65535, "IKE-SA-Lebensdauer in s: Rekey durch uns danach (0 = nur Peer/manuell; LANCOM 28800)" },
    { "child-lifetime",  "childlt",   IpsecFieldType::Int,      IpsecFieldRole::Client, "fv6",   false, nullptr,                         IpsecAlgoGroup::Dh, 0, 65535, "Child-SA-Lebensdauer in s (Soft-Rekey; 0 = WeirdIKE-Vorgabe 3300)" },
    { "child-lifetime-mb","childmb",  IpsecFieldType::Int,      IpsecFieldRole::Client, "fv6",   false, nullptr,                         IpsecAlgoGroup::Dh, 0, 65535, "Child-SA-Lebensdauer nach Datenmenge in MiB (0 = kein Byte-Limit; Zeit und Bytes gelten zusammen)" },
    { "dpd",             "dpd",       IpsecFieldType::Bool,     IpsecFieldRole::Client, "fv6",   true,  nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "Dead Peer Detection: eigene Proben (0/1); Peer-Proben werden immer beantwortet" },
    { "dpd-interval",    "dpdint",    IpsecFieldType::Int,      IpsecFieldRole::Client, "fv6",   false, nullptr,                         IpsecAlgoGroup::Dh, 5, 3600,  "DPD: Sekunden Eingangsstille bis zur Probe (LANCOM 20)" },
    { "dpd-retries",     "dpdretry",  IpsecFieldType::Int,      IpsecFieldRole::Client, "fv6",   false, nullptr,                         IpsecAlgoGroup::Dh, 1, 20,    "DPD: Wiederholungen einer Probe, bevor der Peer als tot gilt (LANCOM 8)" },
    { "natt-keepalive",  "natka",     IpsecFieldType::Int,      IpsecFieldRole::Client, "fv6",   false, nullptr,                         IpsecAlgoGroup::Dh, 5, 600,   "NAT-T-Keepalive-Intervall in s (UDP/4500, nur hinter NAT)" },
    { "listen-port",     "listenport",IpsecFieldType::Int,      IpsecFieldRole::Server, nullptr, false, nullptr,                         IpsecAlgoGroup::Dh, 1, 65535, "Server: IKE-Port" },
    { "pool-subnet",     "poolsub",   IpsecFieldType::Text,     IpsecFieldRole::Server, nullptr, false, nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "Server: virtuelle Client-IPs (CIDR)" },
    { "server-ident",    "srvident",  IpsecFieldType::Text,     IpsecFieldRole::Server, nullptr, false, nullptr,                         IpsecAlgoGroup::Dh, 0, 0,     "Server: eigene Identitaet" },
};

const IpsecFieldDef* ipsecFieldTable(int& count) { count = (int)(sizeof(kFields) / sizeof(kFields[0])); return kFields; }

const IpsecFieldDef* ipsecFieldFind(const String& key) {
    for (const IpsecFieldDef& f : kFields) if (key.equalsIgnoreCase(f.key)) return &f;
    return nullptr;
}

// Zugriff auf das Strukturfeld ueber den Schluessel (der einzige Ort, der die Feldnamen kennt).
static String* strField(IpsecConfig& c, const char* key) {
    if (!strcmp(key, "mode")) return &c.mode;             if (!strcmp(key, "underlay")) return &c.underlay;
    if (!strcmp(key, "proto")) return &c.proto;           if (!strcmp(key, "server")) return &c.serverHost;
    if (!strcmp(key, "auth")) return &c.auth;             if (!strcmp(key, "eap-user")) return &c.eapUser;
    if (!strcmp(key, "extra-pem")) return &c.extraPem;   if (!strcmp(key, "trust-mode")) return &c.trustMode;
    if (!strcmp(key, "ca-pem")) return &c.caPem;          if (!strcmp(key, "local-id-type")) return &c.localIdType;
    if (!strcmp(key, "local-id")) return &c.localId;      if (!strcmp(key, "remote-id-type")) return &c.remoteIdType;
    if (!strcmp(key, "remote-id")) return &c.remoteId;    if (!strcmp(key, "local-tunnel-ip")) return &c.localTunnelIp;
    if (!strcmp(key, "remote-subnets")) return &c.remoteSubnets;
    if (!strcmp(key, "ike-enc")) return &c.ikeEnc;        if (!strcmp(key, "ike-hash")) return &c.ikeHash;
    if (!strcmp(key, "dh")) return &c.ikeDh;              if (!strcmp(key, "esp-enc")) return &c.espEnc;
    if (!strcmp(key, "esp-hash")) return &c.espHash;      if (!strcmp(key, "pool-subnet")) return &c.poolSubnet;
    if (!strcmp(key, "server-ident")) return &c.serverIdent;
    return nullptr;
}
static bool* boolField(IpsecConfig& c, const char* key) {
    if (!strcmp(key, "active")) return &c.active;   if (!strcmp(key, "autoconnect")) return &c.autoConnect;
    if (!strcmp(key, "natt")) return &c.natT;       if (!strcmp(key, "pfs")) return &c.pfs;
    if (!strcmp(key, "dpd")) return &c.dpd;
    return nullptr;
}
static uint16_t* intField(IpsecConfig& c, const char* key) {
    if (!strcmp(key, "port")) return &c.serverPort;   if (!strcmp(key, "listen-port")) return &c.listenPort;
    if (!strcmp(key, "ike-lifetime")) return &c.ikeLifetimeS;     if (!strcmp(key, "child-lifetime")) return &c.childLifetimeS;
    if (!strcmp(key, "child-lifetime-mb")) return &c.childLifetimeMb; if (!strcmp(key, "dpd-interval")) return &c.dpdIntervalS;
    if (!strcmp(key, "dpd-retries")) return &c.dpdRetries;        if (!strcmp(key, "natt-keepalive")) return &c.nattKeepaliveS;
    return nullptr;
}

String ipsecFieldGet(const IpsecConfig& c, const IpsecFieldDef& f) {
    IpsecConfig& m = const_cast<IpsecConfig&>(c);   // nur lesend
    switch (f.type) {
        case IpsecFieldType::Bool:   { bool* b = boolField(m, f.key); return b ? String(*b ? "1" : "0") : String(""); }
        case IpsecFieldType::Int:    { uint16_t* i = intField(m, f.key); return i ? String((unsigned)*i) : String(""); }
        case IpsecFieldType::Secret: return "";   // nie ausgeben
        default:                     { String* s = strField(m, f.key); return s ? *s : String(""); }
    }
}

static bool enumHas(const char* list, const String& v) {
    String l(list); int start = 0;
    while (start <= (int)l.length()) {
        int bar = l.indexOf('|', start); if (bar < 0) bar = l.length();
        if (l.substring(start, bar) == v) return true;
        start = bar + 1;
    }
    return false;
}

String ipsecFieldSet(IpsecConfig& c, const IpsecFieldDef& f, const String& valueIn) {
    String v = valueIn; v.trim();
    switch (f.type) {
        case IpsecFieldType::Bool: {
            bool* b = boolField(c, f.key); if (!b) return "internes Feld fehlt";
            String lv = v; lv.toLowerCase();
            if (lv == "1" || lv == "on" || lv == "an" || lv == "true" || lv == "ja")  { *b = true;  return ""; }
            if (lv == "0" || lv == "off" || lv == "aus" || lv == "false" || lv == "nein") { *b = false; return ""; }
            return String(f.key) + ": erwartet 0/1 (on/off)";
        }
        case IpsecFieldType::Int: {
            uint16_t* i = intField(c, f.key); if (!i) return "internes Feld fehlt";
            if (!v.length()) return String(f.key) + ": Zahl erwartet";
            for (size_t k = 0; k < v.length(); k++) if (!isDigit(v[k])) return String(f.key) + ": Zahl erwartet";
            long n = v.toInt();
            if (n < f.minInt || n > f.maxInt) return String(f.key) + ": Bereich " + String(f.minInt) + ".." + String(f.maxInt);
            *i = (uint16_t)n; return "";
        }
        case IpsecFieldType::Enum: {
            String* s = strField(c, f.key); if (!s) return "internes Feld fehlt";
            if (!enumHas(f.enumValues, v)) return String(f.key) + ": erlaubt sind " + String(f.enumValues);
            *s = v; return "";
        }
        case IpsecFieldType::AlgoList: {
            String* s = strField(c, f.key); if (!s) return "internes Feld fehlt";
            String e = ipsecAlgoCheck(f.algoGroup, v);   // dieselbe Pruefung wie die Web-UI/saveConfig
            if (e.length()) return String(f.key) + ": " + e;
            *s = v; return "";
        }
        case IpsecFieldType::Text: {
            String* s = strField(c, f.key); if (!s) return "internes Feld fehlt";
            *s = v; return "";
        }
        case IpsecFieldType::Secret:
            return String(f.key) + ": Secret -- wird ueber den Secret-Pfad gesetzt";
    }
    return "unbekannter Feldtyp";
}

String ipsecFieldAllowed(const IpsecFieldDef& f) {
    switch (f.type) {
        case IpsecFieldType::Bool:  return "0|1";
        case IpsecFieldType::Int:   return String(f.minInt) + ".." + String(f.maxInt);
        case IpsecFieldType::Enum:  return String(f.enumValues);
        case IpsecFieldType::AlgoList: {
            int n = 0; const IpsecAlgo* t = ipsecAlgoTable(f.algoGroup, n); String o;
            for (int i = 0; i < n; i++) { if (o.length()) o += ","; o += t[i].id; if (!t[i].supported) o += "(nicht implementiert)"; }
            return o + "  (CSV)";
        }
        case IpsecFieldType::Secret: return "<geheim>";
        default: return "Text";
    }
}

String ipsecConfigDump(const IpsecConfig& c, bool pskSet, size_t pskLen, bool eapPassSet) {
    int n = 0; const IpsecFieldDef* t = ipsecFieldTable(n); String o;
    bool client = (c.mode != "server");
    for (int i = 0; i < n; i++) {
        const IpsecFieldDef& f = t[i];
        if ((f.role == IpsecFieldRole::Client && !client) || (f.role == IpsecFieldRole::Server && client)) continue;
        String v;
        if (f.type == IpsecFieldType::Secret) {
            if (!strcmp(f.key, "psk")) v = pskSet ? ("gesetzt (" + String((unsigned)pskLen) + " Zeichen)") : "NICHT gesetzt";
            else v = eapPassSet ? "gesetzt" : "NICHT gesetzt";
        } else if (!strcmp(f.key, "ca-pem")) {
            v = c.caPem.length() ? ("PEM gesetzt (" + String(c.caPem.length()) + " Zeichen)") : "leer";
        } else if (!strcmp(f.key, "extra-pem")) {
            v = c.extraPem.length() ? ("PEM gesetzt (" + String(c.extraPem.length()) + " Zeichen)") : "leer";
        } else {
            v = ipsecFieldGet(c, f); if (!v.length()) v = "(leer)";
        }
        char line[48]; snprintf(line, sizeof(line), "  %-16s = ", f.key);
        o += line; o += v; o += "\r\n";
    }
    return o;
}

#else  // !WEIRDOS_FEATURE_IPSEC
// Stub: IPsec nicht im Build enthalten (WEIRDOS_FEATURE_IPSEC=0)
// Leere Feldtabelle (count 0, aber ein gueltiger Zeiger), kein Schluessel bekannt, jede Zuweisung
// wird abgelehnt. Web-POST /ipsec-save und Konsole 'ipsec fields|get|set' laufen damit ins Leere,
// ohne den echten Feld-Layer zu linken.

// Nullinitialisierter Platzhalter, damit ipsecFieldTable() nie nullptr liefert (count bleibt 0).
static const IpsecFieldDef kFieldsNone[1] = {};

const IpsecFieldDef* ipsecFieldTable(int& count) { count = 0; return kFieldsNone; }
const IpsecFieldDef* ipsecFieldFind(const String&) { return nullptr; }
String ipsecFieldGet(const IpsecConfig&, const IpsecFieldDef&) { return ""; }
String ipsecFieldSet(IpsecConfig&, const IpsecFieldDef&, const String&) { return "IPsec nicht im Build enthalten (WEIRDOS_FEATURE_IPSEC=0)"; }
String ipsecFieldAllowed(const IpsecFieldDef&) { return ""; }
String ipsecConfigDump(const IpsecConfig&, bool, size_t, bool) { return "  IPsec: nicht im Build enthalten (WEIRDOS_FEATURE_IPSEC=0)\r\n"; }

#endif // WEIRDOS_FEATURE_IPSEC
