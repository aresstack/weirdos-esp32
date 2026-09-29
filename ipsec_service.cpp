// ============================================================================
// ipsec_service.cpp -- IPsec/IKEv2 (+ L2TP/IPsec) Backend. Siehe ipsec_service.h.
// Config/Persistenz/Status voll funktionsfaehig; IKE/ESP-Runtime noch nicht (ehrlich in
// connect()/statusJson()). Bewusst lwIP-frei, analog WireGuardService.
// ============================================================================
#include "ipsec_service.h"
#include "ipsec_crypto_caps.h"   // Richtlinie (DH/Enc/Hash/PFS/Auth) gegen Faehigkeitstabelle pruefen
#include "ipsec_runtime.h"
#include "wan_service.h"     // Autostart-Guard: nur connecten wenn WAN echtes Internet hat
#include <Preferences.h>

IpsecService ipsecService;

// JSON-String-Escape (Config-Felder sind Freitext: Host/Identity/Proposals koennten " enthalten).
static String jesc(const String& s) {
    String o; o.reserve(s.length() + 4);
    for (size_t i = 0; i < s.length(); i++) {
        char c = s[i];
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (c == '\n' || c == '\r' || c == '\t') { /* weglassen */ }
        else if ((uint8_t)c >= 0x20) o += c;
    }
    return o;
}

// ---- Backend/Status --------------------------------------------------------
void IpsecService::begin() {
    // Eingebauter Beobachter: gespeicherte Konfiguration -> Verbindungs-Lifecycle folgt.
    addConfigObserver(&IpsecService::lifecycleObserver, this);
    // HW-Gate: war der letzte Reset ein Panic/WDT mit IPsec am Zug, steht hier der letzte Schritt.
    ipsecRuntimeBootReport();
}

bool IpsecService::addConfigObserver(ConfigObserver cb, void* ctx) {
    if (!cb || observerCount_ >= kMaxObservers) return false;
    observers_[observerCount_].cb = cb; observers_[observerCount_].ctx = ctx; observerCount_++;
    return true;
}

void IpsecService::notifyConfigChanged() {
    for (int i = 0; i < observerCount_; i++) observers_[i].cb(cfg_, observers_[i].ctx);
}

// Eingebauter Lifecycle-Beobachter (Speichern != Abriss): deaktiviert -> Trennen planen; aktiv +
// Automatik + KEINE stehende Verbindung -> Verbinden planen (z.B. nach FAILED korrigierte Werte);
// steht der Tunnel, laeuft er mit der vorherigen Konfiguration weiter, bis 'Neu verbinden' bzw.
// 'Speichern & neu verbinden' gedrueckt wird.
void IpsecService::lifecycleObserver(const IpsecConfig& cfg, void* ctx) {
    IpsecService* self = static_cast<IpsecService*>(ctx);
    // Deaktiviert -> ausdruecklich trennen (das ist KEIN manueller Stop im Sinne von "Trennen"-Knopf,
    // aber die Runtime muss beendet werden). Aktiv -> nur signalisieren; supervise() (loop-Task)
    // entscheidet anhand des echten Runtime-Zustands, ob (neu) verbunden wird. KEIN ipsecRuntime.*
    // aus dem HTTP-Task (Owner-Trennung).
    if (!cfg.active) { self->requestDeactivate(); return; }
    self->signalConfigSaved();
}

// Feature abgeschaltet (cfg.active=false): Runtime beenden, aber NICHT als manuellen "Trennen"-Stop
// werten -- sonst bliebe eine spaetere Reaktivierung trotz "Automatisch verbinden" blockiert.
void IpsecService::requestRekey() { lock(); cmd_ = Cmd::Rekey; unlock(); }
void IpsecService::requestIkeRekey() { lock(); cmd_ = Cmd::IkeRekey; unlock(); }

void IpsecService::requestDeactivate() {
    lock();
    cmd_ = Cmd::Disconnect;
    // manualStop_ bewusst unveraendert lassen.
    unlock();
}

// HTTP-Task: nur ein Flag setzen. Die Reconnect-Entscheidung faellt in supervise().
void IpsecService::signalConfigSaved() {
    lock();
    configSaved_ = true;
    unlock();
}

bool IpsecService::runtimeAvailable() const {
    // WeirdIKE-Runtime ist eingebunden -- unterstuetzt Client + IKEv2 + PSK (der Hardware-Pfad)
    // mit der in ipsec_crypto_caps.h freigegebenen Richtlinie.
    return cfg_.mode == "client" && ipsecProtoSupported(cfg_.proto) && ipsecAuthSupported(cfg_.auth)
        && policyError(cfg_).length() == 0;
}

// Richtlinie gegen die Faehigkeitstabelle pruefen (EINE Quelle: ipsec_crypto_caps.h). "" = ok.
// Wird beim Speichern (Ablehnung, nichts persistiert) und vor connect() angewendet.
String IpsecService::policyError(const IpsecConfig& c) {
    if (!ipsecProtoSupported(c.proto)) return "L2TP/IPsec ist noch nicht implementiert (ausgegraut).";
    if (!ipsecAuthSupported(c.auth))   return (c.auth == "eap")
        ? "Benutzer + Passwort (EAP-MSCHAPv2) ist noch nicht implementiert (ausgegraut) - PSK verwenden."
        : "Zertifikat-Authentifizierung ist noch nicht implementiert (ausgegraut) - PSK verwenden.";
    String e;
    if ((e = ipsecAlgoCheck(IpsecAlgoGroup::Dh,      c.ikeDh)).length())   return e;
    if ((e = ipsecAlgoCheck(IpsecAlgoGroup::IkeEnc,  c.ikeEnc)).length())  return e;
    if ((e = ipsecAlgoCheck(IpsecAlgoGroup::IkeHash, c.ikeHash)).length()) return e;
    if ((e = ipsecAlgoCheck(IpsecAlgoGroup::EspEnc,  c.espEnc)).length())  return e;
    if ((e = ipsecAlgoCheck(IpsecAlgoGroup::EspHash, c.espHash)).length()) return e;
    if (c.pfs && !ipsecPfsSupported()) return "PFS (CREATE_CHILD_SA mit neuem DH) ist noch nicht implementiert (ausgegraut).";
    return "";
}

bool IpsecService::isUp() const { return ipsecRuntime.isUp(); }

String IpsecService::statusText() const {
    if (!cfg_.active) return "inaktiv";
    if (!runtimeAvailable())
    { String pe = policyError(cfg_); return pe.length() ? pe : String("Runtime unterstuetzt nur Client/IKEv2/PSK"); }
    if (ipsecRuntime.isActive()) return ipsecRuntime.stateText();
    if (cmd_ == Cmd::Connect) return "verbindet (Start geplant)";
    if (manualStop_) return "getrennt (manuell, kein Autostart)";
    return "getrennt";
}

// ---- Persistenz ------------------------------------------------------------
void IpsecService::loadConfig() {
    Preferences p;
    p.begin("ipsec", true);
    cfg_.mode         = p.getString("mode", "client");
    cfg_.active       = p.getBool("active", false);
    cfg_.autoConnect  = p.getBool("autoconn", true);
    cfg_.underlay     = p.getString("underlay", "auto");
    cfg_.proto        = p.getString("proto", "ikev2");
    cfg_.serverHost   = p.getString("srvhost", "");
    cfg_.serverPort   = (uint16_t)p.getUShort("srvport", 500);
    cfg_.auth         = p.getString("auth", "psk");
    cfg_.natT         = p.getBool("natt", true);
    cfg_.localId      = p.getString("localid", "");
    cfg_.localIdType  = p.getString("localidt", "auto");
    cfg_.remoteId     = p.getString("remoteid", "");
    cfg_.remoteIdType = p.getString("remoteidt", "auto");
    // Migration alter "auto"-Konfigurationen OHNE Raten: leerer Wert -> eindeutig (Uplink-IP bzw.
    // keine Server-Identitaet); nichtleerer Wert -> Typ bleibt "auto" = "Bitte waehlen", Verbinden
    // ist blockiert, bis der Benutzer den Typ festgelegt hat.
    if (cfg_.localIdType  == "auto" && cfg_.localId.length()  == 0) cfg_.localIdType  = "sourceip";
    // Server-Identitaet ohne Wert kann nichts pruefen -> eindeutig "keine feste Server-Identitaet"
    // (egal welcher Typ gewaehlt war). Kein Raten, ein leerer Wert ist keine Identitaet.
    if (cfg_.remoteId.length() == 0) cfg_.remoteIdType = "none";
    cfg_.localTunnelIp= p.getString("localtip", "");
    cfg_.eapUser      = p.getString("eapuser", "");
    cfg_.caPem        = p.getString("capem", "");
    cfg_.extraPem     = p.getString("extrapem", "");
    // Trust-Modell: neue Konfigurationen = oeffentliche CAs (sicherer, erwartbarer Default). MIGRATION
    // OHNE Umdeutung: ein bestehendes Profil MIT ca-pem, aber ohne gespeicherten Modus, behaelt seine
    // bisherige Semantik "eigener Vertrauensanker" (ca_pem war der einzige Anker) -- es wird NICHT
    // stillschweigend auf "oeffentliche CAs" umgestellt.
    cfg_.trustMode    = p.getString("trust", cfg_.caPem.length() ? "own" : "public");
    // Migration ohne Umdeutung: ein EAP-Profil mit 'sourceip' hat bisher tatsaechlich den EAP-Benutzer-
    // namen als IDi gesendet (Core-Verhalten bei fehlender local_id) -> denselben Sachverhalt jetzt
    // ehrlich als 'eapuser' benennen.
    if (cfg_.auth == "eap" && cfg_.localIdType == "sourceip") cfg_.localIdType = "eapuser";
    cfg_.remoteSubnets= p.getString("rsubnets", "0.0.0.0/0");
    cfg_.ikeDh        = p.getString("ikedh",   "dh14");
    cfg_.ikeEnc       = p.getString("ikeenc",  "aes256cbc");
    cfg_.ikeHash      = p.getString("ikehash", "sha256");
    cfg_.espEnc       = p.getString("espenc",  "aes256cbc");
    cfg_.espHash      = p.getString("esphash", "sha256");
    cfg_.pfs          = p.getBool("pfs", false);
    // MIGRATION ohne Verhaltensaenderung: ein BESTEHENDES Profil (Server schon gespeichert) ohne
    // 'ikelt' behaelt sein bisheriges Verhalten (kein selbst-initiierter IKE-SA-Rekey = 0). Nur NEUE
    // Profile bekommen die LANCOM-Vorgabe 8 h. Sonst wuerde ein Firmware-Update stillschweigend einen
    // 8-h-Rekey in funktionierende Tunnel einbauen.
    bool existingProfile = p.isKey("srvhost") && !p.isKey("ikelt");
    cfg_.ikeLifetimeS   = (uint16_t)p.getUShort("ikelt", existingProfile ? 0 : 28800);
    cfg_.childLifetimeS = (uint16_t)p.getUShort("childlt", 3300);
    cfg_.childLifetimeMb= (uint16_t)p.getUShort("childmb", 0);
    cfg_.dpd            = p.getBool("dpd", true);
    cfg_.dpdIntervalS   = (uint16_t)p.getUShort("dpdint", 30);
    cfg_.dpdRetries     = (uint16_t)p.getUShort("dpdretry", 5);
    cfg_.nattKeepaliveS = (uint16_t)p.getUShort("natka", 20);
    cfg_.listenPort   = (uint16_t)p.getUShort("listenport", 500);
    cfg_.poolSubnet   = p.getString("poolsub", "10.10.0.0/24");
    cfg_.serverIdent  = p.getString("srvident", "");
    psk_              = p.getString("psk", "");
    eapPass_          = p.getString("eappass", "");
    p.end();
    loadUsers();
    loadPingHistory();
}

// ---- Ping-Historie (Test-Ping-Dropdown) -----------------------------------
// NVS-Schluessel "pinghist": Ziele mit ';' getrennt, neuestes zuerst. Ziele enthalten nie ';'.
#define IPSEC_PING_HIST_MAX 8
void IpsecService::loadPingHistory() {
    pingHist_.clear();
    Preferences p; p.begin("ipsec", true);
    String raw = p.getString("pinghist", "");
    p.end();
    int start = 0;
    while (start < (int)raw.length() && (int)pingHist_.size() < IPSEC_PING_HIST_MAX) {
        int sep = raw.indexOf(';', start);
        String tok = (sep < 0) ? raw.substring(start) : raw.substring(start, sep);
        tok.trim();
        if (tok.length()) pingHist_.push_back(tok);
        if (sep < 0) break;
        start = sep + 1;
    }
}
void IpsecService::savePingHistory() {
    String raw;
    for (size_t i = 0; i < pingHist_.size(); i++) { if (i) raw += ';'; raw += pingHist_[i]; }
    Preferences p; p.begin("ipsec", false);
    p.putString("pinghist", raw);
    p.end();
}
void IpsecService::rememberPingTarget(const String& ipIn) {
    String ip = ipIn; ip.trim(); ip.replace(";", "");
    if (!ip.length() || ip.length() > 64) return;
    for (size_t i = 0; i < pingHist_.size(); i++)
        if (pingHist_[i] == ip) { pingHist_.erase(pingHist_.begin() + i); break; }
    pingHist_.insert(pingHist_.begin(), ip);
    while ((int)pingHist_.size() > IPSEC_PING_HIST_MAX) pingHist_.pop_back();
    savePingHistory();
}
bool IpsecService::forgetPingTarget(const String& ipIn) {
    String ip = ipIn; ip.trim();
    for (size_t i = 0; i < pingHist_.size(); i++) {
        if (pingHist_[i] == ip) { pingHist_.erase(pingHist_.begin() + i); savePingHistory(); return true; }
    }
    return false;
}
String IpsecService::pingHistoryJson() const {
    String j = "{\"ok\":true,\"targets\":[";
    for (size_t i = 0; i < pingHist_.size(); i++) { if (i) j += ','; j += '"'; j += jesc(pingHist_[i]); j += '"'; }
    j += "]}";
    return j;
}

// NVS-Schreibhelfer mit GEPRUEFTEM Ergebnis: Preferences::put* liefert 0 bei Fehler (und bei leerem
// String auch bei Erfolg) -> nach dem Schreiben zurueckgelesen und verglichen. Erster Fehler zaehlt.
static bool nvsPutStr(Preferences& p, const char* key, const String& v, String& err) {
    p.putString(key, v);
    if (p.getString(key, "\x01") != v) { if (!err.length()) err = String("NVS-Schreibfehler bei '") + key + "'"; return false; }
    return true;
}
static bool nvsPutBool(Preferences& p, const char* key, bool v, String& err) {
    p.putBool(key, v);
    if (p.getBool(key, !v) != v) { if (!err.length()) err = String("NVS-Schreibfehler bei '") + key + "'"; return false; }
    return true;
}
static bool nvsPutU16(Preferences& p, const char* key, uint16_t v, String& err) {
    p.putUShort(key, v);
    if (p.getUShort(key, (uint16_t)(v + 1)) != v) { if (!err.length()) err = String("NVS-Schreibfehler bei '") + key + "'"; return false; }
    return true;
}

// NUR Persistenz: validieren -> NVS schreiben (geprueft) -> cfg_ unter Mutex uebernehmen -> Beobachter.
// KEIN Runtime-Zugriff: eine laufende Verbindung benutzt weiter die alte Config, bis der Benutzer
// "Neu verbinden" drueckt oder der Lifecycle-Beobachter (Automatik) sie neu aufbaut.
String IpsecService::saveConfig(const IpsecConfig& cfgIn, const String& pskOrEmpty, const String& eapPassOrEmpty) {
    IpsecConfig cfg = cfgIn;
    // Server-Identitaet: leerer Wert = "keine feste Server-Identitaet verlangen" (Typ ist dann egal).
    if (cfg.remoteId.length() == 0) cfg.remoteIdType = "none";
    if (cfg.localIdType == "sourceip" || cfg.localIdType == "eapuser") cfg.localId = "";   // kein Wert bei Uplink-IP / EAP-Benutzername
    String psk     = pskOrEmpty.length()     ? pskOrEmpty     : psk_;      // leer = behalten
    String eapPass = eapPassOrEmpty.length() ? eapPassOrEmpty : eapPass_;
    // Richtlinie + Pflichtfelder gegen die NEUE Config pruefen: nicht Implementiertes / Unvollstaendiges
    // wird NICHT gespeichert, sondern gemeldet (die UI graut aus -- das hier ist der Schutz dahinter).
    if (cfg.mode == "client") { String pe = policyError(cfg); if (pe.length()) return "Nicht gespeichert: " + pe; }
    String ve = validateCfg(cfg, psk.length() > 0, eapPass.length() > 0);
    if (ve.length()) return "Nicht gespeichert: " + ve;

    Preferences p;
    if (!p.begin("ipsec", false)) return "Nicht gespeichert: NVS-Namensraum 'ipsec' nicht verfuegbar";
    String err;
    nvsPutStr (p, "mode",      cfg.mode, err);
    nvsPutBool(p, "active",    cfg.active, err);
    nvsPutBool(p, "autoconn",  cfg.autoConnect, err);
    nvsPutStr (p, "underlay",  cfg.underlay, err);
    nvsPutStr (p, "proto",     cfg.proto, err);
    nvsPutStr (p, "srvhost",   cfg.serverHost, err);
    nvsPutU16 (p, "srvport",   cfg.serverPort, err);
    nvsPutStr (p, "auth",      cfg.auth, err);
    nvsPutBool(p, "natt",      cfg.natT, err);
    nvsPutStr (p, "localid",   cfg.localId, err);
    nvsPutStr (p, "localidt",  cfg.localIdType, err);
    nvsPutStr (p, "remoteid",  cfg.remoteId, err);
    nvsPutStr (p, "remoteidt", cfg.remoteIdType, err);
    nvsPutStr (p, "localtip",  cfg.localTunnelIp, err);
    nvsPutStr (p, "eapuser",   cfg.eapUser, err);
    nvsPutStr (p, "capem",     cfg.caPem, err);
    nvsPutStr (p, "extrapem",  cfg.extraPem, err);
    nvsPutStr (p, "trust",     cfg.trustMode, err);
    nvsPutStr (p, "rsubnets",  cfg.remoteSubnets, err);
    nvsPutStr (p, "ikedh",     cfg.ikeDh, err);
    nvsPutStr (p, "ikeenc",    cfg.ikeEnc, err);
    nvsPutStr (p, "ikehash",   cfg.ikeHash, err);
    nvsPutStr (p, "espenc",    cfg.espEnc, err);
    nvsPutStr (p, "esphash",   cfg.espHash, err);
    nvsPutBool(p, "pfs",       cfg.pfs, err);
    nvsPutU16 (p, "ikelt",     cfg.ikeLifetimeS, err);
    nvsPutU16 (p, "childlt",   cfg.childLifetimeS, err);
    nvsPutU16 (p, "childmb",   cfg.childLifetimeMb, err);
    nvsPutBool(p, "dpd",       cfg.dpd, err);
    nvsPutU16 (p, "dpdint",    cfg.dpdIntervalS, err);
    nvsPutU16 (p, "dpdretry",  cfg.dpdRetries, err);
    nvsPutU16 (p, "natka",     cfg.nattKeepaliveS, err);
    nvsPutU16 (p, "listenport",cfg.listenPort, err);
    nvsPutStr (p, "poolsub",   cfg.poolSubnet, err);
    nvsPutStr (p, "srvident",  cfg.serverIdent, err);
    nvsPutStr (p, "psk",       psk, err);
    nvsPutStr (p, "eappass",   eapPass, err);
    size_t freeEntries = p.freeEntries();
    p.end();
    if (err.length()) {
        Serial.printf("[ipsec] %s (NVS freie Eintraege: %u)\r\n", err.c_str(), (unsigned)freeEntries);
        return "Nicht gespeichert: " + err;
    }

    lock();
    cfg_ = cfg; psk_ = psk; eapPass_ = eapPass;
    unlock();
    notifyConfigChanged();   // Beobachter (Funktionszeiger) -- z.B. Lifecycle plant Neu-Verbinden
    return "";
}

// ---- Benutzer/Clients (Server-Rolle) --------------------------------------
// Persistiert als eine Zeichenkette "name|ip;name|ip;..." (Identity-Namen ohne | und ;).
void IpsecService::loadUsers() {
    users_.clear();
    Preferences p; p.begin("ipsec", true);
    String raw = p.getString("users", "");
    p.end();
    int start = 0;
    while (start < (int)raw.length()) {
        int sep = raw.indexOf(';', start);
        String tok = (sep < 0) ? raw.substring(start) : raw.substring(start, sep);
        if (tok.length()) {
            int bar = tok.indexOf('|');
            IpsecUser u;
            u.name = (bar < 0) ? tok : tok.substring(0, bar);
            u.ip   = (bar < 0) ? String("") : tok.substring(bar + 1);
            if (u.name.length()) users_.push_back(u);
        }
        if (sep < 0) break;
        start = sep + 1;
    }
}

void IpsecService::saveUsers() {
    String raw;
    for (size_t i = 0; i < users_.size(); i++) {
        if (i) raw += ";";
        raw += users_[i].name; raw += "|"; raw += users_[i].ip;
    }
    Preferences p; p.begin("ipsec", false);
    p.putString("users", raw);
    p.end();
}

String IpsecService::usersJson() {
    String j = "[";
    for (size_t i = 0; i < users_.size(); i++) {
        if (i) j += ",";
        j += "{\"name\":\""; j += jesc(users_[i].name);
        j += "\",\"ip\":\"";  j += jesc(users_[i].ip); j += "\"}";
    }
    j += "]";
    return j;
}

String IpsecService::addUser(const String& name) {
    String n = name; n.trim();
    n.replace("|", ""); n.replace(";", "");   // Trennzeichen der Serialisierung entfernen
    if (n.length() == 0) { lastError_ = "Leerer Name"; return lastError_; }
    for (auto& u : users_) if (u.name == n) { lastError_ = "Name existiert bereits"; return lastError_; }
    IpsecUser u; u.name = n; u.ip = "";
    users_.push_back(u);
    saveUsers();
    return "";
}

bool IpsecService::deleteUser(int index) {
    if (index < 0 || index >= (int)users_.size()) return false;
    users_.erase(users_.begin() + index);
    saveUsers();
    return true;
}

// ---- Validierung + Lifecycle ----------------------------------------------
// Identitaet als das, was auf die Leitung geht: KEY_ID("fritz9352"), FQDN("..."), IPv4(Uplink-IP) ...
String IpsecService::idText(const String& type, const String& value) {
    if (type == "keyid")    return "KEY_ID(\"" + value + "\")";
    if (type == "fqdn")     return "FQDN(\"" + value + "\")";
    if (type == "rfc822")   return "RFC822(\"" + value + "\")";
    if (type == "ipv4")     return "IPv4(\"" + value + "\")";
    if (type == "sourceip") return "IPv4(aktuelle Uplink-IP)";
    if (type == "none")     return "(keine feste Server-Identitaet)";
    return "(Typ nicht festgelegt)";
}

static bool isIpv4Literal(const String& s) {
    int parts = 0, start = 0;
    if (!s.length()) return false;
    while (start <= (int)s.length()) {
        int dot = s.indexOf('.', start); if (dot < 0) dot = s.length();
        String seg = s.substring(start, dot);
        if (!seg.length() || seg.length() > 3) return false;
        for (size_t i = 0; i < seg.length(); i++) if (!isDigit(seg[i])) return false;
        if (seg.toInt() > 255) return false;
        parts++; start = dot + 1;
    }
    return parts == 4;
}

// Explizite Identitaetsregeln (kein auto, keine Heuristik): Typ + Wert muessen zusammenpassen.
static String checkIdentity(const char* who, const String& type, const String& value, bool isLocal) {
    if (type == "auto" || type.length() == 0)
        return String(who) + ": Typ muss nach dem Update einmal festgelegt werden.";
    if (type == "sourceip") return isLocal ? String("") : String(who) + ": 'aktuelle Uplink-IP' gibt es nur fuer die eigene Identitaet.";
    if (type == "eapuser")  return isLocal ? String("") : String(who) + ": 'EAP-Benutzername verwenden' gibt es nur fuer die eigene Identitaet.";
    if (type == "none")     return isLocal ? String(who) + ": Typ 'keine' gibt es nur fuer die Server-Identitaet." : String("");
    if (type == "keyid" || type == "fqdn" || type == "rfc822") {
        if (!value.length()) {
            if (isLocal) return String(who) + ": Wert fehlt fuer " + type + " (z.B. der VPN-Benutzername der FRITZ!Box).";
            return String(who) + ": Wert fehlt fuer " + type + " - wenn der Server keine feste Identitaet vorgibt, "
                   "'keine feste Server-Identitaet verlangen' waehlen (FRITZ!Box: nicht noetig).";
        }
        return "";
    }
    if (type == "ipv4") {
        if (!isIpv4Literal(value)) return String(who) + ": '" + value + "' ist keine IPv4-Adresse.";
        return "";
    }
    return String(who) + ": unbekannter Identitaetstyp '" + type + "'.";
}

String IpsecService::validateCfg(const IpsecConfig& c, bool pskPresent, bool eapPassPresent) const {
    if (c.mode == "client") {
        if (c.serverHost.length() == 0) return "Server-Adresse fehlt.";
        String ie;
        if ((ie = checkIdentity("Eigene Identitaet",  c.localIdType,  c.localId,  true)).length())  return ie;
        if ((ie = checkIdentity("Server-Identitaet", c.remoteIdType, c.remoteId, false)).length()) return ie;
        if (c.auth == "psk" && !pskPresent) return "PSK fehlt (Pre-Shared Key).";
        // IDi-Typ 'eapuser' = der EAP-Benutzername ist die IKE-Identitaet (WeirdIKE leitet sie bei
        // fehlender expliziter local_id aus der EAP-Identity ab) -- nur bei Benutzer + Passwort sinnvoll;
        // 'sourceip' wird bei EAP vom Core NICHT gesendet (dort gilt ebenfalls die EAP-Identity), deshalb
        // ehrlich als Wahl verlangen statt still umzudeuten.
        if (c.localIdType == "eapuser" && c.auth != "eap") return "Eigene Identitaet: 'EAP-Benutzername verwenden' gibt es nur bei Benutzer + Passwort (EAP).";
        if (c.auth == "eap" && c.localIdType == "sourceip") return "Eigene Identitaet: bei Benutzer + Passwort 'EAP-Benutzername verwenden' oder einen expliziten Typ (KEY_ID/FQDN/RFC822) waehlen -- die Uplink-IP wird bei EAP nicht als Identitaet gesendet.";
        if (c.auth == "eap") {
            if (c.eapUser.length() == 0) return "EAP-Benutzername fehlt.";
            if (!eapPassPresent)          return "EAP-Passwort fehlt.";
            // Trust-Modell (vier Modi, WeirdIKE weirdike_trust_mode_t) -- der Server weist sich mit einem
            // Zertifikat aus (RFC 7296 2.16), die Vertrauensentscheidung trifft der gewaehlte Modus:
            //   own         = nur eigene Vertrauensanker -> ca-pem Pflicht
            //   public      = eingebaute oeffentliche Root-CAs, keine PEM noetig
            //   public-plus = oeffentliche CAs + Zusatz (ca-pem = Zusatz-Anker, extra-pem = Kettenmaterial), optional
            //   none        = KEINE Vertrauenspruefung (bewusste Wahl, nicht empfohlen; IKE-Signatur weiter geprueft)
            const String& tm = c.trustMode;
            if (tm != "public" && tm != "public-plus" && tm != "own" && tm != "none")
                return "Vertrauensmodell ungueltig (public | public-plus | own | none).";
            bool caOk = c.caPem.indexOf("-----BEGIN CERTIFICATE-----") >= 0;
            if (tm == "own" && !caOk) return "Vertrauensanker (PEM) fehlt -- bei 'Eigener Vertrauensanker' Pflicht (CA- oder Serverzertifikat).";
            if (c.caPem.length() && !caOk) return "Vertrauensanker: kein PEM-Zertifikat erkannt (-----BEGIN CERTIFICATE-----).";
            if (c.extraPem.length() && c.extraPem.indexOf("-----BEGIN CERTIFICATE-----") < 0) return "Kettenmaterial: kein PEM-Zertifikat erkannt.";
            if (c.caPem.length() > 4000)    return "Vertrauensanker zu gross (max. 4000 Zeichen PEM).";
            if (c.extraPem.length() > 4000) return "Kettenmaterial zu gross (max. 4000 Zeichen PEM).";
        }
        if (c.proto == "l2tp" && c.eapUser.length() == 0) return "L2TP-Benutzername fehlt.";
        String pe = policyError(c); if (pe.length()) return pe;
    } else {  // server
        if (!pskPresent && userCount() == 0) return "Server braucht mindestens einen PSK oder Benutzer.";
        if (c.poolSubnet.length() == 0) return "IP-Pool (Subnetz) fehlt.";
    }
    return "";
}
String IpsecService::validate() const { return validateCfg(cfg_, pskSet(), eapPassSet()); }

void IpsecService::lock() const {
    if (!mtx_) mtx_ = xSemaphoreCreateMutex();
    if (mtx_) xSemaphoreTake(mtx_, portMAX_DELAY);
}
void IpsecService::unlock() const { if (mtx_) xSemaphoreGive(mtx_); }


// ---- Kommandos (HTTP-Task / Konsole): nur pruefen und planen. Ausfuehrung in supervise(). ----
String IpsecService::requestConnect() {
    lock();
    String v = validate();
    bool avail = runtimeAvailable();
    if (v.length() || !avail) { unlock(); lastError_ = v.length() ? v : String("Diese Runtime unterstuetzt nur mode=client, proto=ikev2, auth=psk."); return lastError_; }
    cmd_ = Cmd::Connect;
    manualStop_ = false;
    unlock();
    return "";
}

void IpsecService::requestDisconnect() {
    lock();
    cmd_ = Cmd::Disconnect;
    manualStop_ = true;      // ausdruecklicher Benutzerwunsch: kein Autostart, bis requestConnect()
    unlock();
}

// loop-Task: Client starten (WeirdIKE-Handshake + ESP-Runtime, siehe ipsec_runtime.cpp) mit einem
// SNAPSHOT der gespeicherten Config -- der HTTP-Task darf cfg_ waehrenddessen neu schreiben.
String IpsecService::startNow() {
    lock();
    IpsecConfig snap = cfg_;
    String psk = psk_;
    unlock();
    lastError_ = "";
    lock(); String eapPass = eapPass_; unlock();
    String e = ipsecRuntime.start(snap, psk, eapPass);
    eapPass = "";
    if (e.length()) { up_ = false; lastError_ = e; return e; }
    up_ = false;   // wird via supervise()/isUp() true, sobald CHILD_ESTABLISHED
    return "";
}

// EINZIGER Besitzer der Runtime (loop-Task).
void IpsecService::supervise() {
    // 0) Diagnose-Ping (HTTP-Task hat angestellt): EINZIG hier ausfuehren -> kein paralleler
    //    ESP-Session-/Socket-Zugriff neben poll(). Blockiert kurz (inneres ICMP mit Timeout).
    ownerTask_ = xTaskGetCurrentTaskHandle();   // der Besitzer-Task (loop) -- fuer testPingJson()
    lock(); bool preq = pingReq_; String pt = pingTarget_; if (preq) pingReq_ = false; unlock();
    if (preq) {
        IpsecPingResult r = pingOwnerPath(pt);
        lock(); pingResult_ = r; pingDone_ = true; unlock();
        return;   // dieser Tick gehoerte dem Ping
    }

    // 1) Kommandos aus HTTP-Task/Konsole
    lock(); Cmd c = cmd_; cmd_ = Cmd::None; unlock();
    if (c == Cmd::Disconnect) { ipsecRuntime.stop(); up_ = false; return; }
    if (c == Cmd::Connect)    { ipsecRuntime.stop(); lastStartAttempt_ = millis(); startNow(); return; }  // Neu verbinden: erst sauber schliessen (evtl. steht/haengt eine SA)
    if (c == Cmd::Rekey)      { Serial.println(ipsecRuntime.rekeyNow() ? "[ipsec] CREATE_CHILD_SA (Rekey) gesendet" : "[ipsec] Rekey nicht moeglich (kein Tunnel / Anfrage offen)"); return; }
    if (c == Cmd::IkeRekey)   { Serial.println(ipsecRuntime.ikeRekeyNow() ? "[ipsec] CREATE_CHILD_SA (IKE-SA-Rekey, neue D-H) gesendet" : "[ipsec] IKE-SA-Rekey nicht moeglich (nicht verbunden / Anfrage offen / Uebergang laeuft)"); return; }

    // 1b) Frisch gespeicherte Config versoehnen (Observer signalisiert nur; hier faellt die
    //     Entscheidung mit dem ECHTEN Runtime-Zustand): laufende Verbindung NICHT abreissen;
    //     ist sie unten (getrennt/FAILED) und "Automatisch verbinden" an und kein manueller Stop,
    //     dann frischer Versuch mit der korrigierten Config.
    lock(); bool saved = configSaved_; configSaved_ = false;
    bool wantAuto = cfg_.active && cfg_.autoConnect; unlock();
    if (saved && wantAuto && !manualStop_ && !ipsecRuntime.isUp()) {
        ipsecRuntime.stop(); lastStartAttempt_ = millis(); startNow(); return;
    }

    // 2) Aktive Runtime bei jedem loop() pumpen (weirdike_poll + Socket-Demux + Retransmit/Keepalive).
    //    FAILED bleibt bewusst stehen (kein Auto-Restart): Fehlertext + IKE-Log + UDP-Zaehler bleiben
    //    fuer die Diagnose sichtbar, bis der Nutzer "Neu verbinden" oder "Trennen" drueckt.
    if (ipsecRuntime.isActive()) {
        ipsecRuntime.poll();
        up_ = ipsecRuntime.isUp();
        return;
    }

    // 3) Autostart (Boot / nach Abbruch), wenn aktiv + "Automatisch verbinden", nicht manuell
    //    getrennt und nicht gestartet.
    if (manualStop_) return;
    uint32_t now = millis();
    if (now - lastStartAttempt_ < 10000) return;
    lock();
    bool want = cfg_.active && cfg_.autoConnect;
    String why = want ? (runtimeAvailable() ? validate() : String("Diese Runtime unterstuetzt nur mode=client, proto=ikev2, auth=psk.")) : String("");
    unlock();
    if (!want) return;
    if (why.length()) {
        // Blockierter Autostart darf NICHT still bleiben: Grund auf die Uebersicht (Fehler-Feld).
        if (lastError_ != "Autostart blockiert: " + why) lastError_ = "Autostart blockiert: " + why;
        lastStartAttempt_ = now;
        return;
    }
    // Kein Autostart ohne per WAN bestaetigtes Internet (DNS/DH wuerden den loop() sonst bei jedem
    // Versuch blockieren). Der Internet-Check laeuft im Hintergrund (wan_service).
    if (!wanService.internetOk()) return;
    lastStartAttempt_ = now;
    startNow();
}

// Der owner-only Ping-Pfad: NUR der Besitzer-Task (supervise/loop) darf ihn ausfuehren, weil er
// Socket + ESP-Session anfasst. Beide Aufrufer (HTTP ueber den Auftrag, Konsole direkt) landen hier.
IpsecPingResult IpsecService::pingOwnerPath(const String& targetIp) {
    IpsecPingResult r;
    if (!ipsecRuntime.isUp()) { r.ok = false; r.stage = "kein Tunnel"; r.detail = "CHILD_SA nicht aufgebaut -- erst verbinden"; }
    else r = ipsecRuntime.testPing(targetIp);
    return r;
}

String IpsecService::testPingJson(const String& targetIp) {
    rememberPingTarget(targetIp);   // Dropdown-Historie (NVS) -- auch bei fehlgeschlagenem Ping
    IpsecPingResult r;
    if (ownerTask_ && xTaskGetCurrentTaskHandle() == ownerTask_) {
        // Serielle Konsole laeuft IM loop-Task = Besitzer: direkt ausfuehren. Auf sich selbst warten
        // wuerde nur in den Timeout laufen (HW-Gate 2026-09-07). Kein zweiter Besitzer, kein Fremdzugriff.
        r = pingOwnerPath(targetIp);
    } else {
        // HTTP-Task fasst den ESP-Datenpfad NICHT an: Ping beim loop-Task (supervise) anstellen und
        // gebunden auf das Ergebnis warten. So bleibt supervise() der einzige Besitzer von Socket/Session.
        lock(); pingTarget_ = targetIp; pingDone_ = false; pingReq_ = true; unlock();
        bool done = false;
        for (int i = 0; i < 45 && !done; i++) {   // ~4,5 s Deckel (testPing selbst ~1 s)
            delay(100);
            lock(); done = pingDone_; if (done) r = pingResult_; unlock();
        }
        if (!done) { r.ok = false; r.stage = "timeout"; r.detail = "loop-Task hat den Ping nicht rechtzeitig ausgefuehrt"; }
    }
    String j = "{";
    j += "\"ok\":";     j += r.ok ? "true" : "false"; j += ",";
    j += "\"rttMs\":";  j += String(r.rttMs); j += ",";
    j += "\"txSeq\":";  j += String(r.txSeq); j += ",";
    j += "\"rxSeq\":";  j += String(r.rxSeq); j += ",";
    j += "\"stage\":\"";  j += jesc(r.stage);  j += "\",";
    j += "\"detail\":\""; j += jesc(r.detail); j += "\"}";
    return j;
}

VpnStatus IpsecService::vpnStatus() {
    VpnStatus s;
    bool client = (cfg_.mode == "client");
    s.service = "IPsec/IKEv2";
    s.role    = client ? "client" : "server";
    s.active  = cfg_.active;
    if (!cfg_.active)                 s.state = VpnState::Inactive;
    else if (!runtimeAvailable())     s.state = VpnState::Error;
    else if (ipsecRuntime.isUp())     s.state = VpnState::Connected;
    else if (ipsecRuntime.isActive()) s.state = (ipsecRuntime.stateText() == "FAILED") ? VpnState::Error : VpnState::Connecting;
    else if (cmd_ == Cmd::Connect)    s.state = VpnState::Connecting;   // Start geplant, loop() fuehrt aus
    else if (manualStop_)             s.state = VpnState::Disconnected;
    else                              s.state = lastError_.length() ? VpnState::Error : VpnState::Disconnected;
    s.stateText = (cfg_.active && runtimeAvailable() && ipsecRuntime.isActive()) ? ipsecRuntime.stateText() : String(vpnStateName(s.state));
    if (manualStop_ && !ipsecRuntime.isActive() && cmd_ != Cmd::Connect) s.stateText += " (manuell, kein Autostart)";
    s.endpoint  = client ? (cfg_.serverHost + ":" + String(cfg_.serverPort)) : (String("Listen-Port ") + String(cfg_.listenPort));
    s.tunnelIp  = cfg_.localTunnelIp;
    s.error     = lastError_;
    if (cfg_.active && !runtimeAvailable() && s.error.length() == 0)
    { String pe = policyError(cfg_); s.error = pe.length() ? pe : String("Runtime unterstuetzt nur Client/IKEv2/PSK"); }
    ipsecRuntime.fillVpnStatus(s);   // Underlay/Quell-IP, Peer, Suite, NAT-T, ESP-Zaehler, Runtime-Fehler
    return s;
}

String IpsecService::statusJson() {
    String j = "{";
    j += "\"mode\":\"";     j += cfg_.mode; j += "\",";
    j += "\"active\":";     j += cfg_.active ? "true" : "false"; j += ",";
    j += "\"proto\":\"";    j += cfg_.proto; j += "\",";
    j += "\"underlay\":\""; j += cfg_.underlay; j += "\",";
    j += "\"runtime\":";    j += runtimeAvailable() ? "true" : "false"; j += ",";
    j += "\"up\":";         j += up_ ? "true" : "false"; j += ",";
    j += "\"auth\":\"";     j += cfg_.auth; j += "\",";
    j += "\"serverHost\":\"";  j += jesc(cfg_.serverHost); j += "\",";
    j += "\"serverPort\":";    j += String(cfg_.serverPort); j += ",";
    j += "\"eapUser\":\"";     j += jesc(cfg_.eapUser); j += "\",";
    j += "\"caPemSet\":";      j += cfg_.caPem.length() ? "true" : "false"; j += ",";
    j += "\"trustMode\":\"";   j += jesc(cfg_.trustMode); j += "\",";
    j += "\"extraPemSet\":";   j += cfg_.extraPem.length() ? "true" : "false"; j += ",";
    j += "\"remoteSubnets\":\"";j += jesc(cfg_.remoteSubnets); j += "\",";
    j += "\"ikeDh\":\"";       j += jesc(cfg_.ikeDh);   j += "\",";
    j += "\"ikeEnc\":\"";      j += jesc(cfg_.ikeEnc);  j += "\",";
    j += "\"ikeHash\":\"";     j += jesc(cfg_.ikeHash); j += "\",";
    j += "\"espEnc\":\"";      j += jesc(cfg_.espEnc);  j += "\",";
    j += "\"espHash\":\"";     j += jesc(cfg_.espHash); j += "\",";
    j += "\"pfs\":";          j += cfg_.pfs ? "true" : "false"; j += ",";
    j += "\"natT\":";          j += cfg_.natT ? "true" : "false"; j += ",";
    j += "\"localId\":\"";     j += jesc(cfg_.localId); j += "\",";
    j += "\"localIdType\":\""; j += jesc(cfg_.localIdType); j += "\",";
    j += "\"remoteId\":\"";    j += jesc(cfg_.remoteId); j += "\",";
    j += "\"remoteIdType\":\"";j += jesc(cfg_.remoteIdType); j += "\",";
    j += "\"idi\":\"";          j += jesc(IpsecService::idText(cfg_.localIdType,  cfg_.localId));  j += "\",";   // Leitungsform
    j += "\"idr\":\"";          j += jesc(IpsecService::idText(cfg_.remoteIdType, cfg_.remoteId)); j += "\",";
    j += "\"localTunnelIp\":\"";j += jesc(cfg_.localTunnelIp); j += "\",";
    j += "\"listenPort\":";    j += String(cfg_.listenPort); j += ",";
    j += "\"poolSubnet\":\"";  j += jesc(cfg_.poolSubnet); j += "\",";
    j += "\"serverIdent\":\""; j += jesc(cfg_.serverIdent); j += "\",";
    j += "\"pskSet\":";     j += pskSet() ? "true" : "false"; j += ",";
    j += "\"eapPassSet\":"; j += eapPassSet() ? "true" : "false"; j += ",";
    j += "\"userCount\":";  j += String(userCount()); j += ",";
    j += "\"users\":";      j += usersJson(); j += ",";
    j += "\"rt\":";         j += ipsecRuntime.diagJson(); j += ",";   // Runtime-Diagnose (keine Secrets)
    j += "\"status\":\"";   j += statusText(); j += "\"";
    j += "}";
    return j;
}
