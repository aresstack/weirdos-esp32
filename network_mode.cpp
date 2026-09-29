// ============================================================================
// network_mode.cpp -- siehe network_mode.h. PHASE 1: Persistenz + Anzeige,
// KEINE Laufzeit-Umschaltung. Der heutige Default (LEGACY_SETUP) bleibt exakt.
// ============================================================================
#include "weirdos_features.h"      // WEIRDOS_FEATURE_NET -- der Schalter dieses Bausteins
#include "network_mode.h"   // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)

// ---- In JEDEM Build vorhanden (reine Zuordnung, keine Hardware, kein Netz) ----
const char* NetworkModeService::modeId(NetworkMode m) {
    switch (m) {
        case NETMODE_LEGACY:   return "legacy";
        case NETMODE_CLIENT:   return "client";
        case NETMODE_LOCAL_AP: return "localap";
        case NETMODE_ROUTER:   return "router";
        case NETMODE_REPEATER: return "repeater";
    }
    return "legacy";
}

const char* NetworkModeService::modeLabel(NetworkMode m) {
    switch (m) {
        case NETMODE_LEGACY:   return "Setup / Automatisch (heutiger Default)";
        case NETMODE_CLIENT:   return "Client (nur STA, AP aus)";
        case NETMODE_LOCAL_AP: return "Lokaler AP (kein WAN, Kanal frei)";
        case NETMODE_ROUTER:   return "Internet-Router (AP=LAN + WAN + NAPT)";
        case NETMODE_REPEATER: return "WLAN-Repeater (gerouteter Uplink + NAPT)";
    }
    return "Setup / Automatisch";
}

NetworkMode NetworkModeService::modeFromId(const String& id) {
    if (id == "client")   return NETMODE_CLIENT;
    if (id == "localap")  return NETMODE_LOCAL_AP;
    if (id == "router")   return NETMODE_ROUTER;
    if (id == "repeater") return NETMODE_REPEATER;
    return NETMODE_LEGACY;
}

bool NetworkModeService::naptCapable() const { return WEIRDOS_NAPT_CAPABLE ? true : false; }

void NetworkModeService::begin() { loadConfig(); /* PHASE 1: bewusst KEIN apply() */ }


#if WEIRDOS_FEATURE_NET
// ============================================================================
// Echte Implementierung (WEIRDOS_FEATURE_NET=1)
// ============================================================================
#include <Preferences.h>

NetworkModeService networkMode;

// lwIP-NAPT-Gate: Router-/Repeater-Mode brauchen IPv4-NAPT im Stack. Wir pruefen
// die ESP-IDF-lwIP-Optionen zur Compile-Zeit; ist keine gesetzt, ist Router-Mode
// (spaeter) nicht ohne lwIP-Rebuild moeglich -- die UI weist darauf hin.
#if defined(CONFIG_LWIP_IPV4_NAPT) || defined(CONFIG_LWIP_IP_NAPT) || defined(IP_NAPT)
  #define WEIRDOS_NAPT_CAPABLE 1
#else
  #define WEIRDOS_NAPT_CAPABLE 0
#endif

void NetworkModeService::loadConfig() {
    Preferences p;
    p.begin("netmode", true);
    cfg_.mode         = modeFromId(p.getString("mode", "legacy"));
    cfg_.wan          = p.getString("wan", "auto");
    cfg_.apChannelPol = p.getString("apchpol", "follow");
    cfg_.apChannel    = (uint8_t)p.getUChar("apch", 6);
    cfg_.lanSubnet    = p.getString("lansub", "192.168.4.0/24");
    cfg_.forwarding   = p.getString("fwd", "none");
    cfg_.dnsHijack    = p.getBool("dnshijack", false);
    cfg_.usecase      = p.getString("usecase", "endpoint");
    cfg_.apInternet   = p.getBool("apinet", false);
    cfg_.accessModel  = p.getString("accmodel", "gateway");
    p.end();
}

String NetworkModeService::saveConfig(const NetworkModeConfig& c) {
    cfg_ = c;
    Preferences p;
    p.begin("netmode", false);
    p.putString("mode",    modeId(cfg_.mode));
    p.putString("wan",     cfg_.wan);
    p.putString("apchpol", cfg_.apChannelPol);
    p.putUChar ("apch",    cfg_.apChannel);
    p.putString("lansub",  cfg_.lanSubnet);
    p.putString("fwd",     cfg_.forwarding);
    p.putBool  ("dnshijack", cfg_.dnsHijack);
    p.putString("usecase", cfg_.usecase);
    p.putBool  ("apinet",  cfg_.apInternet);
    p.putString("accmodel", cfg_.accessModel);
    p.end();
    // PHASE 1: NICHT anwenden -- nur persistieren. Der laufende Setup-Modus bleibt.
    return "";
}

void NetworkModeService::apply() {
    // PHASE 1: definiertes Verhalten nur fuer LEGACY = No-op (heutiger Zustand).
    // Client/Local-AP/Router/Repeater werden erst nach Hardware-Test scharf
    // geschaltet (WiFi-Mode, ApRadioPolicy, ForwardingPolicy/NAPT). Bis dahin
    // aendert die Auswahl das Laufzeitverhalten NICHT.
    if (cfg_.mode == NETMODE_LEGACY) return;
    Serial.printf("[netmode] Modus '%s' gewaehlt -- Laufzeit-Umschaltung folgt (Phase 2), noch inaktiv.\n",
                  modeId(cfg_.mode));
}

static String jescNM(const String& s) {
    String o; for (size_t i = 0; i < s.length(); i++) { char c = s[i];
        if (c == '"' || c == '\\') { o += '\\'; o += c; } else if ((uint8_t)c >= 0x20) o += c; }
    return o;
}

String NetworkModeService::statusJson() const {
    String j = "{";
    j += "\"mode\":\"";        j += modeId(cfg_.mode); j += "\",";
    j += "\"modeLabel\":\"";   j += jescNM(modeLabel(cfg_.mode)); j += "\",";
    j += "\"wan\":\"";         j += jescNM(cfg_.wan); j += "\",";
    j += "\"apChannelPol\":\"";j += jescNM(cfg_.apChannelPol); j += "\",";
    j += "\"apChannel\":";     j += String(cfg_.apChannel); j += ",";
    j += "\"lanSubnet\":\"";   j += jescNM(cfg_.lanSubnet); j += "\",";
    j += "\"forwarding\":\"";  j += jescNM(cfg_.forwarding); j += "\",";
    j += "\"naptCapable\":";   j += (naptCapable() ? "true" : "false"); j += ",";
    j += "\"runtimeActive\":"; j += (runtimeActive() ? "true" : "false");
    j += "}";
    return j;
}
#else
// Stub (WEIRDOS_FEATURE_NET=0): Betriebsart ohne Netz gegenstandslos -- kein NVS, kein apply.
NetworkModeService networkMode;
void   NetworkModeService::begin() {}
void   NetworkModeService::loadConfig() {}
String NetworkModeService::saveConfig(const NetworkModeConfig& c) { (void)c; return String("IP-Stack nicht im Build enthalten (WEIRDOS_FEATURE_NET=0)"); }
void   NetworkModeService::apply() {}
bool   NetworkModeService::naptCapable() const { return false; }
String NetworkModeService::statusJson() const { return String("{\"ok\":false,\"mode\":\"legacy\",\"msg\":") + "IP-Stack nicht im Build enthalten (WEIRDOS_FEATURE_NET=0)" + "}"; }
#endif // WEIRDOS_FEATURE_NET
