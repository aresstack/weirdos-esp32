// access_policy.cpp -- siehe Header.
#include "weirdos_features.h"      // WEIRDOS_FEATURE_NET -- der Schalter dieses Bausteins
#include "access_policy.h"   // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
#if WEIRDOS_FEATURE_NET
// ============================================================================
// Echte Implementierung (WEIRDOS_FEATURE_NET=1)
// ============================================================================
#include "ipsec_runtime.h"
#include <Preferences.h>

extern bool webWanEnabled;                 // .ino: altes WAN-Web-Flag (Spiegel der Web-Internet-Freigabe)
void saveWebWanEnabled(bool enabled);      // .ino

static const AccessService kServices[] = {
    {"web",    "Weboberflaeche (Verwaltung)",     "PIN-Anmeldung",      ACCESS_VPN | ACCESS_INTERNET},
    {"stream", "Videostream (Port 81, MJPEG/H.264)", "Stream-Schluessel", ACCESS_VPN | ACCESS_INTERNET},
    {"nas",    "NAS (SD-Karte, WebDAV)",          "Anmeldung + optional TLS", ACCESS_VPN},
};
const AccessService* accessServices(int& count) { count = sizeof(kServices) / sizeof(kServices[0]); return kServices; }
const char* accessZoneName(AccessZone z) { return z == ZONE_LAN ? "LAN" : z == ZONE_VPN ? "VPN" : "Internet"; }

static bool (*s_isLan)(const String&) = nullptr;
void accessSetLanDetector(bool (*isLanIp)(const String& clientIp)) { s_isLan = isLanIp; }

AccessZone accessZoneOf(const String& clientIp) {
    if (s_isLan && s_isLan(clientIp)) return ZONE_LAN;
    if (ipsecRuntime.tunnelContains(clientIp)) return ZONE_VPN;
    return ZONE_INTERNET;
}

static const AccessService* find(const char* svc) {
    int n; const AccessService* s = accessServices(n);
    for (int i = 0; i < n; i++) if (!strcmp(s[i].id, svc)) return &s[i];
    return nullptr;
}

uint8_t accessMask(const char* svc) {
    const AccessService* s = find(svc);
    if (!s) return 0;
    Preferences p; p.begin("access", true);
    int v = p.getInt(svc, -1);
    p.end();
    if (v >= 0) return (uint8_t)v;
    // Default; fuer "web" spiegelt das alte wanweb-Flag die Internet-Freigabe wider.
    if (!strcmp(svc, "web")) return ACCESS_VPN | (webWanEnabled ? ACCESS_INTERNET : 0);
    return s->defaults;
}

void accessSet(const char* svc, uint8_t mask) {
    if (!find(svc)) return;
    Preferences p; p.begin("access", false);
    p.putInt(svc, (int)(mask & (ACCESS_VPN | ACCESS_INTERNET)));
    p.end();
    if (!strcmp(svc, "web")) saveWebWanEnabled((mask & ACCESS_INTERNET) != 0);   // PIN-Logik liest wanweb
}

bool accessAllowed(const char* svc, const String& clientIp) {
    AccessZone z = accessZoneOf(clientIp);
    if (z == ZONE_LAN) return true;
    uint8_t m = accessMask(svc);
    return (z == ZONE_VPN) ? (m & ACCESS_VPN) != 0 : (m & ACCESS_INTERNET) != 0;
}

String accessJson() {
    int n; const AccessService* s = accessServices(n);
    String j = "{";
    for (int i = 0; i < n; i++) {
        uint8_t m = accessMask(s[i].id);
        if (i) j += ",";
        j += "\""; j += s[i].id; j += "\":{\"vpn\":"; j += (m & ACCESS_VPN) ? "true" : "false";
        j += ",\"internet\":"; j += (m & ACCESS_INTERNET) ? "true" : "false"; j += "}";
    }
    j += "}";
    return j;
}
#else
// Stub (WEIRDOS_FEATURE_NET=0): ohne Netz gibt es keine Zonen -- alles ist "lokal", nichts ist erreichbar.
const AccessService* accessServices(int& count) { count = 0; return nullptr; }
const char*  accessZoneName(AccessZone z) { (void)z; return "lan"; }
void        accessSetLanDetector(bool (*isLanIp)(const String& clientIp)) { (void)isLanIp; }
AccessZone  accessZoneOf(const String& clientIp) { (void)clientIp; return ZONE_LAN; }
uint8_t     accessMask(const char* svc) { (void)svc; return 0; }
void        accessSet(const char* svc, uint8_t mask) { (void)svc; (void)mask; }
bool        accessAllowed(const char* svc, const String& clientIp) { (void)svc; (void)clientIp; return true; }
String      accessJson() { return String("{}"); }
#endif // WEIRDOS_FEATURE_NET
