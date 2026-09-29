// ============================================================================
// network_mode.h -- Konfigurierbare Betriebsarten (Operating Modes) fuer WeirdOS.
//
// PHASE 1 (dieser Stand): Datenmodell + Persistenz + UI. Die Auswahl wird
// gespeichert und angezeigt -- die LAUFZEIT-Umschaltung (WiFi/AP-Radio/Routing/
// NAPT) ist bewusst NOCH NICHT aktiv. Der heutige Default (LEGACY_SETUP) bleibt
// bit-genau das bestehende Verhalten. So bekommt der Anwender den Ueberblick
// ueber die geplanten Modi, ohne dass sich am laufenden System etwas aendert.
//
// Rollen-Architektur (bewusst getrennt, baut auf NetworkRegistry/EgressPolicy):
//   NetworkMode         -- WAS soll das Geraet tun?
//   WAN-Auswahl         -- welches Interface ist Uplink (auto|modem|wifi)
//   ApRadioPolicy       -- Kanal folgt STA (AUTO_FOLLOW) oder ist FIXED
//   ForwardingPolicy    -- NONE | ROUTE_NAPT   (BRIDGE = echtes L2, spaeter)
// ============================================================================
#pragma once
#include <Arduino.h>

enum NetworkMode {
    NETMODE_LEGACY = 0,   // heutiges Setup-Verhalten -- UNVERAENDERT (Default)
    NETMODE_CLIENT,       // nur STA (Client), SoftAP aus
    NETMODE_LOCAL_AP,     // nur SoftAP, kein WAN; Kanal frei waehlbar
    NETMODE_ROUTER,       // SoftAP=LAN + gewaehltes WAN + NAPT (Internet-Router)
    NETMODE_REPEATER      // SoftAP=LAN + WLAN-STA-WAN + NAPT (gerouteter Repeater)
    // NETMODE_BRIDGE: echtes L2 (WDS/4-Address) -- bewusst spaeter, hier NICHT.
};

struct NetworkModeConfig {
    NetworkMode mode          = NETMODE_LEGACY;
    String      wan           = "auto";            // auto|modem|wifi (Egress-Policy fuer den Uplink)
    String      apChannelPol  = "follow";          // follow (Kanal folgt STA) | fixed
    uint8_t     apChannel     = 6;                 // 1..13, nur wirksam bei fixed UND ohne aktives STA
    String      lanSubnet     = "192.168.4.0/24";  // Router-LAN (NICHT 4.3.2.1 -- Setup-Portal bleibt separat)
    String      forwarding    = "none";            // none | napt
    bool        dnsHijack     = false;             // (deprecated) frueher Captive-DNS; jetzt setup_guard

    // Assistent-Wizard (kaskadierende Auswahl). PHASE 1: gespeichert + angezeigt, KEINE
    // Laufzeit-Umschaltung. Aus diesen Feldern wird 'mode' abgeleitet (Vorwaerts-Kompat).
    String      usecase       = "endpoint";        // endpoint (nur selbst online) | ap (AccessPoint)
    bool        apInternet    = false;             // AP reicht Internet durch (nur bei usecase=ap)
    String      accessModel   = "gateway";         // gateway | repeater | guest (nur bei ap+apInternet)
};

class NetworkModeService {
public:
    void begin();                                    // NVS laden (Default LEGACY); wendet NICHT an
    void loadConfig();
    String saveConfig(const NetworkModeConfig& c);   // persistiert; PHASE 1: keine Laufzeit-Anwendung
    const NetworkModeConfig& config() const { return cfg_; }

    // PHASE 1: NUR LEGACY hat definiertes Verhalten (= heutiger Zustand, No-op hier).
    // Andere Modi sind geplant und werden erst nach Hardware-Test scharf geschaltet.
    void apply();

    static const char* modeId(NetworkMode m);        // stabile id fuer NVS/Form ("legacy","client",...)
    static const char* modeLabel(NetworkMode m);     // Anzeigename
    static NetworkMode  modeFromId(const String& id);
    bool   naptCapable() const;                      // lwIP-NAPT einkompiliert? (Gate fuer Router-Mode)
    bool   runtimeActive() const { return false; }   // Modusauswahl ist gespeichert, aber (noch)
                                                     // KEIN Laufzeiteingriff -- Service-AP/NAPT folgt HW-getestet
    String statusJson() const;                       // fuer Diagnose/UI (keine Secrets)

private:
    NetworkModeConfig cfg_;
};

extern NetworkModeService networkMode;
