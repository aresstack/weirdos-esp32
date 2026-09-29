// ============================================================================
// wifi_caps.cpp -- siehe wifi_caps.h.
//
// Baustein WIFI (weirdos_features.h): bei WEIRDOS_FEATURE_WIFI=0 -- per -D abgewaehlt, oder vom
// Schalterkasten hart auf 0 gezogen, weil der SoC keinen Funk hat (ESP32-P4) -- bleibt nur der
// Stub am Ende dieser Datei: kein Funk, kein Repeater, wifiStackShouldInit() IMMER false. Damit
// nimmt setup() in der .ino dieselbe Abzweigung wie bisher der P4 (startBareNetStack, kein
// WiFi.mode/softAP/Scan), ohne dass WiFi.h/esp_wifi ueberhaupt im Bild sind. Die fruehere
// CONFIG_IDF_TARGET_ESP32P4-Entscheidung in wifiPresent() ist damit im Schalterkasten aufgegangen
// (WEIRDOS_SOC_WIFI), die Datei selbst kennt keinen SoC mehr.
// ============================================================================
#include "weirdos_features.h"   // WEIRDOS_FEATURE_WIFI -- der Schalter dieses Bausteins
#include "wifi_caps.h"          // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
#if WEIRDOS_FEATURE_WIFI
// ============================================================================
// Echte Implementierung (WEIRDOS_FEATURE_WIFI=1): Onboard-Funk vorhanden.
// ============================================================================
#include <Preferences.h>
#include "ec200a_modem.h"   // usbEnumerateDevices() -- generische USB-Geraete-Sicht

bool wifiPresent() {
    // Der Baustein ist nur dann 1, wenn der SoC WLAN-Funk hat (Klammer in weirdos_features.h):
    // ESP32-S3 & Co: Onboard-WLAN-Funk vorhanden.
    return true;
}

int wifiRadioCount() {
    // Kein WLAN (P4) -> 0. Sonst Onboard = 1 Funkmodul. Erkannte USB-WLAN-Adapter kommen
    // NICHT hinzu (siehe usbWifiAdapterDetected(): erkannt != nutzbar, kein Treiber).
    return wifiPresent() ? 1 : 0;
}

bool repeaterCapable() {
    // Kein erkanntes Funkmodul meldet WDS/4-Address-Mode -> echter Repeater nicht moeglich.
    // (Onboard-WLAN kann transparentes L2-Bridging prinzipiell nicht.)
    return false;
}

// ---- Nutzer-Schalter (NVS "wifi"/"stackmode") ----------------------------------------
static WifiStackMode s_mode = WifiStackMode::Auto;

const char* wifiStackModeToStr(WifiStackMode mode) {
    switch (mode) {
        case WifiStackMode::On:  return "on";
        case WifiStackMode::Off: return "off";
        default:                 return "auto";
    }
}

WifiStackMode wifiStackModeFromStr(const String& s) {
    if (s == "on")  return WifiStackMode::On;
    if (s == "off") return WifiStackMode::Off;
    return WifiStackMode::Auto;
}

void wifiStackModeLoad() {
    Preferences p;
    p.begin("wifi", true);
    s_mode = wifiStackModeFromStr(p.getString("stackmode", "auto"));
    p.end();
}

WifiStackMode wifiStackMode() { return s_mode; }

void wifiStackModeSave(WifiStackMode mode) {
    s_mode = mode;
    Preferences p;
    p.begin("wifi", false);
    p.putString("stackmode", wifiStackModeToStr(mode));
    p.end();
}

bool wifiStackShouldInit() {
    switch (s_mode) {
        case WifiStackMode::On:  return true;              // erzwingen, auch ohne erkannte Hardware
        case WifiStackMode::Off: return false;              // nie, auch WENN Hardware erkannt wuerde
        default:                 return wifiPresent();      // Auto: nur bei echter Onboard-Funk-HW
    }
}

static bool s_active = false;
void wifiStackMarkActive(bool on) { s_active = on; }
bool wifiStackActive()            { return s_active; }

// ---- USB-WLAN-Adapter: rein informative Erkennung (kein Treiber, siehe .h) ------------
// Bewusst kleine, NICHT erschoepfende Liste verbreiteter USB-WLAN-Chipsaetze -- nur damit die
// Geraete-Registry ehrlich "erkannt, aber ohne Treiber nicht nutzbar" zeigen kann. Kein Eintrag
// gefunden -> einfach "nicht erkannt", kein Anspruch auf Vollstaendigkeit.
struct UsbWifiChip { uint16_t vid, pid; const char* label; };
static const UsbWifiChip kKnownUsbWifiChips[] = {
    { 0x0bda, 0x8179, "Realtek RTL8188EUS" },
    { 0x0bda, 0xc811, "Realtek RTL8811CU" },
    { 0x0bda, 0xb812, "Realtek RTL8812BU" },
    { 0x148f, 0x7601, "MediaTek MT7601U" },
    { 0x148f, 0x5370, "Ralink RT5370" },
    { 0x0cf3, 0x9271, "Atheros AR9271" },
};

const char* usbWifiAdapterDetected(uint16_t* vid, uint16_t* pid) {
    UsbEnumDevice devs[8];
    int n = usbEnumerateDevices(devs, 8);
    for (int i = 0; i < n; i++) {
        for (size_t k = 0; k < sizeof(kKnownUsbWifiChips) / sizeof(kKnownUsbWifiChips[0]); k++) {
            if (devs[i].vid == kKnownUsbWifiChips[k].vid && devs[i].pid == kKnownUsbWifiChips[k].pid) {
                if (vid) *vid = devs[i].vid;
                if (pid) *pid = devs[i].pid;
                return kKnownUsbWifiChips[k].label;
            }
        }
    }
    return nullptr;
}

#else
// ============================================================================
// Stub: nicht im Build enthalten (WEIRDOS_FEATURE_WIFI=0).
// Dieselben Symbole wie oben, triviale Koerper: Registry, UI-Seiten (LAN > WLAN, Assistent,
// Diagnose, Plattform), Konsole ('wlan') und die .ino referenzieren sie weiter. Kein NVS, kein
// USB-Zugriff -- der Stub haelt nur den Linker zufrieden und antwortet ehrlich "kein WLAN":
//   * wifiPresent()/wifiRadioCount()/repeaterCapable(): kein Funk, kein Repeater.
//   * wifiStackShouldInit(): IMMER false -> setup() nimmt den Bare-Net-Pfad (startBareNetStack).
//     Auch "Immer an" (NVS "wifi"/"stackmode"=on) kann hier nichts erzwingen: es gibt keinen
//     WiFi-Code, den man laden koennte. Der Modus ist deshalb unveraenderlich "off".
//   * wifiStackActive(): IMMER false -> AP-Automatik/Scan/Connect-Gates in der .ino greifen.
//   * usbWifiAdapterDetected(): nichts erkannt (die rein informative Erkennung gehoert zum Baustein).
// ============================================================================
bool wifiPresent()     { return false; }
int  wifiRadioCount()  { return 0; }
bool repeaterCapable() { return false; }

const char* wifiStackModeToStr(WifiStackMode mode) {
    switch (mode) {
        case WifiStackMode::On:  return "on";
        case WifiStackMode::Off: return "off";
        default:                 return "auto";
    }
}

WifiStackMode wifiStackModeFromStr(const String& s) {
    if (s == "on")  return WifiStackMode::On;
    if (s == "off") return WifiStackMode::Off;
    return WifiStackMode::Auto;
}

void          wifiStackModeLoad()              {}                             // nichts zu laden
WifiStackMode wifiStackMode()                  { return WifiStackMode::Off; } // ohne Baustein: immer "off"
void          wifiStackModeSave(WifiStackMode) {}                             // nicht schaltbar, nichts speichern
bool          wifiStackShouldInit()            { return false; }
void          wifiStackMarkActive(bool)        {}
bool          wifiStackActive()                { return false; }

const char* usbWifiAdapterDetected(uint16_t* vid, uint16_t* pid) {
    if (vid) *vid = 0;
    if (pid) *pid = 0;
    return nullptr;
}
#endif // WEIRDOS_FEATURE_WIFI
