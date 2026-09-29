// ============================================================================
// usb_ports.cpp -- USB-Port-Mapping (siehe Header). Chip-Tabelle fest, Board-Mapping vom Nutzer.
// ============================================================================
#include "usb_ports.h"
#include "platform.h"               // platformIsCustom(): freie Pins zulassen (auf eigene Gefahr)
#include <Preferences.h>
#include "soc/soc_caps.h"
#if CONFIG_IDF_TARGET_ESP32P4
#include "hal/usb_wrap_ll.h"        // usb_wrap_ll_phy_select (FSLS-PHY 0/1 fuer OTG1.1)
#include "soc/usb_wrap_struct.h"    // USB_WRAP
#endif

// ---- Chip-Tabelle ----------------------------------------------------------------------------------
#if CONFIG_IDF_TARGET_ESP32P4
static const UsbHwPair kPairs[] = {
    { "HS",  -1, -1, USBC_HS,      "OTG 2.0 High-Speed, dedizierte DM/DP-Pads (auf dem P4-Pico: MX1.25-4-Pin)" },
    { "FS0", 24, 25, USBC_FS_PHY0, "OTG 1.1 Full-Speed, FSLS-PHY 0 (Vorgabe fuer USB-Serial/JTAG)" },
    { "FS1", 26, 27, USBC_FS_PHY1, "OTG 1.1 Full-Speed, FSLS-PHY 1 (Chip-Vorgabe fuer OTG-FS)" },
};
#else
static const UsbHwPair kPairs[] = {
    { "FS",  19, 20, USBC_FS, "OTG Full-Speed = USB-Serial/JTAG-Pins (der einzige USB des S3)" },
};
#endif
int usbHwPairCount() { return (int)(sizeof(kPairs) / sizeof(kPairs[0])); }
const UsbHwPair& usbHwPair(int i) { return kPairs[(i < 0 || i >= usbHwPairCount()) ? 0 : i]; }
UsbCtrl usbCtrlForPins(int dm, int dp) {
    for (int i = 0; i < usbHwPairCount(); i++) if (kPairs[i].dm == dm && kPairs[i].dp == dp) return kPairs[i].ctrl;
    return USBC_NONE;
}
static const char* ctrlName(UsbCtrl c) {
    switch (c) { case USBC_HS: return "HS OTG 2.0"; case USBC_FS_PHY0: return "FS OTG 1.1 (PHY 0)"; case USBC_FS_PHY1: return "FS OTG 1.1 (PHY 1)"; case USBC_FS: return "FS OTG"; case USBC_CUSTOM: return "CUSTOM (kein Chip-USB-Paar, nicht initialisierbar)"; default: return "ungueltig"; }
}
// Pins -> Controller; im Profil "custom" bleiben unbekannte Paare als USBC_CUSTOM gespeichert (auf eigene Gefahr).
static UsbCtrl ctrlForEntry(int dm, int dp) {
    UsbCtrl c = usbCtrlForPins(dm, dp);
    if (c == USBC_NONE && platformIsCustom() && dm >= 0 && dp >= 0 && dm != dp) return USBC_CUSTOM;
    return c;
}

// ---- Nutzer-Mapping --------------------------------------------------------------------------------
static UsbPortEntry g_ports[USB_PORTS_MAX];
static int g_count = 0;

static void defaults() {
#if CONFIG_IDF_TARGET_ESP32P4
    // P4-Pico-Vorgabe (aus dem Schaltplan): USB0 = HS am MX1.25 (Modem), USB1 = FS PHY 1 auf der Stiftleiste (PC),
    // USB2 = FS PHY 0 (24/25) vorhanden, aber aus.
    g_count = 3;
    g_ports[0] = UsbPortEntry(); g_ports[0].id = "USB0"; g_ports[0].label = "MX1.25-4-Pin";   g_ports[0].dm = -1; g_ports[0].dp = -1; g_ports[0].enabled = true;
    g_ports[1] = UsbPortEntry(); g_ports[1].id = "USB1"; g_ports[1].label = "Stiftleiste 26/27"; g_ports[1].dm = 26; g_ports[1].dp = 27; g_ports[1].enabled = true;
    g_ports[2] = UsbPortEntry(); g_ports[2].id = "USB2"; g_ports[2].label = "Stiftleiste 24/25"; g_ports[2].dm = 24; g_ports[2].dp = 25; g_ports[2].enabled = false;
#else
    g_count = 1;
    g_ports[0] = UsbPortEntry(); g_ports[0].id = "USB0"; g_ports[0].label = "USB-C"; g_ports[0].dm = 19; g_ports[0].dp = 20; g_ports[0].enabled = true;
#endif
    for (int i = 0; i < g_count; i++) g_ports[i].ctrl = usbCtrlForPins(g_ports[i].dm, g_ports[i].dp);
}
static void persist() {
    Preferences p; p.begin("usbports", false);
    p.putInt("count", g_count);
    for (int i = 0; i < g_count; i++) {
        char k[8];
        snprintf(k, sizeof(k), "l%d", i); p.putString(k, g_ports[i].label);
        snprintf(k, sizeof(k), "m%d", i); p.putChar(k, g_ports[i].dm);
        snprintf(k, sizeof(k), "p%d", i); p.putChar(k, g_ports[i].dp);
        snprintf(k, sizeof(k), "e%d", i); p.putBool(k, g_ports[i].enabled);
    }
    p.end();
}
// Profilwechsel: mitgelieferte Profile setzen die Chip-Vorgaben (defaults()), Custom startet mit den Chip-Paaren
// als Vorschlag (alle aus), damit der Nutzer sieht, was der Chip kann, und dann frei eintraegt.
void usbPortsProfileDefaults(const String& profileId, UsbPortEntry* out, int& count) {
    // Vorgaben OHNE Persistenz (fuer Pinout-Vorschau eines noch nicht gewaehlten Profils)
    UsbPortEntry save[USB_PORTS_MAX]; int saveN = g_count;
    for (int i = 0; i < USB_PORTS_MAX; i++) save[i] = g_ports[i];
    defaults();
    if (profileId == "custom") { for (int i = 0; i < g_count; i++) { g_ports[i].enabled = false; g_ports[i].label = String("Port ") + i + " (Vorschlag: Chip-Paar)"; } }
    count = g_count;
    for (int i = 0; i < USB_PORTS_MAX; i++) { out[i] = g_ports[i]; g_ports[i] = save[i]; }
    g_count = saveN;
}
void usbPortsApplyProfileDefaults(const String& profileId) {
    usbPortsProfileDefaults(profileId, g_ports, g_count);
    persist();
}

void usbPortsLoad() {
    defaults();
    Preferences p; p.begin("usbports", true);
    int n = p.getInt("count", -1);
    if (n >= 1 && n <= USB_PORTS_MAX) {
        g_count = n;
        for (int i = 0; i < n; i++) {
            char k[8];
            snprintf(k, sizeof(k), "l%d", i); g_ports[i].label   = p.getString(k, g_ports[i].label);
            snprintf(k, sizeof(k), "m%d", i); g_ports[i].dm      = (int8_t)p.getChar(k, g_ports[i].dm);
            snprintf(k, sizeof(k), "p%d", i); g_ports[i].dp      = (int8_t)p.getChar(k, g_ports[i].dp);
            snprintf(k, sizeof(k), "e%d", i); g_ports[i].enabled = p.getBool(k, g_ports[i].enabled);
            g_ports[i].id = String("USB") + i;
            g_ports[i].ctrl = ctrlForEntry(g_ports[i].dm, g_ports[i].dp);
        }
    }
    p.end();
}
int usbPortsCount() { return g_count; }
const UsbPortEntry& usbPort(int i) { return g_ports[(i < 0 || i >= g_count) ? 0 : i]; }
int usbPortIndex(const String& id) { for (int i = 0; i < g_count; i++) if (g_ports[i].id == id) return i; return -1; }
bool usbPortHasCustomPins(const String& id) { int i = usbPortIndex(id); return i >= 0 && g_ports[i].ctrl == USBC_CUSTOM; }
bool usbPortUsable(const String& id) { int i = usbPortIndex(id); return i >= 0 && g_ports[i].enabled && g_ports[i].ctrl != USBC_NONE && g_ports[i].ctrl != USBC_CUSTOM; }

String usbPortsSave(int count, const UsbPortEntry* entries) {
    if (count < 1 || count > USB_PORTS_MAX) return String("Anzahl 1..") + USB_PORTS_MAX;
    // Validieren: jedes aktive Paar muss ein Chip-Paar sein, kein Controller doppelt
    UsbCtrl used[USB_PORTS_MAX]; int nu = 0;
    for (int i = 0; i < count; i++) {
        UsbCtrl c = ctrlForEntry(entries[i].dm, entries[i].dp);
        if (c == USBC_NONE) {
            // Mitgelieferte Profile: nur Chip-Paare. (Im Profil "custom" werden fremde Paare als CUSTOM akzeptiert.)
            String e = String("USB") + i + ": Pins " + entries[i].dm + "/" + entries[i].dp + " sind auf diesem Chip kein USB-Paar. Moeglich: ";
            for (int k = 0; k < usbHwPairCount(); k++) { if (k) e += ", "; e += String(kPairs[k].dm) + "/" + kPairs[k].dp + " (" + kPairs[k].name + ")"; }
            return e + ". Freie Pins nur im Profil 'Custom' (Einrichtung > Plattform), auf eigene Gefahr.";
        }
        for (int k = 0; k < nu; k++) if (c != USBC_CUSTOM && used[k] == c && entries[i].enabled) return String("USB") + i + ": derselbe Controller ist schon einem anderen aktiven Port zugeordnet";
        if (entries[i].enabled) used[nu++] = c;
    }
    g_count = count;
    for (int i = 0; i < count; i++) {
        g_ports[i] = entries[i]; g_ports[i].id = String("USB") + i; g_ports[i].ctrl = ctrlForEntry(entries[i].dm, entries[i].dp);
        if (g_ports[i].label.length() > 24) g_ports[i].label = g_ports[i].label.substring(0, 24);
    }
    persist();
    return "";
}

static String pinsText(const UsbPortEntry& e) {
    if (e.dm < 0) return "dedizierte UTMI-Pads (fest, nicht einstellbar)";
    return String("GPIO") + e.dm + " (D-) / GPIO" + e.dp + " (D+)";
}
String usbPortDescribe(const String& id) {
    int i = usbPortIndex(id); if (i < 0) return id + ": unbekannt";
    const UsbPortEntry& e = g_ports[i];
    return e.id + ": " + e.label + " -- " + ctrlName(e.ctrl) + ", " + pinsText(e) + (e.enabled ? "" : " [aus]");
}
String usbPortsText() {
    String t = "USB-Anschluesse (Chip-Paare: ";
    for (int k = 0; k < usbHwPairCount(); k++) { if (k) t += ", "; t += String(kPairs[k].name) + "=" + kPairs[k].dm + "/" + kPairs[k].dp; }
    t += ")\r\n";
    for (int i = 0; i < g_count; i++) t += "  " + usbPortDescribe(g_ports[i].id) + "\r\n";
    return t;
}
String usbPortsJson() {
    String j = "{\"pairs\":[";
    for (int k = 0; k < usbHwPairCount(); k++) { if (k) j += ","; j += String("{\"name\":\"") + kPairs[k].name + "\",\"dm\":" + kPairs[k].dm + ",\"dp\":" + kPairs[k].dp + ",\"note\":\"" + kPairs[k].note + "\"}"; }
    j += "],\"ports\":[";
    for (int i = 0; i < g_count; i++) {
        const UsbPortEntry& e = g_ports[i];
        if (i) j += ",";
        j += String("{\"id\":\"") + e.id + "\",\"label\":\"" + e.label + "\",\"dm\":" + e.dm + ",\"dp\":" + e.dp + ",\"enabled\":" + (e.enabled ? "true" : "false") + ",\"ctrl\":\"" + ctrlName(e.ctrl) + "\"}";
    }
    j += "]}";
    return j;
}

// ---- Host-/Device-Ableitung ------------------------------------------------------------------------
uint32_t usbPortHostPeripheralMap(const String& id) {
#if CONFIG_IDF_TARGET_ESP32P4
    int i = usbPortIndex(id); if (i < 0) return 0;
    // USB_DWC_LL_GET_HW(num): num 1 = USB_DWC_FS, sonst USB_DWC_HS -> FS = BIT1, HS = Default (0)
    return (g_ports[i].ctrl == USBC_FS_PHY0 || g_ports[i].ctrl == USBC_FS_PHY1) ? (1u << 1) : 0u;
#else
    (void)id; return 0;
#endif
}
void usbPortApplyPhySelect(const String& id) {
#if CONFIG_IDF_TARGET_ESP32P4
    int i = usbPortIndex(id); if (i < 0) return;
    if (g_ports[i].ctrl == USBC_FS_PHY0) usb_wrap_ll_phy_select(&USB_WRAP, 0);
    else if (g_ports[i].ctrl == USBC_FS_PHY1) usb_wrap_ll_phy_select(&USB_WRAP, 1);
#else
    (void)id;
#endif
}
bool usbPortIsHighSpeed(const String& id) { int i = usbPortIndex(id); return i >= 0 && g_ports[i].ctrl == USBC_HS; }
UsbDeviceHw usbPortDeviceHw(const String& id) {
    UsbDeviceHw h = { 0, false, false, 1, false };
    int i = usbPortIndex(id); if (i < 0 || !g_ports[i].enabled) return h;
    switch (g_ports[i].ctrl) {
        case USBC_HS:      h.rhport = 1; h.highSpeed = true;  h.utmi = true;  h.phyIdx = 0; h.ok = true; break;   // P4: rhport 1 = OTG_HS
        case USBC_FS_PHY0: h.rhport = 0; h.highSpeed = false; h.utmi = false; h.phyIdx = 0; h.ok = true; break;
        case USBC_FS_PHY1: h.rhport = 0; h.highSpeed = false; h.utmi = false; h.phyIdx = 1; h.ok = true; break;
        case USBC_FS:      h.rhport = 0; h.highSpeed = false; h.utmi = false; h.phyIdx = 0; h.ok = true; break;   // S3
        default: break;
    }
    return h;
}
