// ============================================================================
// ec200a_modem.cpp  --  Treiber-Implementierung fuer das Quectel EC200A-EUV1
//
// USB-Host (rohe usb_host-API), AT-Kanal, PPP-Datenpumpe (lwIP PPPoS ueber
// USB-Bulk), LTE-Band-/RAT-Konfiguration, Modem-Prefs (eigene NVS-Instanz).
// KENNT die App-Schicht nicht - meldet Ereignisse ueber Listener zurueck.
// Der eigentliche Treiber-Code wurde 1:1 aus der urspruenglichen .ino uebernommen.
//
// Baustein MODEM (weirdos_features.h): bei WEIRDOS_FEATURE_MODEM=0 bleibt nur der Stub am Ende
// dieser Datei -- kein usb_host_*, kein PPPoS, keine Transfer-Pools; der Linker wirft die
// usb_host-Komponente und PPP mit --gc-sections heraus. Der Header bleibt fuer alle
// Konsumenten gleich. startUsbHost() ist dabei zugleich der Start des Bausteins USB_HOST
// (das Modem ist heute sein einziger Nutzer, siehe Stub).
// ============================================================================
#include "weirdos_features.h"     // WEIRDOS_FEATURE_MODEM -- der Schalter dieses Bausteins
#include "ec200a_modem.h"         // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
#if WEIRDOS_FEATURE_MODEM
// ============================================================================
// Echte Implementierung (WEIRDOS_FEATURE_MODEM=1) -- unveraendert
// ============================================================================
#include "ec200a_ecm.h"            // ECM-Datenpfad: isUp() + Byte-Zaehler fuer den Speedtest
#include "modem_sim.h"            // modemEnsureSimReady (PIN beim Verbinden, gemeinsam mit ECM)
#include "modem_clock.h"          // modemClockSync: Wanduhr aus dem Netz, solange IF3 frei ist
#include "usb_ports.h"            // USB-Port-Mapping: peripheral_map + FSLS-PHY-Wahl fuer den Modem-Host
#include "peripheral_registry.h"  // periphModemPort (welcher Port traegt cellular0)

#include <Network.h>              // Network.hostByName + NetworkClient (lwIP, funk-unabhaengig) -- KEIN WiFi.h:
                                  // das zoege die WLAN-Library auch bei WEIRDOS_FEATURE_WIFI=0 ins Bild
#include <HTTPClient.h>           // eingebauter LTE-Speedtest (HTTP-GET/POST ueber PPP)
#include <Preferences.h>
#include <cstdlib>
#include <cstring>
#include <esp_heap_caps.h>
#include <esp_err.h>
#include <esp_netif.h>
#include "lwip/ip_addr.h"         // ipaddr_ntoa
#include "netif/ppp/pppapi.h"     // lwIP PPPoS (threadsicher)
#include "netif/ppp/pppos.h"      // pppos_input_tcpip
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"

// ---- geteilte Globals: Definition ----------------------------------------
// (in der .h nur als extern deklariert; hier liegt die eine Definition)
String modemApn = MODEM_APN_DEFAULT;
String modemUser = "";
String modemPass = "";
String modemPdpType = MODEM_PDP_DEFAULT;
String modemAuth = MODEM_AUTH_DEFAULT;
String modemDialNumber = MODEM_DIAL_DEFAULT;
String modemSimPin = "";
uint32_t modemLastResetMs = 0;   // millis() des letzten AT+CFUN=1,1 (0 = keiner) -- USB-Host-Recovery in der .ino
bool   modemAutoconnect = MODEM_AUTOCONNECT_DEFAULT;
String modemBandProfile = "auto";
String modemBandCustom  = "";
String modemNetMode     = "auto";
bool   modemAutoStart = true;    // P4-TEST: Autoconnect default AN (Modem startet selbst, kein UI)
bool   modemLinkUp = false;
String modemLastMessage = "";
volatile bool     modemUsbHostReady = false;
volatile bool     modemUsbFound     = false;
volatile int      modemUsbDevCount  = 0;
volatile uint16_t modemUsbLastVid   = 0;
volatile uint16_t modemUsbLastPid   = 0;
volatile uint32_t modemUsbLibEvents = 0;
volatile uint32_t modemUsbCliEvents = 0;
String            modemUsbError     = "";

// ---- Observer/Listener-Registry ------------------------------------------
static ModemPppListener      g_pppListeners[4]      = { 0 };
static int                   g_pppListenerN         = 0;
static ModemPresenceListener g_presenceListeners[4] = { 0 };
static int                   g_presenceListenerN    = 0;
// USB-Transfer-Fehlerspur (fuer die DEV_GONE-Diagnose): Anzahl nicht-COMPLETED-Transfers, letzter Status, Zeitpunkt.
static volatile uint32_t g_xferErrN = 0, g_xferErrLastMs = 0;
static volatile int      g_xferErrLast = -1;
static volatile uint32_t g_pppTxBytes = 0, g_pppRxBytes = 0;   // PPP-Bytes seit Link-Up (Reset beim PPP-Start)
static uint32_t          g_lastCfunMs = 0;   // letzter eigener AT+CFUN=1,1 -- NUR fuer die Diagnose (modemLastResetMs loescht
                                             // die USB-Host-Recovery sofort wieder, sobald das Geraet noch da ist)
static inline void noteXferStatus(usb_transfer_t* t) {
    if (t->status == USB_TRANSFER_STATUS_COMPLETED) return;
    uint32_t now = millis();
    // Ersten Fehler eines Schubs sichtbar machen (Busfehler gehen dem Abriss voraus): max. 1 Zeile je 5 s.
    if (!g_xferErrLastMs || now - g_xferErrLastMs > 5000)
        Serial.printf("[usb] Transfer-Fehler Status %d auf EP %02X (Nr. %lu, up %lu s, PPP tx %lu rx %lu B)\n",
                      (int)t->status, (unsigned)t->bEndpointAddress, (unsigned long)(g_xferErrN + 1), (unsigned long)(now / 1000),
                      (unsigned long)g_pppTxBytes, (unsigned long)g_pppRxBytes);
    g_xferErrN++; g_xferErrLast = (int)t->status; g_xferErrLastMs = now;
}

void modemAddPppListener(ModemPppListener cb) {
    if (cb && g_pppListenerN < 4) g_pppListeners[g_pppListenerN++] = cb;
}
void modemAddPresenceListener(ModemPresenceListener cb) {
    if (cb && g_presenceListenerN < 4) g_presenceListeners[g_presenceListenerN++] = cb;
}
static void emitPpp(PppState s, const char* ip) {
    for (int i = 0; i < g_pppListenerN; i++) g_pppListeners[i](s, ip);
}
static void emitPresence(bool present, uint16_t vid, uint16_t pid) {
    for (int i = 0; i < g_presenceListenerN; i++) g_presenceListeners[i](present, vid, pid);
}

// ---- eigene NVS-Instanz (statt der .ino-globalen 'preferences') -----------
static Preferences modemNvs;

// ===========================================================================
// Ab hier: der 1:1 aus der .ino uebernommene Treiber-Code.
// ===========================================================================
#define USB_MAX_DEVS 8
struct UsbDevInfo {
    bool                 used;
    uint8_t              addr;
    usb_device_handle_t  handle;
    uint16_t             vid, pid;
    uint8_t              cls;
};
static UsbDevInfo       g_usbDevs[USB_MAX_DEVS];
static portMUX_TYPE     g_usbMux = portMUX_INITIALIZER_UNLOCKED;
static usb_host_client_handle_t g_usbClient = NULL;
char                    g_modemUsbInfo[1024] = "";   // Schnittstellen-/Endpoint-Karte (extern in .h)
static SemaphoreHandle_t g_atSem = NULL;              // Signalisiert AT-Transfer-Abschluss
static bool             g_ifClaimed[8] = { false };   // Interface einmal claimen, dann behalten

// Aktualisiert die abgeleiteten Zaehler/Flags fuer die UI.
static void usbRecount() {
    int count = 0;
    bool found = false;
    for (int i = 0; i < USB_MAX_DEVS; i++) {
        if (!g_usbDevs[i].used) continue;
        count++;
        if (g_usbDevs[i].vid == MODEM_TARGET_VID && g_usbDevs[i].pid == MODEM_TARGET_PID) {
            found = true;
        }
    }
    modemUsbDevCount = count;
    modemUsbFound    = found;
}

// Generische Sicht auf ALLE aktuell erkannten USB-Geraete (nicht nur das Modem) -- siehe .h.
int usbEnumerateDevices(UsbEnumDevice out[], int maxOut) {
    int n = 0;
    portENTER_CRITICAL(&g_usbMux);
    for (int i = 0; i < USB_MAX_DEVS && n < maxOut; i++) {
        if (!g_usbDevs[i].used) continue;
        out[n].vid = g_usbDevs[i].vid;
        out[n].pid = g_usbDevs[i].pid;
        out[n].devClass = g_usbDevs[i].cls;
        n++;
    }
    portEXIT_CRITICAL(&g_usbMux);
    return n;
}

static void usbStoreDev(uint8_t addr, usb_device_handle_t h, const usb_device_desc_t* d) {
    portENTER_CRITICAL(&g_usbMux);
    int slot = -1;
    for (int i = 0; i < USB_MAX_DEVS; i++) {
        if (g_usbDevs[i].used && g_usbDevs[i].addr == addr) { slot = i; break; }
    }
    if (slot < 0) {
        for (int i = 0; i < USB_MAX_DEVS; i++) { if (!g_usbDevs[i].used) { slot = i; break; } }
    }
    if (slot >= 0) {
        g_usbDevs[slot].used   = true;
        g_usbDevs[slot].addr   = addr;
        g_usbDevs[slot].handle = h;
        g_usbDevs[slot].vid    = d->idVendor;
        g_usbDevs[slot].pid    = d->idProduct;
        g_usbDevs[slot].cls    = d->bDeviceClass;
    }
    usbRecount();
    modemUsbLastVid = d->idVendor;
    modemUsbLastPid = d->idProduct;
    portEXIT_CRITICAL(&g_usbMux);
}

static void usbRemoveByHandle(usb_device_handle_t h) {
    portENTER_CRITICAL(&g_usbMux);
    for (int i = 0; i < USB_MAX_DEVS; i++) {
        if (g_usbDevs[i].used && g_usbDevs[i].handle == h) { g_usbDevs[i].used = false; }
    }
    usbRecount();
    portEXIT_CRITICAL(&g_usbMux);
}

// Liest den aktiven Config-Descriptor und baut eine lesbare Schnittstellen-/
// Endpoint-Karte (fuer /modem-usbinfo). Rein lesend.
static void usbDumpConfig(usb_device_handle_t h) {
    const usb_config_desc_t* cfg = NULL;
    if (usb_host_get_active_config_descriptor(h, &cfg) != ESP_OK || !cfg) return;
    const uint8_t* p = (const uint8_t*)cfg;
    int total = cfg->wTotalLength;
    int off = 0, ti = 0, cap = sizeof(g_modemUsbInfo);
    g_modemUsbInfo[0] = 0;
    while (off + 2 <= total && ti < cap - 80) {
        uint8_t bLen = p[off], bType = p[off + 1];
        if (bLen == 0) break;
        if (bType == 0x04 && off + 9 <= total) {            // Interface-Descriptor
            ti += snprintf(g_modemUsbInfo + ti, cap - ti,
                           "IF%u alt%u  cls %02X/%02X/%02X  (%u EP)\n",
                           p[off + 2], p[off + 3], p[off + 5], p[off + 6], p[off + 7], p[off + 4]);
        } else if (bType == 0x05 && off + 7 <= total) {     // Endpoint-Descriptor
            uint8_t a = p[off + 2], attr = p[off + 3];
            uint16_t mps = p[off + 4] | (p[off + 5] << 8);
            const char* dir = (a & 0x80) ? "IN " : "OUT";
            const char* ty = (attr & 3) == 2 ? "bulk" : (attr & 3) == 3 ? "int " :
                             (attr & 3) == 1 ? "iso " : "ctrl";
            ti += snprintf(g_modemUsbInfo + ti, cap - ti,
                           "    EP %02X %s %s mps%u\n", a, dir, ty, mps);
        }
        off += bLen;
    }
}

// Modem-Generation: zaehlt jede Enumeration des EC200A; GONE/NEW_DEV-Zeitpunkte fuer die Diagnose
// (Abstand GONE -> NEW_DEV: ~1 s = Link-/PHY-Verlust mit sofortiger Re-Enumeration, ~10-20 s = Modem bootet).
static uint32_t g_modemGen = 0, g_modemGoneMs = 0, g_modemEnumMs = 0;
uint32_t modemEnumGeneration() { return g_modemGen; }
uint32_t modemEnumMs()         { return g_modemEnumMs; }

// Spontane (nicht durch eigenen CFUN erklaerte) Abrisse des Modem-Links: Zeitstempel-Ring fuer die
// Link-Recovery in der .ino (usbHostRecoveryTick): flattert der Link, wird der USB-Host in Stufen
// frisch aufgesetzt (Root-Port stromlos/an, dann ESP-Neustart) -- genau das, was ein ESP-Reset bei
// laufendem Modem nachweislich heilt.
static uint32_t g_goneRing[8] = {0}; static int g_goneRingN = 0;
static void noteUnexpectedGone(uint32_t now) { g_goneRing[g_goneRingN++ & 7] = now ? now : 1; }
int modemUsbUnexpectedGone(uint32_t windowMs, uint32_t* lastMs) {
    uint32_t now = millis(); int n = 0; uint32_t last = 0;
    for (int i = 0; i < 8; i++) { uint32_t t = g_goneRing[i]; if (!t) continue; if (now - t <= windowMs) n++; if ((int32_t)(t - last) > 0) last = t; }
    if (lastMs) *lastMs = last;
    return n;
}
void modemUsbClearGoneHistory() { for (int i = 0; i < 8; i++) g_goneRing[i] = 0; g_goneRingN = 0; }

// Root-Port des USB-Hosts deaktivieren und wieder aktivieren (usb_host_lib_set_root_port_power): alle Geraete
// bekommen DEV_GONE, der Port startet die Verbindungserkennung neu -> das Modem re-enumeriert, bootet aber nicht.
// Ob dabei auf dem Board die 5-V-Versorgung des Modems wirklich abgeschaltet wird, ist NICHT garantiert
// (Board-Verdrahtung) -- deshalb bewusst "deaktivieren", nicht "stromlos". Das dabei erzeugte DEV_GONE ist
// ERWARTET und zaehlt nicht als spontaner Abriss (g_rootCycleMs, 15-s-Fenster).
static uint32_t g_rootCycleMs = 0;
String modemUsbRootPortCycle(bool* ok) {
    if (ok) *ok = false;
    if (!g_usbClient) return "USB-Host nicht installiert";
    g_rootCycleMs = millis() ? millis() : 1;
    esp_err_t e1 = usb_host_lib_set_root_port_power(false);
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_err_t e2 = usb_host_lib_set_root_port_power(true);
    if (ok) *ok = (e1 == ESP_OK && e2 == ESP_OK);
    return String("Root-Port deaktivieren: ") + esp_err_to_name(e1) + ", aktivieren: " + esp_err_to_name(e2);
}

// Tabelleneintrag zu einem Handle nachschlagen (unter dem Mux). false = unbekannt (nie gespeichert oder
// schon durch ein frueheres DEV_GONE entfernt).
static bool usbLookupHandle(usb_device_handle_t h, uint8_t& addr, uint16_t& vid, uint16_t& pid) {
    bool found = false;
    portENTER_CRITICAL(&g_usbMux);
    for (int i = 0; i < USB_MAX_DEVS; i++) {
        if (g_usbDevs[i].used && g_usbDevs[i].handle == h) { addr = g_usbDevs[i].addr; vid = g_usbDevs[i].vid; pid = g_usbDevs[i].pid; found = true; break; }
    }
    portEXIT_CRITICAL(&g_usbMux);
    return found;
}

static void usbClientCb(const usb_host_client_event_msg_t* msg, void* arg) {
    modemUsbCliEvents++;
    if (msg->event == USB_HOST_CLIENT_EVENT_NEW_DEV) {
        usb_device_handle_t h;
        esp_err_t oe = usb_host_device_open(g_usbClient, msg->new_dev.address, &h);
        if (oe == ESP_OK) {
            const usb_device_desc_t* d = NULL;
            if (usb_host_get_device_descriptor(h, &d) == ESP_OK && d) {
                usbStoreDev(msg->new_dev.address, h, d);
                bool isModem = (d->idVendor == MODEM_TARGET_VID && d->idProduct == MODEM_TARGET_PID);
                uint32_t now = millis();
                if (isModem) { g_modemGen++; g_modemEnumMs = now; }
                Serial.printf("[usb] NEW_DEV addr %u hdl %p %04X:%04X%s gen %lu, up %lu s%s%lu ms nach DEV_GONE, DMA frei %u groesster %u\n",
                              (unsigned)msg->new_dev.address, (void*)h, d->idVendor, d->idProduct, isModem ? " (Modem)" : "",
                              (unsigned long)g_modemGen, (unsigned long)(now / 1000),
                              (isModem && g_modemGoneMs) ? ", " : ", (kein GONE davor) ", (unsigned long)((isModem && g_modemGoneMs) ? now - g_modemGoneMs : 0),
                              (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA));
                if (isModem) usbDumpConfig(h);   // Schnittstellen-/Endpoint-Karte fuellen
                emitPresence(modemUsbFound, d->idVendor, d->idProduct);  // Observer
            }
            // Geraet offen lassen, damit es enumeriert bleibt (reiner Test).
        } else {
            Serial.printf("[usb] NEW_DEV addr %u: device_open fehlgeschlagen: %s\n", (unsigned)msg->new_dev.address, esp_err_to_name(oe));
        }
    } else if (msg->event == USB_HOST_CLIENT_EVENT_DEV_GONE) {
        usb_device_handle_t h = msg->dev_gone.dev_hdl;
        uint8_t addr = 0; uint16_t vid = 0, pid = 0;
        uint32_t now = millis();
        // Idempotent: nur ein GONE je bekanntem Handle. Ein zweites GONE fuer einen schon entfernten/
        // unbekannten Handle darf keinen zweiten Teardown, kein zweites device_close ausloesen.
        if (!usbLookupHandle(h, addr, vid, pid)) {
            Serial.printf("[usb] DEV_GONE hdl %p: unbekannt oder bereits verarbeitet -> ignoriert (up %lu s)\n", (void*)h, (unsigned long)(now / 1000));
            return;
        }
        bool isModem = (vid == MODEM_TARGET_VID && pid == MODEM_TARGET_PID);
        // Diagnose: ERWARTETER Abriss (eigener AT+CFUN=1,1 binnen 30 s -> Modem re-enumeriert) oder SPONTAN?
        // Dazu: Geraet (Adresse, VID:PID, Generation), Uptime, PPP-Bytes seit Link-Up, USB-Lib-/Client-Ereignisse,
        // Transfer-Fehlerspur, interner + DMA-Heap.
        bool afterCfun  = g_lastCfunMs && (now - g_lastCfunMs) < 30000;
        bool afterCycle = g_rootCycleMs && (now - g_rootCycleMs) < 15000;
        {
            Serial.printf("[usb] DEV_GONE %s: addr %u hdl %p %04X:%04X%s gen %lu, up %lu s, CFUN vor %ld s, PPP tx %lu rx %lu B, Lib-Ev %lu Cli-Ev %lu, "
                          "Xfer-Fehler %lu (letzter Status %d vor %lu ms), intern frei %u groesster %u, DMA frei %u groesster %u\n",
                          afterCycle ? "ERWARTET (Root-Port-Zyklus)" : afterCfun ? "ERWARTET (nach CFUN)" : "UNERWARTET (spontan)",
                          (unsigned)addr, (void*)h, vid, pid, isModem ? " (Modem)" : " (KEIN Modem)", (unsigned long)g_modemGen,
                          (unsigned long)(now / 1000),
                          g_lastCfunMs ? (long)((now - g_lastCfunMs) / 1000) : -1L,
                          (unsigned long)g_pppTxBytes, (unsigned long)g_pppRxBytes,
                          (unsigned long)modemUsbLibEvents, (unsigned long)modemUsbCliEvents,
                          (unsigned long)g_xferErrN, g_xferErrLast, (unsigned long)(g_xferErrLastMs ? now - g_xferErrLastMs : 0),
                          (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),
                          (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA), (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA));
        }
        if (isModem) {
            g_modemGoneMs = now;
            if (!afterCfun && !afterCycle) noteUnexpectedGone(now);   // nur SPONTANE Abrisse zaehlen (Link-Flattern)
            pppOnDeviceGone();                                // PPP-Flags/RX-Task stoppen
            ecmOnDeviceGone();                                // ECM ebenso (sonst haengt das Re-Enum)
            // Interfaces AKTIV freigeben, BEVOR wir schliessen. Nur die Flags zu loeschen
            // reicht NICHT: usb_host_device_close scheitert dann mit INVALID_STATE (noch
            // geclaimte Interfaces), die USB-Adresse bleibt belegt und das re-enumerierte
            // Modem laesst sich in NEW_DEV nicht mehr oeffnen (modemUsbFound bleibt false).
            // Genau das passierte nach dem Band-Apply-CFUN-Zyklus (Modem re-enumeriert).
            for (int i = 0; i < 8; i++) {
                if (g_ifClaimed[i]) usb_host_interface_release(g_usbClient, h, i);
                g_ifClaimed[i] = false;
            }
        }
        usbRemoveByHandle(h);
        usb_host_device_close(g_usbClient, h);
        if (isModem) emitPresence(modemUsbFound, MODEM_TARGET_VID, MODEM_TARGET_PID);  // Observer (nur fuer das Modem)
    }
}

static void usbLibTask(void* arg) {
    while (true) {
        uint32_t flags;
        usb_host_lib_handle_events(portMAX_DELAY, &flags);
        modemUsbLibEvents++;
        // NO_CLIENTS/ALL_FREE ignorieren - unser Client bleibt dauerhaft.
    }
}

static void usbClientTask(void* arg) {
    while (true) {
        usb_host_client_handle_events(g_usbClient, portMAX_DELAY);
    }
}

// Enum-Filter: In Arduino-ESP32 3.3.11 ist CONFIG_USB_HOST_ENABLE_ENUM_FILTER_CALLBACK=y.
// Wird KEIN Callback gesetzt (NULL), haengt die Enumeration STILL (Issue #12778):
// "connect" wird erkannt, aber es wird nie eine Adresse vergeben (enum-Adressen 0),
// bei jedem Geraet. Wir lassen hier jedes Geraet zu und aktivieren Konfiguration 1.
static bool usbEnumFilterCb(const usb_device_desc_t* dev_desc, uint8_t* bConfigurationValue) {
    *bConfigurationValue = 1;   // Standard-Konfiguration aktivieren
    return true;                // jedes Geraet enumerieren
}

// Startet USB-Host + Client + Tasks. Fehler landen in modemUsbError (UI).
void startUsbHost() {
    memset(g_usbDevs, 0, sizeof(g_usbDevs));

    usb_host_config_t hc = {};
    hc.skip_phy_setup  = false;
    hc.intr_flags      = ESP_INTR_FLAG_LEVEL1;
    hc.enum_filter_cb  = usbEnumFilterCb;   // <-- der Fix (3.3.11-Regression #12778)
    // Modem-Host = exakt der bewaehrte Pfad (Chip-Default-Controller/PHY). Das USB-Port-Mapping
    // (System > Geraete) fasst den Modem-Host NUR an, wenn der Nutzer bewusst einen anderen als den
    // Chip-Default-Port fuer cellular0 gewaehlt hat -- sonst byte-identisch zum funktionierenden Stand
    // (Default nichts USB-Neues aktiv). map != 0 kommt nur bei einem ausdruecklich gewaehlten FS-Port vor.
    uint32_t modemMap = usbPortHostPeripheralMap(periphModemPort);
    if (modemMap != 0) hc.peripheral_map = modemMap;
    esp_err_t err = usb_host_install(&hc);
    if (err != ESP_OK) {
        modemUsbError = "usb_host_install: " + String(esp_err_to_name(err));
        return;
    }
    if (modemMap != 0) usbPortApplyPhySelect(periphModemPort);   // nur bei bewusst gewaehltem FS-Modem-Port

    usb_host_client_config_t cc = {};
    cc.is_synchronous              = false;
    cc.max_num_event_msg           = 5;
    cc.async.client_event_callback = usbClientCb;
    cc.async.callback_arg          = NULL;
    err = usb_host_client_register(&cc, &g_usbClient);
    if (err != ESP_OK) {
        modemUsbError = "client_register: " + String(esp_err_to_name(err));
        usb_host_uninstall();   // Rollback: installierten Host nicht verwaist lassen
        return;
    }

    // Auf Core 1 (weg von WLAN auf Core 0) und hoehere Prioritaet, damit die
    // zeitkritische Enumeration nach dem Port-Reset nicht verdraengt wird.
    // Rueckgabe PRUEFEN: schlaegt die Task-Erstellung fehl (z.B. RAM knapp), lief
    // frueher trotzdem "USB-Host aktiv" - aber dann pumpt niemand die Host-Events
    // (Bus-Ev bleibt 0, selbst mit gestecktem Modem). Jetzt sauber als Fehler melden.
    // Handles ERFASSEN, damit ein Teilerfolg vollstaendig zurueckgerollt werden kann.
    TaskHandle_t hLib = NULL, hCli = NULL;
    BaseType_t r1 = xTaskCreatePinnedToCore(usbLibTask, "usb_lib", 4096, NULL, 5, &hLib, 1);
    BaseType_t r2 = (r1 == pdPASS)
        ? xTaskCreatePinnedToCore(usbClientTask, "usb_cli", 4096, NULL, 5, &hCli, 1)
        : (BaseType_t)pdFAIL;
    if (r1 != pdPASS || r2 != pdPASS) {
        modemUsbError = "USB-Event-Task nicht gestartet (RAM?) lib=" + String((int)r1)
                      + " cli=" + String((int)r2);
        // Vollstaendiger Rollback: gestartete Tasks loeschen, Client deregistrieren, Host deinstallieren.
        if (hCli) vTaskDelete(hCli);
        if (hLib) vTaskDelete(hLib);
        usb_host_client_deregister(g_usbClient);
        usb_host_uninstall();
        g_usbClient = NULL;
        return;   // modemUsbHostReady bleibt false -> Aufrufer weiss: nicht gestartet
    }
    modemUsbHostReady = true;
}


// -----------------------------------------------------------------------------
// AT-Sendetest: eine Modem-Schnittstelle claimen, "AT\r" per Bulk-OUT senden,
// Antwort per Bulk-IN lesen. Reiner Lese-/Schreibtest auf dem AT-Kanal (kein
// Flashen/Burn). Schnittstelle/Endpoints kommen aus /modem-usbinfo.
// -----------------------------------------------------------------------------
static void atTransferCb(usb_transfer_t* t) {
    SemaphoreHandle_t sem = (SemaphoreHandle_t)t->context;
    if (sem) xSemaphoreGive(sem);
}

static usb_device_handle_t findModemHandle() {
    usb_device_handle_t dev = NULL;
    portENTER_CRITICAL(&g_usbMux);
    for (int i = 0; i < USB_MAX_DEVS; i++) {
        if (g_usbDevs[i].used && g_usbDevs[i].vid == MODEM_TARGET_VID
                && g_usbDevs[i].pid == MODEM_TARGET_PID) {
            dev = g_usbDevs[i].handle;
        }
    }
    portEXIT_CRITICAL(&g_usbMux);
    return dev;
}

// ---- Accessoren fuer den ECM-Datenpfad (ec200a_ecm.cpp) -------------------
// g_usbClient/g_ifClaimed sind file-static; ECM greift nur ueber diese zu, damit
// die DEV_GONE-Freigabe (die g_ifClaimed[0..7] released) auch ECM-IFs erfasst.
usb_host_client_handle_t modemUsbClientHandle() { return g_usbClient; }
usb_device_handle_t      modemDeviceHandle()     { return findModemHandle(); }

bool modemClaimInterface(uint8_t ifNum, uint8_t alt) {
    usb_device_handle_t dev = findModemHandle();
    if (!dev || ifNum >= 8) return false;
    if (g_ifClaimed[ifNum]) return true;                 // schon geclaimt
    esp_err_t e = usb_host_interface_claim(g_usbClient, dev, ifNum, alt);
    if (e != ESP_OK) return false;
    g_ifClaimed[ifNum] = true;
    return true;
}

void modemReleaseInterface(uint8_t ifNum) {
    usb_device_handle_t dev = findModemHandle();
    if (dev && ifNum < 8 && g_ifClaimed[ifNum]) usb_host_interface_release(g_usbClient, dev, ifNum);
    if (ifNum < 8) g_ifClaimed[ifNum] = false;
}

// Bricht einen haengenden Transfer auf einem Endpoint sauber ab, damit das
// Interface danach freigegeben werden kann (sonst bleibt es belegt -> beim
// naechsten claim ESP_ERR_INVALID_STATE).
static void atCancelEp(usb_device_handle_t dev, uint8_t ep) {
    usb_host_endpoint_halt(dev, ep);
    usb_host_endpoint_flush(dev, ep);              // gibt den pending Transfer zurueck
    xSemaphoreTake(g_atSem, pdMS_TO_TICKS(300));   // abgebrochenen Callback abwarten
    usb_host_endpoint_clear(dev, ep);
}

String modemAtTest(uint8_t ifNum, uint8_t epOut, uint8_t epIn, const String& cmd) {
    usb_device_handle_t dev = findModemHandle();
    if (!dev) return "Modem 2C7C:6005 nicht erkannt (am aktiven Hub angeschlossen?)";

    if (!g_atSem) g_atSem = xSemaphoreCreateBinary();
    if (!g_atSem) return "Semaphore-Erzeugung fehlgeschlagen";

    // Interface nur EINMAL claimen und behalten. Re-Claim wuerde den Endpoint-
    // Data-Toggle zuruecksetzen -> Folgekommandos bekaemen keine Antwort mehr.
    if (ifNum < 8 && !g_ifClaimed[ifNum]) {
        esp_err_t cerr = usb_host_interface_claim(g_usbClient, dev, ifNum, 0);
        if (cerr != ESP_OK)
            return "interface_claim IF" + String(ifNum) + ": " + String(esp_err_to_name(cerr));
        g_ifClaimed[ifNum] = true;
    }

    usb_transfer_t* out = NULL;
    usb_transfer_t* in  = NULL;
    bool outPending = false, inPending = false;
    String result;

    do {
        if (usb_host_transfer_alloc(64, 0, &out)  != ESP_OK ||
            usb_host_transfer_alloc(512, 0, &in)  != ESP_OK) {   // 512 = MPS-Vielfaches
            result = "transfer_alloc fehlgeschlagen"; break;
        }

        // Bulk-OUT: <cmd> + "\r"
        int cl = cmd.length(); if (cl > 62) cl = 62;
        for (int i = 0; i < cl; i++) out->data_buffer[i] = (uint8_t)cmd[i];
        out->data_buffer[cl]  = '\r';
        out->num_bytes        = cl + 1;
        out->bEndpointAddress = epOut;
        out->device_handle    = dev;
        out->callback         = atTransferCb;
        out->context          = g_atSem;
        xSemaphoreTake(g_atSem, 0);
        if (usb_host_transfer_submit(out) != ESP_OK) { result = "submit OUT fehlgeschlagen"; break; }
        outPending = true;
        if (xSemaphoreTake(g_atSem, pdMS_TO_TICKS(1000)) != pdTRUE) { result = "OUT timeout"; break; }
        outPending = false;
        if (out->status != USB_TRANSFER_STATUS_COMPLETED) {
            result = "OUT status " + String((int)out->status); break;
        }

        // Bulk-IN: bis "OK"/"ERROR" oder kein Nachschub. Grosser Puffer (512),
        // der Transfer endet am Short-Packet -> meist reicht 1-2 Reads.
        String raw;
        for (int k = 0; k < 16; k++) {
            in->num_bytes        = 512;
            in->bEndpointAddress = epIn;
            in->device_handle    = dev;
            in->callback         = atTransferCb;
            in->context          = g_atSem;
            xSemaphoreTake(g_atSem, 0);
            if (usb_host_transfer_submit(in) != ESP_OK) break;
            inPending = true;
            if (xSemaphoreTake(g_atSem, pdMS_TO_TICKS(500)) != pdTRUE) break;   // pending!
            inPending = false;
            if (in->status != USB_TRANSFER_STATUS_COMPLETED) break;
            int n = in->actual_num_bytes;
            for (int i = 0; i < n; i++) raw += (char)in->data_buffer[i];
            if (raw.indexOf("\r\nOK\r\n") >= 0 || raw.indexOf("ERROR") >= 0) break;
        }
        result = raw.length() ? raw : "(keine Antwort / Timeout)";
    } while (0);

    // Haengende Transfers sauber abbrechen, BEVOR wir freigeben/releasen.
    if (outPending) atCancelEp(dev, epOut);
    if (inPending)  atCancelEp(dev, epIn);

    if (out) usb_host_transfer_free(out);
    if (in)  usb_host_transfer_free(in);
    // Interface bleibt geclaimed (siehe oben) - kein Release hier.
    return result;
}

// Nur LESEN, nichts senden: was liegt auf einem Modem-Port bereits an (unaufgeforderte Meldungen)?
// Nach einer Re-Enumeration unterscheidet das "Modem hat gebootet" (Boot-URCs wie RDY, +CFUN: 1,
// +CPIN: READY, +QIND: SMS DONE) von "nur der USB-Link war weg" (nichts oder Reste der alten Session).
// Wird VOR Escape/ATH/CFUN gerufen. Ein IN-Transfer, kurze Wartezeit, dann sauber abbrechen.
static String usbReadPending(usb_device_handle_t dev, uint8_t ifNum, uint8_t epIn, uint32_t waitMs) {
    String out;
    if (!dev || !g_atSem) { if (!g_atSem) g_atSem = xSemaphoreCreateBinary(); if (!dev || !g_atSem) return out; }
    if (ifNum < 8 && !g_ifClaimed[ifNum]) {
        if (usb_host_interface_claim(g_usbClient, dev, ifNum, 0) != ESP_OK) return out;
        g_ifClaimed[ifNum] = true;
    }
    usb_transfer_t* in = NULL;
    if (usb_host_transfer_alloc(512, 0, &in) != ESP_OK) return out;
    bool pending = false;
    for (int k = 0; k < 4; k++) {
        in->num_bytes = 512; in->bEndpointAddress = epIn; in->device_handle = dev; in->callback = atTransferCb; in->context = g_atSem;
        xSemaphoreTake(g_atSem, 0);
        if (usb_host_transfer_submit(in) != ESP_OK) break;
        pending = true;
        if (xSemaphoreTake(g_atSem, pdMS_TO_TICKS(waitMs)) != pdTRUE) break;   // nichts mehr -> pending abbrechen
        pending = false;
        if (in->status != USB_TRANSFER_STATUS_COMPLETED) break;
        for (int i = 0; i < in->actual_num_bytes && out.length() < 240; i++) {
            char c = (char)in->data_buffer[i];
            if (c == '\r') continue; else if (c == '\n') out += " | "; else if (c < 32 || c > 126) out += '.'; else out += c;
        }
        waitMs = 150;   // Folgepakete kommen dicht hintereinander
    }
    if (pending) atCancelEp(dev, epIn);
    usb_host_transfer_free(in);
    return out;
}


// -----------------------------------------------------------------------------
// PPP (Internet-Datenpfad): lwIP PPPoS ueber die rohe USB-Bulk-Schicht (IF4 =
// Modem-Port). Dial per ATD*99# auf IF4, danach tragen IF4-Bulk-IN/OUT die
// PPP-Frames. RX-Task -> pppos_input_tcpip; Output-Callback -> Bulk-OUT.
// -----------------------------------------------------------------------------
static const uint8_t PPP_IF = 4, PPP_EPIN = 0x81, PPP_EPOUT = 0x0A;

// enum PppState liegt in ec200a_modem.h
static volatile PppState g_pppState = PPP_IDLE;
String g_pppIp = "";

// RF-Snapshot vom letzten Verbindungsaufbau. IF3 (AT-Port) ist bei aktivem PPP
// nicht claimbar (IF3/IF4 teilen sich einen FS-USB-Kanal) -> Live-AT liefert
// dann ESP_ERR_NOT_SUPPORTED. Daher greifen wir Band/EARFCN/Signal/Betreiber
// EINMALIG beim Verbinden ab (IF3 ist da noch kurz geclaimt) und cachen die
// rohen AT-Antworten; die .ino parst sie mit denselben Helfern wie live.
String   modemRfQeng = "", modemRfQnw = "", modemRfCops = "", modemRfCsq = "";
// Statische/SIM-/Reg-Felder ebenfalls beim Verbinden abgreifen (bei aktivem PPP
// sonst leer): Modell/Firmware (ATI), IMEI, ICCID, IMSI, CPIN, CEREG.
String   modemRfAti = "", modemRfImei = "", modemRfIccid = "",
         modemRfImsi = "", modemRfCpin = "", modemRfCereg = "";
uint32_t modemRfMs = 0;   // millis() des Snapshots (0 = noch keiner)

static ppp_pcb*          g_ppp = NULL;
static volatile bool     g_pppcbDead = true;   // true = pcb in PPP_PHASE_DEAD -> ppp_set_auth/pppapi_connect sicher
static struct netif      g_pppNetif;
static TaskHandle_t      g_pppRxTask = NULL;
static volatile bool     g_pppRun = false;

// --- Gepipelinete USB-Datenpumpe ---------------------------------------------
// Frueher: EIN Transfer je Richtung, synchron submit+warten (Stop-and-Wait) ->
// pro Block eine volle USB-Roundtrip-Latenz, und der lwIP-tcpip-Thread stand
// waehrenddessen. Das drueckte den Durchsatz weit unter die 12 Mbit/s der
// Full-Speed-Bulk-Pipe (VGA ruckelte).
// Jetzt: POOLS vorallozierter Transfers, mehrere gleichzeitig "in flight" ->
// die Pipe bleibt gefuellt, keine Luecken zwischen den Transfers. (Kostet keine
// zusaetzlichen USB-Channels: mehrere Transfers je Endpoint werden in der Pipe
// gequeued, nicht parallel als eigene Kanaele - der IF3/IF4-Konflikt bleibt aus.)
// PPP_TX_N = wieviele OUT-Frames GLEICHZEITIG "in flight" sein duerfen. Das ist
// die Durchsatz-Obergrenze der Pipeline: ~ PPP_TX_N * PPP_TX_BUF / OUT-Latenz.
// Jeder PPP-Frame (<=MTU ~1500 B) belegt EINEN Transfer -> nur PPP_TX_N Frames
// unterwegs. Falls die EC200A-OUT-Latenz (Puffern fuer den LTE-Uplink) hoch ist,
// kann schon dieser Pool ~850 kbit/s deckeln - unabhaengig vom Funksignal.
// Pool-Tiefe: 6, NICHT 16. Das 6->16-Experiment (61cec8c) brachte KEINEN Durchsatz --
// der echte Durchsatz-Fix war das lwIP-TCP-Fenster (5744->32768); die Grenze ist
// Antenne/Signal, nicht die Pipeline-Tiefe (siehe Projekt-Memory). Aber 16 kostet
// 16*1536*2 = ~48 KB INTERNES DMA-RAM (usb_host_transfer_alloc kann kein PSRAM) statt
// ~18 KB bei 6. Sobald PPP hochkommt, erschoepfte das unter Modem+AP+STA den internen
// Heap (heapmin 244) -> der Webserver bekam keinen Speicher mehr -> AP-UI-Freeze.
// Zurueck auf die bewiesen stabilen 6. NICHT wieder hochsetzen ohne Heap-Budget!
#define PPP_TX_N   6           // OUT-Transfers im Pool (bewiesen stabil; 16 = OOM-Freeze)
#define PPP_RX_N   6           // IN-Transfers im Pool (spiegelbildlich)
#define PPP_TX_BUF 1536        // Vielfaches von 64 (FS-Bulk-MPS)
#define PPP_RX_BUF 1536

static usb_transfer_t*   g_pppTx[PPP_TX_N] = { 0 };
static usb_transfer_t*   g_pppRx[PPP_RX_N] = { 0 };
static QueueHandle_t     g_pppTxFree = NULL; // freie OUT-Transfers (Pool)
static QueueHandle_t     g_pppRxDone = NULL; // fertige IN-Transfers -> RX-Task

// Dial-String separat (synchron, nur einmal vor dem PPP-Aufbau benutzt).
static SemaphoreHandle_t g_pppDialSem  = NULL;
static usb_transfer_t*   g_pppDialXfer = NULL;

// Durchsatz-Zaehler (Bytes ueber IF4; = PPP-Nutzlast inkl. HDLC-Rahmung).
// g_pppTxBytes / g_pppRxBytes: Definition oben bei der DEV_GONE-Diagnose (wird dort schon gebraucht).

// TX-Pool-Diagnose: beweist, ob die Pipeline-Tiefe der Engpass ist.
//   txPoolWait    = wie oft war der Pool leer, als lwIP senden wollte
//   txPoolTimeout = wie oft riss die 200ms-Frist -> Frame verworfen (TCP-Resend)
//   txSubmitFail  = USB-Submit-Fehler
//   txMaxInFlight = max. gleichzeitig unterwegs (<= PPP_TX_N)
// Deutung: txPoolTimeout==0 UND txPoolWait~0 -> Tiefe egal (nicht der Engpass);
// txPoolWait hoch -> Pool laeuft dauernd leer -> mehr Tiefe wuerde helfen.
static volatile uint32_t g_txPoolWait = 0, g_txPoolTimeout = 0,
                         g_txSubmitFail = 0, g_txMaxInFlight = 0;
static volatile uint32_t g_txPoolWaitUs = 0;   // Summe der Wartezeit bei leerem Pool (us)
static uint32_t          g_txInFlight   = 0;   // exakt (atomar) ausstehende OUT-Transfers

// Completion-Callbacks. Laufen im usb_cli-Task (aus usb_host_client_handle_events)
// -> muessen KURZ sein: nur Bookkeeping + Transfer weiterreichen, keine Blockade.
static void pppDialCb(usb_transfer_t* t) {
    if (t->context) xSemaphoreGive((SemaphoreHandle_t)t->context);
}
static void pppTxCb(usb_transfer_t* t) {
    noteXferStatus(t);
    if (t->status == USB_TRANSFER_STATUS_COMPLETED) g_pppTxBytes += t->actual_num_bytes;
    __atomic_sub_fetch(&g_txInFlight, 1, __ATOMIC_RELAXED);   // -1: Transfer fertig
    if (g_pppTxFree) xQueueSend(g_pppTxFree, &t, 0);   // Transfer zurueck in den Pool
}
static void pppRxCb(usb_transfer_t* t) {
    noteXferStatus(t);
    if (g_pppRxDone) xQueueSend(g_pppRxDone, &t, 0);   // an den RX-Task uebergeben
}

// Transfer-Pools + Queues einmalig anlegen (bleiben ueber Verbindungszyklen).
static bool pppEnsureBuffers() {
    if (!g_pppDialSem)  g_pppDialSem  = xSemaphoreCreateBinary();
    if (!g_pppDialXfer) usb_host_transfer_alloc(64, 0, &g_pppDialXfer);
    if (!g_pppTxFree)   g_pppTxFree   = xQueueCreate(PPP_TX_N,     sizeof(usb_transfer_t*));
    if (!g_pppRxDone)   g_pppRxDone   = xQueueCreate(PPP_RX_N + 2, sizeof(usb_transfer_t*));
    for (int i = 0; i < PPP_TX_N; i++)
        if (!g_pppTx[i]) usb_host_transfer_alloc(PPP_TX_BUF, 0, &g_pppTx[i]);
    for (int i = 0; i < PPP_RX_N; i++)
        if (!g_pppRx[i]) usb_host_transfer_alloc(PPP_RX_BUF, 0, &g_pppRx[i]);
    if (!g_pppDialSem || !g_pppDialXfer || !g_pppTxFree || !g_pppRxDone) return false;
    for (int i = 0; i < PPP_TX_N; i++) if (!g_pppTx[i]) return false;
    for (int i = 0; i < PPP_RX_N; i++) if (!g_pppRx[i]) return false;
    return true;
}

// Gegenstueck: gibt die PPP-Transfer-Pools frei (~48 KB internes DMA-RAM). Aufruf beim
// Umschalten auf ECM, damit PPP- und ECM-Pools nicht koexistieren (sonst Heap-Erschoepfung
// -> Kamera verhungert). Nur wenn PPP wirklich unten und der RX-Task weg ist.
void pppFreeBuffers() {
    if (pppIsUp()) return;
    g_pppRun = false;
    for (int i = 0; i < 40 && g_pppRxTask; i++) vTaskDelay(pdMS_TO_TICKS(50));
    if (g_pppRxTask) return;
    for (int i = 0; i < PPP_TX_N; i++) if (g_pppTx[i]) { usb_host_transfer_free(g_pppTx[i]); g_pppTx[i] = NULL; }
    for (int i = 0; i < PPP_RX_N; i++) if (g_pppRx[i]) { usb_host_transfer_free(g_pppRx[i]); g_pppRx[i] = NULL; }
    if (g_pppDialXfer) { usb_host_transfer_free(g_pppDialXfer); g_pppDialXfer = NULL; }
    if (g_pppTxFree) { vQueueDelete(g_pppTxFree); g_pppTxFree = NULL; }
    if (g_pppRxDone) { vQueueDelete(g_pppRxDone); g_pppRxDone = NULL; }
}

// Rohbytes an einen Endpoint senden (fuer den Dial-String). Ohne Antwort-Lesen.
static bool pppRawSend(usb_device_handle_t dev, uint8_t ep, const String& s) {
    if (!g_pppDialXfer || !g_pppDialSem) return false;
    int L = s.length(); if (L > 64) L = 64;
    for (int i = 0; i < L; i++) g_pppDialXfer->data_buffer[i] = (uint8_t)s[i];
    g_pppDialXfer->num_bytes        = L;
    g_pppDialXfer->bEndpointAddress = ep;
    g_pppDialXfer->device_handle    = dev;
    g_pppDialXfer->callback         = pppDialCb;
    g_pppDialXfer->context          = g_pppDialSem;
    xSemaphoreTake(g_pppDialSem, 0);
    if (usb_host_transfer_submit(g_pppDialXfer) != ESP_OK) return false;
    if (xSemaphoreTake(g_pppDialSem, pdMS_TO_TICKS(1000)) != pdTRUE) return false;
    return g_pppDialXfer->status == USB_TRANSFER_STATUS_COMPLETED;
}

// lwIP ruft das aus dem tcpip-Thread auf -> PPP-Frames per Bulk-OUT ans Modem.
// Nicht-blockierend gepipelinet: freien Transfer aus dem Pool nehmen, fuellen,
// ASYNCHRON abschicken (kein Warten!); der Completion-Callback legt ihn zurueck.
// So sind bis zu PPP_TX_N Frames gleichzeitig unterwegs. Nur wenn der Pool kurz
// leer ist, wird begrenzt gewartet (Backpressure); reicht das nicht, wird der
// Rest verworfen (TCP sendet erneut) - der tcpip-Thread steht nie lange.
static u32_t pppOutputCb(ppp_pcb* pcb, const void* data, u32_t len, void* ctx) {
    usb_device_handle_t dev = findModemHandle();
    if (!dev || !g_pppTxFree) return 0;
    const uint8_t* p = (const uint8_t*)data;
    u32_t sent = 0;
    while (sent < len) {
        usb_transfer_t* t = NULL;
        bool waited = (uxQueueMessagesWaiting(g_pppTxFree) == 0);
        uint32_t w0 = waited ? micros() : 0;
        if (waited) g_txPoolWait++;                // Pool leer -> lwIP wartet gleich
        if (xQueueReceive(g_pppTxFree, &t, pdMS_TO_TICKS(200)) != pdTRUE) { g_txPoolTimeout++; break; }
        if (waited) g_txPoolWaitUs += (uint32_t)(micros() - w0);   // echte Wartezeit summieren
        u32_t chunk = len - sent; if (chunk > PPP_TX_BUF) chunk = PPP_TX_BUF;
        memcpy(t->data_buffer, p + sent, chunk);
        t->num_bytes        = chunk;
        t->bEndpointAddress = PPP_EPOUT;
        t->device_handle    = dev;
        t->callback         = pppTxCb;
        t->context          = NULL;
        if (usb_host_transfer_submit(t) != ESP_OK) { g_txSubmitFail++; xQueueSend(g_pppTxFree, &t, 0); break; }
        uint32_t nf = __atomic_add_fetch(&g_txInFlight, 1, __ATOMIC_RELAXED);  // +1 nach Submit
        if (nf > g_txMaxInFlight) g_txMaxInFlight = nf;
        sent += chunk;
    }
    return sent;
}

static void pppOnLinkEvent(int err);   // -> PPP-State-Machine (weiter unten definiert)

// Klartext fuer die lwIP-PPP-Fehlercodes (Diagnose: WELCHES Event schickt das Modem?).
static const char* pppErrName(int e) {
    switch (e) {
        case PPPERR_NONE:        return "NONE (verbunden)";
        case PPPERR_PARAM:       return "PARAM";
        case PPPERR_OPEN:        return "OPEN";
        case PPPERR_DEVICE:      return "DEVICE";
        case PPPERR_ALLOC:       return "ALLOC";
        case PPPERR_USER:        return "USER (sauberer Close)";
        case PPPERR_CONNECT:     return "CONNECT (Link verloren/kein Aufbau)";
        case PPPERR_AUTHFAIL:    return "AUTHFAIL (APN-Auth)";
        case PPPERR_PROTOCOL:    return "PROTOCOL (Aushandlung gescheitert)";
        case PPPERR_PEERDEAD:    return "PEERDEAD (Gegenstelle tot)";
        case PPPERR_IDLETIMEOUT: return "IDLETIMEOUT";
        case PPPERR_CONNECTTIME: return "CONNECTTIME";
        case PPPERR_LOOPBACK:    return "LOOPBACK";
        default:                 return "?";
    }
}

static void pppLinkStatusCb(ppp_pcb* pcb, int err, void* ctx) {
    // Echtes Link-Event protokollieren -> Fehler werden am EVENT erkannt, nicht per Uhr.
    Serial.printf("[PPP link] err=%d (%s)\n", err, pppErrName(err));
    if (err == PPPERR_NONE) {
        g_pppIp     = String(ipaddr_ntoa(&g_pppNetif.ip_addr));
        modemLinkUp = true;
        g_pppcbDead = false;                 // verbunden -> pcb laeuft (NICHT dead)
    } else {
        g_pppIp     = "";
        modemLinkUp = false;
        g_pppcbDead = true;                  // Session beendet/abgerissen -> pcb ist DEAD
    }
    pppOnLinkEvent(err);   // die State-Machine entscheidet den Uebergang (+ Observer)
}

// RX-Task: haelt PPP_RX_N IN-Transfers GLEICHZEITIG "in flight". Jeder fertige
// Transfer wird sofort in PPPoS gespeist und neu abgeschickt -> waehrend einer
// verarbeitet wird, warten die anderen schon auf Daten (keine Luecke wie beim
// frueheren Ein-Transfer-submit->warten->neu). Der Callback pppRxCb reicht die
// fertigen Transfers ueber g_pppRxDone hierher; Submit/Resubmit/Ende laufen nur
// hier (ein Ort -> keine Cross-Task-Races).
static void pppRxTask(void* arg) {
    usb_device_handle_t dev = findModemHandle();
    int live = 0;
    for (int i = 0; i < PPP_RX_N; i++) {
        usb_transfer_t* t = g_pppRx[i];
        t->num_bytes        = PPP_RX_BUF;
        t->bEndpointAddress = PPP_EPIN;
        t->device_handle    = dev;
        t->callback         = pppRxCb;
        t->context          = NULL;
        if (dev && usb_host_transfer_submit(t) == ESP_OK) live++;
    }
    while (live > 0) {
        usb_transfer_t* t = NULL;
        if (xQueueReceive(g_pppRxDone, &t, portMAX_DELAY) != pdTRUE) continue;
        bool resubmit = false;
        if (g_pppRun && t->status == USB_TRANSFER_STATUS_COMPLETED) {
            if (t->actual_num_bytes > 0 && g_ppp) {
                pppos_input_tcpip(g_ppp, t->data_buffer, t->actual_num_bytes);
                g_pppRxBytes += t->actual_num_bytes;
            }
            dev = findModemHandle();
            if (dev) {
                t->num_bytes     = PPP_RX_BUF;
                t->device_handle = dev;
                t->callback      = pppRxCb;
                t->context       = NULL;
                if (usb_host_transfer_submit(t) == ESP_OK) resubmit = true;
            }
        }
        if (!resubmit) live--;      // Teardown (Endpoint geflusht) oder Fehler
    }
    g_pppRxTask = NULL;
    vTaskDelete(NULL);
}

// Wartet bis zu maxSec auf Netz-Registrierung (CEREG-Stat 1=Heimat / 5=Roaming).
// Nach einem Band-Apply (CFUN-Zyklus) re-attacht das Modem und ist kurz NICHT
// registriert -> die PPP-Aushandlung wuerde sonst scheitern (verhandelt->getrennt).
// Ist das Modem bereits registriert (Normalfall ohne Apply), kehrt es sofort zurueck.
bool modemWaitRegistered(uint8_t ifNum, uint8_t epOut, uint8_t epIn, int maxSec) {
    for (int i = 0; i < maxSec; i++) {
        String r = modemAtTest(ifNum, epOut, epIn, "AT+CEREG?");
        if (r.indexOf("+CEREG:") < 0)                    // Kanal-Lag: Antwort im Folge-Read
            r = modemAtTest(ifNum, epOut, epIn, "AT+CEREG?");
        int p = r.indexOf("+CEREG:");
        int c = (p >= 0) ? r.indexOf(',', p) : -1;
        int stat = (c >= 0) ? (int)r.substring(c + 1, c + 2).toInt() : -1;
        if (stat == 1 || stat == 5) return true;
        delay(1000);
    }
    return false;
}

// ===========================================================================
// PPP-Verbindung als STATE-PATTERN (Single Source of Truth).
//
// Frueher setzten pppStart/pppStop/pppLinkStatusCb g_pppState quer durcheinander
// -> inkongruente Zustaende (Modem-Datensession vs. ESP vs. UI). Jetzt ist EIN
// polymorphes Zustandsobjekt die Wahrheit. Uebergaenge laufen nur ueber
// PppMachine::enter() -> spiegelt g_pppState (fuer Alt-Leser) UND feuert die
// Observer. Die USB/AT/lwIP-Arbeit steckt in doDial()/doTeardown(); jeder Zustand
// implementiert connect()/disconnect()/onLink()/onGone() unterschiedlich.
// ===========================================================================
class PppMachine;

// Zeitpunkt des letzten Zustandswechsels (fuer den NEG-Haenger-Selbstheiler:
// bleibt die Aushandlung zu lange stehen, dialt der naechste 'Verbinden'-Klick neu).
static uint32_t g_pppStateSinceMs = 0;

struct PppStateObj {
    virtual PppState id() const = 0;
    virtual String   label() const = 0;
    virtual String   connect(PppMachine&)    { return "In diesem Zustand nicht moeglich."; }
    virtual String   disconnect(PppMachine&) { return "PPP nicht aktiv."; }
    virtual void     onLink(PppMachine&, int err) {}
    virtual void     onGone(PppMachine&) {}
};

static PppStateObj& stIdle();
static PppStateObj& stNeg();
static PppStateObj& stUp();
static PppStateObj& stFailed();

class PppMachine {
    PppStateObj* m_cur = nullptr;
public:
    PppStateObj& cur() { if (!m_cur) m_cur = &stIdle(); return *m_cur; }
    void enter(PppStateObj& s) {
        m_cur = &s;
        g_pppStateSinceMs = millis();           // Zeitstempel fuer den NEG-Haenger-Selbstheiler
        g_pppState = s.id();                    // Spiegel fuer Alt-Leser (pppRateJson etc.)
        emitPpp(g_pppState, g_pppIp.c_str());   // Observer -> App-Schicht/UI
    }
    String   connect()    { return cur().connect(*this); }
    String   disconnect() { return cur().disconnect(*this); }
    void     onLink(int err) { cur().onLink(*this, err); }
    void     onGone()     { cur().onGone(*this); }
    PppState state()      { return cur().id(); }
    String   label()      { return cur().label(); }
    String   doDial();       // Kontext-Setup + Dial + pppapi_connect
    void     doTeardown();   // graceful Close + Pipes/Interface abbauen
};

static PppMachine g_ppm;

struct StIdle : PppStateObj {
    PppState id() const override { return PPP_IDLE; }
    String   label() const override { return "getrennt"; }
    String   connect(PppMachine& m) override { return m.doDial(); }
};
struct StNeg : PppStateObj {
    PppState id() const override { return PPP_NEG; }
    String   label() const override { return "verhandelt (LCP/IPCP) ..."; }
    String   connect(PppMachine& m) override {
        // WICHTIG: nichts wird automatisch abgebrochen. Echte Fehler erkennt die
        // Maschine am Link-Event (onLink -> Failed, s.u.); ein Auto-Reconnect dialt
        // dann aus Failed neu. NUR wenn die Aushandlung STILL haengt (gar kein Event
        // kommt) und der Nutzer erneut 'Verbinden' klickt (>10s), raeumen wir hier
        // auf und dialen neu = dein manuelles 'Trennen'+'Verbinden' in einem Klick.
        uint32_t age = millis() - g_pppStateSinceMs;
        if (age > 10000) {
            m.doTeardown();
            m.enter(stIdle());
            return m.doDial();
        }
        return "Aushandlung laeuft noch (" + String(age / 1000) + "s) - nichts wird "
               "automatisch abgebrochen. Scheitert sie wirklich, wechselt der Status auf "
               "'fehlgeschlagen'. Haengt sie still, erzwingt ein weiterer 'Verbinden'-Klick "
               "einen sauberen Neuaufbau.";
    }
    void     onLink(PppMachine& m, int err) override {   // Fehlererkennung am ECHTEN Event
        if (err == PPPERR_NONE)      m.enter(stUp());
        else if (err == PPPERR_USER) m.enter(stIdle());   // sauberer Abbruch
        else                         m.enter(stFailed()); // Aushandlung gescheitert (CONNECT/PROTOCOL/AUTHFAIL...)
    }
    void     onGone(PppMachine& m) override { m.enter(stFailed()); }
    String   disconnect(PppMachine& m) override { m.doTeardown(); m.enter(stIdle()); return "PPP getrennt."; }
};
struct StUp : PppStateObj {
    PppState id() const override { return PPP_UP; }
    String   label() const override { return "verbunden, IP " + g_pppIp; }
    String   connect(PppMachine&) override { return "Bereits verbunden."; }
    void     onLink(PppMachine& m, int err) override {
        if (err == PPPERR_USER)      m.enter(stIdle());    // sauberer Close
        else if (err != PPPERR_NONE) m.enter(stFailed());  // unerwarteter Abriss
    }
    void     onGone(PppMachine& m) override { m.enter(stIdle()); }
    String   disconnect(PppMachine& m) override { m.doTeardown(); m.enter(stIdle()); return "PPP getrennt."; }
};
struct StFailed : PppStateObj {
    PppState id() const override { return PPP_FAILED; }
    String   label() const override { return "fehlgeschlagen"; }
    String   connect(PppMachine& m) override { return m.doDial(); }    // Retry (doDial raeumt Reste auf)
    String   disconnect(PppMachine& m) override { m.doTeardown(); m.enter(stIdle()); return "PPP getrennt."; }
    void     onGone(PppMachine& m) override { m.enter(stIdle()); }
};

static PppStateObj& stIdle()   { static StIdle   s; return s; }
static PppStateObj& stNeg()    { static StNeg    s; return s; }
static PppStateObj& stUp()     { static StUp     s; return s; }
static PppStateObj& stFailed() { static StFailed s; return s; }

// lwIP-Link-Callback -> Maschine (von pppLinkStatusCb aufgerufen).
static void pppOnLinkEvent(int err) { g_ppm.onLink(err); }

// --- Aktionen: die frueheren pppStart/pppStop-Koerper ---
String PppMachine::doDial() {
    usb_device_handle_t dev = findModemHandle();
    // Kurz auf das Modem warten, falls es gerade re-enumeriert (Band-Apply/CFUN).
    for (int i = 0; i < 20 && !dev; i++) { delay(100); dev = findModemHandle(); }
    if (!dev) return "Modem 2C7C:6005 nicht erkannt.";
    const uint32_t startGen = g_modemGen;   // Generation, zu der 'dev' gehoert (Guard vor dem IF4-Claim)

    // ===== LIFECYCLE-GATE (STATE, nicht TIME) -- ganz am Anfang, vor Claim/AT/ATD/RX =====
    // ppp_set_auth/pppapi_connect asserten, wenn der lwIP-pcb nicht in PPP_PHASE_DEAD
    // ist. WeirdOS-"IDLE" ist NICHT gleich lwIP-"DEAD": nach USB-Carrier-Verlust ohne
    // sauberen Close haengt der pcb non-DEAD, obwohl unsere Maschine schon Idle meldet.
    // g_pppcbDead spiegelt die ECHTE lwIP-Phase (gesetzt aus pppLinkStatusCb beim
    // Terminierungs-Event) -- keine Zeitheuristik. Ist der pcb noch nicht DEAD:
    // Carrier-lost-Close (nocarrier=1, kein LCP-TermReq) und auf das Terminierungs-
    // Event warten. Erreicht er DEAD nicht, NICHT dialen (keine Nebenwirkungen am
    // Modem) -> der naechste Supervisor-Lauf versucht es sauber erneut.
    if (g_ppp && !g_pppcbDead) {
        pppapi_close(g_ppp, 1);
        for (int i = 0; i < 100 && !g_pppcbDead; i++) vTaskDelay(pdMS_TO_TICKS(50));  // bis ~5s auf DEAD
        if (!g_pppcbDead) return "PPP-Abbau laeuft noch (lwIP-pcb nicht DEAD) - kein Dial.";
    }

    if (PPP_IF < 8 && g_ifClaimed[PPP_IF]) doTeardown();   // Reste eines Vorversuchs abbauen

    // Diagnose nach (Re-)Enumeration: erst LESEN, was der AT-Port IF3 von sich aus meldet, BEVOR irgendein
    // Kommando geht. Boot-URCs (RDY/+CFUN/+CPIN/+QIND) = das Modem selbst hat neu gestartet; nichts = nur der
    // USB-Link war weg. Einmal je Modem-Generation.
    {
        static uint32_t s_probedGen = 0;
        if (g_modemGen != s_probedGen) {
            s_probedGen = g_modemGen;
            String first = usbReadPending(dev, 3, 0x86, 600);
            Serial.printf("[usb] Erste Bytes IF3 nach Enumeration (gen %lu, %lu ms danach): %s\n",
                          (unsigned long)g_modemGen, (unsigned long)(millis() - g_modemEnumMs), first.length() ? first.c_str() : "(nichts)");
        }
    }
    // Registrierung auf dem zuverlaessigen AT-Port IF3 pruefen (vor IF3-Freigabe).
    if (!modemWaitRegistered(3, 0x0F, 0x86, 20)) {
        return "Modem nicht im Netz registriert (Signal/Band pruefen; nach Bandwechsel "
               "dauert der Neu-Attach ~10-20s). Kurz warten, dann erneut 'Verbinden'.";
    }
    // RF-Snapshot holen, solange IF3 noch geclaimt ist (Band/Frequenz/Signal fuer die
    // UI; bei aktivem PPP ist IF3-AT nicht mehr moeglich).
    modemRfQeng  = modemAtTest(3, 0x0F, 0x86, "AT+QENG=\"servingcell\"");
    modemRfQnw   = modemAtTest(3, 0x0F, 0x86, "AT+QNWINFO");
    modemRfCops  = modemAtTest(3, 0x0F, 0x86, "AT+COPS?");
    modemRfCsq   = modemAtTest(3, 0x0F, 0x86, "AT+CSQ");
    modemRfAti   = modemAtTest(3, 0x0F, 0x86, "ATI");
    modemRfImei  = modemAtTest(3, 0x0F, 0x86, "AT+CGSN");
    modemRfIccid = modemAtTest(3, 0x0F, 0x86, "AT+QCCID");
    modemRfImsi  = modemAtTest(3, 0x0F, 0x86, "AT+CIMI");
    modemRfCpin  = modemAtTest(3, 0x0F, 0x86, "AT+CPIN?");
    modemRfCereg = modemAtTest(3, 0x0F, 0x86, "AT+CEREG?");
    modemRfMs    = millis();
    // Wanduhr aus dem Mobilfunknetz (NITZ) -- jetzt, solange IF3 noch frei ist. Grundlage fuer
    // TLS-Zertifikatspruefung/ACME (modem_clock.h). Fehlschlag ist kein Verbindungsfehler.
    modemClockSync(3, 0x0F, 0x86);
    // Uebernahme eines Modems, das nach einem ESP-Neustart noch im PPP-Datenmodus haengt: der
    // PDP-Kontext laesst sich ueber den weiterhin freien AT-Port (IF3) deaktivieren -> die alte
    // PPP-Session am Modem endet, IF4 faellt in den Kommandomodus zurueck. Im Normalfall (kein
    // aktiver Kontext) ist das ein harmloses OK/ERROR.
    modemAtTest(3, 0x0F, 0x86, "AT+CGACT=0,1");
    if (g_ifClaimed[3]) { usb_host_interface_release(g_usbClient, dev, 3); g_ifClaimed[3] = false; }
    // Generationswechsel waehrend des Aufbaus (Modem hat zwischen Handle-Ermittlung und jetzt neu enumeriert):
    // 'dev' ist dann ein toter Handle -> claim liefert INVALID_STATE, alles Weitere waere Kaskade. Sauber
    // abbrechen, der Supervisor startet den naechsten Versuch mit dem frischen Handle.
    if (g_modemGen != startGen || findModemHandle() != dev)
        return "Modem hat waehrend des Aufbaus neu enumeriert -- Versuch abgebrochen, naechster Lauf nimmt den neuen Handle.";
    if (PPP_IF < 8 && !g_ifClaimed[PPP_IF]) {
        esp_err_t ce = usb_host_interface_claim(g_usbClient, dev, PPP_IF, 0);
        if (ce != ESP_OK)
            return String("interface_claim IF4 fehlgeschlagen: ") + esp_err_to_name(ce);
        g_ifClaimed[PPP_IF] = true;
    }
    if (!pppEnsureBuffers()) return "PPP-Puffer (USB-Transfers, internes DMA-RAM) fehlgeschlagen.";
    xQueueReset(g_pppTxFree);
    for (int i = 0; i < PPP_TX_N; i++) xQueueSend(g_pppTxFree, &g_pppTx[i], 0);
    xQueueReset(g_pppRxDone);
    g_pppTxBytes = 0; g_pppRxBytes = 0;
    g_txPoolWait = 0; g_txPoolTimeout = 0; g_txSubmitFail = 0; g_txMaxInFlight = 0;
    g_txPoolWaitUs = 0; g_txInFlight = 0;

    // IF4 muss im Kommandomodus sein. Antwortet es nicht auf "AT" (Modem haengt noch in einer alten
    // PPP-Session -- typisch nach ESP-Neustart bei laufender Einwahl), erst die Escape-Sequenz "+++"
    // (1 s Ruhe davor/danach) + ATH; hilft das nicht, Modem-Neustart (der Supervisor waehlt danach
    // neu, die USB-Host-Recovery ueberwacht die Re-Enumeration). Vorher half nur Neu-Anstecken.
    {
        // Dasselbe fuer IF4 (Datenport): liegen dort noch PPP-Reste (~}#...) oder Boot-URCs?
        String first4 = usbReadPending(dev, PPP_IF, PPP_EPIN, 300);
        if (first4.length()) Serial.printf("[usb] Erste Bytes IF4 vor AT-Probe: %s\n", first4.c_str());
        String probe = modemAtTest(PPP_IF, PPP_EPOUT, PPP_EPIN, "AT");
        if (probe.indexOf("OK") < 0) {
            Serial.println("[PPP] IF4 antwortet nicht auf AT (alte Datensession?) -> Escape +++ / ATH");
            vTaskDelay(pdMS_TO_TICKS(1100));
            pppRawSend(dev, PPP_EPOUT, "+++");
            vTaskDelay(pdMS_TO_TICKS(1100));
            modemAtTest(PPP_IF, PPP_EPOUT, PPP_EPIN, "ATH");
            probe = modemAtTest(PPP_IF, PPP_EPOUT, PPP_EPIN, "AT");
            if (probe.indexOf("OK") < 0) {
                Serial.println("[PPP] weiterhin keine AT-Antwort auf IF4 -> Modem-Neustart zur Uebernahme");
                String r = modemReset();
                return "Modem haengt im Datenmodus - Neustart ausgeloest, Supervisor waehlt danach neu. " + r;
            }
        }
    }

    // SIM bereit? Gemeinsamer Pfad mit ECM (modem_sim.*): PIN-lose SIMs bleiben unberuehrt; bei
    // "SIM PIN" wird die konfigurierte PIN genau einmal je Boot gesendet (PUK-Schutz) und auf READY
    // gewartet. Ohne bereite SIM wird NICHT gewaehlt (der Dial liefe ohnehin ins Leere).
    {
        String simSt = modemEnsureSimReady(PPP_IF, PPP_EPOUT, PPP_EPIN);
        if (!simSt.startsWith("READY")) return "SIM: " + simSt;
    }

    // Kontext 1 auf IF4 setzen: erst deaktivieren, dann APN + PDP-Typ.
    String apn = modemApn.length() ? modemApn : String("netpublic");
    String pdp = (modemPdpType == "IPV4V6") ? String("IPV4V6") : String("IP");
    modemAtTest(PPP_IF, PPP_EPOUT, PPP_EPIN, "AT+CGACT=0,1");
    modemAtTest(PPP_IF, PPP_EPOUT, PPP_EPIN, "AT+CGDCONT=1,\"" + pdp + "\",\"" + apn + "\"");

    // Einwahlnummer aus der Config (Default *99***1# -> identisch zum bisherigen Verhalten).
    String dial = modemDialNumber.length() ? modemDialNumber : String(MODEM_DIAL_DEFAULT);
    pppRawSend(dev, PPP_EPOUT, "ATD" + dial + "\r");
    vTaskDelay(pdMS_TO_TICKS(700));   // CONNECT abwarten (Text ignoriert PPPoS)

    // pcb ist hier garantiert DEAD (Lifecycle-Gate oben) -> ppp_set_auth/connect sicher.
    if (!g_ppp) {
        g_ppp = pppapi_pppos_create(&g_pppNetif, pppOutputCb, pppLinkStatusCb, NULL);
        if (!g_ppp) { enter(stFailed()); return "pppos_create fehlgeschlagen."; }
        ppp_set_usepeerdns(g_ppp, 1);
        g_pppcbDead = true;                    // frisch erzeugt -> DEAD
    }
    // PPP-Auth JETZT wirklich anwenden (war bisher gespeichert, aber nie gesetzt).
    // "0"=keine -> PPPAUTHTYPE_NONE (= bisheriges Verhalten). PAP/CHAP nur wenn gewaehlt.
    {
        uint8_t at = (modemAuth == "2") ? PPPAUTHTYPE_CHAP
                   : (modemAuth == "1") ? PPPAUTHTYPE_PAP
                   : PPPAUTHTYPE_NONE;
        // ppp_set_auth (core, nicht pppapi): setzt nur pcb-Felder, vor pppapi_connect sicher.
        ppp_set_auth(g_ppp, at, modemUser.c_str(), modemPass.c_str());
    }
    pppapi_set_default(g_ppp);
    g_pppRun = true;
    if (!g_pppRxTask &&
        xTaskCreatePinnedToCore(pppRxTask, "ppp_rx", 4096, NULL, 6, &g_pppRxTask, 1) != pdPASS) {
        g_pppRxTask = NULL; g_pppRun = false;
        enter(stFailed());
        return "PPP-RX-Task nicht anlegbar (interner Heap).";   // sonst Aushandlung ohne Empfaenger = stiller Haenger
    }
    enter(stNeg());                   // ab jetzt verhandelt -> onLink fuehrt weiter
    g_pppcbDead = false;              // pcb verlaesst DEAD (Aushandlung laeuft)
    pppapi_connect(g_ppp, 0);
    return "PPP-Aufbau gestartet (ATD*99#). Status abwarten.";
}

void PppMachine::doTeardown() {
    // GRACEFUL Close (nocarrier=0 -> LCP-TERMREQ): das Modem legt den Datenanruf
    // auf und kehrt in den Kommandomodus zurueck. RX/TX muessen dafuer noch laufen.
    if (g_ppp && g_pppState != PPP_IDLE && g_pppState != PPP_FAILED) {
        pppapi_close(g_ppp, 0);
        for (int i = 0; i < 40 && g_pppState != PPP_IDLE && g_pppState != PPP_FAILED; i++)
            vTaskDelay(pdMS_TO_TICKS(50));   // bis ~2s auf sauberen Close (PPPERR_USER)
    }
    g_pppRun = false;
    usb_device_handle_t dev = findModemHandle();
    if (dev) {
        usb_host_endpoint_halt(dev, PPP_EPIN);  usb_host_endpoint_flush(dev, PPP_EPIN);  usb_host_endpoint_clear(dev, PPP_EPIN);
        usb_host_endpoint_halt(dev, PPP_EPOUT); usb_host_endpoint_flush(dev, PPP_EPOUT); usb_host_endpoint_clear(dev, PPP_EPOUT);
    }
    for (int i = 0; i < 100 && g_pppRxTask; i++) vTaskDelay(pdMS_TO_TICKS(20));
    if (dev && PPP_IF < 8 && g_ifClaimed[PPP_IF]) {   // IF4 freigeben (Channels)
        usb_host_interface_release(g_usbClient, dev, PPP_IF);
        g_ifClaimed[PPP_IF] = false;
    }
    g_pppIp = "";
    modemLinkUp = false;
}

// Serialisiert connect/disconnect (Supervisor-Task vs. Web-Klick -> kein Race).
static SemaphoreHandle_t g_pppMutex = nullptr;

// --- Duenne Wrapper: die bestehende .h-API delegiert an die Maschine ---
String pppStart() {
    if (g_pppMutex && xSemaphoreTake(g_pppMutex, 0) != pdTRUE)
        return "Verbindung wird gerade auf-/abgebaut - kurz warten.";
    String r = g_ppm.connect();
    if (g_pppMutex) xSemaphoreGive(g_pppMutex);
    return r;
}
String pppStop() {
    if (g_pppMutex && xSemaphoreTake(g_pppMutex, 0) != pdTRUE)
        return "Verbindung wird gerade auf-/abgebaut - kurz warten.";
    String r = g_ppm.disconnect();
    if (g_pppMutex) xSemaphoreGive(g_pppMutex);
    return r;
}
void   pppOnDeviceGone() {   // vom USB-DEV_GONE-Handler
    g_pppRun = false;
    g_ppm.onGone();
    g_pppIp = "";
    modemLinkUp = false;
}
String pppStatusText() { return g_ppm.label(); }
bool   pppIsUp()       { return g_ppm.state() == PPP_UP; }
String pppIpStr()      { return g_pppIp; }
struct netif* pppNetifHandle() { return pppIsUp() ? &g_pppNetif : nullptr; }   // rohes PPP-netif (Underlay 7.4b)

// MCU-Autoconnect + Auto-Retry: haelt die PPP-Verbindung hoch, solange
// modemAutoStart aktiv ist - rein controller-gesteuert, OHNE etwas in den
// Modem-Flash zu schreiben. Retry mit Backoff (5..~59s). Die State-Machine ist
// die Wahrheit: nur aus Idle/Failed heraus wird ein neuer Versuch gestartet.
static void pppSupervisorTask(void* arg) {
    int failStreak = 0;
    for (;;) {
        bool idle = (g_ppm.state() == PPP_IDLE || g_ppm.state() == PPP_FAILED);
        if (modemAutoStart && findModemHandle() && idle) {
            String r = pppStart();                    // -> Aushandlung (serialisiert)
            // Fehler NIE stumm: bisher verschwand der Rueckgabetext (z.B. "interface_claim IF4",
            // "PPP-Puffer", "SIM: ...") und das Geraet blieb ohne Link und ohne eine einzige Log-Zeile.
            if (g_ppm.state() != PPP_NEG && g_ppm.state() != PPP_UP) {
                Serial.printf("[PPP] Start fehlgeschlagen: %s (intern frei %uk, groesster %uk)\n", r.c_str(),
                              (unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024),
                              (unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) / 1024));
            }
            // Aushandlung (LCP/IPCP) ist normal in <5s durch. Bleibt sie stehen, kommt
            // KEIN Link-Event mehr (alte Datensession des Modems klemmt LCP -> genau das
            // "erst beim 2. Mal"-Symptom). 12s reichen als Ausgang; laenger warten heilt
            // einen stillen Haenger nicht.
            for (int i = 0; i < 12 && g_ppm.state() == PPP_NEG; i++)
                vTaskDelay(pdMS_TO_TICKS(1000));
            // STILLER HAENGER: immer noch NEG -> WIR schliessen aktiv (das ist der
            // PPPERR_USER, den man im Log sieht) und dialen naechste Runde frisch neu.
            // Origin ausdruecklich loggen, damit klar ist: nicht das Netz, nicht das
            // Modem -- der Supervisor bricht die haengende Aushandlung ab.
            if (g_ppm.state() == PPP_NEG) {
                Serial.println("[PPP] Aushandlung haengt (12s, kein Link-Event) -> Supervisor schliesst + dialt neu");
                pppStop();
            }
            failStreak = (g_ppm.state() == PPP_UP) ? 0 : (failStreak + 1);
        } else if (!modemAutoStart) {
            failStreak = 0;
        }
        int wait = 5 + (failStreak > 6 ? 55 : failStreak * 9);   // Backoff
        for (int i = 0; i < wait; i++) vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void startPppSupervisor() {
    static TaskHandle_t h = nullptr;
    if (!g_pppMutex) g_pppMutex = xSemaphoreCreateMutex();
    if (!h) xTaskCreatePinnedToCore(pppSupervisorTask, "ppp_sup", 8192, NULL, 3, &h, 0);
}

// ---- Online-Monitor: Hintergrund-Sampler (1s) + Peak (Max) -----------------
// Die Rate wird UNABHAENGIG von der UI in loop() gesampelt (modemRateTick), damit
// der Peak auch mitlaeuft, wenn ein anderes Menue offen ist (der Browser-Poll laeuft
// nur bei offenem Monitor). cur/max in kbit/s.
volatile uint32_t g_curTxKbit = 0, g_curRxKbit = 0;   // letzter 1s-Mittelwert
volatile uint32_t g_maxTxKbit = 0, g_maxRxKbit = 0;   // Peak seit letztem Reset

void modemRateTick() {
    static uint32_t lastTx = 0, lastRx = 0, lastMs = 0;
    uint32_t nowMs = millis();
    if (lastMs != 0 && (nowMs - lastMs) < 1000) return;      // ~1s Kadenz
    uint32_t tx = g_pppTxBytes, rx = g_pppRxBytes;
    if (ec200aEcm.isUp()) { tx = g_ecmTxBytes; rx = g_ecmRxBytes; }   // ECM statt PPP
    uint32_t dt = nowMs - lastMs;
    // Nur werten, wenn Vorwert da UND Zaehler monoton (PPP<->ECM-Wechsel/Reconnect
    // setzt die Quelle zurueck -> sonst absurde Spitze). Sonst nur die Basis neu setzen.
    if (lastMs != 0 && dt > 0 && tx >= lastTx && rx >= lastRx) {
        uint32_t txk = (uint32_t)(((uint64_t)(tx - lastTx) * 8) / dt);   // bytes*8/ms == kbit/s
        uint32_t rxk = (uint32_t)(((uint64_t)(rx - lastRx) * 8) / dt);
        g_curTxKbit = txk; g_curRxKbit = rxk;
        if (txk > g_maxTxKbit) g_maxTxKbit = txk;
        if (rxk > g_maxRxKbit) g_maxRxKbit = rxk;
    }
    lastTx = tx; lastRx = rx; lastMs = nowMs;
}

void modemRateResetMax() { g_maxTxKbit = 0; g_maxRxKbit = 0; }

// Momentaner Durchsatz + Peak als JSON-Fragment. Werte aus dem 1s-Sampler
// (modemRateTick, laeuft in loop()) -> konsistent, auch im Hintergrund gemessen.
String pppRateJson() {
    uint32_t tx = g_pppTxBytes, rx = g_pppRxBytes;
    if (ec200aEcm.isUp()) { tx = g_ecmTxBytes; rx = g_ecmRxBytes; }   // ECM-Datenpfad statt PPP (Online-Monitor)
    String j = "\"txkbit\":";     j += g_curTxKbit;
    j += ",\"rxkbit\":";          j += g_curRxKbit;
    j += ",\"maxtxkbit\":";       j += g_maxTxKbit;
    j += ",\"maxrxkbit\":";       j += g_maxRxKbit;
    j += ",\"txbytes\":";         j += tx;
    j += ",\"rxbytes\":";         j += rx;
    j += ",\"txwait\":";          j += g_txPoolWait;      // Pool leer (Backpressure)
    j += ",\"txtimeout\":";       j += g_txPoolTimeout;   // 200ms gerissen -> Drop
    j += ",\"txsubmitfail\":";    j += g_txSubmitFail;
    j += ",\"txmaxinflight\":";   j += g_txMaxInFlight;   // <= PPP_TX_N
    j += ",\"txwaitus\":";        j += g_txPoolWaitUs;    // Summe Wartezeit (us)
    return j;
}


// -----------------------------------------------------------------------------
// Mobilfunk-Modem: Persistenz (NVS "modem") + Aktions-Schicht
//
// Datenpfad: derselbe USB-Stecker wie unter Windows, aber PPP ueber den
// CDC-ACM-Modemport (nicht RNDIS). Das USB-Host-/esp_modem-/PPP-Backend ist
// noch NICHT angebunden - die Aktionsfunktionen unten sind bewusst Stubs mit
// klaren TODOs. Die UI ist dadurch bereits voll bedienbar und testbar.
// -----------------------------------------------------------------------------

// USB-Host-Modem ueberhaupt aktiv? (Default an.) Steuert zusammen mit der
// PC-Erkennung beim Boot, ob der Sketch die USB-PHY fuer den OTG-Host uebernimmt
// -> bei angeschlossenem PC bleibt der Programmierport (kein BOOT-Hack noetig).
bool modemUsbEnabled = true;
// Datenschicht: CDC-ECM ist die Produktions-Datenschicht (Default), PPP der Kompatibilitaetspfad.
// Ein Modem, das noch auf RNDIS (usbnet=3) steht, stellt ec200aEcm::begin() einmalig selbst um.
String modemDataMode = "ecm";
String modemNatMode  = "nic";   // ECM: NIC (oeffentliche IP am ESP) | routing (Modem-NAT)

void loadModemPrefs() {
    modemNvs.begin("modem", true);
    modemUsbEnabled  = modemNvs.getBool("usben", true);
    modemDataMode    = modemNvs.getString("datamode", "ecm");
    modemNatMode     = modemNvs.getString("natmode", "nic");
    modemApn         = modemNvs.getString("apn", MODEM_APN_DEFAULT);
    modemUser        = modemNvs.getString("user", "");
    modemPass        = modemNvs.getString("pass", "");
    modemPdpType     = modemNvs.getString("pdp", MODEM_PDP_DEFAULT);
    modemAuth        = modemNvs.getString("auth", MODEM_AUTH_DEFAULT);
    modemDialNumber  = modemNvs.getString("dial", MODEM_DIAL_DEFAULT);
    modemSimPin      = modemNvs.getString("simpin", "");
    modemAutoconnect = modemNvs.getBool("auto", MODEM_AUTOCONNECT_DEFAULT);
    modemBandProfile = modemNvs.getString("bandp", "auto");
    modemBandCustom  = modemNvs.getString("bandc", "");
    modemNetMode     = modemNvs.getString("netm", "auto");
    modemAutoStart   = modemNvs.getBool("autostart", true);   // P4-TEST: default AN (Modem startet selbst)
    modemNvs.end();
}


void saveModemPrefs() {
    modemNvs.begin("modem", false);
    modemNvs.putBool("usben", modemUsbEnabled);
    modemNvs.putString("datamode", modemDataMode);
    modemNvs.putString("natmode", modemNatMode);
    modemNvs.putString("apn", modemApn);
    modemNvs.putString("user", modemUser);
    modemNvs.putString("pass", modemPass);
    modemNvs.putString("pdp", modemPdpType);
    modemNvs.putString("auth", modemAuth);
    modemNvs.putString("dial", modemDialNumber);
    modemNvs.putString("simpin", modemSimPin);
    modemNvs.putBool("auto", modemAutoconnect);
    modemNvs.putString("bandp", modemBandProfile);
    modemNvs.putString("bandc", modemBandCustom);
    modemNvs.putString("netm", modemNetMode);
    modemNvs.putBool("autostart", modemAutoStart);
    modemNvs.end();
}


// -----------------------------------------------------------------------------
// Mobilfunk-Band/RAT-Konfiguration (LTE-Bandwahl + Netzmodus).
// EC200A-Eigenheit (weicht vom Standardmanual ab!): AT+QCFG="band",<GSM>,<LTE>
// mit BARE-HEX (KEIN 0x!) und nur ZWEI Parametern (kein TDS). 0x-Praefix ODER
// 3 Parameter -> +CME ERROR: 50. GSM="d3" = aktuellen Wert behalten. LTE-Bitmaske
// bit(n-1)=Band n. Anwenden per CFUN-Zyklus (RF aus/an, KEIN USB-Re-Enum).
// -----------------------------------------------------------------------------
// struct LteBandInfo liegt in ec200a_modem.h; LTE_BANDS/LTE_BAND_N sind dort
// als extern deklariert (die UI in der .ino liest sie) -> hier NICHT static.
const LteBandInfo LTE_BANDS[] = {
    {  1, 2100,  0, false }, {  3, 1800,  2, false }, {  5,  850,  4, false },
    {  7, 2600,  6, false }, {  8,  900,  7, false }, { 20,  800, 19, false },
    { 28,  700, 27, false }, { 38, 2600, 37, true  }, { 40, 2300, 39, true  },
    { 41, 2500, 40, true  },
};
const int LTE_BAND_N = sizeof(LTE_BANDS) / sizeof(LTE_BANDS[0]);

// Effektive LTE-Bitmaske (bit n-1 = Band n) fuer das aktive Profil.
uint64_t modemProfileLteMask() {
    if (modemBandProfile == "mid")  return (1ULL << 2);   // 1-2 GHz: B3 (1800)
    if (modemBandProfile == "low")                        // <1 GHz: B20,B8,B28,B5
        return (1ULL << 19) | (1ULL << 7) | (1ULL << 27) | (1ULL << 4);
    if (modemBandProfile == "custom") {
        uint64_t m = strtoull(modemBandCustom.c_str(), NULL, 16);
        if (m) return m;
    }
    uint64_t all = 0;                                     // auto = alle unterstuetzten
    for (int i = 0; i < LTE_BAND_N; i++) all |= (1ULL << LTE_BANDS[i].bit);
    return all;
}

static int modemNwScanMode() {                            // nwscanmode-Wert
    if (modemNetMode == "lte") return 3;
    if (modemNetMode == "gsm") return 1;
    return 0;                                             // auto
}

// Stale RX auf IF3 leeren (URCs/verspaetete Antworten), damit die Set-Kommandos
// saubere Antworten bekommen (sonst "Lag": Antwort haengt eine Runde nach).
static void modemAtDrain(int n) {
    for (int i = 0; i < n; i++) modemAtTest(3, 0x0F, 0x86, "AT");
}

// Wendet Band + Netzmodus an (AT auf IF3; PPP muss unten sein). Statuszeile zurueck.
String modemApplyBands() {
    if (!findModemHandle()) return "Modem nicht erkannt.";
    if (pppIsUp())
        return "Bitte zuerst 'Trennen' - Bandwahl geht nur ohne aktive Verbindung.";

    char lteHex[20];
    snprintf(lteHex, sizeof(lteHex), "%llx", (unsigned long long)modemProfileLteMask());
    int nsm = modemNwScanMode();

    modemAtDrain(6);
    modemAtTest(3, 0x0F, 0x86, "AT+CFUN=0");
    delay(300);
    String r1 = modemAtTest(3, 0x0F, 0x86, String("AT+QCFG=\"band\",d3,") + lteHex);
    modemAtTest(3, 0x0F, 0x86, String("AT+QCFG=\"nwscanmode\",") + nsm + ",1");
    delay(200);
    modemAtTest(3, 0x0F, 0x86, "AT+CFUN=1");     // RF an -> Re-Attach auf neuem Bandset

    if (r1.indexOf("ERROR") >= 0)
        return "Bandwahl abgelehnt (Modem: " + r1 + ").";
    return String("Bandwahl uebernommen (LTE-Maske 0x") + lteHex + ", nwscanmode "
         + nsm + "). Modem sucht neu - kurz warten, dann 'Verbinden'.";
}


// ============================================================================
// Best-SINR-Bandscan (zentral im Treiber, DRY)
//
// Scan each band from the active profile, validate that QENG really reports
// the locked band, take medians for SINR/RSRQ/RSRP, and keep the best band.
// The scan is deliberately manual: repeated CFUN cycles interrupt service.
// ============================================================================
struct BandScanRow { uint8_t band; int sinr; int rsrp; int rsrq; bool ok; };
static const int BAND_SCAN_MAX_ROWS = 12;
static BandScanRow  g_bandScan[BAND_SCAN_MAX_ROWS] = {};
static volatile int g_bandScanN     = 0;
static volatile int g_bandScanState = 0;   // 0 idle, 1 running, 2 done, 3 error
static volatile int g_bandScanCur   = 0;
static volatile int g_bandScanBest  = 0;
static char         g_bandScanMsg[160] = "";
static TaskHandle_t g_bandScanTask  = NULL;
static portMUX_TYPE g_bandScanMux   = portMUX_INITIALIZER_UNLOCKED;

static void bandScanSetMessage(const char* message) {
    portENTER_CRITICAL(&g_bandScanMux);
    strncpy(g_bandScanMsg, message ? message : "", sizeof(g_bandScanMsg) - 1);
    g_bandScanMsg[sizeof(g_bandScanMsg) - 1] = '\0';
    portEXIT_CRITICAL(&g_bandScanMux);
}

static void bandScanSetState(int state, int currentBand, int bestBand) {
    portENTER_CRITICAL(&g_bandScanMux);
    g_bandScanState = state;
    g_bandScanCur = currentBand;
    g_bandScanBest = bestBand;
    portEXIT_CRITICAL(&g_bandScanMux);
}

static void bandScanResetRows() {
    portENTER_CRITICAL(&g_bandScanMux);
    memset(g_bandScan, 0, sizeof(g_bandScan));
    g_bandScanN = 0;
    g_bandScanBest = 0;
    g_bandScanCur = 0;
    g_bandScanMsg[0] = '\0';
    portEXIT_CRITICAL(&g_bandScanMux);
}

static void bandScanAppendRow(const BandScanRow& row) {
    portENTER_CRITICAL(&g_bandScanMux);
    if (g_bandScanN < BAND_SCAN_MAX_ROWS) {
        g_bandScan[g_bandScanN] = row;
        g_bandScanN++;
    }
    portEXIT_CRITICAL(&g_bandScanMux);
}

// Parse one CSV field from a QENG line and respect quoted commas.
static String qengField(const String& line, int idx) {
    int field = 0, start = 0;
    bool quoted = false;
    int n = (int)line.length();
    for (int i = 0; i <= n; i++) {
        char c = (i < n) ? line[i] : ',';
        if (c == '"') { quoted = !quoted; continue; }
        if (c == ',' && !quoted) {
            if (field == idx) {
                String s = line.substring(start, i);
                s.replace("\"", "");
                s.trim();
                return s;
            }
            field++;
            start = i + 1;
        }
    }
    return "";
}

static String qengServingLine(const String& raw) {
    int p = raw.indexOf("+QENG:");
    if (p < 0) return "";
    int e = raw.indexOf('\n', p);
    if (e < 0) e = raw.length();
    return raw.substring(p, e);
}

static uint8_t qengBandNum(const String& value) {
    int v = 0;
    bool any = false;
    for (unsigned i = 0; i < value.length(); i++) {
        char c = value[i];
        if (c >= '0' && c <= '9') {
            v = v * 10 + (c - '0');
            any = true;
        } else if (any) {
            break;
        }
    }
    return any ? (uint8_t)v : 0;
}

static bool parseQengInt(const String& value, int& out) {
    String s = value;
    s.trim();
    if (!s.length()) return false;
    char* end = NULL;
    long v = strtol(s.c_str(), &end, 10);
    if (end == s.c_str()) return false;
    while (*end == ' ' || *end == '\t') end++;
    if (*end != '\0') return false;
    out = (int)v;
    return true;
}

// Read one LTE serving-cell sample from IF3.
static bool readServingSinr(uint8_t& band, int& sinr, int& rsrp, int& rsrq) {
    String q = qengServingLine(modemAtTest(3, 0x0F, 0x86, "AT+QENG=\"servingcell\""));
    if (!q.length()) return false;
    band = qengBandNum(qengField(q, 9));
    if (!band) return false;
    return parseQengInt(qengField(q, 16), sinr)
        && parseQengInt(qengField(q, 13), rsrp)
        && parseQengInt(qengField(q, 14), rsrq);
}

static uint8_t bandNumberForBit(uint8_t bit) {
    for (int i = 0; i < LTE_BAND_N; i++)
        if (LTE_BANDS[i].bit == bit) return LTE_BANDS[i].num;
    return 0;
}

static int medianInt(int* values, int count) {
    for (int a = 0; a < count; a++)
        for (int b = a + 1; b < count; b++)
            if (values[b] < values[a]) {
                int t = values[a]; values[a] = values[b]; values[b] = t;
            }
    return values[count / 2];
}

// Apply one LTE mask and restart RF. Return false when the modem rejects it.
static bool modemLockBandMask(uint64_t mask) {
    if (!mask) return false;
    char hex[20];
    snprintf(hex, sizeof(hex), "%llx", (unsigned long long)mask);
    modemAtDrain(4);
    String c0 = modemAtTest(3, 0x0F, 0x86, "AT+CFUN=0");
    if (c0.indexOf("ERROR") >= 0) return false;
    delay(300);
    String cfg = modemAtTest(3, 0x0F, 0x86, String("AT+QCFG=\"band\",d3,") + hex);
    if (cfg.indexOf("ERROR") >= 0) {
        modemAtTest(3, 0x0F, 0x86, "AT+CFUN=1");
        return false;
    }
    delay(200);
    String c1 = modemAtTest(3, 0x0F, 0x86, "AT+CFUN=1");
    return c1.indexOf("ERROR") < 0;
}

static bool modemLockSingleBand(uint8_t bit) {
    return modemLockBandMask(1ULL << bit);
}

static bool pppOwnsDataInterface() {
    return g_pppState != PPP_IDLE || (PPP_IF < 8 && g_ifClaimed[PPP_IF]);
}

static void bandScanTask(void* arg) {
    const uint64_t candidateMask = modemProfileLteMask();
    bandScanResetRows();
    bandScanSetState(1, 0, 0);

    uint8_t bits[BAND_SCAN_MAX_ROWS];
    int count = 0;
    for (int i = 0; i < LTE_BAND_N && count < BAND_SCAN_MAX_ROWS; i++) {
        if (candidateMask & (1ULL << LTE_BANDS[i].bit))
            bits[count++] = LTE_BANDS[i].bit;
    }

    if (count == 0) {
        bandScanSetMessage("Keine unterstuetzten LTE-Baender im aktiven Profil.");
        bandScanSetState(3, 0, 0);
        g_bandScanTask = NULL;
        vTaskDelete(NULL);
        return;
    }

    int bestSinr = -999, bestRsrq = -999, bestRsrp = -999;
    uint8_t bestBit = 0;
    bool haveBest = false;

    for (int k = 0; k < count; k++) {
        const uint8_t bit = bits[k];
        const uint8_t expectedBand = bandNumberForBit(bit);
        bandScanSetState(1, expectedBand, haveBest ? bandNumberForBit(bestBit) : 0);

        BandScanRow row = { expectedBand, -999, -999, -999, false };
        if (!expectedBand || !modemLockSingleBand(bit)) {
            bandScanAppendRow(row);
            continue;
        }

        bool registered = modemWaitRegistered(3, 0x0F, 0x86, 25);
        if (registered) delay(800);

        int sinrValues[5], rsrpValues[5], rsrqValues[5];
        int got = 0;
        for (int sample = 0; registered && sample < 5; sample++) {
            uint8_t measuredBand = 0;
            int s = 0, rp = 0, rq = 0;
            if (readServingSinr(measuredBand, s, rp, rq)
                    && measuredBand == expectedBand) {
                sinrValues[got] = s;
                rsrpValues[got] = rp;
                rsrqValues[got] = rq;
                got++;
            }
            delay(700);
        }

        if (got > 0) {
            row.sinr = medianInt(sinrValues, got);
            row.rsrp = medianInt(rsrpValues, got);
            row.rsrq = medianInt(rsrqValues, got);
            row.ok = true;

            bool better = !haveBest
                || row.sinr > bestSinr
                || (row.sinr == bestSinr && row.rsrq > bestRsrq)
                || (row.sinr == bestSinr && row.rsrq == bestRsrq && row.rsrp > bestRsrp);
            if (better) {
                haveBest = true;
                bestBit = bit;
                bestSinr = row.sinr;
                bestRsrq = row.rsrq;
                bestRsrp = row.rsrp;
            }
        }
        bandScanAppendRow(row);
    }

    if (!haveBest) {
        // Restore the user's candidate mask instead of leaving the modem on
        // the last tested single band after a failed scan.
        modemLockBandMask(candidateMask);
        modemWaitRegistered(3, 0x0F, 0x86, 25);
        bandScanSetMessage("Kein gueltiger SINR-Messwert; urspruengliche Bandmaske wiederhergestellt.");
        bandScanSetState(3, 0, 0);
    } else {
        const uint8_t bestBand = bandNumberForBit(bestBit);
        bool locked = modemLockSingleBand(bestBit);
        bool registered = locked && modemWaitRegistered(3, 0x0F, 0x86, 25);
        char message[160];
        if (registered) {
            snprintf(message, sizeof(message),
                     "Bestes Band: B%u (SINR %d dB, RSRQ %d dB, RSRP %d dBm) gesperrt.",
                     bestBand, bestSinr, bestRsrq, bestRsrp);
            bandScanSetMessage(message);
            bandScanSetState(2, 0, bestBand);
        } else {
            modemLockBandMask(candidateMask);
            modemWaitRegistered(3, 0x0F, 0x86, 25);
            snprintf(message, sizeof(message),
                     "Bestes Band B%u ermittelt, aber finaler Lock fehlgeschlagen; Bandmaske wiederhergestellt.",
                     bestBand);
            bandScanSetMessage(message);
            bandScanSetState(3, 0, bestBand);
        }
    }

    g_bandScanTask = NULL;
    vTaskDelete(NULL);
}

String modemStartBandScan() {
    if (!findModemHandle()) return "Modem nicht erkannt.";
    if (pppOwnsDataInterface())
        return "Bitte zuerst vollstaendig 'Trennen' - IF4/PPP ist noch aktiv.";
    if (modemNetMode == "gsm") return "SINR-Bandscan ist nur fuer LTE verfuegbar.";

    int state;
    portENTER_CRITICAL(&g_bandScanMux);
    state = g_bandScanState;
    portEXIT_CRITICAL(&g_bandScanMux);
    if (state == 1) return "Scan laeuft bereits.";

    bandScanResetRows();
    bandScanSetState(1, 0, 0);
    if (xTaskCreatePinnedToCore(bandScanTask, "bandscan", 6144, NULL, 4,
                                &g_bandScanTask, 1) != pdPASS) {
        bandScanSetMessage("Task-Start fehlgeschlagen.");
        bandScanSetState(3, 0, 0);
        return "Task-Start fehlgeschlagen.";
    }
    return "Best-SINR-Scan gestartet (jedes Band wird einzeln gemessen).";
}

// Query neighbour and serving cells only while IF3 is available.
String modemNeighbourDump() {
    if (!findModemHandle()) return "Modem nicht erkannt.";
    if (pppOwnsDataInterface())
        return "Nur bei vollstaendig getrennter Verbindung abfragbar (IF3/IF4-Konflikt).";
    String out = modemAtTest(3, 0x0F, 0x86, "AT+QENG=\"neighbourcell\"");
    out += "\n";
    out += modemAtTest(3, 0x0F, 0x86, "AT+QENG=\"servingcell\"");
    return out;
}

String modemBandScanJson() {
    BandScanRow rows[BAND_SCAN_MAX_ROWS];
    int rowCount, state, currentBand, bestBand;
    char message[sizeof(g_bandScanMsg)];

    portENTER_CRITICAL(&g_bandScanMux);
    rowCount = g_bandScanN;
    if (rowCount < 0) rowCount = 0;
    if (rowCount > BAND_SCAN_MAX_ROWS) rowCount = BAND_SCAN_MAX_ROWS;
    memcpy(rows, g_bandScan, sizeof(rows));
    state = g_bandScanState;
    currentBand = g_bandScanCur;
    bestBand = g_bandScanBest;
    memcpy(message, g_bandScanMsg, sizeof(message));
    message[sizeof(message) - 1] = '\0';
    portEXIT_CRITICAL(&g_bandScanMux);

    const char* stateText = (state == 1) ? "running"
                          : (state == 2) ? "done"
                          : (state == 3) ? "error" : "idle";
    String j = "\"scanstate\":\""; j += stateText; j += "\"";
    j += ",\"scancur\":";  j += currentBand;
    j += ",\"scanbest\":"; j += bestBand;
    j += ",\"scanmsg\":\""; j += message; j += "\"";
    j += ",\"scanbands\":[";
    for (int i = 0; i < rowCount; i++) {
        if (i) j += ",";
        j += "{\"band\":"; j += rows[i].band;
        j += ",\"sinr\":"; j += rows[i].sinr;
        j += ",\"rsrp\":"; j += rows[i].rsrp;
        j += ",\"rsrq\":"; j += rows[i].rsrq;
        j += ",\"ok\":";   j += rows[i].ok ? "true" : "false";
        j += "}";
    }
    j += "]";
    return j;
}



// True, sobald das USB/PPP-Backend angebunden ist. Bis dahin false, damit die
// UI ehrlich "noch nicht angebunden" meldet statt Erfolg vorzutaeuschen.
bool modemBackendReady() {
    // Meldet das tatsaechlich implementierte USB/PPP-Backend (nicht mehr der historische
    // Stub return false). Link-Zustand bleibt bewusst getrennt: ein erkanntes Modem kann
    // getrennt sein. (Fix aus GPT-Review b4e454b uebernommen.)
    return modemUsbHostReady && modemUsbFound && modemDeviceHandle() != nullptr;
}


// Menschlicher Status-Text fuer die Oberflaeche. Zeigt aktuell den Stand der
// USB-Host-Erkennung (Enumerationstest durch den Hub).
String modemStatusText() {
    if (modemUsbError.length())  return "USB-Host-Fehler: " + modemUsbError;
    if (!modemUsbHostReady)      return "USB-Host nicht gestartet";
    if (modemUsbFound) {
        return "Modem 2C7C:6005 am USB erkannt (" + String(modemUsbDevCount) + " Geraet(e))";
    }
    if (modemUsbDevCount > 0) {
        char b[24];
        snprintf(b, sizeof(b), "%04X:%04X", modemUsbLastVid, modemUsbLastPid);
        return "USB: " + String(modemUsbDevCount) + " Geraet(e), Modem nicht dabei (zuletzt "
               + String(b) + ")";
    }
    // Direkt aus der Host-Lib: wie viele Geraete haben eine Adresse bekommen
    // (= erfolgreich enumeriert)? Trennt "Enum scheitert" von "NEW_DEV kommt nicht an".
    uint8_t addrs[8];
    int enumNum = 0;
    usb_host_device_addr_list_fill(sizeof(addrs), addrs, &enumNum);
    return "USB-Host aktiv, kein NEW_DEV [Bus-Ev " + String(modemUsbLibEvents)
           + " / Connect-Ev " + String(modemUsbCliEvents)
           + " / enum-Adressen " + String(enumNum)
           + " / RAM " + String((unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024)) + "k"
           + " DMA " + String((unsigned)(heap_caps_get_free_size(MALLOC_CAP_DMA) / 1024)) + "k]";
}


// Baut die PPP-Verbindung ueber den USB-Modemport (IF4) auf.
String modemConnect() {
    modemLastMessage = pppStart();
    return modemLastMessage;
}


// Trennt die PPP-Verbindung.
String modemDisconnect() {
    modemLastMessage = pppStop();
    return modemLastMessage;
}


// Soft-Neustart des Modems (statt Power-Cycle) via AT+CFUN=1,1. Beendet auch eine
// haengende Datensession sauber. Danach re-enumeriert das Modem am USB (~15-20s)
// und wird durch den DEV_GONE-Fix sauber neu erkannt.
String modemReset() {
    if (!findModemHandle()) return "Modem nicht erkannt.";
    if (pppIsUp()) pppStop();                      // erst sauber trennen
    modemAtTest(3, 0x0F, 0x86, "AT+CFUN=1,1");     // Reboot ausloesen (MT-Reset)
    modemLastResetMs = millis();                   // USB-Host-Recovery: Re-Enumeration binnen ~90 s erwartet
    g_lastCfunMs     = modemLastResetMs;           // Diagnose-Zeitstempel (bleibt stehen)
    g_pppState = PPP_IDLE;
    modemLinkUp = false;
    modemLastMessage = "Modem-Neustart ausgeloest (AT+CFUN=1,1). ~15-20s, bis wieder erkannt.";
    return modemLastMessage;
}


// Internet-Test ueber den PPP-Pfad (Default-Route): DNS-Aufloesung als Probe.
String modemRunInternetTest() {
    if (!pppIsUp() && !ec200aEcm.isUp()) return "Kein Datenlink. Zuerst 'Verbinden'.";
    IPAddress ip;
    if (Network.hostByName("connectivitycheck.gstatic.com", ip))   // = WiFi.hostByName (Core 3.x), ohne WiFi-Objekt
        return "Internet OK - DNS aufgeloest: " + ip.toString();
    return "PPP-Link steht, aber DNS-Aufloesung fehlgeschlagen.";
}


// ============================================================================
// Eingebauter LTE-Speedtest (Down + Up ueber PPP)
//
// Misst die tatsaechliche Linkrate ENTKOPPELT von Kamera/MJPEG/TCP-Fenster:
// ein Bulk-Download (GET) und ein Bulk-Upload (POST) ueber PLAIN HTTP (kein TLS
// -> kein Krypto-Deckel auf dem ESP32-S3). PPP ist per pppapi_set_default die
// Default-Route, der Traffic laeuft also ueber das Modem/LTE. Laeuft in einem
// eigenen Task; das Web-UI pollt den Zustand ueber sendModemJson.
//
// Endpoint: Tele2 (klassischer offener HTTP-Speedtest-Server).
// ============================================================================
enum StState { STE_IDLE, STE_DOWN, STE_UP, STE_DONE, STE_ERR };
static volatile StState  g_stState      = STE_IDLE;
static volatile uint32_t g_stDownKbit   = 0, g_stUpKbit = 0;
static String            g_stMsg        = "";
static TaskHandle_t      g_stTask       = NULL;
static volatile bool     g_stWorkersRun = false;   // Master-Kill-Switch fuer alle Worker
static volatile int      g_stTargetWorkers = 0;    // Soll-Zahl aktiver Worker (Worker mit Index >= Soll enden sich)
static volatile int      g_stActiveWorkers = 0;    // Ist-Zahl (Live-Anzeige beim Auto-Ramp)

// Worker-Zahl konfigurierbar (Web-UI) + persistiert; Auto-Ramp findet die
// saettigende Zahl selbst. Ein einzelner TCP-Stream ist fenster-limitiert;
// mehrere parallele Verbindungen saettigen den Uplink in Summe.
static const int    ST_CONN_MAX  = 16;
static int          g_stConn     = 6;        // parallele Verbindungen (Vorgabe)
static bool         g_stAuto     = false;    // Auto-Ramp aktiv?
static volatile int g_stBestConn = 0;        // Auto-Ergebnis: optimale Worker-Zahl (Upload)
static bool         g_stLoaded   = false;    // NVS-Konfig schon geladen?

static const char*    ST_DOWN_URL = "http://speedtest.tele2.net/100MB.zip";  // gross genug fur Dauerlast
static const char*    ST_UP_HOST  = "speedtest.tele2.net";
static const uint16_t ST_UP_PORT  = 80;
static const char*    ST_UP_PATH  = "/upload.php";
static const uint32_t ST_RAMP_MS  = 2500;    // Slow-Start/Verbindungsaufbau ueberspringen
static const uint32_t ST_MEAS_MS  = 6000;    // Steady-State-Messfenster (ms)

// NVS-Persistenz der Speedtest-Konfig (eigene lokale Instanz, wie modemNvs).
static void stEnsureLoaded() {
    if (g_stLoaded) return;
    Preferences p;
    if (p.begin("speedtest", true)) {
        g_stConn = p.getInt("conn", 6);
        g_stAuto = p.getBool("auto", false);
        p.end();
    }
    if (g_stConn < 1)            g_stConn = 1;
    if (g_stConn > ST_CONN_MAX)  g_stConn = ST_CONN_MAX;
    g_stLoaded = true;
}
static void stSaveConfig() {
    Preferences p;
    if (p.begin("speedtest", false)) {
        p.putInt("conn", g_stConn);
        p.putBool("auto", g_stAuto);
        p.end();
    }
}

// Ein Upload-Worker: schreibt dauerhaft POST-Body, solange g_stWorkersRun.
// Gemessen wird NICHT hier, sondern zentral ueber g_pppTxBytes (identisch zum
// Online-Monitor -> konsistente Werte). Mehrere Worker saettigen den Uplink,
// den ein einzelner TCP-Stream (peer-/RTT-limitiert) nicht ausfuellt.
static void stUpWorker(void* arg) {
    int idx = (int)(intptr_t)arg;   // Worker endet, sobald idx >= Soll-Zahl (Runterskalieren)
    uint8_t chunk[1460]; memset(chunk, 'X', sizeof(chunk));
    // Reconnect-Schleife: schliesst tele2 die Verbindung frueh (upload.php nimmt
    // die 1-GiB-POST nicht dauerhaft an), wird sofort neu verbunden und weiter
    // gesendet -> zuverlaessige Dauerlast statt einmaligem Abbruch.
    while (g_stWorkersRun && idx < g_stTargetWorkers) {
        NetworkClient c; c.setTimeout(6000);   // Core 3.x: WiFiClient ist nur ein typedef hierauf
        if (c.connect(ST_UP_HOST, ST_UP_PORT)) {
            String hdr  = "POST " + String(ST_UP_PATH) + " HTTP/1.1\r\n";
            hdr += "Host: " + String(ST_UP_HOST) + "\r\n";
            hdr += "Content-Type: application/octet-stream\r\n";
            hdr += "Content-Length: 1073741824\r\n";
            hdr += "Connection: close\r\n\r\n";
            c.print(hdr);
            while (g_stWorkersRun && idx < g_stTargetWorkers && c.connected()) {
                if (c.write(chunk, sizeof(chunk)) <= 0) vTaskDelay(1);
            }
            c.stop();
        } else {
            vTaskDelay(pdMS_TO_TICKS(100));   // kurze Pause, dann Reconnect
        }
    }
    vTaskDelete(NULL);
}

// Ein Download-Worker: liest dauerhaft und verwirft, solange g_stWorkersRun.
static void stDownWorker(void* arg) {
    int idx = (int)(intptr_t)arg;
    uint8_t buf[1460];
    // Reconnect-Schleife: fertige/abgebrochene Downloads sofort neu starten ->
    // die RX-Last bleibt ueber das ganze Messfenster erhalten.
    while (g_stWorkersRun && idx < g_stTargetWorkers) {
        HTTPClient http; NetworkClient client;
        http.setConnectTimeout(6000); http.setTimeout(6000);
        if (http.begin(client, ST_DOWN_URL) && http.GET() == 200) {
            NetworkClient* s = http.getStreamPtr();
            while (g_stWorkersRun && idx < g_stTargetWorkers && http.connected()) {
                int n = s->available();
                if (n > 0) { if (n > (int)sizeof(buf)) n = sizeof(buf); s->readBytes(buf, n); }
                else vTaskDelay(1);
            }
        }
        http.end();
        if (g_stWorkersRun && idx < g_stTargetWorkers) vTaskDelay(pdMS_TO_TICKS(50));
    }
    vTaskDelete(NULL);
}

static void stSpawn(void (*worker)(void*), int index) {
    xTaskCreatePinnedToCore(worker, "st_wrk", 6144, (void*)(intptr_t)index, 4, NULL, 1);
}

// Feste Worker-Zahl: nConn Worker starten, Rampe ueberspringen, dann das Delta
// des PPP-Zaehlers (g_pppTxBytes bzw. g_pppRxBytes) ueber das Messfenster. Das
// ist genau die Metrik des Online-Monitors -> beide Werte sind konsistent.
static uint32_t stMeasureFixed(void (*worker)(void*), volatile uint32_t* counter, int nConn) {
    if (nConn < 1) nConn = 1; if (nConn > ST_CONN_MAX) nConn = ST_CONN_MAX;
    g_stWorkersRun = true;
    g_stTargetWorkers = nConn;
    g_stActiveWorkers = nConn;
    for (int i = 0; i < nConn; i++) stSpawn(worker, i);
    vTaskDelay(pdMS_TO_TICKS(ST_RAMP_MS));       // Slow-Start/Setup ueberspringen
    uint32_t b0 = *counter, t0 = millis();
    vTaskDelay(pdMS_TO_TICKS(ST_MEAS_MS));       // Steady-State messen
    uint32_t dt = millis() - t0, db = *counter - b0;
    g_stWorkersRun = false; g_stTargetWorkers = 0; g_stActiveWorkers = 0;
    vTaskDelay(pdMS_TO_TICKS(800));              // sauber auslaufen lassen
    return (dt > 0) ? (uint32_t)(((uint64_t)db * 8) / dt) : 0;
}

// Auto-Ramp: 1..MAX Worker schrittweise dazuschalten, je Schritt kurz messen,
// die Zahl mit der hoechsten Rate merken. Abbruch, wenn zwei Schritte in Folge
// nichts mehr bringen (Uplink gesaettigt, Knie ueberschritten). Liefert die
// Spitzenrate; die optimale Worker-Zahl via bestOut.
static uint32_t stMeasureAuto(void (*worker)(void*), volatile uint32_t* counter, int* bestOut) {
    g_stWorkersRun = true;
    g_stTargetWorkers = 0;
    uint32_t bestRate = 0; int bestN = 1; int noImprove = 0;
    const uint32_t STEP_SETTLE_MS = 1200, STEP_MEAS_MS = 2500;
    for (int n = 1; n <= ST_CONN_MAX; n++) {
        stSpawn(worker, n - 1);                  // genau einen Worker dazu
        g_stTargetWorkers = n;
        g_stActiveWorkers = n;
        vTaskDelay(pdMS_TO_TICKS(STEP_SETTLE_MS));
        uint32_t b0 = *counter, t0 = millis();
        vTaskDelay(pdMS_TO_TICKS(STEP_MEAS_MS));
        uint32_t dt = millis() - t0, db = *counter - b0;
        uint32_t rate = (dt > 0) ? (uint32_t)(((uint64_t)db * 8) / dt) : 0;
        if (rate > bestRate + bestRate / 20) {   // > 5 % besser -> lohnt sich
            bestRate = rate; bestN = n; noImprove = 0;
        } else if (++noImprove >= 2) {
            break;                               // Saettigung erreicht
        }
    }
    g_stWorkersRun = false; g_stTargetWorkers = 0; g_stActiveWorkers = 0;
    vTaskDelay(pdMS_TO_TICKS(800));
    if (bestOut) *bestOut = bestN;
    return bestRate;
}

static void speedtestTask(void* arg) {
    g_stDownKbit = 0; g_stUpKbit = 0; g_stMsg = ""; g_stBestConn = 0;
    int bestDown = g_stConn, bestUp = g_stConn;
    // Im ECM-Modus fliessen die Bytes durch den ECM-netif -> dessen Zaehler messen,
    // nicht die PPP-Zaehler (die blieben sonst 0).
    volatile uint32_t* rxC = ec200aEcm.isUp() ? &g_ecmRxBytes : &g_pppRxBytes;
    volatile uint32_t* txC = ec200aEcm.isUp() ? &g_ecmTxBytes : &g_pppTxBytes;
    g_stState    = STE_DOWN;
    g_stDownKbit = g_stAuto ? stMeasureAuto(stDownWorker, rxC, &bestDown)
                            : stMeasureFixed(stDownWorker, rxC, g_stConn);
    g_stState    = STE_UP;
    g_stUpKbit   = g_stAuto ? stMeasureAuto(stUpWorker, txC, &bestUp)
                            : stMeasureFixed(stUpWorker, txC, g_stConn);
    if (g_stAuto) {
        g_stBestConn = bestUp;
        g_stConn     = bestUp;               // optimale Zahl als neue Vorgabe uebernehmen
        stSaveConfig();
        g_stMsg = String("Auto: optimal ~") + bestUp + " Worker (Up) / " + bestDown
                + " (Down) -> als Vorgabe gespeichert.";
    }
    if (g_stDownKbit == 0 && g_stUpKbit == 0) g_stMsg = "Keine Daten (Tele2 erreichbar? Datenlink aktiv?)";
    g_stState    = (g_stDownKbit == 0 && g_stUpKbit == 0) ? STE_ERR : STE_DONE;
    g_stTask     = NULL;
    vTaskDelete(NULL);
}

String modemSpeedtestStart(int conn, bool autoMode) {
    if (!pppIsUp() && !ec200aEcm.isUp()) return "Kein Datenlink. Zuerst 'Verbinden'.";
    if (g_stState == STE_DOWN || g_stState == STE_UP) return "Speedtest laeuft bereits.";
    stEnsureLoaded();
    if (conn >= 1) g_stConn = (conn > ST_CONN_MAX) ? ST_CONN_MAX : conn;  // 0 = Vorgabe behalten
    g_stAuto = autoMode;
    stSaveConfig();
    g_stState = STE_DOWN;   // sofort als laufend markieren (vor dem Task-Start)
    if (xTaskCreatePinnedToCore(speedtestTask, "speedtest", 8192, NULL, 4, &g_stTask, 1) != pdPASS) {
        g_stState = STE_ERR; g_stMsg = "Task-Start fehlgeschlagen";
        return g_stMsg;
    }
    return autoMode
        ? "Auto-Speedtest gestartet (Worker-Ramp 1.." + String(ST_CONN_MAX) + "; ~60-90 s)."
        : (String("Speedtest gestartet (") + g_stConn + " Worker; ~20 s).");
}

String modemSpeedtestJson() {
    stEnsureLoaded();
    const char* st = "idle";
    switch (g_stState) {
        case STE_DOWN: st = "down"; break;
        case STE_UP:   st = "up";   break;
        case STE_DONE: st = "done"; break;
        case STE_ERR:  st = "error";break;
        default:       st = "idle"; break;
    }
    String j = "\"ststate\":\""; j += st; j += "\"";
    j += ",\"stdown\":";   j += g_stDownKbit;
    j += ",\"stup\":";     j += g_stUpKbit;
    j += ",\"stconn\":";   j += g_stConn;                    // eingestellte Worker-Zahl
    j += ",\"stauto\":";   j += g_stAuto ? "true" : "false"; // Auto-Ramp aktiv
    j += ",\"stactive\":"; j += g_stActiveWorkers;           // aktuell laufende Worker (Live)
    j += ",\"stbest\":";   j += g_stBestConn;                // Auto-Ergebnis (optimale Zahl)
    j += ",\"stmsg\":\"";  j += g_stMsg; j += "\"";          // nur treiber-interne, JSON-sichere Texte
    return j;
}


// Schreibt den Autoconnect (persistenter Auto-Dial) in den Flash des Modems
// oder deaktiviert ihn wieder. Siehe reverse-eng/68 Abschnitt 2c.
String modemApplyAutoconnect(bool enable) {
    // TODO(USB/PPP-Backend): Auto-Dial im Modem-NVM setzen/loeschen. Kandidat
    // (am Quectel-AT-Manual fuer EC200A zu verifizieren):
    //   AT+CGDCONT=1,"<pdp>","<apn>"          (APN persistent)
    //   AT+QNETDEVCTL=1,1,<autoconnect>       (autoconnect-Parameter)
    //   ggf. AT&W / QCFG-Autodial-Flag, um es dauerhaft zu speichern.
    // Deaktivieren = autoconnect-Parameter 0 schreiben.
    if (!modemBackendReady()) {
        modemLastMessage = enable
            ? "Autoconnect vorgemerkt (in Flash schreiben, sobald Modem angebunden)."
            : "Autoconnect-Deaktivierung vorgemerkt (Modem noch nicht angebunden).";
        return modemLastMessage;
    }
    modemLastMessage = enable
        ? "Autoconnect in Modem-Flash geschrieben."
        : "Autoconnect im Modem-Flash deaktiviert.";
    return modemLastMessage;
}

#else  // !WEIRDOS_FEATURE_MODEM
// ============================================================================
// Stub: Modem nicht im Build enthalten (WEIRDOS_FEATURE_MODEM=0)
//
// Dieselben Symbole wie ec200a_modem.h, triviale Koerper: KEIN usb_host_*-Aufruf, kein lwIP-PPPoS,
// kein WiFi/HTTPClient (Speedtest), kein Preferences/NVS, kein Task, keine Transfer-Pools. Nichts
// referenziert die usb_host-Komponente oder PPP -> der Linker wirft sie mit --gc-sections samt
// Puffern heraus (Flash + statisches RAM + internes DMA-RAM). Alle Konsumenten (.ino, web_ui.h,
// ui_internet/ui_wan/ui_overview/ui_system, network_registry/-platform, wan_policy,
// peripheral_registry, wifi_caps, serial_console, modem_datalink/-sim/-clock) kompilieren und
// linken unveraendert.
//
// Semantik: kein Modem, kein Link, keine USB-Geraete. Prefs bleiben Compile-Defaults (KEIN
// NVS-Zugriff: die im Flash gespeicherten Modem-Einstellungen bleiben fuer einen spaeteren Build
// mit Modem erhalten). Aktionen liefern den Klartext "nicht im Build enthalten"; die JSON-Fragmente
// tragen dieselben Schluessel wie der Treiber mit Nullwerten (die Web-UI parst sie unveraendert).
//
// startUsbHost()/usbEnumerateDevices() gehoeren konzeptionell zum Baustein USB_HOST (Fundament),
// leben aber hier, weil das Modem heute der EINZIGE USB-Host-Nutzer ist -- siehe startUsbHost().
// ============================================================================

static const char* const kModemNotBuilt = "Modem nicht im Build enthalten (WEIRDOS_FEATURE_MODEM=0)";

// ---- Geteilte Globals (ec200a_modem.h) -----------------------------------------
// Zugangsdaten/Profile: dieselben Compile-Defaults wie der Treiber, damit die Formulare
// (ui_internet, serial_console) sinnvolle Vorgaben zeigen; nichts wird geladen oder gespeichert.
String   modemApn         = MODEM_APN_DEFAULT;
String   modemUser        = "";
String   modemPass        = "";
String   modemPdpType     = MODEM_PDP_DEFAULT;
String   modemAuth        = MODEM_AUTH_DEFAULT;
String   modemDialNumber  = MODEM_DIAL_DEFAULT;
String   modemSimPin      = "";
uint32_t modemLastResetMs = 0;                        // nie ein Reset -> usbHostRecoveryTick (.ino) bleibt inert
bool     modemAutoconnect = MODEM_AUTOCONNECT_DEFAULT;
bool     modemAutoStart   = false;                    // nichts, was automatisch starten koennte
String   modemBandProfile = "auto";
String   modemBandCustom  = "";
String   modemNetMode     = "auto";
bool     modemLinkUp      = false;                    // Link ist und bleibt unten (acmeTick/certTick/weirdReqIsWan lesen das)
String   modemLastMessage = kModemNotBuilt;           // /modem-status.json "msg" nennt den Grund
volatile bool     modemUsbHostReady = false;          // .ino: usbHostStarted = modemUsbHostReady -> bleibt false
volatile bool     modemUsbFound     = false;
volatile int      modemUsbDevCount  = 0;
volatile uint16_t modemUsbLastVid   = 0;
volatile uint16_t modemUsbLastPid   = 0;
volatile uint32_t modemUsbLibEvents = 0;
volatile uint32_t modemUsbCliEvents = 0;
String            modemUsbError     = "";             // startUsbHost() setzt den Grund (-> usbHostSkipReason in der .ino)
// RF-Snapshot: leer, modemRfMs = 0 (nie einer). ui_internet zeigt darueber "Variante noch nicht erkannt".
String   modemRfQeng = "", modemRfQnw = "", modemRfCops = "", modemRfCsq = "";
String   modemRfAti = "", modemRfImei = "", modemRfIccid = "", modemRfImsi = "", modemRfCpin = "", modemRfCereg = "";
uint32_t modemRfMs = 0;
char     g_modemUsbInfo[1] = "";   // leere Schnittstellen-/Endpoint-Karte (/modem-usbinfo prueft strlen())
// Modem-Prefs (NVS "modem"): Compile-Defaults, kein NVS.
bool   modemUsbEnabled = false;    // kein USB-Modem im Build -> ehrlich "aus" (Haken unter WAN > Modem leer)
String modemDataMode   = "ecm";    // wan_policy/network_registry/peripheral_registry leiten daraus die Interface-IDs ab
String modemNatMode    = "nic";

// ---- Tabellen -------------------------------------------------------------------
// LTE-Bandtabelle: LEER, aber gueltig (LTE_BAND_N = 0). ui_internet und die .ino iterieren
// 0..LTE_BAND_N-1 -> keine Zeile. Ein Platzhalter-Element, weil ein Array der Laenge 0 kein
// Standard-C++ ist; es ist ueber LTE_BAND_N nie erreichbar.
const LteBandInfo LTE_BANDS[1] = { { 0, 0, 0, false } };
const int         LTE_BAND_N   = 0;

// ---- Observer / Listener: Registrierung angenommen, es feuert nie ein Ereignis ----
void modemAddPppListener(ModemPppListener cb)           { (void)cb; }
void modemAddPresenceListener(ModemPresenceListener cb) { (void)cb; }

// ---- USB-Host (Baustein USB_HOST) ------------------------------------------------
// Der USB-OTG-Host hat heute genau EINEN Nutzer: das Modem. Darum lebt sein Start im Modem-Treiber
// und faellt mit ihm weg:
//   * WEIRDOS_FEATURE_USB_HOST=0: kein Host-Stack im Build -> nur die Meldung.
//   * WEIRDOS_FEATURE_USB_HOST=1, MODEM=0: der Stack WAERE verfuegbar, aber ohne Client waere
//     usb_host_install() nur Kosten (zwei Tasks, ~8 KB Stacks, Enumeration ohne Abnehmer) ->
//     bewusst No-op. Kommt ein zweiter Host-Nutzer (z.B. USB-WLAN-Adapter), wandert der Host-Start
//     in eine eigene UE hinter WEIRDOS_FEATURE_USB_HOST, und der Modem-Treiber wird deren Client.
// In beiden Faellen bleibt modemUsbHostReady false -> die .ino setzt usbHostStarted nicht und
// uebernimmt modemUsbError als usbHostSkipReason (sichtbar in /modem-status.json "usbhostreason").
void startUsbHost() {
#if WEIRDOS_FEATURE_USB_HOST
    modemUsbError = "USB-Host ohne Nutzer nicht gestartet: Modem nicht im Build enthalten (WEIRDOS_FEATURE_MODEM=0)";
    Serial.println("USB-Host: nicht gestartet -- Modem nicht im Build enthalten (WEIRDOS_FEATURE_MODEM=0), kein anderer USB-Host-Nutzer.");
#else
    modemUsbError = "USB-Host nicht im Build enthalten (WEIRDOS_FEATURE_USB_HOST=0)";
    Serial.println("USB-Host nicht im Build enthalten (WEIRDOS_FEATURE_USB_HOST=0)");
#endif
}

String modemAtTest(uint8_t ifNum, uint8_t epOut, uint8_t epIn, const String& cmd) {
    (void)ifNum; (void)epOut; (void)epIn; (void)cmd;
    return kModemNotBuilt;
}
String modemStatusText()   { return kModemNotBuilt; }
bool   modemBackendReady() { return false; }

// USB-Host-Primitiven fuer den ECM-Pfad: kein Client, kein Geraet, kein Claim.
usb_host_client_handle_t modemUsbClientHandle() { return NULL; }
usb_device_handle_t      modemDeviceHandle()     { return NULL; }   // peripheral_registry/.ino: "kein Modem"
bool modemClaimInterface(uint8_t ifNum, uint8_t alt) { (void)ifNum; (void)alt; return false; }
void modemReleaseInterface(uint8_t ifNum)            { (void)ifNum; }

// Generische USB-Geraete-Sicht (wifi_caps: USB-WLAN-Adapter): ohne Host keine Geraete.
int usbEnumerateDevices(UsbEnumDevice out[], int maxOut) { (void)out; (void)maxOut; return 0; }

// ---- Link-Recovery-Sicht (.ino usbLinkRecoveryTick) ------------------------------
int      modemUsbUnexpectedGone(uint32_t windowMs, uint32_t* lastMs) { (void)windowMs; if (lastMs) *lastMs = 0; return 0; }
void     modemUsbClearGoneHistory() {}
String   modemUsbRootPortCycle(bool* ok) { if (ok) *ok = false; return kModemNotBuilt; }
uint32_t modemEnumGeneration() { return 0; }

// ---- PPP (Internet-Datenpfad) -----------------------------------------------------
String pppStart()        { return kModemNotBuilt; }
String pppStop()         { return kModemNotBuilt; }
void   pppFreeBuffers()  {}
void   pppOnDeviceGone() {}
String pppStatusText()   { return "nicht im Build enthalten"; }
bool   pppIsUp()         { return false; }
struct netif* pppNetifHandle() { return nullptr; }   // network_platform: "modem-ppp" -> kein netif
String pppIpStr()        { return ""; }
// JSON-Fragment mit denselben Schluesseln wie der Treiber (der Online-Monitor liest sie), alles 0.
String pppRateJson() {
    return "\"txkbit\":0,\"rxkbit\":0,\"maxtxkbit\":0,\"maxrxkbit\":0,\"txbytes\":0,\"rxbytes\":0,"
           "\"txwait\":0,\"txtimeout\":0,\"txsubmitfail\":0,\"txmaxinflight\":0,\"txwaitus\":0";
}
void modemRateTick()     {}
void modemRateResetMax() {}

// ---- Modem-Prefs: kein NVS -----------------------------------------------------------
void loadModemPrefs() {}
void saveModemPrefs() {}

// ---- Band-/RAT-Konfiguration -----------------------------------------------------------
uint64_t modemProfileLteMask() { return 0; }
String   modemApplyBands()     { return kModemNotBuilt; }
String   modemStartBandScan()  { return kModemNotBuilt; }
String   modemBandScanJson() {
    return String("\"scanstate\":\"idle\",\"scancur\":0,\"scanbest\":0,\"scanmsg\":\"") + kModemNotBuilt
         + "\",\"scanbands\":[]";
}
String   modemNeighbourDump()  { return kModemNotBuilt; }

// ---- Aktionsschicht (HTTP-Handler der .ino, serielle Konsole) -------------------------
String modemConnect()          { return kModemNotBuilt; }
String modemDisconnect()       { return kModemNotBuilt; }
String modemReset()            { return kModemNotBuilt; }
void   startPppSupervisor()    {}
String modemRunInternetTest()  { return kModemNotBuilt; }   // handleModemTest: ok = (Link up) && ... -> false
String modemApplyAutoconnect(bool enable) { (void)enable; return kModemNotBuilt; }
bool   modemWaitRegistered(uint8_t ifNum, uint8_t epOut, uint8_t epIn, int maxSec) {
    (void)ifNum; (void)epOut; (void)epIn; (void)maxSec;
    return false;
}
String modemSpeedtestStart(int conn, bool autoMode) { (void)conn; (void)autoMode; return kModemNotBuilt; }
String modemSpeedtestJson() {
    return String("\"ststate\":\"idle\",\"stdown\":0,\"stup\":0,\"stconn\":0,\"stauto\":false,"
                  "\"stactive\":0,\"stbest\":0,\"stmsg\":\"") + kModemNotBuilt + "\"";
}

#endif // WEIRDOS_FEATURE_MODEM
