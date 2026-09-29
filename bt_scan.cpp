// ============================================================================
// bt_scan.cpp -- BLE-Geraetesuche + best-effort-Kopplung. Siehe bt_scan.h zur
// Hardware-Grenze (S3 = nur BLE, kein Classic/Audio) und zum On-demand-Konzept.
// ============================================================================
#include "bt_scan.h"
#include "net_scan.h"   // netReconBusy(): BLE-Scan und WLAN-Funk-Recon nicht gleichzeitig

#if __has_include("soc/soc_caps.h")
#include "soc/soc_caps.h"
#endif

#if defined(SOC_BLE_SUPPORTED) && SOC_BLE_SUPPORTED
#define BT_OK 1
#else
#define BT_OK 0
#endif

#if BT_OK

#include <vector>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"

#include "BLEDevice.h"
#include "BLEScan.h"
#include "BLEAdvertisedDevice.h"
#include "BLEClient.h"

// ---- Zustand ---------------------------------------------------------------
struct BtDev {
    String   addr;
    String   name;
    int      rssi;
    uint16_t appearance;
    int      svcCount;
    String   svc0;      // erste Service-UUID (falls beworben)
    String   mfg;       // Hersteller-ID (erste 2 Byte der Manufacturer-Data, little-endian) als Hex
    uint8_t  atype;     // BLE-Adresstyp (NimBLE): 0=public,1=random,2=public-id,3=random-id
    bool     rnd;       // abgeleitet: random/privat (atype 1 oder 3)
};

static SemaphoreHandle_t s_mtx = nullptr;
static std::vector<BtDev> s_devs;
static volatile bool s_running     = false;   // Scan ODER Connect laeuft
static volatile bool s_initialized = false;   // BT-Stack (NimBLE) hochgefahren
static volatile int  s_secs        = 0;
static String        s_connResult  = "";
static BLEClient*    s_client      = nullptr;

static void ensureMtx() { if (!s_mtx) s_mtx = xSemaphoreCreateMutex(); }
static void lk() { if (s_mtx) xSemaphoreTake(s_mtx, portMAX_DELAY); }
static void uk() { if (s_mtx) xSemaphoreGive(s_mtx); }

static String jsonEsc(const String& s) {
    String o; o.reserve(s.length() + 4);
    for (size_t i = 0; i < s.length(); i++) {
        char c = s[i];
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (c >= 0x20) o += c;   // Steuerzeichen weglassen
    }
    return o;
}

// Manufacturer-Data (roh) -> "0xNNNN" aus den ersten zwei Bytes (Company Identifier, LE).
static String mfgId(const String& raw) {
    if (raw.length() < 2) return "";
    uint8_t lo = (uint8_t)raw[0], hi = (uint8_t)raw[1];
    char b[8]; snprintf(b, sizeof(b), "0x%02X%02X", hi, lo);
    return String(b);
}

static void ensureStack() {
    if (!BLEDevice::getInitialized()) {
        BLEDevice::init("WeirdOS");
    }
    s_initialized = true;
}

// ---- Scan-Task -------------------------------------------------------------
static void scanTask(void* arg) {
    int secs = (int)(intptr_t)arg;
    ensureStack();

    BLEScan* scan = BLEDevice::getScan();
    scan->setActiveScan(true);      // aktiv -> auch Namen/Scan-Response
    scan->setInterval(100);
    scan->setWindow(99);

    BLEScanResults* res = scan->start(secs, false);   // blockiert secs Sekunden

    lk(); s_devs.clear(); uk();
    if (res) {
        int n = res->getCount();
        for (int i = 0; i < n; i++) {
            BLEAdvertisedDevice d = res->getDevice(i);
            BtDev e;
            e.addr       = d.getAddress().toString();
            e.name       = d.haveName() ? d.getName() : String("");
            e.rssi       = d.haveRSSI() ? d.getRSSI() : 0;
            e.appearance = d.getAppearance();
            e.svcCount   = d.getServiceUUIDCount();
            e.svc0       = (e.svcCount > 0) ? d.getServiceUUID(0).toString() : String("");
            e.mfg        = mfgId(d.getManufacturerData());
            e.atype      = d.getAddressType();          // echter BLE-Adresstyp (NimBLE), keine MAC-Heuristik
            e.rnd        = (e.atype == 1 || e.atype == 3);
            lk(); s_devs.push_back(e); uk();
        }
    }
    scan->clearResults();   // BLE-seitige Ergebnisliste freigeben (Heap)

    s_running = false;
    vTaskDelete(nullptr);
}

// ---- Connect-Task (best-effort) --------------------------------------------
static void connectTask(void* arg) {
    char* a = (char*)arg;
    String addr(a ? a : "");
    if (a) free(a);

    ensureStack();
    lk(); s_connResult = "verbinde ..."; uk();

    if (!s_client) s_client = BLEDevice::createClient();
    String r;
    bool ok = false;
    if (s_client) ok = s_client->connect(BLEAddress(addr));
    if (ok) {
        int svc = 0;
        auto* m = s_client->getServices();
        if (m) svc = (int)m->size();
        r = "BLE-Verbindung erfolgreich - " + String(svc) + " GATT-Service(s); anschliessend getrennt (kein Bonding).";
        s_client->disconnect();
    } else {
        r = "Verbindung fehlgeschlagen";
    }
    lk(); s_connResult = r; uk();

    s_running = false;
    vTaskDelete(nullptr);
}

// ---- Public API ------------------------------------------------------------
bool btBusy() { return s_running; }

// HINWEIS (Review): die gegenseitige Sperre BLE<->WLAN-Recon ist check-then-set (netReconBusy()
// pruefen, dann s_running setzen), also NICHT atomar. Fuer die aktuelle WebServer-Nutzung
// (Requests seriell) praktisch ausreichend. Sauber waere spaeter ein gemeinsamer
// RadioReconCoordinator/Mutex ueber BLE + net_scan. Bewusst noch nicht gebaut.

void btScanStart(int seconds) {
    ensureMtx();
    if (s_running) return;
    if (netReconBusy()) {   // Funk-Recon-Konflikt: WLAN-Sniff/Kanal/Tiefenscan laeuft -> BLE ablehnen
        lk(); s_connResult = "WLAN-Funk-Scan aktiv - Bluetooth-Suche abgelehnt (nicht gleichzeitig)"; uk();
        return;
    }
    if (seconds < 2)  seconds = 2;
    if (seconds > 30) seconds = 30;
    s_secs = seconds;
    s_running = true;
    if (xTaskCreatePinnedToCore(scanTask, "bt_scan", 8192, (void*)(intptr_t)seconds, 4, nullptr, 1) != pdPASS) {
        s_running = false;
    }
}

void btConnectTest(const String& addr) {
    ensureMtx();
    if (s_running) return;
    if (netReconBusy()) { lk(); s_connResult = "WLAN-Funk-Scan aktiv - BLE-Verbindung abgelehnt"; uk(); return; }
    if (addr.length() < 11) { lk(); s_connResult = "ungueltige Adresse"; uk(); return; }
    s_running = true;
    char* a = strdup(addr.c_str());
    if (xTaskCreatePinnedToCore(connectTask, "bt_conn", 8192, a, 4, nullptr, 1) != pdPASS) {
        s_running = false; if (a) free(a);
    }
}

void btStackRelease() {
    ensureMtx();
    if (s_running) return;   // nicht mitten im Scan/Connect
    if (s_client) { s_client = nullptr; }   // Client wird vom Stack-Deinit mit abgeraeumt
    if (BLEDevice::getInitialized()) {
        BLEDevice::deinit(false);   // false: BT-Controller-Speicher NICHT dauerhaft freigeben (Re-Init moeglich)
    }
    s_initialized = false;
    lk(); s_devs.clear(); s_connResult = ""; uk();
}

String btScanJson() {
    ensureMtx();
    lk();
    String j = "{\"running\":"; j += s_running ? "true" : "false";
    j += ",\"initialized\":"; j += s_initialized ? "true" : "false";
    j += ",\"secs\":"; j += String(s_secs);
    j += ",\"count\":"; j += String((uint32_t)s_devs.size());
    j += ",\"heap\":"; j += String((uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    j += ",\"psram\":"; j += String((uint32_t)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    j += ",\"devices\":[";
    for (size_t i = 0; i < s_devs.size(); i++) {
        const BtDev& e = s_devs[i];
        if (i) j += ",";
        j += "{\"addr\":\"";   j += jsonEsc(e.addr);
        j += "\",\"name\":\""; j += jsonEsc(e.name);
        j += "\",\"rssi\":";   j += String(e.rssi);
        j += ",\"appearance\":"; j += String((uint32_t)e.appearance);
        j += ",\"svc\":";      j += String(e.svcCount);
        j += ",\"svc0\":\"";   j += jsonEsc(e.svc0);
        j += "\",\"mfg\":\"";  j += jsonEsc(e.mfg);
        j += "\",\"rnd\":";    j += e.rnd ? "true" : "false";
        j += ",\"atype\":";    j += String((uint32_t)e.atype);
        j += "}";
    }
    j += "]}";
    uk();
    return j;
}

String btStatusJson() {
    ensureMtx();
    lk();
    String j = "{\"initialized\":"; j += s_initialized ? "true" : "false";
    j += ",\"busy\":"; j += s_running ? "true" : "false";
    j += ",\"connResult\":\""; j += jsonEsc(s_connResult); j += "\"";
    j += ",\"heap\":"; j += String((uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    j += ",\"psram\":"; j += String((uint32_t)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    j += "}";
    uk();
    return j;
}

#else  // !BT_OK -- SoC ohne BLE: sichere No-op-Stubs, damit die Aufrufer linken.

void   btScanStart(int)               {}
void   btConnectTest(const String&)   {}
void   btStackRelease()               {}
bool   btBusy()                       { return false; }
String btScanJson()   { return "{\"running\":false,\"initialized\":false,\"secs\":0,\"count\":0,\"devices\":[]}"; }
String btStatusJson() { return "{\"initialized\":false,\"busy\":false,\"connResult\":\"BLE nicht unterstuetzt\"}"; }

#endif // BT_OK
