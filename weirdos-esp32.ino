// -----------------------------------------------------------------------------
// XIAO ESP32S3 - WiFi Setup Portal
//
// Funktionsweise der Captive-Portal-Erkennung (Stand: getestet mit
// Samsung Galaxy / Android 16, One UI):
//
//   1. Der SoftAP nutzt eine NICHT-private IP (4.3.2.1). Das ist der
//      entscheidende Baustein: Loesen die Probe-Hostnamen auf eine
//      RFC-1918-Adresse auf, bricht Android die Validierung ab und
//      schickt nie eine HTTP-Probe - das Netz wird dann nur als
//      "kein Internet" eingestuft.
//   2. Der DHCP-Server kuendigt die AP-IP explizit als DNS-Server an
//      (OFFER_DNS). Ohne das nutzen manche Clients einen fremden DNS
//      und der Hijack laeuft ins Leere.
//   3. Ein eigener DNS-Responder beantwortet alle A-Queries mit der
//      AP-IP, loggt jede Query und antwortet auf beweisbar nicht
//      existente Namen (.onion, unzulaessige Zeichen) mit NXDOMAIN.
//   4. Die klassischen Android/Apple/Windows-Probes werden bedient;
//      Android erhaelt 302 auf die Portalseite, Apple die Seite direkt
//      mit HTTP 200.
//   5. WLAN-Verbindungsaufbau als nichtblockierende State Machine -
//      der HTTP-Server bleibt waehrend des Verbindungsversuchs
//      durchgehend erreichbar.
//   6. WLAN-Scan asynchron mit Ergebnis-Cache; SSID-Auswahl ueber eine
//      selbst gerenderte Liste statt <datalist>.
//   7. Zielnetz ist Opt-in (wie VPN/DynDNS): Standardmaessig laeuft das
//      Geraet als reiner Setup-AP. Erst wenn im Reiter "Netzwerk" das
//      Einhaengen aktiviert und WLAN eingetragen wurde, verbindet es sich
//      beim Boot. Der AP wird nicht beim Boot gestartet, sondern nur bei
//      fehlender/fehlgeschlagener Zielnetz-Verbindung oder wenn "AP
//      dauerhaft an" gesetzt ist.
//   8. Kamera (OV3660, XIAO ESP32S3 Sense): MJPEG-Stream ueber einen
//      eigenen esp_http_server auf Port 81 (/stream), der als separater
//      Task laeuft und die Arduino-Loop nicht blockiert. Zusaetzlich
//      liefert /capture (Port 80) einzelne JPEGs als Fallback. Die
//      Es gibt nur die Root-URL "/" - in AP und Zielnetz identisch:
//      zuerst das PIN-Gate (Standard-PIN 0000, leer = deaktiviert),
//      danach eine Tab-Oberflaeche (Video, Netzwerk, Kamera, Sicherheit,
//      System). JPEG-Qualitaet ist ein Slider ueber den vollen
//      Treiberbereich 0-63.
//
// Erwartetes Verhalten auf Android/One UI: Nach dem Verbinden markiert
// das System das Netz als anmeldepflichtig ("Du musst dich anmelden");
// ein Tap auf den Netzwerkeintrag oeffnet die Portalseite. Ein
// "kein Internet"-Hinweis nach laengerer Zeit ist erwartbar, da der
// Setup-AP nie Internet bereitstellt.
//
// Benoetigt Arduino-ESP32 Core 3.x (ESP-IDF 5.x) fuer die DHCP-Optionen.
// -----------------------------------------------------------------------------

// Schalterkasten + Regeln ZUERST: welche Bausteine im Image sind (MODULES.md, modules.json).
// Ein Baustein mit WEIRDOS_FEATURE_<KEY>=0 wird hier nicht referenziert; seine
// Uebersetzungseinheit liefert dann nur einen Stub ("nicht im Build enthalten").
#include "weirdos_module_rules.h"

#if WEIRDOS_FEATURE_WIFI
#include <WiFi.h>                  // Baustein WIFI: STA + SoftAP + Scan (WLAN-Funk)
#include <WiFiUdp.h>               // Captive-DNS-Responder (UDP/53 auf dem Setup-AP)
#include <ESPmDNS.h>               // <name>.local -- nur im lokalen Funknetz sinnvoll
#endif
#include <Network.h>               // NetworkClient + Network.hostByName: lwIP-Unterbau, funk-unabhaengig (auch ohne WIFI)
#include <HTTPClient.h>            // DynDNS-Update + Speedtest/Internet-Test (GET/POST) -- KEIN Funk, reitet auf lwIP (MODULES.md 7.4)
#include <WiFiClientSecure.h>     // DynDNS ueber HTTPS (setInsecure, wie Router) -- Kompat-Alias fuer NetworkClientSecure, kein Funk
#include <Preferences.h>
#if WEIRDOS_FEATURE_OTA
#include <Update.h>                // OTA-Firmware-Update ueber die Weboberflaeche
#endif // WEIRDOS_FEATURE_OTA
#include "camera_compat.h"   // esp_camera.h auf S3, inerte Shims auf P4/MIPI (kein DVP-Lib-Header)
#include "esp_http_server.h"
#include <esp_heap_caps.h>
#include <esp_timer.h>
#include <esp_netif.h>
#include <esp_event.h>              // esp_event_loop_create_default() -- fuer den WLAN-losen Netz-Unterbau
#include <esp_task_wdt.h>          // 7.9.10: Task-WDT unter VPN-Dauerlast entschaerfen (Idle-Starve)
#include <esp_idf_version.h>
#if WEIRDOS_FEATURE_USB_HOST
#include "usb/usb_host.h"          // USB-Host: Modem-Erkennung (2C7C:6005) am Hub
#endif // WEIRDOS_FEATURE_USB_HOST
#include "driver/usb_serial_jtag.h" // PC-am-USB-Erkennung (SOF) -> Host nur ohne PC starten
#include "esp_log.h"               // Log-Umleitung in RAM-Puffer (/modem-log)
#if WEIRDOS_FEATURE_MODEM
#include "netif/ppp/pppapi.h"      // lwIP PPPoS (threadsicher) fuer den Internet-Datenpfad
#include "netif/ppp/pppos.h"       // pppos_input_tcpip
#endif // WEIRDOS_FEATURE_MODEM
#include "lwip/opt.h"              // TCP_MSS/TCP_SND_BUF/TCP_WND (Durchsatz-Diagnose)

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
#include "dhcpserver/dhcpserver.h"
#endif
#include "ec200a_modem.h"          // EC200A-Treiber (USB-Host/AT/PPP/Band) - ausgelagert
#include "ec200a_ecm.h"            // CDC-ECM-Datenpfad (Alternative zu PPP, umschaltbar)
#include "web_ui.h"                // View-Schicht (HTML/CSS/JS-Renderer) - ausgelagert
#include "peripheral_registry.h"   // Hardware-/Geraete-/Capability-Registry (Zuordnung)
// {name}-Path-Parameter macht der WeirdHttpEsp-Adapter selbst (splitSegs) -> keine
// UriBraces/WebServer-Abhaengigkeit mehr.
#include "esp_random.h"            // Zufalls-Session-Token (Auth-Cookie traegt die PIN nicht mehr)
#include "network_registry.h"      // Registry konkreter Netzwerk-Interfaces (Stufe 7.2)
#include "egress_policy.h"          // geordnete Egress-Auswahl -> Interface (Stufe 7.2b)
#include "wan_policy.h"             // System-WAN-Policy (geordnete Uplink-Wahl; Dienste konsumieren spaeter)
#include "setup_guard.h"            // Einrichtung: Captive-Portal-Sicherung + Werksreset (BOOT/GPIO0)
#include "wifi_caps.h"              // WLAN-Capability-Query (repeaterCapable/wifiRadioCount, runtime)
#include "settings_backup.h"        // zentraler NVS-Sicherungs-Manager (Export/Import, ohne Secrets)
#include "logo_banner.h"            // Banner-PNG-Bytes fuer die Route /banner.png
#include <nvs_flash.h>              // nvs_flash_erase() fuer den kompletten Werksreset (Stufe 2)
#include "network_platform.h"       // 7.9.4: wgRouteDiagJson (Rueckweg-Diagnose)
#include "zone_planner_adapter.h"   // Netzzonen 0.2: /zones-plan.json (Planner-Vorschau, read-only)
#include "zone_lwip_hooks.h"        // Netzzonen 0.3: zoneLwipJson() in /net-interfaces.json
#include "zone_runtime.h"           // Netzzonen 0.5: Policy-Runtime (begin/poll, /zones.json)
#include "net_scan.h"               // 7.10: LAN-Host-Scan + Ping (esp_ping)
#include "bt_scan.h"                 // 8.0: Bluetooth-LE-Geraetesuche + best-effort-Kopplung (BLE-only)
#include "http_transport.h"         // interface-gebundener HTTPS-Transport (Stufe 7.2c-1)
#include "wireguard_service.h"      // WireGuard-Backend (Stufe 7.3: nur Build/Init, kein Tunnel)
#include "ipsec_service.h"          // 8.1: IPsec/IKEv2(+L2TP)-Backend (Config/Status; Runtime folgt)
#include "ipsec_config_fields.h"    // EIN Feld-Layer fuer Web-POST und serielle Konsole (gleiche Pruefung)
#include "ipsec_trust_store.h"      // Trust-Modell: Zertifikatsinfo fuer die UI-Liste (/ipsec-certinfo)
#include "vpn_status.h"             // EIN VPN-Statusmodell (WireGuard + IPsec) fuer die Uebersicht (/vpn-status.json)
#include "access_policy.h"          // Zugangsregel je Dienst (LAN / VPN / Internet)
#include "network_mode.h"           // Betriebsart (Netzwerk-Modus, Phase 1: Config/Anzeige, No-op)
#include "wan_service.h"            // Generalisiertes WAN + Internet-Check (Hintergrund-Task)
extern "C" {
#include "src/qrcode/qrcode.h"      // 7.4d.4: QR-Encoder (ricmoo, MIT) fuer Client-Config-QR
}
#include "camera_manager.h"        // Kamera-Abstraktion (S3-DVP jetzt, P4-MIPI spaeter)
#include "camera_stream_service.h" // MJPEG-Verteiler "ein Frame fuer alle"
#include "camera_server.h"          // Kamera-HTTP: MJPEG-Server + /capture (besitzt/koordiniert)
#include "rtsp_server.h"            // RTSP/RTP (RFC 2326/2435/6184) -- Alternative zum HTTP-Stream-Server
#include "usb_device_service.h"     // WeirdOS als USB-Geraet am PC (UVC-Webcam) -- Port aus dem Board-Mapping
#include "usb_ports.h"              // USB-Port-Mapping des Boards (Nutzer-Konfig: Anzahl, Pins, Namen)
#include "platform.h"               // Board-Profil (P4-Pico | XIAO-S3 | Custom): zentrale Faehigkeiten + Pinout-SVG
void startVideoTransport();   // unten definiert (Video-Transport: HTTP ODER RTSP ODER aus)
#include "h264_encoder.h"           // HW-H.264-Encoder (P4) -> Codec-Capability fuers UI-Dropdown
#include "ppa_converter.h"          // HW-Farbkonvertierung RGB565->YUV420 (P4 PPA) fuer den H.264-Eingang
#include "weird_http.h"             // neutrale HTTP-Abstraktion (weirdHttpParseCookie etc.)
#include "weird_http_esp.h"         // Control-Plane-Adapter: esp_http_server (HTTP ODER HTTPS)
#include "tls_selfsigned.h"         // On-Device self-signed Cert fuer den HTTPS-Management-Transport
#include "weird_auth.h"             // backend-unabhaengiger Session-/Zugriffsdienst
#include "serial_console.h"         // serielle Bedien-Konsole (Alternative zur Web-UI, v.a. P4)
#include "modem_datalink.h"         // neutrale Datenlink-Schicht (ppp|ecm) -- EINE Weiche
#include "h264_guard.h"             // Boot-Reserve fuer den H.264-Referenzpuffer (intern, zusammenhaengend)
#include "modem_sim.h"              // SIM-PIN-Verwaltung (Sperre an/aus/aendern) + SIM-Bereitschaft
#include "modem_clock.h"            // Systemzeit aus dem Mobilfunknetz (Uebersicht, TLS/ACME)
#include "acme_client.h"            // On-Device-ACME (Let's Encrypt) fuer das Management-HTTPS (Phase 3)
#include "cert_store.h"             // EINE Quelle der Wahrheit fuer das HTTPS-Zertifikat (self-signed/Upload/ACME)
#include <sdkconfig.h>              // CONFIG_IDF_TARGET_* fuer Board-Self-Detect

// Board-Self-Detect: siehe wifi_caps.h (wifiPresent()/wifiStackShouldInit()) -- konsolidiert,
// war frueher hier als eigenes boardHasWifi() dupliziert (identische Logik, zwei Quellen).

// -----------------------------------------------------------------------------
// Konfiguration
// -----------------------------------------------------------------------------

// ENABLE_DHCP_OPTION_114:
//   Deaktiviert lassen. Android akzeptiert die Captive-Portal-API nur ueber
//   HTTPS mit vertrauenswuerdigem Zertifikat; ein lokaler Setup-AP kann das
//   nicht bieten, und ein halbfunktionierender Zweitpfad stoert nur.
#define ENABLE_DHCP_OPTION_114 0

static const char* CONFIG_AP_SSID = "WeirdOS";
static const char* CONFIG_AP_PASSWORD = "";

// Bewusst KEINE RFC-1918-Adresse: Android bricht die Portalerkennung ab,
// wenn die Probe-Hostnamen auf eine private IP aufgeloest werden, und
// schickt dann nie eine HTTP-Probe. Mit einer oeffentlich aussehenden
// Adresse greift dieser Abbruch nicht. 4.3.2.1 ist der in ESP32-Portal-
// Projekten etablierte Wert; die echte oeffentliche 4.3.2.1 ist waehrend
// der Verbindung mit dem Setup-AP schlicht nicht erreichbar (der AP hat
// ohnehin kein Internet).
static const IPAddress AP_IP(4, 3, 2, 1);
static const IPAddress AP_NETMASK(255, 255, 255, 0);

// Hostname im Zielnetz: DHCP-Geraetename im Router und mDNS-Name
// (http://xiao-setup.local). Hinweis: Android-Browser loesen .local
// je nach Version unzuverlaessig auf; die IP ist dort der sichere Weg.
const char* DEVICE_HOSTNAME = "weirdos";   // Default; ohne static: externe Bindung fuer web_ui.cpp
String deviceHostname = DEVICE_HOSTNAME;   // konfigurierbare Router-URL (System->Allgemein) -> <name>.local

// AP-Abschaltung: 30 s nach bestaetigter Erreichbarkeit im Zielnetz
// (HTTP-Request ueber das STA-Interface), spaetestens aber nach 10 min
// stabiler Verbindung. Faellt die STA-Verbindung spaeter dauerhaft aus,
// wird der Setup-AP automatisch wieder aktiviert.
// AP-Verhalten:
//   Der Setup-AP dient ausschliesslich der WLAN-Einrichtung und wird NICHT
//   beim Boot gestartet. Beim Start wird zuerst das Zielnetz versucht.
//   Nur wenn das fehlschlaegt, wird der AP nachtraeglich als Einrichthilfe
//   gestartet. Bei erfolgreichem Connect bleibt der AP aus - es sei denn,
//   der Nutzer hat "AP dauerhaft an" gesetzt (NVS, ueberall setzbar).
static const bool KEEP_AP_DEFAULT = false;

// PIN-Schutz: Standard-PIN nach Werksreset. Leere PIN = deaktiviert.
const char* PIN_DEFAULT = "0000";   // ohne static: externe Bindung fuer web_ui.cpp

// Zielnetz ist eine Opt-in-Funktion (wie VPN/DynDNS): standardmaessig aus.
static const bool TARGET_NETWORK_DEFAULT = false;

// Mobilfunk-Modem (EC200A ueber USB-CDC-ACM + PPP). Die APN-/Zugangsdaten
// liegen im ESP32-NVS ("modem"); der Autoconnect wird zusaetzlich in den
// Flash des Modems geschrieben (persistenter Auto-Dial, wieder abschaltbar).
// Das eigentliche USB/PPP-Backend folgt separat - hier zunaechst nur UI,
// Persistenz und klar markierte Aktions-Stubs.

// Kamera: OV3660 auf dem XIAO ESP32S3 Sense.
// Pinbelegung entspricht CAMERA_MODEL_XIAO_ESP32S3 aus den Espressif-
// Beispielen. In der Arduino-IDE muss unter Tools -> PSRAM "OPI PSRAM"
// aktiviert sein; ohne PSRAM bleibt die Kamera deaktiviert (das Portal
// und alle uebrigen Funktionen laufen normal weiter).
#define CAM_PIN_PWDN   -1
#define CAM_PIN_RESET  -1
#define CAM_PIN_XCLK   10
#define CAM_PIN_SIOD   40
#define CAM_PIN_SIOC   39
#define CAM_PIN_D7     48
#define CAM_PIN_D6     11
#define CAM_PIN_D5     12
#define CAM_PIN_D4     14
#define CAM_PIN_D3     16
#define CAM_PIN_D2     18
#define CAM_PIN_D1     17
#define CAM_PIN_D0     15
#define CAM_PIN_VSYNC  38
#define CAM_PIN_HREF   47
#define CAM_PIN_PCLK   13

// Start-Aufloesung nach dem Boot (SVGA: guter Kompromiss aus Bildrate
// und Detail). Das Maximum ist konfigurierbar - siehe unten.
static const framesize_t CAMERA_FRAME_SIZE = FRAMESIZE_SVGA;
static const int CAMERA_JPEG_QUALITY = 12;

// Kamera-Konfiguration: Defaults, ueberschreibbar auf der Kameraseite.
// Die Werte landen im NVS (Namespace "camera") und werden beim Boot
// geladen - Umkonfigurieren wirkt nach einem Neustart, wie beim WLAN.
//
// Aufloesung hat Vorrang vor fps: Reicht das PSRAM nicht fuer zwei
// Framebuffer in der Maximalaufloesung, wird zuerst auf einen Buffer
// reduziert (Bildrate sinkt), erst danach die Aufloesung gesenkt.
static const char* CAMERA_DEFAULT_MAX_SIZE_NAME = "qxga";
static const int CAMERA_DEFAULT_TARGET_FPS = 10;

// Standardmaessig ist nur EIN gleichzeitiger MJPEG-Stream erlaubt
// (Bandbreite und Funkzeit). Mehrfach-Streams (bis MAX_STREAM_CLIENTS)
// lassen sich per Checkbox in der Kamera-Konfiguration aktivieren.
static const bool CAMERA_DEFAULT_MULTI_STREAM = false;

// Sicherheitsreserve im PSRAM fuer WLAN-Stack und andere Nutzer.
static const size_t CAMERA_PSRAM_RESERVE_BYTES = 512 * 1024;


// Zentrale Aufloesungstabelle - einzige Quelle fuer Init-Entscheidung,
// Laufzeit-Umschaltung und die Auswahlfelder der Weboberflaeche.
struct FrameSizeOption {
    const char* name;
    const char* label;
    framesize_t size;
    uint32_t width;
    uint32_t height;
};

static const FrameSizeOption FRAME_SIZE_OPTIONS[] = {
    { "vga",  "VGA 640&times;480",    FRAMESIZE_VGA,  640,  480  },
    { "svga", "SVGA 800&times;600",   FRAMESIZE_SVGA, 800,  600  },
    { "xga",  "XGA 1024&times;768",   FRAMESIZE_XGA,  1024, 768  },
    { "hd",   "HD 1280&times;720",    FRAMESIZE_HD,   1280, 720  },
    { "uxga", "UXGA 1600&times;1200", FRAMESIZE_UXGA, 1600, 1200 },
    { "qxga", "QXGA 2048&times;1536", FRAMESIZE_QXGA, 2048, 1536 },
};

extern const int FRAME_SIZE_OPTION_COUNT =   // extern: von web_ui.cpp verlinkt
    sizeof(FRAME_SIZE_OPTIONS) / sizeof(FRAME_SIZE_OPTIONS[0]);

static const byte DNS_PORT = 53;

static const unsigned long WIFI_CONNECT_TIMEOUT_MS = 20000;
static const unsigned long WIFI_RETRY_INTERVAL_MS = 30000;

static const unsigned long SCAN_CACHE_TTL_MS = 20000;
static const unsigned long SCAN_TIMEOUT_MS = 15000;

static const int MAX_CACHED_NETWORKS = 24;

static const unsigned long LED_BLINK_INTERVAL_MS = 250;


// -----------------------------------------------------------------------------
// Zustandstypen
// -----------------------------------------------------------------------------

enum PortalWifiState {
    PORTAL_WIFI_IDLE,
    PORTAL_WIFI_CONNECTING,
    PORTAL_WIFI_CONNECTED,
    PORTAL_WIFI_FAILED
};


enum PortalScanState {
    PORTAL_SCAN_IDLE,
    PORTAL_SCAN_RUNNING,
    PORTAL_SCAN_DONE,
    PORTAL_SCAN_FAILED
};


struct ScannedNetwork {
    String ssid;
    int32_t rssi;
    bool secure;
};


// -----------------------------------------------------------------------------
// Globaler Zustand
// -----------------------------------------------------------------------------

// Der globale Arduino-WebServer ist mit dem WeirdHttpEsp-Flip entfallen -- die
// Control-Plane laeuft komplett ueber g_web (esp_http_server), Port 80, HTTP.
// HTTPS folgt auf demselben Esp-Backend als eigener Schritt. Muss vor loop() stehen.
WeirdHttpEsp g_web(80, false);
// Port-80-Hilfsserver, NUR wenn die Verwaltung auf HTTPS:443 laeuft: beantwortet die ACME-http-01-
// Challenge (/.well-known/acme-challenge/<token>, PUBLIC) und leitet alles andere per 301 auf
// https:// um. Eigener Control-Port 32772, kleiner Stack (kein App-Render).
#if WEIRDOS_FEATURE_ACME
WeirdHttpEsp g_web80(80, false);
#endif // WEIRDOS_FEATURE_ACME
// Laeuft die Management-Control-Plane gerade ueber HTTPS? Bestimmt das Secure-Cookie-Flag
// und die Transportwechsel-Invalidierung. Task 4 (HTTPS-Transport) setzt das aus der Config;
// bis dahin HTTP (false).
bool g_managementSecure = false;
#if WEIRDOS_FEATURE_WIFI
WiFiUDP dnsSocket;   // Captive-DNS-Hijack des Setup-AP (nur mit WLAN-Baustein)

static const int DNS_MAX_PACKET_SIZE = 512;
uint8_t dnsPacket[DNS_MAX_PACKET_SIZE];
#endif
Preferences preferences;

void loadGeneralPrefs() {
    preferences.begin("cfg", true);
    deviceHostname = preferences.getString("host", DEVICE_HOSTNAME);
    g_cryptoMemPsram = preferences.getBool("cryptopsram", psramFound());   // 7.9.14
    preferences.end();
    deviceHostname.trim();
    if (deviceHostname.length() == 0) deviceHostname = DEVICE_HOSTNAME;
}
void saveGeneralPrefs() {
    preferences.begin("cfg", false);
    preferences.putString("host", deviceHostname);
    preferences.putBool("cryptopsram", g_cryptoMemPsram);   // 7.9.14
    preferences.end();
}

String configuredSsid;
String configuredPassword;
String setupApPassword = CONFIG_AP_PASSWORD;

PortalWifiState wifiState = PORTAL_WIFI_IDLE;
unsigned long wifiAttemptStartedAt = 0;
unsigned long wifiLastAttemptAt = 0;

#if WEIRDOS_FEATURE_WIFI
PortalScanState scanState = PORTAL_SCAN_IDLE;
unsigned long scanStartedAt = 0;
unsigned long scanCompletedAt = 0;
bool scanRequested = false;

ScannedNetwork cachedNetworks[MAX_CACHED_NETWORKS];
int cachedNetworkCount = 0;
#endif

unsigned long ledLastToggleAt = 0;
bool ledIsOn = false;

#if WEIRDOS_FEATURE_WIFI
char captivePortalApiUri[48];
#endif

bool setupApActive = false;
bool keepApAlways = KEEP_AP_DEFAULT;
bool targetNetworkEnabled = TARGET_NETWORK_DEFAULT;
String devicePin = PIN_DEFAULT;
bool mdnsStarted = false;

bool cameraReady = false;
// Der MJPEG-Stream-Server + /capture leben jetzt in CameraServer (camera_server.*).

// USB-Host-Modem: Laufzeit-Status. Der OTG-Host wird beim Boot nur gestartet,
// wenn das Modem aktiviert ist UND kein PC am USB haengt -> sonst bleibt der
// Serial-JTAG-Programmierport erhalten (normales Flashen ohne BOOT-Hack).
bool   usbHostStarted    = false;
String usbHostSkipReason = "";

// Erkennt einen am USB angeschlossenen PC: der USB-Serial-JTAG sieht dessen
// SOF-Pakete (auch ohne geoeffneten COM-Port); eine Powerbank wird NICHT
// erkannt. Kurzes Fenster, damit die USB-Enumeration nach dem Boot Zeit hatte.
bool usbPcConnected() {
    for (int i = 0; i < 30; i++) {
        if (usb_serial_jtag_is_connected()) return true;
        delay(50);
    }
    return false;
}

// Konfiguriertes Maximum (NVS), tatsaechlich aktives Maximum (nach
// Speicherpruefung und ggf. QXGA-Fallback) und aktuelle Aufloesung.
int cameraConfiguredMaxIndex = 0;
int cameraActiveMaxIndex = 0;
int cameraCurrentIndex = 0;
int cameraStartSizeIndex = 1;
int cameraTargetFps = CAMERA_DEFAULT_TARGET_FPS;
int cameraFbCount = 2;

// Bildpuffer-Qualitaet (Init, bestimmt die reservierte Puffergroesse) und
// aktuelle Live-Qualitaet. 0 = beste/groesste Frames. Der Puffer wird auf
// cameraBufferQuality dimensioniert; solange die Live-Qualitaet >= diesem
// Wert bleibt, kann der Puffer nicht ueberlaufen. Default 0 = Puffer fuer
// die bestmoegliche Qualitaet -> der Live-Slider ist ueber den ganzen
// Bereich 0-63 sicher (automatische Ueberlauf-Vermeidung).
int cameraBufferQuality = 0;
int cameraCurrentQuality = 12;

// Roh-MJPEG-Stream: aktivierbar und optional per Schluessel gesichert. Port und
// Pfad sind konfigurierbar (Default 81 / "/stream"); Aenderung wirkt nach Neustart.
// Wird vom Nutzer selbst in der Konfiguration gesetzt.
bool streamEnabled = true;
String streamKey = "";
int streamPort = 81;
String streamPath = "/stream";
// Video-Server: Transport-Auswahl + RTSP (RTSP-Server-Runtime folgt; heute Config-Stub).
String streamType = "http";      // "http" (MJPEG) | "rtsp"
bool   rtspEnabled = false;
int    rtspPort = 554;
String rtspTransport = "tcp";    // "tcp" | "udp"

// Mehrere gleichzeitige Streams erlaubt?
bool multiStreamEnabled = CAMERA_DEFAULT_MULTI_STREAM;



// WAN-Web-Schalter: ist die Weboberflaeche ueber die Mobilfunk-Seite (WAN/PPP)
// erreichbar? true = wie bisher (alle Interfaces). false = nur LAN (WLAN/AP),
// ueber das Internet wird die Oberflaeche nicht mehr angezeigt. NVS "wifi".
bool   webWanEnabled = true;
bool   webHttpsEnabled = false;   // Management-Transport: HTTPS (443) statt HTTP (80). Default HTTP (siehe loadConfig).


// DynDNS (Internet -> Freigaben). Persistenz im NVS "dyndns". Der eigentliche
// Update-Loop kommt mit der Internetverbindung (PPP).
// ============================================================================
// P4-TEST-DEFAULTS (nur ESP32-P4-Bring-up OHNE WLAN-Konfig-UI).
// HINWEIS: Der DynDNS-Default ist LEER. Der Provider-Token (z.B. IONOS) darf
//   NICHT im Quellcode stehen (dieses Repo ist oeffentlich). Die DynDNS-URL wird
//   zur Laufzeit gesetzt: ueber die Web-UI oder NVS (Preferences-Schluessel "url").
// ============================================================================
static const char* DYNDNS_TEST_URL = "";   // LEER: Token gehoert nicht in den Quellcode; zur Laufzeit setzen (Web-UI/NVS)
static const char* DYNDNS_TEST_DOMAIN = "angelworks.eu";

bool   dyndnsEnabled = true;        // P4-TEST: default AN (kein UI zum Aktivieren)
bool   diagEnabled   = true;        // Entwickler-Diagnose (AT-Konsole/USB-Info/Log) aktiv? (Web-UI: Diagnose)
String dyndnsProvider = "custom";   // aktuell nur "custom" (Benutzerdefiniert)
String dyndnsUrl = DYNDNS_TEST_URL;         // P4-TEST: hart als Default (s. Warnung oben)
String dyndnsDomain = DYNDNS_TEST_DOMAIN;   // P4-TEST
String dyndnsUser = "";
String dyndnsPass = "";
// Ausgehendes Netz (Egress-Interface) fuer den DynDNS-Request: bestimmt, welche
// Quell-IP der Provider sieht. "auto" = Mobilfunk bevorzugen (heutiges Verhalten),
// "modem" = Mobilfunk-WAN erzwingen, "wifi" = ueber WLAN-STA. Erste Stufe der
// spaeteren EgressPolicy/Network-Registry: der DynDNS-Dienst bekommt ein waehlbares
// Netzwerk-Objekt statt fest verdrahtetem ECM.
String dyndnsEgress = "auto";

// Energie (System -> Energiemonitor). NVS "energy".
// CPU-Profil = statischer Takt via setCpuFrequencyMhz (kein DFS in diesem Build).
// power=240, balanced=160, eco=80 MHz (unter 80 MHz wuerde WLAN abschalten).
String cpuProfile = "balanced";
bool   wifiOffOnMobile = false;     // WLAN nach erfolgreicher Mobilfunkverbindung aus (greift mit PPP)

// Geplanter Neustart (0 = keiner). Wird genutzt, um nach dem Werksreset
// erst die HTTP-Antwort auszuliefern und dann kontrolliert neu zu starten.
unsigned long pendingRestartAt = 0;
// "Neustart erforderlich": Einstellungen, die erst beim Boot wirken (Video-Transport/Ports, UART-Baud, LAN-Subnetz,
// Forwarding, AP-Kanal, WLAN-Stack ...). Die UI zeigt dann auf JEDER Seite eine gelbe Box mit Neustart-Knopf,
// statt den Hinweis in einem Formular zu verstecken; die Konsole meldet es bei "status".
String g_restartReasons;
void markRestartRequired(const String& why) {
    if (g_restartReasons.indexOf(why) >= 0) return;
    if (g_restartReasons.length()) g_restartReasons += ", ";
    g_restartReasons += why;
    logEvent("Neustart erforderlich: " + why);
}
bool g_certApplyRestart = false;   // Zertifikatsherkunft gewechselt -> Neustart, sobald kein Zuschauer

// 7.9.14: mbedTLS-Speicher-Policy (Plattform-Schalter, UI + NVS "cfg"). true = alle mbedTLS-
// Allocations in den PSRAM (Default auf S3 mit knappem internen RAM); false = intern (z.B. P4).
// Wirkt erst nach Neustart, weil der globale mbedTLS-Allocator einmalig sehr frueh im Boot
// gesetzt werden muss (vor jedem TLS/DRBG). Siehe esp32ApplyCryptoMemoryPolicy().
bool g_cryptoMemPsram = true;


// -----------------------------------------------------------------------------
// Statische Seitenbestandteile
// -----------------------------------------------------------------------------







// -----------------------------------------------------------------------------
// Setup / Loop
// -----------------------------------------------------------------------------

// ---- Observer: der EC200A-Treiber meldet Ereignisse hierher (App-Schicht) ----
// Der Treiber (ec200a_modem.cpp) kennt Webserver/UI/DynDNS NICHT; er ruft nur
// diese registrierten Funktionszeiger. Hier haengt die App ihre Reaktionen an.
// --- Ereignis-Log (Ringpuffer, fuer System -> Ereignisse) ---
struct EventEntry { unsigned long ms; String text; };
static const int EVENT_LOG_N = 30;
static EventEntry g_events[EVENT_LOG_N];
static int g_eventHead = 0, g_eventCount = 0;
void logEvent(const String& text) {
    g_events[g_eventHead].ms   = millis();
    g_events[g_eventHead].text = text;
    g_eventHead = (g_eventHead + 1) % EVENT_LOG_N;
    if (g_eventCount < EVENT_LOG_N) g_eventCount++;
    Serial.print("[event] "); Serial.println(text);
}

void dyndnsForceNow();   // erzwingt ein sofortiges DynDNS-Update (Def. weiter unten)

#if WEIRDOS_FEATURE_MODEM   // PPP-/Praesenz-Observer
void onModemPppState(PppState s, const char* ip) {
    Serial.print("[modem] PPP-Status ");
    Serial.print((int)s);
    if (s == PPP_UP) { Serial.print(" IP="); Serial.print(ip); }
    Serial.println();
    static const char* pppNames[] = { "getrennt", "waehlt", "verhandelt", "verbunden", "fehlgeschlagen" };
    String e = "PPP: "; e += ((int)s >= 0 && (int)s < 5) ? pppNames[(int)s] : "?";
    if (s == PPP_UP && ip) { e += " ("; e += ip; e += ")"; }
    logEvent(e);
    // Bei PPP_UP DynDNS SOFORT anstossen: die frische Session ist der zuverlaessige
    // Fall, und die neue IP muss unmittelbar an den Anbieter (angelworks.eu).
    if (s == PPP_UP) dyndnsForceNow();
}
void onModemPresence(bool present, uint16_t vid, uint16_t pid) {
    Serial.print("[modem] Praesenz: ");
    Serial.println(present ? "erkannt" : "weg");
    logEvent(present ? "Modem am USB erkannt" : "Modem am USB entfernt");
}
#endif // WEIRDOS_FEATURE_MODEM (PPP-/Praesenz-Observer)

// 7.9.12: DynDNS-Selbstheilung. IONOS ist https-only; unter fragmentiertem Heap scheitert
// mbedtls_ssl_setup mit ALLOC_FAILED (55k frei, aber groesster Block < ~32k). Ein Reset
// defragmentiert den Heap -> frischer Boot hat einen grossen Block -> Update zieht sofort
// (vom User bestaetigt). Zaehler der aufeinanderfolgenden Heilungs-Reboots ueberlebt den
// SW-Reboot (RTC_NOINIT) und deckelt so einen Boot-Loop. Erfolgreiches Update setzt ihn auf 0.
// (Vor setup() definiert: setup()/dyndnsTask nutzen ihn; .ino hoisted nur Funktionen, keine Globals.)
RTC_NOINIT_ATTR volatile uint32_t g_dyndnsHealReboots;

// re-vendor-bugfix: Serieller PANIC = "Stack canary watchpoint triggered (loopTask)" (Core 1) ->
// STACK-OVERFLOW im loopTask, nicht Watchdog. Backtrace tief in mbedTLS/Bignum -> der loopTask
// fuehrt mbedTLS-Schwergewichte aus (IPsec-connect DH-Keygen, DynDNS/WG-TLS). Der re-vendorte
// WeirdIKE-Stack drueckte den Default-8-KB-Loop-Stack ueber die Kante. Loop-Stack auf 16 KB anheben
// (Standard-arduino-esp32-Override; gleiche Klasse Fix wie broken-phase1 "groesserer Stack").
// HW-Gate 2026-09-04 (P4, aed8b2e): erneut "Stack protection fault" im loopTask beim Verarbeiten der
// IKE_AUTH-Antwort (RTC-Marker: Schritt 19 weirdike_input_datagram, Zustand AUTH_SENT, Rest 8,7 KB vor
// dem Aufruf). Der Kern haelt mehrere 1500-B-Nachrichtenpuffer verschachtelt auf dem Stack (SK-Klartext,
// innere Payloads, AUTH-Verifikation) + mbedTLS-PRF/AES. 16 -> 24 KB (intern; beim Task-Start ist der
// interne Heap noch leer). Strukturell folgt: Nachrichtenpuffer in den WeirdIKE-Kontext (PSRAM).
// HW-Gate 2026-09-07 BESTANDEN mit dem WeirdIKE-Workspace-Refactor (WeirdIKE 61dbd6a, WeirdOS ede98b1):
// kompletter Zyklus Connect/ESP/DPD/Child-Rekey/DELETE/Reconnect ohne Reset, loopStackMin 19112 B
// bei 24 KB = realer Verbrauch ~5,4 KB. Daher zurueck auf 16 KB (NICHT tiefer: EAP/X.509 auf dem P4
// noch nicht hardwarevalidiert, mbedTLS-interne Frames vom Stack-CI nicht erfasst).
SET_LOOP_TASK_STACK_SIZE(16 * 1024);

// ---- H.264-Internal-RAM-Guard -------------------------------------------------------------
// Der P4-HW-Encoder fordert seinen Reference-Frame-Puffer ZWINGEND aus MALLOC_CAP_INTERNAL an
// (DMA/HW-Anforderung), zusammenhaengend, groesse ~1152*ceil(w/16): 800w~56KB, 720p~90KB, FHD~135KB.
// HTTP/USB/PPP fragmentieren den internen Heap beim Boot -> danach existiert kein so grosser Block.
// Strategie (GPT): FRUEH (nach der Kamera, vor HTTP/USB/PPP) einen zusammenhaengenden Block halten;
// beim H.264-Start freigeben und sofort den Encoder anlegen. Boot-Test: kommt der Router MIT
// gehaltenem Guard komplett hoch, ist das interne Gesamtbudget vorhanden (dann nur Fragmentierung).
// Groesse per NVS "h264guardkb" (Default 0 = aus -> kein Brick-Risiko auf dem LTE-only-Geraet).
// Implementierung + Stream-Verdrahtung (Release beim Start, Restore am Ende): h264_guard.h/.cpp.

// Interner ref-Puffer des GERADE laufenden H.264-Streams (0 = keiner). Der Video-Server setzt ihn;
// der /dev/camera0-Descriptor rechnet ihn zur Verfuegbarkeit zurueck, damit waehrend eines Streams
// nicht alle Aufloesungen ausgegraut erscheinen (der Encoder haelt seinen Block ja gerade).
volatile size_t g_h264ActiveRef = 0;
// Umschalt-Signal: ein neuer H.264-Request setzt das, der laufende Task beendet sich daraufhin
// zuegig -> sauberes Aufloesungs-Umschalten ohne "Verbindung fehlgeschlagen"-Race.
volatile bool g_h264Stop = false;
// H.264-Bitrate (NVS "camera": h264kbit), globale Frame-Politik (dropstale) + Live-Statistik (siehe web_ui.h).
int  h264Kbit       = 6000;
bool streamDropStale = true;   // globale Frame-Politik (Verteiler), siehe web_ui.h
volatile uint32_t g_h264StatFps = 0, g_h264StatKbit = 0, g_h264StatSkips = 0;

// Boot-Zeitleiste fuer die Heap-Map (Diagnose): jede logHeapMark()-Stelle merkt sich Tag +
// internen Free/Largest-Wert, damit /heapmap zeigt, in WELCHER Boot-Phase der zusammenhaengende
// interne Speicher schrumpft (z.B. der WLAN-/Netz-Aufbau) -- ohne echtes Heap-Tracing. MUSS vor
// handleHeapMap() stehen: Arduino generiert Funktions-Prototypen automatisch, aber KEINE fuer
// globale Variablen -- die muessen textuell vor ihrer ersten Nutzung im File liegen.
struct HeapMilestone { const char* tag; uint32_t freeKb; uint32_t largestKb; };
static const int HEAP_MILESTONE_MAX = 8;
static HeapMilestone g_heapMilestones[HEAP_MILESTONE_MAX];
static int g_heapMilestoneCount = 0;

// Bringt NUR den lwIP/tcpip-Unterbau hoch (esp_netif + Default-Event-Loop), OHNE esp_wifi/
// esp_hosted anzufassen. PPP (pppapi_*) und der Management-/Video-Webserver brauchen dafuer
// nur die lwIP-tcpip-Mailbox -- keine echte WLAN-Funktion. Ersetzt WiFi.mode(WIFI_STA) fuer den
// Fall "kein WLAN gewuenscht/vorhanden" (siehe Aufrufstelle in setup() fuer die volle Begruendung
// und das Sicherheitsnetz). Beide Calls sind idempotent (ESP_ERR_INVALID_STATE bei Doppel-Init
// ist unschaedlich, kein Abbruch noetig).
static void startBareNetStack() {
    esp_err_t e1 = esp_netif_init();
    esp_err_t e2 = esp_event_loop_create_default();
    Serial.printf("[Netz] Bare-tcpip-Init (ohne WiFi/esp_hosted): netif=%s, eventloop=%s\n",
                  esp_err_to_name(e1), esp_err_to_name(e2));
}

#if WEIRDOS_FEATURE_USB_HOST   // USB-Host-Recovery
// ---- USB-Host-Recovery -----------------------------------------------------------------------
// Nach einem Modem-Neustart (AT+CFUN=1,1: manuell, Datenschicht-Wechsel, ECM-Auto-Provisioning)
// muss das Modem binnen ~90 s wieder enumerieren. Bleibt es aus, ist mit hoher Wahrscheinlichkeit
// der USB-Host-Zustand des ESP verhakt ("kein NEW_DEV [enum-Adressen 2]", bekannt) -- das Modem
// selbst laeuft weiter. Ein ESP-Neustart setzt den USB-Host frisch auf; bisher half nur ein
// Powercycle, der ueber LTE nicht moeglich ist. GENAU EIN Versuch je Boot-Kette (RTC-Zaehler, der
// ESP.restart() ueberlebt), damit ein wirklich abgestecktes Modem keine Reboot-Schleife ausloest.
RTC_NOINIT_ATTR uint32_t g_usbRecoveryCount;
// ---- USB-Link-Recovery (flatternder Modem-Link) --------------------------------------------------
// Befund (scratch_33, 2026-09-09): nach einem spontanen Abriss (Busfehler, DEV_GONE, Re-Enumeration nach
// ~0,5 s) heilt sich der Link im laufenden Betrieb NICHT -- weitere Abrisse, IF4 ohne AT-Antwort, CFUN,
// "nicht im Netz registriert", claim INVALID_STATE. Ein ESP-Reset bei laufendem Modem heilt sofort. Der
// Unterschied ist allein der frisch aufgesetzte USB-Host. Deshalb in Stufen, jede geloggt:
//   Stufe 1: >= 3 spontane Abrisse in 3 min  -> Root-Port deaktivieren/aktivieren (Modem re-enumeriert, bootet
//            nicht). Gilt nur als WIRKSAM, wenn beide Aufrufe ESP_OK liefern UND binnen 20 s eine neue Modem-
//            Generation erscheint; sonst geht es direkt zu Stufe 2.
//   Stufe 2: Stufe 1 ohne Wirkung ODER danach erneut >= 3 spontane Abrisse -> ESP-Neustart (USB-Host komplett
//            frisch), max. 2 je Boot-Kette (RTC-Zaehler, nur ueber Software-Resets getragen).
// Das vom Zyklus selbst erzeugte DEV_GONE ist im Treiber als ERWARTET markiert und zaehlt nicht.
// Zuruecksetzen: 10 min ohne spontanen Abriss (auch gerechnet ab Boot, damit der RTC-Reboot-Zaehler nach
// einem Stufe-2-Neustart nicht ewig stehen bleibt) -> Stufe 0, Reboot-Zaehler 0.
RTC_NOINIT_ATTR uint32_t g_usbFlapReboots;
static uint8_t  g_usbFlapStage = 0;        // 0 ruhig | 1 Zyklus laeuft/bewertet | 2 Zyklus wirksam, beobachten | 3 aufgegeben
static uint32_t g_usbFlapStageMs = 0;
static uint32_t g_usbFlapStageGen = 0;
static void usbLinkRecoveryTick() {
    if (!usbHostStarted) return;
    uint32_t last = 0;
    int n = modemUsbUnexpectedGone(180000, &last);
    uint32_t now = millis();
    // 10 min Ruhe (seit letztem spontanen Abriss bzw. seit Boot) -> alles zurueck, auch der RTC-Zaehler
    bool quiet = (last ? (now - last) : now) > 600000;
    if (quiet && (g_usbFlapStage || g_usbFlapReboots)) {
        g_usbFlapStage = 0; g_usbFlapReboots = 0; modemUsbClearGoneHistory();
        logEvent("USB-Link-Recovery: Link seit 10 min stabil -- Stufen und Neustart-Zaehler zurueckgesetzt");
        return;
    }
    if (g_usbFlapStage == 3) return;
    if (g_usbFlapStage == 1) {
        // Wirkung des Zyklus bewerten: neue Modem-Generation binnen 20 s?
        if (modemEnumGeneration() != g_usbFlapStageGen) {
            g_usbFlapStage = 2; g_usbFlapStageMs = now;
            logEvent("USB-Link-Recovery Stufe 1 wirksam: Modem neu enumeriert (Generation " + String(modemEnumGeneration()) + ") -- beobachte");
            return;
        }
        if (now - g_usbFlapStageMs < 20000) return;
        logEvent("USB-Link-Recovery Stufe 1 ohne Wirkung: keine neue Modem-Generation binnen 20 s -> Stufe 2");
        // faellt durch zu Stufe 2
    } else if (g_usbFlapStage == 2) {
        if (n < 3) return;   // nach wirksamem Zyklus erst bei erneutem Flattern eskalieren
    } else {
        if (n < 3) return;
        bool ok = false;
        String r = modemUsbRootPortCycle(&ok);
        g_usbFlapStage = 1; g_usbFlapStageMs = now; g_usbFlapStageGen = modemEnumGeneration();
        modemUsbClearGoneHistory();
        logEvent("USB-Link-Recovery Stufe 1: " + String(n) + " spontane USB-Abrisse in 3 min -> Root-Port deaktivieren/aktivieren (" + r + ")");
        Serial.println("[USB] Link-Recovery Stufe 1: " + r);
        if (ok) return;
        logEvent("USB-Link-Recovery Stufe 1 fehlgeschlagen (API-Fehler) -> Stufe 2");
        // faellt durch zu Stufe 2
    }
    if (g_usbFlapReboots >= 2) {
        g_usbFlapStage = 3;
        logEvent("USB-Link-Recovery: Link flattert auch nach 2 ESP-Neustarts -- kein weiterer Versuch (Versorgung/Stecker/Modem pruefen)");
        return;
    }
    g_usbFlapReboots++;
    logEvent("USB-Link-Recovery Stufe 2: -> ESP-Neustart (USB-Host frisch), Versuch " + String(g_usbFlapReboots) + "/2");
    Serial.println("[USB] Link-Recovery Stufe 2: ESP-Neustart, weil der Modem-Link nicht stabil wird.");
    Serial.flush(); delay(300);
    ESP.restart();
}
static void usbHostRecoveryTick() {
    usbLinkRecoveryTick();
    if (!usbHostStarted || modemLastResetMs == 0) return;
    if (modemDeviceHandle()) { modemLastResetMs = 0; g_usbRecoveryCount = 0; return; }   // wieder da
    if ((long)(millis() - modemLastResetMs) < 90000) return;
    modemLastResetMs = 0;
    if (g_usbRecoveryCount >= 1) {
        logEvent("USB-Host-Recovery: Modem auch nach ESP-Neustart nicht enumeriert - kein weiterer Versuch (Modem abgesteckt/defekt?)");
        return;
    }
    g_usbRecoveryCount++;
    logEvent("USB-Host-Recovery: Modem 90 s nach Neustart nicht wieder enumeriert -> ESP-Neustart (USB-Host frisch)");
    Serial.println("[USB] Recovery: ESP-Neustart, weil das Modem nach CFUN=1,1 nicht wieder enumeriert (verhakter USB-Host).");
    Serial.flush(); delay(300);
    ESP.restart();
}
#endif // WEIRDOS_FEATURE_USB_HOST (USB-Host-Recovery)

void setup() {
    Serial.begin(serialConsoleBaud());   // NVS "cfg"/"uartbaud" (Default 115200) -- Einrichtung > Setup > UART
    delay(1000);
#if WEIRDOS_FEATURE_USB_HOST
    if (esp_reset_reason() != ESP_RST_SW) { g_usbRecoveryCount = 0; g_usbFlapReboots = 0; }   // RTC-Zaehler nur ueber Software-Resets tragen
#endif // WEIRDOS_FEATURE_USB_HOST

    // 7.9.10/7.9.11: Unter WireGuard-LAN-Gateway-Dauerlast laeuft die ChaCha20-Krypto +
    // Forwarding + NAPT im tcpip-Task volle Pulle; der Idle-Task kommt kurz nicht dran ->
    // Task-Watchdog-Panic (resetreason:TASK_WDT) mitten im Transfer. NICHT die Idle-WDT
    // abschalten (das entfernt auch die Starvation-Erkennung/Selbstheilung, GPT-Hinweis) -
    // stattdessen nur das Timeout grosszuegiger (5 s -> 30 s), Idle beider Cores weiter
    // ueberwacht. Der strukturelle Fix (Ingress-Backpressure / Krypto aus dem tcpip-Task)
    // ist ein eigener Slice; hier nur die kurze Lastspitze tolerieren.
    {
        esp_task_wdt_config_t wdt = { .timeout_ms = 30000, .idle_core_mask = (1u << 0) | (1u << 1), .trigger_panic = true };
        esp_err_t we = esp_task_wdt_reconfigure(&wdt);
        Serial.printf("[WDT] reconfigure(idle_on,30s) -> %s\n", esp_err_to_name(we));
    }
    // 7.9.12: DynDNS-Heal-Zaehler nur ueber den eigenen SW-Reboot erhalten; sonst (Poweron,
    // Panic/WDT, Brownout) frisch bei 0 starten - RTC_NOINIT ist sonst uninitialisiert.
    if (esp_reset_reason() != ESP_RST_SW) g_dyndnsHealReboots = 0;

    // 7.9.14: mbedTLS-Speicher-Policy SO FRUEH WIE MOEGLICH anwenden - vor jedem TLS/DRBG
    // (DynDNS-Task, WireGuard-RNG, HTTPS). Der globale Allocator-Hook darf im Betrieb NICHT
    // mehr umgeschaltet werden (Race), daher einmalig hier. Default: PSRAM wenn vorhanden.
    {
        preferences.begin("cfg", true);
        g_cryptoMemPsram = preferences.getBool("cryptopsram", psramFound());
        preferences.end();
        esp32ApplyCryptoMemoryPolicy(g_cryptoMemPsram);
    }

    // Durchsatz-Diagnose: die tatsaechlich einkompilierten lwIP-TCP-Fenster.
    // Klein (~5744) => ein einzelner TCP-Stream (Kamera-MJPEG) ist ueber die
    // LTE-RTT auf ~0,5 Mbit gedeckelt. Fix nur ueber IDF-Build (s. TCP-WINDOW-FIX.md).
    Serial.printf("[lwIP] TCP_MSS=%d TCP_SND_BUF=%d TCP_WND=%d\n",
                  (int)TCP_MSS, (int)TCP_SND_BUF, (int)TCP_WND);
    logEvent("System gestartet");

    initializeStatusLed();
#if WEIRDOS_FEATURE_CAMERA
    initializeCamera();
#else
    Serial.println("Kamera: nicht im Build enthalten (WEIRDOS_FEATURE_CAMERA=0) -- Geraet laeuft ohne Bildpfad.");
#endif
    logHeapMark("nach Kamera");
    // H.264-Guard FRUEH sichern (nach Kamera, VOR HTTP/USB/PPP) -> haelt einen zusammenhaengenden
    // internen Block, bevor ihn die spaeteren Subsysteme zerstueckeln. Default "Automatisch":
    // Groesse = Referenzpuffer des GROESSTEN vom Kamera-Backend gemeldeten Modus (+ Reserve) --
    // keine Handzahl, folgt der Kamera-Lib (P4 mit FHD-Lib ~162 KB: Referenz-Zeilenpuffer + Deblocking-
    // Zwischenpuffer + Deskriptoren -- ALLE internen Encoder-Puffer, sonst LP-SRAM-Falle). Wird als EXKLUSIVE Heap-Region
    // (nur der esp_h264-Allocator-Hook kommt hinein) registriert, nie freigegeben (h264_guard.h). Nur wenn der Video-Server
    // (HTTP-Stream, streamEnabled aus loadCameraConfig) aktiv ist -- sonst gibt es keinen H.264-
    // Endpunkt; wie beim WLAN-Stack wirkt die Aenderung ab Neustart.
    {
        uint16_t maxW = 0;
        if (cameraReady) {
            CameraVideoMode modes[16];
            int n = cameraManager.enumModes(modes, 16);
            for (int i = 0; i < n; i++) if (modes[i].width > maxW) maxW = modes[i].width;
        }
        h264GuardBootReserve(h264GuardAutoBytesForWidth(maxW), streamType != "off");   // HTTP ODER RTSP brauchen H.264
    }
    loadWifiCredentials();
    loadApPreference();
    loadSecurityPrefs();
    wifiStackModeLoad();   // Auto/An/Aus fuer den WLAN-Stack (NVS "wifi"/"stackmode") -- VOR dem Netzaufbau
    loadModemPrefs();
    loadDyndnsPrefs();
    acmeLoad();           // ACME-Config + gespeichertes Let's-Encrypt-Zertifikat (vor dem Webserver-Start)
    certStoreLoad();      // HTTPS-Zertifikatsquelle + Upload/Selfsigned aus NVS (vor dem Webserver-Start)
    loadDiagPrefs();
    loadGeneralPrefs();
    platformLoad();       // Board-Profil (Einrichtung > Plattform) -- zentrale Board-Wahrheit, VOR dem USB-Mapping
    usbPortsLoad();       // USB-Port-Mapping des Boards (Nutzer-Konfig) -- VOR Registry und USB-Device-Wunsch
    periphLoadConfig();   // Peripherie-Registry: gewuenschte Geraetezuordnung (USB-Port des Modems)
    wanLoadConfig();      // System-WAN-Policy (geordnete Uplink-Wahl); Default = heutiges "auto"
    setupGuardLoadConfig();               // Einrichtung: Captive-Modus + Werksreset-Config laden
    // USB-Device-Wunsch FRUEH laden (vor der USB-Host-Entscheidung): auf dem P4 entscheidet die Port-Wahl
    // ("hs" = Modem-Port), auf dem S3 der eine gemeinsame USB-C-Port, ob der Modem-Host starten darf.
    usbDeviceService.loadConfig();
    Serial.printf("USB-Device gewuenscht: %s (Port %s)\n", usbDeviceService.enabled() ? (String("UVC <- ") + usbDeviceService.config().cam).c_str() : "aus", usbDeviceService.config().port.c_str());
    pinMode(FACTORY_RESET_PIN, INPUT_PULLUP);  // BOOT-Taste als Werksreset-Eingang (GPIO0)
    esp32BoundHttpTransportBegin();   // gebundenen HTTPS-Worker frueh starten (Stack aus frischem Heap)
#if WEIRDOS_FEATURE_WIREGUARD
    wireguardService.begin();         // Stufe 7.3: WireGuard-Backend einbinden (kein Tunnel)
    wireguardService.loadConfig();    // Stufe 7.4c: Tunnel-Config aus NVS (kein Autostart)
#endif
#if WEIRDOS_FEATURE_IPSEC
    ipsecService.begin();             // 8.1: IPsec-Backend (Config/Status; Runtime folgt)
#endif
#if WEIRDOS_FEATURE_ROUTER
    zoneRuntimeBegin();               // Netzzonen 0.5: Tabellen im PSRAM, persistente Intents laden (Installation folgt im loop-Poll)
#endif
    logHeapMark("nach Zonen-Runtime");   // muss praktisch identisch zur vorigen Marke sein (alles im PSRAM)
    accessSetLanDetector(accessIsLanIp);   // Zugangsregel: LAN-Erkennung (AP/STA-Subnetz)
#if WEIRDOS_FEATURE_IPSEC
    ipsecService.loadConfig();        // 8.1: IPsec-Config aus NVS (kein Autostart)
#endif
    networkMode.begin();              // Betriebsart aus NVS laden (Phase 1: NUR laden, kein apply)
    wanService.begin();               // WAN-Internet-Check als Hintergrund-Task starten
    loadEnergyPrefs();
    applyCpuProfile();       // gespeichertes CPU-Profil beim Boot setzen (kein Reboot noetig)
    startLogCapture();       // ESP-IDF-Log in RAM-Puffer (/modem-log) umleiten
#if WEIRDOS_FEATURE_MODEM
    modemAddPppListener(onModemPppState);        // Observer registrieren (vor dem Host-Start)
    modemAddPresenceListener(onModemPresence);
#endif // WEIRDOS_FEATURE_MODEM
    // USB-Host nur uebernehmen, wenn Modem aktiv UND kein PC am USB haengt.
    // Sonst bleibt der Serial-JTAG-Programmierport erhalten -> Flashen ohne BOOT-Hack.
#if WEIRDOS_FEATURE_MODEM
    if (!modemUsbEnabled) {
        usbHostSkipReason = "Modem in Einstellungen deaktiviert";
        Serial.println("USB-Host uebersprungen: Modem deaktiviert.");
    // Universelle Regel (Board-Mapping): ist der Port des Modems (cellular0) zugleich der Port des PC-Geraets
    // (UVC-Export), gehoert er dem PC -- der Modem-Host bleibt mit Grund aus. Verschiedene Ports = verschiedene
    // Controller = kein gegenseitiges Gate (P4: Modem HS am MX1.25, PC FS auf der Stiftleiste).
    } else if (usbDeviceService.conflictsWithModemPort()) {
        usbHostSkipReason = "USB-Port " + periphModemPort + " ist als PC-Geraet (Webcam) konfiguriert -- Modem-Host aus";
        Serial.println("USB-Host uebersprungen: Modem-Port ist dem USB-Device zum PC zugewiesen.");
#if !CONFIG_IDF_TARGET_ESP32P4
    // S3-Erbe (ein USB-C fuer Programmierport, Modem-Host und PC-Geraet): PC am USB -> kein Host.
    } else if (usbPcConnected()) {
        usbHostSkipReason = usbDeviceService.enabled() ? "PC am USB erkannt -> USB-Geraet (Webcam) statt Modem-Host"
                                                       : "USB-PC erkannt (Programmiermodus) - Reset ohne PC startet das Modem";
        Serial.println("USB-Host uebersprungen: PC am USB erkannt.");
#endif
    } else {
        startUsbHost();          // USB-Host-Erkennung (Modem am Hub) starten
        usbHostStarted = modemUsbHostReady;   // nur bei Erfolg (sonst kann /periph-rescan erneut versuchen)
        if (!usbHostStarted && usbHostSkipReason.length() == 0) usbHostSkipReason = modemUsbError;
    }
#else
    // Kein Modem im Build (WEIRDOS_FEATURE_MODEM=0): der USB-Host hat heute keinen anderen Nutzer.
    // Der Stub startet nichts und nennt den Grund (auch bei USB_HOST=0) -> /modem-status.json "usbhostreason".
    startUsbHost();
    usbHostStarted = modemUsbHostReady;   // bleibt false
    usbHostSkipReason = modemUsbError;
#endif // WEIRDOS_FEATURE_MODEM
    logHeapMark("nach USB-Host");

#if WEIRDOS_FEATURE_WIFI
    WiFi.persistent(false);
#endif

    // Zielnetz ist Opt-in. Ist es aktiv UND sind Zugangsdaten vorhanden, wird
    // verbunden; der AP kommt nur bei "AP dauerhaft an" oder bei fehlgeschlagener
    // Verbindung dazu. Soll der WLAN-/esp_hosted-Stack GAR NICHT laufen (Auto ohne
    // erkannte Funk-Hardware, oder Nutzer-Wahl "Aus" unter LAN > WLAN), entfaellt
    // der ganze WiFi-Aufbau -- siehe wifi_caps.h/wifiStackShouldInit().
    // Baustein WIFI (WEIRDOS_FEATURE_WIFI=0, auf dem P4 immer): der Stub von wifi_caps liefert
    // IMMER false -> dieselbe Bare-Net-Abzweigung wie bisher der P4, ohne dass WiFi.h im Bild ist.
    bool wifiOn = wifiStackShouldInit();
    wifiStackMarkActive(wifiOn);   // Laufzeit-Wahrheit fuer alle spaeteren WLAN-Aktionen (AP-Automatik, Scan, Connect)
#if WEIRDOS_FEATURE_WIFI
    bool useTargetNetwork = wifiOn && targetNetworkEnabled && hasWifiCredentials();
#endif

    if (!wifiOn) {
        // Kein WLAN gewuenscht/vorhanden -> NUR den lwIP/tcpip-Unterbau hochziehen (PPP und der
        // Webserver brauchen die tcpip-Mailbox, KEINE echte WLAN-Funktion). Frueher lief hierfuer
        // WiFi.mode(WIFI_STA) -- das zieht auf dem P4 zusaetzlich den ESP-Hosted-Transport hoch
        // (kein Companion-Chip bestueckt) -> Dauerspam "esp_hosted_reconfigure=ESP_FAIL" UND laut
        // Heap-Map (Diagnose) bis zu ~150 KB zusammenhaengender interner Speicher weg, den z.B.
        // der H.264-Encoder fuer hohe Aufloesungen braucht. esp_netif_init() +
        // esp_event_loop_create_default() sind die dokumentierten IDF-Bausteine, die GENAU die
        // tcpip-Mailbox bringen, OHNE esp_wifi/esp_hosted anzufassen.
        // Sicherheitsnetz: sollte das auf echter Hardware Probleme machen (aehnlich dem
        // historischen "tcpip_send_msg_wait_sem: Invalid mbox"-Bootloop), erzwingt LAN > WLAN
        // auf "An" sofort wieder den alten, bewiesenen WiFi.mode()-Pfad -- ohne Neu-Flash.
        startBareNetStack();
        Serial.println("[Netz] WLAN-Stack aus (kein Funk erkannt/gewuenscht) -> nur Netz-Unterbau; "
                       "Zugang ueber LTE (DynDNS) + serielle Konsole.");
#if WEIRDOS_FEATURE_WIFI
    } else if (!useTargetNetwork || keepApAlways) {
        // Setup-AP in der bewiesenen Reihenfolge (4.3.2.1 -> DHCP-DNS-Offer -> DNS-Hijack).
        startAccessPoint();
        configureSoftApDhcp();
        startDnsServer();
        setupApActive = true;
    } else {
        WiFi.mode(WIFI_STA);
        WiFi.setSleep(false);
#endif
    }
    logHeapMark("nach WLAN/Netz-Aufbau");   // Split ggue. "nach Webserver": zeigt den WLAN-Anteil isoliert

    // Webserver erst NACH dem Netzaufbau starten (bindet an lwIP -> laeuft auch ueber PPP/LTE).
    startWebServer();
    logHeapMark("nach Webserver");
    // USB-Device zum PC (UVC): eigener Controller OTG1.1/FS auf GPIO24/25 -- unabhaengig vom Modem-Host
    // (OTG2.0/HS am MX1.25) und von der Konsole (CH343/UART0). Startet nur, wenn konfiguriert.
    usbDeviceService.begin();
    logHeapMark("nach USB-Device");

    if (cameraReady) {
        startVideoTransport();   // HTTP-Stream-Server (Port 81) ODER RTSP (Port 554), je nach Server > Video
        // beginTls() (Phase-1-TLS-PoC HTTPS-MJPEG auf 443) NICHT mehr automatisch: das aktuelle
        // UI nutzt nur den HTTP-Stream (streamPort), der PoC kostet aber 20 KB internen httpd-Stack,
        // belegt TCP 443 UND einen Control-Port. Reaktivieren, wenn Video-HTTPS wirklich konfiguriert wird.
    }

#if WEIRDOS_FEATURE_WIFI
    if (wifiOn) {
        if (useTargetNetwork) beginWifiConnection();
        else                  requestWifiScan();
    }
#endif

    printNetworkStatus();

    startDyndns();           // DynDNS-Update-Loop (meldet die Mobilfunk-WAN-IP)
    if (usbHostStarted)                          // nur sinnvoll, wenn der USB-Host laeuft
        startModemDataSupervisor();              // ausgewaehlter Datenpfad (ppp|ecm) -- EINE Weiche
    logHeapMark("boot");     // Telemetrie-Baseline: interner Heap nach dem Boot (fuer Leak-Vergleich)
}


// Video-Transport (Server > Video): genau EIN Stream-Server -- HTTP (Port 81: MJPEG + /video.mp4) ODER
// RTSP (Port 554: /mjpeg + /h264) ODER keiner. Socket-Budget bleibt gleich (ein Listener + ein Socket je Client).
void startVideoTransport() {
#if WEIRDOS_FEATURE_RTSP
    if (streamType == "rtsp") { rtspServer.begin((uint16_t)rtspPort, rtspTransport == "udp"); return; }
#else
    // RTSP nicht im Build, aber per NVS gewaehlt: nicht stumm ohne Bild bleiben, sondern auf den
    // HTTP-Stream zurueckfallen (sofern der im Build ist) -- der Nutzer sieht den Grund im Log.
    if (streamType == "rtsp") {
        Serial.println("Video-Server: RTSP gewaehlt, aber nicht im Build enthalten (WEIRDOS_FEATURE_RTSP=0) -> HTTP-Stream als Rueckfall.");
#if WEIRDOS_FEATURE_VIDEO_HTTP
        cameraServer.begin();
#endif
        return;
    }
#endif
#if WEIRDOS_FEATURE_VIDEO_HTTP
    if (streamType == "http") { cameraServer.begin(); return; }
#else
    if (streamType == "http") { Serial.println("Video-Server: HTTP gewaehlt, aber nicht im Build enthalten (WEIRDOS_FEATURE_VIDEO_HTTP=0)."); return; }
#endif
    Serial.println("Video-Server aus (Stream-Transport: aus).");
}

void loop() {
    serialConsoleTick();   // serielle Bedien-Konsole (Alternative zur Web-UI, v.a. P4)
    modemRateTick();       // 1s-Durchsatz-Sampler (Online-Monitor Max) -- laeuft im Hintergrund
#if WEIRDOS_FEATURE_USB_HOST
    usbHostRecoveryTick(); // Modem nach CFUN=1,1 nicht wieder enumeriert -> ESP-Neustart statt Powercycle
#endif // WEIRDOS_FEATURE_USB_HOST
    acmeTick(modemLinkUp); // Let's Encrypt: Erstbezug/Erneuerung (taeglich geprueft, nur mit Link + Uhr)
    certTick(modemLinkUp); // self-signed-Auto-Erneuerung (ACME erneuert acmeTick selbst)
    // Neues Zertifikat gespeichert -> der HTTPS-Server uebernimmt es erst beim Start: Neustart, sobald
    // kein Video-Zuschauer mehr dran ist (ein Zertifikatswechsel kommt alle ~60 Tage).
    if (acmeRestartPending() && pendingRestartAt == 0 && cameraStream.clientCount() == 0) {
        logEvent("ACME: Neustart, um das neue Zertifikat zu aktivieren");
        pendingRestartAt = millis() + 3000;
    }
    if (g_certApplyRestart && pendingRestartAt == 0 && cameraStream.clientCount() == 0) {
        logEvent("Zertifikat: Neustart, um die neue Herkunft zu aktivieren");
        g_certApplyRestart = false;
        pendingRestartAt = millis() + 3000;
    }

    if (pendingRestartAt != 0
        && (long)(millis() - pendingRestartAt) >= 0) {
        Serial.println("Restarting after factory reset.");
        Serial.flush();
        ESP.restart();
    }

#if WEIRDOS_FEATURE_WIFI
    if (setupApActive) {
        processDnsRequests();
    }
#endif

    g_web.loop();   // esp_http_server hat eigene Tasks -> no-op (nur Vertrag erfuellt)

#if WEIRDOS_FEATURE_WIFI
    updateWifiConnection();
    updateWifiScan();
#endif
    updateStatusLed();
    setupGuardTick();               // Captive-Portal-Sicherung (WAN-bewusst) + Werksreset (BOOT/GPIO0)

#if WEIRDOS_FEATURE_WIREGUARD
    wireguardService.supervise();   // 7.9.1: VPN-Autostart + Selbstheilung (kein Start/Stop-Button)
#endif
#if WEIRDOS_FEATURE_IPSEC
    ipsecService.supervise();       // 8.1: IPsec-Autostart (No-op bis Runtime steht)
#endif
#if WEIRDOS_FEATURE_ROUTER
    zoneRuntimePoll();              // Netzzonen 0.5: Policies bei Registry-Aenderung neu kompilieren + installieren
#endif
#if WEIRDOS_FEATURE_RTSP
    rtspServer.poll();              // RTSP: ersten Client annehmen + Worker lazy starten (nur im RTSP-Modus aktiv)
#endif

    // WICHTIG (Scheduling-Regression durch den WeirdHttpEsp-Flip): frueher blockierte
    // WeirdHttpArduino::loop() -> server.handleClient() den loopTask kurz. WeirdHttpEsp::loop()
    // ist No-op, und die restliche loop() hat keinen blockierenden Punkt -> der loopTask dreht
    // auf CPU 1 frei durch und hungert IDLE1 aus -> Task-WDT (IDLE1) nach ~30 s (reproduzierbar
    // ~30 s nach PPP-Up, wenn die Verbindungsarbeit ruhig wird). vTaskDelay(1) macht den loopTask
    // fuer 1 Tick NICHT-runnable -> IDLE0/IDLE1 kommen garantiert dran und resetten ihren WDT.
    // Gehoert fachlich in die App-Loop, NICHT in den HTTP-Adapter (der darf No-op bleiben).
    vTaskDelay(1);
}


// -----------------------------------------------------------------------------
// Status-LED
// -----------------------------------------------------------------------------

// Der XIAO-S3-Variant definiert LED_BUILTIN (aktiv-low). Das ESP32P4 Dev Module
// (Waveshare P4-Pico) tut das NICHT -> Onboard-LED-Pin unbekannt. Dann fassen wir
// bewusst KEINEN GPIO an (koennte Kamera/USB/PSRAM stoeren) und lassen die LED-
// Funktionen No-Ops (ledIsOn wird weiter gefuehrt). Sobald der echte P4-LED-Pin
// bekannt ist: hier WEIRDOS_STATUS_LED_PIN definieren.
#if defined(LED_BUILTIN)
#define WEIRDOS_STATUS_LED_PIN LED_BUILTIN
#endif

void initializeStatusLed() {
#ifdef WEIRDOS_STATUS_LED_PIN
    pinMode(WEIRDOS_STATUS_LED_PIN, OUTPUT);
#endif
    switchLedOff();
}


void switchLedOn() {
#ifdef WEIRDOS_STATUS_LED_PIN
    digitalWrite(WEIRDOS_STATUS_LED_PIN, LOW);
#endif
    ledIsOn = true;
}


void switchLedOff() {
#ifdef WEIRDOS_STATUS_LED_PIN
    digitalWrite(WEIRDOS_STATUS_LED_PIN, HIGH);
#endif
    ledIsOn = false;
}


// Blinkt waehrend des Verbindungsaufbaus, leuchtet dauerhaft bei Verbindung.
void updateStatusLed() {
    if (wifiState == PORTAL_WIFI_CONNECTING) {
        if (millis() - ledLastToggleAt >= LED_BLINK_INTERVAL_MS) {
            ledLastToggleAt = millis();

            if (ledIsOn) {
                switchLedOff();
            } else {
                switchLedOn();
            }
        }

        return;
    }

    if (wifiState == PORTAL_WIFI_CONNECTED) {
        if (!ledIsOn) {
            switchLedOn();
        }

        return;
    }

    if (ledIsOn) {
        switchLedOff();
    }
}


// -----------------------------------------------------------------------------
// Persistenz
// -----------------------------------------------------------------------------

void loadWifiCredentials() {
    preferences.begin("wifi", true);

    configuredSsid = preferences.getString("ssid", "");
    configuredPassword = preferences.getString("password", "");

    preferences.end();
}


void saveWifiCredentials(
    const String& ssid,
    const String& password
) {
    preferences.begin("wifi", false);

    preferences.putString("ssid", ssid);
    preferences.putString("password", password);

    preferences.end();

    configuredSsid = ssid;
    configuredPassword = password;
}


bool hasWifiCredentials() {
    return configuredSsid.length() > 0;
}


// Loescht die im Flash gespeicherten Zugangsdaten. Die RAM-Kopie bleibt
// unberuehrt, damit eine laufende Sitzungsverbindung weiter funktioniert.
void clearStoredCredentials() {
    preferences.begin("wifi", false);
    preferences.clear();
    preferences.end();

    Serial.println("Stored WiFi credentials cleared.");
}


// Uebernimmt Zugangsdaten nur fuer die laufende Sitzung (RAM), ohne sie
// im Flash abzulegen.
void setSessionCredentials(
    const String& ssid,
    const String& password
) {
    configuredSsid = ssid;
    configuredPassword = password;
}


// -----------------------------------------------------------------------------
// PIN-Schutz und Zielnetz-Opt-in (Persistenz im NVS "wifi")
// -----------------------------------------------------------------------------

void loadSecurityPrefs() {
    preferences.begin("wifi", true);
    devicePin = preferences.getString("pin", PIN_DEFAULT);
    targetNetworkEnabled = preferences.getBool("target", TARGET_NETWORK_DEFAULT);
    webWanEnabled = preferences.getBool("wanweb", true);
    // Management-Transport HTTPS. Default HTTP (false), BEWUSST: der P4 ist nur ueber LTE
    // erreichbar (kein Setup-AP) -> ein untestbarer TLS-Fehlstart wuerde die einzige
    // Zugangsmoeglichkeit sperren. HTTPS ist vollstaendig implementiert (esp_https_server,
    // durch den Stream-PoC hardware-erprobt) und per UI einschaltbar; nach einem realen
    // HTTPS-Zugriffstest kann der Default gefahrlos auf true gestellt werden.
    webHttpsEnabled = preferences.getBool("webhttps", false);
    preferences.end();
}


void saveWebWanEnabled(bool enabled) {
    preferences.begin("wifi", false);
    preferences.putBool("wanweb", enabled);
    preferences.end();
    webWanEnabled = enabled;
}

void saveWebHttpsEnabled(bool enabled) {
    preferences.begin("wifi", false);
    preferences.putBool("webhttps", enabled);
    preferences.end();
    webHttpsEnabled = enabled;
}


void saveDevicePin(const String& pin) {
    preferences.begin("wifi", false);
    preferences.putString("pin", pin);
    preferences.end();

    devicePin = pin;
    // PIN-Wechsel (auch Werksreset) invalidiert bestehende Management-Sessions: ein
    // altes/mitgelesenes Token darf nach der Aenderung nicht weitergelten. Der Aufrufer
    // (handlePinChange) gibt danach fuer den aktuellen Browser eine frische Session aus.
    WeirdAuth::invalidate();
}


void saveTargetEnabled(bool enabled) {
    preferences.begin("wifi", false);
    preferences.putBool("target", enabled);
    preferences.end();

    targetNetworkEnabled = enabled;
}


// -----------------------------------------------------------------------------
// Diagnose-Log: ESP-IDF-Logausgabe in einen RAM-Ringpuffer umleiten, damit wir
// die internen USB-/Enumerations-Meldungen ueber /modem-log lesen koennen
// (der serielle Port faellt im USB-Host-Betrieb weg).
// -----------------------------------------------------------------------------
#define USB_LOG_CAP 8192
static char             g_log[USB_LOG_CAP];
static volatile size_t  g_logHead = 0;
static volatile bool    g_logWrapped = false;
static SemaphoreHandle_t g_logMux = NULL;

static int logVprintf(const char* fmt, va_list args) {
    char line[220];
    int n = vsnprintf(line, sizeof(line), fmt, args);
    int len = (n < 0) ? 0 : (n < (int)sizeof(line) ? n : (int)sizeof(line) - 1);
    if (g_logMux && xSemaphoreTake(g_logMux, 0) == pdTRUE) {
        for (int i = 0; i < len; i++) {
            g_log[g_logHead++] = line[i];
            if (g_logHead >= USB_LOG_CAP) { g_logHead = 0; g_logWrapped = true; }
        }
        xSemaphoreGive(g_logMux);
    }
    return n;
}

static void startLogCapture() {
    g_logMux = xSemaphoreCreateMutex();
    esp_log_set_vprintf(logVprintf);
    // Mehr Detail zur Enumeration (soweit in den vorkompilierten Libs verfuegbar).
    esp_log_level_set("ENUM", ESP_LOG_DEBUG);
    esp_log_level_set("USBH", ESP_LOG_DEBUG);
    esp_log_level_set("HUB",  ESP_LOG_DEBUG);
    esp_log_level_set("Hub",  ESP_LOG_DEBUG);
    esp_log_level_set("HAL",  ESP_LOG_DEBUG);
}


// -----------------------------------------------------------------------------
// Der komplette EC200A-Treiber (USB-Host, AT-Kanal, PPP-Datenpumpe, Band-/RAT-
// Konfiguration, Modem-Prefs, Aktionsschicht) liegt jetzt in ec200a_modem.cpp /
// ec200a_modem.h. Diese .ino nutzt ihn ueber die API + Observer-Listener.
// -----------------------------------------------------------------------------

void loadDiagPrefs() {
    preferences.begin("diag", true);
    diagEnabled = preferences.getBool("en", true);   // Default an
    preferences.end();
}
void saveDiagPrefs() {
    preferences.begin("diag", false);
    preferences.putBool("en", diagEnabled);
    preferences.end();
}

void loadDyndnsPrefs() {
    preferences.begin("dyndns", true);
    dyndnsEnabled  = preferences.getBool("en", true);                  // P4-TEST: default AN
    dyndnsProvider = preferences.getString("prov", "custom");
    dyndnsUrl      = preferences.getString("url", DYNDNS_TEST_URL);     // P4-TEST-Default (s. Warnung)
    dyndnsDomain   = preferences.getString("dom", DYNDNS_TEST_DOMAIN);  // P4-TEST-Default
    dyndnsUser     = preferences.getString("user", "");
    dyndnsPass     = preferences.getString("pass", "");
    dyndnsEgress   = preferences.getString("egr", "auto");
    preferences.end();
}


void saveDyndnsPrefs() {
    preferences.begin("dyndns", false);
    preferences.putBool("en", dyndnsEnabled);
    preferences.putString("prov", dyndnsProvider);
    preferences.putString("url", dyndnsUrl);
    preferences.putString("dom", dyndnsDomain);
    preferences.putString("user", dyndnsUser);
    preferences.putString("pass", dyndnsPass);
    preferences.putString("egr", dyndnsEgress);
    preferences.end();
}


// -----------------------------------------------------------------------------
// DynDNS-Update-Loop: meldet die aktuelle oeffentliche PPP-IPv4 an den Anbieter,
// damit die Kamera unter einem festen Namen erreichbar ist (dynamische IP).
// Update erfolgt bei IP-Wechsel, alle 6 h als Keepalive, und auf "Jetzt
// aktualisieren". Der HTTP-GET geht ueber die PPP-Default-Route ins Internet.
// URL-Platzhalter wie im FritzBox-Feld: <ipaddr> <ip6addr> <username> <passwd>
// <domain> (zusaetzlich <pass> als Alias).
// -----------------------------------------------------------------------------
#if WEIRDOS_FEATURE_DYNDNS   // Task-Zustand
static TaskHandle_t  g_dyndnsTask     = NULL;
static String        g_dyndnsLastIp   = "";        // zuletzt erfolgreich gemeldete IP
static uint32_t      g_dyndnsLastOkMs = 0;         // millis der letzten OK-Meldung
static String        g_dyndnsStatus   = "inaktiv"; // Anzeige im UI
static volatile bool g_dyndnsForce    = false;     // "Jetzt aktualisieren"
static String        g_dyndnsEgressUsed = "";      // Default-netif-IP im Moment des letzten Connects (Verifikation)

// Erzwingt beim naechsten Task-Durchlauf sofort ein Update (weckt den Task).
void dyndnsForceNow() { g_dyndnsForce = true; }
#else
void dyndnsForceNow() {}   // kein DynDNS im Build: Aufrufer (PPP-Observer, Konsole, Datenlink) bleiben gueltig
#endif // WEIRDOS_FEATURE_DYNDNS (Task-Zustand)

// Aktuelle oeffentliche WAN-IPv4 - datenpfad-neutral. PPP: der ESP HAT die oeffentliche
// IP direkt. ECM: der ESP-netif hat nur die private Modem-Subnetz-IP -> die oeffentliche
// steht im PDP-Kontext (beim ECM-begin aus CGPADDR gecacht, ecmWanIp()).
static String modemWanIp() {
    // PPP: der ESP hat die oeffentliche IP direkt. ECM: ecmWanIp() liefert jetzt die
    // reale netif-IP als Source of Truth (Sonderfall ausgelagert in ec200a_ecm.cpp).
    return pppIsUp() ? pppIpStr() : ecmWanIp();
}

#if WEIRDOS_FEATURE_DYNDNS   // Prewarm-/Fallback-Update-Pfad (HTTPClient)
static void dyndnsApplyEgress();   // vorwaerts: unmittelbar vor dem Connect aufgerufen

// Host-Teil einer http(s)-URL (fuer DNS-Prewarm).
static String dyndnsUrlHost(const String& u) {
    int s = u.indexOf("://");
    if (s < 0) return "";
    s += 3;
    int e = s;
    while (e < (int)u.length() && u[e] != '/' && u[e] != ':') e++;
    return u.substring(s, e);
}

// Issue #6: Der DynDNS-Request MUSS ueber das gewaehlte Egress-Netz raus (IONOS ist
// quell-IP-basiert). WiFiClientSecure/ssl_client (Core 3.3.11) bietet keinen Socket-
// Bind-Hook; der Socket entsteht intern und folgt netif_default -> Race, wenn WLAN die
// Default-Route zwischen "Route setzen" und "connect" zurueckholt (DHCP-Renew/Reconnect).
// Das echte Interface-Binding (eigener Socket) ist die Stufe-7-Transport-Arbeit. Hier
// wird das Race praktisch geschlossen: (1) DNS vorwaermen, damit der TLS-Connect keinen
// DNS-Roundtrip macht; (2) das Egress-Netz UNMITTELBAR vor http.GET() (= dem connect)
// als Default-Route pinnen -> Restfenster nur noch wenige us statt zig ms.
// Die konfigurierte URL wird VERBATIM benutzt (der IONOS-Token steckt in der URL).
// Bis zu 4 Versuche bei reinen VERBINDUNGSfehlern; HTTP-Antworten NICHT wiederholen.
static String dyndnsDoUpdate(const String& ip) {
    if (dyndnsUrl.length() == 0) return "Fehler: keine Update-URL";
    const String& url = dyndnsUrl;
    const int MAX_TRIES = 4;
    String lastErr = "Fehler: unbekannt";

    // DNS vorwaermen (Egress egal - die Antwort ist IONOS' oeffentliche IP, ueberall
    // gleich; nur der spaetere TLS-Connect entscheidet die Quell-IP). Danach trifft
    // getaddrinfo im Connect den lwIP-Cache -> kein Netz-Roundtrip im heiklen Fenster.
    {
        String host = dyndnsUrlHost(url);
        if (host.length()) { IPAddress rip; Network.hostByName(host.c_str(), rip); }   // = WiFi.hostByName (Core 3.x), ohne WiFi-Objekt
    }

    for (int attempt = 1; attempt <= MAX_TRIES; attempt++) {
        HTTPClient http;
        http.setConnectTimeout(8000);
        http.setTimeout(8000);
        int    code  = 0;
        String body  = "";
        bool   began = false;

        if (url.startsWith("https://")) {
            WiFiClientSecure sec;
            sec.setInsecure();                     // keine Zert-Pruefung (wie Router-DynDNS)
            began = http.begin(sec, url);
            if (began) {
                http.setUserAgent("WeirdOS-DynDNS/1");
                dyndnsApplyEgress();               // Egress-Route unmittelbar VOR dem Connect pinnen
                g_dyndnsEgressUsed = ecmDefaultRouteIp();
                code = http.GET();
                if (code > 0) body = http.getString();
                http.end();
            }
        } else {
            NetworkClient cl;   // Core 3.x: WiFiClient ist nur ein typedef hierauf (WiFi.h nicht noetig)
            began = http.begin(cl, url);
            if (began) {
                http.setUserAgent("WeirdOS-DynDNS/1");
                dyndnsApplyEgress();               // Egress-Route unmittelbar VOR dem Connect pinnen
                g_dyndnsEgressUsed = ecmDefaultRouteIp();
                code = http.GET();
                if (code > 0) body = http.getString();
                http.end();
            }
        }

        if (!began) return "Fehler: URL ungueltig";

        if (code > 0) {                            // Server hat geantwortet -> auswerten, NICHT wiederholen
            body.trim();
            String low = body; low.toLowerCase();
            bool bodyBad = low.indexOf("badauth") >= 0 || low.indexOf("nohost")  >= 0
                        || low.indexOf("notfqdn") >= 0 || low.indexOf("badagent")>= 0
                        || low.indexOf("!donator")>= 0 || low.indexOf("abuse")   >= 0
                        || low.indexOf("dnserr")  >= 0 || low.indexOf("911")     >= 0;
            bool httpOk = (code >= 200 && code < 300);
            String tail = body.length() ? (" / " + body.substring(0, 40)) : "";
            if (httpOk && !bodyBad) return "OK (" + ip + ") HTTP " + String(code)
                                        + " (Versuch " + String(attempt) + ")" + tail;
            return "Fehler: HTTP " + String(code) + tail;
        }

        lastErr = "Fehler: " + HTTPClient::errorToString(code)
                + " (Code " + String(code) + ", Versuch " + String(attempt) + "/" + String(MAX_TRIES)
                + ", Heap " + String((unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024)) + "k/"
                + String((unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) / 1024)) + "k)";
        if (attempt < MAX_TRIES) delay(2000);
    }
    return lastErr;
}
#endif // WEIRDOS_FEATURE_DYNDNS (Prewarm-/Fallback-Update-Pfad (HTTPClient))

// WLAN-STA als Default-Route (Pendant zu ecmSetDefaultRoute fuer das WLAN-Egress).
static void wlanSetDefaultRoute() {
    esp_netif_t* sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (sta) esp_netif_set_default_netif(sta);
}

// Das vom Nutzer gewaehlte Egress-Netz vor dem DynDNS-Update aktiv schalten
// (Default-Route). "wifi" -> WLAN-STA; "auto"/"modem" -> Mobilfunk (sofern ECM up).
// PPP ist per pppapi_set_default ohnehin Default, solange es laeuft.
static void dyndnsApplyEgress() {
    if (dyndnsEgress == "wifi") wlanSetDefaultRoute();
    else if (ec200aEcm.isUp()) ecmSetDefaultRoute();
}

// Repraesentative IP des gewaehlten Egress-Netzes (Link-Check + Change-Detection).
// "wifi": lokale STA-IP (der oeffentliche Wert liegt hinter dem Heim-NAT und ist dem
// ESP unbekannt -> Republish laeuft ueber den 6-h-Keepalive/Force). Sonst: Mobilfunk-WAN.
static String dyndnsEgressIp() {
    if (dyndnsEgress == "wifi") {
#if WEIRDOS_FEATURE_WIFI
        return (WiFi.status() == WL_CONNECTED) ? WiFi.localIP().toString() : String("");
#else
        return String("");   // WLAN nicht im Build -> kein STA-Egress
#endif
    }
    return modemWanIp();   // auto + modem
}

// 7.2c-2: DynDNS ueber den interface-GEBUNDENEN Transport (EgressPolicy -> NetIface ->
// HttpTransport). Laeuft SYNCHRON im bestehenden dyndnsTask (16k Stack, seit Boot) -
// KEIN zusaetzlicher 16k-Worker (der war der Speicher-Blocker). Die HTTPS-QUELL-IP haengt
// hart am Socket-bind() an die Interface-IP -> unabhaengig von netif_default (harter #6-Fix),
// braucht KEIN Route-Pinning fuer HTTPS. Fuer DNS wird die Route noch gepinnt (s.u.), weil
// ECM die Carrier-DNS global setzt; das ist eine spaetere 7.x-Haertung (gebundener Resolver).
// dyndnsDoUpdate (a7bec98: Prewarm + HTTPS-Route-Pinning) bleibt als Fallback.
#if WEIRDOS_FEATURE_DYNDNS   // gebundener Update-Pfad + Task
static String dyndnsDoUpdateBound(const String& ip) {
    if (dyndnsUrl.length() == 0) return "Fehler: keine Update-URL";
    NetIface iface;
    if (!egressResolve(dyndnsEgress, iface)) return "Fehler: kein Egress-Interface verfuegbar";
    g_dyndnsEgressUsed = iface.ip;   // gebundene Quell-IP (Verifikation)

    // NUR fuer den DNS-Resolver: das gewaehlte Netz als Default-Route setzen, damit die
    // (bei ECM Carrier-) DNS-Server erreichbar sind. Die HTTPS-QUELL-IP haengt NICHT
    // hieran, sondern am Socket-bind() im Transport (race-frei) - anders als a7bec98.
    // Spaeter ersetzbar durch einen interface-gebundenen Resolver.
    dyndnsApplyEgress();

    HttpRequest rq; rq.url = dyndnsUrl; rq.egress = &iface;
    HttpResponse rp = esp32BoundHttpTransport().get(rq);   // direkt, kein Extra-Task
    if (rp.error.length()) return "Fehler: " + rp.error;

    String body = rp.body; body.trim();
    String low = body; low.toLowerCase();
    bool bodyBad = low.indexOf("badauth") >= 0 || low.indexOf("nohost")  >= 0
                || low.indexOf("notfqdn") >= 0 || low.indexOf("badagent")>= 0
                || low.indexOf("!donator")>= 0 || low.indexOf("abuse")   >= 0
                || low.indexOf("dnserr")  >= 0 || low.indexOf("911")     >= 0;
    bool httpOk = (rp.status >= 200 && rp.status < 300);
    String tail = body.length() ? (" / " + body.substring(0, 40)) : "";
    if (httpOk && !bodyBad) return "OK (" + ip + ") HTTP " + String(rp.status) + " [bound " + iface.id + "]" + tail;
    return "Fehler: HTTP " + String(rp.status) + tail;
}

// Hintergrund-Task: prueft regelmaessig und meldet bei Bedarf. R1-Schranke bleibt,
// aber egress-abhaengig: kein Update, solange das gewaehlte Netz keine IP hat.
static void dyndnsTask(void* arg) {
    const uint32_t REFRESH_MS = 6UL * 3600 * 1000;  // Keepalive alle 6 h
    uint32_t healFailStreak = 0;   // 7.9.12: aufeinanderfolgende heap-bedingte Update-Fehler bei veralteter DNS
    for (;;) {
        bool force = g_dyndnsForce; g_dyndnsForce = false;
        String ip = dyndnsEgressIp();   // gewaehltes Egress-Netz (auto/modem: Mobilfunk-WAN; wifi: STA)
        if (!dyndnsEnabled) {
            g_dyndnsStatus = "inaktiv";
        } else if (ip.length() == 0) {
            g_dyndnsStatus = "wartet auf Datenlink";
        } else {
            bool ipChanged = (ip != g_dyndnsLastIp);
            bool stale = (g_dyndnsLastOkMs == 0)
                      || ((uint32_t)(millis() - g_dyndnsLastOkMs) >= REFRESH_MS);
            if (force || ipChanged || stale) {
                // Egress-Route wird jetzt in dyndnsDoUpdate unmittelbar vor dem Connect
                // gepinnt (engeres Fenster) - nicht mehr hier, Zeilen vor dem Request.
                g_dyndnsStatus = "aktualisiere ...";
                // 7.2c-2: gebundener Transport aktiv. Fallback = dyndnsDoUpdate(ip) (a7bec98).
                String r = dyndnsDoUpdateBound(ip);
                if (r.startsWith("OK")) {
                    g_dyndnsLastIp = ip; g_dyndnsLastOkMs = millis();
                    healFailStreak = 0; g_dyndnsHealReboots = 0;   // Heilungs-Episode beendet
                } else {
                    // 7.9.12 Selbstheilung: NUR der heap-bedingte TLS-Setup-Fehler ist per
                    // Reboot (Heap-Defrag) heilbar - HTTP/badauth NICHT (sonst Boot-Loop).
                    // Und nur, wenn die DNS-Adresse nach IP-Wechsel wirklich veraltet ist
                    // (ip != zuletzt gemeldet) -> Box von aussen unerreichbar. Reiner
                    // 6h-Keepalive-Fehler bei UNVERAENDERTER IP rechtfertigt keinen Reboot.
                    bool heapHeal = (r.indexOf("ssl_setup") >= 0);
                    bool dnsStale = (ip != g_dyndnsLastIp);
                    if (heapHeal && dnsStale) healFailStreak++; else healFailStreak = 0;
                    const uint32_t HEAL_AFTER  = 6;   // erst ~6 * 12s Live-Retry (~70s+) zulassen
                    const uint32_t HEAL_MAX_RB = 3;   // max. Reboots pro Episode (Boot-Loop-Deckel)
                    if (healFailStreak >= HEAL_AFTER && millis() > 60000UL
                            && g_dyndnsHealReboots < HEAL_MAX_RB) {
                        g_dyndnsHealReboots++;
                        logEvent("DynDNS: Heap fragmentiert, Update scheitert nach IP-Wechsel"
                                 " - kontrollierter Reboot zur Selbstheilung ("
                                 + String((uint32_t)g_dyndnsHealReboots) + "/" + String(HEAL_MAX_RB) + ")");
                        g_dyndnsStatus = "Selbstheilung: Reboot ...";
                        delay(400);          // Log/Status flushen
                        esp_restart();        // frischer Boot -> grosser Heap-Block -> Update zieht
                    }
                }
                g_dyndnsStatus = r;
            } else if (g_dyndnsLastIp.length()) {
                g_dyndnsStatus = "aktuell (" + g_dyndnsLastIp + ")";
            }
        }
        // Bei Fehler schnell erneut versuchen (self-healing), sonst entspannt schlafen.
        int sleepS = g_dyndnsStatus.startsWith("Fehler") ? 12 : 30;
        for (int i = 0; i < sleepS && !g_dyndnsForce; i++) vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void startDyndns() {
    // Stack grosszuegig: der TLS-Handshake (mbedTLS) laeuft synchron in diesem Task.
    // 16k (statt 12k), weil der gebundene Transport die mbedTLS-Kontexte auf dem Stack
    // haelt (WiFiClientSecure legt sie auf den Heap). Einmal bei Boot -> kein
    // Request-Zeit-Alloc, der mit den mbedTLS-Record-Puffern konkurriert.
    if (!g_dyndnsTask)
        xTaskCreatePinnedToCore(dyndnsTask, "dyndns", 16384, NULL, 3, &g_dyndnsTask, 0);
}
#else
void startDyndns() { Serial.println("DynDNS nicht im Build enthalten (WEIRDOS_FEATURE_DYNDNS=0)."); }
#endif // WEIRDOS_FEATURE_DYNDNS (gebundener Update-Pfad + Task)


int cpuFreqForProfile(const String& p) {
    if (p == "power") return 240;
    if (p == "eco")   return 80;
    return 160;                 // balanced
}

// Setzt den CPU-Takt zur Laufzeit (kein Reboot). 80/160/240 sind WLAN-vertraeglich.
void applyCpuProfile() {
    setCpuFrequencyMhz(cpuFreqForProfile(cpuProfile));
}

void loadEnergyPrefs() {
    preferences.begin("energy", true);
    cpuProfile      = preferences.getString("cpu", "balanced");
    wifiOffOnMobile = preferences.getBool("wifioff", false);
    preferences.end();
}

void saveEnergyPrefs() {
    preferences.begin("energy", false);
    preferences.putString("cpu", cpuProfile);
    preferences.putBool("wifioff", wifiOffOnMobile);
    preferences.end();
}


// PIN gilt als deaktiviert, wenn sie leer ist - dann kein Gate.
bool pinDisabled() {
    return devicePin.length() == 0;
}


// Subnetz-Vergleich (fuer die LAN-Erkennung).
static bool ipInSubnet(const IPAddress& ip, const IPAddress& net, const IPAddress& mask) {
    for (int i = 0; i < 4; i++)
        if ((ip[i] & mask[i]) != (net[i] & mask[i])) return false;
    return true;
}

// ENTFERNT (Flip auf WeirdHttpEsp): die server-basierten Alt-Auth-Helfer
// reqIsWan()/reqWanDenied()/isAuthenticated()/sendAuthCookie() lasen aus dem globalen
// Arduino-`server`. Die Control-Plane nutzt jetzt ausschliesslich die backend-neutralen
// Pendants: weirdReqIsWan(clientIp)/weirdReqWanDenied(req) + WeirdAuth::authorized()
// + requireSession(). Kein globaler server-Zugriff mehr fuer Auth.


// WAN-Erkennung aus einer Client-IP (backend-neutral, fuer WeirdHttp-Handler die
// server.client() nicht kennen). Gleiche Logik wie reqIsWan(), nur ueber die IP.
static bool weirdReqIsWan(const String& clientIp) {
    if (!pppIsUp() && !ec200aEcm.isUp()) return false;   // kein WAN aktiv
    IPAddress rip;
    if (!rip.fromString(clientIp)) return true;          // unparsebar -> sicherheitshalber WAN
    if (ipInSubnet(rip, AP_IP, AP_NETMASK)) return false;                       // AP-LAN
#if WEIRDOS_FEATURE_WIFI
    if (WiFi.isConnected() && (uint32_t)WiFi.localIP() != 0
            && ipInSubnet(rip, WiFi.localIP(), WiFi.subnetMask())) return false; // STA-LAN
#endif
    return true;
}

// WAN-Deny aus einer WeirdHttp-Anfrage (Pendant zu reqWanDenied(), backend-neutral):
// Web ueber WAN deaktiviert UND Request kommt uebers WAN. Fuer LAN-public-aber-WAN-gated
// Handler (Status/Scan), die KEINEN PIN verlangen (also KEIN requireSession).
static bool weirdReqWanDenied(WeirdHttpRequest& req) {
    return !accessAllowed("web", req.clientIp());   // Zugangsregel je Dienst (LAN immer, VPN/Internet je Freigabe)
}
// LAN-Erkennung fuer die Zugangsregel (access_policy): AP-/STA-Subnetz = lokal.
static bool accessIsLanIp(const String& clientIp) {
    IPAddress rip;
    if (!rip.fromString(clientIp)) return false;
    if (ipInSubnet(rip, AP_IP, AP_NETMASK)) return true;
#if WEIRDOS_FEATURE_WIFI
    if (WiFi.isConnected() && (uint32_t)WiFi.localIP() != 0 && ipInSubnet(rip, WiFi.localIP(), WiFi.subnetMask())) return true;
#endif
    return false;
}

// requireSession: WeirdHttp-Middleware auf WeirdAuth (Auth VOR dem Dispatch, nicht
// in jedem Handler). Json = 401-JSON fuer API/Aktionen; Page = Redirect auf "/"
// (dort rendert die PIN-Gate). Der native VideoServer nutzt WeirdAuth direkt.
enum class AuthFail { Json, Page };
// Erst-Einrichtung: solange die Werks-PIN aktiv ist, rendert die Root nur die PIN-Setup-Seite.
// Geraet ist ueber Mobilfunk mit oeffentlicher IPv4 erreichbar -> "0000" darf nie Betriebszustand sein.
static bool pinStillDefault() { return devicePin == PIN_DEFAULT; }
static void sendAppOrPinSetup(WeirdHttpResponse& res, const String& page = String()) {
    if (pinStillDefault()) sendPinSetupGate(res, "");
    else                   sendAppPage(res, page);   // genau EINE Seite (?p=tab[/psub]); leer = Uebersicht
}

// Nach einem Formular-POST zurueck auf die Seite, von der er kam (Referer "/?p=..."), sonst Startseite.
// Nur ein Seitenschluessel [a-z0-9/-] wird uebernommen -- kein offener Redirect.
static void uiRedirectBack(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String ref = req.header("Referer");
    String p;
    int i = ref.indexOf("/?p=");
    if (i >= 0) {
        p = ref.substring(i + 4);
        int e = p.indexOf('&'); if (e >= 0) p = p.substring(0, e);
        e = p.indexOf('#');     if (e >= 0) p = p.substring(0, e);
    }
    bool ok = p.length() > 0 && p.length() < 40;
    for (size_t k = 0; ok && k < p.length(); k++) {
        char c = p[k];
        if (!(isalnum((unsigned char)c) || c == '-' || c == '/')) ok = false;
    }
    res.redirect(ok ? String("/?p=") + p : String("/"), 303);
}

static WeirdHttpHandler requireSession(WeirdHttpHandler inner, AuthFail fail = AuthFail::Json) {
    return [inner, fail](WeirdHttpRequest& req, WeirdHttpResponse& res) {
        // Zugangsregel VOR der Session: aus einer nicht freigegebenen Zone (VPN/Internet) gibt es
        // die Weboberflaeche gar nicht -- auch nicht mit gueltiger Session.
        if (!accessAllowed("web", req.clientIp())) {
            if (fail == AuthFail::Json) res.send(403, "application/json", "{\"ok\":false,\"error\":\"zone_denied\",\"msg\":\"Weboberflaeche aus dieser Zone nicht freigegeben.\"}");
            else res.send(403, "text/plain; charset=utf-8", "Weboberflaeche aus dieser Zone nicht freigegeben (System > Sicherheit > Zugriff je Dienst).");
            return;
        }
        if (WeirdAuth::authorized(req.cookie(WeirdAuth::cookieName()), weirdReqIsWan(req.clientIp()))) {
            // Werks-PIN aktiv: ausser PIN-Wechsel/Abmelden nichts erlauben (auch keine API), sonst
            // waere die Oberflaeche mit bekannter PIN vollstaendig aus dem Internet bedienbar.
            if (pinStillDefault() && req.path() != "/pin-change" && req.path() != "/logout") {
                if (fail == AuthFail::Json)
                    res.send(403, "application/json", "{\"ok\":false,\"error\":\"pin_default\",\"msg\":\"Erst eigene PIN setzen.\"}");
                else
                    res.redirect("/");
                return;
            }
            inner(req, res);
            return;
        }
        if (fail == AuthFail::Json)
            res.send(401, "application/json", "{\"ok\":false,\"error\":\"unauthorized\"}");
        else
            res.redirect("/");   // Seite: Root rendert die PIN-Gate
    };
}

// No-Cache-Header fuer migrierte Handler (Pendant zu sendNoCacheHeaders()).
static void resNoCache(WeirdHttpResponse& res) {
    res.header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    res.header("Pragma", "no-cache");
    res.header("Expires", "0");
}

// Explizite Forward-Declaration des backend-neutralen Loggers (Overload). Wird von
// den migrierten Root/PIN/Captive-Handlern VOR seiner Definition aufgerufen -> nicht
// auf die Arduino-Auto-Prototypen fuer ueberladene Referenz-Signaturen verlassen.
void logHttpRequest(WeirdHttpRequest& req, const String& type);


// -----------------------------------------------------------------------------
// Accesspoint und Captive-Portal-Ankuendigung
// Baustein WIFI: SoftAP, DHCP-DNS-Offer und der Captive-DNS-Responder existieren nur
// mit WLAN-Funk im Bild. Die Aufrufer (setup(), loop(), startSetupAp/stopSetupAp)
// sind ebenfalls unter WEIRDOS_FEATURE_WIFI gegated.
// -----------------------------------------------------------------------------
#if WEIRDOS_FEATURE_WIFI

void startAccessPoint() {
    if (!wifiStackActive()) { Serial.println("[WLAN] startAccessPoint uebersprungen: kein WLAN-Stack."); return; }
    WiFi.setHostname(deviceHostname.c_str());

    WiFi.mode(WIFI_AP_STA);
    WiFi.setSleep(false);

    // Kanalwahl: AP und STA teilen sich auf EINEM Funkchip zwangsweise einen Kanal.
    //   - WLAN verbunden -> AP MUSS dessen Kanal nehmen (sonst wackelt die STA-Verbindung).
    //   - sonst (AP allein): fester Kanal, falls gewaehlt; "Automatisch" -> Default 1.
    uint8_t apCh;
    const NetworkModeConfig& nm = networkMode.config();
    if (wifiState == PORTAL_WIFI_CONNECTED) {
        apCh = (uint8_t)WiFi.channel();
    } else if (nm.apChannelPol == "fixed" && nm.apChannel >= 1 && nm.apChannel <= 13) {
        apCh = nm.apChannel;
    } else {
        apCh = 1;
    }

    bool started = WiFi.softAP(
        CONFIG_AP_SSID,
        setupApPassword.c_str(),
        apCh
    );

    if (!started) {
        Serial.println("Configuration access point could not be started.");
        return;
    }

    // IP-Konfiguration nach dem AP-Start setzen, damit das AP-Netif existiert.
    bool configured = WiFi.softAPConfig(
        AP_IP,
        AP_IP,
        AP_NETMASK
    );

    if (!configured) {
        Serial.println("SoftAP IP configuration failed, using default IP.");
    }

    delay(100);

    Serial.print("Configuration AP started: ");
    Serial.println(CONFIG_AP_SSID);

    Serial.print("Configuration address: http://");
    Serial.println(WiFi.softAPIP());
}


// Konfiguriert den DHCP-Server des SoftAP:
//
//   1. DNS: Die AP-IP wird explizit als DNS-Server im DHCP-Offer angekuendigt.
//      Ohne diese Konfiguration erhalten manche Clients keinen oder einen
//      fremden DNS-Server und der Wildcard-DNS-Hijack laeuft ins Leere. Das
//      ist die haeufigste Ursache dafuer, dass die Portalseite manuell
//      erreichbar ist, das Portal aber nie automatisch aufgeht.
//
//   2. Option 114 (RFC 8910): Standardmaessig deaktiviert (siehe Schalter).
//      Android akzeptiert die Captive-Portal-API nur ueber HTTPS mit
//      gueltigem Zertifikat; die klassischen Probes sind auf dieser
//      Hardware der einzige tragfaehige Erkennungsweg.
void configureSoftApDhcp() {
    snprintf(
        captivePortalApiUri,
        sizeof(captivePortalApiUri),
        "http://%s/captive-api",
        WiFi.softAPIP().toString().c_str()
    );

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
    esp_netif_t* apInterface = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");

    if (apInterface == NULL) {
        Serial.println("AP netif handle unavailable, DHCP options skipped.");
        return;
    }

    esp_netif_dhcps_stop(apInterface);

    // AP-IP als primaeren DNS-Server hinterlegen ...
    esp_netif_dns_info_t dnsInfo;
    memset(&dnsInfo, 0, sizeof(dnsInfo));

    dnsInfo.ip.type = ESP_IPADDR_TYPE_V4;
    dnsInfo.ip.u_addr.ip4.addr = static_cast<uint32_t>(WiFi.softAPIP());

    esp_err_t dnsResult = esp_netif_set_dns_info(
        apInterface,
        ESP_NETIF_DNS_MAIN,
        &dnsInfo
    );

    // ... und die DNS-Angabe im DHCP-Offer aktivieren.
    dhcps_offer_t offerDns = OFFER_DNS;

    esp_err_t offerResult = esp_netif_dhcps_option(
        apInterface,
        ESP_NETIF_OP_SET,
        ESP_NETIF_DOMAIN_NAME_SERVER,
        &offerDns,
        sizeof(offerDns)
    );

    if (dnsResult == ESP_OK && offerResult == ESP_OK) {
        Serial.print("DHCP DNS offer configured: ");
        Serial.println(WiFi.softAPIP());
    } else {
        Serial.print("DHCP DNS offer failed, errors ");
        Serial.print(dnsResult);
        Serial.print(" / ");
        Serial.println(offerResult);
    }

#if ENABLE_DHCP_OPTION_114
    esp_err_t capportResult = esp_netif_dhcps_option(
        apInterface,
        ESP_NETIF_OP_SET,
        ESP_NETIF_CAPTIVEPORTAL_URI,
        captivePortalApiUri,
        strlen(captivePortalApiUri)
    );
#endif

    esp_netif_dhcps_start(apInterface);

#if ENABLE_DHCP_OPTION_114
    if (capportResult == ESP_OK) {
        Serial.print("DHCP option 114 announced (best effort): ");
        Serial.println(captivePortalApiUri);
    } else {
        Serial.print("DHCP option 114 failed, error ");
        Serial.println(capportResult);
    }
#else
    Serial.println("DHCP option 114 disabled (no valid HTTPS CAPPORT available).");
#endif
#else
    Serial.println("DHCP options require ESP-IDF 5.x, skipped.");
#endif
}


// Eigener minimaler DNS-Responder statt der DNSServer-Library.
//
// Gruende:
//   1. Diagnose: Jede eingehende Query wird mit Name, Typ und Absender-IP
//      geloggt. Damit ist im Serial-Monitor sichtbar, ob die Probe-Hostnamen
//      des Handys ueberhaupt beim ESP ankommen.
//   2. Robustheit: EDNS0-Additional-Records (ARCOUNT != 0) werden ignoriert
//      statt die Antwort zu verhindern, und Nicht-A-Queries (AAAA, HTTPS/65)
//      erhalten ein korrektes leeres NOERROR statt keiner Antwort. Beides
//      sind bekannte Stolperstellen mit modernen Android-Clients.
//
// Jede A-Query wird mit der AP-IP beantwortet (Wildcard-Hijack).
void startDnsServer() {
    // Ohne WLAN-Stack (P4 ohne Funk) gibt es kein Captive Portal -> keinen UDP-Socket belegen
    // (lwIP-Budget: 16 Sockets gesamt, siehe setMaxOpenSockets).
    if (!wifiStackActive()) { Serial.println("[Netz] Captive-DNS uebersprungen: kein WLAN-Stack."); return; }
    if (dnsSocket.begin(DNS_PORT) == 1) {
        Serial.println("Portal DNS server started (with query logging).");
    } else {
        Serial.println("Portal DNS server could not be started.");
    }
}


const char* dnsTypeName(uint16_t qType) {
    switch (qType) {
        case 1:
            return "A";

        case 12:
            return "PTR";

        case 28:
            return "AAAA";

        case 65:
            return "HTTPS";

        default:
            return "?";
    }
}


void processDnsRequests() {
    // Pro Loop-Durchlauf mehrere anstehende Pakete abarbeiten, aber begrenzt,
    // damit der HTTP-Server nicht verhungert.
    for (int i = 0; i < 4; i++) {
        int packetSize = dnsSocket.parsePacket();

        if (packetSize <= 0) {
            return;
        }

        if (packetSize > DNS_MAX_PACKET_SIZE) {
            dnsSocket.flush();
            continue;
        }

        int length = dnsSocket.read(
            dnsPacket,
            DNS_MAX_PACKET_SIZE
        );

        if (length < 12) {
            continue;
        }

        answerDnsQuery(length);
    }
}


// Namen, bei denen eine positive Antwort ein beweisbarer Fehler waere.
// Moderne Clients (beobachtet: Samsung/Android 16) testen den Resolver nach
// dem Verbinden gezielt mit solchen Queries, um DNS-Hijacking zu erkennen:
// .onion (darf per RFC 7686 nie aufgeloest werden), Namen mit unzulaessigen
// Zeichen wie '*', Fantasienamen. Wer alles beantwortet, wird als defekter
// Resolver eingestuft - und die Portalerkennung findet dann gar nicht statt.
bool mustAnswerNxDomain(const String& name) {
    String lower = name;
    lower.toLowerCase();

    // RFC 7686: .onion liegt ausserhalb des DNS.
    if (lower == "onion" || lower.endsWith(".onion")) {
        return true;
    }

    // Zeichen ausserhalb von Hostname-Konventionen (z.B. '*').
    for (unsigned int i = 0; i < lower.length(); i++) {
        char c = lower.charAt(i);

        bool valid =
            (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9')
            || c == '.'
            || c == '-'
            || c == '_';

        if (!valid) {
            return true;
        }
    }

    return false;
}


void answerDnsQuery(int length) {
    bool isQuery = (dnsPacket[2] & 0x80) == 0;

    uint16_t questionCount =
        (dnsPacket[4] << 8) | dnsPacket[5];

    if (!isQuery || questionCount == 0) {
        return;
    }

    // Ersten Question-Eintrag parsen: Labels bis zum Nullbyte.
    String queryName;
    int pos = 12;

    while (pos < length) {
        uint8_t labelLength = dnsPacket[pos];

        if (labelLength == 0) {
            pos++;
            break;
        }

        // Kompressionszeiger sind in der Question unzulaessig.
        if ((labelLength & 0xC0) != 0) {
            return;
        }

        if (pos + 1 + labelLength > length) {
            return;
        }

        if (queryName.length() > 0) {
            queryName += '.';
        }

        for (int i = 0; i < labelLength; i++) {
            queryName += (char)dnsPacket[pos + 1 + i];
        }

        pos += 1 + labelLength;
    }

    if (pos + 4 > length) {
        return;
    }

    uint16_t queryType =
        (dnsPacket[pos] << 8) | dnsPacket[pos + 1];

    // Ende der Question-Section (Typ + Klasse).
    pos += 4;

    bool refuseName = mustAnswerNxDomain(queryName);
    bool answerWithApIp = (queryType == 1) && !refuseName;

    // Header zur Antwort umbauen. Der RD-Bit des Clients bleibt erhalten,
    // EDNS0-Additional-Records werden durch ARCOUNT=0 verworfen.
    dnsPacket[2] = 0x80 | (dnsPacket[2] & 0x01);
    dnsPacket[3] = refuseName ? 0x83 : 0x80;

    dnsPacket[4] = 0;
    dnsPacket[5] = 1;

    dnsPacket[6] = 0;
    dnsPacket[7] = answerWithApIp ? 1 : 0;

    dnsPacket[8] = 0;
    dnsPacket[9] = 0;

    dnsPacket[10] = 0;
    dnsPacket[11] = 0;

    int responseLength = pos;

    if (answerWithApIp) {
        IPAddress apIp = WiFi.softAPIP();

        uint8_t answer[16] = {
            0xC0, 0x0C,             // Zeiger auf den Namen in der Question
            0x00, 0x01,             // Typ A
            0x00, 0x01,             // Klasse IN
            0x00, 0x00, 0x00, 0x3C, // TTL 60 Sekunden
            0x00, 0x04,             // 4 Byte Adressdaten
            apIp[0], apIp[1], apIp[2], apIp[3]
        };

        if (responseLength + 16 > DNS_MAX_PACKET_SIZE) {
            return;
        }

        memcpy(
            dnsPacket + responseLength,
            answer,
            16
        );

        responseLength += 16;
    }

    dnsSocket.beginPacket(
        dnsSocket.remoteIP(),
        dnsSocket.remotePort()
    );

    dnsSocket.write(
        dnsPacket,
        responseLength
    );

    dnsSocket.endPacket();

    Serial.print("DNS query: ");
    Serial.print(queryName);
    Serial.print(" type=");
    Serial.print(dnsTypeName(queryType));
    Serial.print("(");
    Serial.print(queryType);
    Serial.print(") from ");
    Serial.print(dnsSocket.remoteIP());
    Serial.print(" -> ");

    if (answerWithApIp) {
        Serial.println(WiFi.softAPIP());
    } else if (refuseName) {
        Serial.println("NXDOMAIN");
    } else {
        Serial.println("empty NOERROR");
    }
}

#endif // WEIRDOS_FEATURE_WIFI (SoftAP + DHCP-Offer + Captive-DNS)


// -----------------------------------------------------------------------------
// Kamera (OV3660 auf XIAO ESP32S3 Sense)
// -----------------------------------------------------------------------------

int frameSizeIndexByName(const String& name) {
    for (int i = 0; i < FRAME_SIZE_OPTION_COUNT; i++) {
        if (name == FRAME_SIZE_OPTIONS[i].name) {
            return i;
        }
    }

    return -1;
}


// Grobe, konservative Schaetzung des JPEG-Framebuffers analog zur
// Treiber-Heuristik: etwa Breite x Hoehe / 5 Bytes je Buffer.
size_t estimateJpegFrameBytes(int optionIndex) {
    const FrameSizeOption& option = FRAME_SIZE_OPTIONS[optionIndex];

    return (size_t)option.width * option.height / 5;
}


// Stream-Port begrenzen: gueltiger TCP-Port, aber nicht 80 (Haupt-Weboberflaeche
// -> Aussperr-Gefahr). Ungueltiges faellt auf den Default 81 zurueck.
int sanitizeStreamPort(int port) {
    if (port < 1 || port > 65535 || port == 80) return 81;
    return port;
}

// Stream-Pfad normalisieren: fuehrenden '/' erzwingen, Query/Whitespace entfernen,
// nur unbedenkliche Zeichen zulassen. Leeres/ungueltiges faellt auf "/stream".
String sanitizeStreamPath(String path) {
    path.trim();
    int q = path.indexOf('?');
    if (q >= 0) path = path.substring(0, q);
    if (path.length() == 0) return "/stream";
    if (path[0] != '/') path = "/" + path;
    String out;
    for (unsigned i = 0; i < path.length(); i++) {
        char c = path[i];
        if (isAlphaNumeric(c) || c == '/' || c == '-' || c == '_' || c == '.') out += c;
    }
    if (out.length() < 2) return "/stream";   // "/" allein reicht nicht
    return out;
}

void loadCameraConfig() {
    preferences.begin("camera", true);

    String maxName = preferences.getString(
        "max",
        CAMERA_DEFAULT_MAX_SIZE_NAME
    );

    String startSize = preferences.getString("size", "svga");

    cameraTargetFps = preferences.getInt("fps", CAMERA_DEFAULT_TARGET_FPS);
    cameraCurrentQuality = preferences.getInt("quality", 12);
    cameraBufferQuality = preferences.getInt("bufq", 0);
    multiStreamEnabled = preferences.getBool("multi", CAMERA_DEFAULT_MULTI_STREAM);
    streamEnabled = preferences.getBool("strm", true);
    streamKey = preferences.getString("strmkey", "");
    // Sicherheits-Bootstrap: der Stream (Port 81, MJPEG + H.264) war ab Werk OHNE Schluessel offen --
    // auf einem Geraet mit oeffentlicher IPv4 ein Kamera-Leak. Wurde noch nie ein Schluessel gesetzt
    // (Werkszustand), einen zufaelligen erzeugen; er steht unter Server > Video > Stream. Wer den
    // Stream bewusst offen will, speichert dort einen leeren Schluessel (Flag bleibt gesetzt).
    if (!preferences.getBool("strmkeyset", false)) {
        char k[17];
        snprintf(k, sizeof(k), "%08x%08x", (unsigned)esp_random(), (unsigned)esp_random());
        streamKey = k;
        preferences.end();                       // Load-Handle ist read-only -> kurz schreibbar oeffnen
        preferences.begin("camera", false);
        preferences.putString("strmkey", streamKey);
        preferences.putBool("strmkeyset", true);
        preferences.end();
        preferences.begin("camera", true);       // weiter lesen wie zuvor
        Serial.println("Stream-Schluessel (Werkszustand) zufaellig erzeugt -> Server > Video > Stream");
    }
    streamPort = preferences.getInt("strmport", 81);
    streamPath = preferences.getString("strmpath", "/stream");
    streamType = preferences.getString("strmtype", "http");
    if (streamType != "rtsp" && streamType != "off") streamType = "http";
    if (streamType == "http" && !streamEnabled) streamType = "off";   // Legacy: HTTP-Stream war abgeschaltet
    rtspEnabled = preferences.getBool("rtspen", false);
    rtspPort = preferences.getInt("rtspport", 554);
    rtspTransport = preferences.getString("rtsptr", "tcp");
    h264Kbit      = constrain(preferences.getInt("h264kbit", 6000), 200, 20000);
    streamDropStale = preferences.getBool("dropstale", true);
    cameraStream.setDropStale(streamDropStale);

    preferences.end();

    streamPort = sanitizeStreamPort(streamPort);
    streamPath = sanitizeStreamPath(streamPath);

    // Voller Treiberbereich 0-63, keine kuenstliche Begrenzung.
    cameraBufferQuality = constrain(cameraBufferQuality, 0, 63);
    cameraCurrentQuality = constrain(cameraCurrentQuality, 0, 63);
    cameraTargetFps = constrain(cameraTargetFps, 1, 30);

    cameraConfiguredMaxIndex = frameSizeIndexByName(maxName);
    if (cameraConfiguredMaxIndex < 0) {
        cameraConfiguredMaxIndex = frameSizeIndexByName("uxga");
    }

    // Gespeicherte Live-Startaufloesung (spaeter gegen das aktive Maximum
    // begrenzt, sobald dieses feststeht).
    cameraStartSizeIndex = frameSizeIndexByName(startSize);
    if (cameraStartSizeIndex < 0) {
        cameraStartSizeIndex = frameSizeIndexByName("svga");
    }
}


// Struktur-Konfiguration (wirkt nach Neustart): Maximalaufloesung,
// Bildpuffer-Qualitaet, Mehrfach-Stream, Stream-Aktivierung/-Schluessel.
// Nur noch VideoServer-Einstellungen (max/bufq wandern ueber PATCH /dev/camera0 in denselben
// "camera"-Namespace). Bewusst getrennte Funktion = getrennte Verantwortung.
void saveVideoServerConfig(
    bool allowMultiStream,
    bool enableStream,
    const String& key,
    int port,
    const String& path
) {
    preferences.begin("camera", false);
    preferences.putBool("multi", allowMultiStream);
    preferences.putBool("strm", enableStream);
    preferences.putString("strmkey", key);
    preferences.putBool("strmkeyset", true);   // bewusste Nutzerwahl (auch leer = offen) -> kein Auto-Schluessel mehr
    preferences.putInt("strmport", port);
    preferences.putString("strmpath", path);
    preferences.end();
}


// Live-Werte (Aufloesung, fps, Qualitaet) persistieren, damit die
// Start-Einstellungen einen Neustart ueberdauern. Aufruf nur bei
// abgeschlossener Aenderung (change), nicht bei jedem Slider-Schritt.
void persistLiveCameraValues() {
    preferences.begin("camera", false);
    preferences.putString("size", FRAME_SIZE_OPTIONS[cameraCurrentIndex].name);
    preferences.putInt("fps", cameraTargetFps);
    preferences.putInt("quality", cameraCurrentQuality);
    preferences.putBool("dropstale", streamDropStale);
    preferences.end();
}


// Legacy-DVP-Pinbelegung. TOTER CODE (kein Aufrufer mehr -- der DVP-Init lebt in
// Esp32S3DvpCamera). Bleibt fuer den S3-Build erhalten, aber auf dem P4 gibt es
// weder camera_config_t noch CAM_PIN_* -> board-bedingt ausklammern. Ohne Kamera-Baustein
// (WEIRDOS_FEATURE_CAMERA=0) liefert camera_compat.h nur den P4-Shim -> ebenfalls raus.
#if WEIRDOS_FEATURE_CAMERA && !defined(CONFIG_IDF_TARGET_ESP32P4)
void fillCameraPins(camera_config_t& config) {
    config.ledc_channel = LEDC_CHANNEL_0;
    config.ledc_timer = LEDC_TIMER_0;

    config.pin_d0 = CAM_PIN_D0;
    config.pin_d1 = CAM_PIN_D1;
    config.pin_d2 = CAM_PIN_D2;
    config.pin_d3 = CAM_PIN_D3;
    config.pin_d4 = CAM_PIN_D4;
    config.pin_d5 = CAM_PIN_D5;
    config.pin_d6 = CAM_PIN_D6;
    config.pin_d7 = CAM_PIN_D7;

    config.pin_xclk = CAM_PIN_XCLK;
    config.pin_pclk = CAM_PIN_PCLK;
    config.pin_vsync = CAM_PIN_VSYNC;
    config.pin_href = CAM_PIN_HREF;

    config.pin_sccb_sda = CAM_PIN_SIOD;
    config.pin_sccb_scl = CAM_PIN_SIOC;

    config.pin_pwdn = CAM_PIN_PWDN;
    config.pin_reset = CAM_PIN_RESET;

    config.xclk_freq_hz = 20000000;
    config.pixel_format = PIXFORMAT_JPEG;
    config.grab_mode = CAMERA_GRAB_LATEST;
    config.fb_location = CAMERA_FB_IN_PSRAM;

    // Der Bildpuffer wird fuer diese Qualitaet dimensioniert. 0 = groesster
    // Puffer -> jede Live-Qualitaet passt hinein (kein Ueberlauf).
    config.jpeg_quality = cameraBufferQuality;
}
#endif  // !CONFIG_IDF_TARGET_ESP32P4  (Legacy-DVP-Pins, auf P4 raus)


// Initialisiert die Kamera mit der Aufloesung des angegebenen
// Tabellenindex, inklusive Sensorabstimmung und Selbsttest ueber den
// DVP-Datenpfad. Bei Fehlschlag wird sauber deinitialisiert.
bool tryCameraInit(int maxIndex) {
    // Start-Aufloesung: gespeicherter Live-Wert, nie ueber dem Maximum.
    int startIndex = cameraStartSizeIndex;

    if (startIndex > maxIndex || startIndex < 0) {
        startIndex = (frameSizeIndexByName("svga") <= maxIndex)
            ? frameSizeIndexByName("svga")
            : maxIndex;
    }

    // Init ueber die Kamera-Abstraktion (Pins/OV3660-Tuning/DVP-Selbsttest im
    // Device). Puffer mit bufferQuality dimensioniert, Live-Qualitaet separat ->
    // kein Ueberlauf bei kleinerer Live-Qualitaet.
    CameraManager::Config cfg;
    cfg.frameSize     = (uint16_t)FRAME_SIZE_OPTIONS[startIndex].size;
    cfg.maxFrameSize  = (uint16_t)FRAME_SIZE_OPTIONS[maxIndex].size;
    cfg.width         = (uint16_t)FRAME_SIZE_OPTIONS[startIndex].width;   // P4-MIPI
    cfg.height        = (uint16_t)FRAME_SIZE_OPTIONS[startIndex].height;  // P4-MIPI
    cfg.jpegQuality   = (uint8_t)cameraCurrentQuality;   // LIVE
    cfg.bufferQuality = (uint8_t)cameraBufferQuality;    // Puffer (0 = groesster)
    cfg.fbCount       = (uint8_t)cameraFbCount;

    if (!cameraManager.begin(cfg)) {
        Serial.print("Camera init failed at max ");
        Serial.println(FRAME_SIZE_OPTIONS[maxIndex].name);
        return false;
    }

    // P4: der HW-Encoder hat einen eigenen (bandbreitenfreundlichen) Default. Den UI-Slider
    // darauf synchronisieren, statt den S3-Quality-Default aufzuzwingen -> der Slider zeigt
    // beim Boot den echten Encoder-Wert; danach halten PATCH /dev/camera0 beide im Gleichlauf.
    if (cameraManager.qualityRuntimeSettable()) cameraCurrentQuality = cameraManager.jpegQualityUi();

    cameraCurrentIndex = startIndex;

    Serial.print("Camera init OK, max ");
    Serial.print(FRAME_SIZE_OPTIONS[maxIndex].name);
    Serial.print(", start ");
    Serial.println(FRAME_SIZE_OPTIONS[startIndex].name);

    return true;
}


void initializeCamera() {
    // Ohne PSRAM wird die Kamera gar nicht erst initialisiert: Jede
    // JPEG-Aufloesung ab VGA braucht neben dem WLAN-Stack mehr Speicher,
    // als das interne DRAM hergibt - der DRAM-Pfad des Treibers stuerzt
    // auf dem ESP32-S3 mit einem xQueueSemaphoreTake-Assert ab. Ob PSRAM
    // verfuegbar ist, entscheidet die IDE-Einstellung zur Compile-Zeit;
    // die Firmware kann es nur feststellen und melden.
    if (!psramFound()) {
        Serial.println("PSRAM disabled or not found - camera stays OFF.");
        Serial.println("Enable Tools -> PSRAM -> 'OPI PSRAM' and reflash.");
        Serial.println("WiFi portal and all other functions remain available.");
        return;
    }

    loadCameraConfig();

    int maxIndex = cameraConfiguredMaxIndex;
    size_t freePsram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);

    // Speicherbudget: Aufloesung hat Vorrang vor fps. Zuerst wird die
    // Bufferzahl reduziert (kostet Bildrate), erst danach die Aufloesung.
    cameraFbCount = 2;

    while (cameraFbCount > 1
        && cameraFbCount * estimateJpegFrameBytes(maxIndex)
            + CAMERA_PSRAM_RESERVE_BYTES > freePsram) {
        cameraFbCount--;

        Serial.println(
            "PSRAM budget: reducing frame buffers to 1"
            " (resolution takes priority over fps)."
        );
    }

    while (maxIndex > 0
        && estimateJpegFrameBytes(maxIndex)
            + CAMERA_PSRAM_RESERVE_BYTES > freePsram) {
        maxIndex--;

        Serial.print("PSRAM budget: reducing max resolution to ");
        Serial.println(FRAME_SIZE_OPTIONS[maxIndex].name);
    }

    Serial.print("PSRAM budget: ");
    Serial.print(cameraFbCount * estimateJpegFrameBytes(maxIndex));
    Serial.print(" bytes estimated for ");
    Serial.print(cameraFbCount);
    Serial.print(" buffer(s) at ");
    Serial.print(FRAME_SIZE_OPTIONS[maxIndex].name);
    Serial.print(", ");
    Serial.print(freePsram);
    Serial.println(" bytes free.");

    bool initialized = tryCameraInit(maxIndex);

    // Automatischer Rueckfall: Schlaegt die Initialisierung oder der
    // Selbsttest oberhalb von UXGA fehl, wird der erprobte Referenzpfad
    // (UXGA) versucht, damit das Geraet nutzbar bleibt.
    int uxgaIndex = frameSizeIndexByName("uxga");

    if (!initialized && maxIndex > uxgaIndex) {
        Serial.println("Falling back to UXGA (proven reference path).");

        maxIndex = uxgaIndex;
        initialized = tryCameraInit(maxIndex);
    }

    if (!initialized) {
        Serial.println("Camera could not be initialized, camera stays OFF.");
        return;
    }

    cameraActiveMaxIndex = maxIndex;
    cameraReady = true;

    // Verteiler startklar machen (Mutex idempotent) + Startrate uebernehmen.
    cameraStream.begin();
    cameraStream.setTargetFps(cameraTargetFps);

    Serial.print("Camera initialized (OV3660), max resolution: ");
    Serial.print(FRAME_SIZE_OPTIONS[cameraActiveMaxIndex].name);
    Serial.print(", target fps: ");
    Serial.println(cameraTargetFps);
}




// -----------------------------------------------------------------------------
// AP-Lebenszyklus und Erreichbarkeit im Zielnetz
// -----------------------------------------------------------------------------

#if WEIRDOS_FEATURE_WIFI
void startMdns() {
    if (mdnsStarted) {
        return;
    }
    // mDNS (<name>.local) wirkt nur im lokalen Funknetz; ohne WLAN-Stack nur Socket-Verbrauch.
    if (!wifiStackActive()) { Serial.println("[Netz] mDNS uebersprungen: kein WLAN-Stack."); return; }

    if (MDNS.begin(deviceHostname.c_str())) {
        MDNS.addService("http", "tcp", 80);
        mdnsStarted = true;

        Serial.print("mDNS started: http://");
        Serial.print(deviceHostname);
        Serial.println(".local");
    } else {
        Serial.println("mDNS could not be started.");
    }
}
#endif // WEIRDOS_FEATURE_WIFI (mDNS)


// Praeferenz "AP dauerhaft an" aus dem NVS laden/speichern.
void loadApPreference() {
    preferences.begin("wifi", true);
    keepApAlways = preferences.getBool("keepap", KEEP_AP_DEFAULT);
    setupApPassword = preferences.getString("appass", CONFIG_AP_PASSWORD);
    preferences.end();

    // Treat corrupt/legacy short passwords as open instead of passing an
    // invalid WPA2 key to WiFi.softAP().
    if (setupApPassword.length() > 0 && setupApPassword.length() < 8) {
        setupApPassword = "";
    }
}


void saveApPreference(bool keep) {
    preferences.begin("wifi", false);
    preferences.putBool("keepap", keep);
    preferences.end();

    keepApAlways = keep;
}


// Startet den Setup-AP (4.3.2.1, DHCP-DNS, DNS-Hijack). Idempotent.
void startSetupAp() {
    if (setupApActive) {
        return;
    }
    // Ohne laufenden WLAN-Stack gibt es keinen AP -- und der Versuch waere fatal: WiFi.softAP()
    // initialisiert auf dem P4 lazy den ESP-Hosted-SDIO-Transport (~150 KB intern) -> Assert ->
    // Reboot. Genau das war der 30-s-Reboot-Zyklus (Setup-AP-Automatik bei "kein WAN").
    if (!wifiStackActive()) {
        static bool warned = false;
        if (!warned) { warned = true; logEvent("Setup-AP nicht gestartet: kein WLAN-Stack (kein Funk / LAN > WLAN aus)"); }
        return;
    }
#if WEIRDOS_FEATURE_WIFI
    startAccessPoint();
    configureSoftApDhcp();
    startDnsServer();

    setupApActive = true;

    Serial.println("Setup AP active (WiFi configuration).");
#endif   // ohne WLAN-Baustein ist wifiStackActive() immer false -> oben schon zurueck
}


// Schaltet den Setup-AP ab. Das Geraet bleibt ueber das Zielnetz erreichbar.
void stopSetupAp() {
    if (!setupApActive) {
        return;
    }
#if !WEIRDOS_FEATURE_WIFI
    setupApActive = false;   // WLAN nicht im Build: nie ein AP gelaufen -> nur Flag
    return;
#else
    dnsSocket.stop();
    if (!wifiStackActive()) { setupApActive = false; return; }   // nie ein AP gelaufen -> nur Flag
    WiFi.softAPdisconnect(true);

    if (wifiState == PORTAL_WIFI_CONNECTED) {
        WiFi.mode(WIFI_STA);
    }

    setupApActive = false;

    Serial.println("Setup AP disabled.");

    if (wifiState == PORTAL_WIFI_CONNECTED) {
        Serial.print("Device reachable at http://");
        Serial.print(WiFi.localIP());
        Serial.print(" and http://");
        Serial.print(DEVICE_HOSTNAME);
        Serial.println(".local");
    }
#endif // WEIRDOS_FEATURE_WIFI
}


// Ist IRGENDEIN WAN-Pfad da? WLAN-Zielnetz verbunden ODER Modem-Datenpfad (ECM/PPP) oben.
// Bewusst link-basiert (nicht der flappende Internet-Check) -> stabile AP-Entscheidung.
bool wanPresent() {
    if (wifiState == PORTAL_WIFI_CONNECTED) return true;   // WLAN erreicht das Zielnetz
    NetIface ni;
    if (netInterfaceById("modem-ecm", ni) && ni.up) return true;  // Modem-Internet (ECM)
    if (netInterfaceById("modem-ppp", ni) && ni.up) return true;  // Modem-Internet (PPP)
    return false;   // reiner Modembetrieb ohne Link zaehlt NICHT als WAN -> Portal traegt
}

// Bringt den AP in Einklang mit Praeferenz, Verbindungszustand UND Captive-Sicherung:
//   - "AP dauerhaft an": AP laeuft immer.
//   - Captive-Modus "auto": AP wird ERZWUNGEN, solange kein WAN erreichbar ist
//     (Lockout-Schutz; deckt jetzt auch reinen Modembetrieb ab, nicht nur WLAN).
//   - Captive-Modus "off": AP wird nie erzwungen (bewusst, Warnung in der UI) ->
//     bei fehlendem WAN nur noch ueber den Werksreset-Taster erreichbar.
void applyApPolicy() {
    bool captiveNeeded = setupCaptiveAuto() && !wanPresent();

    // HINWEIS: die frueher hier erzwungene AP-Rolle (Lokaler AP/Gateway/Repeater) ist bewusst
    // ENTFERNT -- sie hat den Setup-AP (mit DNS-Hijack) mitten in einer aktiven WLAN-STA-
    // Verbindung hochgezogen und das Geraet destabilisiert. Die echte AP-Rolle (Service-AP OHNE
    // Captive-Redirect + NAPT) kommt als eigener, hardware-getesteter Slice. Bis dahin ist die
    // Assistent-Modusauswahl rein gespeichert (kein Laufzeiteingriff) -- wie der heutige Default.
    if (keepApAlways || captiveNeeded) {
        if (!setupApActive) {
            startSetupAp();
        }
        return;
    }

    // Weder Dauer-AP noch Captive noetig -> WAN uebernimmt die Erreichbarkeit, AP kann weg.
    if (setupApActive) {
        stopSetupAp();
    }
}


// Werksreset "nur Netzwerk/Zugang": WLAN-Creds, WAN-Policy, Betriebsart/LAN, Captive/Reset.
// Kamera, PIN, VPN (ipsec/wg), DynDNS bleiben erhalten. Danach kommt das Geraet als Setup-AP hoch.
void factoryResetNetwork() {
    const char* ns[] = { "wifi", "wanpol", "netmode", "setup" };
    for (unsigned i = 0; i < sizeof(ns) / sizeof(ns[0]); i++) {
        preferences.begin(ns[i], false);
        preferences.clear();
        preferences.end();
    }
    Serial.println("Factory reset (network/access): wifi/wanpol/netmode/setup cleared.");
    pendingRestartAt = millis() + 1500;   // erst Serial flushen lassen, dann Neustart (loop)
}

// Werksreset "ALLES" (Stufe 2): kompletter NVS-Wipe inkl. PIN, Kamera, VPN, Einstellungen.
// Loescht die gesamte NVS-Partition -> Auslieferungszustand. Danach Neustart.
void factoryResetFull() {
    Serial.println("Factory reset (FULL): erasing entire NVS (PIN + all settings).");
    Serial.flush();
    nvs_flash_erase();   // ganze Default-NVS-Partition loeschen
    nvs_flash_init();    // neu initialisieren, damit der Boot danach sauber laeuft
    pendingRestartAt = millis() + 1000;
}

// Periodischer Einrichtungs-Tick: (1) Werksreset ueber BOOT-Taste (GPIO0, N s halten),
// (2) AP/Captive-Policy neu bewerten -- Modem/WLAN aendern sich unabhaengig voneinander.
void setupGuardTick() {
    static uint32_t lastEval = 0;
    static uint32_t pressStart = 0;
    static bool     wasPressed = false;
    uint32_t now = millis();

    const SetupGuardConfig& sg = setupGuardGet();
    // Zweistufiger Werksreset ueber die BOOT-Taste:
    //   Stufe 1 (>= resetHoldMs): nur Netzwerk/Zugang.
    //   Stufe 2 (>= fullHoldMs, wenn aktiviert): kompletter Wipe inkl. PIN.
    // Die oberste konfigurierte Stufe loest SOFORT aus (laenger halten bringt nichts).
    // Eine tiefere Stufe loest beim LOSLASSEN aus (damit man Stufe 2 noch erreichen kann).
    if (sg.resetEnabled) {
        bool pressed = (digitalRead(FACTORY_RESET_PIN) == LOW);   // BOOT gedrueckt = LOW
        if (pressed) {
            if (pressStart == 0) pressStart = now;
            uint32_t held = now - pressStart;
            if (sg.fullEnabled && held >= sg.fullHoldMs) {
                factoryResetFull();       // oberste Stufe -> sofort
                pressStart = 0;
            } else if (!sg.fullEnabled && held >= sg.resetHoldMs) {
                factoryResetNetwork();    // Stufe 1 ist oberste Stufe -> sofort
                pressStart = 0;
            }
        } else {
            if (wasPressed && pressStart != 0) {   // gerade losgelassen -> tiefere Stufe pruefen
                uint32_t held = now - pressStart;
                if (sg.fullEnabled && held >= sg.resetHoldMs && held < sg.fullHoldMs) {
                    factoryResetNetwork();  // 20-40 s gehalten -> nur Netzwerk
                }
            }
            pressStart = 0;
        }
        wasPressed = pressed;
    } else {
        pressStart = 0;
        wasPressed = false;
    }

    // AP/Captive periodisch neu bewerten -- ABER erst nach einer Boot-Schonfrist. Waehrend des
    // ersten Verbindungsaufbaus regeln die event-getriebenen applyApPolicy()-Aufrufe (wie bisher);
    // das verhindert ein kurzes AP-Aufflackern, bis WLAN/Modem beim Boot oben sind.
    if (now >= 30000 && now - lastEval >= 2000) {   // start/stopSetupAp sind idempotent
        lastEval = now;
        applyApPolicy();
    }
}


// -----------------------------------------------------------------------------
// HTTP-Server
// -----------------------------------------------------------------------------

// g_web (WeirdHttpEsp) ist oben im globalen Zustand definiert (muss vor loop() sichtbar sein).
// Forward-Decls der migrierten Handler (Definition weiter unten).
void handleDevIndex(WeirdHttpRequest&, WeirdHttpResponse&);
void handleDevDescriptor(WeirdHttpRequest&, WeirdHttpResponse&);
void handleDevPatch(WeirdHttpRequest&, WeirdHttpResponse&);
void handleModemConnect(WeirdHttpRequest&, WeirdHttpResponse&);
void handleModemDisconnect(WeirdHttpRequest&, WeirdHttpResponse&);
void handleModemReset(WeirdHttpRequest&, WeirdHttpResponse&);
void handleModemSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleDatalinkSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleModemBandSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleModemTest(WeirdHttpRequest&, WeirdHttpResponse&);
void handleSpeedtestStart(WeirdHttpRequest&, WeirdHttpResponse&);
void handleBandScanStart(WeirdHttpRequest&, WeirdHttpResponse&);
void handleModemStatusJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleModemLog(WeirdHttpRequest&, WeirdHttpResponse&);
void handleModemUsbInfo(WeirdHttpRequest&, WeirdHttpResponse&);
void handleModemAt(WeirdHttpRequest&, WeirdHttpResponse&);
void handleSimPinManage(WeirdHttpRequest&, WeirdHttpResponse&);
void handleDiagSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleModemInfo(WeirdHttpRequest&, WeirdHttpResponse&);
void handleModemJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleNeighbours(WeirdHttpRequest&, WeirdHttpResponse&);
void handleWgSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleWgConnect(WeirdHttpRequest&, WeirdHttpResponse&);
void handleWgDisconnect(WeirdHttpRequest&, WeirdHttpResponse&);
void handleWgStatusJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleVpnStatusJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleWgClientGen(WeirdHttpRequest&, WeirdHttpResponse&);
void handleWgClientsJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleWgClientDel(WeirdHttpRequest&, WeirdHttpResponse&);
void handleDiagWgRoute(WeirdHttpRequest&, WeirdHttpResponse&);
void handleDiagWgUnderlay(WeirdHttpRequest&, WeirdHttpResponse&);
void handleIpsecSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleIpsecConnect(WeirdHttpRequest&, WeirdHttpResponse&);
void handleIpsecDisconnect(WeirdHttpRequest&, WeirdHttpResponse&);
void handleIpsecStatusJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleIpsecPing(WeirdHttpRequest&, WeirdHttpResponse&);
void handleIpsecCertInfo(WeirdHttpRequest&, WeirdHttpResponse&);
void handleIpsecPingHistoryJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleIpsecPingHistoryDel(WeirdHttpRequest&, WeirdHttpResponse&);
void handleIpsecUserAdd(WeirdHttpRequest&, WeirdHttpResponse&);
void handleIpsecUserDel(WeirdHttpRequest&, WeirdHttpResponse&);
void handleDyndnsSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleDyndnsStatusJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleDyndnsUpdate(WeirdHttpRequest&, WeirdHttpResponse&);
void handleNetInterfacesJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleDiagEgressTest(WeirdHttpRequest&, WeirdHttpResponse&);
void handleOpmodeSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleWizardSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleLanGeneralSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleWlanApChannelSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleWanForwardingSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleSetupPortalSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleUartSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleRestartRequiredJson(WeirdHttpRequest&, WeirdHttpResponse&);   // gelbe Box: Neustart noetig? (Poll)
void handleUsbDevSave(WeirdHttpRequest&, WeirdHttpResponse&);            // USB-Geraet (UVC) konfigurieren
void handleUsbPortsSave(WeirdHttpRequest&, WeirdHttpResponse&);          // USB-Port-Mapping (Anzahl, Pins, Namen)
void handlePlatformSave(WeirdHttpRequest&, WeirdHttpResponse&);          // Board-Profil
void handlePlatformJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handlePinoutSvg(WeirdHttpRequest&, WeirdHttpResponse&);
void handlePlatformConfigJson(WeirdHttpRequest&, WeirdHttpResponse&);    // Plattform-Konfiguration exportieren (JSON)
void handlePlatformImport(WeirdHttpRequest&, WeirdHttpResponse&);        // ... importieren (JSON-Body)
void handlePlatformSvgSave(WeirdHttpRequest&, WeirdHttpResponse&);       // eigenes Pinout-SVG speichern/loeschen (Body = SVG)
void handleUsbPortsJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleUsbDevJson(WeirdHttpRequest&, WeirdHttpResponse&);            // USB-Geraet Status
void handleRestartNow(WeirdHttpRequest&, WeirdHttpResponse&);            // Knopf "Jetzt neu starten"
void handleLogout(WeirdHttpRequest&, WeirdHttpResponse&);
void handleWanPolicySave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleWanPolicyJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleWanStatusJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleNetScanStart(WeirdHttpRequest&, WeirdHttpResponse&);
void handleNetScanJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleNetPing(WeirdHttpRequest&, WeirdHttpResponse&);
void handleNetPortScanStart(WeirdHttpRequest&, WeirdHttpResponse&);
void handleNetPortScanJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleNetSniffStart(WeirdHttpRequest&, WeirdHttpResponse&);
void handleNetSniffJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleNetChScanStart(WeirdHttpRequest&, WeirdHttpResponse&);
void handleNetChScanJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleNetDeepChStart(WeirdHttpRequest&, WeirdHttpResponse&);
void handleNetDeepChJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleBtScanStart(WeirdHttpRequest&, WeirdHttpResponse&);
void handleBtScanJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleBtStatusJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleBtConnect(WeirdHttpRequest&, WeirdHttpResponse&);
void handleBtRelease(WeirdHttpRequest&, WeirdHttpResponse&);
void handleWifiScan(WeirdHttpRequest&, WeirdHttpResponse&);
void handleStatusJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleSysinfoJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleEventsJson(WeirdHttpRequest&, WeirdHttpResponse&);
void handleSettingsExport(WeirdHttpRequest&, WeirdHttpResponse&);
void handlePeriphRescan(WeirdHttpRequest&, WeirdHttpResponse&);
void handleWebWanSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleAccessSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleWebTransportSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleAcmeSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleAcmeRun(WeirdHttpRequest&, WeirdHttpResponse&);
void handleAcmeClear(WeirdHttpRequest&, WeirdHttpResponse&);
void handleCertSave(WeirdHttpRequest&, WeirdHttpResponse&);       // Zertifikatsherkunft (self/upload/acme) waehlen
void handleCertUpload(WeirdHttpRequest&, WeirdHttpResponse&);     // eigenes Zertifikat + Schluessel hinterlegen
void handleCertSelfsign(WeirdHttpRequest&, WeirdHttpResponse&);   // self-signed neu erzeugen
void handleCertInfo(WeirdHttpRequest&, WeirdHttpResponse&);       // Quelle/Subjects/Ablaeufe fuer die UI
void handleAcmeStatus(WeirdHttpRequest&, WeirdHttpResponse&);
void handleAcmeChallenge(WeirdHttpRequest&, WeirdHttpResponse&);
void handleHttpToHttpsRedirect(WeirdHttpRequest&, WeirdHttpResponse&);
void handleApSecuritySave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleSaveCredentials(WeirdHttpRequest&, WeirdHttpResponse&);
void handleForget(WeirdHttpRequest&, WeirdHttpResponse&);
void handleEnergySave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleGeneralSave(WeirdHttpRequest&, WeirdHttpResponse&);
void handleRedirectProbe(WeirdHttpRequest&, WeirdHttpResponse&);
void handleUnknownRequest(WeirdHttpRequest&, WeirdHttpResponse&);
void handleVideoConfig(WeirdHttpRequest&, WeirdHttpResponse&);

void startWebServer() {
    // Header-Sammeln entfaellt: der esp_http_server-Adapter liest jeden Header direkt
    // (EspRequest::header via httpd_req_get_hdr_value_str). Kein collectHeaders noetig.

    // Einzige sichtbare Seite ist "/": PIN-Gate oder Tab-Oberflaeche,
    // in AP und Zielnetz identisch. Alles Uebrige sind unsichtbare
    // Form-/AJAX-Ziele.
    // MIGRIERT auf WeirdHttp (Root/PIN/UI-Block): Root ist selbst-gated (WAN+Session),
    // pin-login PUBLIC (nie requireSession), pin-change prueft Auth selbst (403-Text).
    g_web.route(HttpMethod::GET,  "/",           handleRootPage);
    g_web.route(HttpMethod::POST, "/pin-login",  handlePinLogin);
    g_web.route(HttpMethod::POST, "/pin-change", handlePinChange);
    g_web.route(HttpMethod::POST, "/logout",     requireSession(handleLogout, AuthFail::Page));   // Sidebar "Abmelden"
    g_web.route(HttpMethod::POST, "/wanweb-save",      requireSession(handleWebWanSave,     AuthFail::Json));
    g_web.route(HttpMethod::POST, "/access-save",      requireSession(handleAccessSave,     AuthFail::Json));   // Zugriff je Dienst
    g_web.route(HttpMethod::POST, "/web-transport-save", requireSession(handleWebTransportSave, AuthFail::Json));  // HTTP<->HTTPS
    // ACME / Let's Encrypt (System > Sicherheit > Zertifikat). Die Challenge-Route ist PUBLIC (Let's
    // Encrypt hat keine Session) -- im HTTP-Betrieb liegt sie hier auf :80, im HTTPS-Betrieb auf g_web80.
#if WEIRDOS_FEATURE_ACME
    g_web.route(HttpMethod::POST, "/acme-save",         requireSession(handleAcmeSave,   AuthFail::Json));
    g_web.route(HttpMethod::POST, "/acme-run",          requireSession(handleAcmeRun,    AuthFail::Json));
    g_web.route(HttpMethod::POST, "/acme-clear",        requireSession(handleAcmeClear,  AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/acme-status.json",  requireSession(handleAcmeStatus, AuthFail::Json));
#endif // WEIRDOS_FEATURE_ACME
#if WEIRDOS_FEATURE_TLS_SERVER
    g_web.route(HttpMethod::POST, "/cert-save",         requireSession(handleCertSave,     AuthFail::Json));
    g_web.route(HttpMethod::POST, "/cert-upload",       requireSession(handleCertUpload,   AuthFail::Json));
    g_web.route(HttpMethod::POST, "/cert-selfsign",     requireSession(handleCertSelfsign, AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/cert-info.json",    requireSession(handleCertInfo,     AuthFail::Json));
#endif // WEIRDOS_FEATURE_TLS_SERVER
#if WEIRDOS_FEATURE_ACME
    g_web.route(HttpMethod::GET,  "/.well-known/acme-challenge/{token}", handleAcmeChallenge);
#endif // WEIRDOS_FEATURE_ACME
#if WEIRDOS_FEATURE_WIFI
    g_web.route(HttpMethod::POST, "/ap-security-save", requireSession(handleApSecuritySave, AuthFail::Json));
#endif
    // /capture: neutraler WeirdHttp-Handler ueber cameraManager/FrameSource (kein esp_camera-Legacy).
#if WEIRDOS_FEATURE_CAMERA
    // Einzelbild gehoert zur KAMERA (billig, kein eigener Server) -- nicht zum MJPEG-Streamserver:
    // auch ein RTSP-only-Geraet soll Snapshots liefern (RTSP kennt keine Einzelbilder).
    g_web.route(HttpMethod::GET, "/capture", requireSession(handleCaptureFrame, AuthFail::Json));
#endif
    // Diagnose: EIN roher ISP-Frame -> HW-H.264-Encoder -> JSON-Report. Beweist die Kamera->Encoder-
    // Pipeline auf echter Hardware, bevor Transport (fMP4/RTSP) existiert. Stream muss dabei aus sein.
#if WEIRDOS_FEATURE_H264
    g_web.route(HttpMethod::GET, "/h264probe", requireSession(handleH264Probe, AuthFail::Json));
#endif
    // Heap-Test/Steuerung fuer die hohe H.264-Aufloesung: Boot-Guard setzen (?bootkb=N) + Live-Test
    // (?test=1: Guard freigeben -> 720p/FHD-hw_new probieren -> wieder reservieren).
#if WEIRDOS_FEATURE_H264
    g_web.route(HttpMethod::GET, "/h264guard", requireSession(handleH264Guard, AuthFail::Json));
#endif
    // Heap-Map (Diagnose): aggregierte Zahlen + Boot-Zeitleiste, siehe handleHeapMap().
    g_web.route(HttpMethod::GET, "/heapmap", requireSession(handleHeapMap, AuthFail::Json));
    // Isolierter PPA-Test: synthetisches Bild -> PPA-Skalierung -> misst gefuellte Geometrie (Diagnose).
#if WEIRDOS_FEATURE_H264
    g_web.route(HttpMethod::GET, "/ppatest", requireSession(handlePpaTest, AuthFail::Json));
#endif
    g_web.route(HttpMethod::POST, "/video-config", requireSession(handleVideoConfig, AuthFail::Page));   // VideoServer-Config (HTML-Bestaetigung)
    // Geraete-Namespace (Linux-/dev-artig): EIN generischer Capability-API fuer alle Geraete.
    // MIGRIERT auf WeirdHttp (Batch 1): Auth in requireSession-Middleware, Handler (req,res).
    g_web.route(HttpMethod::GET,  "/dev",                requireSession(handleDevIndex,      AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/dev/{device}",       requireSession(handleDevDescriptor, AuthFail::Json));
    g_web.route(HttpMethod::PATCH, "/dev/{device}",      requireSession(handleDevPatch,      AuthFail::Json));   // Resource-API: mode/fps/quality
    // MIGRIERT auf WeirdHttp (Batch 2): generische Sensor-Parameter.
#if WEIRDOS_FEATURE_WIFI
    g_web.route(HttpMethod::POST, "/save",   requireSession(handleSaveCredentials, AuthFail::Page));   // HTML-Bestaetigung (WLAN-Zugangsdaten/AP/Stack)
#endif
    g_web.route(HttpMethod::POST, "/forget", requireSession(handleForget,          AuthFail::Page));   // Werksreset (HTML)
    // SECURITY-AUDIT (Phase 8): /scan + /status.json werden AUSSCHLIESSLICH von der
    // post-auth App gerufen (APP_SCRIPT bzw. WLAN-Panel); die statische PIN-Gate holt
    // NICHTS. Fuer Captive-Setup/Login ohne Auth NICHT noetig -> Management-Auth.
    // (Bei deaktivierter PIN liefert WeirdAuth::authorized ohnehin true -> Setup bleibt offen.)
#if WEIRDOS_FEATURE_WIFI
    g_web.route(HttpMethod::GET, "/scan",        requireSession(handleWifiScan,   AuthFail::Json));
#endif
    g_web.route(HttpMethod::GET, "/status.json", requireSession(handleStatusJson, AuthFail::Json));   // bleibt auch ohne WIFI (WLAN-Felder dann leer/0)
#if WEIRDOS_FEATURE_WIFI
    g_web.route(HttpMethod::GET, "/captive-api", handleCaptiveApi);   // PUBLIC by design: RFC 8908 / Browser-HTML (Captive-Erkennung)
#endif

#if WEIRDOS_FEATURE_MODEM
    // Mobilfunk-Modem (USB + PPP): Einstellungen + Aktionen (AJAX/JSON).
    // MIGRIERT (Batch 3, Modem): Save/Datalink/Band.
    g_web.route(HttpMethod::POST, "/modem-save",      requireSession(handleModemSave,     AuthFail::Json));
    g_web.route(HttpMethod::POST, "/modem-datalink",  requireSession(handleDatalinkSave,  AuthFail::Json));   // Datenschicht PPP<->ECM
    g_web.route(HttpMethod::POST, "/modem-band-save", requireSession(handleModemBandSave, AuthFail::Json));
    // MIGRIERT auf WeirdHttp (Batch 3, Modem-Actions):
    g_web.route(HttpMethod::POST, "/modem-connect",    requireSession(handleModemConnect,    AuthFail::Json));
    g_web.route(HttpMethod::POST, "/modem-disconnect", requireSession(handleModemDisconnect, AuthFail::Json));
    g_web.route(HttpMethod::POST, "/modem-reset",      requireSession(handleModemReset,      AuthFail::Json));
    g_web.route(HttpMethod::POST, "/modem-rate-reset", requireSession([](WeirdHttpRequest&, WeirdHttpResponse& res){  // Online-Monitor: Peak (Max) zuruecksetzen
        modemRateResetMax();
        res.sendJson("{\"ok\":true}");
    }, AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/modem-test",           requireSession(handleModemTest,     AuthFail::Json));
    g_web.route(HttpMethod::POST, "/speedtest-start",      requireSession(handleSpeedtestStart, AuthFail::Json));
    g_web.route(HttpMethod::POST, "/modem-bandscan-start", requireSession(handleBandScanStart, AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/modem-neighbours",     requireSession(handleNeighbours,    AuthFail::Json));
    g_web.route(HttpMethod::POST, "/sim-pin",              requireSession(handleSimPinManage,  AuthFail::Json));   // SIM-PIN-Sperre an/aus/aendern/Status
#endif // WEIRDOS_FEATURE_MODEM
    g_web.route(HttpMethod::GET, "/sysinfo.json", requireSession(handleSysinfoJson, AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/restart-required.json", requireSession(handleRestartRequiredJson, AuthFail::Json));   // gelbe Box (Poll)
    g_web.route(HttpMethod::POST, "/restart",               requireSession(handleRestartNow, AuthFail::Json));            // "Jetzt neu starten"
    g_web.route(HttpMethod::POST, "/usbdev-save",           requireSession(handleUsbDevSave, AuthFail::Page));            // Einrichtung > Setup > USB-Geraet (wirkt nach Neustart)
    g_web.route(HttpMethod::GET,  "/usbdev.json",           requireSession(handleUsbDevJson, AuthFail::Json));            // Status UVC (Host/Stream/Frames)
    g_web.route(HttpMethod::POST, "/usbports-save",         requireSession(handleUsbPortsSave, AuthFail::Page));          // USB-Port-Mapping des Boards (wirkt nach Neustart)
    g_web.route(HttpMethod::GET,  "/usbports.json",         requireSession(handleUsbPortsJson, AuthFail::Json));          // Mapping + Chip-Paare
    g_web.route(HttpMethod::POST, "/platform-save",         requireSession(handlePlatformSave, AuthFail::Page));          // Einrichtung > Plattform: Board-Profil
    g_web.route(HttpMethod::GET,  "/platform.json",         requireSession(handlePlatformJson, AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/platform-config.json",  requireSession(handlePlatformConfigJson, AuthFail::Json));    // Export (Struct als JSON)
    g_web.route(HttpMethod::POST, "/platform-import",       requireSession(handlePlatformImport, AuthFail::Json));        // Import (JSON-Body)
    g_web.route(HttpMethod::POST, "/platform-svg",          requireSession(handlePlatformSvgSave, AuthFail::Json));       // eigenes Pinout (SVG-Body)
    g_web.route(HttpMethod::GET,  "/pinout.svg",            requireSession(handlePinoutSvg, AuthFail::Page));             // generiertes Pinout-Bild
    g_web.route(HttpMethod::GET, "/events.json",  requireSession(handleEventsJson,  AuthFail::Json));
    g_web.route(HttpMethod::GET, "/banner.png", handleBannerPng);   // binaere Resource, neutral (Chunked)
    // App-Assets als gecachte Dateien (URL mit ?v=Asset-Hash): CSS+JS nicht mehr in jeder Seite inline.
    g_web.route(HttpMethod::GET, "/app.css", [](WeirdHttpRequest& req, WeirdHttpResponse& res) { if (weirdReqWanDenied(req)) { res.send(403, "text/plain", "-"); return; } sendAppCss(res); });
    g_web.route(HttpMethod::GET, "/app.js",  [](WeirdHttpRequest& req, WeirdHttpResponse& res) { if (weirdReqWanDenied(req)) { res.send(403, "text/plain", "-"); return; } sendAppJs(res); });
#if WEIRDOS_FEATURE_BACKUP
    g_web.route(HttpMethod::GET, "/settings-export", requireSession(handleSettingsExport, AuthFail::Json));
    g_web.routeUpload(HttpMethod::POST, "/settings-import", handleSettingsImportUpload, handleSettingsImportFinish);
#endif // WEIRDOS_FEATURE_BACKUP
    g_web.route(HttpMethod::POST, "/periph-rescan", requireSession(handlePeriphRescan, AuthFail::Json));  // USB-Host on-demand
#if WEIRDOS_FEATURE_OTA
    g_web.routeUpload(HttpMethod::POST, "/ota-update", handleOtaUpload, handleOtaFinish);
#endif // WEIRDOS_FEATURE_OTA
    g_web.route(HttpMethod::GET, "/modem-status.json", requireSession(handleModemStatusJson, AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/modem-log",     requireSession(handleModemLog,     AuthFail::Json));
#if WEIRDOS_FEATURE_MODEM
    g_web.route(HttpMethod::GET,  "/modem-usbinfo", requireSession(handleModemUsbInfo, AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/modem-at",      requireSession(handleModemAt,      AuthFail::Json));
#endif // WEIRDOS_FEATURE_MODEM
    g_web.route(HttpMethod::POST, "/diag-save",     requireSession(handleDiagSave,     AuthFail::Json));   // Entwickler-Diagnose an/aus
#if WEIRDOS_FEATURE_MODEM
    g_web.route(HttpMethod::GET,  "/modem-info",    requireSession(handleModemInfo,    AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/modem-json",    requireSession(handleModemJson,    AuthFail::Json));
#endif // WEIRDOS_FEATURE_MODEM
    // MIGRIERT (Batch 6, DynDNS/Netz-Diag):
#if WEIRDOS_FEATURE_DYNDNS
    g_web.route(HttpMethod::POST, "/dyndns-save",         requireSession(handleDyndnsSave,        AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/dyndns-status.json",  requireSession(handleDyndnsStatusJson,  AuthFail::Json));
#endif // WEIRDOS_FEATURE_DYNDNS
    g_web.route(HttpMethod::GET,  "/net-interfaces.json", requireSession(handleNetInterfacesJson, AuthFail::Json));
#if WEIRDOS_FEATURE_ROUTER
    g_web.route(HttpMethod::GET,  "/zones-plan.json",     requireSession(handleZonesPlanJson, AuthFail::Json));   // Netzzonen 0.2: Planner-Vorschau (read-only)
    g_web.route(HttpMethod::GET,  "/zones.json",          requireSession(handleZonesJson, AuthFail::Json));       // Netzzonen 0.5: Policies + Plaene + installierter Zustand
    g_web.route(HttpMethod::POST, "/zones-policy",        requireSession(handleZonesPolicy, AuthFail::Json));     // Netzzonen Phase 1: Verbindung erlauben/trennen (dieselben Intents wie 'zones policy')
#endif
    g_web.route(HttpMethod::GET,  "/diag-egress-test",    requireSession(handleDiagEgressTest,    AuthFail::Json));
    // MIGRIERT (Batch 4, WireGuard):
    g_web.route(HttpMethod::GET,  "/diag-wg-underlay", requireSession(handleDiagWgUnderlay, AuthFail::Json));
    g_web.route(HttpMethod::POST, "/wg-save",          requireSession(handleWgSave,         AuthFail::Json));
    g_web.route(HttpMethod::POST, "/wg-connect",       requireSession(handleWgConnect,      AuthFail::Json));
    g_web.route(HttpMethod::POST, "/wg-disconnect",    requireSession(handleWgDisconnect,   AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/wg-status.json",   requireSession(handleWgStatusJson,   AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/vpn-status.json",  requireSession(handleVpnStatusJson,  AuthFail::Json));   // Uebersicht: alle Tunnel
    g_web.route(HttpMethod::POST, "/wg-client-gen",    requireSession(handleWgClientGen,    AuthFail::Json));   // 7.4d.4: Client-Config + QR
    g_web.route(HttpMethod::GET,  "/wg-clients.json",  requireSession(handleWgClientsJson,  AuthFail::Json));   // 7.9.2: Client-Liste
    g_web.route(HttpMethod::GET,  "/diag-wg-route",    requireSession(handleDiagWgRoute,    AuthFail::Json));   // 7.9.4: Rueckweg-Routing-Diagnose
    g_web.route(HttpMethod::POST, "/ipsec-save", requireSession(handleIpsecSave, AuthFail::Json));   // 8.1: IPsec-Config speichern
    // MIGRIERT (Batch 7, WAN/LAN/Setup). Form-POSTs = Page-Redirect (AuthFail::Page -> "/"
    // rendert PIN-Gate); *.json-Status sind PUBLIC (waren vorher ohne Auth) -> ohne requireSession.
    g_web.route(HttpMethod::POST, "/opmode-save",         requireSession(handleOpmodeSave,        AuthFail::Page));   // (Alt) Betriebsart
    g_web.route(HttpMethod::POST, "/wizard-save",         requireSession(handleWizardSave,        AuthFail::Page));   // Assistent
    g_web.route(HttpMethod::POST, "/lan-general-save",    requireSession(handleLanGeneralSave,    AuthFail::Page));   // LAN > Allgemein
    g_web.route(HttpMethod::POST, "/wlan-apchannel-save", requireSession(handleWlanApChannelSave, AuthFail::Page));   // AP-Kanal
    g_web.route(HttpMethod::POST, "/wan-forwarding-save", requireSession(handleWanForwardingSave, AuthFail::Page));   // Forwarding/NAPT
    g_web.route(HttpMethod::POST, "/setup-portal-save",   requireSession(handleSetupPortalSave,   AuthFail::Page));   // Setup > WLAN-Portal
    g_web.route(HttpMethod::POST, "/uart-save",           requireSession(handleUartSave,          AuthFail::Page));   // Setup > UART (Baudrate)
    g_web.route(HttpMethod::POST, "/wan-policy-save",     requireSession(handleWanPolicySave,     AuthFail::Page));   // WAN-Uplink
    // SECURITY-AUDIT (Phase 8): beide werden nur von der post-auth App gepollt
    // (wan-status.json <- Uebersicht; wan-policy.json hat gar keinen JS-Aufrufer).
    // Kein Captive-/Login-Bedarf ohne Auth -> Management-Auth (frueher faelschlich PUBLIC).
    g_web.route(HttpMethod::GET,  "/wan-policy.json",     requireSession(handleWanPolicyJson, AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/wan-status.json",     requireSession(handleWanStatusJson, AuthFail::Json));
    g_web.route(HttpMethod::POST, "/ipsec-connect",     requireSession(handleIpsecConnect,    AuthFail::Json));
    g_web.route(HttpMethod::POST, "/ipsec-disconnect",  requireSession(handleIpsecDisconnect, AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/ipsec-status.json", requireSession(handleIpsecStatusJson, AuthFail::Json));
    g_web.route(HttpMethod::POST, "/ipsec-ping",        requireSession(handleIpsecPing,       AuthFail::Json));   // 8.2e: Diagnose-Tunnel-Ping
    g_web.route(HttpMethod::POST, "/ipsec-certinfo",    requireSession(handleIpsecCertInfo,   AuthFail::Json));   // Trust-Modell: Zertifikatsinfo je PEM-Block
    g_web.route(HttpMethod::GET,  "/ipsec-ping-history.json", requireSession(handleIpsecPingHistoryJson, AuthFail::Json));   // Dropdown: letzte Ziele (NVS)
    g_web.route(HttpMethod::POST, "/ipsec-ping-history",      requireSession(handleIpsecPingHistoryDel,  AuthFail::Json));   // del=<ziel> (SHIFT+ENTF)
    g_web.route(HttpMethod::POST, "/ipsec-user-add",    requireSession(handleIpsecUserAdd,    AuthFail::Json));   // Server-Rolle: Benutzer
    g_web.route(HttpMethod::POST, "/ipsec-user-del",    requireSession(handleIpsecUserDel,    AuthFail::Json));
    // MIGRIERT (Batch 8, Netz-Scan):
#if WEIRDOS_FEATURE_NETSCAN
    g_web.route(HttpMethod::POST, "/net-scan-start",     requireSession(handleNetScanStart,     AuthFail::Json));  // 7.10: LAN-Host-Scan
    g_web.route(HttpMethod::GET,  "/net-scan.json",      requireSession(handleNetScanJson,      AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/net-ping",           requireSession(handleNetPing,          AuthFail::Json));  // 7.10: Einzel-Ping
    g_web.route(HttpMethod::GET,  "/net-scan-targets.json", requireSession(handleNetScanTargetsJson, AuthFail::Json)); // D1: Sweep-Ziele aus der Registry
    g_web.route(HttpMethod::GET,  "/net-resolve",        requireSession(handleNetResolve,       AuthFail::Json));  // D1: Routing-Befund (lokal + optional Forward-Policy)
    g_web.route(HttpMethod::POST, "/net-portscan-start", requireSession(handleNetPortScanStart, AuthFail::Json));  // 7.11: TCP-Port-Scan
    g_web.route(HttpMethod::GET,  "/net-portscan.json",  requireSession(handleNetPortScanJson,  AuthFail::Json));
    g_web.route(HttpMethod::POST, "/net-sniff-start",    requireSession(handleNetSniffStart,    AuthFail::Json));  // 7.13: Passiv-Monitor
    g_web.route(HttpMethod::GET,  "/net-sniff.json",     requireSession(handleNetSniffJson,     AuthFail::Json));
    g_web.route(HttpMethod::POST, "/net-chscan-start",   requireSession(handleNetChScanStart,   AuthFail::Json));  // 7.14: Kanal-Uebersicht
    g_web.route(HttpMethod::GET,  "/net-chscan.json",    requireSession(handleNetChScanJson,    AuthFail::Json));
    g_web.route(HttpMethod::POST, "/net-deepch-start",   requireSession(handleNetDeepChStart,   AuthFail::Json));  // 7.15: Tiefen-Kanal-Scan
    g_web.route(HttpMethod::GET,  "/net-deepch.json",    requireSession(handleNetDeepChJson,    AuthFail::Json));
#endif // WEIRDOS_FEATURE_NETSCAN
#if WEIRDOS_HAS_BT
    g_web.route(HttpMethod::POST, "/bt-scan-start",  requireSession(handleBtScanStart,  AuthFail::Json));   // 8.0: BLE-Geraetesuche
    g_web.route(HttpMethod::GET,  "/bt-scan.json",   requireSession(handleBtScanJson,   AuthFail::Json));
    g_web.route(HttpMethod::GET,  "/bt-status.json", requireSession(handleBtStatusJson, AuthFail::Json));
    g_web.route(HttpMethod::POST, "/bt-connect",     requireSession(handleBtConnect,    AuthFail::Json));   // best-effort BLE
    g_web.route(HttpMethod::POST, "/bt-release",     requireSession(handleBtRelease,    AuthFail::Json));
#endif
    g_web.route(HttpMethod::POST, "/wg-client-del", requireSession(handleWgClientDel, AuthFail::Json));   // 7.9.2: Client entfernen
#if WEIRDOS_FEATURE_DYNDNS
    g_web.route(HttpMethod::POST, "/dyndns-update", requireSession(handleDyndnsUpdate, AuthFail::Json));
#endif // WEIRDOS_FEATURE_DYNDNS
    g_web.route(HttpMethod::POST, "/energy-save",  requireSession(handleEnergySave,  AuthFail::Json));
    g_web.route(HttpMethod::POST, "/general-save",  requireSession(handleGeneralSave, AuthFail::Json));

#if WEIRDOS_FEATURE_WIFI
    registerCaptivePortalEndpoints();

    g_web.onNotFound(handleUnknownRequest);   // Captive-Fallback: unbekannte Route -> Portal (public)
#endif   // ohne WLAN-Baustein kein Captive-Portal -> Adapter-Default 404 fuer unbekannte Routen

    // Socket-Budget: der Browser haelt ~6 Keep-alive-Verbindungen UND die App-Seite pollt
    // an ~6 Stellen alle 2-3 s. Bei 7 Sockets + lru_purge wird bei der naechsten Verbindung
    // die least-recently-used geschlossen -> potenziell eine AKTIVE Browser-Verbindung mitten
    // im Request ("Menue-Klick haengt"). 10 gibt genug Headroom (LWIP-Budget 16; der
    // Stream-Server auf Port 81 belegt seine eigenen nur bei aktivem Stream).
    // KORREKTUR (Hardware-Spur 2026-09-03, 'sockets'): 10 passt NICHT ins lwIP-Budget von 16 --
    // 8 Keep-alive-Verbindungen eines Browsers + 2x Listen + 2x Steuersocket + IKE-UDP + ESP-RAW +
    // 2 UDP = 16 -> Tabelle voll, socket() = ENFILE, KEIN neuer Zugriff mehr (auch nicht aus dem
    // VPN). Mit 5 greift lru_purge, bevor die Tabelle voll ist; Budget: Web 5+2, Stream 2+2, IKE 1,
    // ESP-RAW 1, 2 UDP (mDNS) = 15 -> 1 Reserve fuer DynDNS/DNS/Diagnose. Dauerhafte Loesung:
    // CONFIG_LWIP_MAX_SOCKETS in den eigenen esp32p4_es-libs anheben (Rebuild).
    g_web.setMaxOpenSockets(5);

    // Management-Transport: HTTPS (443) wenn konfiguriert, sonst HTTP (80). Der Cert wird
    // einmal pro Boot self-signed erzeugt (spaeter ACME). g_managementSecure steuert das
    // Secure-Cookie + die Transportwechsel-Invalidierung.
    if (webHttpsEnabled) {
        // EINE Quelle der Wahrheit: cert_store waehlt nach der vom Benutzer gesetzten Herkunft
        // (self-signed / eigenes Zertifikat / Let's Encrypt) und faellt notfalls auf self-signed zurueck.
        static String s_certPem, s_keyPem; String srcText;
        if (certResolveActive(s_certPem, s_keyPem, srcText)) {
            g_web.configure(443, true);
            g_web.useTlsCert(s_certPem, s_keyPem);
            Serial.printf("TLS: %s\n", srcText.c_str());
        } else {
            Serial.printf("TLS: %s -> Fallback auf HTTP:80.\n", srcText.length() ? srcText.c_str() : "Zertifikat-Erzeugung fehlgeschlagen");
            webHttpsEnabled = false;
        }
    }
    g_managementSecure = webHttpsEnabled;
    g_web.begin();

    // Sicherheitsnetz: startet HTTPS nicht (z.B. Cert/Heap/Socket), NICHT den Zugang
    // verlieren -> auf HTTP:80 zurueckfallen. Der P4 ist nur ueber LTE erreichbar.
    if (!g_web.running() && webHttpsEnabled) {
        Serial.printf("HTTPS control-plane FAILED (err=0x%x) -> Fallback HTTP:80\n", (unsigned)g_web.lastError());
        webHttpsEnabled = false; g_managementSecure = false;
        g_web.configure(80, false);
        g_web.begin();
    }

    // Cookie-Name folgt dem ENDGUELTIGEN Transport (nach HTTP-Fallback): "__Secure-xcauth" bei
    // HTTPS, "xcauth" bei HTTP -- siehe weird_auth.cpp (Chrome laesst Secure-Cookies nicht von HTTP
    // ueberschreiben; sonst haengt man nach dem Rueckschalten in der PIN-Maske fest).
    WeirdAuth::setTransportSecure(g_managementSecure);
    if (g_web.running())
        Serial.printf("Control-plane (esp_http_server) started on :%d (%s).\n",
                      g_web.isTls() ? 443 : 80, g_web.isTls() ? "HTTPS" : "HTTP");

    // Port 80 neben HTTPS: ACME-Challenge (Let's Encrypt prueft IMMER ueber http://<domain>:80) +
    // 301-Redirect auf https://. Ohne diesen Listener waere Port 80 bei HTTPS-Betrieb tot und
    // ein Let's-Encrypt-Bezug unmoeglich.
    // NUR wenn Let's Encrypt aktiviert ist: der Hilfsserver kostet ~10 KB internen Heap (Stack +
    // httpd), und mit HTTPS + Video-Reserve ist der P4 am Limit (Boot 64k frei / 30k am Stueck ->
    // PPP-Start scheiterte stumm). Ohne ACME gibt es auf Port 80 nichts zu beantworten.
#if WEIRDOS_FEATURE_ACME
    if (g_web.running() && g_web.isTls() && acmeConfig().enabled) {
        g_web80.setCtrlPort(32772);
        g_web80.setStackSize(6144);
        g_web80.setMaxOpenSockets(3);
        g_web80.route(HttpMethod::GET, "/.well-known/acme-challenge/{token}", handleAcmeChallenge);
        g_web80.onNotFound(handleHttpToHttpsRedirect);
        g_web80.begin();
        Serial.printf("Port-80-Hilfsserver (ACME-Challenge + Redirect auf HTTPS): %s\n",
                      g_web80.running() ? "laeuft" : "NICHT gestartet");
    }
    else
#endif // WEIRDOS_FEATURE_ACME
    if (!g_web.running())   // vorher stand hier ein nacktes else: "FAILED" auch bei laufendem HTTP-Server (irrefuehrend)
        Serial.printf("Control-plane FAILED to start (err=0x%x)\n", (unsigned)g_web.lastError());
}


#if WEIRDOS_FEATURE_WIFI
void registerCaptivePortalEndpoints() {
    // SECURITY-AUDIT (Phase 8): ALLE Routen hier bleiben BEWUSST public (kein
    // requireSession). Sie sind reine OS-Konnektivitaets-/Captive-Probes (Android 204,
    // Apple CNA HTML, Windows NCSI) -- Auth wuerde die Captive-Erkennung zerstoeren.
    // Sie leaken keine Management-Daten (Redirect bzw. Portal-/PIN-Seite). Ebenso
    // public: onNotFound (Captive-Fallback), / (selbst-gated), /pin-login, /captive-api.
    // Android erwartet HTTP 204. Jede Abweichung loest die Portalerkennung aus,
    // ein 302 auf die Portalseite ist hier der zuverlaessigste Weg.
    // MIGRIERT: Redirect-Probes public via g_web (KEIN requireSession -> OS-Probes ohne Session).
    g_web.route(HttpMethod::GET, "/generate_204", handleRedirectProbe);
    g_web.route(HttpMethod::GET, "/gen_204",      handleRedirectProbe);
    g_web.route(HttpMethod::GET, "/generate204",  handleRedirectProbe);

    // Apple: Der CNA folgt Redirects teilweise nicht zuverlaessig. Die Portalseite direkt
    // mit HTTP 200 ausliefern (rendert sendAppPage/sendPinGate), KEIN 302, KEIN Auth-Guard.
    g_web.route(HttpMethod::GET, "/hotspot-detect.html",         handleDirectPortalProbe);
    g_web.route(HttpMethod::GET, "/library/test/success.html",   handleDirectPortalProbe);

    // Windows NCSI.
    g_web.route(HttpMethod::GET, "/connecttest.txt", handleRedirectProbe);
    g_web.route(HttpMethod::GET, "/ncsi.txt",        handleRedirectProbe);
    g_web.route(HttpMethod::GET, "/redirect",        handleRedirectProbe);

    // Weitere verbreitete Konnektivitaetspruefungen.
    g_web.route(HttpMethod::GET, "/canonical.html", handleRedirectProbe);
    g_web.route(HttpMethod::GET, "/success.txt",    handleRedirectProbe);
}


void handleRedirectProbe(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    logHttpRequest(req, "Captive portal probe");
    // Public + verhaltenskompatibel (OS-Probes kommen ohne Session) -> KEIN requireSession.
    String location = "http://"; location += WiFi.softAPIP().toString(); location += "/";
    resNoCache(res);
    res.redirect(location, 302);
}


void handleDirectPortalProbe(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    logHttpRequest(req, "Captive portal probe (direct)");

    // Apple/OS-Probe: Portalseite DIREKT mit HTTP 200 ausliefern (kein 302, kein
    // Auth-Guard). Auth entscheidet nur, OB App oder PIN-Gate gerendert wird.
    if (WeirdAuth::authorized(req.cookie(WeirdAuth::cookieName()), weirdReqIsWan(req.clientIp())))
        sendAppOrPinSetup(res);
    else
        sendPinGate(res, false);
}


void handleUnknownRequest(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    logHttpRequest(req, "Unknown request");
    String location = "http://"; location += WiFi.softAPIP().toString(); location += "/";
    resNoCache(res);
    res.redirect(location, 302);
}
#endif // WEIRDOS_FEATURE_WIFI (Captive-Probes + Captive-Fallback)


// ENTFERNT mit dem WeirdHttpEsp-Flip: redirectToConfigurationPage() (unbenutzt),
// sendNoCacheHeaders() (durch resNoCache(res) ersetzt) und die server-basierte
// logHttpRequest(const String&)-Ueberladung. Es bleibt nur noch die neutrale
// logHttpRequest(WeirdHttpRequest&, const String&) -- kein globaler server-Zugriff.


// Backend-neutrale Variante fuer die migrierten WeirdHttp-Handler: liest aus der
// Anfrage statt aus dem globalen `server` (Ziel: die HTML-Control-Plane braucht
// keinen Arduino-WebServer-Zugriff mehr). Nutzt nur garantiert gesammelte Header.
void logHttpRequest(WeirdHttpRequest& req, const String& type) {
    Serial.print(type);
    Serial.print(": From="); Serial.print(req.clientIp());
    String host = req.header("Host");
    Serial.print(" Host="); Serial.print(host.length() ? host : String("<unknown>"));
    Serial.print(" URI=");  Serial.print(req.path());
    String ua = req.header("User-Agent");
    Serial.print(" UA=");   Serial.println(ua.length() ? ua : String("<unknown>"));
}


// -----------------------------------------------------------------------------
// Captive Portal API (RFC 8908)
// -----------------------------------------------------------------------------

#if WEIRDOS_FEATURE_WIFI
void handleCaptiveApi(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    logHttpRequest(req, "Captive portal API");

    // Ein echter RFC-8908-Client sendet Accept: application/captive+json.
    // Ein Browser sendet text/html und wuerde die JSON-Antwort als unbekannten
    // Dateityp herunterladen. Deshalb Content-Negotiation statt fester Antwort.
    String accept = req.header("Accept");

    bool wantsHtml =
        accept.indexOf("text/html") >= 0
        && accept.indexOf("captive+json") < 0;

    if (wantsHtml) {
        Serial.println("Captive portal API requested by a browser, serving HTML.");

        if (WeirdAuth::authorized(req.cookie(WeirdAuth::cookieName()), weirdReqIsWan(req.clientIp())))
            sendAppOrPinSetup(res);
        else
            sendPinGate(res, false);
        return;
    }

    // Der SoftAP routet nicht zur Station: es gibt kein NAT zwischen
    // WIFI_AP_DEF und WIFI_STA_DEF. Ein Client im Setup-AP hat deshalb auch
    // bei stehender STA-Verbindung keinen Internetzugang. Das Netz bleibt
    // damit dauerhaft captive.
    //
    // Fuer ein spaeteres Produkt waere der saubere Weg, den AP nach
    // erfolgreicher Konfiguration abzuschalten, statt seinen Zustand
    // gegenueber dem Client umzudeuten.
    bool captive = true;

    String json = "{";

    json += "\"captive\":";
    json += captive ? "true" : "false";

    json += ",\"user-portal-url\":\"http://";
    json += WiFi.softAPIP().toString();
    json += "/\"";

    json += "}";

    resNoCache(res);
    res.send(200, "application/captive+json", json);
}
#endif // WEIRDOS_FEATURE_WIFI (Captive-API)


// -----------------------------------------------------------------------------
// WLAN-Verbindung als nichtblockierende State Machine
// Baustein WIFI: ohne WLAN-Funk bleibt wifiState fuer immer PORTAL_WIFI_IDLE
// (wifiStateName()/wifiStatusText()/wifiPortalConnected() bleiben ungegated).
// -----------------------------------------------------------------------------
#if WEIRDOS_FEATURE_WIFI

void beginWifiConnection() {
    if (!wifiStackActive()) { wifiState = PORTAL_WIFI_IDLE; return; }   // kein Stack -> WiFi.begin() wuerde ESP-Hosted lazy initialisieren
    if (!hasWifiCredentials()) {
        wifiState = PORTAL_WIFI_IDLE;
        return;
    }

    Serial.print("Connecting to WiFi: ");
    Serial.println(configuredSsid);

    // AP_STA nur, wenn der AP gerade laeuft; sonst reine Station.
    WiFi.mode(setupApActive ? WIFI_AP_STA : WIFI_STA);
    WiFi.setAutoReconnect(true);

    WiFi.disconnect(
        false,
        false
    );

    WiFi.begin(
        configuredSsid.c_str(),
        configuredPassword.c_str()
    );

    wifiState = PORTAL_WIFI_CONNECTING;
    wifiAttemptStartedAt = millis();
    wifiLastAttemptAt = millis();
}


void updateWifiConnection() {
    switch (wifiState) {
        case PORTAL_WIFI_CONNECTING:
            if (WiFi.status() == WL_CONNECTED) {
                wifiState = PORTAL_WIFI_CONNECTED;

                startMdns();

                if (cameraReady) {
                    startVideoTransport();
                    // beginTls() bewusst NICHT mehr automatisch (s. Boot-Pfad): Phase-1-PoC, vom UI
                    // ungenutzt, kostet 20 KB internen Stack + TCP 443 + Control-Port.
                }

                Serial.println("WiFi connection established.");

                Serial.print("Station IP: ");
                Serial.println(WiFi.localIP());

                // AP an Praeferenz anpassen: bei Erfolg abschalten, sofern
                // nicht "AP dauerhaft an" gewaehlt wurde.
                applyApPolicy();
                break;
            }

            if (millis() - wifiAttemptStartedAt >= WIFI_CONNECT_TIMEOUT_MS) {
                wifiState = PORTAL_WIFI_FAILED;

                WiFi.disconnect(false, false);

                Serial.println("WiFi connection failed.");

                // Zielnetz nicht erreichbar: AP als Einrichthilfe starten.
                applyApPolicy();
            }

            break;

        case PORTAL_WIFI_CONNECTED:
            if (WiFi.status() != WL_CONNECTED) {
                Serial.println("WiFi connection lost, reconnecting.");

                wifiState = PORTAL_WIFI_CONNECTING;
                wifiAttemptStartedAt = millis();

                // Waehrend des Reconnects den AP als Rueckfallebene anbieten.
                applyApPolicy();
            }

            break;

        case PORTAL_WIFI_FAILED:
            if (millis() - wifiLastAttemptAt >= WIFI_RETRY_INTERVAL_MS) {
                beginWifiConnection();
            }

            break;

        case PORTAL_WIFI_IDLE:
        default:
            break;
    }

    // Ein waehrend des Verbindungsaufbaus angeforderter Scan wird nachgeholt.
    if (scanRequested && wifiState != PORTAL_WIFI_CONNECTING) {
        scanRequested = false;
        startWifiScan();
    }
}

#endif // WEIRDOS_FEATURE_WIFI (STA-State-Machine)


const char* wifiStateName() {
    switch (wifiState) {
        case PORTAL_WIFI_CONNECTING:
            return "connecting";

        case PORTAL_WIFI_CONNECTED:
            return "connected";

        case PORTAL_WIFI_FAILED:
            return "failed";

        default:
            return "idle";
    }
}


// -----------------------------------------------------------------------------
// Asynchroner WLAN-Scan mit Ergebnis-Cache (Baustein WIFI, samt /scan-Handler)
// -----------------------------------------------------------------------------
#if WEIRDOS_FEATURE_WIFI

void requestWifiScan() {
    if (!wifiStackActive()) return;   // kein Stack -> WiFi.scanNetworks() wuerde ESP-Hosted lazy initialisieren
    if (wifiState == PORTAL_WIFI_CONNECTING) {
        scanRequested = true;
        return;
    }

    startWifiScan();
}


void startWifiScan() {
    if (scanState == PORTAL_SCAN_RUNNING) {
        return;
    }

    Serial.println("Starting asynchronous WiFi scan.");

    int16_t result = WiFi.scanNetworks(
        true,
        false
    );

    if (result == WIFI_SCAN_FAILED) {
        scanState = PORTAL_SCAN_FAILED;
        Serial.println("WiFi scan could not be started.");
        return;
    }

    scanState = PORTAL_SCAN_RUNNING;
    scanStartedAt = millis();
}


void updateWifiScan() {
    if (scanState != PORTAL_SCAN_RUNNING) {
        return;
    }

    int16_t result = WiFi.scanComplete();

    if (result == WIFI_SCAN_RUNNING) {
        if (millis() - scanStartedAt >= SCAN_TIMEOUT_MS) {
            WiFi.scanDelete();

            scanState = PORTAL_SCAN_FAILED;
            Serial.println("WiFi scan timed out.");
        }

        return;
    }

    if (result == WIFI_SCAN_FAILED) {
        scanState = PORTAL_SCAN_FAILED;
        Serial.println("WiFi scan failed.");
        return;
    }

    cacheScanResults(result);

    WiFi.scanDelete();

    scanState = PORTAL_SCAN_DONE;
    scanCompletedAt = millis();

    Serial.print("WiFi scan completed. Unique networks: ");
    Serial.println(cachedNetworkCount);
}


void cacheScanResults(int networkCount) {
    cachedNetworkCount = 0;

    for (int i = 0; i < networkCount; i++) {
        String ssid = WiFi.SSID(i);

        if (ssid.length() == 0) {
            continue;
        }

        int32_t rssi = WiFi.RSSI(i);
        bool secure = WiFi.encryptionType(i) != WIFI_AUTH_OPEN;

        int existing = findCachedNetwork(ssid);

        if (existing >= 0) {
            // Mehrere Accesspoints derselben SSID: staerkstes Signal gewinnt.
            if (rssi > cachedNetworks[existing].rssi) {
                cachedNetworks[existing].rssi = rssi;
                cachedNetworks[existing].secure = secure;
            }

            continue;
        }

        if (cachedNetworkCount >= MAX_CACHED_NETWORKS) {
            continue;
        }

        cachedNetworks[cachedNetworkCount].ssid = ssid;
        cachedNetworks[cachedNetworkCount].rssi = rssi;
        cachedNetworks[cachedNetworkCount].secure = secure;

        cachedNetworkCount++;
    }

    sortCachedNetworks();
}


int findCachedNetwork(const String& ssid) {
    for (int i = 0; i < cachedNetworkCount; i++) {
        if (cachedNetworks[i].ssid == ssid) {
            return i;
        }
    }

    return -1;
}


void sortCachedNetworks() {
    for (int i = 1; i < cachedNetworkCount; i++) {
        ScannedNetwork current = cachedNetworks[i];
        int j = i - 1;

        while (j >= 0 && cachedNetworks[j].rssi < current.rssi) {
            cachedNetworks[j + 1] = cachedNetworks[j];
            j--;
        }

        cachedNetworks[j + 1] = current;
    }
}


bool isScanCacheStale() {
    if (scanState != PORTAL_SCAN_DONE) {
        return true;
    }

    return (millis() - scanCompletedAt) >= SCAN_CACHE_TTL_MS;
}


void handleWifiScan(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    if (weirdReqWanDenied(req)) { res.send(403, "application/json", "{}"); return; }   // keine SSID-Liste ueber WAN
    bool forceRefresh = req.hasArg("refresh");

    if (forceRefresh || isScanCacheStale()) {
        requestWifiScan();
    }

    String json = "{";

    json += "\"scanning\":";
    json += (scanState == PORTAL_SCAN_RUNNING) ? "true" : "false";

    json += ",\"busy\":";
    json += scanRequested ? "true" : "false";

    json += ",\"networks\":";
    json += createNetworkArrayJson();

    json += "}";

    resNoCache(res);
    res.send(200, "application/json", json);
}


String createNetworkArrayJson() {
    String json = "[";

    for (int i = 0; i < cachedNetworkCount; i++) {
        if (i > 0) {
            json += ",";
        }

        json += "{\"ssid\":\"";
        json += escapeJson(cachedNetworks[i].ssid);

        json += "\",\"rssi\":";
        json += String(cachedNetworks[i].rssi);

        json += ",\"secure\":";
        json += cachedNetworks[i].secure ? "true" : "false";

        json += "}";
    }

    json += "]";

    return json;
}

#endif // WEIRDOS_FEATURE_WIFI (Scan + /scan)


// -----------------------------------------------------------------------------
// Konfigurationsseite
// -----------------------------------------------------------------------------

// Root ist zustandsabhaengig: Vor der Konfiguration das Setup-Formular
// (Captive-Portal-Flow), nach erfolgreichem Connect die Kamera-Ansicht.
// Einzige sichtbare Seite - in AP und Zielnetz identisch.
// Ohne gueltige Authentifizierung erscheint das PIN-Gate, danach die
// Tab-Oberflaeche (Video + Konfiguration).
// /banner.png: Brand-Banner als binaere Resource (separat gecacht, NICHT als Data-URI
// in jeder Seite). Neutral ueber WeirdHttp (Chunked-Binary) statt Arduino-server.send_P
// -> laeuft auf beiden Adaptern. Cache-Header (1 Woche, immutable) bleibt erhalten.
void handleBannerPng(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    res.header("Cache-Control", "public, max-age=604800, immutable");
    if (res.beginChunked(200, "image/png")) {
        res.write((const char*)LOGO_BANNER_PNG, LOGO_BANNER_PNG_LEN);
        res.end();
    }
}


// /capture: EIN JPEG-Einzelbild als Snapshot ueber den ZENTRALEN Verteiler
// (CameraStreamService) -- KEIN zweiter direkter cameraManager.acquireFrame()-Besitzer.
// Der Distributor capturt die Kamera genau einmal in einen gemeinsamen PSRAM-Puffer;
// hier melden wir uns kurz als Client an und ziehen den neuesten Frame per copyLatest.
// So gibt es keine Frame-Arbitrierung zwischen Snapshot und laufendem MJPEG-Stream --
// beide Konsumenten haengen am selben Verteiler (Snapshot ist nur ein weiterer Consumer).
void handleCaptureFrame(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    logHttpRequest(req, "Capture");

    if (!cameraManager.isReady()) {
        res.send(503, "text/plain; charset=utf-8", "Kamera nicht initialisiert.");
        return;
    }

    // Beim Verteiler anmelden -> Capture-Task laeuft (oder laeuft schon fuer den Stream).
    // Dann auf einen frischen Frame warten (Task-Anlauf + erste Capture), ~2 s Timeout.
    cameraStream.addClient();
    uint8_t* buf = nullptr; size_t cap = 0; uint32_t seq = 0; size_t len = 0;
    for (int i = 0; i < 40 && len == 0; i++) {
        len = cameraStream.copyLatest(&buf, &cap, &seq);   // waechst buf (PSRAM) selbst
        if (len == 0) vTaskDelay(pdMS_TO_TICKS(50));
    }
    cameraStream.removeClient();

    if (len == 0) {
        if (buf) heap_caps_free(buf);
        res.send(503, "text/plain; charset=utf-8", "Kein Bild von der Kamera erhalten.");
        return;
    }

    // Der Verteiler publiziert ausschliesslich JPEG -> kein Formatzweig noetig.
    resNoCache(res);
    if (res.beginChunked(200, "image/jpeg")) {
        res.write((const char*)buf, len);
        res.end();
    }
    heap_caps_free(buf);
}

// /h264probe: EIN roher ISP-Frame -> HW-H.264-Encoder -> Report (Format/NAL-Groesse/Keyframe).
// Das ist der Hardware-Test der Kamera->Encoder-Verdrahtung (Phase 2), BEVOR ein Transport
// (fMP4/MSE, RTSP) existiert: hier sieht man empirisch, ob der HW-Encoder den echten Kamera-Frame
// frisst und wie klein das H.264-NAL gegenueber dem Rohbild ist. Voraussetzung: MJPEG-Stream AUS
// (sonst ist der einzige Kamera-Puffer belegt -> "kein Rohframe"). Begin/Encode/End pro Aufruf
// (Diagnose ist selten) -> kein Dauerzustand, kein Heap gehalten.
void handleH264Probe(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    logHttpRequest(req, "H264-Probe");
    if (!cameraManager.isReady())   { res.sendJson("{\"ok\":false,\"error\":\"Kamera nicht bereit\"}"); return; }
    if (!H264Encoder::hwAvailable()) { res.sendJson("{\"ok\":false,\"error\":\"kein HW-H.264-Encoder\"}"); return; }

    // Aufloesung vom aktiven Modus (unabhaengig davon, ob wir einen Rohframe kriegen).
    uint16_t w = 800, h = 800;
    cameraManager.currentMode(w, h);

    // Interner DMA-Heap ZUERST (vor den Scan-Allokationen) -> zeigt das echte Budget. Der HW-Encoder
    // braucht interne Referenz-/Rekonstruktionsframes; -3 (MEM) heisst: passt nicht in diesen Heap.
    String j = "{\"w\":"; j += w; j += ",\"h\":"; j += h;
    j += ",\"intFree\":";    j += (uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    j += ",\"intLargest\":"; j += (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);

    // ---- Was kann der ISP/V4L2 ausgeben? (FourCC) -> kann er YUV420 (YU12/NV12) direkt liefern,
    // dann brauche ich fuer H.264 KEINE Farbkonversion. ----
    {
        uint32_t fcc[16]; int nf = cameraManager.enumPixelFormats(fcc, 16);
        j += ",\"ispFormats\":[";
        for (int i = 0; i < nf; i++) {
            if (i) j += ",";
            char c[5] = { (char)(fcc[i] & 0xff), (char)((fcc[i] >> 8) & 0xff),
                          (char)((fcc[i] >> 16) & 0xff), (char)((fcc[i] >> 24) & 0xff), 0 };
            j += "\""; j += c; j += "\"";
        }
        j += "]";
    }

    // ---- Format-Scan bei (w,h): welches Roh-Eingabeformat akzeptiert hw_new (ARG-Ebene)? ----
    j += ",\"formats\":[";
    int fc = H264Encoder::probeFormatCount();
    for (int i = 0; i < fc; i++) {
        const char* nm = "?";
        int e = H264Encoder::probeFormat(w, h, i, &nm);
        if (i) j += ",";
        j += "{\"name\":\""; j += nm; j += "\",\"err\":"; j += e; j += "}";
    }
    j += "]";

    // ---- Feiner Aufloesungs-Scan fuer das AKZEPTIERTE Format (O_UYY_E_VYY = idx 0): findet den
    // exakten internen-Heap-Deckel zwischen 320x240 (geht) und 480x480 (geht nicht). err 0 = passt. ----
    static const uint16_t RESW[] = {800, 640, 512, 480, 448, 416, 400, 384, 352, 320};
    static const uint16_t RESH[] = {800, 480, 512, 480, 448, 416, 400, 288, 288, 240};
    j += ",\"yuv420res\":[";
    for (int i = 0; i < 10; i++) {
        const char* nm = "?";
        int e = H264Encoder::probeFormat(RESW[i], RESH[i], 0, &nm);
        if (i) j += ",";
        j += "{\"w\":"; j += RESW[i]; j += ",\"h\":"; j += RESH[i]; j += ",\"err\":"; j += e; j += "}";
    }
    j += "]";

    // ---- ECHTE Pipeline Ende-zu-Ende: ISP-RGB565 -> PPA(YUV420) -> HW-H.264 -> NAL ----
    // Testaufloesung: die Kamera liefert nur ihren einen Modus (w x h, i.d.R. 800x800). Der HW-Encoder
    // passt bei aktuellem internem Heap aber nur bis ~320x240 -> PPA skaliert dabei gleich herunter.
    // (Sobald der interne Heap freigeraeumt ist, kann tw/th bis zur Sensor-Aufloesung / Full HD wachsen.)
    const uint16_t tw = 320, th = 240;
    CameraFrame* f = cameraManager.acquireRawFrame();
    if (!f || !f->data || f->size == 0) {
        if (f) cameraManager.releaseFrame(f);
        j += ",\"frame\":false,\"note\":\"kein Rohframe (Stream aktiv?) -> nur Scans\"}";
        res.sendJson(j);
        return;
    }
    size_t rawLen = f->size;
    j += ",\"frame\":true,\"ispPixfmt\":"; j += (int)f->pixelFormat;
    j += ",\"rawLen\":"; j += (uint32_t)rawLen;
    j += ",\"testW\":"; j += tw; j += ",\"testH\":"; j += th;

    if (f->pixelFormat != CAMERA_PIXEL_FORMAT_RGB565) {
        j += ",\"pipeOk\":false,\"stage\":\"isp\",\"note\":\"ISP nicht RGB565\"";
    } else {
        // 1) PPA: RGB565 (w x h) -> YUV420 (tw x th)
        PpaConverter ppa;
        const uint8_t* yuv = nullptr; size_t yuvLen = 0;
        bool pOk = ppa.begin() && ppa.rgb565ToYuv420(f->data, w, h, tw, th, &yuv, &yuvLen);
        j += ",\"ppaOk\":"; j += pOk ? "true" : "false"; j += ",\"yuvLen\":"; j += (uint32_t)yuvLen;
        if (!pOk) {
            j += ",\"pipeOk\":false,\"stage\":\"ppa\"";
        } else {
            // 2) HW-H.264: YUV420 (O_UYY_E_VYY) -> NAL
            H264Encoder enc;
            bool begun = enc.begin(tw, th, 15, 1500000, 15, H264PixFmt::YUV420_OUEV);
            const uint8_t* nal = nullptr; size_t nalLen = 0; bool key = false;
            bool eOk = begun && enc.encode(yuv, yuvLen, &nal, &nalLen, &key);
            j += ",\"encodeOk\":"; j += eOk ? "true" : "false";
            j += ",\"nalLen\":";   j += (uint32_t)nalLen;
            j += ",\"keyframe\":"; j += key ? "true" : "false";
            if (yuvLen && nalLen) { j += ",\"ratio\":"; j += (uint32_t)(yuvLen / nalLen); }
            if (!eOk) { j += ",\"stage\":\"encode\",\"err\":"; j += enc.lastError();
                        j += ",\"errstage\":"; j += enc.lastStage(); }
            else      { j += ",\"pipeOk\":true"; }
            enc.end();
        }
        ppa.end();
    }
    cameraManager.releaseFrame(f);
    j += "}";
    res.sendJson(j);
}


// /ppatest: PPA-Skalierung isoliert vermessen (synthetisches 800x800-Weissbild -> diagScale bei
// mehreren Zielen). filledW/filledH = tatsaechlich gefuellte Geometrie -> zeigt die PPA-Regel, ohne
// Kamera/H.264/Browser. (Ergab: Ausgabe = 50*floor(dst/50); nur 400 & 800 sind auch /16 -> sauber.)
void handlePpaTest(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    logHttpRequest(req, "PPA-Test");
    if (!PpaConverter::hwAvailable()) { res.sendJson("{\"ok\":false,\"error\":\"keine PPA\"}"); return; }
    const uint16_t SW = 800, SH = 800;
    uint8_t* synth = (uint8_t*)heap_caps_malloc((size_t)SW * SH * 2, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!synth) { res.sendJson("{\"ok\":false,\"error\":\"synth-alloc\"}"); return; }
    memset(synth, 0xFF, (size_t)SW * SH * 2);   // weiss

    String j = "{\"ok\":true,\"src\":\"800x800\",\"tests\":[";
    PpaConverter ppa;
    if (ppa.begin()) {
        static const uint16_t T[] = {800, 512, 416, 400, 384, 320, 256};
        for (int i = 0; i < 7; i++) {
            size_t wb = 0, lb = 0; uint16_t fw = 0, fh = 0;
            bool ok = ppa.diagScale(synth, SW, SH, T[i], T[i], &wb, &lb, &fw, &fh);
            if (i) j += ",";
            j += "{\"req\":"; j += T[i]; j += ",\"filledW\":"; j += fw; j += ",\"filledH\":"; j += fh;
            j += ",\"written\":"; j += (uint32_t)wb;
            j += ",\"expected\":"; j += (uint32_t)((size_t)T[i] * T[i] * 3 / 2);
            j += ",\"ok\":"; j += ok ? "true" : "false"; j += "}";
        }
        ppa.end();
    }
    j += "]}";
    heap_caps_free(synth);
    res.sendJson(j);
}

// /h264guard: Heap-Diagnose + -Steuerung fuer hohe H.264-Aufloesung.
//   ?bootkb=N  -> reserviert beim NAECHSTEN Boot N KB zusammenhaengenden internen RAM als Guard
//                 (frueh, vor HTTP/USB/PPP). 0 = aus. Danach Reboot.
//   ?test=1    -> misst hw_new bei 640/800/1280/1920 Breite im aktuellen Zustand (die Reserve ist
//                 eine exklusive Heap-Region und bleibt dabei registriert). So sieht man, ob eine
//                 Breite an der Reserve-Groesse/Fragmentierung haengt.
void handleH264Guard(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    logHttpRequest(req, "H264-Guard");

    String bk = req.arg("bootkb");
    if (bk.length() > 0) h264GuardSetConfiguredKb(bk.toInt());
    int bootKb = h264GuardConfiguredKb();

    String j = "{\"ok\":true,\"guardHeld\":"; j += h264GuardHeld() ? "true" : "false";
    j += ",\"guardKb\":";    j += (uint32_t)(h264GuardBytes() / 1024);
    j += ",\"bootKbPref\":"; j += bootKb;
    j += ",\"intFree\":";    j += (uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    j += ",\"intLargest\":"; j += (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);

    if (req.arg("test") == "1") {
        static const uint16_t TW[] = {640, 800, 1280, 1920};
        static const uint16_t TH[] = {480, 800, 720, 1080};
        j += ",\"probeHeld\":[";
        for (int i = 0; i < 4; i++) { const char* nm = "?"; int e = H264Encoder::probeFormat(TW[i], TH[i], 0, &nm);
            if (i) j += ","; j += "{\"w\":"; j += TW[i]; j += ",\"err\":"; j += e; j += "}"; }
        j += "]";
        // (v1 hatte hier Freigeben/Zurueckholen; v2 = eigene Heap-Region -> der Probe-Lauf oben
        //  alloziert bereits aus der Region, es gibt nichts freizugeben.)
    }
    j += "}";
    res.sendJson(j);
}

// /heapmap: Heap-Map fuer die Diagnose-UI. Kein echtes Heap-Tracing (das braeuchte einen
// Allocator-Hook) -- nur die zwei harten Aggregatzahlen (intern/PSRAM, frei + groesster
// zusammenhaengender Block) plus die beim Boot bereits gesammelte Zeitleiste (logHeapMark(),
// siehe dort) und die aktuell vom H.264-Stream gehaltene Reservierung. Zeigt insbesondere, ob/wie
// stark der WLAN-/Netz-Aufbau den zusammenhaengenden internen Block schrumpft (LAN > WLAN).
void handleHeapMap(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    logHttpRequest(req, "Heap-Map");
    String j = "{\"ok\":true";
    j += ",\"intFree\":";      j += (uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    j += ",\"intLargest\":";   j += (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    j += ",\"psramFree\":";    j += (uint32_t)heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    j += ",\"psramLargest\":"; j += (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    j += ",\"h264ActiveRefKb\":"; j += (uint32_t)(g_h264ActiveRef / 1024);
    j += ",\"guardHeldKb\":"; j += (uint32_t)(h264GuardBytes() / 1024);        // exklusive Video-Reserve
    j += ",\"guardFreeKb\":"; j += (uint32_t)(h264GuardRegionLargest() / 1024); // davon groesster freier Block
    j += ",\"guardHits\":";   j += h264GuardHookHits();                        // Encoder-Puffer aus der Reserve
    j += ",\"guardBootKb\":"; j += (uint32_t)(h264GuardBootBytes() / 1024);    // beim Boot angefordert
    j += ",\"guardPrefKb\":"; j += h264GuardConfiguredKb();                     // NVS (ab Neustart)
    j += ",\"milestones\":[";
    for (int i = 0; i < g_heapMilestoneCount; i++) {
        if (i) j += ",";
        j += "{\"tag\":\""; j += g_heapMilestones[i].tag; j += "\",\"freeKb\":";
        j += g_heapMilestones[i].freeKb; j += ",\"largestKb\":"; j += g_heapMilestones[i].largestKb; j += "}";
    }
    j += "]}";
    res.sendJson(j);
}


void handleRootPage(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    logHttpRequest(req, "Root page");

    // Root ist selbst-gated: erst WAN-Sperre (Web ueber Mobilfunk aus -> aus dem
    // Internet gar nicht anzeigen), dann gueltige Session -> App, sonst PIN-Gate.
    if (weirdReqWanDenied(req)) {
        res.send(403, "text/plain; charset=utf-8",
                 String("Weboberflaeche aus der Zone '") + accessZoneName(accessZoneOf(req.clientIp())) + "' nicht freigegeben.");
        return;
    }
    if (WeirdAuth::authorized(req.cookie(WeirdAuth::cookieName()), weirdReqIsWan(req.clientIp())))
        sendAppOrPinSetup(res, req.arg("p"));   // ?p=tab[/psub] -> nur diese Seite rendern
    else
        sendPinGate(res, false);
}


// Laufzeit-Umschaltung von Aufloesung und JPEG-Qualitaet. Beide Parameter
// sind optional; erlaubt ist nur, was innerhalb der beim Init festgelegten
// Grenzen liegt (aktives Maximum bzw. konfigurierte Bestqualitaet), denn
// der Framebuffer ist auf diese Grenzen allokiert. Genutzt von der
// Weboberflaeche und vom Windows-Screensaver.
// Generische Sensor-Parameter des aktiven Kamera-Geraets (S3-DVP oder P4-MIPI)
// als JSON fuer die Web-UI. Liste kommt komplett vom Geraet -> UI ist geraete-
// unabhaengig (Slider fuer INT, Schalter fuer BOOL).

// Einen Sensor-Parameter setzen (wirkt sofort). key=<param>&value=<int>.


// ============================================================================
// Geraete-Namespace (Linux-/dev-artig): EIN einheitlicher Capability-API statt
// bespoke JSON pro Feature. Quelle = peripheral_registry (Port->Device->Capability).
//   GET   /dev             -> Index aller Geraete [{name,class,present}]
//   GET   /dev/<name>      -> Capability-Descriptor DIESES Geraets (klassenspezifisch)
//   PATCH /dev/<name>      -> Resource-API (Kamera: mode/fps/quality/params)
// Die WebUI liest generisch /dev/<name> -> kein Geraete-Sondercode/#ifdef im JS.
// Neues Geraet -> in der Registry registrieren -> automatisch hier sichtbar.
// ============================================================================
// devClassOf() ENTFERNT: der HTTP-Layer raet die Geraeteklasse nicht mehr per
// Namenspraefix. Die Registry (periphClassOf / PeriphDev.devClass) ist die Quelle.

// /dev-Namespace ist auf WeirdHttp migriert (Batch 1). Die Auth liegt jetzt in der
// requireSession-Middleware VOR dem Dispatch (nicht mehr im Handler) -> devGuard entfaellt.
// Unauthentifiziert -> 401 application/json (nicht das HTML-PIN-Gate).
void handleDevIndex(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    PeriphModel m; periphBuildModel(m);
    String j = "{\"ok\":true,\"devices\":[";
    bool first = true;
    for (int pi = 0; pi < m.portCount; pi++)
        for (int di = 0; di < m.ports[pi].devCount; di++) {
            const PeriphDev& d = m.ports[pi].devs[di];
            if (!d.logical.length()) continue;
            if (!first) j += ","; first = false;
            j += "{\"name\":\"";     j += d.logical;
            j += "\",\"class\":\"";  j += (d.devClass.length() ? d.devClass : String("device"));
            j += "\",\"present\":";  j += (d.detected ? "true" : "false");
            j += "}";
        }
    j += "]}";
    res.sendJson(j);
}

void handleDevDescriptor(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String name = req.pathParam("device");
    String cls  = periphClassOf(name);   // Klasse aus der Registry, nicht aus dem Namen geraten
    String j = "{\"ok\":true,\"name\":\"" + name + "\",\"class\":\"" + cls + "\"";
    if (cls == "camera") {
        j += ",\"present\":"; j += (cameraReady ? "true" : "false");
        CameraVideoMode modes[12]; int n = cameraManager.enumModes(modes, 12);
        j += ",\"modes\":[";                        // nach w×h dedupliziert (Pixelformat/fps gehoeren nicht rein)
        bool first = true;
        for (int i = 0; i < n; i++) {
            bool dup = false;
            for (int k = 0; k < i; k++) if (modes[k].width == modes[i].width && modes[k].height == modes[i].height) { dup = true; break; }
            if (dup) continue;
            if (!first) j += ","; first = false;
            j += "{\"w\":"; j += modes[i].width; j += ",\"h\":"; j += modes[i].height; j += "}";
        }
        j += "]";
        uint16_t cw = 0, ch = 0;
        if (cameraManager.currentMode(cw, ch)) { j += ",\"current\":{\"w\":"; j += cw; j += ",\"h\":"; j += ch; j += "}"; }
        // Live-State fuer die Resource-API (PATCH /dev/camera0): fps + JPEG-Qualitaet.
        j += ",\"fps\":";     j += cameraTargetFps;
        // Quality ist nur setzbar, wo ein esp_camera-Sensor existiert (S3). Am P4 laeuft der
        // HW-JPEG-Encoder fest auf seiner eigenen 1-100-Skala -> KEINE fiktive 0-63-Quality als
        // Live-State ausgeben, sondern quality:null (bis eine normalisierte P4-Quality existiert).
        bool qualitySettable = (esp_camera_sensor_get() != nullptr) || cameraManager.qualityRuntimeSettable();
        j += ",\"quality\":"; j += qualitySettable ? String(cameraCurrentQuality) : String("null");
        j += ",\"qualitySettable\":"; j += qualitySettable ? "true" : "false";
        // Video-Codecs, die diese Hardware kann (fuers UI-Dropdown; nicht verfuegbare -> ausgegraut).
        // MJPEG immer (JPEG-HW/SW). H.264 nur mit HW-Encoder (P4). H.265/AV1 keine P4-HW.
        // "active":true = der Codec, der aktuell den Stream liefert (bis H.264 verdrahtet ist: MJPEG).
        {
            bool h264hw   = H264Encoder::hwAvailable();
            bool h264live = (g_h264ActiveRef != 0);   // EINE Wahrheit: laeuft gerade ein H.264-Stream?
            // RANGFOLGE = Reihenfolge (bester zuerst): AV1 > H.265 > H.264 > MJPEG. Die UI waehlt als
            // Default den ERSTEN verfuegbaren Codec (bzw. den gerade aktiven Stream). "active" heisst
            // nur "liefert JETZT einen Stream" -- MJPEG bekommt kein Dauer-active mehr, sonst wuerde
            // es die Default-Wahl immer gewinnen. Einzelbilder sind die letzte Stufe (Modus-Dropdown).
            j += ",\"codecs\":[";
            j += "{\"id\":\"av1\",\"label\":\"AV1\",\"available\":false,\"active\":false}";
            j += ",{\"id\":\"h265\",\"label\":\"H.265\",\"available\":false,\"active\":false}";
            j += ",{\"id\":\"h264\",\"label\":\"H.264\",\"available\":"; j += h264hw ? "true" : "false";
            j += ",\"active\":"; j += h264live ? "true" : "false"; j += "}";
            j += ",{\"id\":\"mjpeg\",\"label\":\"MJPEG\",\"available\":true,\"active\":false}";
            j += "]";
            // H.264-Ausgabeaufloesungen: ALLE im Dropdown, aber available=false (ausgegraut), wenn der
            // interne ref-Puffer (~1152*ceil(w/16), zwingend zusammenhaengend intern) aktuell NICHT in
            // den groessten freien internen Block passt. So sieht man ehrlich, was jetzt geht -- und
            // sobald der H.264-Guard einen grossen Block freigibt, werden hoehere Werte waehlbar.
            if (h264hw) {
                // Nur Groessen, die findCropScale() sauber (voll gefuellt, KEIN Saum) erzeugt. Empirisch
                // am Geraet bestaetigt: sauber sind die mit PPA-Scale 0,5 bzw. 1,0 -> 800 (Scale 1,0),
                // 400 (Crop800*0,5=volles Blickfeld), 384/320/256 (Crop768/640/512*0,5). 416 dagegen wird
                // Crop512*13/16 -> unterfuellt -> Saum -> NICHT anbieten (krumme Zwischengroessen ebenso).
                // available = ref-Puffer (~1152*ceil(w/16)) passt in den groessten freien internen Block
                // (+ laufender Stream zurueckgerechnet, sonst alles grau).
                // Volle Leiter bis FHD. available = ref-Puffer (~1152*ceil(w/16), zusammenhaengend intern)
                // passt in den groessten freien Block -> hoehere Aufloesungen sind AUSGEGRAUT, bis genug
                // interner Heap frei ist (z.B. nach Abschalten des ungenutzten WLAN-Stacks -> FHD-Ziel).
                // Kleine Groessen quadratisch (sauberer PPA-Downscale 0,5/1,0); FHD/HD 16:9 fuer hoch.
                // Ein gehaltener Boot-Guard (h264_guard.h) wird beim Streamstart freigegeben -> zaehlt
                // als verfuegbarer Block mit (max aus freiem Block+laufendem Stream und Guard).
                size_t largest = h264GuardEffectiveLargest(g_h264ActiveRef);
                // ZWEITE Bedingung (ehrlich): die PPA skaliert nur HERUNTER (findCropScale: k/16 <= 1).
                // Ziel > AKTUELL AKTIVER Sensor-Modus ist damit unmoeglich. Der Sensor-Modus wird unter
                // Server > Video > Bild (Aufloesung) gesetzt -- der OV5647-Treiber kann 1920x1080 (setMode
                // ueber die exportierte Format-Tabelle; MJPEG laeuft damit in FHD). Steht die Kamera aber
                // z.B. auf 800x800, bekommen groessere Eintraege reason "sensor" statt "heap", damit klar
                // ist: erst die Kamera-Aufloesung hochstellen, nicht Heap freischaufeln.
                // Massstab ist NICHT der gerade aktive Kamera-Modus, sondern ob IRGENDEIN vom Backend
                // gemeldeter Modus die Zielgroesse abdeckt: der H.264-Start schaltet die Kamera selbst
                // auf den kleinsten passenden Modus (camera_server.cpp). So ist FHD direkt waehlbar,
                // ohne vorher von Hand den Kamera-Modus umzustellen.
                uint16_t sw = 0, sh = 0;
                {
                    CameraVideoMode modes[16];
                    int nm = cameraManager.enumModes(modes, 16);
                    for (int m = 0; m < nm; m++) { if (modes[m].width > sw) sw = modes[m].width; if (modes[m].height > sh) sh = modes[m].height; }
                    if (nm == 0) cameraManager.currentMode(sw, sh);
                }
                static const uint16_t RW[] = {1920, 1280, 800, 640, 400, 320, 256};
                static const uint16_t RH[] = {1080,  720, 800, 640, 400, 320, 256};
                j += ",\"h264res\":[";
                for (int i = 0; i < 7; i++) {
                    size_t need = h264RefBytesForWidth(RW[i]);   // interner ref-Puffer (breiten-getrieben), EINE Formel
                    bool heapOk   = (need + 1024 < largest);
                    bool sensorOk = (sw == 0 || sh == 0) || (RW[i] <= sw && RH[i] <= sh);
                    if (i) j += ",";
                    j += "{\"w\":"; j += RW[i]; j += ",\"h\":"; j += RH[i];
                    j += ",\"available\":"; j += (heapOk && sensorOk) ? "true" : "false";
                    j += ",\"reason\":\""; j += !sensorOk ? "sensor" : (!heapOk ? "heap" : ""); j += "\"}";
                }
                j += "]";
                // Live-Statistik des laufenden Streams (vom Encode-Task je Sekunde): erreichte fps,
                // gesendete kbit/s, ausgelassene Frames (adaptive Bildrate). 0 = kein Stream.
                j += ",\"h264stat\":{\"fps\":";  j += (uint32_t)g_h264StatFps;
                j += ",\"kbit\":";               j += (uint32_t)g_h264StatKbit;
                j += ",\"skips\":";              j += (uint32_t)g_h264StatSkips;
                j += ",\"targetKbit\":";         j += h264Kbit;
                j += ",\"dropstale\":";          j += streamDropStale ? "true" : "false";
                j += "}";
            }
        }
        // Generische Sensor-Parameter (loest /cam-params.json ab): key/label/min/max/kind/value.
        j += ",\"params\":[";
        int pn = cameraManager.paramCount(); bool pf = true;
        for (int pi = 0; pi < pn; pi++) {
            CameraParamInfo pinfo;
            if (!cameraManager.paramAt(pi, pinfo)) continue;
            if (!pf) j += ","; pf = false;
            j += "{\"key\":\"";     j += escapeJson(pinfo.key);
            j += "\",\"label\":\""; j += escapeJson(pinfo.label);
            j += "\",\"min\":";     j += pinfo.min;
            j += ",\"max\":";       j += pinfo.max;
            j += ",\"kind\":";      j += (int)pinfo.kind;
            j += ",\"value\":";     j += pinfo.value;
            j += "}";
        }
        j += "]";
        // Sensor-Params sind genauso nur am S3 (esp_camera-Sensor) wirklich setzbar. Am P4
        // lehnt der OV5647-esp_video-Treiber jeden VIDIOC_S_CTRL ab -> KEIN Schein-Regler: die
        // UI blendet die Parameter-Sektion aus, PATCH lehnt sie ehrlich mit 501 ab.
        j += ",\"paramsSettable\":"; j += qualitySettable ? "true" : "false";
        j += ",\"settable\":true";
    } else if (cls == "cellular") {
        j += ",\"present\":";  j += ((modemDeviceHandle() != nullptr) ? "true" : "false");
        j += ",\"datalink\":\""; j += modemLinkModeName(); j += "\"";
        j += ",\"up\":";       j += (modemLinkIsUp() ? "true" : "false");
        j += ",\"wanip\":\"";  j += modemLinkWanIp(); j += "\"";
        j += ",\"apn\":\"";    j += escapeJson(modemApn); j += "\"";
    } else if (cls == "wifi") {
        j += ",\"present\":";  j += (wifiPresent() ? "true" : "false");
        j += ",\"radios\":";   j += wifiRadioCount();
    } else if (cls == "audio-input") {
        // Onboard-Mikro (P4/ES8311). runtime=false -> Codec-Runtime (ES8311/I2S) noch nicht aktiv.
        // "formats" sind hier GEPLANTE Hardware-Capabilities (Platzhalter). TODO: langfristig
        // sollen Descriptor + Formate vom Audio-Backend kommen (wie camera enumModes), NICHT
        // hier in handleDevDescriptor hartkodiert.
        j += ",\"present\":true,\"builtin\":true,\"runtime\":false";
        j += ",\"capabilities\":[\"audio.capture\"]";
        j += ",\"formatsPlanned\":[{\"rate\":16000,\"bits\":16,\"channels\":1},{\"rate\":48000,\"bits\":16,\"channels\":1}]";
    } else if (cls == "audio-output") {
        // Ausgangs-/Codec-Pfad ist fest vorhanden; ein angeschlossener Lautsprecher wird NICHT
        // erkannt (extern am MX1.25-Header). Formate = geplante HW-Capabilities (s.o.).
        j += ",\"present\":true,\"builtin\":true,\"runtime\":false,\"speakerDetected\":false";
        j += ",\"capabilities\":[\"audio.playback\"]";
        j += ",\"formatsPlanned\":[{\"rate\":16000,\"bits\":16,\"channels\":1},{\"rate\":48000,\"bits\":16,\"channels\":1}]";
    }
    j += "}";
    res.sendJson(j);
}


// Kleiner JSON-Integer-Feld-Leser fuer kontrollierte UI-Bodies (kein voller Parser noetig):
// erste ganze Zahl nach "key": . DEV_NOFIELD wenn das Feld fehlt.
static const long DEV_NOFIELD = -1000000000L;
static long jsonIntField(const String& body, const char* key) {
    String pat = String("\"") + key + "\"";
    int k = body.indexOf(pat);
    if (k < 0) return DEV_NOFIELD;
    int c = body.indexOf(':', k + pat.length());
    if (c < 0) return DEV_NOFIELD;
    int i = c + 1, n = body.length();
    while (i < n && (body[i] == ' ' || body[i] == '\t')) i++;
    bool neg = false; if (i < n && body[i] == '-') { neg = true; i++; }
    if (i >= n || body[i] < '0' || body[i] > '9') return DEV_NOFIELD;
    long v = 0; while (i < n && body[i] >= '0' && body[i] <= '9') { v = v * 10 + (body[i] - '0'); i++; }
    return neg ? -v : v;
}
// true/false nach "key": -> 1/0 (fuer Bool-Params wie hflip). DEV_NOFIELD sonst.
static long jsonBoolField(const String& body, const char* key) {
    String pat = String("\"") + key + "\"";
    int k = body.indexOf(pat);
    if (k < 0) return DEV_NOFIELD;
    int c = body.indexOf(':', k + pat.length());
    if (c < 0) return DEV_NOFIELD;
    int i = c + 1, n = body.length();
    while (i < n && (body[i] == ' ' || body[i] == '\t')) i++;
    if (body.substring(i, i + 4) == "true")  return 1;
    if (body.substring(i, i + 5) == "false") return 0;
    return DEV_NOFIELD;
}
// String-Wert nach "key":"..." (nur einfache, un-escapte Werte -- kontrollierte UI-Bodies).
// Rueckgabe "" wenn das Feld fehlt (der Aufrufer unterscheidet "fehlt" per hasField).
static bool jsonHasField(const String& body, const char* key) {
    return body.indexOf(String("\"") + key + "\"") >= 0;
}
static String jsonStrField(const String& body, const char* key) {
    String pat = String("\"") + key + "\"";
    int k = body.indexOf(pat);
    if (k < 0) return String();
    int c = body.indexOf(':', k + pat.length());
    if (c < 0) return String();
    int i = c + 1, n = body.length();
    while (i < n && (body[i] == ' ' || body[i] == '\t')) i++;
    if (i >= n || body[i] != '"') return String();
    int e = body.indexOf('"', i + 1);
    if (e < 0) return String();
    return body.substring(i + 1, e);
}

// PATCH /dev/camera0 -- Resource-API fuer den Live-Kamera-State (loest Legacy /cam-set ab).
// Body-JSON: {"mode":{"width":W,"height":H}, "fps":N, "quality":N}. Nur gesendete Felder
// werden angewandt; mode delegiert an cameraManager.setMode. Langfristig SOLL das die eine
// Kamera-Resource sein (statt wachsender /cam-*-/Unterendpunkt-Sammlung).
void handleDevPatch(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String name = req.pathParam("device");
    if (periphClassOf(name) != "camera") {   // Klasse aus der Registry, nicht aus dem Namen geraten
        res.send(404, "application/json", "{\"ok\":false,\"error\":\"kein Kamera-Geraet\"}"); return;
    }
    String body = req.body();
    bool any = false;

    long w = jsonIntField(body, "width"), h = jsonIntField(body, "height");
    if (w != DEV_NOFIELD && h != DEV_NOFIELD) {
        if (!cameraManager.setMode((uint16_t)w, (uint16_t)h)) {
            res.send(500, "application/json", "{\"ok\":false,\"error\":\"Aufloesung nicht anwendbar\"}"); return;
        }
        any = true;
    }

    long fps = jsonIntField(body, "fps");
    if (fps != DEV_NOFIELD) {
        cameraTargetFps = constrain((int)fps, 1, 30);
        cameraStream.setTargetFps(cameraTargetFps);
        any = true;
    }

    // Globale Frame-Politik (neben der Bildrate): veraltete Frames verwerfen ja/nein -> Verteiler.
    long ds = jsonIntField(body, "dropstale");
    if (ds != DEV_NOFIELD) {
        streamDropStale = (ds != 0);
        cameraStream.setDropStale(streamDropStale);
        preferences.begin("camera", false);
        preferences.putBool("dropstale", streamDropStale);
        preferences.end();
        any = true;
    }

    long q = jsonIntField(body, "quality");
    if (q != DEV_NOFIELD) {
        int qq = constrain((int)q, 0, 63);
        sensor_t* s = esp_camera_sensor_get();      // S3: esp_camera-Sensor; P4: NULL (Shim)
        if (s) {
            if (s->set_quality(s, qq) != 0) {
                res.send(500, "application/json", "{\"ok\":false,\"error\":\"Qualitaet nicht uebernommen\"}"); return;
            }
            cameraCurrentQuality = qq; any = true;
        } else if (cameraManager.qualityRuntimeSettable()) {
            // P4: HW-JPEG-Encoder liest image_quality pro Frame -> live setzbar (UI 0..63 -> intern 1..100).
            cameraManager.setJpegQualityUi(qq);
            cameraCurrentQuality = qq; any = true;
        } else {
            res.send(501, "application/json", "{\"ok\":false,\"error\":\"Qualitaet auf diesem Backend nicht aenderbar\"}"); return;
        }
    }

    // "params":{...} -- generische Sensor-Parameter (loest /cam-param ab). Wir iterieren die
    // vom Backend gemeldeten Parameter und lesen den jeweiligen Wert (int ODER true/false) aus
    // dem Body -> keine fremden Keys, kein voller JSON-Parser noetig. Backend-Ablehnung wird
    // NICHT verschluckt (kein blanko ok:true).
    if (body.indexOf("\"params\"") >= 0) {
        // Am P4 (kein esp_camera-Sensor) nimmt der V4L2-Treiber keinen S_CTRL an -> ehrlich
        // als "auf diesem Backend nicht aenderbar" ablehnen (wie Quality), statt jeden Key zu 500en.
        if (!esp_camera_sensor_get()) {
            res.send(501, "application/json",
                     "{\"ok\":false,\"error\":\"Sensor-Parameter auf diesem Backend nicht aenderbar\"}"); return;
        }
        int pn = cameraManager.paramCount();
        String failed;
        for (int pi = 0; pi < pn; pi++) {
            CameraParamInfo pinfo;
            if (!cameraManager.paramAt(pi, pinfo)) continue;
            long v = jsonIntField(body, pinfo.key);
            if (v == DEV_NOFIELD) v = jsonBoolField(body, pinfo.key);
            if (v == DEV_NOFIELD) continue;
            if (cameraManager.setParam(pinfo.key, (int)v)) any = true;
            else { if (failed.length()) failed += ","; failed += pinfo.key; }
        }
        if (failed.length()) {
            res.send(500, "application/json",
                String("{\"ok\":false,\"error\":\"Parameter abgelehnt: ") + escapeJson(failed) + "\"}"); return;
        }
    }

    // Struktur-Capture-Config (loest den Kamera-Teil des alten /cam-config ab): maximale
    // Capture-Aufloesung (max) + Puffer-Qualitaet (bufq). Beide dimensionieren den Framebuffer
    // und wirken erst NACH Neustart -> hier nur persistieren; die Response meldet restartRequired.
    bool restartHint = false;
    long bq = jsonIntField(body, "bufferQuality");
    if (bq != DEV_NOFIELD) {
        cameraBufferQuality = constrain((int)bq, 0, 63);
        preferences.begin("camera", false); preferences.putInt("bufq", cameraBufferQuality); preferences.end();
        any = true; restartHint = true;
    }
    if (jsonHasField(body, "maxMode")) {
        String mm = jsonStrField(body, "maxMode");
        if (frameSizeIndexByName(mm) < 0) {
            res.send(400, "application/json", "{\"ok\":false,\"error\":\"Unbekannte max-Aufloesung\"}"); return;
        }
        preferences.begin("camera", false); preferences.putString("max", mm); preferences.end();
        cameraConfiguredMaxIndex = frameSizeIndexByName(mm);
        any = true; restartHint = true;
    }

    if (!any) { res.send(400, "application/json", "{\"ok\":false,\"error\":\"Keine anwendbaren Felder\"}"); return; }
    persistLiveCameraValues();

    uint16_t cw = 0, ch = 0; cameraManager.currentMode(cw, ch);
    String j = "{\"ok\":true,\"current\":{\"w\":"; j += cw; j += ",\"h\":"; j += ch; j += "}";
    j += ",\"fps\":";     j += cameraTargetFps;
    // Gleiche Ehrlichkeit wie im Descriptor: am P4 (kein esp_camera-Sensor) quality:null.
    j += ",\"quality\":"; j += (esp_camera_sensor_get() != nullptr) ? String(cameraCurrentQuality) : String("null");
    j += ",\"restartRequired\":"; j += (restartHint ? "true" : "false");   // max/bufq wirken erst nach Neustart
    j += "}";
    resNoCache(res);
    res.send(200, "application/json", j);
}





// Erzeugt die <option>-Liste aus der zentralen Tabelle bis einschliesslich
// maxIndex; selectedIndex wird vorausgewaehlt. Damit zeigen Live-Auswahl
// und Konfigurationsformular garantiert nur, was tatsaechlich existiert.
String createSizeOptionsHtml(
    int maxIndex,
    int selectedIndex
) {
    String html;

    html.reserve(64 * (maxIndex + 1));

    for (int i = 0; i <= maxIndex && i < FRAME_SIZE_OPTION_COUNT; i++) {
        html += "<option value='";
        html += FRAME_SIZE_OPTIONS[i].name;
        html += "'";

        if (i == selectedIndex) {
            html += " selected";
        }

        html += ">";
        html += FRAME_SIZE_OPTIONS[i].label;
        html += "</option>";
    }

    return html;
}


// Speichert maximale Aufloesung und Ziel-Bildrate im NVS und startet das
// Geraet neu - gleiche Mechanik wie beim Werksreset: erst die Antwort
// ausliefern, dann kontrolliert rebooten.
// VideoServer-Konfiguration -- die EIGENE Config-Resource des Video-Servers (loest den
// Server-Teil des alten /cam-config ab). NUR Transport/Server: HTTP-MJPEG (enable/multi/
// key/port/path) + RTSP (typ/port/transport). Die Kamera-/Capture-Felder (max/bufq) sind
// hier ENTFALLEN -- sie laufen ueber PATCH /dev/camera0. Wirkt nach Neustart.
void handleVideoConfig(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    logHttpRequest(req, "Video-Server config");

    bool allowMultiStream = req.hasArg("multi");
    // Stream-Transport: off | http | rtsp (Dropdown). Genau EINER laeuft; "off" = kein Videoserver.
    String st = req.arg("streamtype"); if (st != "rtsp" && st != "off") st = "http";
    bool enableStream = (st == "http");   // Legacy-Flag "strm" = HTTP-Stream-Server an
    String key = req.arg("streamkey");
    key.trim();
    int port = sanitizeStreamPort(req.hasArg("streamport") ? req.arg("streamport").toInt() : 81);
    String path = sanitizeStreamPath(req.arg("streampath"));

    saveVideoServerConfig(allowMultiStream, enableStream, key, port, path);

    // Video-Transport: Stream-Typ (http/rtsp) + RTSP-Parameter. RTSP-Server-Runtime folgt;
    // hier wird die Wahl nur persistiert (kein stiller Fallback -- UI weist Stub ehrlich aus).
    {
        streamType = st;
        rtspEnabled = (st == "rtsp");
        rtspPort = req.hasArg("rtspport") ? constrain((int)req.arg("rtspport").toInt(), 1, 65535) : 554;
        String tr = req.arg("rtsptransport"); rtspTransport = (tr == "udp") ? "udp" : "tcp";
        // H.264: Ziel-Bitrate (kbit/s) + adaptive Bildrate. Wirken beim naechsten Streamstart.
        if (req.hasArg("h264kbit")) h264Kbit = constrain((int)req.arg("h264kbit").toInt(), 200, 20000);
        preferences.begin("camera", false);
        preferences.putString("strmtype", streamType);
        preferences.putBool("rtspen", rtspEnabled);
        preferences.putInt("rtspport", rtspPort);
        preferences.putString("rtsptr", rtspTransport);
        preferences.putInt("h264kbit", h264Kbit);
        preferences.end();
    }

    Serial.printf("Video-Server config saved: multi=%d stream=%d port=%d type=%s rtsp=%d\n",
                  allowMultiStream, enableStream, port, streamType.c_str(), rtspEnabled);

    resNoCache(res);
    res.beginChunked(200, "text/html; charset=utf-8");
    res.write(
        "<!DOCTYPE html><html lang='de'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='refresh' content='10;url=/'>"
        "<title>Video-Server</title>"
    );
    res.write(PAGE_STYLE);
    res.write(
        "</head><body><main>"
        "<h1>Video-Server gespeichert</h1>"
        "<p>Das Geraet startet jetzt neu und uebernimmt die neuen "
        "Video-Server-Einstellungen. Diese Seite laedt sich in etwa zehn "
        "Sekunden automatisch neu.</p>"
        "</main></body></html>"
    );
    res.end();

    pendingRestartAt = millis() + 1500;
}



// Die Seite wird gechunkt gesendet, damit sie nicht komplett im RAM
// zusammengebaut werden muss.
// Ein Chunk der Laenge 0 beendet in HTTP/1.1 die gechunkte Antwort. Der
// ESP32-WebServer setzt dabei intern _chunked = false, alles danach wird
// verworfen. Dynamische Werte duerfen deshalb niemals leer gesendet werden.


// -----------------------------------------------------------------------------
// PIN-Gate und Tab-Oberflaeche (in AP und Zielnetz identisch)
// -----------------------------------------------------------------------------

// PIN-Gate: das einzige verpflichtende Element nach dem ersten Verbinden.
// Solange die PIN noch dem Standard entspricht, ist das Feld vorbelegt -
// dann genuegt ein Klick auf "Anmelden".
void handlePinLogin(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    logHttpRequest(req, "PIN login");

    // PUBLIC: NIE requireSession. Die Entscheidung faellt VOLLSTAENDIG vor jeder
    // Ausgabe -> kein begonnener Body, der spaeter noch umschwenken muesste.

    // Brute-Force-Schutz: nach zu vielen Fehlversuchen kurz sperren (kein PIN-Vergleich).
    if (WeirdAuth::pinRateLimited()) { sendPinGate(res, true); return; }

    String pin = req.arg("pin");
    bool ok = pinDisabled() || pin == devicePin;
    WeirdAuth::registerPinResult(ok);

    if (ok) {
        // Erfolg: frische Session (Secure-Cookie, falls Management ueber HTTPS laeuft),
        // Set-Cookie VOR dem Redirect (Header vor Antwortbeginn).
        WeirdAuth::newSession(g_managementSecure);
        resNoCache(res);
        res.header("Set-Cookie", WeirdAuth::setCookieHeader());
        res.redirect("/");
        return;
    }

    sendPinGate(res, true);   // Fehler: PIN-Gate mit Falsch-Hinweis rendern
}

// Abmelden: Session serverseitig loeschen + Cookie im Browser leeren, zurueck zur Root (= PIN-Gate).
// Hinter requireSession (POST, SameSite=Strict-Cookie): nur eine berechtigte Sitzung kann sich
// selbst beenden -- eine fremde Seite kann die (einzige) Session nicht per Cross-Site-POST killen.
void handleLogout(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    logHttpRequest(req, "Logout");
    WeirdAuth::invalidate();
    resNoCache(res);
    res.header("Set-Cookie", WeirdAuth::clearCookieHeader());
    res.redirect("/", 303);   // nach Logout immer zur Startseite (PIN-Gate)
}


// Aendert die PIN. Erfordert eine gueltige Sitzung. Leere PIN = deaktiviert.
void handlePinChange(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    logHttpRequest(req, "PIN change");

    // Geschuetzt. Alte Semantik exakt erhalten: unauth -> 403-Text (kein Redirect/JSON).
    if (!WeirdAuth::authorized(req.cookie(WeirdAuth::cookieName()), weirdReqIsWan(req.clientIp()))) {
        res.send(403, "text/plain; charset=utf-8", "PIN erforderlich.");
        return;
    }

    String newPin = req.arg("newpin");
    newPin.trim();

    // Regeln (Sicherheits-Bootstrap): Werks-PIN nie wieder; keine leere PIN (= Schutz aus), solange
    // die Oberflaeche ueber WAN erreichbar ist; mindestens 4 Zeichen. Bei aktiver Werks-PIN landet
    // der Hinweis auf der Setup-Seite, sonst als Klartext.
    String reject;
    if (newPin == PIN_DEFAULT)                       reject = "0000 ist die Werks-PIN und nicht erlaubt.";
    else if (newPin.length() == 0 && webWanEnabled)  reject = "Ohne PIN waere die Oberflaeche ueber Mobilfunk fuer jeden bedienbar. Erst den Fernzugriff (System > Sicherheit) abschalten, dann kann die PIN deaktiviert werden.";
    else if (newPin.length() > 0 && newPin.length() < 4) reject = "Mindestens 4 Zeichen.";
    if (reject.length()) {
        resNoCache(res);
        if (pinStillDefault()) sendPinSetupGate(res, reject);
        else res.send(400, "text/plain; charset=utf-8", reject);
        return;
    }

    saveDevicePin(newPin);

    Serial.print("PIN changed. Protection: ");
    Serial.println(newPin.length() == 0 ? "disabled" : "enabled");

    // Wie bisher: nach der PIN-Aenderung frische Session ausgeben (saveDevicePin
    // invalidiert alle alten), Cookie VOR dem Redirect setzen -> die laufende Sitzung
    // dieses Browsers bleibt bestehen, andere/mitgelesene Tokens sind ungueltig.
    WeirdAuth::newSession(g_managementSecure);
    resNoCache(res);
    res.header("Set-Cookie", WeirdAuth::setCookieHeader());
    res.redirect("/");
}


// Save the setup-AP security without ever returning the stored password.
// Empty password input means "keep unchanged"; only the explicit open flag
// disables WPA2. A restart is required because changing AP credentials drops
// all currently connected setup clients.
void handleApSecuritySave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    const bool makeOpen = req.hasArg("open");
    String newPassword = req.arg("password");

    if (!makeOpen && newPassword.length() == 0) {
        resNoCache(res);
        res.send(200, "application/json",
                    "{\"ok\":true,\"restart\":false,\"msg\":\"WLAN-Sicherheit unveraendert.\"}");
        return;
    }

    if (!makeOpen && (newPassword.length() < 8 || newPassword.length() > 63)) {
        resNoCache(res);
        res.send(400, "application/json",
                    "{\"ok\":false,\"msg\":\"WPA2-Passwort muss 8 bis 63 Zeichen lang sein.\"}");
        return;
    }

    setupApPassword = makeOpen ? String("") : newPassword;
    preferences.begin("wifi", false);
    preferences.putString("appass", setupApPassword);
    preferences.end();

    resNoCache(res);
    res.send(200, "application/json", setupApPassword.length()
        ? "{\"ok\":true,\"restart\":true,\"msg\":\"WPA2-Passwort gespeichert. Geraet startet neu.\"}"
        : "{\"ok\":true,\"restart\":true,\"msg\":\"Setup-AP wird offen betrieben. Geraet startet neu.\"}");
    pendingRestartAt = millis() + 1500;
}


// WAN-Web-Schalter speichern (System -> Sicherheit). Ohne Haken ist die
// Weboberflaeche ueber die Mobilfunk-Seite nicht mehr erreichbar (nur noch LAN).
// Zugriff je Dienst (System > Sicherheit): <svc>_vpn / <svc>_inet je Dienst als Checkbox-Felder.
void handleAccessSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    int n; const AccessService* s = accessServices(n);
    for (int i = 0; i < n; i++) {
        uint8_t m = 0;
        if (req.hasArg((String(s[i].id) + "_vpn").c_str()))  m |= ACCESS_VPN;
        if (req.hasArg((String(s[i].id) + "_inet").c_str())) m |= ACCESS_INTERNET;
        accessSet(s[i].id, m);
    }
    Serial.printf("[access] gespeichert: %s\r\n", accessJson().c_str());
    resNoCache(res);
    // Ehrlicher Hinweis, falls die Verwaltung aus der aktuellen Zone des Aufrufers nun gesperrt ist.
    String zone = accessZoneName(accessZoneOf(req.clientIp()));
    bool selfLocked = !accessAllowed("web", req.clientIp());
    res.send(200, "application/json", String("{\"ok\":true,\"msg\":\"Gespeichert. ") +
             (selfLocked ? ("ACHTUNG: Die Weboberflaeche ist aus deiner aktuellen Zone (" + zone + ") jetzt gesperrt - Rettungsweg: serielle Konsole.") : ("Deine Zone: " + zone + ".")) + "\"}");
}
void handleWebWanSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    saveWebWanEnabled(req.hasArg("wanweb"));
    Serial.print("WAN web access: ");
    Serial.println(webWanEnabled ? "on" : "off");
    resNoCache(res);
    res.send(200, "application/json", webWanEnabled
        ? "{\"ok\":true,\"msg\":\"Weboberflaeche ueber Mobilfunk (WAN) aktiviert.\"}"
        : "{\"ok\":true,\"msg\":\"Weboberflaeche ueber WAN deaktiviert - nur noch im LAN erreichbar.\"}");
}

// Management-Transportverschluesselung umschalten (System -> Sicherheit). Wirkt nach
// Neustart (der HTTP-Server bindet Port/Transport beim Start). Der Transportwechsel
// invalidiert bestehende Sessions (ein evtl. ueber Klartext ausgespaehtes Token darf
// nach dem TLS-Wechsel nicht weiterleben).
void handleWebTransportSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    bool wantHttps = req.hasArg("https");
#if !WEIRDOS_FEATURE_TLS_SERVER
    if (wantHttps) {   // Baustein abgewaehlt: nicht erst nach dem Neustart auf HTTP zurueckfallen
        resNoCache(res);
        res.send(200, "application/json", "{\"ok\":false,\"msg\":\"HTTPS-Server nicht im Build enthalten (WEIRDOS_FEATURE_TLS_SERVER=0).\"}");
        return;
    }
#endif
    bool changed = (wantHttps != webHttpsEnabled);
    saveWebHttpsEnabled(wantHttps);
    if (changed) WeirdAuth::invalidateOnTransportChange(wantHttps);
    Serial.print("Management transport: "); Serial.println(wantHttps ? "HTTPS" : "HTTP");
    resNoCache(res);
    res.send(200, "application/json", wantHttps
        ? "{\"ok\":true,\"restart\":true,\"msg\":\"HTTPS aktiviert. Geraet startet neu; danach ueber https:// erreichbar (self-signed -> Browserwarnung bestaetigen).\"}"
        : "{\"ok\":true,\"restart\":true,\"msg\":\"HTTP aktiviert (unverschluesselt). Geraet startet neu.\"}");
    pendingRestartAt = millis() + 1500;
}


#if WEIRDOS_FEATURE_ACME   // ACME-Handler
// ---- ACME / Let's Encrypt (System > Sicherheit > Zertifikat) -------------------------------
// App-Hook fuer den ACME-Client: WAN-Interface wie bei DynDNS (EgressPolicy) + DNS-Route.
bool acmeAppResolveEgress(NetIface& out) {
    if (!egressResolve(dyndnsEgress, out)) return false;
    dyndnsApplyEgress();   // (Carrier-)DNS ueber das gewaehlte Netz erreichbar machen (wie DynDNS)
    return true;
}

static String acmeStatusJson() {
    const AcmeConfig& c = acmeConfig();
    String j = "{\"ok\":true";
    j += ",\"enabled\":";  j += c.enabled ? "true" : "false";
    j += ",\"domain\":\"";  j += escapeJson(c.domain); j += "\"";
    j += ",\"email\":\"";   j += escapeJson(c.email);  j += "\"";
    j += ",\"staging\":";  j += c.staging ? "true" : "false";
    j += ",\"tos\":";      j += c.tos ? "true" : "false";
    j += ",\"hasCert\":";  j += acmeHasCert() ? "true" : "false";
    j += ",\"usable\":";   j += acmeCertUsable() ? "true" : "false";
    j += ",\"subject\":\""; j += escapeJson(acmeCertSubject()); j += "\"";
    j += ",\"notAfter\":\""; j += systemClockIsoOf(acmeCertNotAfter()); j += "\"";
    long days = (acmeCertNotAfter() && systemClockValid()) ? (long)((acmeCertNotAfter() - time(nullptr)) / 86400) : -1;
    j += ",\"daysLeft\":"; j += days;
    j += ",\"running\":";  j += acmeRunning() ? "true" : "false";
    j += ",\"state\":\"";   j += escapeJson(acmeStateText()); j += "\"";
    j += ",\"lastError\":\""; j += escapeJson(acmeLastError()); j += "\"";
    j += ",\"lastOk\":";   j += acmeLastOk() ? "true" : "false";
    j += ",\"lastRunAgo\":"; j += acmeLastRunMs() ? (long)((millis() - acmeLastRunMs()) / 1000) : -1;
    j += ",\"clockValid\":"; j += systemClockValid() ? "true" : "false";
    j += ",\"clock\":\"";   j += systemClockIso(); j += "\"";
    j += ",\"restartPending\":"; j += acmeRestartPending() ? "true" : "false";
    j += ",\"httpsActive\":"; j += (g_web.running() && g_web.isTls()) ? "true" : "false";
    j += ",\"port80\":";     j += g_web80.running() ? "true" : "false";
    j += ",\"activeCert\":\"";
    j += (g_web.running() && g_web.isTls()) ? ((c.enabled && acmeCertUsable()) ? "letsencrypt" : "selfsigned") : "http";
    j += "\"";
    j += ",\"linkUp\":";   j += modemLinkUp ? "true" : "false";
    j += "}";
    return j;
}

void handleAcmeStatus(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req; resNoCache(res); res.sendJson(acmeStatusJson());
}

void handleAcmeSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    AcmeConfig c = acmeConfig();
    // EINE Wahrheit: ob Let's Encrypt AKTIV ist, entscheidet die Zertifikatsherkunft (cert_store),
    // nicht dieses Formular. Hier nur Domain/E-Mail/Staging/TOS pflegen.
    c.enabled = (certSource() == CertSource::Acme);
    c.domain  = req.arg("domain");  c.domain.trim();
    c.email   = req.arg("email");   c.email.trim();
    c.staging = req.hasArg("staging");
    c.tos     = req.hasArg("tos");
    if (c.domain.length() == 0) c.domain = dyndnsDomain;
    resNoCache(res);
    if (c.enabled && !c.tos) {
        res.sendJson("{\"ok\":false,\"error\":\"Bitte die Nutzungsbedingungen von Let's Encrypt akzeptieren.\"}"); return;
    }
    if (c.enabled && c.domain.length() == 0) {
        res.sendJson("{\"ok\":false,\"error\":\"Keine Domain (DynDNS-Domain unter Dienste setzen oder hier eintragen).\"}"); return;
    }
    acmeSaveConfig(c);
    Serial.printf("ACME-Config gespeichert: %s, %s (%s)\n", c.enabled ? "AN" : "aus", c.domain.c_str(), c.staging ? "Staging" : "Produktion");
    res.sendJson(String("{\"ok\":true,\"msg\":\"") + (c.enabled
        ? "Gespeichert. Das Zertifikat wird automatisch geholt (mit Link + Netzzeit) oder jetzt per Knopf."
        : "Gespeichert. Let's Encrypt aus; die Verwaltung nutzt (bei HTTPS) das self-signed Zertifikat.") + "\"}");
}

void handleAcmeRun(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req; resNoCache(res);
    const AcmeConfig& c = acmeConfig();
    if (!c.enabled)            { res.sendJson("{\"ok\":false,\"error\":\"Let's Encrypt ist nicht aktiviert (erst speichern).\"}"); return; }
    if (!modemLinkUp)          { res.sendJson("{\"ok\":false,\"error\":\"Kein Mobilfunk-Link.\"}"); return; }
    if (!systemClockValid())   { res.sendJson("{\"ok\":false,\"error\":\"Systemzeit unbekannt -- kommt vom Modem beim Verbinden (Uebersicht > System).\"}"); return; }
    if (acmeRunning())         { res.sendJson("{\"ok\":false,\"error\":\"Laeuft bereits.\"}"); return; }
    if (!acmeStart("manuell (UI)")) { res.sendJson(String("{\"ok\":false,\"error\":\"") + escapeJson(acmeLastError()) + "\"}"); return; }
    res.sendJson("{\"ok\":true,\"msg\":\"Zertifikatsbezug gestartet -- Status unten (Let's Encrypt prueft Port 80 der Domain).\"}");
}

void handleAcmeClear(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req; resNoCache(res);
    acmeClearCert();
    logEvent("ACME: Zertifikat geloescht (zurueck zu self-signed ab Neustart)");
    res.sendJson("{\"ok\":true,\"msg\":\"Zertifikat geloescht. Ab dem naechsten Neustart wieder self-signed.\"}");
}
#endif // WEIRDOS_FEATURE_ACME (ACME-Handler)

#if WEIRDOS_FEATURE_TLS_SERVER   // Zertifikats-Handler
// --- Zertifikatsverwaltung (cert_store): Herkunft, Upload, self-signed, Info ---

void handleCertSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    resNoCache(res);
    String s = req.arg("src");   // "self" | "upload" | "acme"
    CertSource want = CertSource::SelfSigned;
    if (s == "upload") want = CertSource::Upload;
    else if (s == "acme") want = CertSource::Acme;
    // Bei "eigenes hochladen/eintragen" ohne hinterlegtes Zertifikat NICHT umschalten -- sonst
    // liefe HTTPS auf den self-signed-Fallback, was den Benutzer verwirrt.
    if (want == CertSource::Upload && !certUploadPresent()) {
        res.sendJson("{\"ok\":false,\"error\":\"Kein eigenes Zertifikat hinterlegt -- zuerst unten hochladen/eintragen und speichern.\"}"); return;
    }
    if (want == CertSource::Acme) {
        const AcmeConfig& c = acmeConfig();
        if (!c.tos) { res.sendJson("{\"ok\":false,\"error\":\"Fuer Let's Encrypt zuerst die Nutzungsbedingungen akzeptieren (unten).\"}"); return; }
    }
    certSetSelfSignedRenew(req.hasArg("ssrenew"));
    certSetSource(want);
    if (webHttpsEnabled) g_certApplyRestart = true;   // HTTPS bindet das Cert erst beim Start -> Neustart, wenn kein Zuschauer
    logEvent(String("Zertifikatsherkunft: ") + (want == CertSource::Acme ? "Let's Encrypt" : (want == CertSource::Upload ? "eigenes Zertifikat" : "self-signed")));
    const char* msg = (want == CertSource::Acme)
        ? "Uebernommen: Let's Encrypt. Das Zertifikat wird automatisch geholt (Link + Netzzeit) oder unten per Knopf; aktiv nach Neustart."
        : (want == CertSource::Upload)
        ? "Uebernommen: eigenes Zertifikat. Aktiv nach Neustart."
        : "Uebernommen: selbst erstelltes (self-signed) Zertifikat. Aktiv nach Neustart.";
    res.sendJson(String("{\"ok\":true,\"restart\":true,\"msg\":\"") + msg + "\"}");
}

void handleCertUpload(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    resNoCache(res);
    String cert = req.arg("cert");
    String key  = req.arg("key");
    String err  = certUploadSet(cert, key);
    if (err.length()) { res.sendJson(String("{\"ok\":false,\"error\":\"") + escapeJson(err) + "\"}"); return; }
    logEvent(String("Eigenes Zertifikat hinterlegt: ") + certUploadSubject());
    res.sendJson("{\"ok\":true,\"msg\":\"Zertifikat geprueft und gespeichert. Als Herkunft 'eigenes' waehlen und uebernehmen (aktiv nach Neustart).\"}");
}

void handleCertSelfsign(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req; resNoCache(res);
    if (!certRegenerateSelfSigned(dyndnsDomain.length() ? dyndnsDomain.c_str() : nullptr)) {
        res.sendJson("{\"ok\":false,\"error\":\"Erzeugung fehlgeschlagen (Heap?).\"}"); return;
    }
    res.sendJson("{\"ok\":true,\"msg\":\"Neues self-signed Zertifikat erzeugt. Aktiv nach Neustart (falls diese Herkunft gewaehlt ist).\"}");
}

void handleCertInfo(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req; resNoCache(res);
    String j = "{\"ok\":true,\"src\":";
    j += String((unsigned)(uint8_t)certSource());
    j += ",\"ssRenew\":"; j += certSelfSignedRenew() ? "true" : "false";
    j += ",\"ssSubject\":\""; j += escapeJson(certSelfSignedSubject()); j += "\"";
    j += ",\"ssNotAfter\":"; j += String((long)certSelfSignedNotAfter());
    j += ",\"upPresent\":"; j += certUploadPresent() ? "true" : "false";
    j += ",\"upSubject\":\""; j += escapeJson(certUploadSubject()); j += "\"";
    j += ",\"upNotAfter\":"; j += String((long)certUploadNotAfter());
    j += "}";
    res.sendJson(j);
}
#endif // WEIRDOS_FEATURE_TLS_SERVER (Zertifikats-Handler)

#if WEIRDOS_FEATURE_ACME   // Challenge + Port-80-Redirect
// http-01: Let's Encrypt holt http://<domain>/.well-known/acme-challenge/<token> -- PUBLIC, kein
// WAN-Guard, keine Session (die CA hat keine). Antwort = Key-Authorization (token.thumbprint).
void handleAcmeChallenge(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String token = req.pathParam("token"), ka;
    bool hit = acmeChallengeLookup(token, ka);
    Serial.printf("ACME-Challenge von %s: %s\n", req.clientIp().c_str(), hit ? "beantwortet" : "unbekanntes Token");
    res.header("Cache-Control", "no-store");
    if (hit) res.send(200, "application/octet-stream", ka);
    else     res.send(404, "text/plain", "no active challenge");
}

// Port-80-Hilfsserver bei HTTPS-Betrieb: alles ausser der Challenge -> 301 auf https://.
void handleHttpToHttpsRedirect(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String host = req.header("Host");
    int c = host.indexOf(':'); if (c > 0) host = host.substring(0, c);
    if (host.length() == 0) host = dyndnsDomain.length() ? dyndnsDomain : deviceHostname;
    // 302 + no-store, NICHT 301: Browser cachen ein 301 dauerhaft je URL. Schaltet die Verwaltung
    // spaeter zurueck auf HTTP (UI, Konsole 'web http', HTTPS-Fallback), wuerde der Browser
    // http://<host>/ weiter stillschweigend auf das dann tote https:// umbiegen -- "PIN akzeptiert,
    // danach keine Oberflaeche". Ein Geraet, dessen Transport umschaltbar ist, darf nie 301 senden.
    res.header("Cache-Control", "no-store");
    res.redirect("https://" + host + req.path(), 302);
}
#endif // WEIRDOS_FEATURE_ACME (Challenge + Port-80-Redirect)

// Baut die <option>-Liste fuer eine JPEG-Qualitaets-Auswahl ist nicht noetig:
// Qualitaet ist ein Slider. Hier nur die Info-Zeile oben auf der Seite.
void handleSaveCredentials(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    bool enable = req.hasArg("enable");

    String newSsid = req.arg("ssid");
    String newPassword = req.arg("password");
    newSsid.trim();

    bool persistCredentials = req.hasArg("persist");

    if (persistCredentials) {
        saveWifiCredentials(newSsid, newPassword);
    } else {
        clearStoredCredentials();
        setSessionCredentials(newSsid, newPassword);
    }

    // WLAN-Stack Auto/An/Aus (erstes Feld im Formular -- entscheidet, ob ueberhaupt etwas
    // darunter geladen wird). Fehlt das Feld (alte/gecachte Seite), Wert unveraendert lassen.
    if (req.hasArg("wifistack")) {
        wifiStackModeSave(wifiStackModeFromStr(req.arg("wifistack")));
    }
    saveApPreference(req.hasArg("keepap"));
    saveTargetEnabled(enable);

    Serial.print("Network config saved: wifistack=");
    Serial.print(wifiStackModeToStr(wifiStackMode()));
    Serial.print(", target=");
    Serial.print(enable ? "on" : "off");
    Serial.print(", ssid=");
    Serial.println(newSsid);

    // Neustart, damit die Netzwerk-Politik sauber greift (AP/STA-Moduswechsel).
    resNoCache(res);
    res.beginChunked(200, "text/html");
    res.write(
        "<!DOCTYPE html><html lang='de'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='refresh' content='10;url=/'>"
        "<title>Gespeichert</title>"
    );
    res.write(PAGE_STYLE);   // PROGMEM, auf dem ESP32 direkt lesbar
    res.write(
        "</head><body><main>"
        "<h1>Netzwerk gespeichert</h1>"
        "<p>Das Geraet startet neu und uebernimmt die Einstellungen. "
        "Diese Seite laedt in etwa zehn Sekunden neu.</p>"
        "</main></body></html>"
    );
    res.end();

    pendingRestartAt = millis() + 1500;
}


// Werksreset: WLAN, Kamera UND PIN zuruecksetzen, dann Neustart.
void handleForget(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    logHttpRequest(req, "Factory reset");

    preferences.begin("wifi", false);
    preferences.clear();
    preferences.end();

    preferences.begin("camera", false);
    preferences.clear();
    preferences.end();

    preferences.begin("modem", false);
    preferences.clear();
    preferences.end();

    preferences.begin("dyndns", false);
    preferences.clear();
    preferences.end();

    preferences.begin("energy", false);
    preferences.clear();
    preferences.end();

    Serial.println("Factory reset: all preferences cleared (wifi/camera/modem/dyndns/energy).");

    resNoCache(res);
    // Auth-Cookie + Session invalidieren (PIN ist wieder Standard).
    WeirdAuth::invalidate();
    res.header("Set-Cookie", WeirdAuth::clearCookieHeader());
    res.beginChunked(200, "text/html");
    res.write(
        "<!DOCTYPE html><html lang='de'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Zuruecksetzen</title>"
    );
    res.write(PAGE_STYLE);
    res.write(
        "</head><body><main>"
        "<h1>Auf Werkseinstellungen zurueckgesetzt</h1>"
        "<p>WLAN, Kamera, Modem/APN, DynDNS und PIN wurden entfernt. Das Geraet "
        "startet jetzt neu und oeffnet den Setup-Accesspoint <strong>"
    );
    res.write(CONFIG_AP_SSID);
    res.write(
        "</strong>. Standard-PIN ist wieder 0000.</p>"
        "</main></body></html>"
    );
    res.end();

    pendingRestartAt = millis() + 1500;
}


// -----------------------------------------------------------------------------
// Statusendpunkte
// -----------------------------------------------------------------------------

void handleStatusJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    if (weirdReqWanDenied(req)) { res.send(403, "application/json", "{}"); return; }   // kein Info-Leak ueber WAN
    String json = "{";

    json += "\"state\":\"";
    json += wifiStateName();
    json += "\",";

    json += "\"ssid\":\"";
    json += escapeJson(configuredSsid);
    json += "\",";

#if WEIRDOS_FEATURE_WIFI
    json += "\"ip\":\"";
    json += (wifiState == PORTAL_WIFI_CONNECTED)
        ? WiFi.localIP().toString()
        : String("");
    json += "\",";

    json += "\"rssi\":";
    json += (wifiState == PORTAL_WIFI_CONNECTED)
        ? String(WiFi.RSSI())
        : String(0);
    json += ",";

    json += "\"apClients\":";
    json += String(WiFi.softAPgetStationNum());
    json += ",";
#else
    json += "\"ip\":\"\",\"rssi\":0,\"apClients\":0,";   // WLAN nicht im Build
#endif

    json += "\"apActive\":";
    json += setupApActive ? "true" : "false";
    json += ",";

    json += "\"apProtected\":";
    json += setupApPassword.length() ? "true" : "false";
    json += ",";

    json += "\"keepAp\":";
    json += keepApAlways ? "true" : "false";
    json += ",";

    json += "\"targetEnabled\":";
    json += targetNetworkEnabled ? "true" : "false";
    json += ",";

    json += "\"mdns\":\"";
    json += DEVICE_HOSTNAME;
    json += ".local\"";

    json += "}";

    resNoCache(res);
    res.send(200, "application/json", json);
}


// -----------------------------------------------------------------------------
// Mobilfunk-Modem: HTTP-Handler (alle JSON, PIN-geschuetzt)
// -----------------------------------------------------------------------------

// Kleiner JSON-Helfer: {"ok":<bool>,"msg":"..."} + aktueller Modem-Status.
// JSON-Builder (transport-neutral) - von sendModemJson (roh) UND der res-Ueberladung genutzt.
String buildModemStatusJson(bool ok, const String& msg) {
    String json = "{";
    json += "\"ok\":";        json += ok ? "true" : "false";              json += ",";
    json += "\"msg\":\"";     json += escapeJson(msg);                    json += "\",";
    json += "\"status\":\"";  json += escapeJson(modemStatusText());      json += "\",";
    json += "\"linkUp\":";    json += modemLinkUp ? "true" : "false";     json += ",";
    json += "\"backend\":";   json += modemBackendReady() ? "true" : "false"; json += ",";
    json += "\"usbhost\":";   json += usbHostStarted ? "true" : "false";      json += ",";
    json += "\"usbhostreason\":\""; json += escapeJson(usbHostSkipReason);    json += "\",";
    json += "\"ppp\":\"";     json += escapeJson(pppStatusText());        json += "\",";
    json += "\"pppip\":\"";   json += escapeJson(pppIpStr());             json += "\",";
    json += "\"datamode\":\""; json += escapeJson(modemDataMode);         json += "\",";
    json += "\"ecmstatus\":\""; json += escapeJson(ec200aEcm.statusText()); json += "\",";
    // Datenpfad-neutrale WAN-Felder (PPP ODER ECM), OHNE wan_iface (aus cbbed2f/d7a3df):
    json += "\"wanip\":\"";     json += escapeJson(modemWanIp());                              json += "\",";
    json += "\"wanstatus\":\""; json += ((pppIsUp() || ec200aEcm.isUp()) ? "verbunden" : "getrennt"); json += "\",";
    json += "\"wankind\":\"";   json += (pppIsUp() ? "PPP" : (ec200aEcm.isUp() ? "ECM" : "-"));        json += "\",";
    json += ec200aEcm.rateJson(); json += ",";
    json += pppRateJson();
    json += ",";                 json += modemSpeedtestJson();
    json += ",";                 json += modemBandScanJson();
    json += "}";
    return json;
}

// sendModemJson: nur noch die WeirdHttp-Ueberladung (migrierte Handler). Die rohe
// server-Variante + modemGuard() sind mit dem WeirdHttpEsp-Flip entfallen (Auth liegt
// in requireSession vor dem Dispatch).
void sendModemJson(WeirdHttpResponse& res, bool ok, const String& msg) {
    resNoCache(res);
    res.sendJson(buildModemStatusJson(ok, msg));
}


#if WEIRDOS_FEATURE_MODEM   // Modem-Handler
// Speichert APN/Zugangsdaten (NVS) und wendet den Autoconnect an (Modem-Flash).
void handleModemSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String apn = req.arg("apn");       apn.trim();
    String user = req.arg("user");
    String pass = req.arg("pass");
    String pdp = req.arg("pdp");       pdp.trim();
    String auth = req.arg("auth");     auth.trim();
    bool autoconnect = req.hasArg("autoconnect");
    modemAutoStart = req.hasArg("autostart");   // MCU-Autoconnect (kein Modem-Flash)
    modemUsbEnabled = req.hasArg("usben");       // USB-Host-Modem an/aus (wirkt nach Neustart)
    // Hinweis: die Datenschicht (PPP/ECM) hat einen EIGENEN Tab + Endpoint
    // (/modem-datalink, handleDatalinkSave) - hier bewusst NICHT anfassen.

    if (pdp != "IPV4V6") pdp = "IP";
    if (auth != "1" && auth != "2") auth = "0";

    modemApn = apn;
    modemUser = user;
    modemPass = pass;
    modemPdpType = pdp;
    modemAuth = auth;

    // Einwahlnummer (leer -> Default), SIM-PIN (leer = behalten, Secret nie zum Browser),
    // WAN-Art (nur cellular ist real; dsl/docsis/ftth sind Struktur/Stub).
    String dialnum = req.arg("dialnum"); dialnum.trim();
    modemDialNumber = dialnum.length() ? dialnum : String(MODEM_DIAL_DEFAULT);
    if (req.hasArg("simpin")) { String sp = req.arg("simpin"); sp.trim(); if (sp.length()) modemSimPin = sp; }
    if (req.hasArg("simpinclear")) modemSimPin = "";   // gespeicherte PIN bewusst loeschen (leeres Feld = unveraendert)
    // (Die fruehere "Zugangsart"-Ansicht (wantype) ist entfallen: die Wahl des Netzzugangs ist die
    //  WanPolicy oben auf der Seite -- eine Wahrheit, kein Anzeige-Duplikat mehr.)

    bool autoChanged = (autoconnect != modemAutoconnect);
    modemAutoconnect = autoconnect;

    // USB-Port-Zuordnung des Modems (cellular0) in die Peripherie-Registry schreiben -
    // EINE Wahrheit, kein separates modemUsbPort. Rein deklarativ (kein USB-Umbau).
    if (req.hasArg("port")) periphSaveModemPort(req.arg("port"));

    saveModemPrefs();

    Serial.print("Modem config saved: apn=");
    Serial.print(modemApn);
    Serial.print(", pdp=");
    Serial.print(modemPdpType);
    Serial.print(", autoconnect=");
    Serial.println(modemAutoconnect ? "on" : "off");

    // Autoconnect in den Modem-Flash schreiben bzw. deaktivieren.
    String msg = "Einstellungen gespeichert.";
    if (autoChanged) {
        msg += " ";
        msg += modemApplyAutoconnect(modemAutoconnect);
    }

    sendModemJson(res, true, msg);
}


// Datenschicht PPP<->ECM speichern und (optional) LIVE umschalten - eigener Tab/Endpoint.
// Der Wechsel braucht einen MODEM-Reboot (usbnet), aber KEINEN ESP-Neustart.
void handleDatalinkSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String oldMode = modemDataMode;
    String dm = req.arg("datamode"); dm.trim();
    modemDataMode = (dm == "ecm") ? "ecm" : "ppp";
    String oldNat = modemNatMode;
    if (req.hasArg("natmode")) modemNatMode = (req.arg("natmode") == "routing") ? "routing" : "nic";
    bool switchNow = req.hasArg("switchnow");
    saveModemPrefs();

    String msg = "Datenschicht gespeichert: " + modemDataMode + " (" + modemNatMode + ").";
    // Umschalten, wenn die Datenschicht ODER (bei ECM) die NIC-Betriebsart geaendert wurde.
    bool natChanged = (modemDataMode == "ecm" && modemNatMode != oldNat);
    ecmFallbackReset();   // ein bewusster Wechsel hebt einen PPP-Rueckfall auf (ECM erneut versuchen)
    if (switchNow && (modemDataMode != oldMode || natChanged)) {
        if (oldMode == "ecm") { ecmStopSupervisor(); ec200aEcm.stop(); }
        else                  { pppStop(); pppFreeBuffers(); }   // PPP-Pools freigeben (RAM fuer ECM+Kamera)
        // Modem am USB auf den passenden Modus umschalten (usbnet) + Reboot, dann
        // den ausgewaehlten Datenpfad ueber die EINE Weiche hochziehen.
        if (modemDataMode == "ecm") msg += " " + ecmSwitchModemUsbnet(1);   // usbnet=1 (ECM)
        else                        msg += " " + ecmSwitchModemUsbnet(3);   // usbnet=3 (RNDIS -> PPP)
        if (modemDataMode == "ecm") msg += " " + ecmSwitchModemNat(modemNatMode == "routing" ? 0 : 1);
        msg += " " + modemReset();                   // AT+CFUN=1,1 -> Modem-Reboot
        startModemDataSupervisor();
        msg += " Modem startet neu (~15-30s); danach ohne ESP-Neustart aktiv.";
    }
    sendModemJson(res, true, msg);
}


// Mobilfunk-Band/RAT speichern + anwenden (WAN -> Modem -> Frequenzen).
void handleModemBandSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String prof = req.arg("profile"); prof.trim();
    if (prof != "mid" && prof != "low" && prof != "custom") prof = "auto";
    modemBandProfile = prof;

    // Custom-Maske (bare-hex, ohne 0x) nur bei Profil "custom" uebernehmen.
    if (prof == "custom") {
        String bc = req.arg("bandc"); bc.trim();
        bc.replace("0x", ""); bc.replace("0X", "");
        modemBandCustom = bc;
    }

    String nm = req.arg("netmode"); nm.trim();
    if (nm != "lte" && nm != "gsm") nm = "auto";
    modemNetMode = nm;

    saveModemPrefs();

    Serial.print("Band config saved: profile=");
    Serial.print(modemBandProfile);
    Serial.print(", netmode=");
    Serial.println(modemNetMode);

    sendModemJson(res, true, modemApplyBands());
}


void handleModemConnect(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    String msg = modemLinkConnect();                 // neutrale Weiche (ppp|ecm), DynDNS inklusive
    sendModemJson(res, modemLinkIsUp(), msg);
}


void handleModemDisconnect(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    sendModemJson(res, true, modemLinkDisconnect());      // neutrale Weiche (ppp|ecm)
}


void handleModemReset(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    sendModemJson(res, true, modemReset());
}


void handleModemTest(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    String msg = modemRunInternetTest();
    // "ok" nur, wenn der Test-String nicht mit "Test nicht" beginnt.
    bool ok = (pppIsUp() || ec200aEcm.isUp()) && !msg.startsWith("Test nicht");
    sendModemJson(res, ok, msg);
}

// LTE-Speedtest anstossen (laeuft im Treiber-Task; UI pollt ueber modem-status.json).
void handleSpeedtestStart(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    int  conn     = req.hasArg("conn") ? req.arg("conn").toInt() : 0;   // 0 = gespeicherte Vorgabe
    bool autoMode = req.hasArg("auto") && req.arg("auto") == "1";
    String msg = modemSpeedtestStart(conn, autoMode);
    sendModemJson(res, pppIsUp() || ec200aEcm.isUp(), msg);
}

// Best-SINR-Bandscan anstossen (laeuft im Treiber-Task; UI pollt modem-status.json).
void handleBandScanStart(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    sendModemJson(res, true, modemStartBandScan());
}

// Nachbarzellen roh (Diagnose, Text). PPP muss getrennt sein.
void handleNeighbours(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "text/plain", modemNeighbourDump());
}

// SIM-PIN-Sperre auf der Karte (Status / aktivieren / deaktivieren / aendern) -- modem_sim.*.
// Nur bei getrennter Verbindung: im Datenmodus ist der AT-Port (IF3) nicht frei nutzbar.
void handleSimPinManage(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    logHttpRequest(req, "SIM-PIN");
    resNoCache(res);
    if (pppIsUp() || ec200aEcm.isUp()) {
        res.send(200, "application/json", "{\"ok\":false,\"msg\":\"Nur bei getrennter Verbindung moeglich (AT-Port im Datenmodus belegt) - erst Trennen.\"}");
        return;
    }
    if (!modemDeviceHandle()) {
        res.send(200, "application/json", "{\"ok\":false,\"msg\":\"Kein Modem am USB.\"}");
        return;
    }
    String action = req.arg("action"); action.trim();
    String pin    = req.arg("pin");    pin.trim();
    String np     = req.arg("newpin"); np.trim();
    res.send(200, "application/json", modemSimPinManage(action, pin, np));
}
#endif // WEIRDOS_FEATURE_MODEM (Modem-Handler)

// Allgemeiner Systemstatus (Diagnose -> Funktion): Laufzeit, RAM/PSRAM, CPU, WLAN.
// 7.4d.3: WireGuard-Crash-Lokalisierung. RTC_NOINIT ueberlebt den Panic-Reboot (nicht
// den Stromausfall). begin() setzt den Marker an jedem Sub-Schritt; nach einem PANIC sagt
// /sysinfo.json (wgstage) exakt, welcher Schritt zuletzt lief. Serial ist hier nicht lesbar
// (USB haengt am Modem), daher dieser In-Band-Weg.
RTC_NOINIT_ATTR volatile uint32_t g_wgCrashStage;

// Gleiche In-Band-Diagnose fuer den App-Seiten-Render (sendAppPage): vor jedem Renderer
// gesetzt. Ueberlebt einen Panic-Reboot (RTC_NOINIT) -> nach dem Reboot verraet
// /sysinfo.json (httpstage) EXAKT, in welchem Renderer es zuletzt war = die Absturzstelle.
// Serial ist am P4 nicht lesbar (USB=Modem), daher dieser Weg.
RTC_NOINIT_ATTR volatile uint32_t g_httpRenderStage;

static const char* resetReasonStr() {
    switch (esp_reset_reason()) {
        case ESP_RST_POWERON:   return "POWERON";
        case ESP_RST_EXT:       return "EXT";
        case ESP_RST_SW:        return "SW";
        case ESP_RST_PANIC:     return "PANIC";
        case ESP_RST_INT_WDT:   return "INT_WDT";
        case ESP_RST_TASK_WDT:  return "TASK_WDT";
        case ESP_RST_WDT:       return "WDT";
        case ESP_RST_BROWNOUT:  return "BROWNOUT";
        case ESP_RST_DEEPSLEEP: return "DEEPSLEEP";
        default:                return "UNKNOWN";
    }
}

void handleSysinfoJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    unsigned long up = millis() / 1000UL;
    String j = "{\"ok\":true";
    j += ",\"resetreason\":\""; j += resetReasonStr(); j += "\"";
    j += ",\"wgstage\":"; j += (uint32_t)g_wgCrashStage;
    j += ",\"httpstage\":"; j += (uint32_t)g_httpRenderStage;   // letzter App-Render-Schritt (Absturzstelle nach Panic)
    j += ",\"dyndnsheal\":"; j += (uint32_t)g_dyndnsHealReboots;   // 7.9.12: Selbstheilungs-Reboots (Boot-Loop-Deckel)
    j += ",\"cryptomem\":\""; j += (g_cryptoMemPsram && psramFound()) ? "psram" : "internal"; j += "\"";  // 7.9.14
    j += ",\"heaplargest\":";  j += (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);       // Beweis-Telemetrie
    j += ",\"psramlargest\":"; j += (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    j += ",\"uptime\":";  j += up;
    j += ",\"time\":\"";  j += systemClockIso(); j += "\"";   // UTC aus dem Mobilfunknetz ("-" = Uhr ungesetzt)
    j += ",\"heap\":";    j += (uint32_t)ESP.getFreeHeap();
    j += ",\"heapmin\":"; j += (uint32_t)ESP.getMinFreeHeap();
    j += ",\"psram\":";   j += (uint32_t)ESP.getFreePsram();
    j += ",\"psramtot\":";j += (uint32_t)ESP.getPsramSize();
    j += ",\"cpu\":";     j += getCpuFrequencyMhz();
#if WEIRDOS_FEATURE_WIFI
    j += ",\"wifirssi\":";j += WiFi.RSSI();
    j += ",\"wifiip\":\"";j += WiFi.localIP().toString();  j += "\"";
    j += ",\"apip\":\"";  j += WiFi.softAPIP().toString();  j += "\"";
#else
    j += ",\"wifirssi\":0,\"wifiip\":\"\",\"apip\":\"\"";   // WLAN nicht im Build
#endif
    j += ",\"camera\":";  j += cameraReady ? "true" : "false";
    j += ",\"usb\":\"";   j += escapeJson(modemStatusText()); j += "\"";
    j += ",\"flash\":";   j += (uint32_t)ESP.getFlashChipSize();
    j += "}";
    resNoCache(res);
    res.send(200, "application/json", j);
}

#if WEIRDOS_FEATURE_BACKUP   // Export/Import-Handler
// Vollstaendige Sicherung exportieren (System -> Sicherung) ueber den zentralen
// NVS-Manager -> automatisch ALLE Namespaces, OHNE Secrets (Denylist). Nach einem
// Restore sind Passwoerter/PIN neu zu setzen.
void handleSettingsExport(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.header("Content-Disposition", "attachment; filename=weirdos-backup.cfg");
    res.send(200, "text/plain", settingsBackupExport());
}

// Sicherung einspielen (Upload). Body wird im Upload-Callback gesammelt, im Finish
// in den NVS geschrieben, danach Neustart (Subsysteme laden Config frisch beim Boot).
static String g_importBuf;
static bool   g_importAuthed = false;
void handleSettingsImportUpload(WeirdHttpRequest& req, const WeirdHttpUpload& up) {
    if (up.phase == UploadPhase::Start) {
        g_importAuthed = WeirdAuth::authorized(req.cookie(WeirdAuth::cookieName()), weirdReqIsWan(req.clientIp()));
        g_importBuf = "";
    } else if (up.phase == UploadPhase::Write) {
        if (g_importAuthed && up.len) g_importBuf.concat((const char*)up.data, up.len);
    }
}
void handleSettingsImportFinish(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    if (!g_importAuthed) { g_importBuf = ""; res.send(403, "text/plain; charset=utf-8", "PIN erforderlich."); return; }
    int n = settingsBackupImport(g_importBuf);
    g_importBuf = "";
    logEvent("Sicherung eingespielt");
    resNoCache(res);
    res.send(200, "text/plain; charset=utf-8", String("OK - ") + n + " Eintraege wiederhergestellt. Neustart in ~2 s ...");
    delay(1500);
    ESP.restart();
}
#endif // WEIRDOS_FEATURE_BACKUP (Export/Import-Handler)

// Peripherie: "Neue Geraete suchen" -> USB-Host bei Bedarf OHNE Neustart starten (HotPlug auf Abruf).
// Gated: nur wenn Host noch nicht laeuft, Modem-Modus an und KEIN PC/Netzteil am USB-Port (SOF).
// Die Geraete-Erkennung selbst ist live (periphBuildModel liest modemDeviceHandle()).
// Telemetrie: interner Heap-Zustand ins Ereignis-Log (System > Ereignisse). Damit laesst sich
// ueber Boot + wiederholte Scans beweisen: flach = einmalige USB-Kosten, fallend = echtes Leak.
void logHeapMark(const char* tag) {
    uint32_t freeKb = (uint32_t)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024);
    uint32_t largestKb = (uint32_t)(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) / 1024);
    logEvent(String("[heap] ") + tag + ": intern frei " + String(freeKb) + "k, groesster " + String(largestKb) + "k");
    if (g_heapMilestoneCount < HEAP_MILESTONE_MAX) {
        g_heapMilestones[g_heapMilestoneCount++] = { tag, freeKb, largestKb };
    }
}

void handlePeriphRescan(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    String msg; bool ok = true;
    if (usbHostStarted) {
        msg = "USB-Host laeuft bereits -- Geraeteliste wird live aktualisiert.";
    }
#if WEIRDOS_FEATURE_MODEM
    else if (!modemUsbEnabled) {
        ok = false; msg = "USB-Modem ist unter WAN -> Modem deaktiviert.";
    } else if (usbDeviceService.conflictsWithModemPort()) {
        ok = false; msg = "Der USB-Port " + periphModemPort + " ist als PC-Geraet (Webcam) konfiguriert -- der Modem-Host bleibt aus "
                          "(System > Geraete > Bereitstellen an USB, anderen Port waehlen, Neustart).";
#if !CONFIG_IDF_TARGET_ESP32P4
    } else if (usbPcConnected()) {
        ok = false; msg = "Am USB-Port haengt ein PC/Netzteil (Programmiermodus) -- der Host bleibt aus. "
                          "Versorge den ESP anders, stecke das Modem an den USB-Port und suche erneut.";
#endif
    }
#endif // WEIRDOS_FEATURE_MODEM
    else {
        startUsbHost();
        usbHostStarted = modemUsbHostReady;   // nur bei Erfolg (sonst wurde alles zurueckgerollt)
        if (usbHostStarted) {
            usbHostSkipReason = "";
            msg = "USB-Host gestartet -- die Modem-Erkennung laeuft (einige Sekunden). Danach neu laden.";
        } else {
            ok = false;
            msg = "USB-Host-Start fehlgeschlagen (Ressourcen zurueckgerollt): " + modemUsbError;
        }
    }
    logHeapMark("periph-rescan");   // Telemetrie: interner Heap nach dem Scan (Leak vs. USB-Kosten)
    resNoCache(res);
    res.send(200, "application/json", String("{\"ok\":") + (ok ? "true" : "false") + ",\"msg\":\"" + escapeJson(msg) + "\"}");
}

#if WEIRDOS_FEATURE_OTA   // Upload-Handler
// --- OTA-Firmware-Update ueber die Weboberflaeche (System -> Update) ---
// Kein Brick-Risiko: schlaegt Update.begin/end fehl (z.B. kein OTA-Partitions-
// schema), bleibt die laufende Firmware aktiv. Auth wird beim Upload-Start
// geprueft; ohne PIN wird nichts geschrieben.
static bool g_otaAuthed = false;
void handleOtaFinish(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    bool ok = g_otaAuthed && !Update.hasError();
    resNoCache(res);
    res.send(200, "text/plain; charset=utf-8", ok
        ? "OK - Update geschrieben. Neustart in ~2 s ..."
        : "FEHLER - nicht geschrieben (PIN? OTA-faehiges Partitionsschema?).");
    if (ok) { delay(1500); ESP.restart(); }
}
void handleOtaUpload(WeirdHttpRequest& req, const WeirdHttpUpload& up) {
    if (up.phase == UploadPhase::Start) {
        g_otaAuthed = WeirdAuth::authorized(req.cookie(WeirdAuth::cookieName()), weirdReqIsWan(req.clientIp()));
        if (!g_otaAuthed) return;
        logEvent("OTA-Update gestartet");
        if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
    } else if (up.phase == UploadPhase::Write) {
        if (g_otaAuthed && up.len) Update.write((uint8_t*)up.data, up.len);
    } else if (up.phase == UploadPhase::End) {
        if (g_otaAuthed) {
            if (Update.end(true)) Serial.printf("[ota] OK: %u Bytes\n", (unsigned)up.total);
            else Update.printError(Serial);
        }
    }
}
#endif // WEIRDOS_FEATURE_OTA (Upload-Handler)

// Ereignis-Log als JSON (System -> Ereignisse), aeltestes zuerst.
void handleEventsJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    String j = "{\"ok\":true,\"now\":"; j += (unsigned long)(millis() / 1000UL);
    j += ",\"events\":[";
    int idx = (g_eventHead - g_eventCount + EVENT_LOG_N) % EVENT_LOG_N;
    for (int i = 0; i < g_eventCount; i++) {
        if (i) j += ",";
        int k = (idx + i) % EVENT_LOG_N;
        j += "{\"t\":"; j += (unsigned long)(g_events[k].ms / 1000UL);
        j += ",\"m\":\""; j += escapeJson(g_events[k].text); j += "\"}";
    }
    j += "]}";
    resNoCache(res);
    res.send(200, "application/json", j);
}


void handleModemStatusJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    sendModemJson(res, true, modemLastMessage);
}


// DynDNS-Einstellungen speichern (NVS). Der Update-Loop folgt mit PPP.
#if WEIRDOS_FEATURE_DYNDNS   // Save-Handler
void handleDyndnsSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    dyndnsEnabled = req.hasArg("enabled");

    // Anbieter: aktuell nur "custom" (Benutzerdefiniert) zulaessig.
    String prov = req.arg("provider");
    dyndnsProvider = (prov == "custom") ? prov : String("custom");

    // Update-URL verbatim uebernehmen (nicht normalisieren/umschreiben).
    dyndnsUrl    = req.arg("url");
    dyndnsDomain = req.arg("domain"); dyndnsDomain.trim();
    dyndnsUser   = req.arg("user");   dyndnsUser.trim();

    // Kennwort NUR ersetzen, wenn tatsaechlich ein neues eingegeben wurde.
    // Leer abgeschickt => bestehendes Kennwort bleibt erhalten.
    String newPass = req.arg("pass");
    if (newPass.length() > 0) {
        dyndnsPass = newPass;
    }

    // Ausgehendes Netz (Egress-Interface): auto | modem | wifi.
    String egr = req.arg("egress");
    dyndnsEgress = (egr == "modem" || egr == "wifi") ? egr : String("auto");

    saveDyndnsPrefs();

    Serial.print("DynDNS saved: enabled=");
    Serial.print(dyndnsEnabled ? "on" : "off");
    Serial.print(", domain=");
    Serial.println(dyndnsDomain);

    resNoCache(res);
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"DynDNS gespeichert.\"}");
}
#endif // WEIRDOS_FEATURE_DYNDNS (Save-Handler)


// DynDNS-Status fuer die Oberflaeche (Freigaben -> DynDNS).
// Stufe 7.4c: WireGuard-Konfiguration speichern (Secrets leer = behalten, nie zurueck).
void handleWgSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    // 7.9: rollenabhaengig. Basis = bestehende Config, damit die jeweils ANDERE Rolle nicht
    // ueberschrieben wird. mode = "server" (Standard) oder "client".
    WireGuardConfig cfg = wireguardService.config();
    bool client = (req.arg("mode") == "client");
    cfg.mode = client ? "client" : "server";
    cfg.active = req.hasArg("active");

    // Gemeinsame / erweiterte Felder nur uebernehmen, wenn das Formular sie schickt.
    if (req.hasArg("underlay")) cfg.underlay = req.arg("underlay");
    if (req.hasArg("localip"))  { cfg.localIp = req.arg("localip"); cfg.localIp.trim(); }
    if (req.hasArg("keepalive")){ int ka = req.arg("keepalive").toInt(); cfg.keepalive = (uint16_t)((ka >= 0 && ka <= 65535) ? ka : 25); }
    if (req.hasArg("routing"))  cfg.fullTunnel = (req.arg("routing") == "full");
    if (req.hasArg("epport"))   { int ep = req.arg("epport").toInt(); uint16_t p = (uint16_t)((ep >= 1 && ep <= 65535) ? ep : 51820);
                                     if (client) cfg.clientPort = p; else cfg.endpointPort = p; }

    if (client) {
        cfg.clientEndpoint  = req.arg("ephost");  cfg.clientEndpoint.trim();
        cfg.clientPeerPub   = req.arg("peerpub"); cfg.clientPeerPub.trim();
        if (req.hasArg("allowed")) { cfg.clientAllowedIps = req.arg("allowed"); cfg.clientAllowedIps.trim(); }
    } else {
        cfg.peerPublicKey   = req.arg("peerpub"); cfg.peerPublicKey.trim();
        if (req.hasArg("allowed")) { cfg.allowedIps = req.arg("allowed"); cfg.allowedIps.trim(); }
        cfg.lanGateway = req.hasArg("langw");   // 7.6 LAN-Gateway (NAPT), nur Server-Rolle
        if (req.hasArg("lantgt")) cfg.lanTarget = req.arg("lantgt");   // 7.8
    }

    String privKey = req.arg("privkey");   // leer = behalten
    String psk     = req.arg("psk");        // leer = behalten
    wireguardService.saveConfig(cfg, privKey, psk);

    // 7.9.1: kein manueller Start/Stop mehr. Aktiv gespeichert -> sofort (neu) starten (damit
    // die neue Config greift); inaktiv -> stoppen. Der Supervisor haelt es danach am Leben.
    String msg;
    if (cfg.active) {
        wireguardService.disconnect();               // laufende Instanz sauber beenden
        String err = wireguardService.connect();     // mit neuer Config starten
        if (err.length()) msg = err;                 // z.B. "Noch kein Client - erst 'Geraet hinzufuegen'."
        else msg = client ? "Gespeichert - Verbindung wird aufgebaut." : "Gespeichert - VPN-Server laeuft.";
    } else {
        wireguardService.disconnect();
        msg = client ? "Gespeichert - getrennt." : "Gespeichert - VPN-Server gestoppt.";
    }
    resNoCache(res);
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"" + escapeJson(msg) + "\"}");
}


// Stufe 7.4d: WireGuard manuell verbinden/trennen + Status.
void handleWgConnect(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    String err = wireguardService.connect();
    resNoCache(res);
    if (err.length()) res.send(200, "application/json", "{\"ok\":false,\"msg\":\"" + escapeJson(err) + "\"}");
    else              res.send(200, "application/json", "{\"ok\":true,\"msg\":\"Verbinde ...\"}");
}
void handleWgDisconnect(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    wireguardService.disconnect();
    resNoCache(res);
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"Getrennt.\"}");
}
void handleWgStatusJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", wireguardService.statusJson());
}

// Uebersicht > VPN: EIN Statusmodell fuer alle Tunnel (vpn_status.h). Die Dienst-Seiten zeigen
// keinen Status mehr; ihre JSONs (/wg-status.json, /ipsec-status.json) bleiben fuer Public Key,
// Client-/Benutzerlisten und das IKE-Protokoll.
void handleVpnStatusJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", vpnStatusJsonAll());
}

// 8.1: IPsec/IKEv2(+L2TP) - Config/Status analog WireGuard. Client-Rolle ist Default/wichtigste.
void handleIpsecSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    // EIN Feld-Layer fuer Web und serielle Konsole (ipsec_config_fields): jedes Formularfeld wird ueber
    // dieselbe Feldbeschreibung geparst/geprueft wie 'ipsec set <key>' auf der Konsole. Marker (fv2/fv3/
    // fv4) schuetzen weiterhin vor alten Formularen, Checkboxen behalten ihre "fehlt = aus"-Semantik.
    IpsecConfig cfg = ipsecService.config();   // Basis: andere Rolle nicht ueberschreiben
    bool client = (req.arg("mode") != "server");   // Default = client
    cfg.mode = client ? "client" : "server";
    String r;
    int nf = 0; const IpsecFieldDef* ft = ipsecFieldTable(nf);
    for (int i = 0; i < nf && !r.length(); i++) {
        const IpsecFieldDef& f = ft[i];
        if (!f.webArg || f.type == IpsecFieldType::Secret || !strcmp(f.key, "mode")) continue;
        if ((f.role == IpsecFieldRole::Client && !client) || (f.role == IpsecFieldRole::Server && client)) continue;
        if (f.webMarker && !req.hasArg(f.webMarker)) continue;            // altes Formular: Feld unveraendert lassen
        if (f.webCheckbox) { String e = ipsecFieldSet(cfg, f, req.hasArg(f.webArg) ? "1" : "0"); if (e.length()) r = e; continue; }
        if (!req.hasArg(f.webArg)) continue;                              // nicht gesendet = unveraendert
        String e = ipsecFieldSet(cfg, f, req.arg(f.webArg));
        if (e.length()) r = e;
    }
    if (client && !req.hasArg("srvport")) cfg.serverPort = 500;         // wie bisher: fehlender Port = 500
    String psk     = req.arg("psk");       // leer = behalten
    String eapPass = req.arg("eappass");   // leer = behalten
    if (!r.length()) r = ipsecService.saveConfig(cfg, psk, eapPass);   // NUR Persistenz (kein Connect/Disconnect)
    else r = "Nicht gespeichert: " + r;
    // Serial-Spur fuer die Hardware-Diagnose: kam der POST an, und mit welchem Server?
    Serial.printf("[ipsec] Config-POST: mode=%s active=%d server=%s:%u -> %s\r\n",
                  cfg.mode.c_str(), cfg.active ? 1 : 0, cfg.serverHost.c_str(), (unsigned)cfg.serverPort,
                  r.length() ? r.c_str() : "gespeichert");
    resNoCache(res);
    if (r.length()) { res.send(200, "application/json", "{\"ok\":false,\"msg\":\"" + escapeJson(r) + "\"}"); return; }
    String msg = "Konfiguration gespeichert (Server " + cfg.serverHost + ", IDi = " + IpsecService::idText(cfg.localIdType, cfg.localId) + "). ";
    if (!cfg.active)                   msg += "Verbindung inaktiv.";
    else if (ipsecService.isUp())      msg += "Die laufende Verbindung verwendet noch die vorherige Konfiguration - 'Neu verbinden' uebernimmt die Aenderungen.";
    else if (cfg.autoConnect)          msg += "Es steht keine Verbindung - sie wird jetzt mit dieser Konfiguration aufgebaut (Status auf der Uebersicht).";
    else                               msg += "Automatisches Verbinden ist aus - 'Neu verbinden' startet die Verbindung.";
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"" + escapeJson(msg) + "\"}");
}

// Betriebsart (Netzwerk-Modus, Phase 1): plain Form-POST -> speichern -> Redirect (POST/Redirect/GET).
// PHASE 1 speichert NUR; die Laufzeit-Umschaltung ist noch inaktiv (netmode.apply() = No-op).
// Betriebsart: waehlt nur noch Modus + WAN. Die uebrigen Felder (AP-Kanal, LAN-Subnetz,
// Captive-DNS, Forwarding) haben eigene, seiten-lokale Save-Endpunkte -> kein Clobbern.
void handleOpmodeSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    NetworkModeConfig c = networkMode.config();   // Basis behalten -- nur mode/wan anfassen
    if (req.hasArg("mode")) c.mode = NetworkModeService::modeFromId(req.arg("mode"));
    if (req.hasArg("wan"))  { String v = req.arg("wan"); c.wan = (v=="modem"||v=="wifi"||v=="auto") ? v : String("auto"); }
    networkMode.saveConfig(c);   // nur persistieren -- KEIN apply (Default-Verhalten unveraendert)
    resNoCache(res);
    uiRedirectBack(req, res);
}

// Einrichtung > Assistent: kaskadierende Wizard-Wahl. Speichert usecase/apInternet/accessModel
// + Upstream (wan) und LEITET daraus mode + forwarding ab (Vorwaerts-Kompat). PHASE 1: kein apply.
void handleWizardSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    NetworkModeConfig c = networkMode.config();

    String uc = req.arg("usecase"); if (uc != "ap") uc = "endpoint";
    // Effektive Entscheidung (Hardware UND nicht per LAN > WLAN auf "Aus" gestellt) -- serverseitig
    // dieselbe Schwelle wie im Assistenten-UI (ui_netmode.cpp), sonst liesse sich "ap" per direktem
    // POST speichern, obwohl der WLAN-Stack beim naechsten Boot gar nicht laeuft.
    if (uc == "ap" && !wifiStackShouldInit()) uc = "endpoint";
    bool   ai = (req.arg("apinet") == "1") && (uc == "ap");
    String am = req.arg("accmodel"); if (am != "repeater" && am != "guest") am = "gateway";
    if (am == "repeater" && !repeaterCapable()) am = "gateway";   // ausgegraut -> nie speichern

    // WAN-Wahl des Assistenten schreibt DIESELBE WanPolicy wie WAN -> Uplink (keine zweite
    // Wahrheit). Mapping modem->cellular; wirkt sofort (WanService konsumiert die Policy).
    if (req.hasArg("wan")) {
        String v = req.arg("wan");
        WanPolicy wp; wp.preference = (v == "modem") ? "cellular" : ((v == "wifi") ? "wifi" : "auto");
        wanSaveConfig(wp);
    }

    c.usecase = uc; c.apInternet = ai; c.accessModel = am;

    // Abgeleiteter Modus + Forwarding (Assistent belegt die tieferen Ebenen vor):
    if (uc != "ap")            c.mode = NETMODE_LEGACY;      // nur Endpunkt = heutiger Default
    else if (!ai)              c.mode = NETMODE_LOCAL_AP;    // AP ohne Internet
    else if (am == "repeater") c.mode = NETMODE_REPEATER;
    else                       c.mode = NETMODE_ROUTER;      // gateway | guest = NAT-Router
    c.forwarding = ai ? "napt" : "none";

    networkMode.saveConfig(c);   // PHASE 1: nur persistieren, kein apply
    resNoCache(res);
    uiRedirectBack(req, res);
}

// LAN > Allgemein: Router-LAN-Subnetz. (Captive-DNS ist nach Einrichtung > Setup-Portal gewandert.)
void handleLanGeneralSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    NetworkModeConfig c = networkMode.config();
    if (req.hasArg("lansub")) { c.lanSubnet = req.arg("lansub"); c.lanSubnet.trim(); }
    networkMode.saveConfig(c);
    markRestartRequired("LAN-Subnetz");   // wirkt erst beim Boot -> gelbe Box
    resNoCache(res);
    uiRedirectBack(req, res);
}

// LAN > WLAN > Funknetz: EIN AP-Kanal-Dropdown. "auto" -> follow, Zahl 1..13 -> fixed+Kanal.
void handleWlanApChannelSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    NetworkModeConfig c = networkMode.config();
    String v = req.arg("apchan"); v.trim();
    if (v == "auto" || v.length() == 0) {
        c.apChannelPol = "follow";
    } else {
        int ch = v.toInt();
        c.apChannelPol = "fixed";
        c.apChannel = (uint8_t)((ch >= 1 && ch <= 13) ? ch : 6);
    }
    networkMode.saveConfig(c);
    markRestartRequired("AP-Kanal");   // wirkt erst beim Boot -> gelbe Box
    resNoCache(res);
    uiRedirectBack(req, res);
}

// WAN > Firewall & NAT: Forwarding/NAPT.
void handleWanForwardingSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    NetworkModeConfig c = networkMode.config();
    if (req.hasArg("fwd")) { String v = req.arg("fwd"); c.forwarding = (v=="napt"||v=="none") ? v : String("none"); }
    networkMode.saveConfig(c);
    markRestartRequired("Forwarding/NAT");   // wirkt erst beim Boot -> gelbe Box
    resNoCache(res);
    uiRedirectBack(req, res);
}

// Einrichtung > Setup-Portal: Captive-Modus (auto/off) + Werksreset-Config (BOOT-Taste).
void handleSetupPortalSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    SetupGuardConfig sg = setupGuardGet();
    sg.captiveMode  = req.hasArg("captiveoff") ? "off" : "auto";   // Checkbox = Portal deaktivieren
    sg.resetEnabled = req.hasArg("rsten");
    if (req.hasArg("rsthold")) {
        long s = req.arg("rsthold").toInt();
        if (s < 3)   s = 3;
        if (s > 120) s = 120;
        sg.resetHoldMs = (uint32_t)s * 1000UL;
    }
    sg.fullEnabled = req.hasArg("fullen");
    if (req.hasArg("fullhold")) {
        long s = req.arg("fullhold").toInt();
        if (s < 5)   s = 5;
        if (s > 300) s = 300;
        sg.fullHoldMs = (uint32_t)s * 1000UL;
    }
    setupGuardSave(sg);   // clamped: fullHold > resetHold
    resNoCache(res);
    uiRedirectBack(req, res);
}

// Einrichtung > Setup > UART: Baudrate der seriellen Konsole (NVS, wirkt ab Neustart). Nur bekannte
// Standardraten werden uebernommen (serial_console.cpp), sonst bleibt der alte Wert.
// Gelbe Box "Neustart erforderlich": Zustand fuer die UI (alle Seiten pollen das leichtgewichtig).
void handleRestartRequiredJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req; resNoCache(res);
    res.send(200, "application/json", String("{\"required\":") + (g_restartReasons.length() ? "true" : "false") + ",\"why\":\"" + escapeJson(g_restartReasons) + "\"}");
}
// USB-Geraet am PC (Einrichtung > Setup > USB-Geraet): Webcam (UVC) an/aus, Quelle, Bildrate. Deskriptoren
// werden nur beim Boot gebaut -> Aenderung wirkt nach Neustart (gelbe Box), nie live unter einem Windows-Host.
void handleUsbDevSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    UsbDeviceConfig c = usbDeviceService.config();
    String port = req.arg("usbport"); if (!UsbDeviceService::portValid(port)) port = c.port;
    // Export je Geraet: cam_<geraet>=uvc|off; genau EIN UVC-Export (camera0 hat Vorrang vor testpattern0)
    String cam = "";
    if (req.arg("cam_camera0") == "uvc") cam = "camera0";
    else if (req.arg("cam_testpattern0") == "uvc") cam = "testpattern0";
    int fps = req.hasArg("uvcfps") ? req.arg("uvcfps").toInt() : c.fps; if (fps < 1) fps = 1; if (fps > 30) fps = 30;
    bool changed = (port != c.port) || (cam != c.cam) || (fps != c.fps);
    c.port = port; c.cam = cam; c.fps = (uint8_t)fps;
    usbDeviceService.saveConfig(c);
    if (changed) { logEvent(String("USB-Geraet gespeichert: Port ") + port + ", UVC <- " + (cam.length() ? cam : String("aus")) + ", " + fps + " fps"); markRestartRequired("USB-Geraet (Bereitstellen an USB)"); }
    resNoCache(res);
    res.redirect("/?p=peripherie", 303);
}
// USB-Port-Mapping des Boards: Anzahl + je Port Name, D-/D+ (GPIO, -1 = dedizierte HS-Pads), aktiv. Pins werden
// gegen die Chip-Tabelle geprueft (USB-Pads sind nicht frei waehlbar). Wirkt nach Neustart (Host + Device).
// USB-Port-Mapping aus den Formularfeldern (count, label<i>, dm<i>, dp<i>, en<i>) uebernehmen; "" = ok.
static String usbPortsSaveFromForm(WeirdHttpRequest& req, int& count) {
    count = req.arg("count").toInt(); if (count < 1) count = 1; if (count > USB_PORTS_MAX) count = USB_PORTS_MAX;
    UsbPortEntry e[USB_PORTS_MAX];
    for (int i = 0; i < count; i++) {
        String k = String(i);
        e[i].id = String("USB") + i;
        e[i].label = req.arg(("label" + k).c_str()); e[i].label.trim(); if (!e[i].label.length()) e[i].label = "USB" + k;
        String dm = req.arg(("dm" + k).c_str()), dp = req.arg(("dp" + k).c_str()); dm.trim(); dp.trim();
        e[i].dm = dm.length() ? (int8_t)dm.toInt() : -1; e[i].dp = dp.length() ? (int8_t)dp.toInt() : -1;
        if (!req.hasArg(("dm" + k).c_str())) { e[i].dm = -1; e[i].dp = -1; }
        e[i].enabled = req.hasArg(("en" + k).c_str());
    }
    return usbPortsSave(count, e);
}
void handleUsbPortsSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    int count = 0;
    String err = usbPortsSaveFromForm(req, count);
    resNoCache(res);
    if (err.length()) { res.send(200, "text/html; charset=utf-8", "<!DOCTYPE html><html><body><p>USB-Anschluesse NICHT gespeichert: " + escapeHtml(err) + "</p><p><a href='/?p=peripherie'>zurueck</a></p></body></html>"); return; }
    logEvent("USB-Anschluesse gespeichert (Mapping, " + String(count) + " Ports)");
    markRestartRequired("USB-Anschluesse (Mapping)");
    res.redirect("/?p=peripherie", 303);
}
// Einrichtung > Plattform: Board-Profil setzen (setzt bei Wechsel die USB-Port-Vorgaben des Profils; wirkt nach Neustart).
// EIN Formular fuer die ganze Plattform: Profil + USB-Anschluesse. Ein Profilwechsel setzt die USB-Vorgaben
// des neuen Profils; die mitgeschickten Port-Felder gehoeren dann noch zum alten Profil und werden verworfen.
// Das eigene Pinout-SVG (custom) schickt die Seite vorher separat an /platform-svg (roher Body, kein Formular).
void handlePlatformSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String id = req.arg("id"); id.trim();
    String before = platformId();
    resNoCache(res);
    String err = platformSet(id);
    if (err.length()) { res.send(200, "text/html; charset=utf-8", "<!DOCTYPE html><html><body><p>Plattform NICHT gespeichert: " + escapeHtml(err) + "</p><p><a href='/?p=platform'>zurueck</a></p></body></html>"); return; }
    if (id != before) { logEvent("Plattform-Profil: " + id); markRestartRequired("Plattform-Profil"); }
    else if (req.hasArg("count")) {
        int count = 0;
        err = usbPortsSaveFromForm(req, count);
        if (err.length()) { res.send(200, "text/html; charset=utf-8", "<!DOCTYPE html><html><body><p>Plattform NICHT gespeichert -- USB-Anschluesse: " + escapeHtml(err) + "</p><p><a href='/?p=platform'>zurueck</a></p></body></html>"); return; }
        logEvent("Plattform gespeichert (USB-Mapping, " + String(count) + " Ports)");
        markRestartRequired("Plattform (USB-Anschluesse)");
    }
    res.redirect("/?p=platform", 303);
}
void handlePlatformJson(WeirdHttpRequest& req, WeirdHttpResponse& res) { (void)req; resNoCache(res); res.send(200, "application/json", platformJson()); }
// Pinout-Bild; ?profile=<id> = Vorschau eines anderen Profils mit dessen USB-Vorgaben (nichts gespeichert).
// CSP: ein hochgeladenes SVG darf beim Direktaufruf keine Skripte ausfuehren.
void handlePinoutSvg(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    resNoCache(res);
    res.header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:");
    String prof = req.arg("profile"); prof.trim();
    String view = req.arg("view");    view.trim();   // board (Vorgabe) | chip | aux
    if (view != "chip" && view != "aux") view = "";
    res.send(200, "image/svg+xml", prof.length() ? platformSvgFor(prof, view) : platformSvg(view));
}
void handlePlatformConfigJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    resNoCache(res);
    if (req.hasArg("download")) res.header("Content-Disposition", "attachment; filename=\"weirdos-platform.json\"");
    res.send(200, "application/json", platformConfigJson(true));
}
void handlePlatformImport(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    resNoCache(res);
    String err = platformConfigImport(req.body());
    if (err.length()) { res.send(200, "application/json", "{\"ok\":false,\"msg\":\"" + escapeJson(err) + "\"}"); return; }
    logEvent("Plattform-Konfiguration importiert");
    markRestartRequired("Plattform (Import)");
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"Plattform importiert -- wirkt nach Neustart\"}");
}
void handlePlatformSvgSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    resNoCache(res);
    String view = req.arg("view"); view.trim();            // "" = Platine, "chip", "aux"
    if (view != "chip" && view != "aux") view = "";
    String err = platformSvgStore(req.body(), view);
    if (err.length()) { res.send(200, "application/json", "{\"ok\":false,\"msg\":\"" + escapeJson(err) + "\"}"); return; }
    String what = view.length() ? view : String("board");
    logEvent((req.body().length() ? "Eigenes Pinout-SVG gespeichert: " : "Eigenes Pinout-SVG geloescht: ") + what);
    res.send(200, "application/json", "{\"ok\":true}");
}
void handleUsbPortsJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req; resNoCache(res);
    res.send(200, "application/json", usbPortsJson());
}
void handleUsbDevJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req; resNoCache(res);
    res.send(200, "application/json", usbDeviceService.statusJson());
}
void handleRestartNow(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req; resNoCache(res);
    logEvent("Neustart ueber die Web-UI (gelbe Box)");
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"Neustart in 2 s\"}");
    pendingRestartAt = millis() + 2000;
}
void handleUartSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    if (req.hasArg("baud")) {
        uint32_t b = (uint32_t)req.arg("baud").toInt();
        if (b != serialConsoleBaud() && serialConsoleSetBaud(b)) { logEvent(String("UART-Baudrate gespeichert: ") + String(b) + " (ab Neustart)"); markRestartRequired("UART-Baudrate"); }
    }
    // UART-Zugriffsschutz: Checkbox 'uarten' fehlt = Konsole abschalten (nimmt dann keine Befehle mehr an).
    { SetupGuardConfig sg = setupGuardGet(); bool en = req.hasArg("uarten");
      if (en != sg.uartEnabled) { sg.uartEnabled = en; setupGuardSave(sg); logEvent(en ? "UART-Konsole aktiviert" : "UART-Konsole DEAKTIVIERT (Zugriffsschutz)"); } }
    resNoCache(res);
    res.redirect("/?p=portal", 303);   // Hash-Router kennt nur Seite + Menue-psub; der UART-Tab ist ein Klick
}

// WAN-/Internet-Status (generalisiert): fuer Uebersicht + WAN-Seite. Keine Secrets. PUBLIC (kein Auth).
void handleWanStatusJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", wanService.statusJson());
}

// System-WAN-Policy (geordnete Uplink-Wahl). GESPEICHERT + aufgeloest -- aber die Dienste
// (ipsec/wg/dyndns) konsumieren sie in diesem Refactor-Stand NOCH NICHT (eigener Slice). PUBLIC.
void handleWanPolicyJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", wanStatusJson());
}
void handleWanPolicySave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    // Logische Praeferenz (auto|cellular|wifi) -- KEINE internen Interfaces mehr.
    WanPolicy p;
    p.preference = req.arg("pref");   // canonPref() normalisiert in wanSaveConfig
    wanSaveConfig(p);
    resNoCache(res);
    uiRedirectBack(req, res);
}
void handleIpsecConnect(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    String err = ipsecService.requestReconnect();   // (Neu-)Start mit der gespeicherten Config, loop-Task
    resNoCache(res);
    if (err.length()) res.send(200, "application/json", "{\"ok\":false,\"msg\":\"" + escapeJson(err) + "\"}");
    else              res.send(200, "application/json", "{\"ok\":true,\"msg\":\"Neu verbinden angestossen - Status auf der Uebersicht.\"}");
}
void handleIpsecDisconnect(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    ipsecService.requestDisconnect();   // loop-Task trennt; kein Autostart bis 'Neu verbinden'
    resNoCache(res);
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"Trennung angestossen - kein Autostart, bis 'Neu verbinden' gedrueckt wird.\"}");
}
void handleIpsecStatusJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", ipsecService.statusJson());
}
void handleIpsecPing(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String target = req.arg("target"); target.trim();
    resNoCache(res);
    if (target.length() == 0) { res.send(200, "application/json", "{\"ok\":false,\"detail\":\"Ziel-IP fehlt\"}"); return; }
    res.send(200, "application/json", ipsecService.testPingJson(target));
}
// Trust-Modell: Subject/Aussteller/CA/selbstsigniert/Gueltigkeit je PEM-Block -- fuer die Zertifikats-
// liste der UI (Haken "als Vertrauensanker"). Nur oeffentliche Zertifikatsdaten, nichts wird gespeichert.
void handleIpsecCertInfo(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    resNoCache(res);
    res.send(200, "application/json", ipsecCertInfoJson(req.arg("pem")));
}
// Test-Ping-Dropdown: Historie der Ziele liegt im NVS des Geraets (nicht im Browser).
void handleIpsecPingHistoryJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", ipsecService.pingHistoryJson());
}
void handleIpsecPingHistoryDel(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String del = req.arg("del"); del.trim();
    resNoCache(res);
    if (del.length()) ipsecService.forgetPingTarget(del);
    res.send(200, "application/json", ipsecService.pingHistoryJson());   // aktualisierte Liste zurueck
}
void handleIpsecUserAdd(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String err = ipsecService.addUser(req.arg("name"));
    resNoCache(res);
    if (err.length()) res.send(200, "application/json", "{\"ok\":false,\"msg\":\"" + escapeJson(err) + "\"}");
    else              res.send(200, "application/json", "{\"ok\":true,\"users\":" + ipsecService.usersJson() + "}");
}
void handleIpsecUserDel(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    bool ok = ipsecService.deleteUser(req.arg("i").toInt());
    resNoCache(res);
    res.send(200, "application/json", String("{\"ok\":") + (ok ? "true" : "false") + ",\"users\":" + ipsecService.usersJson() + "}");
}

// 7.4d.4: Text -> QR als inline-SVG (kleinste passende Version, ECC_LOW). Nur dunkle Module
// als ein <path> (kompakt). SVG-Attribute in Single-Quotes -> keine JSON-Escapes noetig.
static String qrSvgFromText(const String& text) {
    QRCode qr;
    for (uint8_t v = 10; v <= 22; v++) {
        uint8_t* buf = (uint8_t*)malloc(qrcode_getBufferSize(v));
        if (!buf) return "";
        if (qrcode_initText(&qr, buf, v, ECC_LOW, text.c_str()) == 0) {
            const int n = qr.size, q = 4, total = n + 2 * q;   // 4 Module Quiet-Zone
            String svg;
            svg.reserve((size_t)n * n * 7 + 256);   // ~dunkle Module*13Zeichen, eine Allokation
            svg  = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 ";
            svg += total; svg += " "; svg += total;
            svg += "' width='280' height='280' shape-rendering='crispEdges'>";
            svg += "<rect width='100%' height='100%' fill='#fff'/><path fill='#000' d='";
            for (int y = 0; y < n; y++)
                for (int x = 0; x < n; x++)
                    if (qrcode_getModule(&qr, x, y)) {
                        svg += "M"; svg += (x + q); svg += " "; svg += (y + q); svg += "h1v1h-1z";
                    }
            svg += "'/></svg>";
            free(buf);
            return svg;
        }
        free(buf);   // passte nicht -> naechstgroessere Version
    }
    return "";   // Text zu lang fuer v22
}

// 7.4d.4: "Client hinzufuegen (QR)". Erzeugt Client-Keypair auf dem Geraet, traegt den
// Public Key als Peer ein und liefert Client-.conf + QR-SVG in einem Response.
void handleWgClientGen(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    resNoCache(res);
    String cname = req.arg("name"); cname.trim();
    String conf = wireguardService.generateClientConfig(dyndnsDomain, cname);
    if (conf.length() == 0) {
        res.send(200, "application/json",
                    "{\"ok\":false,\"msg\":\"" + escapeJson(wireguardService.lastError()) + "\"}");
        return;
    }
    String svg = qrSvgFromText(conf);
    if (svg.length() == 0) {
        res.send(200, "application/json",
                    "{\"ok\":false,\"msg\":\"QR-Erzeugung fehlgeschlagen (Config zu lang?).\"}");
        return;
    }
    // 7.9.1: neuer Peer eingetragen. Ist der Server aktiv, sofort neu starten, damit der neue
    // Client akzeptiert wird (sonst laeuft der Server noch mit altem/keinem Peer).
    if (wireguardService.config().active) {
        wireguardService.disconnect();
        wireguardService.connect();
    }
    res.send(200, "application/json",
                "{\"ok\":true,\"conf\":\"" + escapeJson(conf) + "\",\"svg\":\"" + escapeJson(svg) + "\"}");
}

// 7.9.2: Client-Liste (Server-Rolle) fuer die UI.
void handleWgClientsJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", wireguardService.clientsJson());
}
// 7.9.4: Rueckweg-Routing-Diagnose (welches Interface waehlt lwIP fuer den Tunnel-Client / LAN-PC?)
void handleDiagWgRoute(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", wgRouteDiagJson());
}

#if WEIRDOS_FEATURE_NETSCAN   // Sweep/Ping/Resolve-Handler
// 7.10: LAN-Host-Scan (Ping-Sweep des WLAN-Subnetzes) + Einzel-Ping von der MCU aus.
void handleNetScanStart(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    // D1/D2: Ziel = CIDR oder Attachment-id (leer = WLAN-LAN), mode = auto|arp|icmp. Ablehnung mit Grund
    // (z. B. Netz zu gross) statt stillem Abschneiden.
    String target = req.hasArg("target") ? req.arg("target") : String("");
    String mode   = req.hasArg("mode") ? req.arg("mode") : String("auto");
    String err = netScanStartTarget(target, mode);
    resNoCache(res);
    if (err.length()) { res.send(200, "application/json", "{\"ok\":false,\"msg\":\"" + escapeJson(err) + "\"}"); return; }
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"Sweep gestartet.\"}");
}
void handleNetScanTargetsJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", netScanTargetsJson());
}
// D1: Routing-Befund fuer eine Ziel-IP (lokaler Weg vom P4; optional from=<Attachment> -> Forward-Policy).
void handleNetResolve(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String ip = req.arg("ip"); ip.trim();
    String from = req.hasArg("from") ? req.arg("from") : String("");
    resNoCache(res);
    res.send(200, "application/json", netDiagResolveJson(ip, from));
}
void handleNetScanJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", netScanJson());
}
void handleNetPing(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String ip = req.arg("ip"); ip.trim();
    resNoCache(res);
    res.send(200, "application/json", netPingJson(ip));
}
#endif // WEIRDOS_FEATURE_NETSCAN (Sweep/Ping/Resolve-Handler)
// 8.0: Bluetooth-LE (bt_scan.*). BLE-only auf S3 - kein Classic/Audio (Hardware-Grenze).
void handleBtScanStart(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    int secs = req.hasArg("secs") ? req.arg("secs").toInt() : 6;
    btScanStart(secs);
    resNoCache(res);
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"BLE-Suche gestartet.\"}");
}
void handleBtScanJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", btScanJson());
}
void handleBtStatusJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", btStatusJson());
}
void handleBtConnect(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String a = req.arg("addr"); a.trim();
    btConnectTest(a);
    resNoCache(res);
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"Verbindungsversuch laeuft.\"}");
}
void handleBtRelease(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    btStackRelease();
    resNoCache(res);
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"BT-Stack freigegeben.\"}");
}
// 7.11: TCP-Port-Scan starten (ip + optional from/to; ohne = haeufige Ports) + Ergebnisse.
#if WEIRDOS_FEATURE_NETSCAN   // Portscan/Funk-Handler
void handleNetPortScanStart(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String ip = req.arg("ip"); ip.trim();
    int from = req.hasArg("from") ? req.arg("from").toInt() : 0;
    int to   = req.hasArg("to")   ? req.arg("to").toInt()   : 0;
    bool udp = (req.arg("proto") == "udp");
    String err = netPortScanStart(ip, from, to, udp);   // zu grosser Bereich -> Ablehnung mit Grund, nie stilles Kappen
    resNoCache(res);
    if (err.length()) { res.send(200, "application/json", "{\"ok\":false,\"msg\":\"" + escapeJson(err) + "\"}"); return; }
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"Port-Scan gestartet.\"}");
}
void handleNetPortScanJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", netPortScanJson());
}
// 7.13: Passiv-Monitor (WLAN mithoeren) starten + Ergebnisse.
void handleNetSniffStart(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    int secs = req.hasArg("secs") ? req.arg("secs").toInt() : 8;
    netSniffStart(secs);
    resNoCache(res);
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"Passiv-Monitor laeuft.\"}");
}
void handleNetSniffJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", netSniffJson());
}
// 7.14: Kanal-Uebersicht starten + Ergebnisse.
void handleNetChScanStart(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    netChannelScanStart();
    resNoCache(res);
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"Kanal-Scan laeuft.\"}");
}
void handleNetChScanJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", netChannelScanJson());
}
// 7.15: Tiefen-Kanal-Scan (Channel-Hopping) - trennt das WLAN kurz.
void handleNetDeepChStart(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    netDeepChScanStart();
    resNoCache(res);
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"Tiefen-Scan laeuft.\"}");
}
void handleNetDeepChJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", netDeepChScanJson());
}
#endif // WEIRDOS_FEATURE_NETSCAN (Portscan/Funk-Handler)
void handleWgClientDel(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    int idx = req.hasArg("i") ? req.arg("i").toInt() : -1;
    bool ok = wireguardService.deleteClient(idx);
    resNoCache(res);
    res.send(200, "application/json", ok ? "{\"ok\":true,\"msg\":\"Client entfernt.\"}"
                                            : "{\"ok\":false,\"msg\":\"Client nicht gefunden.\"}");
}


// Stufe 7.4b: WireGuard-Underlay-Aufloesung (kein Tunnel). Auth + diagEnabled.
// sel = auto|modem|wifi (Policy) oder direkt eine NetIface-id.
void handleDiagWgUnderlay(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    if (!diagEnabled) { res.send(403, "application/json", "{\"error\":\"Diagnose deaktiviert\"}"); return; }
    String sel = req.hasArg("sel") ? req.arg("sel") : String("auto");
    resNoCache(res);
    res.send(200, "application/json", wireguardService.underlayDiagJson(sel));
}


// Stufe 7.2c-1: isolierter Beweis der interface-gebundenen Egress-Bindung.
// Auth- UND diagEnabled-gated. Kein beliebiges URL-Ziel (kein SSRF-Werkzeug):
// fester harmloser HTTPS-IP-Echo. Loest die Policy -> Interface auf, bindet den
// HTTPS-Socket an dessen lokale IPv4 und meldet localIp vs. von aussen beobachteter
// Quell-IP. DynDNS wird NICHT beruehrt (bleibt auf a7bec98).
void handleDiagEgressTest(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    if (!diagEnabled) { res.send(403, "application/json", "{\"ok\":false,\"error\":\"Diagnose deaktiviert\"}"); return; }

    String policy = req.hasArg("policy") ? req.arg("policy") : String("auto");
    NetIface ni;
    String j = "{\"policy\":\""; j += escapeJson(policy); j += "\",";
    if (!egressResolve(policy, ni)) {
        j += "\"ok\":false,\"error\":\"kein verfuegbares Interface\"}";
        resNoCache(res); res.send(200, "application/json", j); return;
    }

    HttpRequest rq; rq.url = "https://api.ipify.org"; rq.egress = &ni;   // FESTER IP-Echo
    HttpResponse rp = esp32BoundHttpGet(rq);

    bool ok = (rp.status >= 200 && rp.status < 300 && rp.error.length() == 0);
    j += "\"ok\":"; j += ok ? "true" : "false"; j += ",";
    j += "\"interface\":\""; j += escapeJson(ni.id);   j += "\",";
    j += "\"localIp\":\"";   j += escapeJson(ni.ip);   j += "\",";
    j += "\"observedIp\":\"";j += escapeJson(rp.body); j += "\",";
    j += "\"httpStatus\":";  j += String(rp.status);
    if (rp.error.length()) { j += ",\"error\":\""; j += escapeJson(rp.error); j += "\""; }
    j += "}";
    resNoCache(res);
    res.send(200, "application/json", j);
}


// Stufe 7.2/7.2b: konkrete Netzwerk-Interfaces + Policy-Aufloesung (read-only,
// Verifikation von NetworkRegistry + EgressPolicy). Keine Routing-Aktion.
void handleNetInterfacesJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    String j = netRegistryJson();          // {"interfaces":[...]}
    if (j.endsWith("}")) {
        j.remove(j.length() - 1);          // schliessende } entfernen, policies anhaengen
        j += ",\"policies\":{";
        j += "\"auto\":\"";  j += egressResolvedId("auto");  j += "\",";
        j += "\"modem\":\""; j += egressResolvedId("modem"); j += "\",";
        j += "\"wifi\":\"";  j += egressResolvedId("wifi");  j += "\"}";
        j += ",\"zones\":"; j += zoneLwipJson();   // Netzzonen 0.3: Hook-Praesenz, Zielrouten, Test-Filter, Zaehler
        j += "}";
    }
    resNoCache(res);
    res.send(200, "application/json", j);
}

// Netzzonen 0.2: Planner-Vorschau fuer EINE Paarung (?src=<attachment>&dst=<attachment>&intent=allow|deny|route|nat).
// Read-only: nichts wird installiert. Attachment-ids siehe /net-interfaces.json (attachments[]).
void handleZonesPlanJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String src = req.arg("src"), dst = req.arg("dst"); src.trim(); dst.trim();
    bool ok = true; ZoneIntent intent = zoneIntentParse(req.arg("intent"), ok);
    resNoCache(res);
    if (!src.length() || !dst.length() || !ok) {
        res.send(400, "application/json", "{\"error\":\"src, dst und intent (allow|deny|route|nat) erwartet\"}");
        return;
    }
    res.send(200, "application/json", zonePlanJson(src, dst, intent));
}

// Netzzonen 0.5: persistente Intents, effektive Plaene und installierter lwIP-Zustand (read-only).
void handleZonesJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    resNoCache(res);
    res.send(200, "application/json", zoneRuntimeJson());
}
// Netzzonen Phase 1: Verbindung setzen (src, dst, intent = allow|deny|route|nat). Dieselbe Runtime wie die
// Konsole; Intent wird persistent, Commit sofort (oder gemeldet verschoben).
void handleZonesPolicy(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String src = req.arg("src"), dst = req.arg("dst"), intent = req.arg("intent"); src.trim(); dst.trim(); intent.trim();
    resNoCache(res);
    String r = zoneRuntimeSetPolicy(src, dst, intent.length() ? intent : String("allow"));
    bool deferred = r.startsWith("gespeichert") || r.startsWith("entfernt");
    if (r.length() && !deferred) { res.send(200, "application/json", "{\"ok\":false,\"msg\":\"" + escapeJson(r) + "\"}"); return; }
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"" + escapeJson(r.length() ? r : String("gespeichert und installiert")) + "\"}");
}


#if WEIRDOS_FEATURE_DYNDNS   // Status/Update-Handler
void handleDyndnsStatusJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    String j = "{";
    j += "\"enabled\":"; j += dyndnsEnabled ? "true" : "false";                 j += ",";
    j += "\"status\":\"";  j += escapeJson(g_dyndnsStatus);                     j += "\",";
    j += "\"ip\":\"";      j += escapeJson(modemWanIp());                        j += "\",";
    j += "\"last\":\"";    j += escapeJson(g_dyndnsLastIp);                      j += "\",";
    j += "\"def\":\"";     j += escapeJson(ecmDefaultRouteIp());                 j += "\",";  // Default-netif JETZT (kann nach dem Update wieder WLAN sein)
    j += "\"egress\":\"";  j += escapeJson(g_dyndnsEgressUsed);                  j += "\"";  // Default-netif im Moment des letzten DynDNS-Connects (ECM-WAN=ok, 172.x=WLAN=falsch)
    j += "}";
    resNoCache(res);
    res.send(200, "application/json", j);
}

// "Jetzt aktualisieren": stoesst einen sofortigen Update an (der Task fuehrt ihn aus).
void handleDyndnsUpdate(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    if (!dyndnsEnabled) {
        res.send(200, "application/json", "{\"ok\":false,\"msg\":\"DynDNS ist nicht aktiv.\"}");
        return;
    }
    if (dyndnsEgressIp().length() == 0) {
        res.send(200, "application/json", "{\"ok\":false,\"msg\":\"Kein Datenlink - zuerst verbinden.\"}");
        return;
    }
    g_dyndnsForce = true;
    resNoCache(res);
    res.send(200, "application/json", "{\"ok\":true,\"msg\":\"Update angestossen ...\"}");
}
#endif // WEIRDOS_FEATURE_DYNDNS (Status/Update-Handler)


// Energie-Einstellungen speichern: CPU-Profil (sofort wirksam) + WLAN-Fallback-Flag.
void handleEnergySave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String p = req.arg("cpu");
    if (p != "power" && p != "eco") p = "balanced";
    cpuProfile = p;
    wifiOffOnMobile = req.hasArg("wifioff");
    saveEnergyPrefs();
    applyCpuProfile();          // sofort, kein Reboot

    Serial.print("Energy saved: cpu=");
    Serial.print(cpuProfile);
    Serial.print(" (");
    Serial.print(getCpuFrequencyMhz());
    Serial.print(" MHz), wifiOffOnMobile=");
    Serial.println(wifiOffOnMobile ? "on" : "off");

    String j = "{\"ok\":true,\"cpu\":\"" + cpuProfile + "\",\"freq\":"
             + String(getCpuFrequencyMhz()) + "}";
    resNoCache(res);
    res.send(200, "application/json", j);
}


// Router-Name / URL (System -> Allgemein). Speichert den mDNS-Hostnamen und
// startet mDNS live neu; WiFi.setHostname greift bei der naechsten Verbindung.
void handleGeneralSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    String raw = req.arg("host");
    String h;                              // nur [a-z0-9-], klein, RFC-1123-tauglich
    for (size_t i = 0; i < raw.length() && h.length() < 31; i++) {
        char c = raw[i];
        if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
        bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        if (!ok) continue;
        if (c == '-' && h.length() == 0) continue;    // kein fuehrender Bindestrich
        h += c;
    }
    while (h.length() && h[h.length() - 1] == '-') h.remove(h.length() - 1);
    if (h.length() == 0) h = DEVICE_HOSTNAME;

    deviceHostname = h;

    // 7.9.14: mbedTLS-Speicher-Schalter (PSRAM/intern). Aenderung wirkt erst nach Neustart,
    // weil der globale Allocator einmalig sehr frueh im Boot gesetzt werden muss. Bei
    // Aenderung planen wir einen kontrollierten Reboot, nachdem die Antwort raus ist.
    bool rebootNeeded = false;
    if (req.hasArg("cryptomem")) {
        bool want = (req.arg("cryptomem").toInt() != 0);
        if (want != g_cryptoMemPsram) { g_cryptoMemPsram = want; rebootNeeded = true; }
    }

    saveGeneralPrefs();                          // persistiert host + cryptopsram
#if WEIRDOS_FEATURE_WIFI
    WiFi.setHostname(deviceHostname.c_str());   // wirkt bei naechster (Re)Verbindung
    MDNS.end();                                 // mDNS live mit neuem Namen neu starten
    mdnsStarted = false;
    startMdns();
#endif

    Serial.print("General saved: host=");
    Serial.print(deviceHostname);
    Serial.printf(" cryptomem=%s reboot=%d\n", g_cryptoMemPsram ? "psram" : "internal", rebootNeeded);

    String j = "{\"ok\":true,\"host\":\"" + escapeJson(deviceHostname) + "\""
             + ",\"cryptomem\":\"" + (g_cryptoMemPsram ? "psram" : "internal") + "\""
             + ",\"reboot\":" + (rebootNeeded ? "true" : "false") + "}";
    resNoCache(res);
    res.send(200, "application/json", j);
    if (rebootNeeded) pendingRestartAt = millis() + 900;   // erst Antwort ausliefern, dann Neustart
}


// --- Parser-Helfer fuer strukturierte Mobilfunkdaten ---------------------------
// Erste Zeile aus einer rohen AT-Antwort, die mit prefix beginnt -> Rest dahinter.
static String atExtract(const String& raw, const char* prefix) {
    int p = raw.indexOf(prefix);
    if (p < 0) return "";
    int start = p + strlen(prefix);
    int end = raw.indexOf('\r', start);
    int endN = raw.indexOf('\n', start);
    if (end < 0 || (endN >= 0 && endN < end)) end = endN;
    if (end < 0) end = raw.length();
    String s = raw.substring(start, end);
    s.trim();
    return s;
}

// CSV-Feld idx aus einer Zeile, respektiert Anfuehrungszeichen (fuer QENG/COPS).
static String csvField(const String& line, int idx) {
    int field = 0;
    bool quoted = false;
    String cur;
    for (unsigned i = 0; i < line.length(); i++) {
        char c = line[i];
        if (c == '"') { quoted = !quoted; continue; }
        if (c == ',' && !quoted) {
            if (field == idx) { cur.trim(); return cur; }
            field++; cur = ""; continue;
        }
        cur += c;
    }
    if (field == idx) { cur.trim(); return cur; }
    return "";
}

// Erste reine Ziffern-Zeile (fuer IMEI/IMSI, die "nackt" zurueckkommen).
static String firstNumericLine(const String& raw) {
    unsigned i = 0, n = raw.length();
    while (i < n) {
        int e = raw.indexOf('\n', i);
        unsigned end = (e < 0) ? n : (unsigned)e;
        String line = raw.substring(i, end);
        line.trim();
        if (line.length() >= 6) {
            bool allDigit = true;
            for (unsigned k = 0; k < line.length(); k++)
                if (!isDigit(line[k])) { allDigit = false; break; }
            if (allDigit) return line;
        }
        i = end + 1;
    }
    return "";
}

#if WEIRDOS_FEATURE_MODEM   // AT/Info/JSON-Handler
static String atRun(const char* cmd) { return modemAtTest(3, 0x0F, 0x86, cmd); }

// Band-Nummer (QENG-Feld, "3" oder "LTE BAND 3") -> nominale Frequenz in MHz
// aus der LTE_BANDS-Tabelle des Treibers.
static String bandFreqMhz(const String& bandField) {
    int n = 0; bool any = false;
    for (unsigned i = 0; i < bandField.length(); i++) {
        char c = bandField[i];
        if (c >= '0' && c <= '9') { n = n * 10 + (c - '0'); any = true; }
        else if (any) break;
    }
    if (!any) return "";
    for (int i = 0; i < LTE_BAND_N; i++)
        if (LTE_BANDS[i].num == n) return String(LTE_BANDS[i].mhz) + " MHz";
    return "";
}


// Strukturierte Mobilfunkdaten als JSON: ATI/CGSN/QCCID/CIMI/CPIN/CEREG/CSQ/
// COPS/QNWINFO/QENG(servingcell)/CGPADDR -> geparst fuer die Mobilfunk-Info-Tabs.
void handleModemJson(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    // Bei aktivem PPP ist IF3-Live-AT nicht moeglich -> ALLE Felder aus dem
    // Snapshot vom Verbindungsaufbau (sonst waeren Modell/Firmware/SIM/Reg/IP leer).
    bool online     = pppIsUp() || ec200aEcm.isUp();   // ECM zaehlt genauso als 'verbunden' -> RF-Snapshot statt Live-AT
    String ati      = online ? modemRfAti : atRun("ATI");
    String firmware = atExtract(ati, "Revision:");
    String model;
    { int q = ati.indexOf("Quectel");
      if (q >= 0) { int s = ati.indexOf('\n', q);
        if (s >= 0) { int e = ati.indexOf('\r', s + 1); if (e < 0) e = ati.indexOf('\n', s + 1);
          if (e < 0) e = ati.length(); model = ati.substring(s + 1, e); model.trim(); } } }

    String imei  = firstNumericLine(online ? modemRfImei  : atRun("AT+CGSN"));
    String iccid = atExtract(online ? modemRfIccid : atRun("AT+QCCID"), "+QCCID:");
    String imsi  = firstNumericLine(online ? modemRfImsi  : atRun("AT+CIMI"));
    String cpin  = atExtract(online ? modemRfCpin  : atRun("AT+CPIN?"), "+CPIN:");
    String cereg = atExtract(online ? modemRfCereg : atRun("AT+CEREG?"), "+CEREG:");
    String csq   = atExtract(online ? modemRfCsq   : atRun("AT+CSQ"), "+CSQ:");
    String cops  = atExtract(online ? modemRfCops  : atRun("AT+COPS?"), "+COPS:");
    String qnw   = atExtract(online ? modemRfQnw   : atRun("AT+QNWINFO"), "+QNWINFO:");
    String qeng  = atExtract(online ? modemRfQeng  : atRun("AT+QENG=\"servingcell\""), "+QENG:");
    // CGPADDR beim Snapshot ist noch leer (vor dem Dial) -> online die PPP-IP nehmen.
    String cgp   = online ? String("") : atExtract(atRun("AT+CGPADDR"), "+CGPADDR:");

    // QENG (LTE): 0="servingcell" 1=state 2=RAT 3=duplex 4=MCC 5=MNC 6=CellID
    //   7=PCI 8=EARFCN 9=Band 12=TAC 13=RSRP 14=RSRQ 15=RSSI 16=SINR
    String j = "{\"ok\":true";
    j += ",\"model\":\"" + escapeJson(model) + "\"";
    j += ",\"firmware\":\"" + escapeJson(firmware) + "\"";
    j += ",\"imei\":\"" + escapeJson(imei) + "\"";
    j += ",\"iccid\":\"" + escapeJson(iccid) + "\"";
    j += ",\"imsi\":\"" + escapeJson(imsi) + "\"";
    j += ",\"cpin\":\"" + escapeJson(cpin) + "\"";
    j += ",\"reg\":\"" + escapeJson(csvField(cereg, 1)) + "\"";
    j += ",\"operator\":\"" + escapeJson(csvField(cops, 2)) + "\"";
    j += ",\"rat\":\"" + escapeJson(csvField(qnw, 0)) + "\"";
    j += ",\"csq\":\"" + escapeJson(csvField(csq, 0)) + "\"";
    j += ",\"mcc\":\"" + escapeJson(csvField(qeng, 4)) + "\"";
    j += ",\"mnc\":\"" + escapeJson(csvField(qeng, 5)) + "\"";
    j += ",\"cellid\":\"" + escapeJson(csvField(qeng, 6)) + "\"";
    j += ",\"pci\":\"" + escapeJson(csvField(qeng, 7)) + "\"";
    j += ",\"earfcn\":\"" + escapeJson(csvField(qeng, 8)) + "\"";
    j += ",\"band\":\"" + escapeJson(csvField(qeng, 9)) + "\"";
    j += ",\"freq\":\"" + escapeJson(bandFreqMhz(csvField(qeng, 9))) + "\"";
    j += ",\"rfsnap\":"; j += online ? "true" : "false";   // Werte aus Verbindungs-Snapshot?
    j += ",\"tac\":\"" + escapeJson(csvField(qeng, 12)) + "\"";
    j += ",\"rsrp\":\"" + escapeJson(csvField(qeng, 13)) + "\"";
    j += ",\"rsrq\":\"" + escapeJson(csvField(qeng, 14)) + "\"";
    j += ",\"rssi\":\"" + escapeJson(csvField(qeng, 15)) + "\"";
    j += ",\"sinr\":\"" + escapeJson(csvField(qeng, 16)) + "\"";
    j += ",\"ipv4\":\"" + escapeJson(online ? modemWanIp() : csvField(cgp, 1)) + "\"";
    j += ",\"ipv6\":\"" + escapeJson(online ? String("")  : csvField(cgp, 2)) + "\"";
    j += "}";

    resNoCache(res);
    res.send(200, "application/json", j);
}


// Live-Mobilfunkstatus: feste AT-Abfragen ueber den AT-Port (IF3), roh
// konkateniert (Roh-Dump im Diagnose-Tab).
void handleModemInfo(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    String out;
    out.reserve(2048);
    if (pppIsUp() || ec200aEcm.isUp()) {
        // Bei aktivem Datenpfad (PPP oder ECM) ist IF3 nicht claimbar -> Snapshot
        // statt Fehler-Dump. Der Snapshot wird beim PPP- wie beim ECM-Connect gefuellt.
        out += (pppIsUp() ? "PPP" : "ECM");
        out += " ist aktiv - Live-AT ueber IF3 nicht moeglich (IF3/IF4 teilen sich\n";
        out += "einen USB-Kanal). RF-Snapshot vom letzten Verbindungsaufbau:\n\n";
        out += "> ATI\n";                     out += modemRfAti;  out += "\n";
        out += "> AT+CPIN?\n";                out += modemRfCpin; out += "\n";
        out += "> AT+CEREG?\n";               out += modemRfCereg;out += "\n";
        out += "> AT+CSQ\n";                  out += modemRfCsq;  out += "\n";
        out += "> AT+COPS?\n";                out += modemRfCops; out += "\n";
        out += "> AT+QNWINFO\n";              out += modemRfQnw;  out += "\n";
        out += "> AT+QENG=\"servingcell\"\n"; out += modemRfQeng; out += "\n";
    } else {
        static const char* cmds[] = {
            "ATI", "AT+CPIN?", "AT+CEREG?", "AT+CSQ", "AT+COPS?",
            "AT+QNWINFO", "AT+QENG=\"servingcell\"", "AT+CGACT?", "AT+CGPADDR"
        };
        for (unsigned i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
            out += "> ";
            out += cmds[i];
            out += "\n";
            out += modemAtTest(3, 0x0F, 0x86, String(cmds[i]));   // IF3 = AT-Port
            if (!out.endsWith("\n")) out += "\n";
        }
    }
    resNoCache(res);
    res.send(200, "text/plain", out);
}


// AT-Sendetest auf einer Modem-Schnittstelle: /modem-at?if=3 (Standard), ?if=4, ?if=2.
void handleModemAt(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    if (!diagEnabled) { res.send(403, "text/plain", "Diagnose deaktiviert (Web-UI: Diagnose > USB/Modem)."); return; }
    int ifn = req.hasArg("if") ? req.arg("if").toInt() : 3;
    uint8_t epOut, epIn;
    if      (ifn == 2) { epOut = 0x0B; epIn = 0x82; }   // aus /modem-usbinfo
    else if (ifn == 3) { epOut = 0x0F; epIn = 0x86; }
    else if (ifn == 4) { epOut = 0x0A; epIn = 0x81; }
    else { res.send(400, "text/plain", "if muss 2, 3 oder 4 sein"); return; }

    String cmd = req.hasArg("cmd") ? req.arg("cmd") : String("AT");
    cmd.trim();
    if (cmd.length() == 0) cmd = "AT";

    String r = modemAtTest((uint8_t)ifn, epOut, epIn, cmd);
    resNoCache(res);
    res.send(200, "text/plain", r);
}


// Gibt die USB-Schnittstellen-/Endpoint-Karte des Modems als Klartext aus.
void handleModemUsbInfo(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    if (!diagEnabled) { res.send(403, "text/plain", "Diagnose deaktiviert (Web-UI: Diagnose > USB/Modem)."); return; }
    resNoCache(res);
    res.send(200, "text/plain",
        strlen(g_modemUsbInfo) ? g_modemUsbInfo
                               : "(kein Modem-Descriptor - ist 2C7C:6005 angeschlossen?)");
}
#endif // WEIRDOS_FEATURE_MODEM (AT/Info/JSON-Handler)


// Gibt den aufgefangenen ESP-IDF-Log (USB/Enumeration) als Klartext aus.
void handleModemLog(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    (void)req;
    if (!diagEnabled) { res.send(403, "text/plain", "Diagnose deaktiviert (Web-UI: Diagnose > USB/Modem)."); return; }
    String out;
    out.reserve(USB_LOG_CAP + 64);
    if (g_logMux) xSemaphoreTake(g_logMux, portMAX_DELAY);
    if (g_logWrapped) {
        for (size_t i = g_logHead; i < USB_LOG_CAP; i++) out += g_log[i];
    }
    for (size_t i = 0; i < g_logHead; i++) out += g_log[i];
    if (g_logMux) xSemaphoreGive(g_logMux);

    resNoCache(res);
    res.send(200, "text/plain", out.length() ? out : "(noch kein Log)");
}


// Entwickler-Diagnose (AT-Konsole/USB-Info/Log) an/aus schalten (Web-UI: Diagnose).
void handleDiagSave(WeirdHttpRequest& req, WeirdHttpResponse& res) {
    diagEnabled = req.hasArg("diagen");
    saveDiagPrefs();
    resNoCache(res);
    res.send(200, "application/json",
        String("{\"ok\":true,\"diagen\":") + (diagEnabled ? "true" : "false") + "}");
}


// App-Hook fuer die View: WLAN im Zustand PORTAL_WIFI_CONNECTED? (kapselt das
// wifiState-Enum, damit web_ui.cpp es nicht kennen muss).
bool wifiPortalConnected() {
    return wifiState == PORTAL_WIFI_CONNECTED;
}

String wifiStatusText() {
    switch (wifiState) {
        case PORTAL_WIFI_CONNECTING:
            return "verbinde ...";

        case PORTAL_WIFI_CONNECTED:
            return "verbunden";

        case PORTAL_WIFI_FAILED:
            return "fehlgeschlagen";

        default:
#if WEIRDOS_FEATURE_WIFI
            return "nicht konfiguriert";
#else
            return "nicht im Build enthalten";   // WEIRDOS_FEATURE_WIFI=0
#endif
    }
}


// -----------------------------------------------------------------------------
// Hilfsfunktionen
// -----------------------------------------------------------------------------

void printNetworkStatus() {
    Serial.println();
    Serial.println("Network status:");

#if WEIRDOS_FEATURE_WIFI
    Serial.print("  AP SSID: ");
    Serial.println(CONFIG_AP_SSID);

    Serial.print("  AP IP: ");
    Serial.println(WiFi.softAPIP());

    Serial.print("  Captive portal API: ");
    Serial.println(captivePortalApiUri);
#else
    Serial.println("  WLAN: nicht im Build enthalten (WEIRDOS_FEATURE_WIFI=0) -> kein AP, kein Captive-Portal");
#endif

    Serial.print("  STA state: ");
    Serial.println(wifiStateName());

    Serial.println();
}
