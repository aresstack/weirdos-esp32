// ============================================================================
// ec200a_modem.h  --  Treiber-Schnittstelle fuer das Quectel EC200A-EUV1
//
// Saubere Schichtentrennung: dieser Treiber (USB-Host, AT-Kanal, PPP, Band-/RAT-
// Konfiguration) kennt die App-Schicht (Webserver/UI/DynDNS) NICHT. Er meldet
// Ereignisse ueber registrierte Funktionszeiger (Observer/Listener) zurueck.
// Die .ino bindet diese .h ein, ruft die API und registriert Listener.
// ============================================================================
#ifndef EC200A_MODEM_H
#define EC200A_MODEM_H

#include <Arduino.h>
#include <cstdint>
#include "usb/usb_host.h"     // usb_device_handle_t in einigen Prototypen

// ---- Konstanten -----------------------------------------------------------
static constexpr const char* MODEM_APN_DEFAULT         = "netpublic";  // o2-DE oeffentliche IPv4 (kein CGNAT) -- "internet" gibt nur 10.x/CGNAT
static constexpr const char* MODEM_PDP_DEFAULT         = "IP";        // IP | IPV4V6
static constexpr const char* MODEM_AUTH_DEFAULT        = "0";         // 0=keine 1=PAP 2=CHAP
static constexpr const char* MODEM_DIAL_DEFAULT        = "*99***1#";  // GPRS/LTE-Einwahlnummer (ATD<dial>)
static constexpr bool        MODEM_AUTOCONNECT_DEFAULT = false;
static constexpr uint16_t    MODEM_TARGET_VID          = 0x2C7C;      // Quectel
static constexpr uint16_t    MODEM_TARGET_PID          = 0x6005;      // EC200A Normalmodus

// ---- PPP-Zustand ----------------------------------------------------------
enum PppState { PPP_IDLE, PPP_DIAL, PPP_NEG, PPP_UP, PPP_FAILED };

// ---- LTE-Band-Tabelle -----------------------------------------------------
struct LteBandInfo { uint8_t num; uint16_t mhz; uint8_t bit; bool tdd; };
extern const LteBandInfo LTE_BANDS[];
extern const int         LTE_BAND_N;

// ---- Geteilte Globals (Definition in der .ino, hier nur extern) -----------
extern String modemApn, modemUser, modemPass, modemPdpType, modemAuth;
extern String modemDialNumber;   // Einwahlnummer (ATD<dial>); Default *99***1#
extern String modemSimPin;       // SIM-PIN (leer = keine); nur bei gesperrter SIM angewandt
extern uint32_t modemLastResetMs;   // millis() des letzten Modem-Neustarts (CFUN=1,1), 0 = keiner; USB-Host-Recovery
// Link-Recovery (spontane USB-Abrisse des Modems, nicht durch eigenen CFUN erklaert):
int      modemUsbUnexpectedGone(uint32_t windowMs, uint32_t* lastMs);   // Anzahl im Fenster, Zeit des letzten
void     modemUsbClearGoneHistory();
String   modemUsbRootPortCycle(bool* ok);                               // Root-Port deaktivieren/aktivieren (alle Geraete re-enumerieren); ok = beide Aufrufe ESP_OK
uint32_t modemEnumGeneration();                                         // zaehlt jede Enumeration des Modems
extern bool   modemAutoconnect;
extern bool   modemAutoStart;   // MCU-Autoconnect (kein Modem-Flash) + Auto-Retry
extern String modemBandProfile, modemBandCustom, modemNetMode;
extern bool   modemLinkUp;
extern String modemLastMessage;
extern volatile bool     modemUsbHostReady, modemUsbFound;
extern volatile int      modemUsbDevCount;
extern volatile uint16_t modemUsbLastVid, modemUsbLastPid;
extern volatile uint32_t modemUsbLibEvents, modemUsbCliEvents;
extern String            modemUsbError;

// RF-Snapshot vom Verbindungsaufbau (rohe AT-Antworten; die .ino parst sie).
// Bei aktivem PPP ist IF3-Live-AT nicht moeglich -> diese Werte anzeigen.
extern String   modemRfQeng, modemRfQnw, modemRfCops, modemRfCsq;
extern String   modemRfAti, modemRfImei, modemRfIccid, modemRfImsi, modemRfCpin, modemRfCereg;
extern uint32_t modemRfMs;   // millis() des Snapshots (0 = noch keiner)
extern char              g_modemUsbInfo[];   // Schnittstellen-/Endpoint-Karte (fuer /modem-usbinfo)

// ---- Observer / Listener (Funktionszeiger) --------------------------------
// Der Treiber ruft registrierte Callbacks bei Ereignissen -> die App-Schicht
// muss im Treiber NICHT bekannt sein. Mehrere Listener je Ereignis moeglich.
typedef void (*ModemPppListener)(PppState state, const char* ip);
typedef void (*ModemPresenceListener)(bool present, uint16_t vid, uint16_t pid);
void modemAddPppListener(ModemPppListener cb);        // PPP-Statuswechsel
void modemAddPresenceListener(ModemPresenceListener cb); // Modem am USB da/weg

// ---- USB-Host / AT --------------------------------------------------------
void   startUsbHost();
String modemAtTest(uint8_t ifNum, uint8_t epOut, uint8_t epIn, const String& cmd);
String modemStatusText();
bool   modemBackendReady();

// ---- USB-Host-Primitiven fuer den ECM-Datenpfad (ec200a_ecm.cpp) ----------
// Der ECM-Modul braucht Client-/Device-Handle und Interface-Claim; diese Statics
// liegen in ec200a_modem.cpp und werden hier als schmale Accessoren exportiert.
usb_host_client_handle_t modemUsbClientHandle();
usb_device_handle_t      modemDeviceHandle();
bool modemClaimInterface(uint8_t ifNum, uint8_t alt);   // claim mit Altsetting (ECM Data-IF = alt 1)
void modemReleaseInterface(uint8_t ifNum);

// ---- Generische USB-Geraete-Sicht (fuer Erkennung JENSEITS des Modems) -----
// Der Host enumeriert ohnehin JEDES USB-Geraet (VID/PID/Klasse), nicht nur das Modem.
// Dieser Accessor gibt eine Kopie der aktuell erkannten Geraete zurueck -- z.B. fuer die
// (rein informative) USB-WLAN-Adapter-Anzeige in wifi_caps.cpp/peripheral_registry.cpp.
struct UsbEnumDevice { uint16_t vid; uint16_t pid; uint8_t devClass; };
int usbEnumerateDevices(UsbEnumDevice out[], int maxOut);

// ---- PPP (Internet-Datenpfad) --------------------------------------------
String pppStart();
String pppStop();
void   pppFreeBuffers();       // PPP-Transfer-Pools freigeben (~48 KB) - beim Wechsel auf ECM
void   pppOnDeviceGone();
String pppStatusText();
bool   pppIsUp();
struct netif;                     // Vorwaertsdeklaration (kein lwIP-Include im Header)
struct netif* pppNetifHandle();   // rohes lwIP-netif des PPP-Pfads (nullptr wenn down) - fuer Underlay-Bindung
String pppIpStr();
String pppRateJson();
void   modemRateTick();       // 1s-Hintergrund-Sampler (in loop() aufrufen) -> cur/max fuellen
void   modemRateResetMax();   // Peak-Werte (Online-Monitor Max) zuruecksetzen

// ---- Modem-Prefs (NVS "modem") -------------------------------------------
extern bool modemUsbEnabled;   // USB-Host-Modem aktiv? (Default an; steuert Host-Start bei Boot)
extern String modemDataMode;   // Datenschicht: "ecm" (CDC-ECM, Standard/Produktion) | "ppp" (Kompatibilitaet)
extern String modemNatMode;    // ECM-Betriebsart des Modem-NIC (AT+QCFG="nat"): "nic" (Default, oeffentliche
                               // IP direkt am ESP) | "routing" (Modem-NAT, 192.168.43.x, kein Inbound)
void loadModemPrefs();
void saveModemPrefs();

// ---- Band-/RAT-Konfiguration ---------------------------------------------
uint64_t modemProfileLteMask();
String   modemApplyBands();
String   modemStartBandScan();   // Best-SINR-Scan (sperrt jedes Kandidatenband, misst, lockt bestes)
String   modemBandScanJson();    // Scan-Zustand/-Ergebnis als JSON-Fragment
String   modemNeighbourDump();   // Nachbarzellen roh (AT+QENG="neighbourcell") - PPP muss unten sein

// ---- Aktionsschicht (fuer die HTTP-Handler in der .ino) -------------------
String modemConnect();
String modemDisconnect();
String modemReset();          // Soft-Reboot des Modems (AT+CFUN=1,1)
void   startPppSupervisor();  // MCU-Autoconnect/Auto-Retry-Task starten
String modemRunInternetTest();
String modemApplyAutoconnect(bool enable);
// Wartet bis zu maxSec auf Netz-Registrierung (CEREG 1=Heimat/5=Roaming) auf dem
// angegebenen IF/Endpoint. Von PPP-Connect UND ECM-begin() (vor RF-Snapshot) genutzt.
bool   modemWaitRegistered(uint8_t ifNum, uint8_t epOut, uint8_t epIn, int maxSec);
String modemSpeedtestStart(int conn, bool autoMode);  // LTE-Speedtest; conn=Worker-Zahl (0=Vorgabe), autoMode=Auto-Ramp
String modemSpeedtestJson();    // Zustand/Ergebnis als JSON-Fragment (fuer sendModemJson)

#endif // EC200A_MODEM_H
