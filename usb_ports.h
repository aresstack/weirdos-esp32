// ============================================================================
// usb_ports.h -- Vom Nutzer gepflegtes USB-Port-Mapping des Boards (universelle Firmware).
//
// Idee: Die Firmware kennt nur die USB-Faehigkeiten des CHIPS; welche davon auf dem konkreten Board
// an einer Buchse/Stiftleiste liegen und wie sie heissen, traegt der Nutzer ein (System > Geraete >
// USB-Anschluesse): Anzahl der Ports, je Port ein Name (z.B. "MX1.25", "Stiftleiste"), die Pins D-/D+
// und ob er benutzt wird. Rollen (Modem-Host = cellular0, PC-Geraet = UVC/...) verweisen auf diese Ports.
//
// Ehrliche Grenze: USB-Pins sind auf ESP32-Chips NICHT frei waehlbar -- die Controller haengen an festen
// Pads. Die Pin-Eingabe wird deshalb gegen die Chip-Tabelle geprueft und sagt, welcher Controller das ist:
//   ESP32-P4: HS  = OTG 2.0 High-Speed an dedizierten DM/DP-Pads (keine GPIO-Nummer; Eingabe "-1/-1")
//             FS0 = OTG 1.1 Full-Speed / USB-Serial-JTAG an FSLS-PHY 0 = GPIO24 (D-) / GPIO25 (D+)
//             FS1 = OTG 1.1 Full-Speed an FSLS-PHY 1 = GPIO26 (D-) / GPIO27 (D+)   (Chip-Vorgabe fuer OTG-FS)
//   ESP32-S3: FS  = OTG Full-Speed / USB-Serial-JTAG an GPIO19 (D-) / GPIO20 (D+)  (der einzige USB)
// Andere Pin-Paare werden abgelehnt (mit Hinweis auf die moeglichen).
//
// Host-Seite (Modem): peripheral_map fuer usb_host_install + FSLS-PHY-Wahl; Device-Seite (PC): rhport,
// PHY-Ziel, Geschwindigkeit. Beide Rollen auf demselben Port schliessen sich aus (ein Controller) --
// das entscheidet der Boot (Geraet-Export hat Vorrang, Modem-Host wird mit Grund uebersprungen).
// ============================================================================
#pragma once
#include <Arduino.h>

#define USB_PORTS_MAX 3

enum UsbCtrl : uint8_t { USBC_NONE = 0, USBC_HS = 1, USBC_FS_PHY0 = 2, USBC_FS_PHY1 = 3, USBC_FS = 4 /* S3: einziger FS */,
                         USBC_CUSTOM = 5 /* Profil "custom": Pins ohne Chip-Zuordnung -- gespeichert, aber von keinem Treiber initialisierbar (rote Warnung) */ };

struct UsbHwPair { const char* name; int8_t dm; int8_t dp; UsbCtrl ctrl; const char* note; };
struct UsbPortEntry {
    String  id;        // "USB0".."USB2" (fest, Referenz fuer Rollen)
    String  label;     // Nutzertext: Buchse/Stecker/Stiftleiste
    int8_t  dm = -1;   // GPIO D- (-1 = dedizierte HS-Pads)
    int8_t  dp = -1;   // GPIO D+
    bool    enabled = true;
    UsbCtrl ctrl = USBC_NONE;   // abgeleitet aus den Pins (Chip-Tabelle)
};

// Chip-Tabelle (fest)
int  usbHwPairCount();
const UsbHwPair& usbHwPair(int i);
UsbCtrl usbCtrlForPins(int dm, int dp);          // USBC_NONE = nicht moeglich

// Nutzer-Mapping (NVS "usbports")
void  usbPortsLoad();                             // frueh im Boot, VOR periphLoadConfig()/usbDeviceService.loadConfig()
int   usbPortsCount();
const UsbPortEntry& usbPort(int i);
int   usbPortIndex(const String& id);             // -1 = unbekannt
bool  usbPortUsable(const String& id);            // bekannt UND enabled UND Pins gueltig
String usbPortsSave(int count, const UsbPortEntry* entries);   // validiert (Profil custom: freie Pins, ctrl=USBC_CUSTOM); "" = ok, sonst Fehlertext
void   usbPortsApplyProfileDefaults(const String& profileId);   // Vorgaben des Plattform-Profils uebernehmen + speichern
void   usbPortsProfileDefaults(const String& profileId, UsbPortEntry* out, int& count);   // Vorgaben nur berechnen (Vorschau, ohne Speichern)
bool   usbPortHasCustomPins(const String& id);                // ctrl == USBC_CUSTOM (fuer die rote Warnung)
String usbPortDescribe(const String& id);         // "USB1: Stiftleiste -- FS OTG1.1, GPIO26 (D-)/GPIO27 (D+)"
String usbPortsText();                            // Konsole
String usbPortsJson();

// Host-Seite (Modem) fuer den gewaehlten Port
uint32_t usbPortHostPeripheralMap(const String& id);   // usb_host_config_t.peripheral_map (0 = Chip-Default)
void     usbPortApplyPhySelect(const String& id);      // P4: FSLS-PHY 0/1 fuer OTG1.1 waehlen (nach Host-Install/Device-PHY)
bool     usbPortIsHighSpeed(const String& id);

// Device-Seite (PC) fuer den gewaehlten Port
struct UsbDeviceHw { uint8_t rhport; bool highSpeed; bool utmi; uint8_t phyIdx; bool ok; };
UsbDeviceHw usbPortDeviceHw(const String& id);
