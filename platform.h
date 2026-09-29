// ============================================================================
// platform.h -- Plattform-/Board-Profil (Einrichtung > Plattform): zentrale Wahrheit darueber, WELCHES
// Board unter der Firmware liegt, damit alle Module ihre Faehigkeiten an EINER Stelle abfragen koennen
// (universelle Firmware: P4-Pico mit Modem, XIAO-S3 als VPN-Zugangspunkt, reine Webcam, ...).
//
// Ebenen:
//   * Chip = Compile-Ziel (fest je Binary): ESP32-P4 | ESP32-S3 -- liefert die harten Faehigkeiten
//     (USB-Controller und deren feste Pins, WLAN-Funk, PSRAM ...).
//   * Profil = Board-Verdrahtung (Nutzerwahl, persistent): welche Chip-Faehigkeit an welcher Buchse/Stiftleiste
//     liegt, Beschriftungen, Pinout-Bild. Mitgelieferte Profile: "esp32-p4-pico", "xiao-esp32-s3" (Daten aus
//     Schaltplan/Pinout). "custom" = Nutzer traegt alles selbst ein (USB-Pins frei, auf eigene Gefahr, rote Warnung).
//   * Das USB-Port-Mapping (usb_ports.*) wird aus dem Profil vorbelegt und bleibt danach editierbar.
//
// Pinout-Bild: aus einer Pin-Tabelle je Profil als SVG erzeugt (/pinout.svg); USB-Paare und die gemappten
// Ports werden hervorgehoben. Fuer "custom" kann spaeter eine eigene SVG-Datei hinterlegt werden (LittleFS).
// ============================================================================
#pragma once
#include <Arduino.h>

// func = die FESTE Besonderheit dieses Pins: ADC-/Touch-Kanal, I2C/I3C, USB-PHY, Versorgung -- und wo
// das Board den Pin intern mitbenutzt. Bewusst NUR Festes: was ueber die GPIO-Matrix frei routbar ist
// (UART/SPI/PWM/...), gehoert NICHT ins Pinout, sonst suggeriert das Bild eine feste Funktion.
// wired = wo das BOARD diesen Pin intern zusaetzlich mitbenutzt (nullptr = frei). Genau das ist die
// Information, die in einem einzigen Pinout-Bild untergeht: dieselbe Chip-Faehigkeit ist je Board frei,
// mitbenutzt oder gar nicht herausgefuehrt.
struct PlatformPin { const char* label; int8_t gpio; const char* func; const char* wired; };   // gpio -1 = Versorgung/GND/kein GPIO

// Pin, der NICHT an der Stiftleiste liegt: fest intern verdrahtet oder ein dediziertes Pad ohne
// GPIO-Nummer (USB-HS DM/DP, MIPI-Lanes). Header-Pins + diese ergeben zusammen die Chip-Sicht.
struct PlatformIntPin { const char* label; int8_t gpio; const char* func; const char* wired; bool dedicated; };

// Onboard-Baustein und die Pins, an denen er haengt (Zusatzchip-Sicht).
// bus/addr modellieren den BUS als eigene Ebene: mehrere Bausteine an EINEM I2C-Bus sind nicht vier
// direkte Leitungen zum SoC, sondern ein geteilter Bus mit vier Teilnehmern. Genau das macht die
// Aussage "GPIO27 ist geteilt" ueberhaupt erst verstaendlich.
//   bus  = "I2C" | "I2S" | "SPI" | "SDIO" | "RMII" | "USB" | "" (direkt/dediziert)
//   addr = Busadresse, wo es eine gibt (I2C), sonst ""
// gpios = dieselben Pins maschinenlesbar (CSV) fuer die ansichtsuebergreifende Markierung.
struct PlatformAux { const char* name; const char* kind; const char* bus; const char* addr;
                     const char* pins; const char* gpios; const char* note; };

// Wie belastbar sind die Daten dieses Profils? Ein Boardname allein ist KEINE Unterstuetzung --
// die Oberflaeche muss den Unterschied benennen, sonst sieht ein leeres Profil aus wie ein fertiges.
//   PDL_CATALOG = nur Name und Chip (aus dem Waveshare-Verzeichnis)
//   PDL_PARTIAL = interne Verdrahtung/Bausteine aus der Doku belegt, Stiftleiste noch nicht erfasst
//   PDL_FULL    = Stiftleiste UND interne Verdrahtung belegt
enum PlatformDataLevel : uint8_t { PDL_CATALOG = 0, PDL_PARTIAL = 1, PDL_FULL = 2 };
// MCU-Familie = die harte Chip-Wahrheit aus Datenblatt/Hardware-Design-Guide, unabhaengig vom Board.
// "USB-faehig" gibt es hier bewusst nicht: High-Speed-OTG, Full-Speed-OTG, blosses Serial/JTAG und
// gar kein USB sind vier verschiedene Dinge -- nur die erste Klasse traegt ein USB-Modem.
struct PlatformMcu { const char* id; const char* name; const char* usb; const char* radio; const char* io; };
int platformMcuCount();
const PlatformMcu& platformMcuAt(int i);
const PlatformMcu* platformMcuFor(const char* chipId);

struct PlatformProfile {
    const char* id;          // "esp32-p4-pico" | "xiao-esp32-s3" | "custom"
    const char* name;        // Anzeigename
    const char* chip;        // "ESP32-P4" | "ESP32-S3" | "*"  (Profil passt nur zu diesem Compile-Ziel; * = jedes)
    const PlatformPin* left;  int nLeft;    // Stiftleiste links (oben -> unten)
    const PlatformPin* right; int nRight;   // Stiftleiste rechts (oben -> unten)
    const PlatformIntPin* intPins; int nInt;   // nicht herausgefuehrt / dedizierte Pads (Chip-Sicht)
    const PlatformAux*    aux;     int nAux;   // Onboard-Bausteine (Zusatzchip-Sicht)
    uint8_t level;           // PlatformDataLevel: wie belastbar sind die Daten dieses Profils?
    const char* notes;       // Kurztext (Buchsen, USB, Besonderheiten)
};

void   platformLoad();                              // NVS "platform" (frueh im Boot, VOR usbPortsLoad)
const PlatformProfile& platformCurrent();
String platformId();
bool   platformIsCustom();
String platformSet(const String& id);               // "" = ok; setzt bei Profilwechsel die USB-Port-Vorgaben des Profils
int    platformCount();
const PlatformProfile& platformAt(int i);
bool   platformFitsChip(const PlatformProfile& p);  // passt zum Compile-Ziel?
bool   platformHasPinout(const PlatformProfile& p); // Pin-Daten hinterlegt (sonst blosser Katalogeintrag)
const char* platformLevelText(const PlatformProfile& p);   // Kurztext fuer die Oberflaeche
const char* platformChipName();                     // Compile-Ziel
// Drei Ansichten aus DENSELBEN Daten (view: ""|"board" = Platine, "chip" = SoC, "aux" = Zusatzchips):
//   board = was ist an der Stiftleiste herausgefuehrt und wie nutzbar
//   chip  = welche Pins/Pads der SoC ueberhaupt hat und was davon dieses Board belegt
//   aux   = welcher Onboard-Baustein an welchen Pins haengt
String platformSvg(const String& view = String());                              // Custom mit hinterlegter Datei -> diese, sonst erzeugt
String platformSvgFor(const String& profileId, const String& view = String());  // Vorschau fuer ein noch nicht gespeichertes Profil
String platformJson();
String platformText();                              // Konsole 'platform'

// ---- Eigenes Pinout-Bild (Profil "custom"): SVG-Datei auf der Datenpartition (LittleFS, Label "spiffs") ----
#define PLATFORM_SVG_MAX 98304                      // 96 KB
// Jede der drei Ansichten hat einen EIGENEN Speicherplatz -- man kann also auch die Chip- oder die
// Zusatzchip-Ansicht durch ein eigenes Bild ersetzen, nicht nur die Platine (view: ""|"chip"|"aux").
bool   platformSvgCustomExists(const String& view = String());
bool   platformSvgCustomAny();                      // irgendeine der drei Ansichten hinterlegt
String platformSvgCustomLoad(const String& view = String());   // "" wenn keine Datei
String platformSvgStore(const String& xml, const String& view = String());   // "" = ok (leerer Text loescht), sonst Fehlertext

// ---- Plattform-Konfiguration als Ganzes (Struct, JSON-Export/-Import) ---------------------------------------
// Zentrale Board-Wahrheit fuer alle Module (spaetere Feature-Schalter gehoeren hierher): Profil, USB-Mapping,
// Modem-Port, eigenes Pinout. Export = JSON zum Sichern/Uebertragen, Import = dieselbe Datei zurueckspielen.
#include "usb_ports.h"
struct PlatformConfig {
    String       profile;                 // Profil-ID
    int          portCount = 0;           // USB-Mapping
    UsbPortEntry ports[USB_PORTS_MAX];
    String       modemPort;               // Port von cellular0 (peripheral_registry)
    bool         hasSvg = false;          // eigenes Pinout hinterlegt (nur custom)
};
PlatformConfig platformConfigGet();
String platformConfigJson(bool withSvg);            // Export (withSvg: eigenes Pinout eingebettet)
String platformConfigImport(const String& json);    // "" = ok, sonst Fehlertext; wirkt nach Neustart
