// ============================================================================
// platform.cpp -- Plattform-Profile (siehe Header). Pin-Tabellen: P4-Pico aus dem Waveshare-Layout/Schaltplan,
// XIAO ESP32-S3 aus dem Seeed-Pinout. Custom = leere Tabelle, Nutzer pflegt USB-Pins selbst.
// ============================================================================
#include "platform.h"
#include "usb_ports.h"
#include "wifi_caps.h"
#include "peripheral_registry.h"   // periphModemPort / periphSaveModemPort (Teil der Plattform-Konfiguration)
#include <Preferences.h>
#include <LittleFS.h>              // eigenes Pinout-SVG (Profil custom) auf der Datenpartition "spiffs"

#if CONFIG_IDF_TARGET_ESP32P4
#define PLATFORM_CHIP "ESP32-P4"
#elif CONFIG_IDF_TARGET_ESP32S3
#define PLATFORM_CHIP "ESP32-S3"
#else
#define PLATFORM_CHIP "ESP32"
#endif

// ---- Waveshare ESP32-P4-Pico (Stiftleiste, oben -> unten; aus dem Board-Layout) ----------------
// ADC1 CH0-CH7 = GPIO16-23, Touch 1-14 = GPIO2-15 (ESP32-P4-Datenblatt/Hardware-Design-Guide).
// GPIO7/8 liegen auf dem Board am gemeinsamen Netz ESP_I2C_SDA/SCL (ES8311-Audiocodec und CSI-/DSI-
// Konfiguration) -- der Header haengt also am schon belegten Bus, daher "onboard geteilt". GPIO32/33
// sind die speziellen I3C-Pins (konfigurierbare interne Pull-ups), als normale GPIO trotzdem nutzbar.
static const PlatformPin kP4Left[]  = {
    {"GPIO54",54,nullptr},{"GPIO19",19,"ADC1 CH3"},{"GND",-1,nullptr},{"GPIO18",18,"ADC1 CH2"},{"GPIO17",17,"ADC1 CH1"},
    {"GPIO16",16,"ADC1 CH0"},{"GPIO15",15,"Touch 14"},{"GND",-1,nullptr},{"GPIO14",14,"Touch 13"},{"GPIO6",6,"Touch 5"},
    {"GPIO5",5,"Touch 4"},{"GPIO4",4,"Touch 3"},{"GND",-1,nullptr},{"GPIO3",3,"Touch 2"},{"GPIO2",2,"Touch 1"},
    {"GPIO8 / SCL",8,"I²C-Takt","ES8311 + CSI-/DSI-Konfiguration"},
    {"GPIO7 / SDA",7,"I²C-Daten","ES8311 + CSI-/DSI-Konfiguration"},{"GND",-1,nullptr},
    {"GPIO24 / USB D-",24,"Full-Speed-PHY 0"},{"GPIO25 / USB D+",25,"Full-Speed-PHY 0"} };
static const PlatformPin kP4Right[] = {
    {"VBUS",-1,"5 V von der USB-C-Buchse"},{"VSYS",-1,"Systemversorgung"},{"GND",-1,nullptr},{"EN",-1,"3,3-V-Regler ein/aus"},
    {"3V3",-1,"3,3 V Ausgang"},{"GPIO20",20,"ADC1 CH4"},{"GPIO21",21,"ADC1 CH5"},{"GND",-1,nullptr},{"GPIO22",22,"ADC1 CH6"},
    {"GPIO23",23,"ADC1 CH7"},{"RUN",-1,"ESP_EN / Reset"},{"GPIO26 / USB D-",26,"Full-Speed-PHY 1"},{"GND",-1,nullptr},
    {"GPIO27 / USB D+",27,"Full-Speed-PHY 1"},{"GPIO32",32,"I3C SCL"},{"GPIO33",33,"I3C SDA"},{"GPIO46",46,nullptr},
    {"GND",-1,nullptr},{"GPIO47",47,nullptr},{"GPIO48",48,nullptr} };
// ---- P4-Pico: Pins, die NICHT an der Stiftleiste liegen (Waveshare-Schaltplan Seite 1) -----------
// Das ist die Information, die im Board-Pinout zwangslaeufig fehlt und die man braucht, um zu
// verstehen, warum bestimmte Funktionen belegt sind oder sich gegenseitig ausschliessen.
static const PlatformIntPin kP4Int[] = {
    {"USB HS D-",-1,"USB 2.0 High-Speed","MX1.25-Buchse P1",true},
    {"USB HS D+",-1,"USB 2.0 High-Speed","MX1.25-Buchse P1",true},
    {"GPIO37",37,"UART0","CH343P, USB-C-Konsole",false},
    {"GPIO38",38,"UART0","CH343P, USB-C-Konsole",false},
    {"GPIO35",35,"BOOT","CH343 DTR/RTS: Auto-Boot/-Reset",false},
    {"GPIO9",9,"I2S DSDIN","ES8311 Audio-Codec",false},
    {"GPIO10",10,"I2S LRCK","ES8311 Audio-Codec",false},
    {"GPIO11",11,"I2S ASDOUT","ES8311 Audio-Codec",false},
    {"GPIO12",12,"I2S SCLK","ES8311 Audio-Codec",false},
    {"GPIO13",13,"I2S MCLK","ES8311 Audio-Codec",false},
    {"GPIO53",53,nullptr,"NS4150B Lautsprecher-Verstaerker",false},
    {"GPIO39-44",-1,nullptr,"microSD laut Boarddesign",false},
    {"MIPI-CSI D0/D1/CLK",-1,"Kamera-Lanes","Kamera-Buchse J1",true},
    {"MIPI-DSI D0/D1/CLK",-1,"Display-Lanes","Display-Buchse J2",true},
    {"FLASH-Pads",-1,nullptr,"GD25Q256 Flash",true},
};
// ---- P4-Pico: Onboard-Bausteine, nach BUS gruppiert -------------------------------------------
// Der I2C-Bus ist eine eigene Ebene: ES8311, Kamera- und Display-Konfiguration haengen NICHT je
// einzeln am SoC, sondern gemeinsam an GPIO7/8. Genau das macht "GPIO7 ist geteilt" verstaendlich.
static const PlatformAux kP4Aux[] = {
    {"ES8311","Audio-Codec","I2C","","GPIO7/8 (Steuerung), GPIO9-13 (I2S-Daten)","7,8,9,10,11,12,13",
     "Steuerung ueber den geteilten I2C-Bus, Audiodaten ueber eigene I2S-Leitungen."},
    {"Buchse J1","MIPI-CSI Kamera","I2C","","dedizierte CSI-Lanes + GPIO7/8","7,8",
     "Die Lanes sind dediziert; nur die Konfiguration laeuft ueber den geteilten I2C-Bus."},
    {"Buchse J2","MIPI-DSI Display","I2C","","dedizierte DSI-Lanes + GPIO7/8","7,8",
     "Die Lanes sind dediziert; nur die Konfiguration laeuft ueber den geteilten I2C-Bus."},
    {"NS4150B","Lautsprecher-Verstaerker","","","GPIO53","53","Haengt am Codec-Ausgang."},
    {"CH343P","USB-UART","","","GPIO37/38 (UART0)","37,38",
     "Die USB-C-Buchse fuehrt NICHT an den USB des Chips, sondern an diesen Wandler."},
    {"MX1.25 P1","USB-2.0-Buchse","","","dedizierte HS-Pads DM/DP","",
     "Der einzige echte USB-Anschluss des Chips am Board -- hier haengt das Modem."},
    {"GD25Q256","Flash","","","dedizierte Flash-Pads","","Programmspeicher, nicht anderweitig nutzbar."},
    {"microSD","Kartenleser","","","GPIO39-44 (laut Boarddesign)","39,40,41,42,43,44",
     "Einzelne Netze im Schaltplan nicht nachgeprueft -- vor eigener Nutzung pruefen."},
};
// SDA/SCL/MOSI/MISO/SCK sind die Seeed-VORGABEN der XIAO-Belegung, keine festen Chip-Funktionen --
// der S3 kann sie ueber die GPIO-Matrix auf fast jeden Pin legen. GPIO43/44 sind dagegen die festen
// UART0-Leitungen des Chips.
static const PlatformPin kS3Left[]  = {
    {"D0 / GPIO1",1,nullptr},{"D1 / GPIO2",2,nullptr},{"D2 / GPIO3",3,nullptr},{"D3 / GPIO4",4,nullptr},
    {"D4 / GPIO5",5,"SDA, XIAO-Vorgabe"},{"D5 / GPIO6",6,"SCL, XIAO-Vorgabe"},{"D6 / GPIO43",43,"TX, UART0"} };
static const PlatformPin kS3Right[] = {
    {"5V",-1,"Versorgung 5 V"},{"GND",-1,nullptr},{"3V3",-1,"3,3 V Ausgang"},
    {"D10 / GPIO9",9,"MOSI, XIAO-Vorgabe"},{"D9 / GPIO8",8,"MISO, XIAO-Vorgabe"},{"D8 / GPIO7",7,"SCK, XIAO-Vorgabe"},
    {"D7 / GPIO44",44,"RX, UART0"} };
// XIAO-S3: nur das, was sicher belegt ist (nativer USB des Chips an der USB-C-Buchse). Die uebrige
// Onboard-Verdrahtung ist hier NICHT hinterlegt -- lieber leer als geraten.
static const PlatformIntPin kS3Int[] = {
    {"GPIO19",19,"USB D-","USB-C-Buchse, nativer USB des Chips",false},
    {"GPIO20",20,"USB D+","USB-C-Buchse, nativer USB des Chips",false},
};

// ---- MCU-Familien: die harte Chip-Wahrheit (Datenblatt / Hardware-Design-Guide) --------------------
// Unabhaengig vom Board: dieselbe Familie sitzt auf voellig unterschiedlich verdrahteten Platinen.
// "USB-faehig" gibt es hier bewusst nicht -- die Klassen unterscheiden sich zu stark.
static const PlatformMcu kMcus[] = {
    { "ESP32-P4", "ESP32-P4", "USB 2.0 High-Speed OTG auf dedizierten DM/DP-Pads + Full-Speed OTG + USB Serial/JTAG", "kein Funk im Chip -- WLAN/Bluetooth nur ueber einen Co-Prozessor (z.B. ESP32-C6)", "55 GPIO, 8 ADC-Kanaele, 14 Touch, I3C, MIPI-CSI/DSI, Ethernet-MAC; Varianten mit 16/32 MB PSRAM" },
    { "ESP32-S31", "ESP32-S31", "nativer USB-OTG", "WLAN 6 (2,4 GHz), Bluetooth 5.4 LE + Classic, 802.15.4; Gigabit-Ethernet-MAC", "60 GPIO, 16 ADC-Pins (8 differentiell), 14 Touch, DVP-Kamera, RGB-LCD" },
    { "ESP32-S3", "ESP32-S3", "USB 2.0 Full-Speed OTG + USB Serial/JTAG, gemeinsames Paar GPIO19/20", "WLAN 4 (2,4 GHz), Bluetooth 5 LE", "45 GPIO, 20 ADC-Kanaele, 14 Touch, LCD-/Kamera-Schnittstelle" },
    { "ESP32-S2", "ESP32-S2", "USB 2.0 Full-Speed OTG, typisch GPIO19/20", "WLAN 4 (2,4 GHz), kein Bluetooth", "43 GPIO, 20 ADC-Kanaele, 14 Touch, DAC" },
    { "ESP32-C6", "ESP32-C6", "NUR USB Serial/JTAG (Full-Speed), GPIO12 D-/GPIO13 D+ -- kein allgemeiner USB-Host", "WLAN 6 (2,4 GHz), Bluetooth 5 LE, 802.15.4", "30 GPIO (QFN40) bzw. 22 (QFN32), 7 ADC-Kanaele, kein Touch" },
    { "ESP32-C61", "ESP32-C61", "NUR USB Serial/JTAG, GPIO12/13", "WLAN 6 (2,4 GHz), Bluetooth 5 LE", "30 GPIO, 4 ADC-Kanaele, kein Touch; In-Package-PSRAM" },
    { "ESP32-C5", "ESP32-C5", "NUR USB Serial/JTAG, GPIO13 D-/GPIO14 D+", "WLAN 6 zweibandig 2,4 + 5 GHz, Bluetooth 5 LE, 802.15.4", "29 GPIO, 6 ADC-Kanaele, kein Touch" },
    { "ESP32-C3", "ESP32-C3", "NUR USB Serial/JTAG, GPIO18 D-/GPIO19 D+", "WLAN 4 (2,4 GHz), Bluetooth 5 LE", "22 GPIO, 6 ADC-Kanaele, kein Touch" },
    { "ESP32-C2", "ESP32-C2 / ESP8684", "kein nativer USB", "WLAN 4 (2,4 GHz), Bluetooth 5 LE", "14 GPIO, 5 ADC-Kanaele" },
    { "ESP32-H4", "ESP32-H4", "Full-Speed USB-OTG plus separates USB Serial/JTAG", "kein WLAN; Bluetooth 5.4 LE + 802.15.4", "40 GPIO, 15 Touch, CAN FD" },
    { "ESP32-H21", "ESP32-H21", "NUR USB Serial/JTAG", "kein WLAN; Bluetooth LE + 802.15.4", "19 GPIO" },
    { "ESP32-H2", "ESP32-H2", "NUR USB Serial/JTAG, GPIO26 D-/GPIO27 D+", "kein WLAN; Bluetooth 5 LE + 802.15.4", "19 GPIO, kein Touch" },
    { "ESP32", "ESP32 (klassisch)", "kein nativer USB", "WLAN 4 (2,4 GHz), Bluetooth 4.2 Classic + LE", "bis 34 GPIO, 18 ADC-Kanaele, 10 Touch, 2 DAC, Ethernet-MAC" },
    { "ESP8266", "ESP8266 / ESP8285", "kein nativer USB", "WLAN 4 (2,4 GHz), kein Bluetooth", "bis 17 GPIO, 1 ADC-Kanal" },
};

// ---- Waveshare-Katalog: oeffentlich dokumentierte Boards je Familie -------------------------------
// Fuer diese Eintraege liegt (noch) KEIN Pinout vor -- nur Name und Chip. Waehlbar und speicherbar
// sind sie trotzdem: USB-Mapping und Faehigkeiten kommen dann aus der Chip-Tabelle. Ein Pinout kommt
// erst dazu, wenn Boardseite UND Schaltplan die Verdrahtung belegen -- geraten wird nichts.
static const char kNote_p4[] = "Waveshare-Katalog (ESP32-P4). Pinout noch nicht hinterlegt. Der P4 hat kein eigenes Funkmodul; USB 2.0 High-Speed liegt auf dedizierten Pads.";
static const char kNote_c6[] = "Waveshare-Katalog (ESP32-C6). Pinout noch nicht hinterlegt. ACHTUNG: der C6 hat nur USB Serial/JTAG, also KEINEN USB-Host -- ein USB-Modem laesst sich damit nicht betreiben.";
static const char kNote_c5[] = "Waveshare-Katalog (ESP32-C5). Pinout noch nicht hinterlegt. Nur USB Serial/JTAG, kein USB-Host.";
static const char kNote_c3[] = "Waveshare-Katalog (ESP32-C3). Pinout noch nicht hinterlegt. Nur USB Serial/JTAG, kein USB-Host.";
static const char kNote_h2[] = "Waveshare-Katalog (ESP32-H2). Pinout noch nicht hinterlegt. Nur USB Serial/JTAG, kein USB-Host, kein WLAN.";
static const char kNote_s2[] = "Waveshare-Katalog (ESP32-S2, aelterer Bestand ausserhalb der sechs aktuellen Doku-Verzeichnisse). Pinout noch nicht verifiziert. Nativer Full-Speed-USB-OTG auf GPIO19/20.";
static const char kNote_s3[] = "Waveshare-Katalog (ESP32-S3). Pinout noch nicht hinterlegt. Nativer Full-Speed-USB auf GPIO19/20 (Host mit OTG-Adapter moeglich).";

static const PlatformProfile kCatalog[] = {
    { "esp32-p4-core-dev-kit", "ESP32-P4-Core-DEV-KIT", "ESP32-P4", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_p4 },
    { "esp32-p4-eth", "ESP32-P4-ETH", "ESP32-P4", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_p4 },
    { "esp32-p4-module-dev-kit", "ESP32-P4-Module-DEV-KIT", "ESP32-P4", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_p4 },
    { "esp32-p4-nano", "ESP32-P4-NANO", "ESP32-P4", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_p4 },
    { "esp32-p4-wifi6", "ESP32-P4-WIFI6", "ESP32-P4", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_p4 },
    { "esp32-p4-wifi6-dev-kit", "ESP32-P4-WIFI6-DEV-KIT", "ESP32-P4", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_p4 },
    { "esp32-p4-wifi6-poe-eth", "ESP32-P4-WIFI6-POE-ETH", "ESP32-P4", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_p4 },
    { "esp32-p4-wifi6-touch-lcd-3-5", "ESP32-P4-WIFI6-Touch-LCD-3.5", "ESP32-P4", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_p4 },
    { "esp32-p4-wifi6-touch-lcd-4-3", "ESP32-P4-WIFI6-Touch-LCD-4.3", "ESP32-P4", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_p4 },
    { "esp32-p4-wifi6-touch-lcd-4b", "ESP32-P4-WIFI6-Touch-LCD-4B", "ESP32-P4", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_p4 },
    { "esp32-p4-wifi6-touch-lcd-5", "ESP32-P4-WIFI6-Touch-LCD-5", "ESP32-P4", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_p4 },
    { "esp32-p4-wifi6-touch-lcd-7b", "ESP32-P4-WIFI6-Touch-LCD-7B", "ESP32-P4", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_p4 },
    { "esp32-p4-wifi6-touch-lcd-x", "ESP32-P4-WIFI6-Touch-LCD-X", "ESP32-P4", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_p4 },
    { "esp32-p4-wifi6-touch-lcd-xc", "ESP32-P4-WIFI6-Touch-LCD-XC", "ESP32-P4", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_p4 },
    { "esp32-c6-dev-kit-nx", "ESP32-C6-DEV-KIT-NX", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-geek", "ESP32-C6-GEEK", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-zero", "ESP32-C6-Zero", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-zero-b", "ESP32-C6-Zero-B", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-lcd-0-85", "ESP32-C6-LCD-0.85", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-lcd-1-28", "ESP32-C6-LCD-1.28", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-lcd-1-3", "ESP32-C6-LCD-1.3", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-lcd-1-47", "ESP32-C6-LCD-1.47", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-lcd-1-69", "ESP32-C6-LCD-1.69", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-lcd-1-9", "ESP32-C6-LCD-1.9", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-lcd-2-73", "ESP32-C6-LCD-2.73", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-touch-lcd-1-28", "ESP32-C6-Touch-LCD-1.28", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-touch-lcd-1-47", "ESP32-C6-Touch-LCD-1.47", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-touch-lcd-1-54", "ESP32-C6-Touch-LCD-1.54", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-touch-lcd-1-69", "ESP32-C6-Touch-LCD-1.69", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-touch-lcd-2-8", "ESP32-C6-Touch-LCD-2.8", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-touch-amoled-1-32", "ESP32-C6-Touch-AMOLED-1.32", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-touch-amoled-1-43", "ESP32-C6-Touch-AMOLED-1.43", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-touch-amoled-1-64", "ESP32-C6-Touch-AMOLED-1.64", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-touch-amoled-1-8", "ESP32-C6-Touch-AMOLED-1.8", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-touch-amoled-2-06", "ESP32-C6-Touch-AMOLED-2.06", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-touch-amoled-2-16", "ESP32-C6-Touch-AMOLED-2.16", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c6-epaper-1-54", "ESP32-C6-ePaper-1.54", "ESP32-C6", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c6 },
    { "esp32-c5-lcd-1-47", "ESP32-C5-LCD-1.47", "ESP32-C5", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c5 },
    { "esp32-c5-mini-kit", "ESP32-C5-MINI-KIT", "ESP32-C5", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c5 },
    { "esp32-c5-pico", "ESP32-C5-Pico", "ESP32-C5", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c5 },
    { "esp32-c5-touch-lcd-1-69", "ESP32-C5-Touch-LCD-1.69", "ESP32-C5", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c5 },
    { "esp32-c5-touch-lcd-2-8", "ESP32-C5-Touch-LCD-2.8", "ESP32-C5", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c5 },
    { "esp32-c5-wifi6-kit", "ESP32-C5-WIFI6-KIT", "ESP32-C5", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c5 },
    { "esp32-c5-zero", "ESP32-C5-Zero", "ESP32-C5", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c5 },
    { "esp32-c3-lcd-0-71", "ESP32-C3-LCD-0.71", "ESP32-C3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c3 },
    { "esp32-c3-lcd-1-47", "ESP32-C3-LCD-1.47", "ESP32-C3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c3 },
    { "esp32-c3-zero", "ESP32-C3-Zero", "ESP32-C3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_c3 },
    { "esp32-h2-zero", "ESP32-H2-Zero", "ESP32-H2", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_h2 },
    { "esp32-s3-amoled-1-91", "ESP32-S3-AMOLED-1.91", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-audio-board", "ESP32-S3-AUDIO-Board", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-cam", "ESP32-S3-CAM", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-dev-kit-n8r8", "ESP32-S3-DEV-KIT-N8R8", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-dualeye-lcd-1-28", "ESP32-S3-DualEye-LCD-1.28", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-dualeye-touch-lcd-1-28", "ESP32-S3-DualEye-Touch-LCD-1.28", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-geek", "ESP32-S3-GEEK", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-lcd-0-85", "ESP32-S3-LCD-0.85", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-lcd-1-9", "ESP32-S3-LCD-1.9", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-lcd-2", "ESP32-S3-LCD-2", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-lcd-2-8", "ESP32-S3-LCD-2.8", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-lcd-2-8b", "ESP32-S3-LCD-2.8B", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-lcd-2-8c", "ESP32-S3-LCD-2.8C", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-lcd-driver-board", "ESP32-S3-LCD-Driver-Board", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-lr1121-xf", "ESP32-S3-LR1121-XF", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-matrix", "ESP32-S3-Matrix", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-rgb-matrix", "ESP32-S3-RGB-Matrix", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-rlcd-4-2", "ESP32-S3-RLCD-4.2", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-tiny", "ESP32-S3-Tiny", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-amoled-1-32", "ESP32-S3-Touch-AMOLED-1.32", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-amoled-1-43", "ESP32-S3-Touch-AMOLED-1.43", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-amoled-1-43c", "ESP32-S3-Touch-AMOLED-1.43C", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-amoled-1-64", "ESP32-S3-Touch-AMOLED-1.64", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-amoled-1-75", "ESP32-S3-Touch-AMOLED-1.75", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-amoled-1-75c", "ESP32-S3-Touch-AMOLED-1.75C", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-amoled-1-8", "ESP32-S3-Touch-AMOLED-1.8", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-amoled-2-06", "ESP32-S3-Touch-AMOLED-2.06", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-amoled-2-16", "ESP32-S3-Touch-AMOLED-2.16", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-amoled-2-41", "ESP32-S3-Touch-AMOLED-2.41", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-1-28", "ESP32-S3-Touch-LCD-1.28", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-1-46", "ESP32-S3-Touch-LCD-1.46", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-1-47", "ESP32-S3-Touch-LCD-1.47", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-1-54", "ESP32-S3-Touch-LCD-1.54", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-1-69", "ESP32-S3-Touch-LCD-1.69", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-1-83", "ESP32-S3-Touch-LCD-1.83", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-1-85", "ESP32-S3-Touch-LCD-1.85", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-1-85b", "ESP32-S3-Touch-LCD-1.85B", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-1-85c", "ESP32-S3-Touch-LCD-1.85C", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-2", "ESP32-S3-Touch-LCD-2", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-2-1", "ESP32-S3-Touch-LCD-2.1", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-2-8", "ESP32-S3-Touch-LCD-2.8", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-2-8b", "ESP32-S3-Touch-LCD-2.8B", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-2-8c", "ESP32-S3-Touch-LCD-2.8C", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-3-49", "ESP32-S3-Touch-LCD-3.49", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-3-5", "ESP32-S3-Touch-LCD-3.5", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-3-5b", "ESP32-S3-Touch-LCD-3.5B", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-4-3", "ESP32-S3-Touch-LCD-4.3", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-4-3b", "ESP32-S3-Touch-LCD-4.3B", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-4-3c", "ESP32-S3-Touch-LCD-4.3C", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-5", "ESP32-S3-Touch-LCD-5", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-7", "ESP32-S3-Touch-LCD-7", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-7b", "ESP32-S3-Touch-LCD-7B", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-touch-lcd-7c-box", "ESP32-S3-Touch-LCD-7C-BOX", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-zero", "ESP32-S3-Zero", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-epaper-1-54", "ESP32-S3-ePaper-1.54", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-epaper-1-54g", "ESP32-S3-ePaper-1.54G", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-epaper-3-97", "ESP32-S3-ePaper-3.97", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s3-epaper-13-3e6", "ESP32-S3-ePaper-13.3E6", "ESP32-S3", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s3 },
    { "esp32-s2-pico-m", "ESP32-S2-Pico-M", "ESP32-S2", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s2 },
    { "esp32-s2-lcd-0-96", "ESP32-S2-LCD-0.96", "ESP32-S2", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s2 },
    { "esp32-s2-lcd-0-96-m", "ESP32-S2-LCD-0.96-M", "ESP32-S2", nullptr,0, nullptr,0, nullptr,0, nullptr,0, PDL_CATALOG, kNote_s2 },
};

// ================== Boards mit belegter Verdrahtung (Recherchebericht 09.09.2026) ==================
// Quellen: Espressif-Datenblatt/HDG fuer die Chip-Wahrheit, Waveshare-Boarddoku fuer die Verdrahtung.
// Fuer diese Boards ist die INTERNE Verdrahtung belegt, die Reihenfolge der Stiftleiste aber (noch)
// nicht -- deshalb PDL_PARTIAL: Chip- und Zusatzchip-Sicht tragen echte Daten, die Platinen-Sicht
// sagt ehrlich, dass die Leiste fehlt. Nichts davon ist aus Boardnamen abgeleitet.

// ---- Waveshare ESP32-C5-LCD-2.73 (der vollstaendigste dokumentierte Fall) -----------------------
static const PlatformIntPin kC5Lcd273Int[] = {
    {"GPIO6",6,"SPI SCK","ILI9488-Display und TF-Karte",false},
    {"GPIO7",7,"SPI MOSI","ILI9488-Display und TF-Karte",false},
    {"GPIO5",5,"SPI MISO","ILI9488-Display und TF-Karte",false},
    {"GPIO4",4,"SPI DC","ILI9488-Display",false},
    {"GPIO8",8,"SPI CS","ILI9488-Display",false},
    {"GPIO9",9,"SPI CS","TF-Karte",false},
    {"GPIO27",27,"I2C SDA","geteilter Bus: QMI8658, PCF85063, SHTC3, CH32V003",false},
    {"GPIO26",26,"I2C SCL","geteilter Bus: QMI8658, PCF85063, SHTC3, CH32V003",false},
    {"GPIO11",11,"UART TX","Konsole",false},
    {"GPIO12",12,"UART RX","Konsole",false},
    {"GPIO13",13,"USB D-","USB Serial/JTAG des Chips",false},
    {"GPIO14",14,"USB D+","USB Serial/JTAG des Chips",false},
};
static const PlatformAux kC5Lcd273Aux[] = {
    {"QMI8658","Lage-/Beschleunigungssensor","I2C","0x6B","GPIO27 SDA / GPIO26 SCL","26,27","Am geteilten I2C-Bus."},
    {"PCF85063","Echtzeituhr","I2C","0x51","GPIO27 SDA / GPIO26 SCL","26,27","Am geteilten I2C-Bus."},
    {"SHTC3","Temperatur/Feuchte","I2C","0x70","GPIO27 SDA / GPIO26 SCL","26,27","Am geteilten I2C-Bus."},
    {"CH32V003","Co-Controller / IO-Erweiterung","I2C","0x24","GPIO27 SDA / GPIO26 SCL","26,27",
     "Setzt LCD-Reset (IO0), regelt die Hintergrundbeleuchtung per PWM, misst die Batterie per ADC; IO4-IO14 sind zusaetzliche IOs."},
    {"ILI9488","Display-Controller","SPI","","SCK 6, MOSI 7, MISO 5, DC 4, CS 8","4,5,6,7,8","Teilt den SPI-Bus mit der TF-Karte (eigenes CS)."},
    {"TF-Karte","Kartenleser","SPI","","SCK 6, MOSI 7, MISO 5, CS 9","5,6,7,9","Teilt den SPI-Bus mit dem Display (eigenes CS)."},
};

// ---- Waveshare ESP32-C6-Pico ---------------------------------------------------------------------
static const PlatformAux kC6PicoAux[] = {
    {"TCA9554PWR","IO-Erweiterung","I2C","","GPIO22 SDA / GPIO23 SCL","22,23",
     "Waveshare warnt ausdruecklich: diese beiden Header-Pins sind intern belegt und nicht beliebig anders nutzbar."},
};

// ---- Waveshare ESP32-S3-Pico ---------------------------------------------------------------------
static const PlatformAux kS3PicoAux[] = {
    {"CH343P","USB-UART","","","(Verdrahtung nicht erfasst)","",
     "Die Type-C-Buchse ist deshalb NICHT gleichbedeutend mit dem nativen USB des Chips."},
    {"CH334F","USB-Hub","","","(Verdrahtung nicht erfasst)","","Verteilt den USB-Anschluss auf dem Board."},
    {"W25Q128JVSIQ","Flash 16 MB","","","dedizierte Flash-Pads","","Programmspeicher."},
    {"MP28164","DC/DC-Wandler","","","(Versorgung)","","Spannungsversorgung des Boards."},
};

// ---- Waveshare ESP32-C6-Touch-LCD-1.83 -----------------------------------------------------------
static const PlatformAux kC6Lcd183Aux[] = {
    {"ST7789P","Display-Controller","","","(Verdrahtung nicht erfasst)","",""},
    {"CST816D","Touch-Controller","I2C","","(Adresse/Pins nicht erfasst)","",""},
    {"QMI8658","Lage-/Beschleunigungssensor","I2C","","(Adresse/Pins nicht erfasst)","",""},
    {"PCF85063","Echtzeituhr","I2C","","(Adresse/Pins nicht erfasst)","",""},
    {"AXP2101","Energieverwaltung/Laderegler","I2C","","(Adresse/Pins nicht erfasst)","",""},
    {"ES8311","Audio-Codec","I2C","","(Adresse/Pins nicht erfasst)","",""},
    {"ES7210","Audio-ADC (Mikrofone)","I2C","","(Adresse/Pins nicht erfasst)","",""},
    {"TF-Slot","Kartenleser","","","(Verdrahtung nicht erfasst)","",""},
};

// ---- Waveshare ESP32-P4-NANO-WIFI6-DB (Belastungstest fuer das Modell) ---------------------------
static const PlatformIntPin kP4NanoInt[] = {
    {"GPIO7",7,"I2C SDA","geteilter Bus: ES8311, GT911-Touch, Hintergrundbeleuchtung",false},
    {"GPIO8",8,"I2C SCL","geteilter Bus: ES8311, GT911-Touch, Hintergrundbeleuchtung",false},
    {"GPIO9-13",-1,"I2S","ES8311 Audio-Codec",false},
    {"GPIO14-19",-1,"SDIO","ESP32-C5 als Funk-Coprozessor",false},
    {"GPIO54",54,"RESET","ESP32-C5 als Funk-Coprozessor",false},
    {"GPIO28-35, 49-52",-1,"RMII","IP101GRI Ethernet-PHY",false},
    {"GPIO39-45",-1,"SDMMC","TF-Karte",false},
    {"USB HS D-/D+",-1,"USB 2.0 High-Speed","dedizierte Pads",true},
};
static const PlatformAux kP4NanoAux[] = {
    {"ES8311","Audio-Codec","I2C","","GPIO7/8 (Steuerung), GPIO9-13 (I2S)","7,8,9,10,11,12,13","Am geteilten I2C-Bus."},
    {"GT911","Touch-Controller","I2C","","GPIO7/8","7,8","Am geteilten I2C-Bus."},
    {"Hintergrundbeleuchtung","Display","I2C","","GPIO7/8","7,8","Ebenfalls ueber den geteilten I2C-Bus gesteuert."},
    {"ESP32-C5","Funk-Coprozessor (WLAN/BT)","SDIO","","GPIO14-19, RESET GPIO54","14,15,16,17,18,19,54",
     "Der P4 hat selbst keinen Funk -- WLAN kommt von diesem zweiten Chip."},
    {"IP101GRI","Ethernet-PHY","RMII","","GPIO28-35, 49-52","28,29,30,31,32,33,34,35,49,50,51,52",""},
    {"TF-Karte","Kartenleser","SDIO","","GPIO39-45","39,40,41,42,43,44,45",""},
};

// ---- Waveshare ESP32-H2-DEV-KIT-N4 ---------------------------------------------------------------
static const PlatformAux kH2DevAux[] = {
    {"ESP32-H2-MINI-1","Modul","","","(Modulpinout nicht erfasst)","","Traegt den Chip; Board-Pinout kompatibel zum DevKitM."},
    {"CH343","USB-UART","","","(Verdrahtung nicht erfasst)","",""},
    {"CH334","USB-Hub","","","(Verdrahtung nicht erfasst)","",""},
};

// ---- Waveshare ESP32-S2-Pico (aelterer Bestand, nicht im aktuellen Doku-Index) --------------------
static const PlatformIntPin kS2PicoInt[] = {
    {"GPIO19",19,"USB D-","USB-C-Buchse, nativer Full-Speed-OTG des Chips",false},
    {"GPIO20",20,"USB D+","USB-C-Buchse, nativer Full-Speed-OTG des Chips",false},
};
static const PlatformAux kS2PicoAux[] = {
    {"APS6404L","PSRAM 8 MB","","","(dedizierte Speicherpins)","",""},
    {"MP28164","DC/DC-Wandler","","","(Versorgung)","",""},
    {"WS2812B","RGB-LED","","","(Verdrahtung nicht erfasst)","",""},
};
#define PF_N(a) (int)(sizeof(a)/sizeof(a[0]))
static const PlatformProfile kProfiles[] = {
    { "esp32-p4-pico", "Waveshare ESP32-P4-Pico", "ESP32-P4", kP4Left, 20, kP4Right, 20,
      kP4Int, PF_N(kP4Int), kP4Aux, PF_N(kP4Aux), PDL_FULL,
      "USB-C = CH343-UART (Konsole/Flash, KEIN USB des Chips; die UART-Seite haengt an GPIO37/38). MX1.25-4-Pin = "
      "USB 2.0 High-Speed OTG (dedizierte DM/DP-Pads, keine GPIO-Nummern). Stiftleiste: GPIO24/25 = Full-Speed-PHY 0 "
      "(Vorgabe USB-Serial/JTAG), GPIO26/27 = Full-Speed-PHY 1 (Vorgabe OTG-FS). BOOT = GPIO35. "
      "SCL/SDA am Header sind GPIO8/GPIO7 und liegen am selben I2C-Bus wie der ES8311-Audiocodec und die "
      "CSI-/DSI-Konfiguration -- eigene Geraete daran teilen sich den Bus (Adressen pruefen)." },
    { "xiao-esp32-s3", "Seeed XIAO ESP32-S3", "ESP32-S3", kS3Left, 7, kS3Right, 7,
      kS3Int, PF_N(kS3Int), nullptr, 0, PDL_FULL,
      "USB-C = nativer USB des Chips (GPIO19 D-/GPIO20 D+): Programmierport, Modem-Host (OTG-Adapter) und PC-Geraet -- ein Port fuer alles. WLAN vorhanden." },

    // Verdrahtung aus der Waveshare-Boarddoku belegt, Stiftleiste noch nicht erfasst (PDL_PARTIAL).
    { "esp32-c5-lcd-2-73", "Waveshare ESP32-C5-LCD-2.73", "ESP32-C5", nullptr, 0, nullptr, 0,
      kC5Lcd273Int, PF_N(kC5Lcd273Int), kC5Lcd273Aux, PF_N(kC5Lcd273Aux), PDL_PARTIAL,
      "Vollstaendigster dokumentierter Fall: ein geteilter I2C-Bus (GPIO27 SDA / GPIO26 SCL) traegt QMI8658 (0x6B), "
      "PCF85063 (0x51), SHTC3 (0x70) und den Co-Controller CH32V003 (0x24); Display und TF-Karte teilen sich den "
      "SPI-Bus mit eigenen CS-Leitungen. USB Serial/JTAG liegt fest auf GPIO13/14. Kein USB-Host -- kein Modem." },
    { "esp32-c6-pico", "Waveshare ESP32-C6-Pico", "ESP32-C6", nullptr, 0, nullptr, 0,
      nullptr, 0, kC6PicoAux, PF_N(kC6PicoAux), PDL_PARTIAL,
      "Referenzfall fuer 'herausgefuehrt, aber intern belegt': GPIO22/23 liegen an der Stiftleiste UND am "
      "TCA9554PWR-IO-Erweiterer. Waveshare warnt ausdruecklich davor, sie anderweitig zu benutzen. "
      "Der C6 hat nur USB Serial/JTAG -- kein USB-Host, also kein Modem." },
    { "esp32-s3-pico", "Waveshare ESP32-S3-Pico", "ESP32-S3", nullptr, 0, nullptr, 0,
      nullptr, 0, kS3PicoAux, PF_N(kS3PicoAux), PDL_PARTIAL,
      "Zeigt den Unterschied zwischen nativem ESP-USB und externen USB-Bausteinen: an der Type-C-Buchse haengen "
      "CH343P (USB-UART) und CH334F (USB-Hub), nicht direkt der USB des Chips. Die Verdrahtung der einzelnen "
      "GPIOs ist in der Boarddoku nicht aufgeschluesselt und daher hier nicht hinterlegt." },
    { "esp32-c6-touch-lcd-1-83", "Waveshare ESP32-C6-Touch-LCD-1.83", "ESP32-C6", nullptr, 0, nullptr, 0,
      nullptr, 0, kC6Lcd183Aux, PF_N(kC6Lcd183Aux), PDL_PARTIAL,
      "Bausteine aus der Boarddoku belegt (Display, Touch, IMU, RTC, Energieverwaltung, Audio-Codec und -ADC, "
      "TF-Slot); die GPIO-Zuordnung nennt Waveshare dort nicht, sie fehlt hier deshalb bewusst. "
      "Der C6 hat nur USB Serial/JTAG -- kein USB-Host." },
    { "esp32-p4-nano-wifi6-db", "Waveshare ESP32-P4-NANO-WIFI6-DB", "ESP32-P4", nullptr, 0, nullptr, 0,
      kP4NanoInt, PF_N(kP4NanoInt), kP4NanoAux, PF_N(kP4NanoAux), PDL_PARTIAL,
      "Der Belastungstest fuers Modell: dedizierte HS-USB-Pads, ein geteilter I2C-Bus (GPIO7/8) fuer ES8311, "
      "GT911-Touch und Hintergrundbeleuchtung, I2S auf GPIO9-13, ein zweiter ESP32-C5 als Funk-Coprozessor ueber "
      "SDIO (GPIO14-19, Reset GPIO54), Ethernet-PHY IP101GRI ueber RMII und die TF-Karte ueber SDMMC." },
    { "esp32-h2-dev-kit-n4", "Waveshare ESP32-H2-DEV-KIT-N4", "ESP32-H2", nullptr, 0, nullptr, 0,
      nullptr, 0, kH2DevAux, PF_N(kH2DevAux), PDL_PARTIAL,
      "Einfacher Gegentest zum Modell: Modul ESP32-H2-MINI-1, CH343 als USB-UART und CH334 als Hub, Pinout "
      "kompatibel zum DevKitM. Kein WLAN, kein USB-Host." },
    { "esp32-s2-pico", "Waveshare ESP32-S2-Pico", "ESP32-S2", nullptr, 0, nullptr, 0,
      kS2PicoInt, PF_N(kS2PicoInt), kS2PicoAux, PF_N(kS2PicoAux), PDL_PARTIAL,
      "Aelterer Bestand ausserhalb der sechs aktuellen Waveshare-Doku-Verzeichnisse -- bewusst aufgenommen, damit "
      "die Datenbasis nicht nur die heutige Webnavigation abbildet. ESP32-S2FH4 mit 8 MB PSRAM (APS6404L); "
      "nativer Full-Speed-USB-OTG auf GPIO19/20." },

    { "custom", "Eigenes Board (Custom)", "*", nullptr, 0, nullptr, 0, nullptr, 0, nullptr, 0, PDL_CATALOG,
      "Alles selbst eintragen: USB-Anschluesse mit Pins (auf eigene Gefahr, ohne Pruefung gegen die Chip-Tabelle), Beschriftungen. Kein Pinout-Bild." },
};
static String g_id;

// Zwei Quellen, EIN Index: erst die Profile mit echten Pin-Daten, dann der Waveshare-Katalog.
#define PF_BUILTIN ((int)(sizeof(kProfiles) / sizeof(kProfiles[0])))
#define PF_CATALOG ((int)(sizeof(kCatalog)  / sizeof(kCatalog[0])))
int platformCount() { return PF_BUILTIN + PF_CATALOG; }
const PlatformProfile& platformAt(int i) {
    if (i < 0 || i >= platformCount()) i = 0;
    return i < PF_BUILTIN ? kProfiles[i] : kCatalog[i - PF_BUILTIN];
}
int platformMcuCount() { return (int)(sizeof(kMcus) / sizeof(kMcus[0])); }
const PlatformMcu& platformMcuAt(int i) { return kMcus[(i < 0 || i >= platformMcuCount()) ? 0 : i]; }
const PlatformMcu* platformMcuFor(const char* chipId) {
    for (int i = 0; i < platformMcuCount(); i++) if (!strcmp(kMcus[i].id, chipId)) return &kMcus[i];
    return nullptr;
}
bool platformHasPinout(const PlatformProfile& p) { return p.level >= PDL_PARTIAL; }
// Ehrlicher Kurztext statt "(kein Pinout)": ein Boardname allein ist keine Unterstuetzung, und ein
// Profil mit belegter Verdrahtung, aber ohne Stiftleiste, ist etwas anderes als ein leeres.
const char* platformLevelText(const PlatformProfile& p) {
    if (p.level >= PDL_FULL)    return "Stiftleiste und Verdrahtung belegt";
    if (p.level == PDL_PARTIAL) return "Verdrahtung belegt, Stiftleiste fehlt";
    return "Katalog -- Verdrahtung nicht verifiziert";
}
const char* platformChipName() { return PLATFORM_CHIP; }
bool platformFitsChip(const PlatformProfile& p) { return p.chip[0] == '*' || !strcmp(p.chip, PLATFORM_CHIP); }
static const PlatformProfile* find(const String& id) {
    for (int i = 0; i < platformCount(); i++) { const PlatformProfile& q = platformAt(i); if (id == q.id) return &q; }
    return nullptr;
}
// Vorgabe: das erste EIGENE Profil (mit Pin-Daten), das zum Build passt -- nie ein Katalogeintrag.
static const char* defaultId() {
    for (int i = 0; i < PF_BUILTIN; i++) if (platformFitsChip(kProfiles[i]) && kProfiles[i].chip[0] != '*') return kProfiles[i].id;
    return "custom";
}

void platformLoad() {
    Preferences p; p.begin("platform", true);
    g_id = p.getString("id", defaultId());
    p.end();
    const PlatformProfile* pr = find(g_id);
    if (!pr || !platformFitsChip(*pr)) g_id = defaultId();
}
const PlatformProfile& platformCurrent() { const PlatformProfile* pr = find(g_id); return pr ? *pr : kProfiles[PF_BUILTIN - 1]; }
String platformId() { return g_id; }
bool   platformIsCustom() { return g_id == "custom"; }
String platformSet(const String& id) {
    const PlatformProfile* pr = find(id);
    if (!pr) return "unbekanntes Profil";
    if (!platformFitsChip(*pr)) return String("Profil '") + pr->name + "' passt nicht zum Chip dieses Builds (" + PLATFORM_CHIP + ")";
    bool changed = (id != g_id);
    g_id = id;
    Preferences p; p.begin("platform", false); p.putString("id", g_id); p.end();
    if (changed) usbPortsApplyProfileDefaults(g_id);   // USB-Mapping des Profils vorbelegen (Custom: leer/frei)
    return "";
}

// ---- Pinout-SVG ------------------------------------------------------------------------------------
static bool pinIsUsb(const UsbPortEntry* ports, int nPorts, int gpio, String& portTag) {
    portTag = "";
    if (gpio < 0) return false;
    for (int i = 0; i < nPorts; i++) {
        const UsbPortEntry& e = ports[i];
        if (e.dm == gpio || e.dp == gpio) { portTag = e.id + (e.enabled ? "" : " (aus)"); return true; }
    }
    for (int k = 0; k < usbHwPairCount(); k++) if (usbHwPair(k).dm == gpio || usbHwPair(k).dp == gpio) return true;
    return false;
}
static String esc(const String& s) { String o = s; o.replace("&", "&amp;"); o.replace("<", "&lt;"); o.replace(">", "&gt;"); return o; }
static bool entryIsFixedHs(const UsbPortEntry& e) { return e.dm < 0 && usbCtrlForPins(e.dm, e.dp) == USBC_HS; }
// Pin-Beschriftung: Name in normaler Groesse, die feste Besonderheit klein und grau in Klammern,
// ein zugeordneter USB-Port in eckigen Klammern -- als tspans, damit die Zusatztexte das Bild nicht
// dominieren und das Pinout auf einen Blick lesbar bleibt.
static String pinLabelSvg(const char* label, const char* func, const String& note, const String& portTag) {
    String t = esc(label);
    String extra = (func && func[0]) ? String(func) : String();
    if (note.length()) { if (extra.length()) extra += ", "; extra += note; }
    if (extra.length())   t += String("<tspan fill='#666' font-size='10' font-weight='normal'> (") + esc(extra) + ")</tspan>";
    if (portTag.length()) t += String("<tspan fill='#8a3d10' font-size='10' font-weight='bold'> [") + esc(portTag) + "]</tspan>";
    return t;
}
// Farbe = Nutzbarkeit. Der Klammertext sagt dasselbe noch einmal in Worten, damit die Aussage nicht
// allein an der Farbe haengt (Farbsehschwaeche).
static const char* kColHeader = "#4c9be8", *kColShared = "#8e44ad", *kColInternal = "#7f8c8d",
                  *kColPad    = "#e8732a", *kColUsb    = "#e0a800", *kColPower    = "#999";
// Markierung: die Seite haengt die Klasse 'sel' an eine Pin- bzw. Bausteingruppe. Die Regeln stehen IM
// SVG, damit sie auch beim Direktaufruf von /pinout.svg greifen (dort gibt es kein Seiten-CSS).
// Klickbare Pin-Gruppe: nur GPIO-nummerierte Pins sind ansichtsuebergreifend identifizierbar.
// Dedizierte Pads haben bewusst keine Nummer -- genau das ist ja ihre Aussage.
static String pinGroupOpen(int gpio) {
    if (gpio < 0) return String();
    return String("<g class='pin' data-pin='") + gpio + "'>";
}
// Zwei Stufen, damit ein Klick nicht "alles leuchtet" bedeutet:
//   .sel = das ANGEKLICKTE Element (durchgezogen, kraeftig)
//   .rel = teilt sich Pins damit (gestrichelt, zurueckhaltend)
// Gelb-orange als Auswahlfarbe; Rot waere in dieser Oberflaeche ein Fehler, und eine Auswahl ist
// keiner. Die Unterscheidung traegt zusaetzlich durchgezogen vs. gestrichelt -- damit bleibt sie
// auch bei Farbsehschwaeche lesbar und kollidiert nicht mit den Pin-Farben (die Bedeutung tragen).
static const char* kSvgStyle =
    "<style>.pin,.aux{cursor:pointer}"
    ".pin.sel circle{stroke:#e8871a;stroke-width:3.5}.pin.sel>text{font-weight:bold}"
    ".pin.rel circle{stroke:#e8871a;stroke-width:2.5;stroke-dasharray:3 2}"
    ".aux.sel rect{stroke:#e8871a;stroke-width:3;fill:#fff6e5}"
    ".aux.rel rect{stroke:#e8871a;stroke-width:2;stroke-dasharray:5 3;fill:#fffdf7}</style>";
static String buildBoardSvg(const PlatformProfile& p, const UsbPortEntry* ports, int nPorts) {
    // Breiter als frueher: die Pins tragen jetzt zusaetzlich ihre feste Besonderheit als Klammertext.
    const int rowH = 22, top = 60, w = 800, bx = 300, bw = 180, cx = bx + bw / 2;
    int rows = p.nLeft > p.nRight ? p.nLeft : p.nRight;
    // Feste USB-Anschluesse (HS-OTG, dedizierte UTMI-Pads ohne GPIO) als eigener Block unter dem Chip, orange.
    int fixedN = 0;
    for (int i = 0; i < nPorts; i++) if (entryIsFixedHs(ports[i])) fixedN++;
    int h = top + rows * rowH + 90 + (fixedN ? fixedN * 30 + 12 : 0);   // Platz fuer die orangen Bloecke + dreizeilige Legende
    // data-empty: die Seite zeigt dann einen Upload-Kasten statt eines leeren Bildes.
    bool empty = (p.nLeft == 0 && p.nRight == 0);
    String s = String("<svg xmlns='http://www.w3.org/2000/svg' width='") + w + "' height='" + h + "' viewBox='0 0 " + w + " " + h + "'"
             + (empty ? " data-empty='1'" : "") + " font-family='Arial,Helvetica,sans-serif' font-size='12'>" + kSvgStyle;
    s += String("<rect x='") + bx + "' y='30' width='" + bw + "' height='" + (rows * rowH + 30) + "' rx='10' fill='#1f6f3f' stroke='#0f3a20'/>";
    s += String("<text x='") + cx + "' y='50' text-anchor='middle' fill='#fff' font-size='13' font-weight='bold'>" + esc(p.name) + "</text>";
    s += String("<text x='") + cx + "' y='" + (top + rows * rowH + 12) + "' text-anchor='middle' fill='#cde' font-size='11'>" + PLATFORM_CHIP + "</text>";
    if (p.nLeft == 0 && p.nRight == 0) {
        s += String("<text x='") + cx + "' y='" + (top + 30) + "' text-anchor='middle' fill='#fff'>kein Pinout hinterlegt</text>";
        s += String("<text x='") + cx + "' y='" + (top + 50) + "' text-anchor='middle' fill='#cde' font-size='11'>Katalogeintrag oder eigenes Board -- Pin-Daten koennen ueber XML ergaenzt werden</text>";
    }
    for (int i = 0; i < rows; i++) {
        int y = top + i * rowH;
        if (i < p.nLeft) {
            const PlatformPin& pin = p.left[i];
            String tag; bool usb = pinIsUsb(ports, nPorts, pin.gpio, tag);
            bool shared = pin.wired && pin.wired[0];
            const char* fill = usb ? kColUsb : (pin.gpio < 0 ? kColPower : (shared ? kColShared : kColHeader));
            s += pinGroupOpen(pin.gpio);
            s += String("<circle cx='") + (bx + 6) + "' cy='" + y + "' r='6' fill='" + fill + "' stroke='#222'/>";
            s += String("<text x='") + (bx - 6) + "' y='" + (y + 4) + "' text-anchor='end' fill='#222'" + (usb ? " font-weight='bold'" : "") + ">"
                 + pinLabelSvg(pin.label, pin.func, shared ? String("onboard geteilt") : String(), tag) + "</text>";
            if (pin.gpio >= 0) s += "</g>";
        }
        if (i < p.nRight) {
            const PlatformPin& pin = p.right[i];
            String tag; bool usb = pinIsUsb(ports, nPorts, pin.gpio, tag);
            bool shared = pin.wired && pin.wired[0];
            const char* fill = usb ? kColUsb : (pin.gpio < 0 ? kColPower : (shared ? kColShared : kColHeader));
            s += pinGroupOpen(pin.gpio);
            s += String("<circle cx='") + (bx + bw - 6) + "' cy='" + y + "' r='6' fill='" + fill + "' stroke='#222'/>";
            s += String("<text x='") + (bx + bw + 6) + "' y='" + (y + 4) + "' fill='#222'" + (usb ? " font-weight='bold'" : "") + ">"
                 + pinLabelSvg(pin.label, pin.func, shared ? String("onboard geteilt") : String(), tag) + "</text>";
            if (pin.gpio >= 0) s += "</g>";
        }
    }
    int fy = top + rows * rowH + 34;
    for (int i = 0, k = 0; i < nPorts; i++) {
        const UsbPortEntry& e = ports[i];
        if (!entryIsFixedHs(e)) continue;
        s += String("<rect x='") + (cx - 120) + "' y='" + (fy + k * 30) + "' width='240' height='22' rx='5' fill='#e8732a' stroke='#8a3d10'/>";
        s += String("<text x='") + cx + "' y='" + (fy + k * 30 + 15) + "' text-anchor='middle' fill='#fff' font-size='11' font-weight='bold'>"
             + esc(e.label) + " = " + e.id + " USB 2.0 HS (fest)</text>";
        k++;
    }
    s += String("<text x='10' y='") + (h - 62) + "' fill='#555' font-size='11'>gelb = USB-Datenpins [zugeordneter Port], blau = frei an der Stiftleiste, violett = intern mitbenutzt, grau = Versorgung"
         + (fixedN ? ", orange = fester USB-Anschluss (dedizierte Pads, nicht einstellbar)" : "") + "</text>";
    s += String("<text x='10' y='") + (h - 44) + "' fill='#777' font-size='10'>(Klammer) = feste Besonderheit des Pins: ADC-/Touch-Kanal, I2C/I3C, USB-PHY, Versorgung.</text>";
    s += String("<text x='10' y='") + (h - 28) + "' fill='#777' font-size='10'>Frei routbare Funktionen (UART, SPI, PWM ...) stehen bewusst nicht im Bild: die GPIO-Matrix legt sie auf fast jeden Pin.</text>";
    s += "</svg>";
    return s;
}
// ---- Chip-Sicht: alle Pins/Pads des SoC, die dieses Board kennt -------------------------------------
// Beantwortet "was hat der Chip ueberhaupt, und was davon ist auf DIESEM Board schon vergeben".
// Ohne Zwischenspeicher: der Zugriff laeuft zweimal ueber dieselben const-Tabellen (n ist klein) --
// auf dem P4 gehoert kein KB-Array auf den HTTP-Stack.
struct ChipRow { const char* label; const char* func; const char* wired; int8_t gpio; bool dedicated; bool header; };
static int chipRowCount(const PlatformProfile& p) {
    int n = p.nInt;
    for (int i = 0; i < p.nLeft;  i++) if (p.left[i].gpio  >= 0) n++;
    for (int i = 0; i < p.nRight; i++) if (p.right[i].gpio >= 0) n++;
    return n;
}
static bool chipRowAt(const PlatformProfile& p, int k, ChipRow& r) {
    for (int i = 0; i < p.nLeft; i++)  if (p.left[i].gpio  >= 0 && k-- == 0) { r = { p.left[i].label,  p.left[i].func,  p.left[i].wired,  p.left[i].gpio,  false, true }; return true; }
    for (int i = 0; i < p.nRight; i++) if (p.right[i].gpio >= 0 && k-- == 0) { r = { p.right[i].label, p.right[i].func, p.right[i].wired, p.right[i].gpio, false, true }; return true; }
    for (int i = 0; i < p.nInt; i++)   if (k-- == 0) { const PlatformIntPin& q = p.intPins[i]; r = { q.label, q.func, q.wired, q.gpio, q.dedicated, false }; return true; }
    return false;
}
static String buildChipSvg(const PlatformProfile& p) {
    const int rowH = 22, top = 60, w = 900, bx = 340, bw = 200, cx = bx + bw / 2;
    int n = chipRowCount(p), rows = (n + 1) / 2;
    int h = top + rows * rowH + 92;
    // data-empty: die Seite zeigt dann einen Upload-Kasten statt eines leeren Bildes.
    bool empty = (n == 0);
    String s = String("<svg xmlns='http://www.w3.org/2000/svg' width='") + w + "' height='" + h + "' viewBox='0 0 " + w + " " + h + "'"
             + (empty ? " data-empty='1'" : "") + " font-family='Arial,Helvetica,sans-serif' font-size='12'>" + kSvgStyle;
    s += String("<rect x='") + bx + "' y='30' width='" + bw + "' height='" + (rows * rowH + 30) + "' rx='10' fill='#2c3e50' stroke='#16202a'/>";
    s += String("<text x='") + cx + "' y='50' text-anchor='middle' fill='#fff' font-size='13' font-weight='bold'>" + PLATFORM_CHIP + "</text>";
    s += String("<text x='") + cx + "' y='" + (top + rows * rowH + 12) + "' text-anchor='middle' fill='#9fb3c8' font-size='11'>auf " + esc(p.name) + "</text>";
    if (!n) s += String("<text x='") + cx + "' y='" + (top + 30) + "' text-anchor='middle' fill='#fff'>keine Pin-Daten hinterlegt</text>";
    for (int k = 0; k < n; k++) {
        ChipRow r; if (!chipRowAt(p, k, r)) break;
        bool left = (k < rows);
        int y = top + (left ? k : k - rows) * rowH;
        bool shared = r.wired && r.wired[0];
        const char* fill = r.dedicated ? kColPad : (r.header ? (shared ? kColShared : kColHeader) : kColInternal);
        String note = shared ? String(r.wired) : String();
        if (!r.header && !shared) note = "nicht herausgefuehrt";
        // "dediziertes Pad" sagt schon die Farbe samt Legende -- nicht doppelt in die Zeile schreiben.
        s += pinGroupOpen(r.gpio);
        s += String("<circle cx='") + (left ? bx + 6 : bx + bw - 6) + "' cy='" + y + "' r='6' fill='" + fill + "' stroke='#222'/>";
        s += String("<text x='") + (left ? bx - 6 : bx + bw + 6) + "' y='" + (y + 4) + "'" + (left ? " text-anchor='end'" : "") + " fill='#222'>"
             + pinLabelSvg(r.label, r.func, note, String()) + "</text>";
        if (r.gpio >= 0) s += "</g>";
    }
    s += String("<text x='10' y='") + (h - 62) + "' fill='#555' font-size='11'>blau = frei an der Stiftleiste, violett = an der Stiftleiste UND intern mitbenutzt, grau = nur intern verdrahtet, orange = dediziertes Pad ohne GPIO-Nummer</text>";
    s += String("<text x='10' y='") + (h - 44) + "' fill='#777' font-size='10'>Die Farbe steht auch als Wort im Klammertext -- die Aussage haengt nicht an der Farbe allein.</text>";
    s += String("<text x='10' y='") + (h - 28) + "' fill='#777' font-size='10'>Nur was das Board belegt bzw. herausfuehrt. Frei routbare Funktionen legt die GPIO-Matrix ohnehin auf fast jeden Pin.</text>";
    s += "</svg>";
    return s;
}
// ---- Zusatzchip-Sicht: welcher Onboard-Baustein haengt an welchen Pins -------------------------------
// Bewusst Kaesten statt gezeichneter Leitungen: die Aussage "X haengt an diesen Pins" ist genau das,
// was im Board-Pinout fehlt -- ein Linien-Layout waere viel Code fuer wenig zusaetzliche Aussage.
// Bausteine nach BUS gruppiert (Modell aus dem Recherchebericht): vier Geraete an einem I2C-Bus sind
// NICHT vier direkte Leitungen zum SoC, sondern ein geteilter Bus mit vier Teilnehmern. Erst so wird
// verstaendlich, warum ein einzelner Pin "geteilt" ist und was daran noch haengt.
static String busTitle(const char* bus) {
    if (!bus || !bus[0])       return "direkt verdrahtet / dediziert";
    if (!strcmp(bus, "I2C"))   return "I²C-Bus (geteilt)";
    if (!strcmp(bus, "I2S"))   return "I²S (Audiodaten)";
    if (!strcmp(bus, "SPI"))   return "SPI-Bus (geteilt, eigene CS)";
    if (!strcmp(bus, "SDIO"))  return "SDIO";
    if (!strcmp(bus, "RMII"))  return "RMII (Ethernet)";
    return String(bus);
}
// GPIO-Nummern aller Teilnehmer eines Busses, ohne Dopplungen und in der Reihenfolge des Auftretens.
static String busGpios(const PlatformProfile& p, const char* bus) {
    String u, out;
    for (int i = 0; i < p.nAux; i++) {
        const PlatformAux& a = p.aux[i];
        if (strcmp(a.bus ? a.bus : "", bus ? bus : "")) continue;
        String csv = a.gpios ? a.gpios : "";
        int s = 0;
        while (s < (int)csv.length()) {
            int c = csv.indexOf(',', s);
            String t = (c < 0) ? csv.substring(s) : csv.substring(s, c);
            t.trim();
            if (t.length() && u.indexOf("," + t + ",") < 0) { u += "," + t + ","; out += (out.length() ? ", " : "") + t; }
            if (c < 0) break; s = c + 1;
        }
    }
    return out;
}
// Ein Eintrag EROEFFNET eine Gruppe, wenn vor ihm kein Eintrag mit demselben Bus steht.
// Bewusst zwei geschachtelte for-Schleifen ueber nAux statt einer Zeichenketten-Suche: die
// terminieren nachweislich. Die erste Fassung zerlegte eine Trennzeichenliste; bei einem LEEREN
// Busnamen ("direkt verdrahtet") lieferte indexOf -1, der Laufindex wurde -1, und -1 < length
// startete die Schleife von vorn -- endlos, waehrend der SVG-String weiterwuchs. Der HTTP-Task
// blieb haengen, danach Heap-Erschoepfung und Reset.
static bool auxOpensGroup(const PlatformProfile& p, int i) {
    const char* bus = p.aux[i].bus ? p.aux[i].bus : "";
    for (int k = 0; k < i; k++) {
        const char* b2 = p.aux[k].bus ? p.aux[k].bus : "";
        if (!strcmp(b2, bus)) return false;
    }
    return true;
}
static String buildAuxSvg(const PlatformProfile& p) {
    const int w = 800, boxH = 60, top = 46;
    int groups = 0;
    for (int i = 0; i < p.nAux; i++) if (auxOpensGroup(p, i)) groups++;
    int h = top + (p.nAux ? (groups * 26 + p.nAux * (boxH + 8) + 10) : 60) + 34;
    String s = String("<svg xmlns='http://www.w3.org/2000/svg' width='") + w + "' height='" + h + "' viewBox='0 0 " + w + " " + h + "'"
             + (p.nAux ? "" : " data-empty='1'") + " font-family='Arial,Helvetica,sans-serif' font-size='12'>" + kSvgStyle;
    s += String("<text x='10' y='24' font-size='13' font-weight='bold' fill='#222'>Onboard-Bausteine: ") + esc(p.name) + "</text>";
    if (!p.nAux) {
        s += "<text x='10' y='60' fill='#555'>Fuer dieses Profil ist keine interne Verdrahtung hinterlegt.</text>";
        s += "<text x='10' y='80' fill='#777' font-size='10'>Lieber leer als geraten -- die Angaben kommen nur aus der Boarddokumentation.</text>";
    }
    int y = top;
    // Pass 0: Bausteine an einem Bus, Pass 1: direkt verdrahtete. Beide Schleifen sind durch nAux begrenzt.
    for (int pass = 0; pass < 2; pass++)
        for (int g = 0; g < p.nAux; g++) {
            const char* bus = p.aux[g].bus ? p.aux[g].bus : "";
            if ((pass == 0) == (bus[0] == 0)) continue;
            if (!auxOpensGroup(p, g)) continue;
            String gp = busGpios(p, bus);
            s += String("<text x='10' y='") + (y + 12) + "' font-size='12' font-weight='bold' fill='#444'>" + esc(busTitle(bus))
                 + (gp.length() ? (String("<tspan fill='#8e44ad' font-weight='normal'>  GPIO ") + esc(gp) + "</tspan>") : "") + "</text>";
            y += 26;
            for (int i = g; i < p.nAux; i++) {
                const PlatformAux& a = p.aux[i];
                if (strcmp(a.bus ? a.bus : "", bus)) continue;
                s += String("<g class='aux' data-aux='") + i + "' data-gpios='" + (a.gpios ? a.gpios : "") + "'>";
                s += String("<rect x='26' y='") + y + "' width='" + (w - 36) + "' height='" + boxH + "' rx='6' fill='#f5f7f9' stroke='#d7dbe0'/>";
                s += String("<text x='38' y='") + (y + 20) + "' font-size='13' font-weight='bold' fill='#222'>" + esc(a.name)
                     + "<tspan fill='#666' font-size='11' font-weight='normal' dx='10'>" + esc(a.kind) + "</tspan></text>";
                String pins = a.pins ? String(a.pins) : String();
                if (a.addr && a.addr[0]) pins += String(pins.length() ? "  --  " : "") + "Adresse " + a.addr;
                if (pins.length()) s += String("<text x='38' y='") + (y + 37) + "' font-size='11' fill='#8e44ad'>" + esc(pins) + "</text>";
                if (a.note && a.note[0]) s += String("<text x='38' y='") + (y + 52) + "' font-size='10' fill='#777'>" + esc(a.note) + "</text>";
                s += "</g>";
                y += boxH + 8;
            }
        }
    s += String("<text x='10' y='") + (h - 12) + "' fill='#777' font-size='10'>Diese Pins sind vom Board schon vergeben. An einem geteilten Bus geht eigene Hardware zusaetzlich (Adressen pruefen) -- bei fester Verdrahtung nicht.</text>";
    s += "</svg>";
    return s;
}
// Kleiner JSON-Escaper: die Texte kommen zwar alle aus dieser Datei, aber ein Boardname mit
// Anfuehrungszeichen wuerde sonst die Antwort zerlegen.
static String jsonEsc(const char* s) {
    String o;
    for (const char* p = s; p && *p; p++) {
        char c = *p;
        if (c == 34 || c == 92) { o += (char)92; o += c; }      // Anfuehrungszeichen und Backslash maskieren
        else if ((uint8_t)c < 0x20) o += ' ';
        else o += c;
    }
    return o;
}
String platformJson() {
    const PlatformProfile& p = platformCurrent();
    const PlatformMcu* m = platformMcuFor(PLATFORM_CHIP);
    String j = String("{\"id\":\"") + g_id + "\",\"name\":\"" + p.name + "\",\"chip\":\"" + PLATFORM_CHIP
             + "\",\"wifi\":" + (wifiPresent() ? "true" : "false") + ",\"custom\":" + (platformIsCustom() ? "true" : "false")
             + ",\"pinout\":" + (platformHasPinout(p) ? "true" : "false");
    if (m) j += String(",\"usb\":\"") + jsonEsc(m->usb) + "\",\"radio\":\"" + jsonEsc(m->radio) + "\",\"io\":\"" + jsonEsc(m->io) + "\"";
    // Nur die Profile, die zu diesem Build passen. Der Katalog hat ueber 110 Eintraege -- die alle in
    // jede Statusantwort zu schreiben waere reine Verschwendung (Heap, LTE).
    j += ",\"profiles\":[";
    bool first = true;
    for (int i = 0; i < platformCount(); i++) {
        const PlatformProfile& q = platformAt(i);
        if (!platformFitsChip(q)) continue;
        if (!first) j += ","; first = false;
        j += String("{\"id\":\"") + q.id + "\",\"name\":\"" + jsonEsc(q.name) + "\",\"pinout\":" + (platformHasPinout(q) ? "true" : "false") + "}";
    }
    j += "]}";
    return j;
}
String platformText() {
    const PlatformProfile& p = platformCurrent();
    const PlatformMcu* m = platformMcuFor(PLATFORM_CHIP);
    String t = String("platform: ") + g_id + " (" + p.name + "), Chip " + PLATFORM_CHIP
             + ", WLAN " + (wifiPresent() ? "ja" : "nein") + (platformHasPinout(p) ? "" : ", KEIN Pinout hinterlegt") + "\r\n  " + p.notes + "\r\n";
    if (m) t += String("  USB:  ") + m->usb + "\r\n  Funk: " + m->radio + "\r\n  I/O:  " + m->io + "\r\n";
    // Passende Profile nennen, aber die Katalogeintraege nur zaehlen (ueber 110 Namen sprengen die Zeile).
    int fit = 0, withPin = 0;
    t += "  mit Pinout:";
    for (int i = 0; i < platformCount(); i++) {
        const PlatformProfile& q = platformAt(i);
        if (!platformFitsChip(q)) continue;
        fit++;
        if (platformHasPinout(q)) { withPin++; t += String(" ") + q.id; }
    }
    if (!withPin) t += " (keine)";
    t += String("\r\n  Katalog fuer diesen Chip: ") + (fit - withPin) + " weitere Profile ohne Pinout (Auswahl in der Web-UI)\r\n";
    return t;
}

// ---- Eigenes Pinout-SVG (custom) auf LittleFS ------------------------------------------------------
// Lazy: nur fuer den Zugriff einhaengen und wieder aushaengen -> kein dauerhafter RAM-Verbrauch. Erste Nutzung
// formatiert die (sonst ungenutzte) Datenpartition "spiffs" einmalig. Ob eine Datei existiert, wird gecacht.
// Drei Ansichten = drei Speicherplaetze: jede laesst sich einzeln durch ein eigenes SVG ersetzen.
// Lazy: nur fuer den Zugriff einhaengen und wieder aushaengen -> kein dauerhafter RAM-Verbrauch.
// Erste Nutzung formatiert die (sonst ungenutzte) Datenpartition "spiffs" einmalig.
static const char* svgPath(const String& view) {
    if (view == "chip") return "/platform/pinout-chip.svg";
    if (view == "aux")  return "/platform/pinout-aux.svg";
    return "/platform/pinout.svg";                     // Board-Ansicht behaelt den alten Pfad
}
static int svgSlot(const String& view) { return view == "chip" ? 1 : (view == "aux" ? 2 : 0); }
static int g_svgState[3] = { -1, -1, -1 };             // -1 unbekannt, 0 keine Datei, 1 vorhanden
static bool fsMount()   { return LittleFS.begin(true, "/lfs", 2, "spiffs"); }
static void fsUnmount() { LittleFS.end(); }

bool platformSvgCustomExists(const String& view) {
    int k = svgSlot(view);
    if (g_svgState[k] < 0) { g_svgState[k] = 0; if (fsMount()) { g_svgState[k] = LittleFS.exists(svgPath(view)) ? 1 : 0; fsUnmount(); } }
    return g_svgState[k] == 1;
}
bool platformSvgCustomAny() {
    return platformSvgCustomExists("") || platformSvgCustomExists("chip") || platformSvgCustomExists("aux");
}
String platformSvgCustomLoad(const String& view) {
    String s;
    if (!platformSvgCustomExists(view) || !fsMount()) return s;
    File f = LittleFS.open(svgPath(view), "r");
    if (f) {
        s.reserve(f.size() + 1);                       // > 4 KB -> landet per SPIRAM-malloc im PSRAM
        char buf[512];
        while (f.available()) { int n = f.read((uint8_t*)buf, sizeof(buf)); if (n <= 0) break; s.concat(buf, n); }
        f.close();
    }
    fsUnmount();
    return s;
}
String platformSvgStore(const String& xml, const String& view) {
    if (xml.length() > PLATFORM_SVG_MAX) return String("SVG zu gross (max. ") + (PLATFORM_SVG_MAX / 1024) + " KB)";
    if (xml.length() && xml.indexOf("<svg") < 0) return "kein SVG-Dokument (<svg ...> fehlt)";
    if (!fsMount()) return "Datenpartition nicht einhaengbar";
    int k = svgSlot(view);
    String err;
    if (!xml.length()) { LittleFS.remove(svgPath(view)); g_svgState[k] = 0; }
    else {
        LittleFS.mkdir("/platform");
        File f = LittleFS.open(svgPath(view), "w");
        if (!f) err = "Datei nicht schreibbar";
        else { size_t w = f.print(xml); f.close(); if (w != xml.length()) err = "Schreibfehler (Partition voll?)"; else g_svgState[k] = 1; }
    }
    fsUnmount();
    return err;
}

// Verteiler: drei Ansichten aus DENSELBEN Tabellen. Es wird immer nur EINE erzeugt und gesendet --
// der Browser haelt entsprechend auch nur ein Bild (Heap/Sockets).
static String buildSvg(const PlatformProfile& p, const UsbPortEntry* ports, int nPorts, const String& view) {
    if (view == "chip") return buildChipSvg(p);
    if (view == "aux")  return buildAuxSvg(p);
    return buildBoardSvg(p, ports, nPorts);
}
String platformSvg(const String& view) {
    // Jede der drei Ansichten kann durch ein eigenes SVG ersetzt sein (Profil Custom).
    if (platformIsCustom() && platformSvgCustomExists(view)) return platformSvgCustomLoad(view);
    UsbPortEntry ports[USB_PORTS_MAX]; int n = usbPortsCount();
    for (int i = 0; i < n; i++) ports[i] = usbPort(i);
    return buildSvg(platformCurrent(), ports, n, view);
}
String platformSvgFor(const String& profileId, const String& view) {
    if (profileId == g_id || !find(profileId)) return platformSvg(view);
    if (profileId == "custom" && platformSvgCustomExists(view)) return platformSvgCustomLoad(view);
    UsbPortEntry ports[USB_PORTS_MAX]; int n = 0;
    usbPortsProfileDefaults(profileId, ports, n);   // Vorschau mit den Vorgaben des Profils, nichts gespeichert
    return buildSvg(*find(profileId), ports, n, view);
}

// ---- Plattform-Konfiguration: Struct, JSON-Export, JSON-Import -------------------------------------
PlatformConfig platformConfigGet() {
    PlatformConfig c;
    c.profile = g_id;
    c.portCount = usbPortsCount();
    for (int i = 0; i < c.portCount; i++) c.ports[i] = usbPort(i);
    c.modemPort = periphModemPort;
    c.hasSvg = platformIsCustom() && platformSvgCustomAny();
    return c;
}
static String jq(const String& s) {   // JSON-String-Escaping (klein, ohne web_ui-Abhaengigkeit)
    String o; o.reserve(s.length() + 8);
    for (size_t i = 0; i < s.length(); i++) {
        char c = s[i];
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (c == '\n') o += "\\n"; else if (c == '\r') o += "\\r"; else if (c == '\t') o += "\\t";
        else if ((uint8_t)c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", (unsigned)(uint8_t)c); o += b; }
        else o += c;
    }
    return o;
}
String platformConfigJson(bool withSvg) {
    PlatformConfig c = platformConfigGet();
    String j = String("{\"weirdos\":\"platform\",\"version\":1,\"chip\":\"") + PLATFORM_CHIP + "\",\"profile\":\"" + jq(c.profile)
             + "\",\"modemPort\":\"" + jq(c.modemPort) + "\",\"ports\":[";
    for (int i = 0; i < c.portCount; i++) {
        if (i) j += ",";
        j += String("{\"id\":\"") + c.ports[i].id + "\",\"label\":\"" + jq(c.ports[i].label) + "\",\"dm\":" + (int)c.ports[i].dm
           + ",\"dp\":" + (int)c.ports[i].dp + ",\"enabled\":" + (c.ports[i].enabled ? "true" : "false") + "}";
    }
    j += "]";
    // Export/Import fuehren weiter NUR die Platinen-Ansicht mit (das ist das Bild des Boards);
    // Chip- und Zusatzchip-Ansicht sind Sichten auf dieselben Daten und werden erzeugt.
    if (withSvg && platformSvgCustomExists("")) { j += ",\"svg\":\""; j += jq(platformSvgCustomLoad("")); j += "\""; }
    j += "}";
    return j;
}

// Mini-JSON-Leser (flach; genau fuer dieses Format): Schluessel suchen, Wert ab dem Doppelpunkt lesen.
static int jsonValuePos(const String& j, const char* key, int from = 0) {
    String k = String("\"") + key + "\"";
    int i = j.indexOf(k, from); if (i < 0) return -1;
    i = j.indexOf(':', i + k.length()); if (i < 0) return -1;
    i++;
    while (i < (int)j.length() && (j[i] == ' ' || j[i] == '\t' || j[i] == '\r' || j[i] == '\n')) i++;
    return i;
}
static bool jsonStr(const String& j, const char* key, String& out, int from = 0) {
    int i = jsonValuePos(j, key, from);
    if (i < 0 || i >= (int)j.length() || j[i] != '"') return false;
    out = ""; out.reserve(64); i++;
    while (i < (int)j.length() && j[i] != '"') {
        char c = j[i++];
        if (c == '\\' && i < (int)j.length()) {
            char e = j[i++];
            if (e == 'n') out += '\n'; else if (e == 'r') out += '\r'; else if (e == 't') out += '\t';
            else if (e == 'u') { i += 4; out += '?'; } else out += e;
        } else out += c;
    }
    return true;
}
static long jsonNum(const String& j, const char* key, long def, int from = 0) {
    int i = jsonValuePos(j, key, from); if (i < 0) return def;
    return j.substring(i, i + 12).toInt();
}
static bool jsonBool(const String& j, const char* key, bool def, int from = 0) {
    int i = jsonValuePos(j, key, from); if (i < 0) return def;
    if (j.startsWith("true", i)) return true; if (j.startsWith("false", i)) return false; return def;
}
String platformConfigImport(const String& json) {
    String magic; if (!jsonStr(json, "weirdos", magic) || magic != "platform") return "keine WeirdOS-Plattform-Datei (\"weirdos\":\"platform\" fehlt)";
    String chip; if (jsonStr(json, "chip", chip) && chip.length() && chip != PLATFORM_CHIP)
        return String("Datei stammt von Chip ") + chip + ", dieser Build ist " + PLATFORM_CHIP;
    String profile; if (!jsonStr(json, "profile", profile)) return "Feld 'profile' fehlt";
    String err = platformSet(profile);
    if (err.length()) return err;
    // Ports: Objekte innerhalb von "ports":[ ... ]
    int a = jsonValuePos(json, "ports");
    if (a >= 0 && a < (int)json.length() && json[a] == '[') {
        int end = json.indexOf(']', a);
        UsbPortEntry e[USB_PORTS_MAX]; int n = 0;
        int pos = a;
        while (n < USB_PORTS_MAX) {
            int o = json.indexOf('{', pos); if (o < 0 || (end >= 0 && o > end)) break;
            int c = json.indexOf('}', o);   if (c < 0) break;
            String obj = json.substring(o, c + 1);
            e[n].id = String("USB") + n;
            if (!jsonStr(obj, "label", e[n].label)) e[n].label = e[n].id;
            e[n].dm = (int8_t)jsonNum(obj, "dm", -1); e[n].dp = (int8_t)jsonNum(obj, "dp", -1);
            e[n].enabled = jsonBool(obj, "enabled", true);
            n++; pos = c + 1;
        }
        if (n) { err = usbPortsSave(n, e); if (err.length()) return "USB-Anschluesse: " + err; }
    }
    String mp; if (jsonStr(json, "modemPort", mp) && mp.length()) periphSaveModemPort(mp);
    String svg;
    if (jsonStr(json, "svg", svg)) { err = platformSvgStore(svg); if (err.length()) return "Pinout-SVG: " + err; }
    return "";
}
