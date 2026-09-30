// ============================================================================
// usb_device_service.h -- WeirdOS als USB-Geraet am PC (PC = Host, ESP32 = Device).
//
// Modell (System > Geraete > "Bereitstellen an USB"):
//   * EIN USB-Port des Boards wird als Device-Port zum PC gewaehlt (persistente Wahl, wirkt beim Boot).
//   * Je Geraet der Registry ein Export: heute camera0 -> UVC (Webcam) und das virtuelle Geraet
//     testpattern0 (statisches Testbild) -> UVC. microphone0 -> UAC und usb-network -> NCM sind als
//     Klassen vorgesehen, aber NICHT implementiert (UI ausgegraut). Genau ein UVC-Export gleichzeitig.
//   * Deskriptoren entstehen nur beim Boot -> jede Aenderung = Neustart (gelbe Box); ein verbundener
//     Windows-Host wird nie im Betrieb umgeschaltet.
//
// Ports (aus dem offiziellen Schaltplan / IDF-HAL, nicht aus dem Datenblatt geraten):
//   ESP32-P4-Pico:
//     "fs26" (Vorgabe) OTG 1.1 Full-Speed ueber FSLS-PHY 1 = GPIO26 (D-) / GPIO27 (D+), Stiftleiste.
//                      Hardware-Default des P4 fuer OTG-FS; USB-Serial/JTAG bleibt auf PHY 0 (GPIO24/25).
//     "fs24"           OTG 1.1 Full-Speed ueber FSLS-PHY 0 = GPIO24 (D-) / GPIO25 (D+) (PHY-Tausch per
//                      usb_wrap_ll_phy_select; USB-Serial/JTAG wandert dann auf GPIO26/27).
//     "hs"             OTG 2.0 High-Speed ueber UTMI = MX1.25-4-Pin. NUR moeglich, wenn der Modem-Host dort
//                      nicht laeuft (ein Controller): dann startet der EC200A-Host nicht.
//     Die USB-C-Buchse ist ein CH343-UART (Konsole/Flash) und hat KEINE Verbindung zum USB des P4.
//   ESP32-S3 (XIAO):
//     "native"         die einzige USB-C-Buchse = interner FS-PHY (GPIO19/20), geteilt mit USB-Serial/JTAG
//                      UND dem Modem-Host. Beim Boot entscheidet die bestehende PC-Erkennung: PC dran ->
//                      kein Modem-Host -> Device-Modus moeglich; kein PC -> Modem-Host wie bisher.
//
// Power-Semantik: WeirdOS ist extern versorgt -> Konfigurationsdeskriptor SELF_POWERED, 100 mA. Eine
// VBUS-Erkennung (Pull-up nur bei gueltigem VBUS) gibt es auf keinem der Ports (kein VBUS-Sense-GPIO
// verdrahtet) -> der Pull-up liegt ab Boot an; Hotplug wird ueber Bus-Reset/SOF erkannt. Das ist ein
// dokumentierter Abstand zur USB-Spezifikation fuer Self-Powered-Geraete (siehe USB-DEVICE.md).
//
// Stack: usbd + dcd_dwc2 aus den gelinkten Arduino-Libs; die VIDEOKLASSE kommt aus uvc_video_device.c
// (eigene Uebersetzungseinheit: Bulk-Endpunkt, 4-KB-Payloads -- die Bibliotheksklasse sendet auf dem S3
// 64-Byte-ISO-Payloads = ~62 KB/s und zerrissene Bilder). Eigener PHY-/rhport-Init, NIE USB.begin() des
// Cores (der nimmt auf dem P4 rhport 1 = HS = Modem-Controller). Die Deskriptor-Callbacks des Cores sind
// __weak und werden hier ueberschrieben; tud_mount_cb & Co. definiert der Core stark -> wir nutzen sie
// nicht (Zustand per tud_mounted()).
// Transport: MJPEG ueber BULK (UVC 1.5, ein Alternate Setting). Ein SVGA-JPEG (40-70 KB) braucht am
// Full-Speed-Port ~50-100 ms -> 10-20 fps; VGA entsprechend mehr. Isochron waere am S3 auf 1 Paket je
// Millisekunde begrenzt.
// ============================================================================
#pragma once
#include <Arduino.h>

struct UsbDeviceConfig {
    String  port;        // Port-ID aus dem Board-Mapping (usb_ports.*): "USB0".."USB2"
    String  cam;         // UVC-Export: "" (aus) | "camera0" | "testpattern0"
    uint8_t fps = 15;    // angebotene Bildrate 1..30 (Angebot; real zaehlt die USB-Bandbreite: FS-Bulk ~1 MB/s)
};

class UsbDeviceService {
public:
    void   loadConfig();                                    // NVS "usbdev" (frueh im Boot, NACH usbPortsLoad, VOR der USB-Host-Entscheidung)
    String saveConfig(const UsbDeviceConfig& c);            // persistieren; "" = ok. Wirkt beim naechsten Boot.
    const UsbDeviceConfig& config() const { return cfg_; }
    bool   enabled() const { return cfg_.cam.length() > 0; } // irgendein Export konfiguriert?
    bool   conflictsWithModemPort() const;                  // Export aktiv UND derselbe Port wie cellular0 -> Modem-Host bleibt aus
    bool   begin();                                         // beim Boot: PHY + TinyUSB + Task (nur wenn enabled)
    bool   active() const { return started_; }
    String failReason() const { return fail_; }             // warum nicht gestartet ("" = laeuft / nicht gewuenscht)
    static bool   builtIn();                                // Device-Stack im Build enthalten (WEIRDOS_USB_DEVICE=1)? Sonst nur Konfiguration.
    static String defaultPort();                            // erster nutzbarer Port, der NICHT der Modem-Port ist (sonst der erste)
    static bool   portValid(const String& p);               // im Mapping vorhanden + aktiv + gueltige Pins
    static String portLabel(const String& p);               // Klartext aus dem Mapping (usbPortDescribe)
    String statusText();                                    // Konsole 'usbdev'
    String statusJson();                                    // /usbdev.json
    void   taskLoop();                                      // intern (Worker)
private:
    UsbDeviceConfig cfg_;
    bool   started_ = false;
    String fail_;
};
extern UsbDeviceService usbDeviceService;
