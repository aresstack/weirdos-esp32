// ============================================================================
// usb_device_service.cpp -- USB-Device (UVC) -- Port-Auswahl je Board, Export je Geraet. Siehe Header.
// ============================================================================
#include "usb_device_service.h"
#include "soc/soc_caps.h"
// FEATURE-FLAG (Build-Zeit, Vorgabe AUS): Die vorkompilierte TinyUSB-Geraetebibliothek des Arduino-Cores
// (libarduino_tinyusb.a) haelt ~48 KB STATISCHE Puffer im internen RAM (Audio 13 KB, NCM 19 KB, MSC 8 KB,
// DFU 4 KB, CDC/HID/MIDI ...), sobald usbd.c gelinkt wird -- unabhaengig davon, ob das Feature zur Laufzeit
// eingeschaltet ist (Hardware-Befund 2026-09-09: statischer RAM 75 -> 125 KB, Boot-Heap 84k -> 30k, Modem-Host
// ohne DMA-RAM -> keine Enumeration). Ein Laufzeitschalter kann statische Puffer einer fertigen Bibliothek
// nicht freigeben. Deshalb entscheidet ein Build-Flag, ob der Device-Stack ueberhaupt eingebunden wird:
//   -DWEIRDOS_USB_DEVICE=1   (build_opt.h / platform.local.txt)  -> UVC verfuegbar, ~48 KB weniger interner Heap
// Ohne das Flag bleibt der Code ein Stub (Status "im Build deaktiviert"); Konfiguration/UI bleiben erhalten.
// Weg zu echtem Laufzeit-Einschalten: eigene, minimale TinyUSB-Uebersetzung (usbd + dcd_dwc2 + video, ~2 KB
// statisch) statt der Core-Bibliothek -- siehe USB-DEVICE.md.
// Seit dem Schalterkasten ist der Key WEIRDOS_FEATURE_USB_DEVICE (weirdos_features.h); der alte
// Name WEIRDOS_USB_DEVICE bleibt dort als Alias definiert, damit dieser Code unveraendert gilt.
// Videoklasse: NICHT die der Bibliothek (64-Byte-ISO-Payloads auf dem S3 = ~62 KB/s und Bildmuell),
// sondern uvc_video_device.c (eigene Uebersetzungseinheit, Bulk, 4-KB-Payloads) -- siehe dort.
#include "weirdos_features.h"
// UVC ist heute die einzige Geraeteklasse: ohne den Baustein UVC gibt es nichts zu exportieren, also
// auch keinen TinyUSB-Start (USB_DEVICE = Stack, UVC = Kamera-Klasse; USB_NCM folgt als eigene Klasse).
// Der TinyUSB-Device-Stack startet fuer JEDE Geraeteklasse, nicht nur die Kamera:
// UVC (Webcam) ODER USB_NCM (Netzwerkadapter, z.B. Profil usb-tether ohne Kamera).
// Frueher nur UVC -> usb-tether (USB_DEVICE+USB_NCM, kein UVC) startete den Stack
// nie und lieferte kein Netz (statischer Befund 2026-09-30).
#if SOC_USB_OTG_SUPPORTED && defined(CONFIG_TINYUSB_ENABLED) && WEIRDOS_USB_DEVICE && (WEIRDOS_FEATURE_UVC || WEIRDOS_FEATURE_USB_NCM)
#define WEIRDOS_USBDEV_SUPPORTED 1
#else
#define WEIRDOS_USBDEV_SUPPORTED 0
#endif
#ifndef WEIRDOS_UVC_TESTPATTERN
#define WEIRDOS_UVC_TESTPATTERN 0   // 1 = Vorgabe des Exports ist das Testbild statt camera0 (Diagnose-Build)
#endif
bool UsbDeviceService::builtIn() { return WEIRDOS_USBDEV_SUPPORTED != 0; }

#include <Preferences.h>
#include "web_ui.h"                 // logEvent, cameraReady
#include "camera_stream_service.h"  // cameraStream (Consumer-API, MJPEG-Passthrough)
#include "camera_manager.h"         // cameraManager.currentMode (Deskriptor-Groesse)
#include "usb_uvc_testimage.h"
#include "usb_ports.h"              // Board-Mapping: Port-ID -> Controller/PHY/rhport
#include "peripheral_registry.h"    // periphModemPort (Konflikt: derselbe Port fuer Modem-Host und PC-Geraet)
#include <cstring>

// USB-Mikrofon (UAC2) laeuft als zweite Funktion im selben Composite-Geraet.
// Nur wenn der AUDIO-Baustein im Build ist; sonst kein Byte davon. Die
// TinyUSB-Audio-Klasse ist im Core aktiv (CONFIG_TINYUSB_AUDIO_ENABLED) und
// parst den Deskriptor dynamisch -- kein Verdraengen wie bei der Videoklasse.
#if WEIRDOS_USBDEV_SUPPORTED && WEIRDOS_FEATURE_AUDIO
#define WEIRDOS_UAC_SUPPORTED 1
#else
#define WEIRDOS_UAC_SUPPORTED 0
#endif

// USB-Netzwerkadapter (CDC-NCM) als weitere Funktion im selben Composite-Geraet.
// Nur mit dem Baustein USB_NCM; sonst kein Byte davon. net-Klasse aktiv im Core
// (CONFIG_TINYUSB_NCM_ENABLED), Netif/DHCP in usb_net_service.
#if WEIRDOS_USBDEV_SUPPORTED && WEIRDOS_FEATURE_USB_NCM
#define WEIRDOS_UNC_SUPPORTED 1
#else
#define WEIRDOS_UNC_SUPPORTED 0
#endif

#if WEIRDOS_USBDEV_SUPPORTED
#include "tusb.h"
#include "class/video/video_device.h"
#if WEIRDOS_UAC_SUPPORTED
#include "class/audio/audio_device.h"
#include "mic_capture.h"
#endif
#if WEIRDOS_UNC_SUPPORTED
#include "class/net/net_device.h"
#include "usb_net_service.h"
#endif
#include "esp_private/usb_phy.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <esp_heap_caps.h>
#include <esp_mac.h>
#include <esp_timer.h>
#endif

extern bool usbHostStarted;         // .ino: laeuft der Modem-USB-Host? (HS-Port belegt)

UsbDeviceService usbDeviceService;

// ---- Ports (aus dem Board-Mapping usb_ports.*) ------------------------------------------------------
String UsbDeviceService::defaultPort() {
    for (int i = 0; i < usbPortsCount(); i++) if (usbPortUsable(usbPort(i).id) && usbPort(i).id != periphModemPort) return usbPort(i).id;
    for (int i = 0; i < usbPortsCount(); i++) if (usbPortUsable(usbPort(i).id)) return usbPort(i).id;
    return "USB0";
}
bool   UsbDeviceService::portValid(const String& p) { return usbPortUsable(p); }
String UsbDeviceService::portLabel(const String& p) { return usbPortDescribe(p); }
bool   UsbDeviceService::conflictsWithModemPort() const { return enabled() && cfg_.port == periphModemPort; }

// ---- Konfiguration --------------------------------------------------------------------------------
void UsbDeviceService::loadConfig() {
    Preferences p; p.begin("usbdev", true);
    cfg_.port = p.getString("port", defaultPort());
    cfg_.cam  = p.getString("cam", "");
    cfg_.fps  = (uint8_t)p.getUChar("fps", 15);   // Angebot; Bulk schafft SVGA mit ~10-20 fps, VGA mehr
    // Migration der ersten Fassung (uvc/src): uvc=1 -> Export je nach Quelle
    if (!p.isKey("cam") && p.getBool("uvc", false)) cfg_.cam = (p.getString("src", "camera") == "test") ? "testpattern0" : "camera0";
#if WEIRDOS_USBDEV_SUPPORTED
    // Frisches Board, nie konfiguriert: wer den Baustein UVC einbaut, will die Kamera am PC sehen --
    // per Vorgabe AN. Ein Webcam-Profil ohne Weboberflaeche/Konsole haette sonst keinen Weg, den
    // Export je einzuschalten. Ein gespeichertes "aus" (cam="") bleibt ein "aus".
    // Diagnose ohne Weboberflaeche/Konsole: -DWEIRDOS_UVC_TESTPATTERN=1 zwingt die Vorgabe auf das
    // Testbild -> der USB-Pfad laesst sich getrennt von der Kamera pruefen (Bild am PC = USB in Ordnung).
    if (!p.isKey("cam") && !p.isKey("uvc")) cfg_.cam = (WEIRDOS_FEATURE_CAMERA && !WEIRDOS_UVC_TESTPATTERN) ? "camera0" : "testpattern0";
#endif
    p.end();
    if (!portValid(cfg_.port)) cfg_.port = defaultPort();
    if (cfg_.cam != "camera0" && cfg_.cam != "testpattern0") cfg_.cam = "";
    if (cfg_.fps < 1) cfg_.fps = 1;
    if (cfg_.fps > 30) cfg_.fps = 30;
}
String UsbDeviceService::saveConfig(const UsbDeviceConfig& c) {
    cfg_ = c;
    if (!portValid(cfg_.port)) cfg_.port = defaultPort();
    if (cfg_.cam != "camera0" && cfg_.cam != "testpattern0") cfg_.cam = "";
    if (cfg_.fps < 1) cfg_.fps = 1;
    if (cfg_.fps > 30) cfg_.fps = 30;
    Preferences p; p.begin("usbdev", false);
    p.putString("port", cfg_.port); p.putString("cam", cfg_.cam); p.putUChar("fps", cfg_.fps);
    p.end();
    return "";
}

#if WEIRDOS_USBDEV_SUPPORTED
// ---- Deskriptor-Tabelle (Composite-vorbereitet: Interfaces/EPs/Strings fortlaufend) ---------------
// Video belegt die Interfaces 0/1 NUR mit UVC. Ohne Kamera (NCM-only, usb-tether)
// beginnen Audio/CDC/NCM bei Interface 0. ITF_COUNT = Basis fuer den Rest.
enum { ITF_VC = 0, ITF_VS = 1 };
#if WEIRDOS_FEATURE_UVC
#define ITF_COUNT 2
#else
#define ITF_COUNT 0
#endif
enum { STR_LANG = 0, STR_MANUF = 1, STR_PRODUCT = 2, STR_SERIAL = 3, STR_UVC = 4, STR_UAC = 5,
       STR_CDC = 8 };   // 6/7 = NCM (STR_NCM/STR_NCM_MAC, nur mit USB_NCM)
#define UVC_EP_IN     0x81
#if WEIRDOS_UAC_SUPPORTED
// Audio-Funktion: eigene IAD ueber die Interfaces 2 (AudioControl) und 3
// (AudioStreaming); iso IN-Endpunkt 0x82. Feste 16 kHz mono 16-bit (Sprach-Mikro).
#define UAC_ITF_AC    ITF_COUNT          // 2
#define UAC_ITF_AS    (ITF_COUNT + 1)    // 3
#define UAC_ITF_COUNT (ITF_COUNT + 2)    // 4
#define UAC_EP_IN     0x82
#define UAC_CLK_ID    0x04
#define UAC_IT_ID     0x01               // Input Terminal (Mikrofon)
#define UAC_OT_ID     0x02               // Output Terminal (USB-Stream)
#define UAC_RATE      16000u
#define UAC_EP_MPS    64                 // 16 kHz mono 16-bit = 32 B/ms; 64 mit Reserve (async)
static bool s_audioOn = false;           // Mikro erkannt und Deskriptor traegt die Audio-Funktion
static volatile bool s_audioStreaming = false;
#endif
#if WEIRDOS_UNC_SUPPORTED
// NCM-Funktion: IAD ueber comm+data-Interface (nach Video, ggf. nach Audio).
// Notify-EP 0x83 (int IN), Daten-EP 0x84 (bulk IN) / 0x04 (bulk OUT).
#define NCM_ITF_COMM  (ITF_COUNT + (WEIRDOS_UAC_SUPPORTED ? 2 : 0))
#define NCM_EP_NOTIF  0x83
#define NCM_EP_IN     0x84
#define NCM_EP_OUT    0x04
#define STR_NCM       6
#define STR_NCM_MAC   7
static bool s_ncmOn = false;             // USB-Netz aktiv und Deskriptor traegt die NCM-Funktion
static char s_ncmMacStr[13] = "025745495245";  // iMACAddress: 12 Hex, Host-Seite
#endif
#define UVC_BULK_MPS_FS 64          // Bulk-Paket Full-Speed (USB 2.0, 5.8.3) -- S3, P4-FSLS
#define UVC_BULK_MPS_HS 512         // Bulk-Paket High-Speed -- P4-UTMI
#define UVC_CLOCK_HZ  48000000
#define UVC_VID       0x1209        // pid.codes (Open-Source-VID)
#define UVC_PID       0x0001        // pid.codes TEST-PID -- ausdruecklich fuer interne/Testgeraete freigegeben

static usb_phy_handle_t s_phy = nullptr;
static uint8_t   s_rhport = 0;
static bool      s_highSpeed = false;
static uint8_t*  s_cfgDesc = nullptr; static uint16_t s_cfgLen = 0;       // Full-Speed-Konfiguration (Bulk 64)
static uint8_t*  s_cfgDescHs = nullptr; static uint16_t s_cfgLenHs = 0;   // High-Speed-Konfiguration (Bulk 512), nur HS-Port
static uint32_t  s_payloadMax = 0;                                        // vom Host bestaetigte dwMaxPayloadTransferSize
static tusb_desc_device_t s_devDesc;
static tusb_desc_device_qualifier_t s_qualDesc;
static char      s_serial[20] = "0";
static uint16_t  s_strBuf[64];
static uint16_t  s_w = UVC_TEST_JPEG_W, s_h = UVC_TEST_JPEG_H;
static uint32_t  s_maxFrame = 0;

// Aufloesungsliste im Deskriptor: UVC-Frame-Index i+1 <-> s_modeW/H[i]. Der Host
// (Windows-Kamera-Einstellungen) waehlt darueber die Aufloesung; COMMIT schaltet
// den Sensor um (tud_video_commit_cb). Leer (0) = genau ein Frame (Testbild oder
// Kamera ohne Modusliste).
enum { UVC_MAX_MODES = 8 };
static uint16_t  s_modeW[UVC_MAX_MODES], s_modeH[UVC_MAX_MODES];
static int       s_modeCount = 0;
static uint32_t  s_modeSwitchUs = 0;   // Flush-Fenster: nach dem Umschalten liegen noch Alt-Frames in der Pipeline

static uint32_t frameBufMax(uint16_t w, uint16_t h) {
    uint32_t m = (uint32_t)w * h * 2;                    // MJPEG: grosszuegig, Windows reserviert diesen Puffer
    if (m > 1024UL * 1024UL) m = 1024UL * 1024UL;
    return m;
}

// Laufzeit
static volatile bool s_txBusy = false;
static volatile bool s_streaming = false, s_mounted = false, s_suspended = false;
static uint32_t  s_intervalMs = 100;
static uint32_t  s_lastFrameUs = 0;
static uint32_t  s_frames = 0, s_bytes = 0, s_lastLen = 0, s_maxLen = 0, s_skipsNoFrame = 0;
static uint8_t*  s_buf = nullptr; static size_t s_cap = 0; static uint32_t s_seq = 0; static size_t s_len = 0;
static bool      s_camConsumer = false;
static bool      s_srcTest = true;

// Eine Konfiguration je Bus-Geschwindigkeit: der Bulk-Endpunkt hat 64 B (FS) bzw. 512 B (HS) wMaxPacketSize.
// Transport = BULK, nicht isochron: (1) Full-Speed-ISO ist 1 Paket je 1-ms-Rahmen -- mit dem 64-B-Puffer der
// Core-Bibliothek ~62 KB/s, ein SVGA-JPEG braucht ~1 s; (2) der ISO-IN-Pfad der DWC2 (Rahmen-Paritaet) verliert
// Pakete, wenn der Task spaet nachlegt -> zerrissene JPEGs (Hardware-Befund 2026-09-30). Bulk laeuft so schnell,
// wie der Host abholt (FS ~1 MB/s), ohne Paritaet, und die eigene Videoklasse (uvc_video_device.c) schickt 4-KB-
// Payloads am Stueck aus der ISR. Bulk-UVC hat GENAU EIN Alternate Setting (0) mit dem Endpunkt darin; der
// Host startet den Stream mit COMMIT und liest -- kein SET_INTERFACE(1) wie bei ISO.
static bool buildOneConfig(uint16_t w, uint16_t h, uint8_t fps, uint16_t bulkMps, uint8_t** outDesc, uint16_t* outLen) {
#if WEIRDOS_FEATURE_UVC
    const uint32_t interval = 10000000UL / fps;  // 100-ns-Einheiten
    // Ein Frame-Deskriptor je waehlbarer Aufloesung (s_mode*); ohne Liste genau
    // einer (w,h) -- Testbild oder Kamera ohne Modusliste. Der Host waehlt per
    // bFrameIndex, COMMIT schaltet den Sensor.
    const int nFrames = (s_modeCount > 0) ? s_modeCount : 1;
    const uint16_t csLen = TUD_VIDEO_DESC_CS_VS_FMT_MJPEG_LEN
                         + (uint16_t)nFrames * TUD_VIDEO_DESC_CS_VS_FRM_MJPEG_CONT_LEN
                         + TUD_VIDEO_DESC_CS_VS_COLOR_MATCHING_LEN;
    const uint8_t partA[] = {
        TUD_VIDEO_DESC_IAD(ITF_VC, ITF_COUNT, STR_UVC),
        TUD_VIDEO_DESC_STD_VC(ITF_VC, 0, STR_UVC),
        TUD_VIDEO_DESC_CS_VC(0x0150, TUD_VIDEO_DESC_CAMERA_TERM_LEN + TUD_VIDEO_DESC_OUTPUT_TERM_LEN, UVC_CLOCK_HZ, ITF_VS),
        TUD_VIDEO_DESC_CAMERA_TERM(1, 0, 0, 0, 0, 0, 0),
        TUD_VIDEO_DESC_OUTPUT_TERM(2, VIDEO_TT_STREAMING, 0, 1, 0),
        TUD_VIDEO_DESC_STD_VS(ITF_VS, 0, 1, STR_UVC),   // alt 0 MIT dem Bulk-Endpunkt (kein alt 1)
        TUD_VIDEO_DESC_CS_VS_INPUT(1, csLen, UVC_EP_IN, 0, 2, 0, 0, 0, 0),
        TUD_VIDEO_DESC_CS_VS_FMT_MJPEG(1, (uint8_t)nFrames, 0, 1, 0, 0, 0, 0),
    };
    const uint8_t partC[] = {
        TUD_VIDEO_DESC_CS_VS_COLOR_MATCHING(VIDEO_COLOR_PRIMARIES_BT709, VIDEO_COLOR_XFER_CH_BT709, VIDEO_COLOR_COEF_SMPTE170M),
        TUD_VIDEO_DESC_EP_BULK(UVC_EP_IN, bulkMps, 0)
    };
    const uint16_t videoLen = (uint16_t)sizeof(partA)
                            + (uint16_t)nFrames * TUD_VIDEO_DESC_CS_VS_FRM_MJPEG_CONT_LEN
                            + (uint16_t)sizeof(partC);
#else
    (void)w; (void)h; (void)fps;
    const uint16_t videoLen = 0;
#endif

#if WEIRDOS_UAC_SUPPORTED
    // UAC2-Mikrofon (nur wenn ein Mikro erkannt wurde). Von Hand nach Spec, weil
    // der Core die TUD_AUDIO_DESC_*-Makros nicht mitliefert. wTotalLength der
    // CS-AC = 9(Header)+8(Clock)+17(Input)+12(Output) = 46.
    const uint8_t audio[] = {
        // Interface Association: Audio-Funktion, 2 Interfaces (AC+AS)
        8, 0x0B, UAC_ITF_AC, 2, 0x01, 0x00, 0x20, STR_UAC,
        // Std AC-Interface (alt 0, 0 EP)
        9, 0x04, UAC_ITF_AC, 0, 0, 0x01, 0x01, 0x20, 0,
        // CS AC-Header (UAC2): bcdADC=0x0200, Kategorie I/O-Box=0x08, wTotalLength=46, bmControls=0
        9, 0x24, 0x01, 0x00, 0x02, 0x08, 46, 0x00, 0x00,
        // Clock Source: ID=4, intern/fest, Freq lesbar (0x01), assoc=Input-Terminal
        8, 0x24, 0x0A, UAC_CLK_ID, 0x01, 0x01, UAC_IT_ID, 0,
        // Input Terminal: ID=1, Typ Mikrofon 0x0201, clk=4, 1 Kanal
        17, 0x24, 0x02, UAC_IT_ID, 0x01, 0x02, 0, UAC_CLK_ID, 1, 0,0,0,0, 0, 0x00,0x00, 0,
        // Output Terminal: ID=2, USB-Stream 0x0101, Quelle=Input, clk=4
        12, 0x24, 0x03, UAC_OT_ID, 0x01, 0x01, 0, UAC_IT_ID, UAC_CLK_ID, 0x00,0x00, 0,
        // Std AS-Interface alt 0 (0 EP)
        9, 0x04, UAC_ITF_AS, 0, 0, 0x01, 0x02, 0x20, 0,
        // Std AS-Interface alt 1 (1 EP)
        9, 0x04, UAC_ITF_AS, 1, 1, 0x01, 0x02, 0x20, 0,
        // CS AS General: Link=Output-Terminal, Format Typ I, bmFormats=PCM(0x01), 1 Kanal
        16, 0x24, 0x01, UAC_OT_ID, 0x00, 0x01, 0x01,0x00,0x00,0x00, 1, 0,0,0,0, 0,
        // Type I Format: SubslotSize=2, BitResolution=16
        6, 0x24, 0x02, 0x01, 2, 16,
        // Std iso EP IN: 0x82, iso+async (0x05), Paketgroesse, bInterval=1
        7, 0x05, UAC_EP_IN, 0x05, (uint8_t)(UAC_EP_MPS & 0xFF), (uint8_t)(UAC_EP_MPS >> 8), 1,
        // CS AS iso EP General
        8, 0x25, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const bool withAudio = s_audioOn;
    const uint16_t audioLen = withAudio ? (uint16_t)sizeof(audio) : 0;
    const uint8_t  audioItf = withAudio ? 2 : 0;
#else
    const uint16_t audioLen = 0;
    const uint8_t  audioItf = 0;
#endif

    // CDC-Konsole = LEBENSADER, immer dabei: die USBCDC-Callbacks des Cores
    // (USBCDC.cpp, via CDCOnBoot=cdc fest gelinkt) tragen den Bootloader-Einstieg
    // -- 1200-Baud-Touch und die esptool-DTR/RTS-Sequenz -> usb_persist_restart
    // (RESTART_BOOTLOADER). Ohne diese Schnittstelle ist ein OTG-Build nur noch
    // mit BOOT+RESET an den Tasten flashbar. Bonus: Serial-Log am PC.
    //
    // IN-Endpunkte sind knapp: der S3 hat OTG_NUM_IN_EPS=5 -> nutzbar sind EP1..EP4
    // (EP0 = Control). Vergabe LAUFZEITABHAENGIG in fester
    // Prioritaet: Video 0x81, Audio 0x82 (wenn Mikro), dann CDC (Notify+Daten),
    // dann NCM (Notify+Daten) NUR wenn noch zwei frei sind -- sonst faellt NCM
    // fuer diesen Lauf weg (Log), die Lebensader faellt nie.
    // Erster freier IN-Endpunkt: EP1 (0x81) nur mit Video, EP2 (0x82) nur mit Audio.
    uint8_t nextIn = (uint8_t)(1 + (WEIRDOS_FEATURE_UVC ? 1 : 0) + (audioItf ? 1 : 0));
    const uint8_t cdcNotifEp = (uint8_t)(0x80 | nextIn++);
    const uint8_t cdcDataNum = nextIn++;
    const uint8_t cdcItf = (uint8_t)(ITF_COUNT + audioItf);
    const uint8_t cdc[] = {
        TUD_CDC_DESCRIPTOR(cdcItf, STR_CDC, cdcNotifEp, 16,
                           cdcDataNum, (uint8_t)(0x80 | cdcDataNum), bulkMps)
    };

#if WEIRDOS_UNC_SUPPORTED
    bool withNcm = s_ncmOn;
    // NCM braucht ZWEI IN-EPs (Notify nextIn, Daten nextIn+1); hoechster gueltiger
    // IN-EP ist 4. Passt das nicht (z.B. Video+Audio+Konsole belegen schon EP1..4),
    // faellt NCM fuer diesen Lauf weg -- die Lebensader bleibt.
    if (withNcm && (nextIn + 1) > 4) {
        withNcm = false;
        Serial.println("USB-Device: IN-Endpunkte voll (Video+Audio+Konsole) -> NCM fuer diesen Lauf aus");
    }
    const uint8_t ncmNotifEp = (uint8_t)(0x80 | nextIn);
    const uint8_t ncmDataNum = (uint8_t)(nextIn + 1);
    const uint8_t ncmComm = (uint8_t)(cdcItf + 2);
    const uint8_t ncm[] = {
        TUD_CDC_NCM_DESCRIPTOR(ncmComm, STR_NCM, STR_NCM_MAC, ncmNotifEp, 64,
                               ncmDataNum, (uint8_t)(0x80 | ncmDataNum), bulkMps, 1514, 16, 0)
    };
    const uint16_t ncmLen = withNcm ? (uint16_t)sizeof(ncm) : 0;
    const uint8_t  ncmItf = withNcm ? 2 : 0;
#else
    const uint16_t ncmLen = 0;
    const uint8_t  ncmItf = 0;
#endif

    const uint8_t  itfTotal = (uint8_t)(ITF_COUNT + audioItf + 2 /*CDC*/ + ncmItf);
    const uint16_t total = TUD_CONFIG_DESC_LEN + videoLen
                         + audioLen + (uint16_t)sizeof(cdc) + ncmLen;
    // Extern versorgt -> SELF_POWERED, 100 mA (VBUS-Sense gibt es nicht -> siehe Header/USB-DEVICE.md)
    const uint8_t head[] = { TUD_CONFIG_DESCRIPTOR(1, itfTotal, 0, total, TUSB_DESC_CONFIG_ATT_SELF_POWERED, 100) };
    uint8_t* d = (uint8_t*)malloc(total);
    if (!d) return false;
    if (*outDesc) free(*outDesc);
    *outDesc = d; *outLen = total;
    uint8_t* p = d;
    memcpy(p, head, sizeof(head));   p += sizeof(head);
#if WEIRDOS_FEATURE_UVC
    memcpy(p, partA, sizeof(partA)); p += sizeof(partA);
    for (int i = 0; i < nFrames; i++) {
        const uint16_t fw = (s_modeCount > 0) ? s_modeW[i] : w;
        const uint16_t fh = (s_modeCount > 0) ? s_modeH[i] : h;
        const uint32_t minbr = (uint32_t)fw * fh * 16UL, maxbr = (uint32_t)fw * fh * 16UL * fps;
        const uint8_t frm[] = {
            TUD_VIDEO_DESC_CS_VS_FRM_MJPEG_CONT((uint8_t)(i + 1), 0, fw, fh, minbr, maxbr,
                                                frameBufMax(fw, fh), interval, interval, interval, interval)
        };
        memcpy(p, frm, sizeof(frm)); p += sizeof(frm);
    }
    memcpy(p, partC, sizeof(partC)); p += sizeof(partC);
#endif
#if WEIRDOS_UAC_SUPPORTED
    if (withAudio) { memcpy(p, audio, sizeof(audio)); p += sizeof(audio); }
#endif
    memcpy(p, cdc, sizeof(cdc)); p += sizeof(cdc);   // Lebensader, immer
#if WEIRDOS_UNC_SUPPORTED
    if (withNcm) { memcpy(p, ncm, sizeof(ncm)); p += sizeof(ncm); }
#endif
    return true;
}

static bool buildDescriptors(uint16_t w, uint16_t h, uint8_t fps) {
    s_w = w; s_h = h;
    s_maxFrame = frameBufMax(w, h);
    if (!buildOneConfig(w, h, fps, UVC_BULK_MPS_FS, &s_cfgDesc, &s_cfgLen)) return false;
    if (s_highSpeed && !buildOneConfig(w, h, fps, UVC_BULK_MPS_HS, &s_cfgDescHs, &s_cfgLenHs)) return false;

    memset(&s_devDesc, 0, sizeof(s_devDesc));
    s_devDesc.bLength = sizeof(tusb_desc_device_t); s_devDesc.bDescriptorType = TUSB_DESC_DEVICE;
    s_devDesc.bcdUSB = 0x0200;
    s_devDesc.bDeviceClass = TUSB_CLASS_MISC; s_devDesc.bDeviceSubClass = MISC_SUBCLASS_COMMON; s_devDesc.bDeviceProtocol = MISC_PROTOCOL_IAD;
    s_devDesc.bMaxPacketSize0 = 64;
    s_devDesc.idVendor = UVC_VID; s_devDesc.idProduct = UVC_PID; s_devDesc.bcdDevice = 0x0100;
    s_devDesc.iManufacturer = STR_MANUF; s_devDesc.iProduct = STR_PRODUCT; s_devDesc.iSerialNumber = STR_SERIAL;
    s_devDesc.bNumConfigurations = 1;
    // Device-Qualifier (nur HS-faehige Geraete werden danach gefragt; FS-Betrieb antwortet damit ebenfalls korrekt)
    memset(&s_qualDesc, 0, sizeof(s_qualDesc));
    s_qualDesc.bLength = sizeof(tusb_desc_device_qualifier_t); s_qualDesc.bDescriptorType = TUSB_DESC_DEVICE_QUALIFIER;
    s_qualDesc.bcdUSB = 0x0200; s_qualDesc.bDeviceClass = TUSB_CLASS_MISC; s_qualDesc.bDeviceSubClass = MISC_SUBCLASS_COMMON;
    s_qualDesc.bDeviceProtocol = MISC_PROTOCOL_IAD; s_qualDesc.bMaxPacketSize0 = 64; s_qualDesc.bNumConfigurations = 1;
    uint8_t mac[6] = {0}; esp_read_mac(mac, ESP_MAC_BASE);
    snprintf(s_serial, sizeof(s_serial), "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return true;
}

// ---- TinyUSB-Deskriptor-Callbacks (ueberschreiben die __weak-Versionen des Arduino-Cores) ----------
extern "C" uint8_t const* tud_descriptor_device_cb(void) { return (uint8_t const*)&s_devDesc; }
// Konfiguration je ausgehandelter Geschwindigkeit: HS-Port am HS-Host -> Bulk 512, sonst Bulk 64. Die
// "andere" Geschwindigkeit liefert das jeweils andere Exemplar (nur ein HS-Port hat zwei).
static uint8_t const* cfgForSpeed(bool high) { return (high && s_cfgDescHs) ? s_cfgDescHs : s_cfgDesc; }
extern "C" uint8_t const* tud_descriptor_configuration_cb(uint8_t index) { (void)index; return cfgForSpeed(tud_speed_get() == TUSB_SPEED_HIGH); }
extern "C" uint8_t const* tud_descriptor_device_qualifier_cb(void) { return (uint8_t const*)&s_qualDesc; }
extern "C" uint8_t const* tud_descriptor_other_speed_configuration_cb(uint8_t index) { (void)index; return cfgForSpeed(tud_speed_get() != TUSB_SPEED_HIGH); }
extern "C" uint16_t const* tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void)langid;
    const char* s = nullptr;
    switch (index) {
        case STR_LANG:    s_strBuf[1] = 0x0409; s_strBuf[0] = (uint16_t)((TUSB_DESC_STRING << 8) | 4); return s_strBuf;
        case STR_MANUF:   s = "WeirdOS"; break;
        case STR_PRODUCT: s = "WeirdOS Camera"; break;
        case STR_SERIAL:  s = s_serial; break;
        case STR_UVC:     s = "WeirdOS Camera"; break;
        case STR_UAC:     s = "WeirdOS Microphone"; break;
        case STR_CDC:     s = "WeirdOS Console"; break;
#if WEIRDOS_UNC_SUPPORTED
        case STR_NCM:     s = "WeirdOS USB Network"; break;
        case STR_NCM_MAC: s = s_ncmMacStr; break;   // iMACAddress: 12 Hex, Host-Seite
#endif
        default: return nullptr;
    }
    size_t n = strlen(s); if (n > 62) n = 62;
    for (size_t i = 0; i < n; i++) s_strBuf[1 + i] = (uint8_t)s[i];
    s_strBuf[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * n + 2));
    return s_strBuf;
}

// ---- Video-Callbacks (tud_mount_cb & Co. bewusst NICHT: der Core definiert sie stark) --------------
extern "C" int tud_video_commit_cb(uint_fast8_t ctl_idx, uint_fast8_t stm_idx, video_probe_and_commit_control_t const* parameters) {
    (void)ctl_idx; (void)stm_idx;
    uint32_t iv = parameters->dwFrameInterval; if (iv < 333333) iv = 333333; if (iv > 10000000) iv = 10000000;
    s_intervalMs = iv / 10000;
    s_payloadMax = parameters->dwMaxPayloadTransferSize;   // = WEIRDOS_UVC_PAYLOAD_MAX, sofern der Host es uebernimmt
    // Aufloesungswahl des Hosts: bFrameIndex (1-basiert) -> Sensor umschalten.
    // Schlaegt setMode fehl, bekommt der Host den FEHLER -- nicht stillschweigend
    // eine andere Groesse als angesagt (der Deskriptor ist ein Vertrag).
    const int fi = (int)parameters->bFrameIndex;
    if (s_modeCount > 0 && fi >= 1 && fi <= s_modeCount) {
        const uint16_t nw = s_modeW[fi - 1], nh = s_modeH[fi - 1];
        if (nw != s_w || nh != s_h) {
            if (!cameraManager.setMode(nw, nh)) {
                logEvent(String("UVC: Host will ") + nw + "x" + nh + ", setMode lehnt ab -- Stream bleibt bei " + s_w + "x" + s_h);
                return VIDEO_ERROR_OUT_OF_RANGE;
            }
            s_w = nw; s_h = nh; s_maxFrame = frameBufMax(nw, nh);
            s_len = 0;                                        // letzter Frame hat die alte Groesse
            s_modeSwitchUs = (uint32_t)esp_timer_get_time();  // Alt-Frames aus der Pipeline verwerfen
            logEvent(String("UVC: Host waehlt ") + nw + "x" + nh);
        }
    }
    return VIDEO_ERROR_NONE;
}
// ---- CDC-Lebensader: Bootloader-Einstieg OHNE Tasten -----------------------------------------------
// NICHT vom Core geerbt: unsere Builds laufen mit CDCOnBoot=Disabled (beim XIAO
// ist der Wert-Schluessel "cdc" = Disabled!), also linkt main.cpp USBCDC.cpp NIE
// und dessen Reset-Callbacks existieren nicht. Deshalb hier selbst, Logik 1:1 aus
// USBCDC.cpp des Cores: 1200-Baud-Touch (Arduino IDE) und die esptool-DTR/RTS-
// Sequenz IDLE -(0,1)-> 1 -(1,1)-> 2 -(1,0)-> 3 -(0,0)-> Bootloader. Der ROM
// bleibt dank usb_persist am OTG-Port -> flashbar am selben Kabel.
#include "esp32-hal-tinyusb.h"   // usb_persist_restart(RESTART_BOOTLOADER)
extern "C" void tud_cdc_line_coding_cb(uint8_t itf, cdc_line_coding_t const* c) {
    (void)itf;
    if (c->bit_rate == 1200) usb_persist_restart(RESTART_BOOTLOADER);
}
extern "C" void tud_cdc_line_state_cb(uint8_t itf, bool dtr, bool rts) {
    (void)itf;
    static uint8_t st = 0;
    static bool ldtr = false, lrts = false;
    if (dtr == ldtr && rts == lrts) return;   // doppelte Ereignisse ueberspringen
    ldtr = dtr; lrts = rts;
    if (!dtr && rts)      st = (st == 0) ? 1 : 0;
    else if (dtr && rts)  st = (st == 1) ? 2 : 0;
    else if (dtr && !rts) st = (st == 2) ? 3 : 0;
    else { if (st == 3) usb_persist_restart(RESTART_BOOTLOADER); st = 0; }
}

extern "C" int tud_video_power_mode_cb(uint_fast8_t ctl_idx, uint8_t power_mod) { (void)ctl_idx; (void)power_mod; return VIDEO_ERROR_NONE; }
extern "C" void tud_video_frame_xfer_complete_cb(uint_fast8_t ctl_idx, uint_fast8_t stm_idx) { (void)ctl_idx; (void)stm_idx; s_txBusy = false; }

#if WEIRDOS_UAC_SUPPORTED
// ---- UAC2-Mikrofon-Callbacks (die vorkompilierte Audio-Klasse ruft sie) ----------------------------
// Host waehlt AS-Alt: alt 1 = Stream an, alt 0 = aus.
extern "C" bool tud_audio_set_itf_cb(uint8_t rhport, tusb_control_request_t const* req) {
    (void)rhport;
    s_audioStreaming = (TU_U16_LOW(req->wValue) != 0);
    return true;
}
extern "C" bool tud_audio_set_itf_close_ep_cb(uint8_t rhport, tusb_control_request_t const* req) {
    (void)rhport; (void)req; s_audioStreaming = false; return true;
}
// Clock-Entity: feste Abtastrate melden (CUR/RANGE) + Clock gueltig.
extern "C" bool tud_audio_get_req_entity_cb(uint8_t rhport, tusb_control_request_t const* req) {
    const uint8_t entity  = TU_U16_HIGH(req->wIndex);
    const uint8_t ctrlSel = TU_U16_HIGH(req->wValue);
    if (entity != UAC_CLK_ID) return false;
    if (ctrlSel == 0x01 /*SAM_FREQ_CONTROL*/) {
        if (req->bRequest == 0x01 /*CUR*/) {
            uint32_t f = UAC_RATE;
            return tud_audio_buffer_and_schedule_control_xfer(rhport, req, &f, sizeof(f));
        }
        if (req->bRequest == 0x02 /*RANGE*/) {
            struct TU_ATTR_PACKED { uint16_t n; int32_t mn, mx, res; } r = { 1, (int32_t)UAC_RATE, (int32_t)UAC_RATE, 0 };
            return tud_audio_buffer_and_schedule_control_xfer(rhport, req, &r, sizeof(r));
        }
    } else if (ctrlSel == 0x02 /*CLK_VALID_CONTROL*/ && req->bRequest == 0x01 /*CUR*/) {
        uint8_t v = 1;
        return tud_audio_buffer_and_schedule_control_xfer(rhport, req, &v, sizeof(v));
    }
    return false;
}
// Nur 16 kHz -> jede Setzung der Rate bestaetigen (der Host schickt genau die).
extern "C" bool tud_audio_set_req_entity_cb(uint8_t rhport, tusb_control_request_t const* req, uint8_t* buf) {
    (void)rhport; (void)req; (void)buf; return true;
}
#endif

// ---- Frame-Pumpe -----------------------------------------------------------------------------------
static void pump() {
    bool mounted = tud_mounted();
    if (mounted != s_mounted) {
        s_mounted = mounted;
        if (mounted) logEvent(String("USB-Device: vom PC angesprochen (konfiguriert, ") + (tud_speed_get() == TUSB_SPEED_HIGH ? "High-Speed" : "Full-Speed") + ")");
        else { s_streaming = false; s_txBusy = false; logEvent("USB-Device: vom PC getrennt");
#if WEIRDOS_FEATURE_UVC
               if (s_camConsumer) { cameraStream.removeClient(); s_camConsumer = false; }
#endif
        }
    }
    s_suspended = tud_suspended();
#if !WEIRDOS_FEATURE_UVC
    return;   // ohne Kamera nichts zu pumpen (NCM/CDC laufen ueber ihre eigenen Klassen)
#else
    bool streaming = mounted && tud_video_n_streaming(0, 0);
    if (streaming != s_streaming) {
        s_streaming = streaming;
        if (streaming) { s_txBusy = false; s_lastFrameUs = 0; logEvent(String("UVC: Stream gestartet (") + s_w + "x" + s_h + ", Intervall " + s_intervalMs + " ms, Bulk-Payload " + s_payloadMax + " B)"); }
        else logEvent("UVC: Stream gestoppt");
        if (!s_srcTest) {
            if (streaming && !s_camConsumer) { s_seq = cameraStream.latestSequence(); cameraStream.addClient(); s_camConsumer = true; }
            if (!streaming && s_camConsumer) { cameraStream.removeClient(); s_camConsumer = false; }
        }
    }
    if (!streaming || s_txBusy) return;
    uint32_t now = (uint32_t)esp_timer_get_time();
    if (s_lastFrameUs && (now - s_lastFrameUs) < s_intervalMs * 1000UL) return;

    const void* data = nullptr; size_t len = 0;
    if (s_srcTest) { data = kUvcTestJpeg; len = UVC_TEST_JPEG_LEN; }
    else {
        // Nach einer Sensor-Umschaltung liegen noch Frames der ALTEN Groesse in
        // der Pipeline (esp_camera-Framebuffer). 400 ms verwerfen, dann nur noch
        // Frames NACH dem aktuellen Stand nehmen -- ein Alt-Frame im neuen
        // Stream ist exakt der Dekodier-Salat, den der Deskriptor-Fix beseitigt.
        if (s_modeSwitchUs) {
            if ((now - s_modeSwitchUs) < 400000UL) { s_skipsNoFrame++; return; }
            s_modeSwitchUs = 0; s_seq = cameraStream.latestSequence(); s_len = 0;
        }
        size_t n = cameraStream.copyLatest(&s_buf, &s_cap, &s_seq);   // 0 = kein neuer Frame
        if (n > 0) { s_len = n; }
        else if (s_len == 0 || (now - s_lastFrameUs) < 500000UL) { s_skipsNoFrame++; return; }   // kurz warten, sonst letzten Frame wiederholen
        data = s_buf; len = s_len;
        if (len > s_maxFrame) { s_skipsNoFrame++; return; }   // groesser als dem Host angekuendigt -> nicht senden
    }
    if (!tud_video_n_frame_xfer(0, 0, (void*)data, len)) return;
    s_txBusy = true; s_lastFrameUs = now;
    s_frames++; s_bytes += (uint32_t)len; s_lastLen = (uint32_t)len; if (len > s_maxLen) s_maxLen = (uint32_t)len;
#endif  // WEIRDOS_FEATURE_UVC
}

#if WEIRDOS_UAC_SUPPORTED
// Mikrofon-PCM in die Audio-Klasse schieben (unabhaengig vom Video-Pfad, der in
// pump() frueh zurueckkehrt). Die Klasse laedt daraus den iso IN-Endpunkt.
static void pumpAudio() {
    if (!s_audioOn || !s_audioStreaming || !tud_mounted()) return;
    static int16_t tmp[256];
    size_t n = cam::mic::read(tmp, 256);
    if (n) tud_audio_write((uint8_t*)tmp, (uint16_t)(n * sizeof(int16_t)));
}
#endif

static void usbdevTask(void*) { usbDeviceService.taskLoop(); vTaskDelete(nullptr); }
void UsbDeviceService::taskLoop() {
    for (;;) {
        tud_task_ext(2, false);   // Ereignisse verarbeiten, max. 2 ms blockieren
        pump();
#if WEIRDOS_UAC_SUPPORTED
        pumpAudio();
#endif
    }
}

static void cleanupAfterFail(bool tusbInited) {
#if WEIRDOS_UAC_SUPPORTED
    if (s_audioOn) { cam::mic::end(); s_audioOn = false; s_audioStreaming = false; }
#endif
#if WEIRDOS_UNC_SUPPORTED
    if (s_ncmOn) { cam::usbnet::end(); s_ncmOn = false; }
#endif
    if (tusbInited) tusb_deinit(s_rhport);
    if (s_phy) { usb_del_phy(s_phy); s_phy = nullptr; }
    if (s_cfgDesc) { free(s_cfgDesc); s_cfgDesc = nullptr; s_cfgLen = 0; }
    if (s_cfgDescHs) { free(s_cfgDescHs); s_cfgDescHs = nullptr; s_cfgLenHs = 0; }
}

bool UsbDeviceService::begin() {
    fail_ = "";
    uint16_t w = UVC_TEST_JPEG_W, h = UVC_TEST_JPEG_H;
    s_srcTest = (cfg_.cam == "testpattern0");
#if WEIRDOS_FEATURE_UVC
    // Video-Build: es braucht einen Kamera-/Testbild-Export, sonst nichts zu tun.
    if (!enabled()) { Serial.println("USB-Device: kein Export konfiguriert (System > Geraete > Bereitstellen an USB)."); return false; }
    if (!s_srcTest) {
        if (!cameraReady) { fail_ = "camera0 nicht bereit"; Serial.println("USB-Device: camera0 nicht bereit -> nicht gestartet"); logEvent("UVC: " + fail_); return false; }
        // KEIN stiller Rueckfall auf die Testbild-Masse: der Deskriptor ist ein
        // Vertrag mit dem Host. Stimmt er nicht mit den JPEGs ueberein, dekodiert
        // Windows in den falschen Puffer (Magenta/Gruen-Salat, Befund 2026-09-30
        // -- Sensor lief per NVS auf UXGA, Deskriptor sagte 640x480). Lieber laut
        // scheitern als falsch ansagen.
        uint16_t cw = 0, ch = 0;
        if (!cameraManager.currentMode(cw, ch) || !cw || !ch) {
            fail_ = "camera0-Aufloesung nicht lesbar (currentMode)";
            Serial.println("USB-Device: " + fail_ + " -> nicht gestartet");
            logEvent("UVC: " + fail_);
            return false;
        }
        w = cw; h = ch;
        // Waehlbare Aufloesungen fuer den Deskriptor (Host waehlt per bFrameIndex).
        // enumModes liefert nur, was setMode() annimmt (am PSRAM-Maximum gedeckelt).
        // Frame-Index 1 ist die UVC-VORGABE: Apps ohne Auswaehler (Windows-Kamera-
        // App) zeigen genau diese. Also die aktuell konfigurierte Aufloesung (cw,ch)
        // ZUERST -- sonst landet die App auf der kleinsten (640x480) und man kann sie
        // dort mangels Auswahl nicht hochstellen.
        s_modeCount = 0;
        s_modeW[s_modeCount] = w; s_modeH[s_modeCount] = h; s_modeCount++;   // Vorgabe = currentMode
        CameraVideoMode modes[UVC_MAX_MODES];
        const int nm = cameraManager.enumModes(modes, UVC_MAX_MODES);
        for (int i = 0; i < nm && s_modeCount < UVC_MAX_MODES; i++) {
            if (!modes[i].width || !modes[i].height) continue;
            if (modes[i].width == w && modes[i].height == h) continue;   // Vorgabe steht schon vorn
            s_modeW[s_modeCount] = modes[i].width;
            s_modeH[s_modeCount] = modes[i].height;
            s_modeCount++;
        }
    } else {
        s_modeCount = 0;   // Testbild: genau ein Frame in Testbild-Groesse
    }
#else
    // Kein Video im Build (z.B. usb-tether): kein Kamera-Export, kein Frame.
    s_srcTest = false;
    s_modeCount = 0;
#endif
#if WEIRDOS_UAC_SUPPORTED
    // Mikrofon best-effort erkennen (Option 3): klappt es, traegt der Deskriptor
    // die Audio-Funktion; sonst bleibt es beim reinen Video (kein Fehler).
    uint32_t micRate = 0;
    s_audioOn = cam::mic::begin(UAC_RATE, &micRate);
    if (s_audioOn) { Serial.printf("USB-Device: Mikrofon aktiv (%s)\n", cam::mic::backendName()); logEvent(String("UAC: Mikrofon aktiv (") + cam::mic::backendName() + ")"); }
    else { Serial.println("USB-Device: kein Mikrofon -> nur Video"); }
#endif
#if WEIRDOS_UNC_SUPPORTED
    // USB-Netzadapter hochbringen (netif + DHCP). iMACAddress-String aus der
    // Geraete-MAC ableiten (Host-Seite = device ^ 1 im letzten Byte).
    {
        uint8_t m[6]; memcpy(m, tud_network_mac_address, 6); m[5] ^= 0x01;
        for (int i = 0; i < 6; i++) snprintf(s_ncmMacStr + i * 2, 3, "%02X", m[i]);
    }
    s_ncmOn = cam::usbnet::begin();
    if (s_ncmOn) { Serial.printf("USB-Device: USB-Netz aktiv (%s)\n", cam::usbnet::deviceIpText()); logEvent(String("NCM: USB-Netz aktiv (") + cam::usbnet::deviceIpText() + ")"); }
    else { Serial.println("USB-Device: USB-Netz nicht gestartet -> ohne NCM"); }
#endif
    // Port -> Controller/PHY/rhport aus dem Board-Mapping
    UsbDeviceHw hw = usbPortDeviceHw(cfg_.port);
    if (!hw.ok) { fail_ = "Port " + cfg_.port + " ist im USB-Mapping nicht nutzbar (aus/ungueltige Pins)"; Serial.println("USB-Device: " + fail_); logEvent("UVC: " + fail_); return false; }
    if (usbHostStarted && cfg_.port == periphModemPort) { fail_ = "Port " + cfg_.port + " ist vom Modem-Host belegt"; Serial.println("USB-Device: " + fail_); logEvent("UVC: " + fail_); return false; }
    usb_phy_config_t pc = {};
    pc.controller = USB_PHY_CTRL_OTG; pc.otg_mode = USB_OTG_MODE_DEVICE;
    pc.target = hw.utmi ? USB_PHY_TARGET_UTMI : USB_PHY_TARGET_INT;
    pc.otg_speed = hw.highSpeed ? USB_PHY_SPEED_HIGH : USB_PHY_SPEED_FULL;
    s_rhport = hw.rhport; s_highSpeed = hw.highSpeed;
    if (!buildDescriptors(w, h, cfg_.fps)) { fail_ = "kein Heap fuer Deskriptoren"; Serial.println("USB-Device: " + fail_); return false; }
    esp_err_t e = usb_new_phy(&pc, &s_phy);
    if (e != ESP_OK) { fail_ = String("PHY nicht initialisierbar: ") + esp_err_to_name(e); Serial.println("USB-Device: " + fail_); logEvent("UVC: " + fail_); cleanupAfterFail(false); return false; }
    usbPortApplyPhySelect(cfg_.port);   // P4 + FS: FSLS-PHY 0 (24/25) oder 1 (26/27)
    tusb_rhport_init_t ri = {}; ri.role = TUSB_ROLE_DEVICE; ri.speed = s_highSpeed ? TUSB_SPEED_HIGH : TUSB_SPEED_FULL;
    if (!tusb_rhport_init(s_rhport, &ri)) { fail_ = String("TinyUSB rhport ") + s_rhport + " nicht initialisierbar"; Serial.println("USB-Device: " + fail_); logEvent("UVC: " + fail_); cleanupAfterFail(false); return false; }
    if (xTaskCreatePinnedToCore(usbdevTask, "usbdev", 4096, nullptr, tskIDLE_PRIORITY + 5, nullptr, 0) != pdPASS) {
        fail_ = "Worker-Task nicht anlegbar (interner Heap)"; Serial.println("USB-Device: " + fail_); logEvent("UVC: " + fail_); cleanupAfterFail(true); return false;
    }
    started_ = true;
    Serial.printf("USB-Device bereit: 'WeirdOS Camera' <- %s, MJPEG %ux%u @%u fps, Bulk %u B/Paket, Port %s\n",
                  cfg_.cam.c_str(), (unsigned)w, (unsigned)h, (unsigned)cfg_.fps, (unsigned)(s_highSpeed ? UVC_BULK_MPS_HS : UVC_BULK_MPS_FS), portLabel(cfg_.port).c_str());
    return true;
}

String UsbDeviceService::statusText() {
    String t = String("usbdev: Port ") + cfg_.port + " (" + portLabel(cfg_.port) + ")\r\n";
    String micState =
#if WEIRDOS_UAC_SUPPORTED
        s_audioOn ? (String("UAC (") + cam::mic::backendName() + ")") : String("kein Mikro erkannt");
#else
        String("nicht im Build");
#endif
    t += String("  Export: camera0=") + (cfg_.cam == "camera0" ? "UVC" : "aus") + "  testpattern0=" + (cfg_.cam == "testpattern0" ? "UVC" : "aus") + "  microphone0=" + micState + "  usb-network=NCM nicht implementiert  fps " + cfg_.fps + "\r\n";
    t += String("  Stack: ") + (started_ ? "laeuft" : (fail_.length() ? ("NICHT gestartet: " + fail_) : "nicht gestartet")) + "\r\n";
    if (started_) {
        t += String("  Host: ") + (s_mounted ? "konfiguriert" : "nicht verbunden") + (s_suspended ? " (suspend)" : "") + "  Stream: " + (s_streaming ? "AN" : "aus") + "  Intervall " + s_intervalMs + " ms  " + (s_highSpeed ? "HS" : "FS") + " rhport " + s_rhport + "  Transport Bulk, Payload " + s_payloadMax + " B\r\n";
        t += String("  Format: MJPEG ") + s_w + "x" + s_h + "  Frames " + s_frames + "  Bytes " + s_bytes + "  letzte/max JPEG " + s_lastLen + "/" + s_maxLen + " B  uebersprungen " + s_skipsNoFrame + "\r\n";
    }
    return t;
}
String UsbDeviceService::statusJson() {
    return String("{\"port\":\"") + cfg_.port + "\",\"portLabel\":\"" + escapeJson(portLabel(cfg_.port)) + "\",\"cam\":\"" + cfg_.cam + "\",\"fps\":" + cfg_.fps +
           ",\"active\":" + (started_ ? "true" : "false") + ",\"fail\":\"" + escapeJson(fail_) + "\"" +
           ",\"mounted\":" + (s_mounted ? "true" : "false") + ",\"streaming\":" + (s_streaming ? "true" : "false") + ",\"intervalMs\":" + s_intervalMs +
           ",\"highSpeed\":" + (s_highSpeed ? "true" : "false") + ",\"transport\":\"bulk\",\"payloadMax\":" + s_payloadMax + ",\"width\":" + s_w + ",\"height\":" + s_h + ",\"frames\":" + s_frames + ",\"bytes\":" + s_bytes +
           ",\"lastLen\":" + s_lastLen + ",\"maxLen\":" + s_maxLen + ",\"skips\":" + s_skipsNoFrame + "}";
}
#else
static const char* kNotBuilt = "im Build deaktiviert (Feature-Flag WEIRDOS_USB_DEVICE=1 setzen; TinyUSB kostet ~48 KB internen RAM)";
bool   UsbDeviceService::begin() { if (enabled()) { fail_ = kNotBuilt; Serial.println(String("USB-Device: Export konfiguriert, aber ") + kNotBuilt); logEvent(String("USB-Device: ") + kNotBuilt); } return false; }
void   UsbDeviceService::taskLoop() {}
String UsbDeviceService::statusText() { return String("usbdev: Port ") + cfg_.port + ", Export " + (cfg_.cam.length() ? cfg_.cam : String("aus")) + " -- " + kNotBuilt + "\r\n"; }
String UsbDeviceService::statusJson() { return String("{\"port\":\"") + cfg_.port + "\",\"cam\":\"" + cfg_.cam + "\",\"fps\":" + cfg_.fps + ",\"active\":false,\"builtIn\":false,\"fail\":\"" + kNotBuilt + "\"}"; }
#endif
