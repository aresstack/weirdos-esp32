// ============================================================================
// weirdos_features.h -- DER Schalterkasten von WeirdOS (Build-Zeit).
//
// Jeder Baustein (Modul) hat GENAU EIN Makro WEIRDOS_FEATURE_<KEY> mit 0 oder 1.
// Ein Modul, dessen Schalter 0 ist, wird NICHT referenziert -> der Linker wirft
// seine Uebersetzungseinheit samt globaler Puffer heraus (Flash UND statisches
// RAM). Ein Laufzeitschalter kann das nicht (belegt am TinyUSB-Fall: ~48 KB
// statisches RAM, sobald der Device-Stack nur gelinkt ist).
//
// ZWEI WEGE, EIN SATZ:
//   * Das Cam-Tool gibt beim Bauen -DWEIRDOS_FEATURE_<KEY>=0/1 mit.
//   * Ohne Tool (Arduino-IDE) gelten die Vorgaben unten (#ifndef).
//   Vorgabe = 1 fuer alles, was der SoC kann -> ein unveraenderter Build ist
//   der bisherige Vollausbau. -Wundef: ein Tippfehler im Makronamen warnt statt
//   still zu 0 zu werden -- deshalb bekommt JEDER Key eine Definition.
//
// Die Abhaengigkeiten/Konflikte zwischen den Schaltern prueft
// weirdos_module_rules.h (immer NACH dieser Datei einbinden; der Composition
// Root bindet nur weirdos_module_rules.h ein, das zieht diese Datei mit).
// Die Wahrheit ueber Schnitt, Abhaengigkeiten und Profile: MODULES.md +
// modules.json (maschinenlesbar, dieselbe Quelle fuer Firmware und Tool).
// ============================================================================
#pragma once

#if __has_include("soc/soc_caps.h")
#include "soc/soc_caps.h"
#endif
#if __has_include("sdkconfig.h")
#include "sdkconfig.h"
#endif

// ---------------------------------------------------------------------------
// SoC-Faehigkeiten (harte Chip-Wahrheit, KEINE Nutzerwahl). Ein Feature, das
// der Chip nicht kann, wird unten hart auf 0 gezogen -- ein Haken dafuer waere
// eine Luege.
// ---------------------------------------------------------------------------
#if defined(SOC_WIFI_SUPPORTED) && SOC_WIFI_SUPPORTED && !defined(CONFIG_IDF_TARGET_ESP32P4)
#define WEIRDOS_SOC_WIFI 1
#else
#define WEIRDOS_SOC_WIFI 0            // P4: kein Funkteil im Chip (nur via Co-Prozessor, nicht bestueckt)
#endif
#if defined(SOC_BT_SUPPORTED) && SOC_BT_SUPPORTED
#define WEIRDOS_SOC_BLE 1
#else
#define WEIRDOS_SOC_BLE 0
#endif
#if defined(SOC_USB_OTG_SUPPORTED) && SOC_USB_OTG_SUPPORTED
#define WEIRDOS_SOC_USB_OTG 1         // S2/S3/P4 -- USB-Host und USB-Device
#else
#define WEIRDOS_SOC_USB_OTG 0
#endif
#if defined(CONFIG_IDF_TARGET_ESP32P4)
#define WEIRDOS_SOC_H264HW 1          // esp_h264 + PPA nur auf dem P4
#else
#define WEIRDOS_SOC_H264HW 0
#endif
#if defined(CONFIG_IDF_TARGET_ESP32C3) || defined(CONFIG_IDF_TARGET_ESP32C6)
#define WEIRDOS_SOC_CAMERA 0          // kein DVP/MIPI-Interface
#else
#define WEIRDOS_SOC_CAMERA 1
#endif
#if defined(CONFIG_SPIRAM) || defined(BOARD_HAS_PSRAM)
#define WEIRDOS_SOC_PSRAM 1
#else
#define WEIRDOS_SOC_PSRAM 0
#endif

// ---------------------------------------------------------------------------
// Die Bausteine. Vorgabe 1 (Vollausbau), es sei denn, der SoC kann es nicht.
// Reihenfolge = Schichten aus MODULES.md.
// ---------------------------------------------------------------------------

// ---- Hardware / Transport --------------------------------------------------
#ifndef WEIRDOS_FEATURE_CAMERA
#define WEIRDOS_FEATURE_CAMERA      WEIRDOS_SOC_CAMERA     // Sensor + Bildpfad (FrameSource)
#endif
#ifndef WEIRDOS_FEATURE_USB_HOST
#define WEIRDOS_FEATURE_USB_HOST    WEIRDOS_SOC_USB_OTG    // USB-OTG-Host (Fundament fuer MODEM)
#endif
// Alter Einzelschalter WEIRDOS_USB_DEVICE (build_opt.h / -D) speist den neuen Key, solange
// der neue nicht selbst gesetzt ist -- bestehende Build-Konfigurationen bleiben gueltig.
#if !defined(WEIRDOS_FEATURE_USB_DEVICE) && defined(WEIRDOS_USB_DEVICE)
#define WEIRDOS_FEATURE_USB_DEVICE  WEIRDOS_USB_DEVICE
#endif
#ifndef WEIRDOS_FEATURE_USB_DEVICE
#define WEIRDOS_FEATURE_USB_DEVICE  0                      // TinyUSB-Device-Stack (~48 KB statisch) -- bewusst AUS (wie bisher WEIRDOS_USB_DEVICE)
#endif
#ifndef WEIRDOS_FEATURE_WIFI
#define WEIRDOS_FEATURE_WIFI        WEIRDOS_SOC_WIFI       // STA + AP + Captive-Portal + mDNS
#endif
#ifndef WEIRDOS_FEATURE_BLE
#define WEIRDOS_FEATURE_BLE         WEIRDOS_SOC_BLE        // BLE-Scan/Kopplung (NimBLE)
#endif

// ---- Netz ------------------------------------------------------------------
#ifndef WEIRDOS_FEATURE_NET
#define WEIRDOS_FEATURE_NET         1                      // IP-Stack + Netz-Registry + Egress/WAN-Policy
#endif
#ifndef WEIRDOS_FEATURE_MODEM
#define WEIRDOS_FEATURE_MODEM       WEIRDOS_SOC_USB_OTG    // EC200A ueber USB-Host (PPP/ECM)
#endif
#ifndef WEIRDOS_FEATURE_USB_NCM
#define WEIRDOS_FEATURE_USB_NCM     0                      // ESP als USB-Netzwerkadapter (GEPLANT, noch nicht implementiert)
#endif
#ifndef WEIRDOS_FEATURE_ROUTER
#define WEIRDOS_FEATURE_ROUTER      WEIRDOS_SOC_PSRAM      // Netzzonen: Forwarding/NAT/Policies (PSRAM-Pflicht)
#endif
#ifndef WEIRDOS_FEATURE_WIREGUARD
#define WEIRDOS_FEATURE_WIREGUARD   1
#endif
#ifndef WEIRDOS_FEATURE_IPSEC
#define WEIRDOS_FEATURE_IPSEC       WEIRDOS_SOC_PSRAM      // IKEv2/IPsec (WeirdIKE), PSRAM-Pflicht
#endif
#ifndef WEIRDOS_FEATURE_DYNDNS
#define WEIRDOS_FEATURE_DYNDNS      1
#endif
#ifndef WEIRDOS_FEATURE_NETSCAN
#define WEIRDOS_FEATURE_NETSCAN     1                      // Ping/Portscan/Sniff/Kanalscan (Diagnose)
#endif

// ---- Video-Ausgang (alle brauchen CAMERA) ----------------------------------
#ifndef WEIRDOS_FEATURE_VIDEO_HTTP
#define WEIRDOS_FEATURE_VIDEO_HTTP  1                      // MJPEG-Stream + /capture
#endif
#ifndef WEIRDOS_FEATURE_RTSP
#define WEIRDOS_FEATURE_RTSP        1
#endif
#ifndef WEIRDOS_FEATURE_H264
#define WEIRDOS_FEATURE_H264        WEIRDOS_SOC_H264HW     // HW-Encoder + PPA + fMP4
#endif
#ifndef WEIRDOS_FEATURE_UVC
#define WEIRDOS_FEATURE_UVC         WEIRDOS_FEATURE_USB_DEVICE   // Webcam am PC (braucht USB_DEVICE)
#endif

// ---- Bedienung / Verwaltung ------------------------------------------------
#ifndef WEIRDOS_FEATURE_HTTP
#define WEIRDOS_FEATURE_HTTP        1                      // HTTP-Server-Transport + Auth (Basis fuer WEBUI/VIDEO_HTTP/OTA)
#endif
#ifndef WEIRDOS_FEATURE_WEBUI
#define WEIRDOS_FEATURE_WEBUI       1                      // Weboberflaeche (Seiten + Assets)
#endif
#ifndef WEIRDOS_FEATURE_CONSOLE
#define WEIRDOS_FEATURE_CONSOLE     1                      // serielle Konsole (Kontrollpfad ohne Netz)
#endif
#ifndef WEIRDOS_FEATURE_OTA
#define WEIRDOS_FEATURE_OTA         1
#endif
#ifndef WEIRDOS_FEATURE_BACKUP
#define WEIRDOS_FEATURE_BACKUP      1                      // NVS-Sicherung Export/Import
#endif
#ifndef WEIRDOS_FEATURE_TLS_SERVER
#define WEIRDOS_FEATURE_TLS_SERVER  1                      // HTTPS + Self-Signed + Zertifikatsspeicher
#endif
#ifndef WEIRDOS_FEATURE_TLS_CLIENT
#define WEIRDOS_FEATURE_TLS_CLIENT  1                      // HTTPS-Client (DynDNS, ACME, Speedtest)
#endif
#ifndef WEIRDOS_FEATURE_ACME
#define WEIRDOS_FEATURE_ACME        1                      // Let's-Encrypt-Client
#endif
#ifndef WEIRDOS_FEATURE_CRYPTO_AES
#define WEIRDOS_FEATURE_CRYPTO_AES  WEIRDOS_FEATURE_IPSEC  // eigener AES-Treiber (HW-Block/soft) -- Zulieferer fuer IPSEC
#endif

// ---- Zukunfts-Slots (definiert, damit Tool und Firmware dieselbe Sprache
//      sprechen; noch KEINE Implementierung -> Vorgabe 0) ----------------------
#ifndef WEIRDOS_FEATURE_DETECTION
#define WEIRDOS_FEATURE_DETECTION   0                      // Muster-/Objekterkennung -> Ereignisse
#endif
#ifndef WEIRDOS_FEATURE_AUDIO
#define WEIRDOS_FEATURE_AUDIO       0                      // Mikrofon/Lautsprecher (Gegensprechen)
#endif
#ifndef WEIRDOS_FEATURE_ACTUATOR
#define WEIRDOS_FEATURE_ACTUATOR    0                      // GPIO-Aktor (Tueroeffner, Klingeltaster)
#endif

// ---------------------------------------------------------------------------
// SoC-Klammer: was der Chip nicht kann, ist hart 0 -- auch wenn es jemand per -D
// erzwingt. Sitzt HIER (nicht in weirdos_module_rules.h), damit jede Datei, die
// nur den Schalterkasten einbindet, bereits den geklammerten Wert sieht.
// ---------------------------------------------------------------------------
#if WEIRDOS_FEATURE_WIFI && !WEIRDOS_SOC_WIFI
#undef  WEIRDOS_FEATURE_WIFI
#define WEIRDOS_FEATURE_WIFI 0
#endif
#if WEIRDOS_FEATURE_BLE && !WEIRDOS_SOC_BLE
#undef  WEIRDOS_FEATURE_BLE
#define WEIRDOS_FEATURE_BLE 0
#endif
#if (WEIRDOS_FEATURE_USB_HOST || WEIRDOS_FEATURE_USB_DEVICE) && !WEIRDOS_SOC_USB_OTG
#undef  WEIRDOS_FEATURE_USB_HOST
#define WEIRDOS_FEATURE_USB_HOST 0
#undef  WEIRDOS_FEATURE_USB_DEVICE
#define WEIRDOS_FEATURE_USB_DEVICE 0
#endif
#if WEIRDOS_FEATURE_H264 && !WEIRDOS_SOC_H264HW
#undef  WEIRDOS_FEATURE_H264
#define WEIRDOS_FEATURE_H264 0
#endif
#if WEIRDOS_FEATURE_CAMERA && !WEIRDOS_SOC_CAMERA
#undef  WEIRDOS_FEATURE_CAMERA
#define WEIRDOS_FEATURE_CAMERA 0
#endif

// ---------------------------------------------------------------------------
// Vertraeglichkeits-Aliase fuer die bisherigen, verstreuten Einzelschalter.
// Die alten Namen bleiben gueltig, zeigen aber auf den neuen Schalterkasten.
// ---------------------------------------------------------------------------
#undef  WEIRDOS_USB_DEVICE
#define WEIRDOS_USB_DEVICE  WEIRDOS_FEATURE_USB_DEVICE
