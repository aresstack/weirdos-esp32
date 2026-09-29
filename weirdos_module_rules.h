// ============================================================================
// weirdos_module_rules.h -- Abhaengigkeiten und Konflikte der Bausteine,
// zur BUILD-Zeit geprueft. Der Composition Root bindet NUR diese Datei ein.
//
// Drei Arten von Regeln (Quelle: MODULES.md / modules.json):
//   1. SoC-Grenze   -> Feature wird still auf 0 gezogen (der Chip kann es nicht;
//                      ein Haken dafuer im Tool ist bereits verboten).
//   2. Harte Pflicht -> #error. Ein Baustein ohne sein Fundament ist kein
//                      halbfertiges Feature, sondern ein Linkfehler mit besserer
//                      Fehlermeldung.
//   3. Ableitung    -> ein Zulieferer-Baustein wird automatisch mitgezogen
//                      (z.B. IPSEC braucht CRYPTO_AES; VPN-Status braucht ein VPN).
// ============================================================================
#pragma once
#include "weirdos_features.h"

// ---- 1. SoC-Grenzen: liegen im Schalterkasten selbst (weirdos_features.h), damit
//         sie auch fuer Dateien gelten, die nur diesen einbinden. Hier nichts.

// ---- 2. Harte Pflichten (#error mit Klartext) -------------------------------
#if WEIRDOS_FEATURE_MODEM && !WEIRDOS_FEATURE_USB_HOST
#error "WEIRDOS_FEATURE_MODEM=1 braucht WEIRDOS_FEATURE_USB_HOST=1 (das EC200A haengt am USB-Host)."
#endif
#if WEIRDOS_FEATURE_UVC && !WEIRDOS_FEATURE_USB_DEVICE
#error "WEIRDOS_FEATURE_UVC=1 braucht WEIRDOS_FEATURE_USB_DEVICE=1 (Webcam = TinyUSB-Device)."
#endif
#if WEIRDOS_FEATURE_USB_NCM && !WEIRDOS_FEATURE_USB_DEVICE
#error "WEIRDOS_FEATURE_USB_NCM=1 braucht WEIRDOS_FEATURE_USB_DEVICE=1."
#endif
#if (WEIRDOS_FEATURE_UVC || WEIRDOS_FEATURE_VIDEO_HTTP || WEIRDOS_FEATURE_RTSP || WEIRDOS_FEATURE_H264 || WEIRDOS_FEATURE_DETECTION) && !WEIRDOS_FEATURE_CAMERA
#error "Ein Video-Ausgang (UVC/VIDEO_HTTP/RTSP/H264/DETECTION) braucht WEIRDOS_FEATURE_CAMERA=1."
#endif
#if (WEIRDOS_FEATURE_MODEM || WEIRDOS_FEATURE_WIFI || WEIRDOS_FEATURE_USB_NCM || WEIRDOS_FEATURE_ROUTER \
   || WEIRDOS_FEATURE_WIREGUARD || WEIRDOS_FEATURE_IPSEC || WEIRDOS_FEATURE_DYNDNS || WEIRDOS_FEATURE_NETSCAN \
   || WEIRDOS_FEATURE_RTSP || WEIRDOS_FEATURE_HTTP || WEIRDOS_FEATURE_OTA || WEIRDOS_FEATURE_ACME \
   || WEIRDOS_FEATURE_TLS_CLIENT) && !WEIRDOS_FEATURE_NET
#error "Ein Netzwerk-Baustein ist an, aber WEIRDOS_FEATURE_NET=0 (IP-Stack + Netz-Registry sind das Fundament)."
#endif
#if (WEIRDOS_FEATURE_WEBUI || WEIRDOS_FEATURE_VIDEO_HTTP || WEIRDOS_FEATURE_OTA || WEIRDOS_FEATURE_TLS_SERVER) && !WEIRDOS_FEATURE_HTTP
#error "WEBUI/VIDEO_HTTP/OTA/TLS_SERVER brauchen WEIRDOS_FEATURE_HTTP=1 (HTTP-Server-Transport)."
#endif
#if WEIRDOS_FEATURE_ACME && !(WEIRDOS_FEATURE_TLS_SERVER && WEIRDOS_FEATURE_TLS_CLIENT)
#error "WEIRDOS_FEATURE_ACME=1 braucht TLS_SERVER=1 (Zertifikat einsetzen) und TLS_CLIENT=1 (Let's Encrypt erreichen)."
#endif
#if WEIRDOS_FEATURE_DYNDNS && !WEIRDOS_FEATURE_TLS_CLIENT
#error "WEIRDOS_FEATURE_DYNDNS=1 braucht WEIRDOS_FEATURE_TLS_CLIENT=1 (Anbieter sind https-only)."
#endif
#if WEIRDOS_FEATURE_IPSEC && !WEIRDOS_FEATURE_CRYPTO_AES
#error "WEIRDOS_FEATURE_IPSEC=1 braucht WEIRDOS_FEATURE_CRYPTO_AES=1 (ESP-Datenpfad)."
#endif
#if (WEIRDOS_FEATURE_ROUTER || WEIRDOS_FEATURE_IPSEC) && !WEIRDOS_SOC_PSRAM
#error "ROUTER (Netzzonen) und IPSEC brauchen PSRAM: ihre Tabellen/Workspaces liegen nicht im internen RAM."
#endif

// ---- 3. Ableitungen ------------------------------------------------------------
// VPN-Statusmodell: existiert, sobald irgendein VPN im Build ist (sonst Stub).
#define WEIRDOS_FEATURE_VPN_ANY (WEIRDOS_FEATURE_WIREGUARD || WEIRDOS_FEATURE_IPSEC)
// Mindestens ein Kontrollpfad ist dringend empfohlen -- aber KEIN Fehler: ein
// vorkonfiguriertes Geraet (Tool schreibt die Konfiguration beim Flashen) darf
// voellig headless laufen (z.B. reine USB-Webcam).
#if !(WEIRDOS_FEATURE_WEBUI || WEIRDOS_FEATURE_CONSOLE)
#warning "Weder WEBUI noch CONSOLE im Build: das Geraet ist nur ueber vorkonfigurierte Einstellungen bedienbar."
#endif
// Ein Video-Ausgang ohne Weg nach draussen ist sinnlos -- Hinweis, kein Fehler.
#if WEIRDOS_FEATURE_CAMERA && !(WEIRDOS_FEATURE_UVC || WEIRDOS_FEATURE_VIDEO_HTTP || WEIRDOS_FEATURE_RTSP || WEIRDOS_FEATURE_DETECTION)
#warning "CAMERA ist an, aber kein Video-Ausgang (UVC/VIDEO_HTTP/RTSP) -- das Bild verlaesst das Geraet nicht."
#endif
