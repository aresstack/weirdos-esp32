# WeirdOS — Modulkatalog & Zerlegung

Ziel: WeirdOS so zerlegen, dass beim Flashen **nur die referenzierten Module**
im Binary landen. Diese Datei ist die *Wahrheit* über die echten Module — sie
ersetzt den fiktiven Katalog, den das Cam-Tool bisher kannte.

## 1. Die zwei Compile-Ziele (Chip) — nicht sechs

Der Chip ist das feste Compile-Ziel je Binary. WeirdOS kennt real **genau zwei**
plus ein Frei-Profil (aus `platform.h`):

| Profil-ID | Chip | Rolle | Besonderheit |
|-----------|------|-------|--------------|
| `xiao-esp32-s3` | ESP32-**S3** | Kamera + VPN-Zugangspunkt | 1 USB-Port (BOOT+RESET-Flash-Hack), FS-OTG 12 Mbit, **WLAN-Funk** |
| `esp32-p4-pico` | ESP32-**P4** | Modem-Host + Kamera | 2 USB (JTAG **und** HS-OTG → kein Flash-Hack), HW-H.264, **kein Funk** |
| `custom` | * | frei verdrahtet | USB-Pins auf eigene Gefahr |

> S2/C3/C6 aus dem alten Tool-Katalog sind **irrelevant**: kein Kamera-Interface
> (C3/C6) bzw. nie eingesetzt. Der Katalog des Tools ist auf S3 + P4 (+ custom)
> zu kürzen — deckungsgleich mit `platform.h`.

**S3 → P4-Schwenk (der kritische Punkt).** Der S3 war das ursprüngliche Board
(XIAO-S3-Kamera/WLAN-Webserver + Modem). Er stößt an Heap/Flash und hat den
Ein-Port-Flash-Hack. Der P4 hat Dual-USB (flashen, während das Modem hängt) und
hebt den 12-Mbit-Deckel — **aber kein WLAN-Funk**. Daraus folgt die Trennlinie
zwischen Kern und Option (Abschnitt 3).

## 2. Was am Tool-Katalog falsch ist

Der bisherige Tool-Katalog (`weirdos_features.cpp`) erfindet Module und verfehlt
die echten Schwergewichte:

| Tool sagt | Realität |
|-----------|----------|
| `ETHERNET` | **nicht implementiert.** `ui_wan.cpp` sagt es selbst: „auf diesem Board ist kein PHY bestückt und in dieser Firmware kein Ethernet-Treiber eingebunden" (ausgegraut). Uplink ist WLAN **oder** Modem. |
| `WEBRTC` | **fiktiv.** Kein WebRTC im Baum. Streaming = MJPEG/HTTP **oder** RTSP. |
| `ONVIF` | **fiktiv.** Kein ONVIF-Dienst im Baum. |
| `DETECTION` | **noch fiktiv.** Nur als Zukunft in Kommentaren (AI/YOLO), kein Modul. |
| `AUDIO` | fast leer — nur `audio_source.h` (Platzhalter), keine Implementierung. |

**Fehlend, obwohl real und schwer** (die eigentlichen Heap/Flash-Fresser):
WireGuard, IPsec/IKEv2, Netzzonen (moderne Netzverwaltung), H.264-Encoder,
USB-Device/UVC, Bluetooth-LE, DynDNS, ACME/TLS, Settings-Backup.

## 3. Der echte Modulkatalog

Legende Schalter: `WEIRDOS_FEATURE_<KEY>` (Compile-Zeit, `1`/`0`).
„Ära": S3 = war schon im schlanken S3-Stand da (→ Kern-Kandidat).
P4 = kam mit/nach dem P4-Schwenk (→ eher optional, heap-/flashintensiv).

### Kern — immer kompiliert (kein Schalter)
Composition Root (`weirdos-esp32.ino`), `platform.*` (Board-Profil), `serial_console.*`,
`setup_guard.*`, `peripheral_registry.*`, `network_registry.*`, HTTP-Server +
Setup-Portal-Skelett, NVS/Settings. Ohne die ist WeirdOS nicht lauffähig.

### Basis-Module

| Key | Modul | Dateien | Ära | SoC-Bedarf | Hinweis |
|-----|-------|---------|-----|-----------|---------|
| `CAMERA` | Kamera + Bildpfad | `camera_frame/device/manager/stream/server`, `esp32s3_camera_device`, `esp32p4_camera_device` | S3 | DVP (S3) / MIPI (P4) | Interface schon da: `camera_device.h` → Backend je Chip |
| `WEBUI` | Weboberfläche | `web_ui*.cpp`, `ui_*.cpp`, `web_ui_assets.cpp` | S3 | — | Flashkosten v.a. die Assets → **gzip**, s. flash-and-heap.md |
| `WIFI` | WLAN (STA/AP, Setup-Portal) | in `.ino` (`WiFi.h`), `wifi_caps.*` | S3 | **nur S3** | P4 hat keinen Funk → auf P4 hart aus |
| `MODEM` | LTE-Modem EC200A | `ec200a_modem.*`, `ec200a_ecm.*`, `modem_*` | S3 | USB-Host (S2/S3/P4) | ECM **oder** PPP Datenpfad |
| `USB_HOST` | USB-Host-Fundament | `usb_host`-API in `.ino`, `usb_ports.*` | S3 | OTG | Voraussetzung für `MODEM` |

### Netzwerk / Uplink

| Key | Modul | Dateien | Ära | Hinweis |
|-----|-------|---------|-----|---------|
| `RTSP` | RTSP/RTP-Server | `rtsp_server.*` | P4 | genügsamer Streamingweg |
| `H264` | HW-H.264 + fMP4 | `h264_encoder.*`, `h264_fmp4.*`, `h264_guard.*` | P4 | HW nur P4; Heap-Region exklusiv reservieren |
| `DYNDNS` | DynDNS-Update | in `.ino` (`HTTPClient`/`WiFiClientSecure`) | S3 | |
| `OTA` | OTA-Update | in `.ino` (`Update.h`) | S3 | braucht 2-App-Partition; **aus → single-app spart Flash** |
| `NETSCAN` | LAN-Scan/Ping | `net_scan.*` | S3 | |
| `ZONES` | **Moderne Netzverwaltung** | `zone_planner*`, `zone_runtime*`, `zone_commit*`, `zone_lwip_hooks*`, `egress_policy*`, `wan_policy*`, `wan_service*`, `access_policy*`, `network_mode*` | P4 | ~15 KB statische Tabellen → **PSRAM-Pflicht**; „kann das in den Kern?" s.u. |

### VPN / Sicherheit (P4-Ära, die Schwergewichte)

| Key | Modul | Dateien | Hinweis |
|-----|-------|---------|---------|
| `WIREGUARD` | WireGuard | `wireguard_service.*`, `src/WireGuard/**` | vendored Krypto |
| `IPSEC` | IPsec/IKEv2 (WeirdIKE) | `ipsec_*`, `src/weirdike/**`, `vpn_status.*` | groß; eigener AES-Treiber, weil P4-HW-AES/DMA unter Last scheitert |
| `TLS_ACME` | ACME + Zertifikate | `acme_client.*`, `cert_store.*`, `tls_selfsigned.*`, `aes_engine.*`, `aes_soft.*` | echte Let's-Encrypt-Kette optional |

### Erweiterungen

| Key | Modul | Dateien | Hinweis |
|-----|-------|---------|---------|
| `USB_DEVICE` | WeirdOS als UVC-Webcam am PC | `usb_device_service.*`, `tinyusb_class_stubs.c`, `usb_uvc_testimage.h` | **Musterfall**: schon hinter `WEIRDOS_USB_DEVICE=1` (Default AUS), weil der TinyUSB-Device-Stack ~48 KB statisch zieht |
| `BLUETOOTH` | BLE-Scan/Kopplung | `bt_scan.*` | schon `WEIRDOS_HAS_BT`-Guard |
| `BACKUP` | NVS-Sicherung Export/Import | `settings_backup.*` | |
| `AUDIO` | Audiospur | `audio_source.h` | Platzhalter, noch keine Implementierung |

## 4. Kann die moderne Netzverwaltung (`ZONES`) in den Kern?

Kurz: **auf dem P4 mit PSRAM ja, als abschaltbarer Kern; auf dem S3 nein.**
Belege aus der Historie:
- Die Zonen-Runtime hält ~15 KB statische Tabellen; im internen `.bss` nahmen sie
  dem USB-Host/PPP das DMA-RAM → jetzt zwingend in PSRAM (`zoneHooksInit`,
  „ohne PSRAM Runtime aus"). Das ist genau der Heap-Kompromiss.
- Ohne PSRAM (knappe S3-Varianten) muss `ZONES` aus bleiben.

Empfehlung: `ZONES` als eigenes Feature mit Default **an nur auf P4-Profilen mit
PSRAM**, sonst aus. Die Grund-Egress-/WAN-Wahl (`egress_policy`, `wan_policy`)
ist leichter und kann im Kern bleiben; erst Planner+Runtime+lwIP-Hooks sind der
schwere Teil hinter dem Schalter.

## 5. Wie der Schalter technisch wirkt (Dependency Inversion + Factory)

Der Ansatz ist bereits im Code angelegt und wird nur konsequent gezogen:
1. **Interface** je Modul (`camera_device.h`, `frame_source.h`, `http_transport.h`,
   `modem_ports.hpp`-Analogon …).
2. **Composition Root** (`weirdos-esp32.ino`) referenziert die **Factory** einer
   Implementierung nur unter ihrem `#if WEIRDOS_FEATURE_<KEY>`. Ohne Referenz
   wirft der Linker Implementierung **und** ihre globalen Puffer heraus.
3. **Registry als String→Instanz-Aufloesung**: `peripheral_registry` bildet schon
   heute logische Namen (`camera0`, `cellular0`) auf konkrete Instanzen ab
   (`periphResolveFrameSource`). Die Fabrik wählt also über den String — genau das
   gewünschte Muster —, aber nur unter den einkompilierten Schaltern.
4. **`weirdos_features.h`** (eine Datei) trägt alle `#define WEIRDOS_FEATURE_*`.
   Dieselben Werte gibt das Cam-Tool beim Flashen als `-D…` mit; beide Wege müssen
   denselben Satz ergeben. Nicht unterstützte Kombinationen (z. B. `WIFI` auf P4)
   sind hart `0`.

Reihenfolge der Umsetzung: erst `CAMERA`/`WIFI`/`MODEM`/`USB_HOST` sauber hinter
Schalter (Basis testbar), dann die Schwergewichte (`ZONES`, `IPSEC`, `WIREGUARD`,
`USB_DEVICE`, `H264`), zuletzt Kleinkram.
