# DECOMPOSITION.md — WeirdOS Modul-Dekomposition

Stand: 2026-09-29. Grundlage: das Repository `quectel-ec200a-eu/esp32-modem-host`
(WeirdOS 7.x, belegt über `tls_selfsigned.cpp` `weirdosGenSelfSignedCert`,
`serial_console.cpp` `WEIRDOS-BACKUP`, `WireGuard-ESP32.h` „WeirdOS 7.x").

Dieses Dokument beschreibt, welche Module WeirdOS wirklich enthält, was davon
Kern und was optional ist, und wie die optionalen Teile über einen einzigen
Schalterkasten (`weirdos_features.h`) zur **Build-Zeit** aus dem Image
verschwinden. Es ist die Wahrheit, gegen die das PC-Werkzeug (OpenIPC Cam Tool)
seinen Komponentenkatalog stellen muss.

---

## 1. Die zwei realen Build-Targets (+ Custom)

WeirdOS baut heute für genau zwei SoC-Familien; ein drittes Profil ist der
Platzhalter für fremde Boards. Quelle: `platform.cpp` (`kProfiles[]`,
`platformIsCustom()`), `platform.h`.

| Profil-ID (`platformId()`) | Board | SoC | Funk | USB | Kamera |
|---|---|---|---|---|---|
| `xiao-esp32-s3` | Seeed XIAO ESP32-S3 | ESP32-S3 | WLAN 4 (2,4 GHz) + BT 5 LE **im Chip** | FS-OTG, gemeinsames Paar GPIO19/20 | DVP (OV3660) |
| `esp32-p4-pico` | Waveshare ESP32-P4-Pico | ESP32-P4 | **kein Funk im Chip** — WLAN/BT nur über Co-Prozessor (z.B. C6), **nicht bestückt** | HS-OTG (dedizierte Pads) + 2× FS-PHY (GPIO24/25, GPIO26/27) + USB-Serial/JTAG | MIPI-CSI (OV5647) |
| `custom` | Eigenes Board (`platform "*"`) | beliebig | offen | offen | offen |

Konsequenzen, die den ganzen Katalog prägen (belegt in `platform.cpp` `kMcus[]`,
`wifi_caps.cpp` `wifiPresent()`):

- **P4 hat kein eigenes Funkteil.** `wifiPresent()` ist auf P4 hart `false`
  (`#if CONFIG_IDF_TARGET_ESP32P4 return false`). WLAN, Bluetooth-Scan, mDNS und
  Captive-Portal sind auf P4 tot.
- **Der HW-H.264-Encoder (`esp_h264_enc_single_hw`) und die PPA existieren nur
  auf dem P4.** Auf dem S3 kompilieren `h264_encoder`/`ppa_converter` zu Stubs.
- **USB-OTG-Host und -Device gibt es auf S3 und P4** (S3: ein FS-Paar; P4: HS +
  zwei FS-PHYs). Der Chip/Pin-Unterschied lebt in `usb_ports.*` hinter einem
  reinen SoC-`#if`, nicht hinter einem Feature-Schalter.
- **IPsec/WeirdIKE und Zonen sind PSRAM-gebunden** und praktisch nur auf dem
  P4-32MB-Board erprobt.

---

## 2. Was der alte Cam-Tool-Katalog falsch hatte

Der bisherige Katalog (`tool/src/core/weirdos_features.cpp`) bot Komponenten an,
die WeirdOS **nicht** enthält. Ein Haken dafür ist eine Lüge: das Werkzeug
erzeugt `-DWEIRDOS_FEATURE_<KEY>` für einen Composition Root, der diesen Schalter
nirgends auswertet (firmwareweit **null** Treffer für `WEIRDOS_FEATURE_*`).

Nur die folgenden Einträge sind durch die adversarialen Verdikte (jeweils
`holds=true`) als fiktiv bestätigt und werden entfernt:

| Alter Key | Behauptung | Realität in WeirdOS | Beleg |
|---|---|---|---|
| `ETHERNET` | „Kabelnetz-Feature" | **Kein Treiber.** 0 Treffer für `esp_eth`/`emac`/`LAN8720`; `ui_wan.cpp:67-70` zeigt „Ethernet (PHY)" fest `disabled` mit Tooltip „kein Ethernet-Treiber eingebunden". `IP101GRI`/`esp32-p4-eth` sind nur Pinout-/Katalog-Strings; „Ethernet over USB" ist die **CDC-ECM** des LTE-Modems, kein Kabel-Feature. | Verdikt 1 |
| `WEBRTC` | „Low-Latency-Stream" | **Genuin abwesend.** 0 Treffer für `webrtc`/`peerconnection`/`srtp`/`dtls`. SDP/RTP-Tokens gehören zu RTSP (`rtsp_server.h`). | Verdikt 2 |
| `ONVIF` | „Kamera-Autodiscovery" | **Genuin abwesend.** 0 Treffer für `onvif`/`WS-Discovery`/`3702`/SOAP. README nennt den Dienst ausdrücklich „läuft nicht". | Verdikt 3 |
| `DETECTION` | „Bewegungs-/Objekterkennung" | **Nicht implementiert.** 0 Treffer für `esp-dl`/`tflite`/Motion-Diff. Einziger Bezug: Kommentar `peripheral_registry.h` „später ObjectDetectionService"; keine Klasse existiert. | Verdikt 4 |
| `AUDIO` (als Pipeline) | „Mikrofon/Audiospur im Stream" | **Nur Interface, keine Runtime.** `audio_source.h:11` „Noch KEINE ES8311/I2S-Runtime, keine Pipeline"; Header wird von niemandem inkludiert; keine `i2s_*`/`es8311_*`-Aufrufe. Bleibt als reine DI-Schnittstelle erhalten, ist aber **kein baubares Feature**. | Verdikt 5 |

Nicht als fiktiv behandelt (Gegenprobe): **RTSP** ist real (`rtsp_server.cpp`,
41 KB, echtes RFC-2326/3550/2435/6184-State-Machine) — bleibt im Katalog.

---

## 3. Der reale Modulkatalog

Gruppen: **Basis** (Kern + Kamera-Grundpfad), **Netzwerk**, **VPN/Security**,
**Erweiterungen**. Spalten: Key · Dateien · Ära (S3/P4/infra) · SoC-Bedarf ·
Flash-Gewicht · Heap-Beleg. Die Keys sind die firmware-internen (feingranularen)
`WEIRDOS_FEATURE_*`-Rümpfe; das PC-Werkzeug fasst sie zu gröberen Schaltern
zusammen (siehe §5, Abschnitt „Abbildung").

### 3.0 Kern/Infra — immer im Image (kein Schalter)

| Key | Dateien | Ära | SoC | Flash | Heap-Beleg |
|---|---|---|---|---|---|
| `PLATFORM` | platform.* | infra | any (SoC-`#if`) | high (69 KB const-Tabellen) | Katalog in rodata; SVG in PSRAM/LittleFS |
| `PERIPHERAL_REGISTRY` | peripheral_registry.* | infra | any (P4-Audio-Deskriptoren SoC-`#if`) | med (11 KB) | feste Kapazität, **kein Heap** |
| `USB_PORT_MAP` | usb_ports.* | infra (P4-geboren) | any (SoC-`#if` P4/S3) | low | `g_ports[3]` |
| `NETWORK_REGISTRY` | network_registry.* | infra | any | med (23 KB) | Stack-Arrays (`NET_ATTACH_MAX 16`) |
| `NETWORK_PLATFORM` | network_platform.* | infra | any (lwIP/esp_netif) | low-med | keine |
| `WEIRD_HTTP` | weird_http.* | infra | any | low | reines Interface |
| `WEIRD_HTTP_ESP` | weird_http_esp.* | infra | any (TLS: +mbedTLS) | med (esp_http_server) | OBUF 4 KB PSRAM/Resp; httpd-Stack 16–20 KB **intern** |
| `WEIRD_AUTH` | weird_auth.* | infra | any | low | ein Session-Token, winzig |

Diese acht sind die „HTTP/Console-Skeleton"- und Board-Wahrheit-Schicht. Sie
tragen keinen Feature-`#if`; fällt die **gesamte** darüberliegende Feature-Menge
weg, entfernt `--gc-sections` sie automatisch.

### 3.1 Basis — Kamera-Grundpfad, Web-UI, Modem, WLAN

| Key | Dateien | Ära | SoC | Flash | Heap-Beleg |
|---|---|---|---|---|---|
| `CAMERA` | camera_manager.*, camera_frame.h, camera_device.h, frame_source.h, camera_compat.h | S3 | any (Laufzeit: PSRAM Pflicht) | med (Anker) | keine großen Statics; FB dynamisch (`w*h/5`), 512 KB PSRAM-Reserve |
| `CAMERA_DVP_S3` | esp32s3_camera_device.* | S3 | S3/`esp_camera` (DVP, OV3660) | low-med (zieht esp32-camera-Komponente) | FB in PSRAM; `DVP_PARAMS[]` rodata |
| `CAMERA_MIPI_P4` | esp32p4_camera_device.* | P4 | **P4** (esp_video/V4L2 + HW-JPEG) | high (38 KB) | HW-JPEG-Buffer PSRAM; V4L2 mmap 4 Buffer |
| `CAMERA_STREAM` | camera_stream_service.* | S3 | any | low-med (13 KB) | latest-frame PSRAM-realloc; Capture-Task |
| `CAMERA_HTTP` | camera_server.* | S3 | any (TLS optional) | high (41 KB, bündelt MJPEG+H264+TLS) | per-Client-Buffer PSRAM; HTTP-Stacks in PSRAM erzwungen |
| `WEB_UI` | web_ui.*, web_ui_menu.cpp, ui_overview/setup/system/diag/platform/netmode/wan/lan/stubs.cpp | S3 | any | med (Framework) | code-only |
| `WEB_UI` (Assets) | web_ui_assets.cpp | S3 | any | **high (~124 KB, UNKOMPRIMIERT)** | 3 PROGMEM-rodata-Arrays (`APP_SCRIPT` 114 KB) |
| `MODEM` | ec200a_modem.* | S3 | USB-OTG-Host | high (100 KB, größte Datei) | PPP-DMA-Pools `g_pppTx/Rx[6]` ~18–48 KB **intern** |
| `MODEM_ECM` | ec200a_ecm.* | S3 | USB-Host | med (36 KB) | ECM-DMA-Pools `g_ecmTx/Rx[6]` ~20–51 KB **intern** |
| `MODEM_DATALINK` | modem_datalink.* | P4 | any | low (2,6 KB) | vernachlässigbar |
| `MODEM_SIM` | modem_sim.* | P4 | any (AT) | low (5,9 KB) | file-static Strings |
| `MODEM_CLOCK` | modem_clock.* | P4 | any (Sync: Modem) | low (3,2 KB) | eine static; **Read-Helfer bleiben immer an** |
| `WIFI` | wifi_caps.*, .ino | S3 | Funk (S3; P4 nur via C6, nicht bestückt) | high (WLAN-Stack) | ESP-Hosted-SDIO ~150 KB **intern** (bei P4-Bring-up → Reboot) |
| `CAPTIVE_PORTAL` | .ino | S3 | SoftAP (⊂ WIFI) | low-med | `dnsPacket[512]` + 1 lwIP-UDP-Socket |
| `MDNS` | .ino | S3 | Funk (⊂ WIFI) | low | 1 UDP-Socket |

### 3.2 Netzwerk — Streaming-Wege, Zonen, Diagnose, DynDNS

| Key | Dateien | Ära | SoC | Flash | Heap-Beleg |
|---|---|---|---|---|---|
| `RTSP_SERVER` | rtsp_server.* | P4 | any (MJPEG) / **P4** (/h264-Mount) | high (41 KB) | `s_pkt` 4272 B PSRAM; Worker-Task 16 KB **intern** |
| `H264_ENCODER` | h264_encoder.* | P4 | **P4** (`libespressif__esp_h264.a`) | med Quelle / high Lib | NAL-Buffer PSRAM ~4 MB @ FHD |
| `PPA_CONVERTER` | ppa_converter.* | P4 | **P4** (PPA) | low | YUV420 PSRAM ~3 MB @ FHD; fail-closed |
| `H264_FMP4` | h264_fmp4.* | P4 | any (nur mit H.264-Quelle sinnvoll) | med (12 KB) | wachsende PSRAM-Buffer |
| `H264_GUARD` | h264_guard.* | P4 | **P4** (link-time-Override esp_h264) | low | reserviert 56–166 KB **internes** DMA-RAM |
| `ZONES` | zone_planner*.{h,cpp}, zone_runtime.*, zone_commit.*, zone_lwip_hooks.*, ui_zones.cpp | P4 | any, aber **PSRAM Pflicht** + custom-lwIP | high (~90 KB) | alles PSRAM-Heap; self-disable ohne PSRAM |
| `NET_SCAN` | net_scan.* | P4 | L3/L4 any; Funk-Scan S3 | med (46 KB) | `s_hosts`-Vector; 5 Tasks à 4 KB |
| `DYNDNS` | .ino | S3 | Egress + mbedTLS | med | `dyndnsTask` 16 KB; **hartkodiertes IONOS-Token** (Secret) |
| `EGRESS_POLICY` | egress_policy.* | P4 | any | low (1,3 KB) | keine |
| `WAN_POLICY` | wan_policy.* | P4 | any (NVS) | low (2,7 KB) | ein static |
| `WAN_SERVICE` | wan_service.* | P4 | any (Socket-Probe) | low (5,6 KB) | `wancheck`-Task 6 KB |
| `ACCESS_POLICY` | access_policy.* | P4 | any | low (2,8 KB) | `kServices[3]` rodata |
| `NETWORK_MODE` | network_mode.* | P4 | any (Phase-1: no-op) | low (5 KB) | eine Config-Instanz |

### 3.3 VPN/Security

| Key | Dateien | Ära | SoC | Flash | Heap-Beleg |
|---|---|---|---|---|---|
| `WIREGUARD` | wireguard_service.*, src/WireGuard/** | S3 | any (Software-Crypto) | med-high (wireguard.c 41 KB + if 36 KB + Service 27 KB) | `peers[8]`; Connect-Task 16 KB; **kein PSRAM** |
| `IPSEC` | ipsec_service.*, ipsec_runtime.*, ipsec_crypto_caps.*, ipsec_config_fields.*, ipsec_trust_store.*, src/weirdike/** | P4 | **PSRAM (P4)**; mbedTLS; SOCK_RAW + UDP/4500 | high (weirdike.c 153 KB + runtime 79 KB) | `s_rx/raw/pt` 4800 B **intern**; PSRAM-Workspace + ESP-RX-Scratch; loop-Stack 24 KB |
| `IPSEC_AES` | aes_engine.*, aes_soft.* | P4 | HW-Block (S3/P4) / soft | low-med | Bench-Statics 4,85 KB; ⊂ IPSEC |
| `VPN_STATUS` | vpn_status.* | P4 | any | low | keine; Schalter = OR(WIREGUARD, IPSEC) |
| `ACME` | acme_client.* | P4 | any (Uhr + Port 80 erreichbar) | med (23 KB) | `acme`-Task 20 KB (transient) |
| `CERT_STORE` | cert_store.* | P4 | mbedTLS x509 | med (8 KB) | Strings; Hub für Self-Signed/Upload/ACME |
| `TLS_SELFSIGNED` | tls_selfsigned.* | P4 | mbedTLS (ECC P-256) | low (3,9 KB) | Stack; **zweiter Konsument camera_server (HTTPS-MJPEG)** |

### 3.4 Erweiterungen

| Key | Dateien | Ära | SoC | Flash | Heap-Beleg |
|---|---|---|---|---|---|
| `USB_DEVICE_UVC` | usb_device_service.*, tinyusb_class_stubs.c, usb_uvc_testimage.h | P4 | USB-OTG-Device + TinyUSB | med | **~48 KB STATISCHES internes RAM** sobald `usbd.c` gelinkt wird (Kernbefund) |
| `BLE_SCAN` | bt_scan.* | P4 (Ära) | **S3** BLE-Funk (`SOC_BLE_SUPPORTED`) | high (NimBLE-Lib) | NimBLE-Stack ~zig KB intern; 2 Tasks à 8 KB; heapmin fiel auf ~2,7 KB |
| `OTA` | .ino (`Update.h`) | S3 | OTA-Partition (Huge-APP) | low (Lib), aber verdoppelt App-Budget | streaming, keine großen Statics |
| `SETTINGS_BACKUP` | settings_backup.* | P4 | any (NVS) | low (4,8 KB) | transient; Secret-Denylist |
| `SETUP_GUARD` | setup_guard.* | P4 | GPIO0 + SoftAP | low (2,1 KB) | eine Config; gate für SERIAL_CONSOLE |
| `SERIAL_CONSOLE` | serial_console.* | P4 | any (USB-CDC/UART) | high (85 KB) | `s_line[1024]`; **einziger Kontrollpfad auf funklosem P4** |
| `LOGO_BANNER` | logo_banner.* | P4 | any | high (29 KB PNG-rodata) | rodata; größte trivial droppbare Konstante |
| `AUDIO` (nur Interface) | audio_source.h (+ Deskriptoren in peripheral_registry) | P4 | P4 ES8311/I2S | low (header-only) | **keine Runtime** — kein baubares Feature, nur DI-Naht |

---

## 4. Kern vs. optional

Die frühere These „WiFi + Camera + Modem + WebUI = schlanke Basis, alles andere
optional" ist durch die Belege widerlegt (adversariales Verdikt 6, `holds=false`)
und wird hier korrigiert:

1. **WiFi ist nicht schlank und nicht Kern.** Wo es läuft, zieht es den
   ESP-Hosted-SDIO-Transport mit ~150 KB internem Heap-Bedarf und ist bereits
   Auto/On/Off-schaltbar (`wifi_caps`). Auf P4 ist es funktional tot.
2. **Die größten Flash-Posten liegen in der angeblichen Basis:**
   `logo_banner.cpp` 148 KB Quelle / 29 KB rodata, `web_ui_assets.cpp` 127 KB
   (**unkomprimiert** — kein gzip/Content-Encoding firmwareweit), `ec200a_modem.cpp`
   100 KB. Diese übertreffen den gesamten VPN/Zonen-Code.
3. **Der dokumentierte Heap-Druck** ist BLE (`problems.md`: heapmin ~2,7 KB) plus
   Kamera+WireGuard-Gleichzeitigkeit — nicht der VPN-Stack allein.
4. **Kamera ist ein schwerer PSRAM-Verbraucher**, nicht „leichte Basis".

Daraus folgt die reale Trennung:

- **Immer im Image (Kern/Infra):** die acht Module aus §3.0. Sie sind die
  Board-Wahrheit, das HTTP-/Auth-Skeleton und die Netz-Registry, gegen die alle
  Features programmieren.
- **Alles andere ist ein Feature hinter einem Schalter** — einschließlich
  CAMERA, WEB_UI, MODEM und WIFI. Es gibt keinen unantastbaren „lean base"
  jenseits der Infra.
- **Standard-Sätze statt Zwang** (siehe §6): auf dem S3 ein sinnvoller
  Feldgerät-Satz, auf dem funklosen P4 ein anderer (WLAN/BT/mDNS/Captive aus,
  H.264/Zonen/UVC an, SERIAL_CONSOLE als Kontrollpfad **ein**).

Faktisch schwer und damit vorrangige Schalter: `WEB_UI` (Assets), `LOGO_BANNER`,
`MODEM`/`MODEM_ECM` (internes DMA-RAM), `BLE_SCAN` (NimBLE, S3-Heap), `H264*`
(56–166 KB internes DMA + MB-PSRAM), `IPSEC`/`WEIRDIKE` (153 KB Flash), `ZONES`
(~90 KB), `USB_DEVICE_UVC` (~48 KB statisches internes RAM), `SERIAL_CONSOLE`
(85 KB).

---

## 5. Der Mechanismus

### 5.1 Bausteine, die schon da sind (Dependency Inversion)

WeirdOS trägt die DI-Nähte bereits; die Dekomposition macht sie nur zu
Compile-Schaltern:

- **Kamera:** `FrameSource` + `CameraDevice` (abstrakte Typen). Der Rest der App
  (Stream, RTSP, UVC, AI) sieht nie `esp_camera`/V4L2. Backend-Wahl heute schon
  per `#if CONFIG_IDF_TARGET_ESP32P4` in `camera_manager.*`.
- **HTTP:** `WeirdHttpServer/Request/Response` (drei pure-virtual Interfaces);
  der Composition Root wählt den Transport (`WeirdHttpEsp`) ohne die ~20 Renderer
  anzufassen.
- **Modem-Datalink:** `modemLinkConnect/…` als eine `ppp|ecm`-Weiche; Beobachter
  per Funktionszeiger (`ModemPppListener`).
- **Netz:** opaque `void* nativeNetif()` — lwIP leckt nicht zu den Konsumenten.
- **Audio:** `AudioSource/AudioSink` (nur Interface, keine Runtime).

### 5.2 Composition-Root-`#if` + Factory + Registry

Regel (Kommentar-Vorbild `#if WEIRDOS_HAS_BT` in `.ino:2791`, `ui_bluetooth.cpp:10`):
Der Composition Root (`WeirdOS.ino` / `esp32-modem-host.ino`) referenziert die
**Factory/Global** einer Komponente **nur unter ihrem `#if`**. Ohne Referenz
wirft der Linker (`-ffunction-sections`/`-fdata-sections` + `--gc-sections`, in
ESP-IDF Vorgabe) die Übersetzungseinheit samt globaler Puffer und Konstruktoren
heraus — genau das spart auf dem S3 das statische RAM.

Zwei Fälle beim Weglassen:

1. **Reines Weglassen der Referenz reicht** (Global mit Konstruktor + `--gc-sections`):
   der Linker zieht die TU nicht. So bei `wireguard_service`, `ipsec_service`,
   `rtsp_server`, `net_scan`, `settings_backup`, `logo_banner`.
2. **TU muss aus dem Build genommen werden**, weil Arduino/PlatformIO jede
   Sketch-`.cpp` kompiliert: dann `#if WEIRDOS_FEATURE_<KEY>` um den **ganzen
   .cpp-Rumpf** oder `build_src_filter`/`src/CMakeLists.txt`-Ausschluss. So bei
   `zone_*.cpp`, `wan_service.cpp`, `network_mode.cpp`, den `weirdike/*.c`.

Stubs, damit querliegende Konsumenten linken (wichtig!): `btBusy()->false`
(net_scan ↔ bt_scan), `netReconBusy()->false` (bt_scan ↔ net_scan),
`modemClockSync()->false` bei `MODEM` aus (Read-Helfer bleiben an),
`setupUartEnabled()->true` bei `SETUP_GUARD` aus (SERIAL_CONSOLE-Gate),
`usbEnumerateDevices()`-Stub bei `MODEM` aus (wifi_caps-Konsument).

### 5.3 `weirdos_features.h` und `-Wundef`

Denselben Satz gibt es auf zwei Wegen: als `-DWEIRDOS_FEATURE_<KEY>=0/1` beim
Bauen **und** als generierte `weirdos_features.h` im Projektordner, damit derselbe
Sketch auch in der Arduino-IDE ohne das Werkzeug baut. **Jede** Komponente bekommt
ein Define, auch die abgeschalteten (`=0`): ein fehlendes Makro wäre im Quellcode
nicht von einem Tippfehler zu unterscheiden. Mit `-Wundef` fällt genau das auf —
`#if WEIRDOS_FEATURE_TIPPFEHLER` warnt statt still zu 0 zu werden. Nicht
unterstützte Kombinationen (z.B. `WIFI` auf P4) sind hart `0`.

### 5.4 Abbildung PC-Werkzeug (grob) → Firmware (fein)

Das Cam-Tool bietet 17 grobe, benutzerfreundliche Schalter; jeder ist ein
Schirm über die feinen Firmware-Keys aus §3:

| Tool-Key | Firmware-Keys (Schirm) |
|---|---|
| `CAMERA` | CAMERA (+DVP_S3/MIPI_P4), CAMERA_STREAM, CAMERA_HTTP, camera_compat |
| `WEBUI` | WEB_UI (+assets/menu/ui_*) |
| `WIFI` | WIFI, CAPTIVE_PORTAL, MDNS, ui_wlan |
| `RTSP` | RTSP_SERVER |
| `H264` | H264_ENCODER, PPA_CONVERTER, H264_FMP4, H264_GUARD |
| `ZONES` | ZONES (planner/adapter/runtime/commit/hooks/ui_zones) |
| `NETSCAN` | NET_SCAN, ui_netscan |
| `DYNDNS` | DYNDNS |
| `WIREGUARD` | WIREGUARD (+VPN_STATUS-Zweig) |
| `IPSEC` | IPSEC (+IPSEC_AES, +VPN_STATUS-Zweig) |
| `TLS_ACME` | ACME, CERT_STORE, TLS_SELFSIGNED |
| `USB_HOST` | USB-OTG-Host-Fundament (usb_host_install; Basis für MODEM/USB_DEVICE) |
| `MODEM` | MODEM, MODEM_ECM, MODEM_DATALINK, MODEM_SIM, MODEM_CLOCK |
| `USB_DEVICE` | USB_DEVICE_UVC (+stubs, +testpattern) |
| `BLUETOOTH` | BLE_SCAN, ui_bluetooth |
| `OTA` | OTA |
| `BACKUP` | SETTINGS_BACKUP |

---

## 6. Umsetzungsreihenfolge (leicht → schwer)

Die Reihenfolge (Details in §5) beginnt bei den
Modulen mit sauberer DI-Naht und wenigen, klar lokalisierten Referenzen.

1. **CAMERA** — ein Include-Block + `initializeCamera()`/`tryCameraInit()` +
   `/capture`-Route; die `FrameSource`/`CameraDevice`-Naht macht es zum
   Musterfall.
2. **WIFI** — Radio-Bring-up im `setup()` kollabiert auf `startBareNetStack()`;
   `WiFiClientSecure.h` **nicht** droppen (DynDNS-über-LTE). CAPTIVE_PORTAL und
   MDNS als geschachtelte Sub-Schalter.
3. **USB_HOST / MODEM** — `startUsbHost()` + Listener + `loadModemPrefs()`;
   MODEM_ECM/DATALINK/SIM als Sub-Schalter; MODEM_CLOCK **splitten** (Read-Helfer
   bleiben).
4. **WEBUI** — Master-Schalter über alle `render*`/`kUiPages`/Asset-Routen;
   SERIAL_CONSOLE als Alternativ-Kontrollpfad behalten.
5. **RTSP**, **OTA**, **DYNDNS**, **BACKUP**, **NETSCAN**, **BLUETOOTH** —
   je ein Include + wenige Routen; BLE nutzt bereits `WEIRDOS_HAS_BT` als Vorbild.
6. **H264** (Split von `camera_server.cpp`: MJPEG bleibt bei CAMERA_HTTP, die
   `/video.mp4`-Route + `ppa/h264_*`-Includes wandern unter H264), **ZONES**
   (ein Schalter über sechs `.cpp` + custom-lwIP-Objekt), **WIREGUARD**,
   **IPSEC** (+AES, +VPN_STATUS als OR-Gate), **TLS_ACME** (Hub `cert_store`,
   Self-Signed bleibt für Kamera-HTTPS), **USB_DEVICE** (schon `WEIRDOS_USB_DEVICE`,
   nur umbenennen/erweitern) — die schweren, querverdrahteten Fälle zuletzt.

Nach jedem Schritt: Build mit dem Schalter `=0` **und** `=1` (beide Targets),
`-Wundef` grün, und ein PPP-only- bzw. WLAN-los-P4-Build als Regressionsprobe.
