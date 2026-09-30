# WeirdOS — Bausteine (Module) und ihr Schnitt

Dies ist die Wahrheit über den Modulschnitt von WeirdOS. `DECOMPOSITION.md`
beschreibt, **was der Code heute ist** (Inventar, Gewichte, Belege). Diese Datei
beschreibt, **wie er geschnitten wird und warum** — getrieben von echten
Einsatzzwecken, nicht von der Dateistruktur. Maschinenlesbar: `modules.json`
(dieselbe Quelle für Firmware und Cam-Tool).

## 1. Warum Lego und nicht Vollausbau

Alle Features zusammen passen **nie** auf das Gerät. Auf dem S3 scheitert es am
Flash und am statischen RAM, auf dem P4 passt es eher in den Flash, scheitert
dann aber am Heap (internes DMA-RAM für USB-Host/PPP/Krypto). Belegt im Code:
der TinyUSB-Device-Stack nimmt ~48 KB statisches internes RAM, sobald er nur
gelinkt ist; die Zonen-Runtime musste komplett ins PSRAM; H.264 braucht bis
166 KB internes DMA-RAM.

Deshalb ist die Einheit nicht „Feature an/aus zur Laufzeit", sondern **Baustein
im Image oder nicht**. Ein Baustein, der nicht referenziert wird, fliegt beim
Linken samt seiner globalen Puffer heraus.

## 2. Einsatzzwecke, die den Schnitt bestimmen

| Einsatz | Was gebraucht wird | Was NICHT gebraucht wird |
|---|---|---|
| **USB-Webcam** am PC | CAMERA, USB_DEVICE, UVC | kein IP-Stack, kein WLAN, kein Modem |
| **RTSP-Kamera über WLAN** | CAMERA, RTSP, NET, WIFI, (HTTP+WEBUI zum Einrichten) | Modem, VPN, Zonen |
| **RTSP-Kamera über LTE** | CAMERA, RTSP, NET, USB_HOST, MODEM, (CONSOLE oder WEBUI) | WLAN, VPN, Zonen |
| **Überwachungskamera LTE im IPsec-Tunnel** (die Standardrolle; Profile `surveillance-lte-ipsec` und `…-headless`) | CAMERA, RTSP, H264 (P4), NET, USB_HOST, MODEM, IPSEC, CRYPTO_AES, dazu HTTP+WEBUI+OTA+BACKUP — oder als Rückfall nur CONSOLE (Einrichtung: `apn`, `wan`, `ipsec set`/`save`, `camera rtsp`) | WLAN, WireGuard, Zonen, DynDNS, ACME, HTTPS |
| **Reiner VPN-Gateway** (kein Bild) | NET, Uplink (WIFI \| MODEM), WIREGUARD \| IPSEC, ROUTER, Downlink (WIFI-AP \| USB_NCM), HTTP, WEBUI | Kamera, Video |
| **USB-Tethering** (Internet vom Modem an den PC) | NET, USB_HOST, MODEM, USB_DEVICE, USB_NCM, ROUTER | Kamera, WLAN, VPN — **nur P4** (zwei USB) |
| **WLAN-Hotspot** (Modem → WLAN) | NET, USB_HOST, MODEM, WIFI, ROUTER | Kamera, VPN — **nur mit Funk** (nicht P4) |
| **Türklingel / Gegensprechen** | CAMERA, VIDEO_HTTP \| RTSP, NET, Uplink, DETECTION*, ACTUATOR*, AUDIO* | Zonen, IPsec |
| **Entwickler-Vollausbau** | alles, was der SoC kann | — (mit Heap-Warnung) |

\* geplant, Slot definiert, noch keine Implementierung.

Der Schnitt fällt daraus fast von selbst: **Netzwerk ist kein Kern** (die Webcam
hat keins), **Kamera ist kein Kern** (der Gateway hat keine), **Bedienung ist
kein Kern** (ein vorkonfiguriertes Gerät läuft headless).

## 3. Der Kern — bewusst winzig

Immer im Image, ohne Schalter:

| Baustein | Dateien | Warum unverzichtbar |
|---|---|---|
| Composition Root | `weirdos-esp32.ino` (setup/loop) | verdrahtet alles |
| Board-Wahrheit | `platform.*`, `usb_ports.*` | welcher Chip, welche Buchse |
| Geräte-Registry | `peripheral_registry.*` | String → Instanz (die Fabrik), feste Kapazität, kein Heap |
| Konfiguration | NVS/Preferences, `setup_guard.*` (Werksreset) | ohne Config kein Betrieb |
| HTTP-Interfaces | `weird_http.h` (nur Header, pure virtual) | kostet nichts, hält Konsumenten vom Transport fern |
| Log | `Serial` + RAM-Log | Diagnose immer |

Alles andere ist ein Baustein hinter `WEIRDOS_FEATURE_<KEY>`.

## 4. Die Bausteine

Status: **wired** = Schalter wirkt im Code · **declared** = Schalter existiert,
Code noch nicht dahinter gezogen (Vorgabe 1 = wie bisher) · **planned** = Slot
ohne Implementierung (Vorgabe 0).

### 4.1 Hardware / Transport

| Key | Baustein | Braucht | SoC | Status |
|---|---|---|---|---|
| `CAMERA` | Sensor + `FrameSource`-Pfad (DVP auf S3, MIPI auf P4) + Einzelbild `/capture` | PSRAM (Laufzeit) | nicht C3/C6 | **wired** |
| `USB_HOST` | USB-OTG-Host (Fundament für MODEM) | — | S2/S3/P4 | **wired** |
| `USB_DEVICE` | TinyUSB-Device-Stack (**~48 KB statisch**) | — | S2/S3/P4 | **wired** (bisher `WEIRDOS_USB_DEVICE`) |
| `WIFI` | STA + AP + Captive-Portal + mDNS | NET | Funk (nicht P4) | **wired** |
| `BLE` | BLE-Scan/Kopplung (NimBLE) | — | BLE-Funk (nicht S2/P4) | **wired** (bisher `WEIRDOS_HAS_BT`) |

### 4.2 Netz

| Key | Baustein | Braucht | Status |
|---|---|---|---|
| `NET` | IP-Stack, `network_registry`, Egress-/WAN-Policy | — | **wired** |
| `MODEM` | EC200A: USB, AT, PPP/ECM-Datenpfad, SIM, Netzzeit | USB_HOST, NET | **wired** |
| `USB_NCM` | ESP als USB-Netzwerkadapter am PC (CDC-NCM, `usb_net_service`: 192.168.7.1 + DHCP). Weboberfläche/OTA über USB; Tethering-Routing (Zonen) noch offen. S3-EP-Budget: Video + NCM verdrängen die CDC-Konsole | USB_DEVICE, NET | **wired** (Laufzeit ungeprüft) |
| `ROUTER` | Netzzonen: Forwarding, NAT, Policies, lwIP-Hooks | NET, **PSRAM** | **wired** |
| `WIREGUARD` | WireGuard Server/Client (eigene Krypto vendored) | NET | **wired** |
| `IPSEC` | IKEv2/IPsec-Client (WeirdIKE) | NET, CRYPTO_AES, **PSRAM** | **wired** |
| `DYNDNS` | DynDNS-Updater | NET, TLS_CLIENT | **wired** |
| `NETSCAN` | Ping/Portscan/Sniff/Kanalscan | NET | **wired** |

### 4.3 Video-Ausgang (alle brauchen `CAMERA`)

| Key | Baustein | Braucht zusätzlich | Status |
|---|---|---|---|
| `VIDEO_HTTP` | MJPEG-Streamserver (Port 81) + `/video.mp4`. Das Einzelbild `/capture` gehört zu CAMERA (+HTTP), damit auch ein RTSP-only-Gerät Snapshots liefert | HTTP | **wired** |
| `RTSP` | RTSP/RTP-Server (MJPEG; H.264-Mount mit H264) | NET | **wired** |
| `H264` | HW-Encoder + PPA + fMP4 + interne RAM-Reserve (die Boot-Reserve entfällt damit auch auf dem S3, der keinen Encoder hat) | P4 | **wired** |
| `UVC` | Webcam am PC — MJPEG über **Bulk** aus der eigenen TinyUSB-Videoklasse `uvc_video_device.c` (die Klasse der Core-Lib sendet auf dem S3 64-Byte-ISO-Payloads: ~62 KB/s, zerrissene Bilder) | USB_DEVICE | **wired** (Kamera per Vorgabe, Testbild wählbar) |

### 4.4 Bedienung / Verwaltung

| Key | Baustein | Braucht | Status |
|---|---|---|---|
| `HTTP` | HTTP-Server-Transport (`weird_http_esp`) + Auth | NET | **wired** |
| `WEBUI` | Weboberfläche (Seiten + Assets) | HTTP | **wired** |
| `CONSOLE` | serielle Konsole (Kontrollpfad ohne Netz) | — | **wired** |
| `OTA` | Firmware-Update per Web | HTTP | **wired** |
| `BACKUP` | NVS-Sicherung Export/Import | — | **wired** |
| `TLS_SERVER` | HTTPS + Self-Signed + Zertifikatsspeicher | HTTP | **wired** |
| `TLS_CLIENT` | HTTPS-Client | NET | **wired** |
| `ACME` | Let's-Encrypt-Client | TLS_SERVER, TLS_CLIENT | **wired** |
| `CRYPTO_AES` | eigener AES-Treiber (Zulieferer für IPSEC) | — | **wired** |

### 4.5 Zukunfts-Slots

| Key | Baustein | Braucht | Status |
|---|---|---|---|
| `DETECTION` | Muster-/Objekterkennung → Ereignisse | CAMERA | planned |
| `AUDIO` | Mikrofon/Lautsprecher (Gegensprechen) | — | planned (`audio_source.h` = Naht) |
| `ACTUATOR` | GPIO-Aktor (Türöffner, Klingeltaster) | — | planned |

## 5. Regeln (in `weirdos_module_rules.h` erzwungen)

- **SoC-Grenze** → still 0: WIFI auf P4, BLE auf S2/P4, USB_* ohne OTG, H264
  außerhalb P4, CAMERA auf C3/C6.
- **Harte Pflicht** → `#error`: MODEM⇒USB_HOST · UVC/USB_NCM⇒USB_DEVICE ·
  jeder Video-Ausgang⇒CAMERA · jeder Netz-Baustein⇒NET · WEBUI/VIDEO_HTTP/OTA/
  TLS_SERVER⇒HTTP · ACME⇒TLS_SERVER+TLS_CLIENT · DYNDNS⇒TLS_CLIENT ·
  IPSEC⇒CRYPTO_AES · ROUTER/IPSEC⇒PSRAM.
- **Laufzeit-Konflikt (kein Build-Fehler):** auf dem S3 teilen sich USB_HOST und
  USB_DEVICE **einen** Port — es läuft nur eines (PC-Erkennung entscheidet). Auf
  dem P4 beides (zwei USB). Darum ist USB-Tethering **P4-only**.
- **Warnung, kein Fehler:** kein Kontrollpfad (weder WEBUI noch CONSOLE) — erlaubt
  für vorkonfigurierte Geräte.

## 6. Der Mechanismus

1. **Ein Schalterkasten:** `weirdos_features.h` — jeder Key genau einmal, 0 oder 1,
   Vorgabe = Vollausbau (soweit der SoC es kann). Das Tool übersteuert per `-D`.
2. **Regeln:** `weirdos_module_rules.h` (bindet den Schalterkasten ein; der
   Composition Root bindet nur diese Datei).
3. **Gating einer Übersetzungseinheit:** die `.cpp` eines Bausteins hat die Form
   ```cpp
   #include "weirdos_features.h"
   #include "mein_modul.h"          // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
   #if WEIRDOS_FEATURE_<KEY>
   ... echte Implementierung ...
   #else
   ... Stub: dieselben Symbole, triviale Koerper, "nicht im Build enthalten" ...
   #endif
   ```
   Der Stub ist Pflicht, weil Querkonsumenten (Konsole, Registry, UI-Seiten)
   die Symbole referenzieren. Er ist winzig und hält den Linker zufrieden.
4. **Composition Root:** referenziert `begin()/poll()/Routen` eines Bausteins nur
   unter `#if WEIRDOS_FEATURE_<KEY>`.
5. **Vendored C** (`src/WireGuard`, `src/weirdike`) wird NICHT gegated: ohne
   Referenz aus dem gegateten Service wirft `--gc-sections` es heraus.
6. **Reine Logik ohne Hardware** (`zone_planner.cpp`, `zone_commit.cpp`) bleibt
   ungegated — sie ist host-testbar (CI-Selftest) und wird nur von der gegateten
   Runtime referenziert.
7. **UI-Seiten bleiben** und zeigen „nicht im Build enthalten" (Muster
   `ui_bluetooth.cpp`): billig, und der Nutzer sieht, was ihm fehlt. Ohne IDs, deren
   Routen im Build fehlen — dann bindet auch das JS nichts an (`ui_zones`, `ui_netscan`,
   `ui_internet` Mobilfunk, `ui_system` Zertifikat/Sicherung/Update, `ui_diag`).
8. **CI beweist den Schnitt:** ein `lean`-Build mit den schweren Bausteinen auf 0
   muss linken. Fällt er, ist ein Stub unvollständig.

## 7. Reihenfolge

1. ✅ Mechanismus + RTSP, ROUTER, WIREGUARD, IPSEC (+ BLE/USB_DEVICE übernommen).
2. ✅ CAMERA, VIDEO_HTTP, H264, UVC — der Bildpfad (Naht `FrameSource`/`CameraDevice`).
3. ✅ USB_HOST, MODEM — der Uplink (`startUsbHost()` ist der Start des USB_HOST-Bausteins;
   Systemuhr-Helfer und `ecmDefaultRouteIp()` bleiben in jedem Build).
4. ✅ WIFI (P4-Pfad auf jedem SoC: `Network.h` statt `WiFi.h` für DynDNS/ACME/IPsec),
   NET als eigenständiges Fundament (die Webcam ohne IP-Stack: kein tcpip-Unterbau,
   kein `NetworkManager`).
5. ✅ HTTP (kein `g_web`, kein `startWebServer()` → Server, Auth, Handler und Seiten
   fallen per gc-sections), WEBUI (Seitengerüst, Menü, Renderer, App-Assets; PIN-Gate
   und JSON-API bleiben), CONSOLE (Baudrate bleibt), OTA, BACKUP, TLS_SERVER (auch
   HTTPS-Zweig in `weird_http_esp`/`camera_server`), TLS_CLIENT, ACME, DYNDNS
   (Konfig-Globals und Egress-Helfer bleiben), NETSCAN, CRYPTO_AES.
6. Offen: USB_NCM implementieren (Tethering/Netzwerkadapter), dann die Zukunfts-Slots
   DETECTION/AUDIO/ACTUATOR. Jeder Baustein des Manifests ist damit **wired**; jeder
   Schnitt hat einen eigenen CI-Job (§8).

Was sich beim Verdrahten als Regel bewährt hat:

- **Ein globaler Konstruktor hält eine ganze Bibliothek fest.** `WiFiClass WiFi`,
  `NetworkManager Network`, `WeirdHttpEsp g_web` — jedes dieser Objekte zieht seine
  Bibliothek samt IDF-Komponenten ins Bild, selbst wenn kein Code es benutzt. Deshalb
  werden nicht nur Aufrufe, sondern die **Includes und Instanzen** gegated.
- **Konfig bleibt, Verhalten geht.** Globals wie `dyndnsDomain`, Baudrate, Betriebsart-
  Namen bleiben in jedem Build: andere Bausteine lesen sie (Zertifikat-CN, UART-Seite),
  und ein späterer Build mit dem Baustein findet seine NVS-Werte wieder.
- **Handler dürfen kompiliert bleiben.** Freie Funktionen der `.ino` ohne Referenz
  wirft `--gc-sections` heraus; gegated werden die **Routen** (die Referenz), nicht
  jeder Handler. Nur Blöcke mit eigenem Zustand (Tasks, RTC-Zähler, Observer) werden
  ganz gegated.
- **Pure Zuordnungen vor den Schalter** (`modeId()`, `systemClockIso()`,
  `serialConsoleBaud()`): einmal definiert, kein Stub-Duplikat, das auseinanderläuft.

## 8. Messungen (CI, esp32-Core 3.3.11, Stand Lauf 15 = Commit f4bb677; webcam-only aus Lauf 18 = c0505d7; Webcam-Zeilen aus Lauf 30 = e052cdc: Bulk-UVC, Sensor-Modi, UAC2-Mikrofon; Standardrolle aus Lauf 33 = dfe330e)

Was der Schnitt auf dem Gerät tatsächlich spart. „statisches RAM" = globale
Variablen (`.data`+`.bss`), also das, was dem Heap fehlt, bevor irgendetwas läuft.
Jede Zeile ist ein CI-Job in `.github/workflows/build.yml`; fällt einer, ist ein
Stub unvollständig oder ein Baustein leckt in einen anderen.

### XIAO ESP32-S3 (8 MB, `default_8MB`: App-Partition 3 342 336 B)

| Build | Schalter auf 0 | Flash | statisches RAM |
|---|---|---|---|
| S3 full (Stand vor dem Schnitt) | — | 2 670 859 B (79 %) | 102 408 B |
| **S3 full** | — (H264 ist auf dem S3 immer 0) | 2 662 058 B (79 %) | 102 364 B |
| S3 api-only | WEBUI | 2 341 118 B (70 %) | 102 356 B |
| S3 no-modem | MODEM, USB_HOST | 2 494 934 B (74 %) | 99 084 B |
| S3 no-camera (Netzwerkadapter) | CAMERA, VIDEO_HTTP, RTSP | 2 544 738 B (76 %) | 90 792 B |
| S3 lean | WIREGUARD, IPSEC, ROUTER, RTSP | 2 408 994 B (72 %) | 84 476 B |
| S3 no-wifi (P4-Pfad) | WIFI | 2 271 842 B (67 %) | 81 008 B |
| S3 slim-control | TLS_SERVER, ACME, TLS_CLIENT, DYNDNS, OTA, CONSOLE, NETSCAN, BACKUP, CRYPTO_AES, IPSEC | 2 138 558 B (63 %) | 79 884 B |
| S3 headless | HTTP, WEBUI, VIDEO_HTTP, OTA, TLS_SERVER, ACME | 1 734 058 B (51 %) | 96 936 B |
| S3 webcam (USB-OTG) | MODEM, USB_HOST; **USB_DEVICE + UVC auf 1** | 2 539 398 B (75 %) | 104 372 B |
| S3 webcam+mic (UVC + UAC2) | wie webcam; **zusätzlich AUDIO auf 1** | 2 560 098 B (76 %) | 111 244 B |
| S3 webcam-only | alles außer CAMERA, USB_DEVICE, UVC (auch NET) | **492 175 B (14 %)** | 50 808 B |
| **S3 Standardrolle** `surveillance-lte-ipsec` | Profil aus modules.json: CAMERA, NET, USB_HOST, MODEM, RTSP, IPSEC, CRYPTO_AES, HTTP, WEBUI, CONSOLE, OTA, BACKUP an, alles andere 0 (H264 auf dem S3 immer 0) | 1 697 071 B (50 %) | 72 840 B |
| S3 Standardrolle ohne Weboberfläche `…-headless` | wie oben, aber HTTP, WEBUI, OTA, BACKUP auf 0 | 1 145 751 B (34 %) | 71 840 B |

Was die Zeilen sagen:

- **Weboberfläche weg (WEBUI):** −321 KB Flash — der größte Einzelposten der Bedienung
  (App-CSS/JS + alle Seiten). PIN-Gate und JSON-API bleiben.
- **HTTP-Server weg (headless):** −928 KB Flash, mehr als ein Drittel des Images —
  esp_http_server, Auth, alle Handler und Seiten fallen per gc-sections, sobald `g_web`
  fehlt. Das statische RAM sinkt kaum, weil der Server seine Puffer erst zur Laufzeit holt;
  der Heap-Gewinn (Tasks, Sockets, Sitzungen) kommt hier nicht in der Tabelle vor.
- **WLAN weg (no-wifi):** −390 KB Flash, −21 KB statisches RAM — die WiFi-Bibliothek samt
  esp_wifi-Blobs, SoftAP, Captive-Portal, mDNS. Genau der Pfad, den der P4 immer nimmt.
- **Verwaltungs-Extras weg (slim-control):** −524 KB Flash, −22 KB statisches RAM — kein
  HTTPS-Server, kein Let's Encrypt, kein HTTPS-Client, kein DynDNS, kein OTA, keine Konsole,
  keine Netz-Diagnose, keine Sicherung, kein eigener AES.
- **VPN + Zonen + RTSP weg (lean):** −253 KB Flash, −18 KB statisches RAM.
- **Kamera-Pfad weg (no-camera):** −117 KB Flash, −11,6 KB statisches RAM (esp32-camera
  wird nicht mehr gelinkt).
- **Modem weg (no-modem):** −167 KB Flash, −3 KB statisches RAM (EC200A-Treiber, PPP, ECM,
  SIM, USB-Host-Recovery).
- **USB-Webcam (USB_DEVICE + UVC an):** +79 KB Flash und +32 KB statisches RAM gegenüber no-modem — die
  TinyUSB-Puffer, die der Baustein USB_DEVICE deshalb nie per Vorgabe mitbringt. Der Bulk-Transport
  (Lauf 24 gegen Lauf 18) kostet **+4 016 B statisches RAM** und +680 B Flash: der eigene Payload-Puffer
  der Videoklasse (`WEIRDOS_UVC_PAYLOAD_MAX` = 4064 B statt der 64 B der Bibliothek) — der Preis für
  ~1 MB/s statt ~62 KB/s am Full-Speed-Port. Die übrigen elf Zeilen sind in Lauf 24 byte-identisch.
  Lauf 30 (nach den Commits „echte Sensorauflösung", „Auflösung wählbar" und „UAC2-Mikrofon") misst
  die Webcam mit 104 372 B und webcam-only mit 50 808 B statischem RAM; das Mikrofon (AUDIO an) kostet
  auf dem S3 +6 872 B RAM und +20,7 KB Flash, auf dem P4 (ES8311) 2 507 566 B / 83 204 B.
- **Die Standardrolle (RTSP über LTE im IPsec-Tunnel, mit Weboberfläche)** liegt auf dem S3 bei 50 % der
  App-Partition und **72 840 B statischem RAM — 29,5 KB weniger als der Vollausbau**, weil WLAN, BLE,
  WireGuard, Zonen, DynDNS, HTTPS, ACME, Netz-Diagnose und der USB-Gerätestack fehlen. Die Weboberfläche
  selbst kostet in dieser Rolle **551 KB Flash, aber nur 1 000 B statisches RAM** (ihre Puffer entstehen
  zur Laufzeit im Heap). Der Rückfall ohne Weboberfläche ist deshalb vor allem ein Flash-, kein RAM-Gewinn;
  wo der Heap knapp wird, sind eher Kamera-Framebuffer und IPsec-Workspaces (beide im PSRAM) zu prüfen.
  Beide Profile werden in der CI wortwörtlich aus der modules.json gebaut (`ci/profile_flags.py`).
- **IP-Stack weg (webcam-only):** das Profil „USB-Webcam" wortwörtlich — CAMERA, USB_DEVICE,
  UVC und sonst nichts. **527 KB statt 2 573 KB Flash (−80 %), 77 KB statt 131 KB statisches
  RAM** gegenüber der Webcam mit vollem Netz-Unterbau; gegenüber dem Vollausbau fehlen
  2,1 MB. Kein lwIP, kein esp_netif, kein mbedTLS, kein Funk-Blob — genau der Beweis, dass
  der Kern ohne Netz auskommt und NET ein Baustein ist, kein Fundament des Kerns.
- **H264 auf dem S3:** kaum Flash, aber die **Boot-Reserve von ~172 KB internem RAM**
  für einen Encoder, den der S3 nicht hat, entfällt (Heap, nicht statisches RAM).

### ESP32-P4 (Waveshare P4-Pico: 32 MB Flash + 32 MB PSRAM, generisches `esp32p4`-Target, Stock-Core 3.3.11)

Gemessen bis Lauf 18 gegen `app3M_fat9M_16MB` (App-Partition 3 145 728 B); seit Lauf 19
baut die CI wie das Cam-Tool mit `FlashSize=32M,PartitionScheme=app13M_data7M_32MB`
(`default_32MB`: zwei 12,5-MB-App-Slots mit OTA + Datenpartition `spiffs`, App-Partition
13 107 200 B). Die Bytes ändern sich dadurch nicht, nur die Prozente.

| Build | Schalter auf 0 | Flash | in 3-MB-App | in 12,5-MB-App | statisches RAM |
|---|---|---|---|---|---|
| P4 full (vor dem WIFI-Schnitt) | — | 3 058 382 B | 97 % | 23 % | 76 124 B |
| **P4 full** | — (WIFI/BLE sind auf dem P4 immer 0) | 2 635 632 B | 83 % | 20 % | 66 900 B |
| P4 lean | IPSEC, ROUTER | 2 436 056 B | 77 % | 19 % | 50 372 B |
| **P4 Standardrolle** `surveillance-lte-ipsec` | Profil aus modules.json (mit HW-H.264) | 2 329 204 B | 74 % | 17 % | 63 884 B |
| P4 Standardrolle ohne Weboberfläche `…-headless` | wie oben, HTTP/WEBUI/OTA/BACKUP auf 0 | 1 764 406 B | 56 % | 13 % | 62 884 B |

- **Der WIFI-Schnitt allein bringt dem P4 −423 KB Flash und −9 KB statisches RAM:** vorher
  zog `WiFi.h` (globaler `WiFiClass WiFi`) die ganze WiFi-Bibliothek in ein Image für einen
  Chip ohne Funk.
- IPsec + Zonen weglassen: −200 KB Flash, −16,5 KB statisches RAM.
- Mit dem 4-MB-Default des Cores (1,25-MB-App) passt kein P4-Build. Auf dem 32-MB-Board ist
  Flash keine Grenze mehr; der Schnitt zählt dort für den **Heap**, nicht für den Flash.
- Das 16-MB-Schema trägt eine `ffat`-Datenpartition; die Firmware mountet LittleFS auf dem
  Label `spiffs` (eigenes Pinout-SVG). Nur `default_32MB` passt zu beidem.
- Der P4-Heap ist mit dieser Messung noch nicht erfasst (statisches RAM ≠ Heap;
  H264-Encoder, PPA und Kamera-Puffer kommen zur Laufzeit dazu). Deshalb bleibt
  der Schnitt entlang der Profile der Weg, nicht eine größere Partition.
