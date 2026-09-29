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
| `USB_HOST` | USB-OTG-Host (Fundament für MODEM) | — | S2/S3/P4 | declared |
| `USB_DEVICE` | TinyUSB-Device-Stack (**~48 KB statisch**) | — | S2/S3/P4 | **wired** (bisher `WEIRDOS_USB_DEVICE`) |
| `WIFI` | STA + AP + Captive-Portal + mDNS | NET | Funk (nicht P4) | declared |
| `BLE` | BLE-Scan/Kopplung (NimBLE) | — | BLE-Funk (nicht S2/P4) | **wired** (bisher `WEIRDOS_HAS_BT`) |

### 4.2 Netz

| Key | Baustein | Braucht | Status |
|---|---|---|---|
| `NET` | IP-Stack, `network_registry`, Egress-/WAN-Policy | — | declared |
| `MODEM` | EC200A: USB, AT, PPP/ECM-Datenpfad, SIM, Netzzeit | USB_HOST, NET | declared |
| `USB_NCM` | ESP als USB-Netzwerkadapter am PC (Downlink) | USB_DEVICE, NET | **planned** |
| `ROUTER` | Netzzonen: Forwarding, NAT, Policies, lwIP-Hooks | NET, **PSRAM** | **wired** |
| `WIREGUARD` | WireGuard Server/Client (eigene Krypto vendored) | NET | **wired** |
| `IPSEC` | IKEv2/IPsec-Client (WeirdIKE) | NET, CRYPTO_AES, **PSRAM** | **wired** |
| `DYNDNS` | DynDNS-Updater | NET, TLS_CLIENT | declared |
| `NETSCAN` | Ping/Portscan/Sniff/Kanalscan | NET | declared |

### 4.3 Video-Ausgang (alle brauchen `CAMERA`)

| Key | Baustein | Braucht zusätzlich | Status |
|---|---|---|---|
| `VIDEO_HTTP` | MJPEG-Streamserver (Port 81) + `/video.mp4`. Das Einzelbild `/capture` gehört zu CAMERA (+HTTP), damit auch ein RTSP-only-Gerät Snapshots liefert | HTTP | **wired** |
| `RTSP` | RTSP/RTP-Server (MJPEG; H.264-Mount mit H264) | NET | **wired** |
| `H264` | HW-Encoder + PPA + fMP4 + interne RAM-Reserve (die Boot-Reserve entfällt damit auch auf dem S3, der keinen Encoder hat) | P4 | **wired** |
| `UVC` | Webcam am PC | USB_DEVICE | declared (heute: Testbild; echte Kamera folgt) |

### 4.4 Bedienung / Verwaltung

| Key | Baustein | Braucht | Status |
|---|---|---|---|
| `HTTP` | HTTP-Server-Transport (`weird_http_esp`) + Auth | NET | declared |
| `WEBUI` | Weboberfläche (Seiten + Assets) | HTTP | declared |
| `CONSOLE` | serielle Konsole (Kontrollpfad ohne Netz) | — | declared |
| `OTA` | Firmware-Update per Web | HTTP | declared |
| `BACKUP` | NVS-Sicherung Export/Import | — | declared |
| `TLS_SERVER` | HTTPS + Self-Signed + Zertifikatsspeicher | HTTP | declared |
| `TLS_CLIENT` | HTTPS-Client | NET | declared |
| `ACME` | Let's-Encrypt-Client | TLS_SERVER, TLS_CLIENT | declared |
| `CRYPTO_AES` | eigener AES-Treiber (Zulieferer für IPSEC) | — | declared |

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
   `ui_bluetooth.cpp`): billig, und der Nutzer sieht, was ihm fehlt.
8. **CI beweist den Schnitt:** ein `lean`-Build mit den schweren Bausteinen auf 0
   muss linken. Fällt er, ist ein Stub unvollständig.

## 7. Reihenfolge

1. ✅ Mechanismus + RTSP, ROUTER, WIREGUARD, IPSEC (+ BLE/USB_DEVICE übernommen).
2. CAMERA, VIDEO_HTTP, H264, UVC — der Bildpfad (Naht `FrameSource`/`CameraDevice`).
3. USB_HOST, MODEM — der Uplink.
4. WIFI (mit STA/AP-Unterschaltern), NET als eigenständiges Fundament (die
   Webcam ohne IP-Stack).
5. HTTP, WEBUI, CONSOLE, OTA, BACKUP, TLS_*, ACME, DYNDNS, NETSCAN.
6. USB_NCM implementieren (Tethering/Netzwerkadapter), dann die Zukunfts-Slots.
