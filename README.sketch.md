> **Hinweis:** In diesem Repo heißt der Sketch `weirdos-esp32.ino` und liegt im Wurzelverzeichnis. Die Flash-Befehle unten nennen noch den alten Ordnernamen `esp32-modem-host` — ersetze ihn durch `.` (das Repo-Wurzelverzeichnis) bzw. `weirdos-esp32`.
> **Überholt:** Der unten beschriebene BOOT+RESET-Hack ist im Normalfall nicht mehr nötig — WeirdOS erkennt PC vs. Modem am USB und gibt bei angeschlossenem PC den Programmierport frei. Siehe `README.md` → „Bauen & Flashen".

# esp32-modem-host — XIAO ESP32-S3 als USB-Host zum EC200A

Versionierte Kopie des Arbeits-Sketches (Quelle: `~/Documents/Arduino/Homeserver_Autosetup_Modem_V1_USBHost/`).
Basis ist der XIAO-ESP32-S3-Kamera-/WLAN-Webserver; ergänzt um **USB-Host + Modem-Ansteuerung**.

## Was drin ist
- **Internet-Tab** in der Weboberfläche: APN/PDP/Auth/Autoconnect-UI (Persistenz im NVS `modem`),
  Aktionen (Verbinden/Trennen/Test/Reset) voll implementiert, **plus AT-Konsole** und eingebauter **Speedtest**.
- **USB-Host** (rohe `usb_host`-API): enumeriert das Modem `2C7C:6005` durch den aktiven Hub.
- **AT-Kanal** über die CDC-ACM-Bulk-Endpoints (Interface claimen → Bulk-OUT `AT\r` → Bulk-IN lesen).

## Kernpunkt: Arduino-ESP32 3.3.11 USB-Host-Regression (#12778)
Die vorkompilierten Libs setzen `CONFIG_USB_HOST_ENABLE_ENUM_FILTER_CALLBACK=y`. Ohne gesetzten
`usb_host_config_t::enum_filter_cb` **hängt die Enumeration still** (connect erkannt, aber 0 Adressen).
**Fix im Sketch:** `enum_filter_cb` gesetzt (gibt `true` zurück, `*bConfigurationValue = 1`).

## Flashen & Board-Einstellungen (Arduino Studio)
Vollständige Tools-Einstellungen (verifiziert am XIAO ESP32-S3):

| Einstellung | Wert |
|---|---|
| Board | XIAO_ESP32S3 |
| **USB Mode** | **Hardware CDC and JTAG** |
| USB CDC On Boot | Disabled |
| USB DFU On Boot | Disabled |
| USB Firmware MSC On Boot | Disabled |
| **PSRAM** | **OPI PSRAM** |
| Flash Size | 8MB (64Mb) |
| Flash Mode | QIO 80MHz |
| Partition Scheme | Default with spiffs (3MB APP/1.5MB SPIFFS) = `default_8MB` |
| CPU Frequency | 240MHz (WiFi) |
| Upload Mode | UART0 / Hardware CDC |
| Upload Speed | 921600 |
| JTAG Adapter | Disabled |
| Core Debug Level | egal (IDF-Logs sind in den Arduino-Libs eh auf ERROR gedeckelt) |

### Warum Flashen nur mit BOOT+RESET klappt (USB-BOOT-„Hack")
Der XIAO ESP32-S3 hat **nur EINEN** USB-C-Port. Der teilt sich zwischen dem eingebauten
**USB-Serial-JTAG** (Programmieren + automatischer Reset-in-den-Bootloader) und dem
**USB-OTG** (USB-Host = Modem). Sobald der laufende Sketch `usb_host_install()` aufruft,
übernimmt der OTG-Host die PHY / den Port → der Serial-JTAG-COM-Port **verschwindet zur
Laufzeit** → der Auto-Reset über USB funktioniert nicht.
**Wie „Host Mode" aktiviert wird** (zweistufig, kein einzelner IDE-Schalter):
1. **Code:** `startUsbHost()` → `usb_host_install()` (`ec200a_modem.cpp`), aufgerufen in
   `setup()`. Das schnappt sich bei jedem Boot den OTG + die gemeinsame PHY (GPIO19/20).
2. **Voraussetzung = die IDE-Option `USB Mode = "Hardware CDC and JTAG"`** (+ CDC On Boot
   Disabled): hält den OTG-Controller frei (Arduino belegt ihn NICHT als TinyUSB-Device) und
   legt `Serial` auf den separaten USB-Serial-JTAG. Mit `USB Mode = "USB-OTG (TinyUSB)"` würde
   Arduino den OTG schon beim Boot als Device beanspruchen → `usb_host_install()` bekäme ihn nicht.
Der BOOT-Hack kommt also vom **Code** (host grabt die PHY), nicht von der Option — die Option
ist nur nötig, damit Host überhaupt geht. Umstellen entfernt den Hack nicht und bricht den Host.

**Ablauf zum Flashen:** **BOOT gedrückt halten + kurz RESET** → das ROM startet im
Download-Modus, der COM-Port erscheint wieder, Upload läuft; danach RESET/normaler Boot.

**Ist das „zurückstellbar"? Nein** — nicht am S3 und nicht über eine Einstellung (auch nicht
PSRAM). Es liegt am **einen geteilten USB-Port**: Wer USB-Host macht, verliert den
Programmier-Port. Ohne Host-Betrieb (z.B. `USB CDC On Boot = Enabled`, kein `usb_host_install`)
ginge Auto-Upload — aber dann kein Modem. Der PSRAM ist unabhängig davon nötig (Kamera).

### Flashen aus CLion (zukünftig)
CLion hat kein eigenes ESP32-Upload → über die (in Arduino IDE gebündelte) `arduino-cli`:
```
ACLI="C:\Program Files\Arduino IDE\resources\app\lib\backend\resources\arduino-cli.exe"
FQBN="esp32:esp32:XIAO_ESP32S3:USBMode=hwcdc,CDCOnBoot=cdc,PSRAM=opi,FlashSize=8M,PartitionScheme=default_8MB"
"$ACLI" compile --fqbn "$FQBN" "<Sketch-Ordner>"
# Board in den Download-Modus: BOOT halten + RESET, dann:
"$ACLI" upload --fqbn "$FQBN" -p COM4 "<Sketch-Ordner>"      # COM4 = Download-Mode-Port, ggf. anpassen
```
Als CLion **External Tool** hinterlegen (Program = obige arduino-cli, Args = `upload --fqbn … -p $Prompt$ …`).
Der **BOOT+RESET-Schritt bleibt** auf dem S3 nötig (siehe oben).

### ESP32-P4 (Ausblick): kein BOOT-Hack dank Dual-USB
Der P4 hat **zwei** USB: einen dedizierten **USB-Serial-JTAG** *und* **USB-OTG (High-Speed)**.
Damit flasht man **über den JTAG-Port, während das Modem am OTG-Port hängt** → **kein
BOOT+RESET-Hack**. Ob das konkrete P4-Devkit BOOT/RESET-Taster hat, ist boardabhängig —
beim Flashen über den Serial-JTAG braucht man sie nicht.
**TODO Firmware (P4):** weil der P4 zwei USB-Controller hat, soll **per Web-UI wählbar** sein,
an welchem Port/Controller das Modem hängt; der USB-Host-Init wird entsprechend konfiguriert.
(HS-OTG am P4 hebt zudem den Full-Speed-12-Mbit-Deckel des S3 auf.)

## Lokaler Build (schneller Loop) + CI
Die GH-Action war unzuverlässig; **lokal kompilieren** ist schneller und entspricht 1:1 dem geflashten Build.
Arduino IDE 2.x bündelt `arduino-cli`; der esp32-Core 3.3.11 ist installiert.
```
ACLI="C:\Program Files\Arduino IDE\resources\app\lib\backend\resources\arduino-cli.exe"
FQBN="esp32:esp32:XIAO_ESP32S3:USBMode=hwcdc,CDCOnBoot=cdc,PSRAM=opi,FlashSize=8M,PartitionScheme=default_8MB"
"$ACLI" compile --fqbn "$FQBN" "C:\Users\<user>\Documents\Arduino\Homeserver_Autosetup_Modem_V1_USBHost"
```
Erster Lauf baut den Core (~Min.), danach gecacht → Sekunden. Referenz: ~41 % Flash / ~22 % RAM.
**Flashen** macht man weiter manuell aus Arduino Studio (BOOT+RESET). **CI:** `esp32-modem-host-build.yml`
baut denselben Sketch mit `arduino-cli` (grün); der frühere PlatformIO/IDF-Hybrid ist abgelöst.
Der Repo-Ordner `esp32-modem-host/` ist ein **Mirror** des Arduino-Sketches — nach jeder Änderung mitziehen.

## Architektur (Schichten)
- **Treiber** `ec200a_modem.{h,cpp}` — USB-Host, AT-Kanal, PPP-Datenpumpe, Band/RAT, Best-SINR-Scan, Speedtest.
  Kennt Webserver/UI NICHT; Events per Listener an die App. Eigene `Preferences modemNvs`.
- **View** `web_ui*.cpp` (Skin/Assets/Menü) + `ui_*.cpp` (Content je Sidebar-Seite). GOTCHA: `const char[]`-Assets
  haben interne Bindung → `web_ui_assets.cpp` muss `web_ui.h` inkludieren (sonst „undefined reference").
- **Kamera-Schicht** (Refactor, entkoppelt esp_camera): `camera_frame.h` (neutraler `CameraFrame`) →
  `camera_device.h` (Interface) → `esp32s3_camera_device.*` (OV3660/DVP-Wrapper) → `camera_manager.*`
  (Lebenszyklus-Fassade) → `camera_stream_service.*` („ein Frame für alle", HTTP-neutral). Ziel: AI/YOLO +
  spätere P4-MIPI ohne Änderung an Stream/App. Verdrahtung in .ino läuft schrittweise.
- **.ino** — Routing (`server.on`), Auth, DynDNS, Energie, HTTP-Handler.

## Hardware
- XIAO über **5V/GND (Powerbank)** versorgen (USB-C bleibt Host), USB-C → **Upstream** eines **aktiven**
  Hubs, Modem am **Downstream**, Hub-Netzteil an. Der XIAO liefert selbst zu schwaches VBUS fürs Modem
  (LTE-Peaks) — Stromversorgungs-Optionen siehe `reverse-eng/69-esp32-modem-stromversorgung.md`.

## Web-Endpoints (Diagnose/Steuerung)
| Endpoint | Zweck |
|----------|-------|
| Tab „Internet" → Status | USB-Erkennung live (Bus-Ev/Connect-Ev/enum-Adressen) |
| `/modem-usbinfo` | Schnittstellen-/Endpoint-Karte des Modems |
| `/modem-at?if=3&cmd=AT+CPIN?` | AT-Kommando senden (IF3=AT, IF4=Modem, IF2=DIAG) |
| `/modem-info` | Live-Mobilfunkstatus (feste AT-Diagnose, roh) |
| `/modem-json` | strukturierte Mobilfunkdaten (ATI/CGSN/QCCID/CIMI/CPIN/CEREG/CSQ/COPS/QNWINFO/QENG/CGPADDR geparst) |
| `/dyndns-save` (POST) | DynDNS-Einstellungen speichern (NVS `dyndns`) |
| `/dyndns-status.json` | DynDNS-Status (letzte Meldung, gemeldete IP) |
| `/dyndns-update` (POST) | sofortigen DynDNS-Update anstossen („Jetzt aktualisieren") |
| `/energy-save` (POST) | CPU-Profil (setCpuFrequencyMhz, sofort) + WLAN-Fallback-Flag (NVS "energy") |
| `/modem-log` | aufgefangener ESP-IDF-Log (Libs auf ERROR gedeckelt → meist leer) |

## UI (FRITZ!OS-artig)
Saubere Trennung **Sidebar = Seite**, **obere Tabs = Unteransicht innerhalb der Seite**
(`.nav-item` schaltet `.tab-panel`; `.tabs`/`.tab` schalten `.page-sub`, per `.tab-panel` gescoped).

| Sidebar-Seite | obere Tabs |
|---|---|
| Übersicht | – (Status, System: Laufzeit/Heap/PSRAM/CPU/Modem/Kamera, Mobilfunk: Modell/Betreiber/IPs, WAN/Internet + Interfaces, Online-Monitor) |
| WAN → Netzzugang | Zugang waehlen (Automatisch · Mobilfunk · WLAN-Client · Ethernet, capability-gated) + Zustand; Mobilfunk-Tabs: Anschluss · Zugangsdaten (inkl. SIM-PIN-Sperre) · IPv6 · DNS-Server · Frequenzen |
| WAN → Firewall & NAT | – |
| LAN → Allgemein / WLAN | WLAN: Funknetz · Sicherheit |
| IoT → Bluetooth | – (gekoppelte Funk-/Netz-Geraete; ohne BT-Funk ehrlicher Hinweis) |
| Dienste → DynDNS / VPN · Server → VPN / Video | Video: Stream · Bild |
| System → Allgemein/Geraete/Energiemonitor/Sicherheit/Sicherung/Update | Energiemonitor: Energieverbrauch · Einstellungen |
| Diagnose → System / Modem / Netzwerk / Video | System: Ereignisse · Heap-Map; Modem: Mobilfunk · Netzliste · SIM-Karte · Pipeline · Durchsatz · Entwickler; Netzwerk: Rechner · Funk; Video = Livebild |

Naming bewusst **„Mobilfunk"** (LTE Cat-4), nicht „5G". Kamera-`/cam-config` bleibt EIN atomares
Formular (umschließt Bild+Stream, bei Livebild per CSS ausgeblendet). AT-Konsole liegt jetzt unter
**Diagnose → USB/Modem** (nicht mehr prominent auf der Mobilfunkseite). Platzhalter täuschen kein
Backend vor; QENG-Parser + Energiespar-Backend folgen als eigene Slices.

## AT-Kanal — harte Lektionen
- **Interface einmal claimen und behalten** (`g_ifClaimed`): Release+Re-Claim pro Kommando setzt den
  Endpoint-Data-Toggle zurück → nur das erste AT nach dem Boot kommt an, Rest timeoutet.
- **Pending Transfers bei Timeout abbrechen** (`usb_host_endpoint_halt/flush/clear`), sonst bleibt das
  Interface belegt → `interface_claim` liefert danach `ESP_ERR_INVALID_STATE`.
- IN-Puffer 512 B (Transfer endet am Short-Packet). PIN-Cookie: `xcauth=<pin>`.

## Verifizierter Modem-Stand (o2, via ESP32)
`ATI`=EC200A `…R02A07M16` · `+CPIN: READY` · `+CEREG: 0,1` (LTE) · `+CSQ: 28,99` · `+COPS: "o2 - de",7` ·
`+CGACT: 1,1` · `+CGPADDR` = WAN-IP. Hinweis: o2 braucht APN **`netpublic`** für IPv4 (Profil im UI).

### Telekom: Erreichbarkeit von außen → APN `internet.t-d1.de` (nicht IPv6!)
Telekom-Standard-APNs geben nur **CGNAT-IPv4** + eine **eingehend gefilterte IPv6** → von außen
nicht erreichbar. Das Gegenstück zu o2 `netpublic` ist **`internet.t-d1.de`** (PDP-Typ **`IP`**,
ohne Auth) → **öffentliche dynamische IPv4** (`37.81.x`), eingehendes TCP kommt durch.
Hardware-verifiziert (PDP-Adresse + TCP-Listener von außen erreicht + ESP-P4-Webserver via
`http://37.81.x/` erreichbar). Details, AT-Sequenzen und Messwerte: **[TELEKOM-PUBLIC-IPV4.md](TELEKOM-PUBLIC-IPV4.md)**.
Betrieb (P4-Konsole): `mode ppp` · `pdp ip` · `apn internet.t-d1.de` · `connect`.

## USB-Interface-Karte des EC200A (2C7C:6005, RNDIS-Config)
```
IF0/IF1  RNDIS (Netzwerk)
IF2      DIAG   (FF/00/00, 2x bulk, kein AT)
IF3      AT     (FF/00/00, bulk IN 86 / OUT 0F + int 89)  <- AT-Port
IF4      Modem  (FF/00/00, bulk IN 81 / OUT 0A + int 88)  <- PPP-Port
```

## PPP (Internet-Datenpfad)
lwIP **PPPoS über die rohe USB-Bulk-Schicht** (IF4 = Modem-Port, IN 0x81 / OUT 0x0A). `CONFIG_LWIP_PPP_SUPPORT=y`
in den Arduino-Libs → kein cdc_acm_host/esp_modem nötig. Ablauf: Kontext-Setup + `ATD*99***1#` roh auf
IF4 → `pppapi_pppos_create` + RX-Task (`pppos_input_tcpip`) + Output-Callback (Bulk-OUT) + `pppapi_connect`.
Gesteuert über die vorhandenen Buttons: „Verbinden" (`/modem-connect` → `pppStart`), „Trennen"
(`pppStop`), „Internet testen" (DNS-Probe über die PPP-Default-Route). Status/IP in `/modem-status.json`
(`ppp`, `pppip`).

### Durchsatz: gepipelinete Datenpumpe
Die erste Fassung war **Stop-and-Wait** (EIN Transfer je Richtung, `submit`→`xSemaphoreTake`→nächster) und
blockierte dabei den lwIP-tcpip-Thread → Durchsatz weit unter dem **Full-Speed-Deckel (12 Mbit/s brutto)**,
VGA ruckelte. Nicht das LTE-Modul (Cat-4) ist der Flaschenhals, sondern der ESP32-S3-USB (nur Full-Speed)
**und** die serielle Pumpe. Neu: **Pools vorallozierter Transfers**, mehrere gleichzeitig „in flight":
- **TX** (`pppOutputCb`): nicht-blockierend — freien Transfer aus `g_pppTxFree` nehmen, füllen, **asynchron**
  abschicken; `pppTxCb` legt ihn zurück. Bis zu `PPP_TX_N` Frames unterwegs; kurze Backpressure statt Blockade.
- **RX** (`pppRxTask`): hält `PPP_RX_N` IN-Transfers gleichzeitig, jeder fertige wird sofort in PPPoS gespeist
  und neu abgeschickt → keine Lücke zwischen Transfers. Callback `pppRxCb` reicht via `g_pppRxDone` weiter.
- Kostet **keine** zusätzlichen USB-Channels (mehrere Transfers je Endpoint werden in der Pipe gequeued) →
  der IF3/IF4-Channelkonflikt bleibt aus.
- **Messung:** `/modem-status.json` liefert `txkbit`/`rxkbit`/`txbytes`/`rxbytes`; UI zeigt „Durchsatz" in der
  Mobilfunk-Übersicht (TX/RX). Damit ist prüfbar, ob der Engpass Pumpe, Kamera/MJPEG oder LTE ist.

## DynDNS (dynamische öffentliche IP → fester Name)
Die netpublic-IPv4 ist öffentlich, aber **dynamisch** (ändert sich bei Neueinwahl). Ein Hintergrund-Task
(`dyndnsTask`, Core 0) meldet die aktuelle PPP-IP an den DynDNS-Anbieter, damit die Kamera unter einem
festen Namen erreichbar bleibt:
- **Wann:** bei **IP-Wechsel**, alle **6 h** als Keepalive, und auf **„Jetzt aktualisieren"** (`/dyndns-update`).
- **Wie:** HTTP(S)-GET an die **Update-URL** über die PPP-Default-Route. HTTPS via `WiFiClientSecure`
  (`setInsecure()`, wie ein Router). `myip=` wird **explizit** aus `pppIpStr()` gesetzt → korrekte IP auch bei
  Providern mit Quell-IP-Erkennung.
- **URL-Platzhalter** wie im FritzBox-Feld: `<ipaddr>`, `<ip6addr>` (leer), `<username>`, `<passwd>` (Alias
  `<pass>`), `<domain>`. Sind Credentials nicht in der URL (`user:pass@…`), wird optional Basic-Auth gesetzt.
- **Erfolg/Fehler:** HTTP-2xx **und** keine dyndns2-Fehlertoken im Body (`badauth`/`nohost`/`notfqdn`/…);
  die Antwort wird im Status-Feld (Freigaben → DynDNS) angezeigt. Nur **Benutzerdefiniert** (Custom-URL).
- Persistenz im NVS `dyndns`; Kennwort wird nie im Klartext an den Browser gegeben (leeres Feld = unverändert).

## Mobilfunk-Bandwahl + Netzmodus (WAN → Modem → Frequenzen)
FritzBox-artige **LTE-Bandsteuerung** — Bänder **mit Frequenz** wählbar, Profile, RAT-Modus:
- **Netzmodus** (`AT+QCFG="nwscanmode",<0=Auto|3=nur LTE|1=nur 2G>,1`). Das EC200A kann **kein 3G** (nur 2G+4G).
- **Bandprofil:** Automatisch (alle) · **1–2 GHz** (B3/1800) · **<1 GHz** (B20/B8/B28/B5) · Benutzerdefiniert.
- **Benutzerdefiniert:** Checkboxen je Band mit Frequenz (B1 2100 … B41 2500 TDD). JS baut die LTE-Maske als
  **BigInt** (Bänder bis Bit 40 > 32-Bit).
- **Anwenden:** `/modem-band-save` → `modemApplyBands()` sendet die AT-Sequenz auf IF3 (PPP muss getrennt sein),
  danach **CFUN=0→CFUN=1** (RF-Zyklus, kein USB-Re-Enum) → Modem sucht neu. Persistenz NVS `modem`.

### EC200A-Eigenheit (wichtig, weicht vom Quectel-Standardmanual ab!)
Der Band-Write ist `AT+QCFG="band",<GSM>,<LTE>` mit **bare-Hex OHNE `0x`-Präfix** und **nur 2 Parametern**
(kein TDS-Param). `0x`-Präfix **oder** 3 Parameter → **`+CME ERROR: 50`**. `GSM="d3"` behält den GSM-Wert.
LTE-Bitmaske bit(n-1)=Band n. Beispiel B3-only: `AT+QCFG="band",d3,4`. Auto/alle = `…,d3,1a0080800d5`.

## WAN/LAN: Weboberfläche über Mobilfunk abschaltbar (System → Sicherheit → Fernzugriff)
Wie bei einem Router ist **Modem = WAN**, **WLAN/AP = LAN**. Der Konfig-Webserver (Port 80) lauscht technisch
auf allen Interfaces. Neuer Schalter **`webWanEnabled`** (Default **an** = wie bisher): ohne Haken wird die
**Weboberfläche aus dem Internet nicht mehr angezeigt** (HTTP 403 auf WAN-Requests), nur noch im LAN.
- **WAN-Erkennung** (`reqIsWan()`): LAN = AP-Subnetz (`4.3.2.x`) **oder** WLAN-Client-Subnetz (per
  `remoteIP()` + Maske); alles andere bei aktivem PPP = WAN. Ohne PPP gibt es keine WAN-Seite.
- **Gate:** `reqWanDenied()` = `!webWanEnabled && reqIsWan()`. Greift in `isAuthenticated()` (alle geschützten
  Endpunkte) **und** `handleRootPage()` (403 statt PIN-Gate). **Kurzschluss:** bei Default (an) wird `reqIsWan`
  gar nicht erst ausgewertet → null Verhaltensänderung.
- Der **Kamera-Stream (Port 81)** bleibt bewusst **unberührt** (eigener Server, eigener Stream-Key) — die
  Kamera soll ja aus dem Internet erreichbar bleiben. Persistenz NVS `wifi` (`wanweb`).

### Durchsatz — ENDGÜLTIG geklärt: lwIP-TCP-Fenster, NICHT Antenne/Band
Definitiv nachgewiesen (PC vs. ESP am **selben** Modem/SIM/Ort/Band): der PC holt ~6,8 Mbit/s, der ESP nur
~0,5 Mbit/s auf **einer** Verbindung — **unabhängig von Band/SINR** (B8/SINR1 und B20/SINR9 liefern beide
~0,5). Ursache ist das kleine, **vorkompilierte lwIP-Sende-/Empfangsfenster** des Arduino-Cores
(`TCP_SND_BUF_DEFAULT=5744`, `TCP_WND_DEFAULT=5760`): `Durchsatz ≈ Fenster/RTT`. Die frühere „Antenne/Band"-These
war **falsch** (belegt). Details + Hebel: [`doc/arduino-tcp-window-throughput.md`](../doc/arduino-tcp-window-throughput.md).

**Zwei Hebel (Arduino-kompatibel):**
- **Aggregat via Worker:** Ein einzelner Stream ist gedeckelt; mehrere parallele Verbindungen sättigen den
  Uplink in Summe (gemessen: 6 Worker → ~2,1 Mbit/s Up / ~4,0 Mbit/s Down). Umgesetzt im eingebauten Speedtest
  (Worker-Zahl in der UI einstellbar + Auto-Ramp, der die sättigende Zahl selbst findet). Hilft Bulk-Transfers
  und mehreren gleichzeitigen Zuschauern — **nicht** einem einzelnen MJPEG-Stream.
- **Einzelstream via größerem Fenster:** Der `esp32-arduino-lib-builder` baut die vorkompilierten esp32s3-Libs
  mit `TCP_SND_BUF/WND=32768` neu (Workflow `.github/workflows/lwip-highwindow-libs.yml`, Release
  `esp32s3-libs-tcp32k`). Einspielen auf jedem Rechner: `tools/install-highwindow-libs.ps1` (sichert + ersetzt
  `esp32s3-libs/<ver>`, `-Revert` rollt zurück). Danach flasht der **unveränderte** Sketch normal aus Arduino Studio.
