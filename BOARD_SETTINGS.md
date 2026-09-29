# Board-Einstellungen (Arduino IDE / "AS")

Sketch: `esp32-modem-host`  · esp32-Core: **3.3.11** (arduino-esp32, IDF 5.5.x)
Der User flasht **direkt diese Repo-Working-Copy** (der frühere `Documents\Arduino\…`-Ordner ist tot).

---

## Board 1 — XIAO ESP32-S3 (bisheriger Stand, verifiziert)

Im Board-Dropdown: **XIAO_ESP32S3**. Menü-Einstellungen (entsprechen der belegten FQBN):

| Menüpunkt (Tools) | Wert | FQBN-Token |
|---|---|---|
| Board | XIAO_ESP32S3 | `XIAO_ESP32S3` |
| USB Mode | Hardware CDC and JTAG | `USBMode=hwcdc` |
| USB CDC On Boot | Enabled | `CDCOnBoot=cdc` |
| PSRAM | OPI PSRAM | `PSRAM=opi` |
| Flash Size | 8 MB | `FlashSize=8M` |
| Partition Scheme | 8 MB (default) | `PartitionScheme=default_8MB` |

**FQBN (verifiziert, aus `admin-maint/acli-build-dir/build.options.json`):**
```
esp32:esp32:XIAO_ESP32S3:USBMode=hwcdc,CDCOnBoot=cdc,PSRAM=opi,FlashSize=8M,PartitionScheme=default_8MB
```

Wichtig (S3-spezifisch): der Durchsatz-Fix ist ein **manueller lwIP-`.o`-Tausch** ins gebündelte
`liblwip.a` (TCP-Fenster 5744→32768), gebaut mit `tools/build-lwip.ps1` (`tools/liblwip-32k.a` /
`liblwip-64k.a`). Das ist **kein** PlatformIO/menuconfig, sondern ein Lib-Patch — muss beim Boardwechsel
neu bewertet werden (andere lwIP-Config auf dem P4).

---

## Board 2 — Waveshare ESP32-P4-Pico (Ziel, Umstellung läuft)

> Werte hier sind **im IDE-Board-Dropdown zu bestätigen** — nicht blind übernehmen. Kamera-Treiber
> `esp32p4_camera_device.*` (MIPI-CSI via V4L2) liegt bereits im Repo.

Board-Dropdown: **„ESP32P4 Dev Module"** (`esp32:esp32:esp32p4`).
→ **GPTs Anleitung (bestätigt): für den Waveshare ESP32-P4-Pico in der Arduino IDE Board =
`ESP32P4 Dev Module` wählen** (es gibt keinen eigenen Pico-Eintrag; das Dev-Module-Profil passt).
Restliche Menüwerte:

**Board-Hardware (Waveshare-Doku, verbindlich):** ESP32-P4-Pico = Chip **ESP32-P4NRW32**,
**32 MB NOR-Flash + 32 MB gestapeltes PSRAM**. Also NICHT 16 MB. Das Default-Board-Profil steht
auf 4 MB Flash / PSRAM DISABLED — **beides falsch**, muss gesetzt werden.

| Menüpunkt (Tools) | Wert | Anmerkung |
|---|---|---|
| Board | **ESP32P4 Dev Module** | GPT-Anleitung; FQBN `esp32:esp32:esp32p4` |
| **Flash Size** | **32MB (256Mb)** | Waveshare P4-Pico hat 32 MB NOR-Flash. Default 4 MB ist falsch. **Zuerst das setzen** — danach erscheinen im Partition-Menü ggf. eigene 32-MB-Layouts. |
| **PSRAM** | **Enabled / OPI PSRAM** | ⚠ UNBEDINGT AN: 32 MB PSRAM (ESP32-P4NRW32). Ohne PSRAM sieht die Firmware nur ~320 KB internen Heap → Kamera/USB/große Worker testen dann am völlig falschen Speicherbild. |
| Flash Frequency | 80 MHz | zunächst so lassen |
| Flash Mode | QIO | passt zum externen NOR-Flash |
| **Partition Scheme** | **große App-Partition** | ⚠ PFLICHT: Firmware ~1,74 MB, Default-App (1,25 MB) → „Textbereich überschreitet Platz". Nach Flash Size=32MB im Menü nachsehen: **wenn ein 32-MB-Schema mit großer APP + OTA angeboten wird, das nehmen** (OTA am P4 später über den Netzwerkpfad nutzbar, nicht absichtlich aufgeben). Nur wenn nur klassische Schemata da sind: **„Huge APP (3MB No OTA/1MB SPIFFS)"** reicht für den Test. |
| USB / USB Mode | HS-OTG | P4 hat **natives USB 2.0 High-Speed OTG** → gut für den Modem-USB-Host + eigenen Port |
| CDC On Boot | Enabled | für Serial-Log wie am S3 |

**FQBN (zu bestätigen, NICHT verifiziert):**
```
esp32:esp32:esp32p4          # generisches Dev Module; Waveshare-Variante ggf. eigener Bezeichner
```

### ⚠ Kritische Portierungs-Punkte P4 (nicht nur „Board umstellen")
- **Kein natives WLAN/BT auf dem ESP32-P4.** WiFi kommt nur über einen **Companion-Chip (ESP32-C6)**
  via **ESP-Hosted** (SDIO/SPI, „network_adapter"-Firmware auf dem C6). Prüfen, ob der P4-Pico einen
  **onboard C6** hat und ob `WiFi`/`AP+STA` in Arduino über den Hosted-Pfad laufen. Diese Firmware ist
  **AP+STA-zentriert** → das ist der größte Portier-Brocken, nicht die Kamera.
  - **USB-WLAN-Dongle geht NICHT** (getestet-gedacht, D-Link 2,4 GHz): ESP-IDF/Arduino haben
    **keine Treiber für generische USB-WLAN-Chipsätze** (RTL/MediaTek…). Der Hub/Host erkennt den
    Stick elektrisch, aber es gibt keinen Pfad an lwIP → kein Netz-Interface. (Anders als Linux.)
    WLAN-Weg bleibt **ESP-Hosted + C6 (SDIO/SPI)**, nicht USB.
  - **SDIO-WLAN-Karte im SD-Slot geht auch NICHT:** kommerzielle SDIO-WLAN-Chips (Marvell/Broadcom/TI…)
    haben ebenfalls keinen ESP-IDF-Treiber. Das einzige SDIO-WLAN-„Gerät", das der P4 ansprechen kann,
    ist ein **ESP32-C6/C5 mit ESP-Hosted** (ESP-Chip als SDIO-Slave, keine Kauf-Karte). Der sichtbare
    SD-Slot ist Storage (anderer SDMMC-Host als die C6-Anbindung) — dort steckt man keine WLAN-Karte rein.
  - **Ohne lokales WLAN Zugang zur UI:** über die **LTE-IP des Modems** (+ DynDNS) sobald PPP steht,
    oder **serielle Konsole**. Deshalb sind modemAutoStart + DynDNS im P4-Test hart aktiviert.
- **2 USB-Ports** sind der Grund für den Wechsel: Modem bekommt einen **eigenen** USB-Port (eigene
  ISR-/Strom-Domäne) → adressiert die S3-Regression (Kamera-Freeze bei aktiver Modem-Datenverbindung)
  auf Hardware-Ebene.
- **Kamera:** DVP/`esp_camera` (S3) → **MIPI-CSI/V4L2** (P4). Umschaltung liegt in
  `esp32p4_camera_device.*` vs `esp32s3_camera_device.*`.
- **lwIP-Fenster-Patch** (s. o.) gilt so nur für den S3-Build; am P4 neu prüfen.
- **OV5647-FHD-Lib-Swap (P4, Toolchain-Eingriff):** die vorkompilierte `libespressif__esp_cam_sensor.a`
  hat per Kconfig nur den 800×800-RAW8-Modus. `tools/build-camsensor.ps1` baut `ov5647.c.obj` mit den
  zusätzlichen Modi **1280×960 RAW10/45 + 1920×1080 RAW10/30** neu (Fidelity-Gate: Referenz-`.text` ==
  Stock aus dem Ziel-Archiv → dann Patch grösser) und tauscht die `.obj` per `ar r` ins Archiv.
  ⚠️ **WELCHES Archiv real gelinkt wird, NICHT am Ordnernamen raten — die Sketch-`.map` ist die Wahrheit.**
  Der Waveshare-P4 (`esp32p4-eco2`-ROM) linkt die **Engineering-Sample-Libs `esp32p4_es-libs`** (arduino-esp32
  wählt sie für die ECO/ES-Silizium-Rev), NICHT `esp32p4-libs`. Das Skript defaultet daher auf `-LibsPkg
  esp32p4_es-libs`; Gegencheck: `<sketch-build>\*.ino.map` → `libespressif__esp_cam_sensor.a`-Pfad.
  `-Install` sichert Stock → `.stock-bak`, `-Revert` rollt zurück. **Nach einem Core-Update erneut `-Install`.**
- **„Compile durch" = nur Phase 1**, nicht „Port fertig". Echte Target-Probleme kommen als Nächstes:
  `esp_video`/MIPI-CSI-Kamera, WLAN/ESP-Hosted, USB-Host — die zeigen sich erst beim Bauen/Booten
  auf echter P4-Hardware.
- **OTA nicht absichtlich aufgeben:** der P4 hat kein natives WLAN, aber OTA kann später über den
  externen Netzwerkpfad (Modem) laufen → wenn ein Partition-Schema mit OTA passt, dieses bevorzugen.

---

_Notiz gepflegt beim Boardwechsel S3 → P4-Pico. Bei bestätigten P4-FQBN/Menüwerten diese Tabelle
mit den echten Dropdown-Werten aktualisieren._
