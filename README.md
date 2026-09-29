# WeirdOS

_Repo `aresstack/weirdos-esp32`. „WeirdOS" ist der Produktname (AP-SSID, Hostname `weirdos`); der Repo- und Sketch-Name folgt der Kleinschreib-Konvention._

Modulare ESP32-Firmware (ESP32-**S3** und ESP32-**P4**) für IP-Kamera + LTE-Modem-Host.
Ein einzelner Arduino-Sketch, der eine Kamera bereitstellt, ein USB-LTE-Modem
(Quectel EC200A) als Uplink ansteuert und eine Weboberfläche zum Einrichten,
Streamen und für VPN/Netzwerk mitbringt.

> **Herkunft.** WeirdOS ist die verselbständigte Kopie von
> `Miguel0888/quectel-ec200a-eu` → Unterordner `esp32-modem-host/`. Der Sketch
> wurde beim Herauslösen von `esp32-modem-host.ino` in **`weirdos-esp32.ino`**
> umbenannt und auf die Repo-Wurzel gelegt, damit sich das Repo direkt aus dem
> Git-Ordner flashen lässt (`git clone … weirdos-esp32` → Arduino öffnet den Ordner
> `weirdos-esp32/` mit `weirdos-esp32.ino`, keine Kopie nötig). Die technische
> Sketch-Doku steht unverändert in [`README.sketch.md`](README.sketch.md).
> Provenienz und Lizenzhinweise: [`NOTICE.md`](NOTICE.md).

## Warum dieses Repo existiert

Das Cam-Tool (`Miguel0888/ipcam-lan-discovery`) soll WeirdOS als Grundlage
verwenden und beim Flashen **nur die Module ausliefern, die gebraucht werden**.
Der Grund sind zwei harte Grenzen auf dem ESP32:

1. **Heap** – vor allem auf dem P4. Ungenutzte Module belegen statisches RAM,
   das dem USB-Host/PPP und der Krypto fehlt.
2. **Flash** – der App-Teil läuft voll, je mehr Module fest mitkompiliert werden.

Arduino liefert ungenutzten Code nur dann *nicht* aus, wenn er **gar nicht erst
referenziert** wird. Ein Laufzeitschalter genügt nicht: er kann die statischen
Puffer einer schon gelinkten Bibliothek nicht mehr freigeben (belegt am
TinyUSB-Fall, siehe [`docs/flash-and-heap.md`](docs/flash-and-heap.md)). Deshalb
werden die Module hinter **Compile-Schalter** (`#if WEIRDOS_FEATURE_*`) gelegt
und im Composition Root nur unter ihrem Schalter referenziert.

## Dokumente

| Thema | Datei |
|-------|-------|
| **Echter Modulkatalog** (S3-Kern vs. P4-optional, was Kern werden kann) | [`DECOMPOSITION.md`](DECOMPOSITION.md) |
| **Flash & Heap** – die „gezippt hochladen"-Frage ehrlich beantwortet | [`docs/flash-and-heap.md`](docs/flash-and-heap.md) |
| Sketch-/Hardware-Doku (Board-Settings, USB-Host, Flashen) | [`README.sketch.md`](README.sketch.md) |

## Bauen

`arduino-cli` mit esp32-Core 3.3.11. Beispiel S3:

```
FQBN="esp32:esp32:XIAO_ESP32S3:USBMode=hwcdc,CDCOnBoot=cdc,PSRAM=opi,FlashSize=8M,PartitionScheme=default_8MB"
arduino-cli compile --fqbn "$FQBN" .
```

Flashen weiterhin manuell aus Arduino Studio (S3: BOOT+RESET-Hack, siehe
`README.sketch.md`). Board-Settings: [`BOARD_SETTINGS.md`](BOARD_SETTINGS.md).
