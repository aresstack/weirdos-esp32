# Flash & Heap — ehrliche Antworten

Zwei getrennte Probleme, die oft verwechselt werden.

## „Man kann den Code doch gezippt hochladen?" — jein

Es gibt kein „ZIP hochladen, Bootloader entpackt". Der ESP-Bootloader flasht ein
rohes Image. Was real existiert und was es *nicht* löst:

| Technik | Was sie tut | Löst „Flash ist voll"? |
|---------|-------------|------------------------|
| **Komprimiertes OTA** (gzip/heatshrink, Gerät entpackt in den OTA-Slot) | verkleinert den **Upload/Transfer** (gut über LTE) | **Nein.** Das entpackte Image muss trotzdem in die App-Partition passen. |
| **Gezippte Web-Assets** (`Content-Encoding: gzip`) | HTML/CSS/JS liegen **komprimiert im Flash**, Browser entpackt | **Ja**, spürbar. HTML/CSS/JS ~3–5× kleiner. |
| **Assets in LittleFS statt im App-Image** (gzipped) | verschiebt Ballast aus der App-Partition | **Ja**, entlastet App-Flash. |
| **Feature nicht mitkompilieren** | Code + statische Puffer fallen weg | **Ja**, der größte Hebel. |
| **Single-App-Partition** (kein OTA) | ~3 MB → ~6 MB App auf 8-MB-Flash | **Ja**, verdoppelt fast den App-Platz. |

**Fazit fürs Flash-Problem:** der Kollege meint vermutlich komprimiertes OTA —
das hilft beim *Übertragen* über das Modem, nicht beim *Reinpassen*. Zum
Reinpassen zählen: (1) ungenutzte Module weglassen, (2) Web-Assets gzippen,
(3) bei Verzicht auf OTA die Single-App-Partition.

## Der Flash-Hebel Nr. 1: Web-Assets gzippen

`web_ui_assets.cpp` hält Seiten als `const char[]` im Flash. Statt roh:
1. Assets zur Build-Zeit gzippen (Skript in `scripts/`), als Byte-Array einbetten.
2. Beim Ausliefern `Content-Encoding: gzip` + korrekten `Content-Type` setzen.
3. Der Browser entpackt selbst. Kein Heap-Aufwand auf dem ESP.

Erwartung: die UI-Seiten sind der größte statische Textblock; Faktor 3–5 weniger
App-Flash für die Assets.

## Der Flash-Hebel Nr. 2 (= Heap-Hebel): nicht referenzieren

Arduino/`gc-sections` wirft nur weg, was **nirgends referenziert** wird. Ein
**Laufzeitschalter reicht nicht** — belegt am TinyUSB-Device-Fall:

> Die bloße Referenz auf den Device-Stack zog `libarduino_tinyusb.a` komplett mit;
> deren Klassen halten ~48 KB statische Puffer im internen RAM (audio 13k, ncm 19k,
> msc 8k, dfu 4k …). Statischer RAM **75 KB → 125 KB**, Boot-Heap **84 KB → 30 KB**
> → der Modem-Host bekam kein DMA-RAM, keine Enumeration, kein PPP.
> Fix: nur mit Build-Flag `WEIRDOS_USB_DEVICE=1` einbinden; ohne Flag ein Stub.
> „Ein Laufzeitschalter kann statische Lib-Puffer nicht freigeben."

Das ist der Beweis für den ganzen Ansatz: Module müssen **zur Compile-Zeit** aus
dem Link fallen, nicht nur zur Laufzeit „aus" sein. Deshalb `#if WEIRDOS_FEATURE_*`
im Composition Root, nicht `if (enabled)`.

## Heap-Muster, die schon im Code stehen (übernehmen)

- Große statische Tabellen in **PSRAM** legen, nicht ins interne `.bss`
  (Zonen-Runtime ~15 KB → PSRAM; ohne PSRAM Feature aus).
- Worker-Task-Stacks für Video/H.264 in **PSRAM**.
- Exklusive Heap-Region für den H.264-Allocator, nur bei aktivem Video-Server.

## Konkrete Build-Stellschrauben

- `PartitionScheme`: mit OTA `default_8MB` (2×3 MB App). Ohne OTA ein
  Single-App-Schema (~6 MB App) — Feature `OTA=0` sollte das Schema mitwählen.
- Linker: `-ffunction-sections -fdata-sections -Wl,--gc-sections` (Core-Default),
  ggf. LTO. `-Os` für Größe.
- `-Wundef`: jedes `WEIRDOS_FEATURE_*` ist immer definiert (`0`/`1`), damit ein
  Tippfehler auffällt statt still „aus" zu bedeuten.
