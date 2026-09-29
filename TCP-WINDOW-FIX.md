# Durchsatz-A/B-Test: grosses lwIP-TCP-Fenster

## Empirischer Befund

| Messung (gleiches Modem/SIM/Ort/Band B20, SINR ~9-10) | Download | Upload |
|---|---:|---:|
| **PC über EC200A (RNDIS)** | 6,8 Mbit/s | 6,0 Mbit/s |
| **ESP32 über EC200A (PPPoS)** | 0,55 Mbit/s | 0,31 Mbit/s |

Damit ist die Funkstrecke als Hauptursache stark entlastet: Der ESP erreicht auf B20 mit
praktisch identischem SINR nur einen Bruchteil des PC-Durchsatzes. Der Engpass liegt im
ESP-Datenpfad (USB-Host / PPPoS / lwIP / TCP / Scheduling).

## Was die TX-Zähler beweisen – und was nicht

Während des Speedtests wurden beobachtet:

```text
txmaxinflight = 2      (bei PPP_TX_N = 16)
txwait        = 0
txtimeout     = 0
```

`txwait=0` und `txtimeout=0` entlasten den USB-TX-Transferpool: lwIP musste nicht auf einen
freien OUT-Transfer warten und die 200-ms-Drop-Stelle wurde nicht erreicht.

**Wichtig:** `txmaxinflight` zählt USB-Bulk-OUT-Transfers. Es ist **kein** TCP-Zähler und
beweist weder `cwnd`, `snd_wnd` noch die Anzahl unbestätigter TCP-Segmente. Die frühere
Ableitung „2 USB-Transfers = 2 unbestätigte TCP-Segmente“ war zu stark.

## Arbeitshypothese: kleines TCP-Fenster

Arduino-ESP32 verwendet im normalen Arduino-Build vorkompilierte ESP-IDF/lwIP-Bibliotheken.
Die tatsächlich einkompilierten Werte werden deshalb beim Boot ausgegeben:

```text
[lwIP] TCP_MSS=... TCP_SND_BUF=... TCP_WND=...
```

Der übliche Arduino-ESP32-3.x-Build liegt beim TCP-Sendepuffer in der Größenordnung von
5744 Byte. Über eine LTE-Strecke mit ungefähr 35 ms RTT ist das für mehrere Mbit/s knapp.
Ein 32-KiB-Fenster besitzt dagegen ein Bandwidth-Delay-Product von rund 7,5 Mbit/s:

```text
32 KiB * 8 / 35 ms ~= 7,5 Mbit/s
```

Das macht das grössere Fenster zu einem guten **A/B-Test**, aber noch nicht zur bewiesenen
Ursache. Bleibt der Durchsatz unverändert, wird die Fenster-Hypothese verworfen und als
Nächstes direkt lwIP-PCB (`cwnd`, `snd_wnd`, `unacked`) bzw. USB-RX-Timing instrumentiert.

## A/B-Konfiguration

`sdkconfig.defaults` setzt für den IDF-Build:

```ini
CONFIG_LWIP_TCP_SND_BUF_DEFAULT=32768
CONFIG_LWIP_TCP_WND_DEFAULT=32768
CONFIG_LWIP_TCP_RECVMBOX_SIZE=25
```

## Warum der normale Arduino-IDE-Build nicht reicht

Arduino-ESP32 linkt vorkompilierte ESP-IDF-Bibliotheken. Eine daneben gelegte
`sdkconfig.defaults` baut lwIP in der Arduino IDE nicht neu. Für diesen Test braucht es
einen echten ESP-IDF-Build mit Arduino als ESP-IDF-Komponente.

## Build-Weg im Repository

`platformio.ini` pinnt aktuell:

- Arduino-ESP32 **3.3.11**
- ESP-IDF **5.5.5**
- pioarduino Platform **55.03.311**
- `framework = arduino, espidf`

Damit bleibt der Sketch Arduino-Code (`setup()` / `loop()`), während IDF und lwIP aus der
Projektkonfiguration gebaut werden. Die Quelltexte bleiben direkt in `esp32-modem-host/`;
es gibt keine zweite `src/`-Kopie.

Für Arduino als IDF-Komponente ist `CONFIG_FREERTOS_HZ=1000` gesetzt.

### USB-Hinweis für den ESP32-S3

Der EC200A benutzt den nativen USB-OTG-Host des S3. Deshalb wird in `sdkconfig.defaults`
**keine** `CONFIG_ESP_CONSOLE_USB_CDC` erzwungen: diese IDF-Konsole benutzt ebenfalls den
USB-OTG-Controller. USB-OTG und USB-Serial/JTAG teilen sich beim S3 die interne PHY und
können dort nicht gleichzeitig arbeiten, sofern keine externe PHY verwendet wird.

## Partitionierung / OTA

PlatformIO verwendet `default_8MB.csv` statt `huge_app.csv`. Damit stehen zwei OTA-App-Slots
zur Verfügung und das Web-OTA kann grundsätzlich funktionieren. Falls die Anwendung nicht
in einen Slot passt, soll der Build fehlschlagen; dann muss die Partitionierung bewusst
angepasst werden, statt OTA zur Laufzeit nur scheinbar anzubieten.

## Testreihenfolge

1. Arduino-IDE-Firmware booten und die aktuellen `TCP_MSS/TCP_SND_BUF/TCP_WND` notieren.
2. PlatformIO/IDF-Build erstellen und im Boot-Log `TCP_SND_BUF=32768` sowie
   `TCP_WND=32768` bestätigen.
3. Modem auf B20 mit vergleichbaren RF-Werten verbinden.
4. Eingebauten Speedtest ausführen.
5. Ergebnis vergleichen:
   - **deutlicher Sprung auf mehrere Mbit/s:** TCP-Fenster war leistungsrelevant.
   - **weiter ~0,55/0,31 Mbit/s:** Fenster-Hypothese verwerfen; lwIP-PCB/USB-RX messen.
