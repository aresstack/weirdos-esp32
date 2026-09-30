# Flashen ohne Tasten — Ablauf für automatische Hardware-Tests

Hardware-bewiesen am 2026-09-30 (XIAO ESP32-S3 Sense, Windows, arduino-cli 1.5.1,
esptool 4.5.1, esp32-Core 3.3.11). Ziel: ein Test-Runner flasht beliebige
WeirdOS-Builds in Schleife, ohne dass jemand BOOT/RESET drückt.

## Die zwei Gerätezustände am USB-Port

| Zustand | Windows sieht | Bedeutung |
|---|---|---|
| **App läuft (OTG-Build)** | `VID 1209:0001` — „WeirdOS Camera/Microphone/USB Network" + ein CDC-COM („WeirdOS Console", wenn im EP-Budget) | normaler Betrieb |
| **ROM-Bootloader / hwcdc-App** | `VID 303A:1001` — „USB JTAG/serial debug unit" + COM | flashbar bzw. hwcdc-Konsole |

Ein OTG-Build **ohne** sichtbares 1209-Gerät = App nicht (fertig) gestartet
oder Gerät im Bootloader.

## Der bewiesene Flash-Loop (OTG-Builds)

```text
App (1209, Console-COM z.B. COM20)
  │  1) Bootloader auslösen: Console-COM mit 1200 Baud öffnen (DTR an, ~300 ms, schließen)
  │     -> Chip rebootet SOFORT per usb_persist_restart(RESTART_BOOTLOADER)
  │     -> das Open() schlägt oft mit „Gerät nicht vorhanden" fehl: DAS IST DIE ERFOLGS-
  │        SIGNATUR (der Port verschwand mitten im Open). Fehler NICHT als Fehlschlag werten.
  ▼
ROM-Bootloader (303A, COM z.B. COM4)          [~4 s warten, COM-Liste neu lesen]
  │  2) Flashen:  arduino-cli upload -p COM4 --fqbn <FQBN> <Sketchordner>
  │     (schlägt der Upload einmal fehl, weil der Port noch belegt ist: 2 s warten, wiederholen)
  ▼
App bootet VON SELBST (persist-Mechanismus)   [~8 s warten, dann 1209 prüfen]
```

PowerShell-Bausteine für den Runner:

```powershell
# 1200-Baud-Touch (Fehler beim Open ist Erfolg, s.o.)
$p = New-Object System.IO.Ports.SerialPort "COM20",1200,None,8,One
try { $p.DtrEnable = $true; $p.Open(); Start-Sleep -m 300; $p.Close() } catch { }

# warten bis Bootloader-COM da ist
# (Get-WmiObject Win32_SerialPort).DeviceID  -> 303A-COM suchen

# nach dem Upload: App-Prüfung
Get-PnpDevice -Status OK | Where-Object { $_.InstanceId -match "VID_1209" }
```

## Bootloader-Weg ohne CDC-Konsole

EP-Vergabe auf dem S3 (nur IN-EP1..4): **Video → Audio → NCM → Konsole**.
Bei `webcam + USB_NCM` fällt die Konsole weg. Dann:

```
POST /usb-bootloader        (Weboberfläche, Peripherie › USB-Gerät, „Bootloader starten";
                             Session nötig — requireSession)
```
→ ruft `usb_persist_restart(RESTART_BOOTLOADER)`, Gerät meldet sich als 303A-COM,
weiter wie oben ab Schritt 2. Erreichbar über das USB-Netz selbst (`192.168.7.1`)
oder WLAN. Nur S2/S3 — der P4 flasht über den CH343/UART.

## hwcdc-Builds (USBMode=hwcdc, z. B. Standardrolle)

Der 303A-COM ist hier die **App-Konsole** (Serial lesbar!). Flashen:
`arduino-cli upload -p <COM>` — esptool zieht den Chip über die
DTR/RTS-Emulation selbst in den Download-Modus.

## Die eine Falle: physisch per BOOT+RESET in den Download

Wurde der Download-Modus über die **Tasten** betreten (Strapping), bootet der
Chip nach dem Flashen NICHT von selbst in die App — esptools „Hard resetting
via RTS pin" ist am nativen USB-Serial-JTAG wirkungslos, und auch ein
SW-Reset landete im Versuch wieder im ROM. Befund 2026-09-30: erst ein
physischer RESET/Replug startete die App; ab dann trägt der persist-Loop oben.
**Konsequenz für Automatik:** nie über die Tasten einsteigen; immer über
1200-Touch bzw. `POST /usb-bootloader` (setzen den persist-Einmal-Merker,
mit dem der Auto-Boot nach dem Flashen funktioniert).

## Referenz-FQBN (XIAO ESP32-S3, geprüft)

```
esp32:esp32:XIAO_ESP32S3:USBMode=default,CDCOnBoot=cdc,PSRAM=opi,FlashSize=8M,PartitionScheme=default_8MB
```
`CDCOnBoot=cdc` heißt beim XIAO **Disabled** (Wert-Schlüssel vertauscht!) —
gewollt: die Firmware besitzt den USB-Stack selbst, die Reset-Callbacks
(1200-Touch, esptool-DTR/RTS) definiert `usb_device_service.cpp`.

## Prüfbausteine je Build (für die Testmatrix)

- **UVC**: `ffmpeg -f dshow -list_options true -i video="WeirdOS Camera"`
  (Auflösungsliste) und Roh-Frame: `-vcodec mjpeg -frames:v 1 -update 1 out.jpg`.
- **UAC**: Aufnahmegerät „WeirdOS Microphone" vorhanden.
- **NCM**: neuer Netzwerkadapter, DHCP-Adresse `192.168.7.x`, `ping 192.168.7.1`,
  WebUI `http://192.168.7.1`. Am Test-PC sofort die Schnittstellen-Metrik des
  NEUEN Adapters hochsetzen (z. B. 9999), damit Windows nie das Internet über
  das Gerät routet — den produktiven WLAN-Adapter nie anfassen.
- **Console**: 303A-frei? dann CDC-COM unter 1209 vorhanden; 1200-Touch als Loop-Test.
