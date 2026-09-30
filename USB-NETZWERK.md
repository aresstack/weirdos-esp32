# USB-Netzwerk (NCM): Architektur, drei Root Causes, Diagnosewerkzeuge

Stand 2026-09-30, hardware-abgenommen am XIAO ESP32-S3 (Seeed Sense) unter
Windows 11 LTSC 26100. Umgebung: arduino-esp32 **3.3.11** (ESP-IDF 5.5.5,
TinyUSB **0.21.0** vorkompiliert), Windows-Inbox-Treiber **UsbNcm.sys
10.0.26100.9444**.

**Endzustand:** USB einstecken → Adapter „WeirdOS USB Network" → Windows holt
per DHCP automatisch die **192.168.7.2** → Ping <1 ms → WebUI über
`http://192.168.7.1/`. Stabil unter Discover-Dauerbeschuss, keine
Reboots/kein Geräte-Flattern.

---

## 1. Aufbau

```
lwIP (tcpip-Thread)                         USB-Task (tud_task)
  dhcps/HTTP/DNS/...                              │
        │ linkOutput():                           │
        │  Frame in Pool-Slot KOPIEREN            │
        └─────────── Index-Queue ────────────────>│ pump():
                                                  │  tud_network_xmit(Slot)
   (kein pbuf verlaesst je den tcpip-Thread)      │   └─ xmit_cb: memcpy + Slot frei
                                                  ▼
                                     ncm_device_patched.c (TinyUSB-Kopie)
                                                  ▼
                                            DWC2 (FS, Slave-Mode)
```

- **Composite:** NCM (Interfaces 0/1; EP 0x81 Notify, 0x82 Bulk-IN, 0x02
  Bulk-OUT) + CDC-Konsole „WeirdOS Console" (Interfaces 2/3). Die Konsole ist
  die Lebensader (1200-Baud-Touch, Boot-Log-Dump, s. HARDWARE-FLASH.md).
- **`ncm_device_patched.c`**: Kopie der TinyUSB-0.21-NCM-Klasse im Sketch.
  Sketch-Objekte verdrängen das Archiv-Objekt der vorkompilierten Bibliothek
  (gleiche Mechanik wie `tinyusb_class_stubs.c`) — so sind Fixes an
  vorkompilierten Klassen möglich, ohne den Core neu zu bauen.
- **Copy-TX (`usb_net_service.cpp`)**: `linkOutput` kopiert das Frame noch im
  tcpip-Thread in einen festen Pool (8 × 1536 B) und reiht nur den Slot-Index
  ein. lwIP behält damit die volle pbuf-Eigentümerschaft (Semantik wie der
  WLAN-Treiber); der USB-Task sendet aus eigenen Puffern. Pool leer → Frame
  verwerfen (TCP sendet neu).
- **DHCP**: eigener Mini-Responder (Default) oder originaler IDF-dhcps per
  Build-Schalter `-DWEIRDOS_USBNET_IDF_DHCPS=1` — beide hardware-verifiziert,
  s. Abschnitt 4.

---

## 2. Die drei Root Causes (und ihre Beweise)

Symptom-Historie in zeitlicher Reihenfolge: (a) Gerätemanager **Code 10** am
Netzadapter, (b) nach dessen Fix: kein DHCP-Lease + Gerät **flattert im
Sekundentakt** (Connect/Disconnect-Gebimmel), (c) nach TX-Fix: Flattern nur
noch mit IDF-dhcps.

### 2.1 Windows Code 10: `wNdpOutDivisor = 1` fällt durch eine neue Treiber-Validierung

- **Fehlerbild:** UsbNcm.sys bindet, Gerät startet nicht. Ereignis 411:
  Problem 0xA, Problemstatus **0xC0000483 = STATUS_DEVICE_HARDWARE_ERROR** —
  exakt die Konstante, mit der Microsofts NCM-Treiber Validierungen ablehnt.
- **Ursache:** Der Inbox-Treiber prüft seit dem September-2026-Update
  (10.0.26100.9444) nach `GET_NTB_PARAMETERS`:
  `(wNdpOutDivisor >= 4) && (Zweierpotenz) && (<= dwNtbOutMaxSize)`.
  TinyUSB 0.21 meldet **1** → Ablehnung vor jedem weiteren Request.
  = TinyUSB-Issue **#3913**, Upstream-Fix **#3914** (14.09.2026).
- **Beweisweg (ohne funktionierenden USB-Sniffer):** Treiber-PDB vom
  Microsoft-Symbolserver geladen (RSDS-GUID aus der .sys extrahieren →
  `msdl.microsoft.com/download/symbols/UsbNcm.pdb/<GUID+Age>/`), die
  Prüf-Symbole gefunden und die **vollständigen Bedingungstexte als
  Klartext-Literale im Treiber-Binary** gelesen. Das öffentliche
  NCM-Driver-for-Windows-Sample enthält diese Prüfung NICHT — nur das
  Shipping-Binary.
- **Fix:** `wNdbIn/OutDivisor = 4` in `ncm_device_patched.c` (entspricht dem
  tatsächlichen Sendeverhalten: TinyUSB alignt ohnehin auf 4).

### 2.2 Hängender Sendepfad + PANIC-Flattern: FIFO-Push vs. USB-ISR

- **Fehlerbild:** Erster „langer" Bulk-IN-Transfer (DHCP-Offer, ~622 B =
  10 Pakete) bekommt nie eine Completion → der einzige Sende-NTB bleibt
  belegt → `tud_network_can_xmit()` dauerhaft false → nie eine DHCP-Antwort
  beim PC; dazu sporadische PANIC-Reboots unter RX-Last (= das Flattern).
- **Messbeweis (Register-Dump im Hänger):**
  `DIEPCTL2 = 0x80898040` (EPENA=1, Bulk, FIFO#2, MPS 64),
  `DIEPTSIZ2 = 0x00500000` (**XFERSIZE = 0, PKTCNT = 10**), `DIEPEMPMSK = 0`.
  Übersetzt: Software hat alle Bytes „in den FIFO geschrieben", die Hardware
  hat kein einziges Paket gesendet — der 64-B-FIFO wurde überrannt, der
  Treiber hält den Transfer für fertig befüllt.
- **Ursache:** Der FIFO-Push beim IN-Kickoff (`dcd_edpt_xfer` →
  `epin_write_tx_fifo`, prebuilt) läuft im USB-**Task**; poppt der USB-**ISR**
  währenddessen den RX-FIFO (genau beim Discover-Sturm, dessen Antwort der
  Offer ist), zerreißt der Push. Upstream-TinyUSB (master) hat hier keinen
  Fix (Diff geprüft).
- **Fix:** Jeder IN-Kickoff der NCM-Klasse läuft atomar gegen den
  USB-Interrupt: `ncm_edpt_xfer_guarded()` = `dcd_int_disable()` →
  `usbd_edpt_xfer()` → `dcd_int_enable()` (Mikrosekunden; der RX-FIFO puffert
  derweil in Hardware). Gilt für Daten-IN, Notify-IN und ZLP.
- **Sicherheitsnetz:** bleibt aktiv in `pump()` — nach 1,2 s Dauerblockade
  werden die DWC2-Register in den Event-Ring gedumpt und der
  Nachfüll-Interrupt versuchsweise reaktiviert.

### 2.3 IDF-dhcps-PANIC: Lease-Callback wird ohne NULL-Prüfung gerufen

- **Fehlerbild:** Mit IDF-dhcps crasht das Board reproduzierbar beim ersten
  vollständigen DISCOVER→REQUEST-Zyklus (PANIC → Reboot → Windows discovert
  neu → Crash → Sekundentakt-Flattern). Mini-Responder auf identischem Pfad:
  stabil.
- **Falsifizierte Hypothesen (je per Experiment):**
  - *pbuf-Lebenszeit über die Core-Grenze*: Copy-TX-Umbau änderte nichts —
    Crash identisch.
  - *Stack/Heap-Erschöpfung*: Der Mini-Responder verbraucht MEHR
    tcpip-Stack (876 B lokale Puffer) und überlebt; Allokationsfehler werden
    im dhcps geprüft (early return, kein Panic); >130 KB Heap frei.
  - *ARP-Static-/Unicast-Sonderpfad, ip4_route, netif-Flags*: Die
    instrumentierte Quelle zeigte zwei komplette `unicast+arp`-Antworten
    ERFOLGREICH auf dem Draht, Tod erst danach.
- **Beweis (instrumentierte dhcps-Quelle, RTC-Krümel):** Letzter Krümel
  **114** = exakt der Block nach `etharp_remove_static_entry` in `send_ack`:

  ```c
  if (SendAck_err_t == ERR_OK) {
      dhcps->dhcps_cb(dhcps->dhcps_cb_arg, m->yiaddr, m->chaddr);  // IDF 5.5.5: UNGEPRUEFT
  }
  ```

  `dhcps_new()` liefert `dhcps_cb = NULL`. Die esp_netif-Schicht registriert
  am WLAN **immer** `dhcps_set_new_lease_cb(...)` vor `dhcps_start()` —
  deshalb fällt der Fehler dort nie auf. Rohe Low-Level-Nutzung ohne
  Registrierung springt beim ersten vergebenen Lease auf Adresse 0.
  Der aktuelle **ESP-IDF-master enthält bereits den NULL-Guard** — es ist ein
  echter, upstream stillschweigend behobener 5.5.5-Bug.
- **Fix (beides):** (1) Lease-Callback registrieren (`dhcpsLeaseCb` loggt die
  vergebene IP in den Event-Ring), (2) NULL-Guard als Master-Backport in der
  Kopie `dhcpserver_instrumented.c`.
- **Hardware-Verifikation:** Originaler IDF-dhcps mit registriertem Callback:
  Lease 192.168.7.2, Ping 0 % Verlust, 35 s stabil, kein Reboot.

---

## 3. Diagnosewerkzeuge (bleiben in der Firmware)

Das Gerät ist sein eigener Sniffer — auf diesem Host war USBPcap für genau
dieses Gerät blind (Filter-Attach-Defekt; andere Geräte am selben Root-Hub
wurden erfasst), und `pnputil /restart-device` läuft komplett aus dem
PnP-Descriptor-Cache (erzeugt KEINEN Bus-Verkehr — als Trace-Trigger
unbrauchbar).

- **Event-Ring-Marker** (Konsolen-Dump beim Öffnen der „WeirdOS Console"):
  jeder Control-Request der NCM-Klasse (`NCM ctrl <bmRequestType> <bRequest>
  <wValue>`), String-Descriptor-Anfragen (Index ≥ 4; Windows-UsbNcms erster
  Draht-Zugriff ist String 7 = iMACAddress), RX-NTBs/Frames, TX-Schritte,
  DHCP-Anfragen/-Antworten mit `err`-Code. Gedrosselt (first-N). **Achtung:**
  Ring = 30 Slots, rotiert bei RX-Stürmen in ~2 s; der Dump kommt einmalig
  bei DTR-Connect.
- **RTC-Krümelspuren** (überleben Panic-Reboots; Ausgabe im Boot-Event
  `System gestartet (Reset: PANIC, NCM-Schritt N, USB-Task M)`):

  | Krümel | Ort |
  |---|---|
  | 10–13 | `tud_network_recv_cb` (Start/pbuf/vor/nach `tcpip_input`) |
  | 20/21 | `linkOutput` Start/Ende |
  | 30–33 | `pump()` (vor can_xmit/vor/nach xmit/idle) |
  | 40/41 | `tud_network_xmit_cb` Start/Ende |
  | 50/51 | Klasse ep_out (NTB empfangen/validiert) |
  | 60–63 | Klasse ep_in (Completion/Free/ZLP/Start) |
  | 70 | `tud_network_can_xmit` |
  | 80–83 | USB-Task-Schleife (80 = in `tud_task`, wo der Task meist wartet) |
  | 88/89 | dhcps `dhcps_response_ip_set` (88 ohne 89 ≈ `etharp_add_static_entry`) |
  | 90/91/105/106 | dhcps `handle_dhcp` (Start/nach parse/vor/nach Frees) |
  | 92–100 | dhcps `send_offer` (95/96 = um `udp_sendto`, 98/99 = um `pbuf_free`) |
  | 110–116 | dhcps `send_ack` (**114 = Lease-Callback-Aufruf**) |
  | 120/125/130/140 | `send_nak` / `send_ack_inform` / `parse_msg` / `dhcps_tmr` |

- **TX-Hänger-Sicherheitsnetz** in `pump()` (s. 2.2).
- **Reset-Grund** immer im Boot-Event (PANIC/INT_WDT/TASK_WDT/SW/POWERON/…).

## 4. DHCP: Mini-Responder (Default) vs. IDF-dhcps (Schalter)

| | Mini-Responder (Default) | IDF-dhcps (`-DWEIRDOS_USBNET_IDF_DHCPS=1`) |
|---|---|---|
| Umfang | ~100 Zeilen, ein Client, feste .2, Lease 24 h | vollständige Lease-Verwaltung |
| Antwortweg | immer Broadcast (kein ARP-Static-Tanz) | RFC-konform Unicast + temporärer Static-ARP |
| Voraussetzungen | – | **Lease-Callback registrieren** (sonst 5.5.5-NULL-Call) |
| Status | hardware-abgenommen, Produktionsdefault | hardware-abgenommen (Verify-Lauf) |

**lwIP-Bind-Falle (gilt für beide):** Ein PCB, das die
`0.0.0.0 → 255.255.255.255:67`-Discover empfangen soll, muss wie der
IDF-dhcps gebunden werden: `udp_bind_netif(pcb, netif)` **und**
`udp_bind(pcb, &netif->ip_addr, 67)` (konkrete IP!) plus
`ip_set_option(pcb, SOF_BROADCAST)`. Ein Bind auf `IP_ANY_TYPE` scheitert
still am Typ-Mismatch (v4-PCB), und auch ein v4-ANY-Bind bekam die
Broadcast-Discover auf diesem Stack nicht zugestellt.

## 5. Windows-Betriebsnotizen

- **Adaptername:** UsbNcm baut „<Hersteller> <Funktions-String>" — der
  NCM-String ist deshalb nur „USB Network" (Anzeige: „WeirdOS USB Network").
- **„NCM can-xmit blockiert"-Events** sind bei Burst-Verkehr normal
  (Sende-NTB kurz belegt, nächster pump-Umlauf sendet). Fehlerhaft war nur
  die DAUERblockade ohne `tx-done`.
- **DHCP-Backoff:** Nach vielen Fehlversuchen pausiert Windows' DHCP-Client
  minutenlang (Adapter zeigt APIPA 169.254.x). `ipconfig /release` +
  `/renew` auf dem Interface stößt ihn unprivilegiert neu an.
- **Flashen bei flatterndem Gerät:** Panic-Reboots fressen den
  persist-Merker; der 1200-Touch muss das kurze Lebensfenster treffen →
  Dauerfeuer-Touch (100-ms-Takt über alle CDC-COMs, bis der ROM/COM4
  erscheint; der ROM ist crash-frei). Details HARDWARE-FLASH.md.

## 6. Architektur-Entscheid: Raw-netif + WeirdOS-Zonenkern statt esp_netif

Für Tethering/Router-Ziele (PC über WLAN/LTE/VPN ins Netz) wurde erwogen,
NCM als Custom-`esp_netif_t` anzubinden („dann bekommt USB dieselbe Schicht
wie WLAN": DHCP-Lifecycle, NAPT, DNS, Events, Default-Route).

**Entscheidung: Raw-lwIP-netif bleibt.** Begründung:

1. Der einzige harte esp_netif-Vorteil („DHCP funktioniert nur so") ist
   widerlegt — der Crash war der 5.5.5-Callback-Bug (2.3), mit Registrierung
   läuft der IDF-dhcps auf dem Raw-netif einwandfrei. Auch `ip4_route`,
   Static-ARP und die netif-Flags arbeiten nachweislich korrekt.
2. WeirdOS **hat** die Schicht, die esp_netif verspricht, bereits als
   geteilten Kern: Zonen-Runtime + Netz-Registry (`resolveNetif` /
   `netRegistryBuild` mit `modem-ecm`, `wifi-sta`, `wg0`, `ipsec0`),
   Zonen-Forwarder mit NAPT in den lwIP-Hooks, eigener DNS-Dienst,
   Zugriffszonen. VPN-Interfaces sind dort gleichberechtigte Netifs — genau
   der Punkt, an dem esp_netif schwächelt (VPN ist dort Overlay, kein
   Interface).
3. Ein esp_netif nur für NCM ergäbe ZWEI parallele
   Interface-Verwaltungsmodelle. NAPT ist kein esp_netif-Privileg
   (`esp_netif_napt_enable` setzt dasselbe lwIP-NAPT, das der Zonen-Forwarder
   auf rohen netifs nutzt).

**Fortsetzung:** Die Routing-/VPN-Schicht darueber (Zonen-Hooks/liblwip-Patch,
WireGuard-Endpoint, PBUF_RAW-Falle, DHCP-Option 121 Zero-Config, NAPT-Grenzen,
RTSP-Default) ist in **`VPN-TETHERING.md`** dokumentiert.

**Tethering-Weg (UMGESETZT + hardware-bewiesen 2026-09-30):** `usb-ncm` ist im
Registry-/Zonen-Kern registriert — vier Stellen plus zwei Stolpersteine:

1. `cam::usbnet::nativeNetif()` (Accessor, usb_net_service).
2. `network_platform::resolveNetif("usb-ncm")`.
3. Registry: Interface `usb-ncm` (NETROLE_LAN) + Attachment `usb-lan`
   (192.168.7.1/24, accept any / return any — Muster wlan-ap).
4. **Onlink-Prefix nicht vergessen:** `netReachablePrefixesBuild` muss
   `usb-lan → 192.168.7.0/24 (NPFX_ONLINK)` melden, sonst sagt der Planner
   „IMPOSSIBLE (Quelle meldet kein Quellnetz)".
5. Plug&Play: Beim Boot bekommt `usb-lan` einmalig `ALLOW_AUTO` auf den besten
   Uplink im Build (WLAN vor Mobilfunk; Planner wählt NAT). Vorhandene
   Benutzer-Policies werden nie überschrieben; VPN-Ziele (`wg-client`/
   `ipsec-client`) wählt der Benutzer über die Zonen-Oberfläche.
6. **DNS über DHCP-Option 6 = öffentliche Resolver (1.1.1.1, 8.8.8.8):** die
   Anfragen laufen als normale UDP-Pakete durchs NAT (WLAN/LTE/VPN identisch).
   Der Port-53-Dienst des ESP ist der Captive-Portal-Dummy des Setup-AP
   (antwortet 4.3.2.1) — für den USB-Client bewusst KEIN DNS-Proxy.

Diagnose ohne Weboberfläche: 12 s nach Boot loggt die Firmware den effektiven
Plan in den Ereignisring (`Zonen-Plan usb-lan > …: NAT/…`).
**Beweis:** PC → USB → ESP-NAT → WLAN → Internet, Ping 1.1.1.1 = 4/4, Ø 25 ms
(NAT-Quelle = WLAN-IP). Profile: `usb-tether` (LTE→PC, P4), `usb-tether-wifi`
(WLAN→PC, auch S3), `usb-tether-vpn` (VPN-Dongle), `surveillance-usb-lte/-wifi`
(Kamera+IPsec+Tethering).
