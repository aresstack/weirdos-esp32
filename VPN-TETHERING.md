# VPN-Tethering & Zonen-Routing — Erkenntnisse und Entscheidungen (Nacht 2026-09-30/10-01)

Dieses Dokument haelt fest, was in der Nacht vom 30.09. auf den 01.10. am
S3-Vollbuild (WLAN + IPsec + WireGuard + USB-NCM + Kamera) gefunden, entschieden
und hardware-bewiesen wurde. Es ergaenzt `USB-NETZWERK.md` (USB-NCM-Grundlagen,
drei Windows-Ursachen) um die Routing-/VPN-Schicht darueber.

## 1. Endstand: Was funktioniert (alles hardware-bewiesen)

| Pfad | Beweis |
|---|---|
| PC → USB → NAT → WLAN → Internet | Ping 1.1.1.1 + DNS, dauerhaft |
| PC → WireGuard → ESP → NAT → IPsec → LANCOM | Browser-Login auf 192.168.110.11 |
| PC → USB → NAT → IPsec → LANCOM | Ping 4/4 (23 ms) + HTTP 200 |
| **Zero-Config**: USB anstecken, sonst NICHTS | Windows lernt die Tunnel-Route per DHCP-Option 121; Ping+HTTP ohne jede Handroute |
| RTSP ueber alle Interfaces (WLAN/USB/Tunnel-IP) | `INADDR_ANY`-Bind; Default-Transport siehe §5 |

Der Ziel-Workflow des Projekts ist damit erreicht: **USB-Dongle anstecken →
IPsec in der WebUI konfigurieren → Zonen-Haken setzen → alles laeuft.**

## 2. Die drei Root Causes der Nacht

### 2.1 Zonen-Routen brauchen die gepatchte liblwip.a (Route-/Forward-Hooks)

Die vorkompilierte `liblwip.a` des Arduino-Cores kennt die WeirdOS-Zonen
nicht: `hooks: route:false, forward:false` — die Zonen-Runtime plant und
"installiert" Policies, aber der Stack fragt die Routentabelle nie. Folgen:

* **Internet-NAT funktioniert TROTZDEM** (Default-Route + Stock-NAPT) — das
  tarnte den Defekt den ganzen Tag.
* **Nicht-Default-Ziele (VPN-Netze!) landen auf der Default-Route** und
  versanden im Heimnetz. ipsec0/wg0 sind Punkt-zu-Punkt-netifs; ohne den
  Route-Hook findet `ip4_route()` sie fuer fremde Ziel-Netze nie.

Fix: `tools/build-lwip-zones.ps1` (Objekt-Tausch von `ip4.c` im Stock-Archiv,
kein IDF-Vollbau; `-Install`/-`Revert`/-`VerifyElf`, Marker
`weirdos_lwip_*_hook_present`). Produktisiert im Cam-Tool als Checkbox
**„Zonen-Hooks"**: vor jedem Build wird der Patch sichergestellt (einmal je
Core-Version; fuer Nicht-Router-Profile unschaedlich, die Haken sind ohne die
Sketch-Symbole No-Ops). Die Zonen-Seite zeigt den Zustand ehrlich an
(„lwIP-Hooks vorhanden/fehlen").

### 2.2 WireGuard-Client-Configs trugen stur die DynDNS-Domain

`Geraet erzeugen` schrieb immer `Endpoint = <DynDNS>` — korrekt nur im alten
P4-Setup (Mobilfunk mit oeffentlicher IPv4). Der S3 im WLAN hinter dem
Router-NAT ist darunter NICHT erreichbar: Client „Aktiv, 0 B empfangen",
WeirdOS „rx nie" (kein einziges Handshake-Paket kam an — der Server lief die
ganze Zeit fehlerfrei).

Fix (topologie-ehrlich): Mobilfunk-WAN up → DynDNS wie bisher; sonst die
aktuelle Underlay-IP. Ohne konfigurierte DynDNS-Domain gibt es jetzt ueberhaupt
erst eine Config (IP statt Fehlermeldung).

### 2.3 PBUF_RAW im IPsec-Empfang — der stille Paketfresser

`tunDeliver()` speiste entschluesselte Tunnel-Pakete als `PBUF_RAW` (0 Byte
Headroom) ein. Beim **Zonen-Forward auf ein Ethernet-netif** (USB-NCM, auch
WLAN) scheitert `pbuf_add_header(14)` in `ethernet_output` → lwIP verwirft
**still**, NACH dem replies-Zaehler des Forward-Hooks, VOR `linkoutput`.

Warum es nie auffiel: lokale Zustellung (ESP-Eigen-Ping) braucht keinen
Ethernet-Header, WireGuard (wg0) ist ein Tunnel-netif ohne Ethernet — beide
Pfade liefen. Nur Tunnel→Ethernet-Forward war tot. Fix: eine Zeile,
`PBUF_LINK`.

**Beweisfuehrung** (uebertragbares Muster):
1. Funktionierenden Zwilling daneben stellen (WG→IPsec ging, USB→IPsec nicht —
   gleiche Route, gleiches NAT, gleicher Tunnel → Unterschied im Rueckgabe-netif).
2. Paar-Zaehler der Zonen (`fwd/natTranslated/replies`) eingrenzen: ESP gab
   Antworten frei.
3. `pktmon` am PC: nur Requests auf dem Draht, null Drops in Windows → der
   Verlust liegt im ESP NACH dem Hook.
4. Telemetrie an der Weiche: „NCM: TX fremde Quelle" im linkOutput — Internet-
   Antworten (8.8.8.8) erschienen, Tunnel-Antworten (110.11) nie → der Verlust
   liegt VOR linkOutput → ethernet_output/Headroom. (Telemetrie bleibt drin,
   erste 3 Events.)

## 3. Zero-Config: DHCP-Option 121 (RFC 3442)

Der Mini-DHCP des USB-netif traegt die Ziel-Netze der `usb-lan`-Zonen-Policies
als classless static routes in die Lease — dasselbe Prinzip wie die
AllowedIPs-Injektion in WireGuard-Client-Configs. Entscheidungen:

* **DESIRED statt Reachable**: Die Lease kommt Sekunden nach dem Boot, der
  Tunnel steht erst spaeter — Reachable waere leer und Windows erneuert erst
  nach Stunden (Henne-Ei). `desired` ist persistent (NVS) und existiert genau
  dafuer. Neuer Getter `zoneRuntimeIntentAllows()` prueft Intents unabhaengig
  vom kompilierten Plan (fruehe DHCP-Zeit).
* **0.0.0.0/0 nur bei Uplink-Intent**: RFC-gemaess ignorieren Clients Option 3,
  sobald 121 vorhanden ist. Ein USB-only-PC behaelt so Internet; auf
  Dual-Netz-PCs bleibt die WLAN-Default per Metrik vorn (verifiziert: WLAN 45 <
  USB 56 — keine Metrik-Pinnerei noetig).
* **Ohne Zonen-Ziele keine Option 121** → Verhalten exakt wie vorher.
* Nach Policy-AENDERUNGEN holt Windows die neuen Routen mit der naechsten
  Lease (Neu-Anstecken oder `ipconfig /renew`).

## 4. Grenzen und bewusste Entscheidungen

* **esp-lwIP-NAPT-Grenze**: Dasselbe Interface kann nicht gleichzeitig
  NAT-Eingang und NAT-Ausgang sein. Konkret: „WLAN-Gateway in den Tunnel"
  (wifi-sta als Eingang) schliesst „USB→WLAN-Internet" (wifi-sta als Ausgang)
  aus. Der Planner meldet das fail-closed mit Klartext-Grund statt still zu
  brechen.
* **WLAN-Gateway = Advanced-Checkbox, default AUS** (Zonen-Seite → Erweitert):
  schaltet `wlan-sta-lan → ipsec-client` an und die USB-Internet-Regel
  konsequent ab (und umgekehrt). Im Kleingedruckten steht die zweite Wahrheit:
  Im Heimnetz verteilt der fremde Router die Leases — eine Route je Client
  bleibt dort Handarbeit. **Zero-Config gibt es prinzipbedingt nur am
  USB-Kabel, wo der ESP selbst DHCP-Server ist.** Deshalb ist der USB-Dongle
  der Default-Weg.
* **Default-Policy beim Boot** (unveraendert): `usb-lan → bester Uplink`
  (WLAN vor Mobilfunk) einmalig, nie Benutzer-Policies ueberschreiben;
  VPN-Ziele sind bewusst Benutzerwahl.

## 5. RTSP-Default (Kamera-Profile)

Kameras muessen ohne Konfiguration streamen — ueber WLAN/Modem UND IPsec.
Befund: Der Video-Transport-Default war hart `"http"`; in RTSP-only-Builds
(`VIDEO_HTTP=0`, alle surveillance-Profile) startete damit GAR KEIN
Video-Server (Port 554 zu, nur eine Logzeile). Entscheidung:

* RTSP-only-Build → Default `rtsp` (gespeicherte Nutzerwahl gewinnt immer).
* Builds mit beiden Transporten behalten `http` als Default (kein
  Verhaltensbruch fuer Webcam-Profile).
* Der RTSP-Server bindet `INADDR_ANY` und lauscht damit auf ALLEN Interfaces
  gleichzeitig — WLAN, Modem, USB und der IPsec-Tunnel-Adresse. Kein
  Interface-Gating, keine Extra-Konfiguration.

## 6. Betriebswissen

* **IPsec nach ESP-Reboot**: Autostart verbindet, aber die Gegenstelle haelt
  die alte SA — erst Trennen/Verbinden liefert Antworten. Offener Feinschliff:
  automatischer Reconnect-Zyklus nach Boot.
* **Windows-Seite bleibt unkonfiguriert**: Alle Routen kommen per DHCP. Die
  waehrend der Debug-Nacht gesetzten Testrouten wurden entfernt.
* **robocopy in Build-Skripten**: NIEMALS POSIX-Pfade (`/c/...`) an
  PowerShell-robocopy — rc>=8 wird leicht verschluckt und der Build-Spiegel
  veraltet still (kostete einen Blindflash). Gegenmittel im Skript: Windows-
  Pfade, rc-Check, und eine Kontrollzeile, die das erwartete Symbol im
  Spiegel zaehlt, BEVOR kompiliert wird.

## 7. Offen

* IPsec-Auto-Reconnect nach Boot (s. §6).
* LTE-Uplink: gleicher Zonen-Mechanismus, Hardware-Abnahme braucht P4+Modem.
* WLAN-Gateway-Checkbox: UI fertig, Ende-zu-Ende-Test steht aus (braucht
  abgeschaltetes USB-Internet + eine Client-Route).
* WireGuard-Gegenrichtung des PBUF-Musters: wg-Backend-RX-pbufs bei Gelegenheit
  auf Headroom pruefen (usb-lan → wg-* wurde noch nicht hardware-getestet).
