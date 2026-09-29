# Telekom: öffentliche IPv4 für Erreichbarkeit von außen (APN `internet.t-d1.de`)

## Problem

Die Telekom vergibt auf den Standard-Mobilfunk-APNs (`internet.telekom`,
`internet.v6.telekom`) nur eine **CGNAT-IPv4** (`10.x` / `100.64.x`) — von außen
**nicht** erreichbar. Zwar kommt zusätzlich eine **globale IPv6** (`2a01:…`), aber
**eingehendes IPv6 wird bei Telekom-Mobilfunk netzseitig gefiltert** (Hardware-Test:
Seitenaufruf von außen lädt endlos). Für Kamera/VPN-Zugriff von außen ist damit
weder das CGNAT-IPv4 noch das IPv6 nutzbar.

## Lösung (hardware-verifiziert 2026-08-28)

Es gibt bei der Telekom ein funktionierendes Gegenstück zu o2 `netpublic`:

```text
APN:              internet.t-d1.de
PDP-Typ:          IP            (IPv4-only!)
Authentifizierung: keine        (kein Benutzer/Passwort)
```

Damit vergibt die Telekom eine **öffentliche, dynamische IPv4** (Bereich `37.81.x.x`),
die **direkt am Mobilfunkinterface** hängt (kein NAT davor) und für die die Telekom
**eingehendes TCP durchlässt**.

> Hinweis: `internet.t-d1.de` ist kein offiziell dokumentierter Standard-APN, funktioniert
> aber auf der getesteten Business-SIM nachweislich. `PDP-Typ IP` (nicht `IPV4V6`) und
> **keine** Zugangsdaten sind entscheidend.

## Betrieb (WeirdOS)

### Serielle Konsole (P4, headless)

```text
mode ppp
pdp ip
apn internet.t-d1.de
disconnect
connect
```

`mode` schaltet die Datenschicht um und **rebootet den ESP** (der Live-Übergang verklemmt
sonst); nach dem Boot verbindet der PPP-Supervisor automatisch. `status` / `ip` zeigen die
öffentliche WAN-IPv4.

### SIM-Preset (Web-UI, S3)

Preset `telekompublic` (`web_ui_assets.cpp`): `internet.t-d1.de`, PDP `IP`, ohne Auth.

## Verifikation

**1. Öffentliche IPv4 statt CGNAT** — direkt am Modem (AT):

```text
AT+CGDCONT=1,"IP","internet.t-d1.de"
AT+CGACT=1,1
AT+CGPADDR=1
+CGPADDR: 1,"37.81.97.187"                 <- public, kein 10.x/100.64.x
AT+CGCONTRDP=1
+CGCONTRDP: 1,6,"internet.t-d1.de","37.81.97.187",...   <- IP hängt am Interface selbst
```

**2. Eingehendes TCP kommt von außen durch** — TCP-Listener auf dem EC200A, Verbindung
vom Festnetz-Anschluss hinein:

```text
AT+QIACT=1
AT+QIOPEN=1,0,"TCP LISTENER","127.0.0.1",0,8080,0
+QIOPEN: 0,0
AT+QISTATE=1,0
+QISTATE: 0,"TCP LISTENER","37.81.97.187",0,8080,3,1,0,0,"usbat"

# Verbindung von außen (WLAN/Festnetz -> Internet -> Telekom -> SIM):
+QIURC: "incoming",11,0,"78.94.9.92",62060     <- 78.94.9.92 = öffentl. IPv4 der Fritzbox
+QIURC: "recv",11
AT+QIRD=11,64
+QIRD: 16
HELLO-FROM-WAN                                  <- die von außen gesendeten Daten
```

**3. Ende-zu-Ende am ESP-P4** (PPP + `internet.t-d1.de`, Webserver von außen):

```text
status ->  mode PPP, link UP, wan-ip 37.81.89.206
TCP 37.81.89.206:80  -> OFFEN   (UI)
TCP 37.81.89.206:81  -> OFFEN   (MJPEG-Stream)
HTTP GET http://37.81.89.206/  -> 200, WeirdOS-Login-Seite
```

## Topologie

```text
Telekom Business SIM
        │  APN internet.t-d1.de, PDP IP, ohne Auth
        ▼
      EC200A ── PPP ──► öffentliche dynamische IPv4 (37.81.x.x)
        │
        ▼
   ESP-P4 Webserver :80 / :81   ◄── Internet (eingehend, von Telekom durchgelassen)
```

Funktional praktisch identisch zu o2 `netpublic`.

## Empfehlung für den Dauerbetrieb

**PPP + `internet.t-d1.de` + PDP `IP` + DynDNS-A.** Die IPv4 ist dynamisch (bei jedem
PPP-Reconnect kann sie wechseln, z.B. `37.81.97.187` → `37.81.89.206`); der MCU aktualisiert
nach jedem Reconnect den **A-Record** (bestehende IONOS-`ipv4.api.hosting.ionos.com`-URL —
IONOS liest die Quell-IP des Requests, kein `myip=`-Parameter nötig).

**IPv6 ist für diesen Anwendungsfall komplett aus dem kritischen Pfad zu nehmen** (Telekom
filtert eingehend). Der ECM/IPv6-SLAAC-Weg bleibt als Technik im Code (korrekt für Carrier
**ohne** v6-Inbound-Filter), ist aber für Telekom nicht der Weg.
