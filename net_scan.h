// ============================================================================
// net_scan.h -- 7.10: LAN-Host-Scan + Ping von der MCU aus (Diagnose/Router-Feature).
// ICMP-Ping-Sweep des wifi-sta-Subnetzes (esp_ping), plus Einzel-Ping. Zeigt, welche
// Rechner im WLAN antworten - u.a. um den MCU->LAN-Pfad (WireGuard-Weiterleitung) zu pruefen.
// ============================================================================
#ifndef NET_SCAN_H
#define NET_SCAN_H

#include <Arduino.h>

// ---- D1/D2 (Netzzonen-Diagnose): generische L3-Werkzeuge, Ziel = beliebiges Netz -------------
// Schichten: L3/L4 (Ping, ICMP-Sweep, Portscan, Resolve) kennen kein WLAN; lokales L2 (ARP-Discovery)
// ist eine Capability des Ausgangsinterfaces (NETIF_FLAG_ETHARP + on-link), nicht "WLAN"; Funk
// (Passiv-Monitor, Kanal-Scans) bleibt WLAN-only. Routing immer durch lwIP/Zonen-Runtime, keine
// Diagnose-Routen, kein Policy-Bypass.
//
// Host-Sweep: target = "a.b.c.d/n" (CIDR) oder Attachment-id aus der Registry (wlan-sta-lan, wlan-ap,
// wg-server, ipsec-client, ...; erstes routingfaehiges Prefix) oder "" (= wlan-sta-lan).
// mode = "auto" (ARP wenn L2 moeglich, sonst ICMP) | "arp" | "icmp". Harte Grenze NET_SWEEP_MAX Ziele:
// groessere Netze werden ABGELEHNT (Fehlertext), nicht still abgeschnitten.
#define NET_SWEEP_MAX 512
String netScanStartTarget(const String& target, const String& mode);   // "" = gestartet, sonst Fehlertext
// Rueckwaerts kompatibel: Sweep des WLAN-Subnetzes (= netScanStartTarget("wlan-sta-lan","auto")).
void   netScanStart();
// {"running","total","scanned","target","mode":"arp|icmp","egress","attachment","error","hosts":[{ip,mac,vendor,ms}]}
String netScanJson();
// Moegliche Sweep-Ziele aus der Registry: [{"attachment","iface","net","prefix","hosts","l2":bool,"source"}]
String netScanTargetsJson();
// Lokaler Routing-Befund fuer eine Ziel-IP (Verkehr VOM P4): Ausgangsinterface, Attachment, Zonenroute,
// TSr-Deckung. Optional from = Quell-Attachment: zusaetzlich Forward-Policy (installiert: ROUTE/NAT/SNAT)
// und Planner-Vorschau -- getrennt vom lokalen Pfad, weil der P4-eigene Verkehr keine Policy durchlaeuft.
String netDiagResolveJson(const String& ip, const String& from);
// Einzel-Ping (synchron, ~timeout). {"ip":"..","up":bool,"ms":n}
String netPingJson(const String& ip);

// 7.11: TCP-Port-Scan (connect-scan) eines Hosts im Hintergrund-Task. from/to <=0 -> haeufige
// Ports; sonst Bereich from..to (gekappt). Findet offene Ports auch auf Ping-toten Rechnern.
// Rueckgabe "" = gestartet, sonst Fehlertext. Ein zu grosser Bereich wird ABGELEHNT (max. NET_PORTSCAN_MAX_TCP /
// NET_PORTSCAN_MAX_UDP Ports je Lauf), nie still gekappt; der JSON nennt den tatsaechlich gescannten Bereich.
#define NET_PORTSCAN_MAX_TCP 4096
#define NET_PORTSCAN_MAX_UDP 512
String netPortScanStart(const String& ip, int fromPort, int toPort, bool udp);
String netPortScanJson();   // {"running","ip","proto","from","to","common":bool,"total","scanned","open":[{"port","svc","state"}]}

// 7.13: Passiv-Monitor (WLAN-Promiscuous). Hoert 'seconds' lang mit, sammelt sendende Geraete
// (MAC + RSSI + Paketzahl) - findet auch Hosts, die auf aktive Scans schweigen. WPA2: nur
// 802.11-Header (MAC/Signal), keine IPs/Payload (verschluesselt). MACs werden mit dem letzten
// ARP-Scan korreliert, um IPs zu zeigen wo bekannt.
void   netSniffStart(int seconds);
String netSniffJson();

// 7.14: Kanal-Uebersicht (WLAN-Scan aggregiert je Kanal: APs, Signal, ueberlappungsgewichtete
// Stoerlast) + Empfehlung des besten Kanals. Hintergrund-Task.
void   netChannelScanStart();
String netChannelScanJson();

// 7.15: Tiefen-Kanal-Scan - Channel-Hopping (Promiscuous) -> aktive Geraete + Traffic je Kanal.
// ACHTUNG: trennt das eigene WLAN waehrend des Sweeps (~17s); Ergebnisse nach Reconnect abrufbar.
void   netDeepChScanStart();
String netDeepChScanJson();

// 8.0: Laeuft gerade ein WLAN-Funk-Recon (Passiv-Monitor / Kanal- / Tiefen-Scan, alle promiscuous/
// hopping)? Fuer die gegenseitige Sperre mit dem BLE-Scan (bt_scan) - beide nutzen das Funkteil.
bool   netReconBusy();

#endif // NET_SCAN_H
