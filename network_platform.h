// ============================================================================
// network_platform.h -- Plattform-Bruecke NetIface-id -> natives lwIP-netif (7.4b).
//
// Loest einen fachlichen Interface-Namen (id aus der NetworkRegistry) auf das
// konkrete native lwIP-netif auf. Haelt lwIP/esp_netif-Details aus den Consumern:
// der WireGuardService kennt nur die id und diesen opaken void*. So bleibt
// NetworkInterface fachlich (id/kind/up/ip), native Handles sind Plattformdetail.
//
//   NetIface ("modem-ecm") -> netIfaceNativeHandle() -> struct netif* (void*)
//     modem-ecm -> ecmNetifHandle()  (rohes lwIP-netif)
//     modem-ppp -> pppNetifHandle()  (rohes lwIP-netif)
//     wifi-sta  -> esp_netif WIFI_STA_DEF -> darunterliegendes lwIP-netif
// ============================================================================
#ifndef NETWORK_PLATFORM_H
#define NETWORK_PLATFORM_H

#include <Arduino.h>

// Natives lwIP-netif zum Interface als opaker Zeiger; nullptr wenn nicht aufloesbar/down.
void*  netIfaceNativeHandle(const String& id);

// Diagnose: lwIP-netif-Name+Index (z.B. "st1") oder "" wenn nicht aufloesbar.
String netIfaceNativeName(const String& id);

// Egress fuer Namensaufloesung vorbereiten: fuer Interfaces, deren Resolver sonst nicht
// erreichbar ist (ECM setzt Carrier-DNS global), die Default-Route hierher pinnen.
// Kapselt das Plattform-/ECM-Wissen; Consumer (WireGuardService) kennt kein ECM.
void netIfacePrepareEgress(const String& id);

// 7.6 LAN-Gateway: NAPT (Masquerade) auf dem LAN-Interface an-/ausschalten. Weitergeleitete
// Tunnel-Pakete werden beim Egress ueber dieses netif auf dessen IP maskiert. true = Erfolg.
bool netIfaceSetNapt(const String& id, bool enable);

// 7.9.8: NAPT auf einem nativen lwIP-netif-Handle (z.B. dem WG-netif). esp-lwip markiert das
// PRIVATE/Input-netif mit NAPT (nicht das Output-netif!) - daher gehoert das Flag aufs wg-netif.
bool netIfaceSetNaptNative(void* nativeHandle, bool enable);

// 7.6: LAN-Subnetz des Interfaces als CIDR (z.B. "172.17.1.0/24") aus ip&netmask; "" wenn
// nicht aufloesbar/down. Fuer die AllowedIPs der Client-Config.
String netIfaceSubnetCidr(const String& id);

// 7.9.4 Diagnose: wg-netif-Zustand (up/link/ip/maske) + welches Interface lwIP fuer
// 10.9.0.2 (Tunnel-Client) und 172.17.1.18 (LAN-PC) waehlt. Zeigt Rueckweg-Routing-Bugs.
String wgRouteDiagJson();

#endif // NETWORK_PLATFORM_H
