// ============================================================================
// zone_lwip_hooks.h -- Netzzonen Phase 0.3-0.5: Zielrouten, Forward-Policy, NAT-Entscheidung,
// Zaehler (Sketch-Seite der lwIP-Hooks).
//
// Die Hooks sitzen in EINEM getauschten Objekt des eigenen lwIP-Builds (tools/build-lwip-zones.ps1:
// ip4.c.obj). Contract (alle Symbole schwach referenziert -- fehlt das Sketch-Symbol, Stock-Verhalten):
//
//   int weirdos_ip4_route_lookup(src, dest, struct netif** out)
//        Tri-State in ip4_route_src() UND ip4_route(): 0 NO_MATCH (weiter wie Stock), 1 ROUTE (*out),
//        2 BLOCK (sofort NULL, KEIN Rueckfall auf on-link/ESP-Hook/Standardroute -- fail-closed bei
//        down/entferntem/veraltetem Ausgang oder BLOCK-Eintrag).
//   int weirdos_ip4_forward_allow(p, iphdr, inp, outp)
//        in ip4_forward() NACH der Routingentscheidung, VOR TTL/NAPT; 0 = verwerfen. Policy-Modus
//        (sobald ein Intent existiert): nur veroeffentlichte Paare (ROUTE/NAT) und Antworten von
//        NAT-Fluessen (pbuf-Flag WEIRDOS_PBUF_FLAG_DNAT aus ip4_input) zur Gegenrichtung einer
//        NAT-Policy; alles andere DENY. Ohne Intents Stock (alles weiterleiten), Test-Filter zaehlen.
//   int weirdos_ip4_nat_wanted(p, iphdr, inp, outp)     (0.4) 1 = ip_napt_forward() rufen (Policy NAT),
//        0 = reines Routing. NAT-Domain (napt-Flag) = natives Eingangsinterface.
//   void weirdos_ip4_nat_done(inp, outp)                 (0.5) nur bei TATSAECHLICH geaenderter
//        Quelladresse -> Zaehler natTranslated (Hardware-Gate), getrennt von natWanted.
//   Marker weirdos_lwip_route_hook_present / weirdos_lwip_forward_hook_present.
//
// COMMIT (0.5): ein Apply ist EIN Commit unter LOCK_TCPIP_CORE (zoneHooksCommit): napt-Flags der
// NAT-Domains aktivieren -> Resolver (zone_commit.*) entscheidet fail-closed -> Routen, Paare und
// Policy-Modus in einem Zug veroeffentlichen -> nicht mehr benoetigte, von uns gesetzte napt-Flags
// entfernen. Der tcpip-Thread sieht keinen Zwischenzustand (er haelt waehrend des Commits nicht den
// Core-Lock). Nicht installierbare NAT-Paare (NAPT-Aktivierung fehlgeschlagen, Domain-Kapazitaet)
// werden nicht veroeffentlicht, ihre Routen werden BLOCK.
// Lebensdauer der netif-Zeiger: alle Tabellen speichern Zeiger; die Hooks pruefen je Paket gegen
// netif_list. Die Runtime baut alles bei jeder Registry-Aenderung neu (kein manuelles Rebind).
// Leser kopieren die Tabellen unter dem Lock in einen Heap-Snapshot und bauen Text/JSON danach.
// ============================================================================
#ifndef ZONE_LWIP_HOOKS_H
#define ZONE_LWIP_HOOKS_H

#include <Arduino.h>
#include "zone_commit.h"

#define ZONE_ROUTE_MAX   32
#define ZONE_FILTER_MAX  8
#define ZONE_COUNTER_MAX 16
#define ZONE_PAIR_MAX    32

bool zoneLwipRouteHookPresent();
bool zoneLwipForwardHookPresent();
bool zoneHooksInit();              // Tabellen im PSRAM allokieren (setup, vor zoneRuntimeBegin); false = kein PSRAM
bool zoneHooksReady();

// ---- Konsolen-Routen (0.3-Test; Herkunft "konsole") ----------------------------------------
String zoneRouteAdd(const String& cidr, const String& ifaceId, const String& source);
String zoneRouteDel(const String& cidr);
void   zoneRouteClear();           // nur Konsolen-Routen
int    zoneRouteRebind();          // Konsolen-Routen ueber ifaceId neu aufloesen
String zoneRoutesText();

// ---- Commit (Runtime, 0.5) -------------------------------------------------------------------
struct ZoneCommitPair  { void* inp; void* outp; ZcPair zc; };                      // zc.inIface/outIface = NAT-Domains
struct ZoneCommitRoute { ZcRoute zc; void* nif; char ifaceId[12]; char note[24]; }; // nif = Ziel (NULL -> BLOCK)
struct ZoneCommitInput {
    ZoneCommitPair  pairs[ZONE_PAIR_MAX];  int nPairs;
    ZoneCommitRoute routes[ZONE_ROUTE_MAX]; int nRoutes;
    void*           domainNif[ZC_DOMAIN_MAX];   // netif je NAT-Domain (Reihenfolge wie zcCollectDomains), NULL = nicht aufloesbar
    ZcDomain        domains[ZC_DOMAIN_MAX];     int nDomains; bool domainOverflow;
    bool            policyMode;
    void*           keepNaptNif;                // napt-Flag hier nie entfernen (WireGuard-LAN-Gateway)
};
// Fuehrt den Commit unter EINEM Core-Lock aus; out.pairInstalled/pairReason/routeBlock fuer die Runtime.
void zoneHooksCommit(ZoneCommitInput& in, ZcResult& out);

// Diagnose (D1): passt eine Zonenroute auf ipHost? Liefert Netz, Interface-id und ob sie BLOCK ist.
bool zoneRouteMatch(uint32_t ipHost, String& net, String& ifaceId, bool& block);

// ---- Test-Filter (Konsole) -----------------------------------------------------------------
String zoneFilterDeny(const String& inIface, const String& outIface);
String zoneFilterAllow(const String& inIface, const String& outIface);
void   zoneFilterClear();
String zoneFiltersText();

// ---- Zaehler ---------------------------------------------------------------------------------
String zoneCountersText();

// Diagnose: alle lwIP-netifs mit up/napt-Flag; die globale esp-lwIP-NAPT-Tabelle existiert genau dann, wenn
// irgendein netif napt hat. Konsole: zones napt.
String zoneNaptText();
void   zoneCountersReset();

// JSON-Objekt {"hooks":{...},"routes":[...],"pairs":[...],"filters":[...],"counters":[...]}.
String zoneLwipJson();

#endif // ZONE_LWIP_HOOKS_H
