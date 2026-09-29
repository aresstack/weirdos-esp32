// ============================================================================
// zone_commit.h -- Netzzonen 0.5: Commit-Resolver (reine Datenlogik, host-testbar).
//
// Ein Apply ist EIN Commit unter LOCK_TCPIP_CORE (zone_lwip_hooks: zoneHooksCommit). Innerhalb des
// Commits werden zuerst die NAT-Domains (napt-Flag auf dem nativen Eingangsinterface) aktiviert,
// dann entscheidet dieser Resolver aus den Aktivierungsergebnissen, welche Paare/Routen wirklich
// veroeffentlicht werden -- fail-closed:
//   * NAT-Paar, dessen Domain kein napt-Flag bekam (Aktivierung fehlgeschlagen, Interface down,
//     Kapazitaet der Domain-Liste erschoepft): NICHT installiert, Grund gesetzt, seine Routen werden
//     BLOCK-Eintraege (nie Standardroute, nie Forwarding ohne Uebersetzung).
//   * ROUTE-Paar: installiert, wenn beide Interfaces vorhanden.
// Keine stillen Grenzen: Domain-Kapazitaet = ZC_DOMAIN_MAX; ein Ueberlauf macht das betroffene
// Paar IMPOSSIBLE mit Grund "Kapazitaet NAT-Domains".
// ============================================================================
#ifndef ZONE_COMMIT_H
#define ZONE_COMMIT_H

#include <stdint.h>
#include <stddef.h>

#define ZC_ID_LEN     16
#define ZC_PAIR_MAX   32
#define ZC_ROUTE_MAX  32
#define ZC_DOMAIN_MAX 16      // >= NET_ATTACH_MAX: mehr native Interfaces als Attachments gibt es nicht
#define ZC_REASON_LEN 128

struct ZcPair {
    char    srcId[ZC_ID_LEN];
    char    dstId[ZC_ID_LEN];
    char    inIface[ZC_ID_LEN];    // natives Eingangsinterface (NAT-Domain)
    char    outIface[ZC_ID_LEN];
    uint8_t mode;                  // 1 ROUTE, 2 NAT
    bool    ifacesPresent;         // beide netifs aufgeloest und registriert
};
struct ZcRoute {
    uint32_t net; uint8_t len;
    int8_t   pairIdx;              // Paar, zu dem die Route gehoert (-1: BLOCK-Eintrag ohne Paar)
    bool     block;                // Eingabe: bereits als BLOCK gedacht (Ziel down)
};
struct ZcDomain {
    char iface[ZC_ID_LEN];
    bool naptOk;                   // Ergebnis der Aktivierung (vom Commit gefuellt)
};
struct ZcResult {
    bool pairInstalled[ZC_PAIR_MAX];
    char pairReason[ZC_PAIR_MAX][ZC_REASON_LEN];   // "" wenn installiert
    bool routeBlock[ZC_ROUTE_MAX];                 // Route als BLOCK statt Ziel-Interface installieren
    int  nDomains;
    bool domainOverflow;
};

// Schritt 1: aus den NAT-Paaren die Menge der NAT-Domains (distinct inIface) bilden. Rueckgabe: Anzahl;
// overflow=true, wenn mehr Domains noetig waeren als Platz (die ueberzaehligen Paare scheitern spaeter).
int  zcCollectDomains(const ZcPair* pairs, int nPairs, ZcDomain* domains, int maxDomains, bool* overflow);

// Schritt 2 (nach der Aktivierung): Ergebnis bestimmen. Deterministisch, ohne Seiteneffekte.
void zcResolve(const ZcPair* pairs, int nPairs, const ZcRoute* routes, int nRoutes,
               const ZcDomain* domains, int nDomains, bool domainOverflow, ZcResult* out);

#endif // ZONE_COMMIT_H
