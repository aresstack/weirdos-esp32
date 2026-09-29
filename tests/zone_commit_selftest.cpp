// ============================================================================
// tests/zone_commit_selftest.cpp -- Host-Selftest fuer den Commit-Resolver (Netzzonen 0.5).
// g++ -std=c++11 -I.. ../zone_commit.cpp zone_commit_selftest.cpp
// Prueft (PO-Rework 0.4/0.5):
//   * NAPT-Aktivierung fehlgeschlagen -> NAT-Paar NICHT installiert, seine Routen BLOCK
//   * mehr NAT-Eingangs-Domains als Kapazitaet -> ueberzaehlige Paare fail-closed (kein un-NATed Forward)
//   * ROUTE-Paare unabhaengig von NAPT; fehlende Interfaces -> nicht installiert
//   * Ergebnis ist EIN vollstaendiges Bild (alle Paare + alle Routen) -> wird in einem Lock veroeffentlicht
// ============================================================================
#include "zone_commit.h"
#include <stdio.h>
#include <string.h>

static int g_fails = 0;
#define CHECK(cond, name) do { if (cond) printf("ok   %s\n", name); else { printf("FAIL %s\n", name); g_fails++; } } while (0)

static void mkPair(ZcPair& p, const char* s, const char* d, const char* in, const char* out, uint8_t mode, bool present = true) {
    memset(&p, 0, sizeof(p)); strncpy(p.srcId, s, ZC_ID_LEN - 1); strncpy(p.dstId, d, ZC_ID_LEN - 1);
    strncpy(p.inIface, in, ZC_ID_LEN - 1); strncpy(p.outIface, out, ZC_ID_LEN - 1); p.mode = mode; p.ifacesPresent = present;
}
static void mkRoute(ZcRoute& r, uint32_t net, uint8_t len, int8_t pairIdx, bool block = false) { r.net = net; r.len = len; r.pairIdx = pairIdx; r.block = block; }

int main() {
    ZcPair pairs[ZC_PAIR_MAX]; ZcRoute routes[ZC_ROUTE_MAX]; ZcDomain dom[ZC_DOMAIN_MAX]; ZcResult res; bool ovf; int nd;

    // Hauptfall: wg0 -> ipsec0 NAT, Domain wg0 aktiviert.
    mkPair(pairs[0], "wg-server", "ipsec-client", "wg0", "ipsec0", 2);
    mkRoute(routes[0], 0xC0A86E00u, 24, 0);
    nd = zcCollectDomains(pairs, 1, dom, ZC_DOMAIN_MAX, &ovf);
    CHECK(nd == 1 && !ovf && strcmp(dom[0].iface, "wg0") == 0, "domains: eine NAT-Domain wg0");
    dom[0].naptOk = true;
    zcResolve(pairs, 1, routes, 1, dom, nd, ovf, &res);
    CHECK(res.pairInstalled[0] && !res.routeBlock[0], "napt ok: NAT-Paar installiert, Route aktiv");

    // NAPT-Aktivierung fehlgeschlagen: Paar NICHT installiert, Route BLOCK.
    dom[0].naptOk = false;
    zcResolve(pairs, 1, routes, 1, dom, nd, ovf, &res);
    CHECK(!res.pairInstalled[0] && strstr(res.pairReason[0], "NAPT") != nullptr, "napt fail: NAT-Paar nicht veroeffentlicht, Grund gesetzt");
    CHECK(res.routeBlock[0], "napt fail: Route wird BLOCK (kein Forwarding ohne Uebersetzung, keine Standardroute)");

    // ROUTE-Paar braucht kein NAPT; fehlendes Interface -> nicht installiert.
    mkPair(pairs[1], "wlan-ap", "wg-server", "wifi-ap", "wg0", 1);
    mkPair(pairs[2], "wg-server", "wlan-ap", "wg0", "wifi-ap", 1, false);
    mkRoute(routes[1], 0x0A090000u, 24, 1); mkRoute(routes[2], 0xC0A80400u, 24, 2);
    nd = zcCollectDomains(pairs, 3, dom, ZC_DOMAIN_MAX, &ovf); dom[0].naptOk = true;
    zcResolve(pairs, 3, routes, 3, dom, nd, ovf, &res);
    CHECK(res.pairInstalled[1] && !res.routeBlock[1], "route pair: installiert ohne NAPT");
    CHECK(!res.pairInstalled[2] && res.routeBlock[2] && strstr(res.pairReason[2], "Interface") != nullptr, "route pair ohne Interface: nicht installiert, Route BLOCK");

    // Kapazitaet: mehr NAT-Domains als Platz -> ueberzaehlige NAT-Paare fail-closed, keine stille Luecke.
    int n = 0;
    for (int i = 0; i < ZC_DOMAIN_MAX + 3; i++) { char in[ZC_ID_LEN]; snprintf(in, sizeof(in), "if%d", i); mkPair(pairs[n], "s", "d", in, "ipsec0", 2); mkRoute(routes[n], 0x0A000000u + ((uint32_t)i << 8), 24, (int8_t)n); n++; }
    nd = zcCollectDomains(pairs, n, dom, ZC_DOMAIN_MAX, &ovf);
    CHECK(nd == ZC_DOMAIN_MAX && ovf, "capacity: Domain-Liste voll, Ueberlauf gemeldet");
    for (int k = 0; k < nd; k++) dom[k].naptOk = true;
    zcResolve(pairs, n, routes, n, dom, nd, ovf, &res);
    { bool okFirst = true, blockedRest = true;
      for (int i = 0; i < ZC_DOMAIN_MAX; i++) okFirst = okFirst && res.pairInstalled[i] && !res.routeBlock[i];
      for (int i = ZC_DOMAIN_MAX; i < n; i++) blockedRest = blockedRest && !res.pairInstalled[i] && res.routeBlock[i] && strstr(res.pairReason[i], "Kapazitaet") != nullptr;
      CHECK(okFirst, "capacity: Paare innerhalb der Kapazitaet installiert");
      CHECK(blockedRest, "capacity: ueberzaehlige NAT-Paare nicht installiert, Routen BLOCK, Grund Kapazitaet"); }
    CHECK(res.domainOverflow, "capacity: Ueberlauf im Ergebnis sichtbar (Diagnose)");

    // Bereits als BLOCK gedachte Route (Ziel down) bleibt BLOCK, auch wenn das Paar installiert waere.
    mkPair(pairs[0], "wg-server", "ipsec-client", "wg0", "ipsec0", 2); mkRoute(routes[0], 0xC0A86E00u, 24, 0, true);
    nd = zcCollectDomains(pairs, 1, dom, ZC_DOMAIN_MAX, &ovf); dom[0].naptOk = true;
    zcResolve(pairs, 1, routes, 1, dom, nd, ovf, &res);
    CHECK(res.routeBlock[0], "down: vorgemerkte BLOCK-Route bleibt BLOCK");

    // Unbekannter Modus: fail-closed.
    mkPair(pairs[0], "a", "b", "x", "y", 7); mkRoute(routes[0], 1, 24, 0);
    nd = zcCollectDomains(pairs, 1, dom, ZC_DOMAIN_MAX, &ovf);
    zcResolve(pairs, 1, routes, 1, dom, nd, ovf, &res);
    CHECK(!res.pairInstalled[0] && res.routeBlock[0], "unknown mode: nicht installiert, Route BLOCK");

    if (g_fails) { printf("ZONE COMMIT SELFTEST FAILED (%d)\n", g_fails); return 1; }
    printf("ZONE COMMIT SELFTEST OK\n");
    return 0;
}
