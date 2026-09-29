// ============================================================================
// zone_commit.cpp -- Netzzonen 0.5: Commit-Resolver (reine Datenlogik). Siehe zone_commit.h.
// ============================================================================
#include "zone_commit.h"
#include <string.h>
#include <stdio.h>

int zcCollectDomains(const ZcPair* pairs, int nPairs, ZcDomain* domains, int maxDomains, bool* overflow) {
    int n = 0; if (overflow) *overflow = false;
    for (int i = 0; i < nPairs; i++) {
        if (pairs[i].mode != 2) continue;
        bool have = false;
        for (int k = 0; k < n; k++) if (strncmp(domains[k].iface, pairs[i].inIface, ZC_ID_LEN) == 0) { have = true; break; }
        if (have) continue;
        if (n >= maxDomains) { if (overflow) *overflow = true; continue; }
        memset(&domains[n], 0, sizeof(ZcDomain));
        strncpy(domains[n].iface, pairs[i].inIface, ZC_ID_LEN - 1);
        domains[n].naptOk = false;
        n++;
    }
    return n;
}

void zcResolve(const ZcPair* pairs, int nPairs, const ZcRoute* routes, int nRoutes,
               const ZcDomain* domains, int nDomains, bool domainOverflow, ZcResult* out) {
    memset(out, 0, sizeof(*out));
    out->nDomains = nDomains; out->domainOverflow = domainOverflow;
    if (nPairs > ZC_PAIR_MAX) nPairs = ZC_PAIR_MAX;
    if (nRoutes > ZC_ROUTE_MAX) nRoutes = ZC_ROUTE_MAX;
    for (int i = 0; i < nPairs; i++) {
        const ZcPair& p = pairs[i];
        if (!p.ifacesPresent) { snprintf(out->pairReason[i], ZC_REASON_LEN, "Interface fehlt/veraltet (%s -> %s)", p.inIface, p.outIface); continue; }
        if (p.mode == 1) { out->pairInstalled[i] = true; continue; }
        if (p.mode != 2) { snprintf(out->pairReason[i], ZC_REASON_LEN, "unbekannter Modus (fail-closed)"); continue; }
        // NAT: Domain muss in der Liste sein UND aktiviert.
        const ZcDomain* d = nullptr;
        for (int k = 0; k < nDomains; k++) if (strncmp(domains[k].iface, p.inIface, ZC_ID_LEN) == 0) { d = &domains[k]; break; }
        if (!d) { snprintf(out->pairReason[i], ZC_REASON_LEN, "Kapazitaet NAT-Domains (%d) erschoepft, kein napt-Flag auf %s -- nicht installiert", ZC_DOMAIN_MAX, p.inIface); continue; }
        if (!d->naptOk) { snprintf(out->pairReason[i], ZC_REASON_LEN, "NAPT auf %s nicht aktivierbar (Interface down oder ip_napt_enable_netif fehlgeschlagen) -- nicht installiert", p.inIface); continue; }
        out->pairInstalled[i] = true;
    }
    for (int r = 0; r < nRoutes; r++) {
        const ZcRoute& rt = routes[r];
        if (rt.block || rt.pairIdx < 0 || rt.pairIdx >= nPairs) { out->routeBlock[r] = true; continue; }
        out->routeBlock[r] = !out->pairInstalled[rt.pairIdx];   // Paar nicht installiert -> Route BLOCK (fail-closed)
    }
}
