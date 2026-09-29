// ============================================================================
// zone_lwip_hooks.cpp -- Netzzonen 0.3-0.5: Routentabelle (fail-closed), Forward-Policy,
// NAT-Entscheidung je Paar, Commit unter einem Core-Lock, Zaehler, Test-Filter.
// Contract siehe zone_lwip_hooks.h.
// ============================================================================
#include "zone_lwip_hooks.h"
#include "network_platform.h"   // netIfaceNativeHandle

#include "lwip/netif.h"
#include "lwip/ip4_addr.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ip4.h"
#include "lwip/tcpip.h"
#include "lwip/lwip_napt.h"     // ip_napt_enable_netif (unter dem Core-Lock im Commit)
#include <esp_heap_caps.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define WEIRDOS_PBUF_FLAG_DNAT 0x80U   // muss zum Patch in tools/build-lwip-zones.ps1 passen

extern "C" {
    extern const int weirdos_lwip_route_hook_present   __attribute__((weak));
    extern const int weirdos_lwip_forward_hook_present __attribute__((weak));
}
bool zoneLwipRouteHookPresent()   { return &weirdos_lwip_route_hook_present   != nullptr; }
bool zoneLwipForwardHookPresent() { return &weirdos_lwip_forward_hook_present != nullptr; }

// ---- Tabellen (Schreiben nur unter LOCK_TCPIP_CORE) --------------------------------------
struct ZoneRoute   { uint32_t net; uint8_t len; struct netif* nif; bool block; char ifaceId[12]; char source[12]; char note[24]; uint32_t hits, blocks; };
struct ZoneFilter  { char inId[12]; char outId[12]; struct netif* inNif; struct netif* outNif; };
struct ZoneCounter { struct netif* inp; struct netif* outp; uint32_t fwd, dropFilter, dropPolicy, replies; };
struct ZonePair    { struct netif* inp; struct netif* outp; uint8_t mode; char srcId[16]; char dstId[16]; uint32_t fwd, replies, natWanted, natTranslated; };

// Tabellen liegen im PSRAM (internes RAM ist knapp: USB-Host/PPP brauchen internes DMA-RAM). Allokation in
// zoneHooksInit() (setup); ohne Tabellen verhalten sich die Hooks wie Stock und die Verwaltung meldet Fehler.
struct ZoneTables {
    ZoneRoute   routes[ZONE_ROUTE_MAX];
    ZoneFilter  filters[ZONE_FILTER_MAX];
    ZoneCounter counters[ZONE_COUNTER_MAX];
    ZonePair    pairs[ZONE_PAIR_MAX];
    struct netif* naptOurs[ZC_DOMAIN_MAX];
};
static ZoneTables* g_tab = nullptr;
static ZoneRoute*   g_routes = nullptr;   static volatile uint8_t g_nRoutes = 0;
static ZoneFilter*  g_filters = nullptr;  static volatile uint8_t g_nFilters = 0;
static ZoneCounter* g_counters = nullptr; static volatile uint8_t g_nCounters = 0;
static ZonePair*    g_pairs = nullptr;    static volatile uint8_t g_nPairs = 0;
static struct netif** g_naptOurs = nullptr; static uint8_t g_nNaptOurs = 0;   // von UNS gesetzte napt-Flags
String zoneNaptText() {
    String t = String("NAPT: eigene napt-Flags: ") + String((unsigned)g_nNaptOurs) + "\r\n";
    struct netif* n; bool any = false;
    NETIF_FOREACH(n) {
        char nm[8]; snprintf(nm, sizeof(nm), "%c%c%u", n->name[0], n->name[1], (unsigned)n->num);
        t += String("  ") + nm + (netif_is_up(n) ? " up  " : " down") + (n->napt ? "  napt=1" : "  napt=0") + "\r\n";
        if (n->napt) any = true;
    }
    t += String("  -> NAPT-Tabelle ") + (any ? "existiert (mind. ein netif mit napt)" : "NICHT vorhanden (kein netif mit napt -> ip_napt_deinit gelaufen)") + "\r\n";
    return t;
}
bool zoneHooksInit() {
    if (g_tab) return true;
    ZoneTables* t = (ZoneTables*)heap_caps_calloc(1, sizeof(ZoneTables), MALLOC_CAP_SPIRAM);
    if (!t) return false;   // bewusst KEIN Fallback auf internes RAM
    g_routes = t->routes; g_filters = t->filters; g_counters = t->counters; g_pairs = t->pairs; g_naptOurs = t->naptOurs;
    g_tab = t;
    return true;
}
static const char* kNoTables = "Zonen-Tabellen nicht allokiert (PSRAM) -- zoneHooksInit() fehlgeschlagen";
bool zoneHooksReady() { return g_tab != nullptr; }
static volatile bool g_policyMode = false;
static uint32_t g_dropNoRoute = 0, g_routeHits = 0, g_routeMiss = 0, g_routeBlocks = 0, g_counterOverflow = 0, g_dropPolicy = 0, g_dnatReplies = 0, g_natTranslated = 0;

static uint32_t maskOf(uint8_t len) { return len == 0 ? 0 : (len >= 32 ? 0xFFFFFFFFu : ~((1u << (32 - len)) - 1u)); }
static void nifName(const struct netif* n, char* b, size_t bl) {
    if (!n) { snprintf(b, bl, "-"); return; }
    snprintf(b, bl, "%c%c%u", n->name[0], n->name[1], (unsigned)n->num);
}
static bool parseCidr(const String& s, uint32_t& net, uint8_t& len) {
    String t = s; t.trim(); int sl = t.indexOf('/');
    IPAddress ip; int l = 32;
    if (sl > 0) { if (!ip.fromString(t.substring(0, sl))) return false; l = t.substring(sl + 1).toInt(); }
    else if (!ip.fromString(t)) return false;
    if (l < 1 || l > 32) return false;
    len = (uint8_t)l;
    net = (((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) | ((uint32_t)ip[2] << 8) | ip[3]) & maskOf(len);
    return true;
}
static void cidrFmt(uint32_t net, uint8_t len, char* b, size_t bl) {
    snprintf(b, bl, "%u.%u.%u.%u/%u", (unsigned)(net >> 24) & 255u, (unsigned)(net >> 16) & 255u, (unsigned)(net >> 8) & 255u, (unsigned)net & 255u, (unsigned)len);
}
static bool netifRegistered(const struct netif* nif) {
    for (struct netif* n = netif_list; n; n = n->next) if (n == nif) return true;
    return false;
}
static bool netifUsable(const struct netif* nif) {
    return nif && netifRegistered(nif) && netif_is_up(nif) && netif_is_link_up(nif);
}

// ---- Hooks (tcpip-Thread) -------------------------------------------------------------------
extern "C" int weirdos_ip4_route_lookup(const ip4_addr_t* src, const ip4_addr_t* dest, struct netif** out) {
    (void)src;
    if (!dest || !out) return 0;
    uint32_t d = lwip_ntohl(ip4_addr_get_u32(dest));
    ZoneRoute* best = nullptr;
    uint8_t n = g_nRoutes;
    for (uint8_t i = 0; i < n; i++) {
        ZoneRoute& r = g_routes[i];
        if ((d & maskOf(r.len)) != r.net) continue;
        if (!best || r.len > best->len) best = &r;
    }
    if (!best) { g_routeMiss++; return 0; }
    if (best->block || !netifUsable(best->nif)) { best->blocks++; g_routeBlocks++; *out = nullptr; return 2; }
    best->hits++; g_routeHits++;
    *out = best->nif;
    return 1;
}
static ZoneCounter* counterFor(struct netif* inp, struct netif* outp) {
    if (!g_tab) return nullptr;   // keine Tabellen (PSRAM fehlt): nur Stock-Verhalten, keine Zaehler
    uint8_t n = g_nCounters;
    for (uint8_t i = 0; i < n; i++) if (g_counters[i].inp == inp && g_counters[i].outp == outp) return &g_counters[i];
    if (n >= ZONE_COUNTER_MAX) { g_counterOverflow++; return nullptr; }
    ZoneCounter& c = g_counters[n]; memset(&c, 0, sizeof(c)); c.inp = inp; c.outp = outp;
    g_nCounters = (uint8_t)(n + 1);
    return &c;
}
static ZonePair* pairFor(struct netif* inp, struct netif* outp) {
    uint8_t n = g_nPairs;
    for (uint8_t i = 0; i < n; i++) if (g_pairs[i].inp == inp && g_pairs[i].outp == outp) return &g_pairs[i];
    return nullptr;
}
extern "C" int weirdos_ip4_forward_allow(struct pbuf* p, const struct ip_hdr* iphdr, struct netif* inp, struct netif* outp) {
    (void)iphdr;
    if (!outp) { g_dropNoRoute++; return 0; }
    ZoneCounter* c = counterFor(inp, outp);
    uint8_t nf = g_nFilters;
    for (uint8_t i = 0; i < nf; i++) {
        const ZoneFilter& f = g_filters[i];
        if (((f.inNif == nullptr) || (f.inNif == inp)) && ((f.outNif == nullptr) || (f.outNif == outp))) { if (c) c->dropFilter++; return 0; }
    }
    if (!g_policyMode) { if (c) c->fwd++; return 1; }
    ZonePair* pr = pairFor(inp, outp);
    if (pr && netifRegistered(inp) && netifRegistered(outp)) { pr->fwd++; if (c) c->fwd++; return 1; }
    if (p && (p->flags & WEIRDOS_PBUF_FLAG_DNAT)) {
        ZonePair* rev = pairFor(outp, inp);
        if (rev && rev->mode == 2) { rev->replies++; g_dnatReplies++; if (c) { c->fwd++; c->replies++; } return 1; }
    }
    g_dropPolicy++; if (c) c->dropPolicy++;
    return 0;
}
extern "C" int weirdos_ip4_nat_wanted(struct pbuf* p, const struct ip_hdr* iphdr, struct netif* inp, struct netif* outp) {
    (void)p; (void)iphdr;
    if (!g_policyMode) return 1;
    ZonePair* pr = pairFor(inp, outp);
    if (pr && pr->mode == 2) { pr->natWanted++; return 1; }
    return 0;
}
extern "C" void weirdos_ip4_nat_done(struct netif* inp, struct netif* outp) {
    g_natTranslated++;
    ZonePair* pr = pairFor(inp, outp);
    if (pr) pr->natTranslated++;
}

// ---- Konsolen-Routen ---------------------------------------------------------------------------
static int routeIndexLocked(uint32_t net, uint8_t len) {
    for (uint8_t i = 0; i < g_nRoutes; i++) if (g_routes[i].net == net && g_routes[i].len == len) return i;
    return -1;
}
static void routeRemoveAtLocked(int i) {
    for (int k = i; k + 1 < g_nRoutes; k++) g_routes[k] = g_routes[k + 1];
    g_nRoutes = (uint8_t)(g_nRoutes - 1);
}
String zoneRouteAdd(const String& cidr, const String& ifaceId, const String& source) {
    if (!g_tab) return kNoTables;
    uint32_t net; uint8_t len;
    if (!parseCidr(cidr, net, len)) return "ungueltiges Netz (a.b.c.d/1..32; keine Standardroute)";
    struct netif* nif = (struct netif*)netIfaceNativeHandle(ifaceId);
    if (!nif) return "Interface '" + ifaceId + "' nicht aufloesbar (ids: modem-ecm, modem-ppp, wifi-sta, wifi-ap, wg0, ipsec0; muss aktiv sein)";
    String r;
    LOCK_TCPIP_CORE();
    int idx = routeIndexLocked(net, len);
    if (idx < 0) { if (g_nRoutes >= ZONE_ROUTE_MAX) r = "Routentabelle voll (" + String(ZONE_ROUTE_MAX) + ")"; else idx = g_nRoutes; }
    if (idx >= 0) {
        ZoneRoute& e = g_routes[idx]; memset(&e, 0, sizeof(e)); e.net = net; e.len = len; e.nif = nif;
        strncpy(e.ifaceId, ifaceId.c_str(), sizeof(e.ifaceId) - 1); strncpy(e.source, source.c_str(), sizeof(e.source) - 1);
        if (idx == g_nRoutes) g_nRoutes = (uint8_t)(g_nRoutes + 1);
    }
    UNLOCK_TCPIP_CORE();
    return r;
}
String zoneRouteDel(const String& cidr) {
    uint32_t net; uint8_t len;
    if (!parseCidr(cidr, net, len)) return "ungueltiges Netz";
    String r = "nicht gefunden";
    LOCK_TCPIP_CORE();
    int i = routeIndexLocked(net, len);
    if (i >= 0) { routeRemoveAtLocked(i); r = ""; }
    UNLOCK_TCPIP_CORE();
    return r;
}
void zoneRouteClear() {
    LOCK_TCPIP_CORE();
    for (int i = (int)g_nRoutes - 1; i >= 0; i--) if (strcmp(g_routes[i].source, "planner") != 0) routeRemoveAtLocked(i);
    UNLOCK_TCPIP_CORE();
}
int zoneRouteRebind() {
    char ids[ZONE_ROUTE_MAX][12]; bool isCon[ZONE_ROUTE_MAX]; uint8_t n;
    LOCK_TCPIP_CORE(); n = g_nRoutes; for (uint8_t i = 0; i < n; i++) { memcpy(ids[i], g_routes[i].ifaceId, 12); isCon[i] = strcmp(g_routes[i].source, "planner") != 0; } UNLOCK_TCPIP_CORE();
    struct netif* nifs[ZONE_ROUTE_MAX]; int unresolved = 0;
    for (uint8_t i = 0; i < n; i++) { nifs[i] = isCon[i] ? (struct netif*)netIfaceNativeHandle(String(ids[i])) : nullptr; if (isCon[i] && !nifs[i]) unresolved++; }
    LOCK_TCPIP_CORE();
    for (uint8_t i = 0; i < n && i < g_nRoutes; i++) if (isCon[i] && memcmp(ids[i], g_routes[i].ifaceId, 12) == 0) g_routes[i].nif = nifs[i];
    UNLOCK_TCPIP_CORE();
    return unresolved;
}

// ---- Commit (ein Core-Lock) ---------------------------------------------------------------------
void zoneHooksCommit(ZoneCommitInput& in, ZcResult& out) {
    if (!g_tab) {   // keine Tabellen: nichts veroeffentlichen, alles fail-closed melden
        memset(&out, 0, sizeof(out));
        for (int i = 0; i < in.nPairs && i < ZC_PAIR_MAX; i++) strncpy(out.pairReason[i], kNoTables, ZC_REASON_LEN - 1);
        for (int r = 0; r < in.nRoutes && r < ZC_ROUTE_MAX; r++) out.routeBlock[r] = true;
        return;
    }
    LOCK_TCPIP_CORE();
    // 1) NAT-Domains aktivieren (napt-Flag auf dem Eingangsinterface). Ergebnis je Domain.
    for (int d = 0; d < in.nDomains; d++) {
        struct netif* nif = (struct netif*)in.domainNif[d];
        bool ok = false;
        if (nif && netifRegistered(nif) && netif_is_up(nif)) {
            ok = ip_napt_enable_netif(nif, 1) != 0;
            if (ok) { bool have = false; for (uint8_t k = 0; k < g_nNaptOurs; k++) if (g_naptOurs[k] == nif) have = true;
                      if (!have && g_nNaptOurs < ZC_DOMAIN_MAX) g_naptOurs[g_nNaptOurs++] = nif; }
        }
        in.domains[d].naptOk = ok;
    }
    // 2) Resolver: was darf veroeffentlicht werden (fail-closed).
    ZcPair zp[ZC_PAIR_MAX]; ZcRoute zr[ZC_ROUTE_MAX];
    int np = in.nPairs < ZC_PAIR_MAX ? in.nPairs : ZC_PAIR_MAX, nr = in.nRoutes < ZC_ROUTE_MAX ? in.nRoutes : ZC_ROUTE_MAX;
    for (int i = 0; i < np; i++) { zp[i] = in.pairs[i].zc; zp[i].ifacesPresent = in.pairs[i].inp && in.pairs[i].outp && netifRegistered((struct netif*)in.pairs[i].inp) && netifRegistered((struct netif*)in.pairs[i].outp); }
    for (int r = 0; r < nr; r++) { zr[r] = in.routes[r].zc; if (!in.routes[r].nif) zr[r].block = true; }
    zcResolve(zp, np, zr, nr, in.domains, in.nDomains, in.domainOverflow, &out);
    // 3) Routen: Planner-Routen ersetzen (Konsolen-Routen bleiben).
    for (int i = (int)g_nRoutes - 1; i >= 0; i--) if (strcmp(g_routes[i].source, "planner") == 0) routeRemoveAtLocked(i);
    for (int r = 0; r < nr; r++) {
        if (zr[r].len < 1 || zr[r].len > 32) continue;
        uint32_t net = zr[r].net & maskOf(zr[r].len);
        if (routeIndexLocked(net, zr[r].len) >= 0) continue;   // Konsolen-Route hat Vorrang (Test)
        if (g_nRoutes >= ZONE_ROUTE_MAX) break;
        ZoneRoute& e = g_routes[g_nRoutes]; memset(&e, 0, sizeof(e));
        e.net = net; e.len = zr[r].len; e.block = out.routeBlock[r]; e.nif = e.block ? nullptr : (struct netif*)in.routes[r].nif;
        strncpy(e.ifaceId, in.routes[r].ifaceId, sizeof(e.ifaceId) - 1); strncpy(e.source, "planner", sizeof(e.source) - 1); strncpy(e.note, in.routes[r].note, sizeof(e.note) - 1);
        g_nRoutes = (uint8_t)(g_nRoutes + 1);
    }
    // 4) Paare + Policy-Modus (Zaehler bestehender Paare behalten).
    ZonePair fresh[ZONE_PAIR_MAX]; uint8_t cnt = 0;
    for (int i = 0; i < np && cnt < ZONE_PAIR_MAX; i++) {
        if (!out.pairInstalled[i]) continue;
        ZonePair& z = fresh[cnt]; memset(&z, 0, sizeof(z));
        z.inp = (struct netif*)in.pairs[i].inp; z.outp = (struct netif*)in.pairs[i].outp; z.mode = zp[i].mode;
        strncpy(z.srcId, zp[i].srcId, 15); strncpy(z.dstId, zp[i].dstId, 15);
        for (uint8_t k = 0; k < g_nPairs; k++) if (g_pairs[k].inp == z.inp && g_pairs[k].outp == z.outp) { z.fwd = g_pairs[k].fwd; z.replies = g_pairs[k].replies; z.natWanted = g_pairs[k].natWanted; z.natTranslated = g_pairs[k].natTranslated; }
        cnt++;
    }
    memcpy(g_pairs, fresh, sizeof(ZonePair) * cnt);
    g_nPairs = cnt;
    g_policyMode = in.policyMode;
    // 5) Von uns gesetzte napt-Flags entfernen, deren Domain kein installiertes NAT-Paar mehr hat.
    // REGRESSION-REVERT 2026-09-08: der Versuch, das Flag dauerhaft gesetzt zu lassen (0f91869, gegen
    // den DENY->ALLOW-Reboot-Zwang), liess die globale esp-lwIP-NAPT-Tabelle permanent im internen Heap
    // liegen (MEM_LIBC_MALLOC -> malloc -> internes RAM, ~512 Eintraege). Auf dem P4 ist der interne Heap
    // extrem knapp (Sockets/Krypto von IPsec+WG brauchen ihn) -> danach schlugen sowohl der WG->IPsec-Pfad
    // als auch der innere IPsec-Test-Ping fehl, auch nach Reset (Policy beim Boot aktiv -> Tabelle sofort
    // wieder belegt). Reflashen des alten Stands half. Also zurueck: napt aus, sobald keine NAT-Domain mehr.
    // Der DENY->ALLOW-Live-Fall bleibt damit vorerst der bekannte "erst nach Reboot"-Punkt (siehe TODO).
    for (int k = (int)g_nNaptOurs - 1; k >= 0; k--) {
        struct netif* nif = g_naptOurs[k]; bool needed = false;
        for (uint8_t i = 0; i < g_nPairs; i++) if (g_pairs[i].mode == 2 && g_pairs[i].inp == nif) needed = true;
        if (needed) continue;
        if (nif != (struct netif*)in.keepNaptNif && netifRegistered(nif)) ip_napt_enable_netif(nif, 0);
        for (int q = k; q + 1 < g_nNaptOurs; q++) g_naptOurs[q] = g_naptOurs[q + 1];
        g_nNaptOurs--;
    }
    // 6) Veraltete Zaehler/Filter entfernen.
    for (int i = (int)g_nCounters - 1; i >= 0; i--) {
        if (netifRegistered(g_counters[i].inp) && netifRegistered(g_counters[i].outp)) continue;
        for (int k = i; k + 1 < g_nCounters; k++) g_counters[k] = g_counters[k + 1];
        g_nCounters = (uint8_t)(g_nCounters - 1);
    }
    for (int i = (int)g_nFilters - 1; i >= 0; i--) {
        if ((!g_filters[i].inNif || netifRegistered(g_filters[i].inNif)) && (!g_filters[i].outNif || netifRegistered(g_filters[i].outNif))) continue;
        for (int k = i; k + 1 < g_nFilters; k++) g_filters[k] = g_filters[k + 1];
        g_nFilters = (uint8_t)(g_nFilters - 1);
    }
    UNLOCK_TCPIP_CORE();
}

bool zoneRouteMatch(uint32_t ipHost, String& net, String& ifaceId, bool& block) {
    if (!g_tab) return false;
    bool hit = false; char nb[24] = {0}; char ib[12] = {0}; bool bl = false;
    LOCK_TCPIP_CORE();
    const ZoneRoute* best = nullptr;
    for (uint8_t i = 0; i < g_nRoutes; i++) { const ZoneRoute& r = g_routes[i]; if ((ipHost & maskOf(r.len)) != r.net) continue; if (!best || r.len > best->len) best = &r; }
    if (best) { hit = true; cidrFmt(best->net, best->len, nb, sizeof(nb)); memcpy(ib, best->ifaceId, 12); bl = best->block || !netifUsable(best->nif); }
    UNLOCK_TCPIP_CORE();
    if (hit) { net = nb; ifaceId = ib; block = bl; }
    return hit;
}

// ---- Test-Filter -----------------------------------------------------------------------------
String zoneFilterDeny(const String& inIface, const String& outIface) {
    if (!g_tab) return kNoTables;
    struct netif* in = nullptr; struct netif* out = nullptr;
    if (inIface != "*")  { in  = (struct netif*)netIfaceNativeHandle(inIface);  if (!in)  return "Eingangs-Interface '" + inIface + "' nicht aufloesbar"; }
    if (outIface != "*") { out = (struct netif*)netIfaceNativeHandle(outIface); if (!out) return "Ausgangs-Interface '" + outIface + "' nicht aufloesbar"; }
    String r;
    LOCK_TCPIP_CORE();
    if (g_nFilters >= ZONE_FILTER_MAX) r = "Filterliste voll (" + String(ZONE_FILTER_MAX) + ")";
    else {
        ZoneFilter& f = g_filters[g_nFilters]; memset(&f, 0, sizeof(f)); f.inNif = in; f.outNif = out;
        strncpy(f.inId, inIface.c_str(), sizeof(f.inId) - 1); strncpy(f.outId, outIface.c_str(), sizeof(f.outId) - 1);
        g_nFilters = (uint8_t)(g_nFilters + 1);
    }
    UNLOCK_TCPIP_CORE();
    return r;
}
String zoneFilterAllow(const String& inIface, const String& outIface) {
    String r = "keine solche Regel";
    LOCK_TCPIP_CORE();
    for (uint8_t i = 0; i < g_nFilters; i++) {
        if (inIface != g_filters[i].inId || outIface != g_filters[i].outId) continue;
        for (uint8_t k = i; k + 1 < g_nFilters; k++) g_filters[k] = g_filters[k + 1];
        g_nFilters = (uint8_t)(g_nFilters - 1); r = ""; break;
    }
    UNLOCK_TCPIP_CORE();
    return r;
}
void zoneFilterClear() { LOCK_TCPIP_CORE(); g_nFilters = 0; UNLOCK_TCPIP_CORE(); }
void zoneCountersReset() {
    LOCK_TCPIP_CORE();
    g_nCounters = 0; g_dropNoRoute = 0; g_routeHits = 0; g_routeMiss = 0; g_routeBlocks = 0; g_counterOverflow = 0; g_dropPolicy = 0; g_dnatReplies = 0; g_natTranslated = 0;
    for (uint8_t i = 0; i < g_nRoutes; i++) { g_routes[i].hits = 0; g_routes[i].blocks = 0; }
    for (uint8_t i = 0; i < g_nPairs; i++) { g_pairs[i].fwd = 0; g_pairs[i].replies = 0; g_pairs[i].natWanted = 0; g_pairs[i].natTranslated = 0; }
    UNLOCK_TCPIP_CORE();
}

// ---- Snapshot (Heap; Kopie unter dem Lock, Auswertung danach) ------------------------------------
struct RouteView   { char net[24]; char ifaceId[12]; char source[12]; char note[24]; char nifName[8]; bool usable, registered, block; uint32_t hits, blocks; };
struct FilterView  { char inId[12]; char outId[12]; };
struct CounterView { char in[8]; char out[8]; uint32_t fwd, dropFilter, dropPolicy, replies; };
struct PairView    { char in[8]; char out[8]; char srcId[16]; char dstId[16]; uint8_t mode; bool usable, inNapt; uint32_t fwd, replies, natWanted, natTranslated; };
struct ZoneSnapshot {
    RouteView routes[ZONE_ROUTE_MAX]; uint8_t nRoutes;
    FilterView filters[ZONE_FILTER_MAX]; uint8_t nFilters;
    CounterView counters[ZONE_COUNTER_MAX]; uint8_t nCounters;
    PairView pairs[ZONE_PAIR_MAX]; uint8_t nPairs; bool policyMode;
    uint32_t dropNoRoute, routeHits, routeMiss, routeBlocks, counterOverflow, dropPolicy, dnatReplies, natTranslated;
};
static ZoneSnapshot* takeSnapshot() {
    ZoneSnapshot* s = (ZoneSnapshot*)heap_caps_calloc(1, sizeof(ZoneSnapshot), MALLOC_CAP_SPIRAM);
    if (!s) s = (ZoneSnapshot*)calloc(1, sizeof(ZoneSnapshot));
    if (!s) return nullptr;
    LOCK_TCPIP_CORE();
    s->nRoutes = g_nRoutes;
    for (uint8_t i = 0; i < s->nRoutes; i++) {
        const ZoneRoute& r = g_routes[i]; RouteView& v = s->routes[i];
        cidrFmt(r.net, r.len, v.net, sizeof(v.net));
        memcpy(v.ifaceId, r.ifaceId, 12); memcpy(v.source, r.source, 12); memcpy(v.note, r.note, 24);
        v.block = r.block; v.registered = r.nif && netifRegistered(r.nif);
        v.usable = v.registered && netif_is_up(r.nif) && netif_is_link_up(r.nif);
        if (v.registered) nifName(r.nif, v.nifName, sizeof(v.nifName)); else snprintf(v.nifName, sizeof(v.nifName), "-");
        v.hits = r.hits; v.blocks = r.blocks;
    }
    s->nFilters = g_nFilters;
    for (uint8_t i = 0; i < s->nFilters; i++) { memcpy(s->filters[i].inId, g_filters[i].inId, 12); memcpy(s->filters[i].outId, g_filters[i].outId, 12); }
    s->nCounters = g_nCounters;
    for (uint8_t i = 0; i < s->nCounters; i++) {
        nifName(g_counters[i].inp, s->counters[i].in, sizeof(s->counters[i].in)); nifName(g_counters[i].outp, s->counters[i].out, sizeof(s->counters[i].out));
        s->counters[i].fwd = g_counters[i].fwd; s->counters[i].dropFilter = g_counters[i].dropFilter; s->counters[i].dropPolicy = g_counters[i].dropPolicy; s->counters[i].replies = g_counters[i].replies;
    }
    s->nPairs = g_nPairs; s->policyMode = g_policyMode;
    for (uint8_t i = 0; i < s->nPairs; i++) {
        PairView& v = s->pairs[i]; const ZonePair& z = g_pairs[i];
        nifName(z.inp, v.in, sizeof(v.in)); nifName(z.outp, v.out, sizeof(v.out));
        memcpy(v.srcId, z.srcId, 16); memcpy(v.dstId, z.dstId, 16); v.mode = z.mode;
        v.usable = netifUsable(z.inp) && netifUsable(z.outp);
        v.inNapt = netifRegistered(z.inp) && z.inp->napt != 0;
        v.fwd = z.fwd; v.replies = z.replies; v.natWanted = z.natWanted; v.natTranslated = z.natTranslated;
    }
    s->dropNoRoute = g_dropNoRoute; s->routeHits = g_routeHits; s->routeMiss = g_routeMiss; s->routeBlocks = g_routeBlocks; s->counterOverflow = g_counterOverflow;
    s->dropPolicy = g_dropPolicy; s->dnatReplies = g_dnatReplies; s->natTranslated = g_natTranslated;
    UNLOCK_TCPIP_CORE();
    return s;
}

static String hooksLine() {
    String t = "lwIP-Hooks: Route-Hook ";
    t += zoneLwipRouteHookPresent() ? "vorhanden" : "FEHLT (Stock-liblwip.a, Routen wirkungslos)";
    t += ", Forward-Hook ";
    t += zoneLwipForwardHookPresent() ? "vorhanden" : "FEHLT (Stock-liblwip.a, Filter/Policy/Zaehler wirkungslos)";
    return t;
}
String zoneRoutesText() {
    ZoneSnapshot* s = takeSnapshot(); if (!s) return "Snapshot: kein Speicher";
    String t = hooksLine() + "\r\n";
    t += "Zielrouten (" + String((unsigned)s->nRoutes) + "/" + String(ZONE_ROUTE_MAX) + "): Treffer " + String((unsigned long)s->routeHits)
       + ", BLOCK (fail-closed) " + String((unsigned long)s->routeBlocks) + ", kein Treffer " + String((unsigned long)s->routeMiss) + "\r\n";
    for (uint8_t i = 0; i < s->nRoutes; i++) {
        const RouteView& v = s->routes[i];
        t += String("  ") + v.net + " -> " + v.ifaceId + " (" + v.nifName + ", ";
        if (v.block) t += String("BLOCK: ") + v.note;
        else t += v.usable ? "up" : (v.registered ? "DOWN -> BLOCK" : "VERALTET -> BLOCK");
        t += ")  Herkunft: " + String(v.source) + "  Treffer " + String((unsigned long)v.hits) + " Block " + String((unsigned long)v.blocks) + "\r\n";
    }
    if (!s->nRoutes) t += "  (keine)\r\n";
    t += String("Forward-Policy: ") + (s->policyMode ? "aktiv (nur veroeffentlichte Paare + NAT-Antworten, Rest DENY)" : "inaktiv (keine Intents -> Stock: alles weiterleiten)") + "\r\n";
    for (uint8_t i = 0; i < s->nPairs; i++) {
        const PairView& v = s->pairs[i];
        t += String("  ") + v.srcId + " -> " + v.dstId + "  (" + v.in + " -> " + v.out + ")  " + (v.mode == 2 ? "NAT" : "ROUTE") + (v.usable ? "" : "  [Interface down/veraltet]");
        if (v.mode == 2) t += v.inNapt ? "  napt-Flag auf Eingang: ja" : "  napt-Flag auf Eingang: NEIN (keine Uebersetzung!)";
        t += "  weitergeleitet " + String((unsigned long)v.fwd) + ", NAT gewollt " + String((unsigned long)v.natWanted) + ", NAT uebersetzt " + String((unsigned long)v.natTranslated) + ", Antworten " + String((unsigned long)v.replies) + "\r\n";
    }
    free(s);
    return t;
}
String zoneFiltersText() {
    ZoneSnapshot* s = takeSnapshot(); if (!s) return "Snapshot: kein Speicher";
    String t = "Test-Filter (verwerfen; " + String((unsigned)s->nFilters) + "/" + String(ZONE_FILTER_MAX) + "):\r\n";
    for (uint8_t i = 0; i < s->nFilters; i++) t += String("  ") + s->filters[i].inId + " -> " + s->filters[i].outId + "\r\n";
    if (!s->nFilters) t += "  (keine)\r\n";
    free(s);
    return t;
}
String zoneCountersText() {
    ZoneSnapshot* s = takeSnapshot(); if (!s) return "Snapshot: kein Speicher";
    String t = "Forward-Zaehler je (Eingang -> Ausgang): weitergeleitet / Filter / Policy-DENY / NAT-Antworten\r\n";
    for (uint8_t i = 0; i < s->nCounters; i++)
        t += String("  ") + s->counters[i].in + " -> " + s->counters[i].out + ": " + String((unsigned long)s->counters[i].fwd) + " / " + String((unsigned long)s->counters[i].dropFilter)
           + " / " + String((unsigned long)s->counters[i].dropPolicy) + " / " + String((unsigned long)s->counters[i].replies) + "\r\n";
    if (!s->nCounters) t += "  (noch kein weitergeleitetes Paket gesehen)\r\n";
    t += "  ohne Ausgang verworfen: " + String((unsigned long)s->dropNoRoute) + ", Policy-DENY gesamt: " + String((unsigned long)s->dropPolicy)
       + ", NAT uebersetzt gesamt: " + String((unsigned long)s->natTranslated) + ", NAT-Antworten gesamt: " + String((unsigned long)s->dnatReplies);
    if (s->counterOverflow) t += "  (Zaehler-Paare ueber Limit: " + String((unsigned long)s->counterOverflow) + ")";
    free(s);
    return t;
}

String zoneLwipJson() {
    ZoneSnapshot* s = takeSnapshot(); if (!s) return "{\"error\":\"kein Speicher\"}";
    String j = "{\"hooks\":{\"route\":"; j += zoneLwipRouteHookPresent() ? "true" : "false";
    j += ",\"forward\":"; j += zoneLwipForwardHookPresent() ? "true" : "false";
    j += ",\"policyMode\":"; j += s->policyMode ? "true" : "false";
    j += ",\"routeHits\":"; j += String((unsigned long)s->routeHits);
    j += ",\"routeBlocks\":"; j += String((unsigned long)s->routeBlocks);
    j += ",\"routeMiss\":"; j += String((unsigned long)s->routeMiss);
    j += ",\"dropNoRoute\":"; j += String((unsigned long)s->dropNoRoute);
    j += ",\"dropPolicy\":"; j += String((unsigned long)s->dropPolicy);
    j += ",\"dnatReplies\":"; j += String((unsigned long)s->dnatReplies);
    j += ",\"natTranslated\":"; j += String((unsigned long)s->natTranslated);
    j += "},\"routes\":[";
    for (uint8_t i = 0; i < s->nRoutes; i++) {
        const RouteView& v = s->routes[i];
        if (i) j += ",";
        j += String("{\"net\":\"") + v.net + "\",\"iface\":\"" + v.ifaceId + "\",\"netif\":\"" + v.nifName + "\",\"source\":\"" + v.source + "\",\"note\":\"" + v.note
           + "\",\"usable\":" + (v.usable ? "true" : "false") + ",\"block\":" + (v.block ? "true" : "false") + ",\"stale\":" + ((v.block || v.registered) ? "false" : "true")
           + ",\"hits\":" + String((unsigned long)v.hits) + ",\"blocks\":" + String((unsigned long)v.blocks) + "}";
    }
    j += "],\"pairs\":[";
    for (uint8_t i = 0; i < s->nPairs; i++) {
        const PairView& v = s->pairs[i];
        if (i) j += ",";
        j += String("{\"src\":\"") + v.srcId + "\",\"dst\":\"" + v.dstId + "\",\"in\":\"" + v.in + "\",\"out\":\"" + v.out + "\",\"mode\":\"" + (v.mode == 2 ? "NAT" : "ROUTE")
           + "\",\"usable\":" + (v.usable ? "true" : "false") + ",\"inNapt\":" + (v.inNapt ? "true" : "false") + ",\"fwd\":" + String((unsigned long)v.fwd)
           + ",\"natWanted\":" + String((unsigned long)v.natWanted) + ",\"natTranslated\":" + String((unsigned long)v.natTranslated) + ",\"replies\":" + String((unsigned long)v.replies) + "}";
    }
    j += "],\"filters\":[";
    for (uint8_t i = 0; i < s->nFilters; i++) { if (i) j += ","; j += String("{\"in\":\"") + s->filters[i].inId + "\",\"out\":\"" + s->filters[i].outId + "\"}"; }
    j += "],\"counters\":[";
    for (uint8_t i = 0; i < s->nCounters; i++) {
        if (i) j += ",";
        j += String("{\"in\":\"") + s->counters[i].in + "\",\"out\":\"" + s->counters[i].out + "\",\"fwd\":" + String((unsigned long)s->counters[i].fwd) + ",\"dropFilter\":" + String((unsigned long)s->counters[i].dropFilter)
           + ",\"dropPolicy\":" + String((unsigned long)s->counters[i].dropPolicy) + ",\"replies\":" + String((unsigned long)s->counters[i].replies) + "}";
    }
    j += "]}";
    free(s);
    return j;
}
