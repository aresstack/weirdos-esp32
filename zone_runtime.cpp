// ============================================================================
// zone_runtime.cpp -- Netzzonen Phase 0.5: Policy-Runtime. Siehe zone_runtime.h.
//
// Speicher: alle grossen Arbeitsdaten liegen auf dem Heap (PSRAM), NICHT auf dem Stack -- der
// loop-Task hat 16 KB und Planner-Attachments sind ~350 B je Eintrag. Nebenlaeufigkeit: Apply aus
// loop() und aus der Konsole/Web laufen unter einem Mutex.
// Baustein ROUTER (WEIRDOS_FEATURE_ROUTER): bei 0 bleibt nur der Stub am Dateiende (Header unveraendert).
// ============================================================================
#include "weirdos_features.h"
#include "zone_runtime.h"
#if WEIRDOS_FEATURE_ROUTER
#include "zone_planner_adapter.h"
#include "zone_lwip_hooks.h"
#include "network_registry.h"     // netAttachmentById (Validierung der Intent-ids)
#include "network_platform.h"     // netIfaceNativeHandle
#include "wireguard_service.h"    // LAN-Gateway haelt das napt-Flag auf wg0 selbst -> nicht wegnehmen
#include <Preferences.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <string.h>
#include <stdlib.h>

// desired = zuletzt bekannte routingfaehige Ziel-Netze des Ziel-Attachments (CSV), persistent.
// Das ist der GEWUENSCHTE Routing-Zustand fuer Client-Konfigurationen (WireGuard AllowedIPs) und
// haengt NICHT davon ab, ob das Ziel gerade up ist -- ein voruebergehend getrennter IPsec-Tunnel
// laesst 192.168.110.0/24 nicht aus einer neu erzeugten Client-Konfig verschwinden.
// desired: bis zu ZP_ROUTES_MAX (8) Prefixe als CSV; "255.255.255.255/32," x 8 = 152 Zeichen -> 192 reicht IMMER.
// Sollte ein Ziel dennoch mehr liefern, wird NICHT abgeschnitten, sondern der alte Stand behalten und
// desiredOverflow gemeldet (nie ein halbes CIDR in WireGuard-AllowedIPs).
#define ZONE_DESIRED_LEN 192
struct ZoneIntentEntry { char src[ZP_ID_LEN]; char dst[ZP_ID_LEN]; ZoneIntent intent; char desired[ZONE_DESIRED_LEN]; bool desiredOverflow; };
// Intents/Plaene/Cache liegen im PSRAM (internes RAM ist knapp: USB-Host/PPP brauchen internes DMA-RAM).
static ZoneIntentEntry* g_intents = nullptr;
static int             g_nIntents = 0;

struct ZoneRouteCache { ZpPrefix routes[ZP_ROUTES_MAX]; uint8_t n; char dstIface[ZP_ID_LEN]; bool valid; };
static ZonePlan*       g_plans = nullptr;
static ZoneRouteCache* g_cache = nullptr;
static int            g_nPlans = 0;
static bool           g_dirty = true;
static uint32_t       g_lastFingerprint = 0, g_lastPollMs = 0, g_applyCount = 0, g_lastApplyMs = 0;
static SemaphoreHandle_t g_mutex = nullptr;
static bool           g_lastDomainOverflow = false; static int g_lastDomains = 0;
static String         g_commitError;   // "" = letzter Commit ausgefuehrt; sonst Grund (Preflight-Kapazitaet)

// Arbeitsspeicher eines Apply-Laufs (Heap).
struct ZoneWork {
    ZpAttachment    att[NET_ATTACH_MAX];
    ZonePolicyIn    pol[ZONE_INTENT_MAX];
    ZoneCommitInput in;
    ZcResult        res;
};
static void* bigAlloc(size_t n) { void* p = heap_caps_calloc(1, n, MALLOC_CAP_SPIRAM); if (!p) p = calloc(1, n); return p; }

// ---- Persistenz ----------------------------------------------------------------------------
// Format je Eintrag: src>dst=INTENT|desired-csv;   (der |-Teil ist optional, Kompatibilitaet zu v1)
static void saveIntents() {
    String s;
    for (int i = 0; i < g_nIntents; i++) { s += g_intents[i].src; s += ">"; s += g_intents[i].dst; s += "="; s += zoneIntentName(g_intents[i].intent); if (g_intents[i].desired[0]) { s += "|"; s += g_intents[i].desired; } s += ";"; }
    Preferences p; p.begin("zones", false); p.putString("pol", s); p.putUChar("v", 2); p.end();
}
static void loadIntents() {
    Preferences p; p.begin("zones", true); String s = p.getString("pol", ""); p.end();
    g_nIntents = 0;
    while (s.length() && g_nIntents < ZONE_INTENT_MAX) {
        int semi = s.indexOf(';'); String one = semi < 0 ? s : s.substring(0, semi); s = semi < 0 ? String("") : s.substring(semi + 1);
        int gt = one.indexOf('>'), eq = one.indexOf('=');
        if (gt <= 0 || eq <= gt) continue;
        int bar = one.indexOf('|', eq);
        String intentWord = bar < 0 ? one.substring(eq + 1) : one.substring(eq + 1, bar);
        bool ok; ZoneIntent in = zoneIntentParse(intentWord, ok);
        if (!ok) continue;
        ZoneIntentEntry& e = g_intents[g_nIntents++]; memset(&e, 0, sizeof(e));
        strncpy(e.src, one.substring(0, gt).c_str(), ZP_ID_LEN - 1); strncpy(e.dst, one.substring(gt + 1, eq).c_str(), ZP_ID_LEN - 1); e.intent = in;
        if (bar >= 0) strncpy(e.desired, one.substring(bar + 1).c_str(), sizeof(e.desired) - 1);
    }
}
// Gewuenschte Ziel-Netze eines Intents aus dem aktuellen Registry-Bild auffrischen (nur wenn das Ziel
// gerade Prefixe liefert; sonst bleibt der letzte bekannte Stand). true = geaendert (persistieren).
static bool refreshDesired(ZoneIntentEntry& e, const ZpAttachment* att, int nAtt) {
    const ZpAttachment* d = nullptr;
    for (int k = 0; k < nAtt; k++) if (!strncmp(att[k].id, e.dst, ZP_ID_LEN)) d = &att[k];
    if (!d || !d->up || !d->reach.known || d->reach.any || d->reach.n == 0) return false;
    String csv; char b[24];
    for (uint8_t i = 0; i < d->reach.n; i++) { zpFormatPrefix(d->reach.items[i], b, sizeof(b)); if (csv.length()) csv += ","; csv += b; }
    if (csv.length() >= sizeof(e.desired)) { bool was = e.desiredOverflow; e.desiredOverflow = true; return !was; }   // nie abschneiden: alter Stand bleibt, Overflow sichtbar
    e.desiredOverflow = false;
    if (csv == e.desired) return false;
    strncpy(e.desired, csv.c_str(), sizeof(e.desired) - 1); e.desired[sizeof(e.desired) - 1] = 0;
    return true;
}

// ---- Fingerprint (FNV-1a ueber die Planner-Attachments ohne Zaehler + netif-Zeiger) --------------
static uint32_t fnv(uint32_t h, const void* d, size_t n) { const uint8_t* b = (const uint8_t*)d; for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 16777619u; } return h; }
static uint32_t fingerprint(const ZpAttachment* att, int n) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < n; i++) {
        const ZpAttachment& a = att[i];
        h = fnv(h, a.id, ZP_ID_LEN); h = fnv(h, a.ifaceId, ZP_ID_LEN); h = fnv(h, &a.kind, 1); h = fnv(h, &a.up, 1);
        h = fnv(h, &a.local, 4); h = fnv(h, &a.localLen, 1); h = fnv(h, &a.mtu, 2);
        const ZpPrefixSet* sets[4] = { &a.srcNets, &a.acceptSrc, &a.reach, &a.returnTo };
        for (int k = 0; k < 4; k++) { h = fnv(h, &sets[k]->n, 1); h = fnv(h, &sets[k]->any, 1); h = fnv(h, &sets[k]->known, 1); h = fnv(h, sets[k]->items, sizeof(ZpPrefix) * sets[k]->n); }
        void* nif = netIfaceNativeHandle(String(a.ifaceId)); h = fnv(h, &nif, sizeof(nif));
    }
    return h;
}

// ---- Kompilieren + Commit (ein Core-Lock) --------------------------------------------------------
static void applyNow(ZoneWork* w) {
    int nAtt = zoneAdapterBuild(w->att, NET_ATTACH_MAX);
    for (int i = 0; i < g_nIntents; i++) { memset(&w->pol[i], 0, sizeof(w->pol[i])); strncpy(w->pol[i].srcId, g_intents[i].src, ZP_ID_LEN - 1); strncpy(w->pol[i].dstId, g_intents[i].dst, ZP_ID_LEN - 1); w->pol[i].intent = g_intents[i].intent; }
    g_nPlans = g_nIntents ? zoneCompilePolicies(w->pol, g_nIntents, w->att, nAtt, g_plans, ZONE_INTENT_MAX, true /* per-Policy-NAT (0.4) */) : 0;

    // Gewuenschte Ziel-Netze (fuer Client-Konfigs) aus dem Registry-Bild auffrischen, unabhaengig vom Plan.
    { bool changed = false; for (int i = 0; i < g_nIntents; i++) if (g_intents[i].intent != ZI_DENY && refreshDesired(g_intents[i], w->att, nAtt)) changed = true; if (changed) saveIntents(); }

    // PREFLIGHT (PO): der gesamte Commit muss in die Tabellen passen -- sonst KEINE Teilinstallation:
    // alter (sicherer) Zustand bleibt installiert, Fehler wird gemeldet, alle Plaene zeigen den Grund.
    {
        int needPairs = 0, needRoutes = 0, needDomains = 0;
        char domIf[ZONE_INTENT_MAX][ZP_ID_LEN];
        for (int i = 0; i < g_nPlans; i++) {
            const ZonePlan& pl = g_plans[i];
            if (pl.mode == ZE_ROUTE || pl.mode == ZE_NAT) {
                needPairs++; needRoutes += pl.nRoutes;
                if (pl.mode == ZE_NAT) {   // NAT-Domain = natives Eingangsinterface der Quelle (distinct zaehlen)
                    const char* ifc = "";
                    for (int k = 0; k < nAtt; k++) if (!strncmp(w->att[k].id, pl.srcId, ZP_ID_LEN)) { ifc = w->att[k].ifaceId; break; }
                    bool have = false; for (int d = 0; d < needDomains; d++) if (!strncmp(domIf[d], ifc, ZP_ID_LEN)) have = true;
                    if (!have && needDomains < ZONE_INTENT_MAX) { strncpy(domIf[needDomains], ifc, ZP_ID_LEN - 1); domIf[needDomains][ZP_ID_LEN - 1] = 0; needDomains++; }
                }
            }
            else if (pl.mode != ZE_DENY && g_cache[i].valid) needRoutes += g_cache[i].n;   // Fail-closed-BLOCK-Routen
        }
        String err;
        if (needPairs > ZONE_PAIR_MAX) err = "Paar-Kapazitaet: " + String(needPairs) + " > " + String(ZONE_PAIR_MAX);
        else if (needRoutes > ZONE_ROUTE_MAX) err = "Routen-Kapazitaet: " + String(needRoutes) + " Routen (inkl. BLOCK) > " + String(ZONE_ROUTE_MAX);
        else if (needDomains > ZC_DOMAIN_MAX) err = "NAT-Domain-Kapazitaet: " + String(needDomains) + " Eingangsinterfaces > " + String(ZC_DOMAIN_MAX);
        if (err.length()) {
            g_commitError = "Commit abgelehnt (" + err + ") -- vorheriger installierter Zustand bleibt bestehen";
            for (int i = 0; i < g_nPlans; i++) { g_plans[i].mode = ZE_IMPOSSIBLE; g_plans[i].natSource = 0; g_plans[i].nRoutes = 0; strncpy(g_plans[i].reason, g_commitError.c_str(), ZP_REASON_LEN - 1); g_plans[i].reason[ZP_REASON_LEN - 1] = 0; }
            g_dirty = false;   // erst eine Aenderung (Intents/Registry) loest den naechsten Versuch aus
            return;
        }
        g_commitError = "";
    }

    ZoneCommitInput& in = w->in; memset(&in, 0, sizeof(in));
    int pairOfPlan[ZONE_INTENT_MAX]; for (int i = 0; i < ZONE_INTENT_MAX; i++) pairOfPlan[i] = -1;

    for (int i = 0; i < g_nPlans; i++) {
        ZonePlan& pl = g_plans[i];
        const ZpAttachment* s = nullptr; const ZpAttachment* d = nullptr;
        for (int k = 0; k < nAtt; k++) { if (!strncmp(w->att[k].id, pl.srcId, ZP_ID_LEN)) s = &w->att[k]; if (!strncmp(w->att[k].id, pl.dstId, ZP_ID_LEN)) d = &w->att[k]; }
        void* sNif = s ? netIfaceNativeHandle(String(s->ifaceId)) : nullptr;
        void* dNif = d ? netIfaceNativeHandle(String(d->ifaceId)) : nullptr;

        if ((pl.mode == ZE_ROUTE || pl.mode == ZE_NAT) && sNif && dNif && in.nPairs < ZONE_PAIR_MAX) {
            // Kapazitaet: passen nicht ALLE Routen dieses Plans + das Paar in die Commit-Tabellen, wird der
            // Plan gar nicht installiert (fail-closed, IMPOSSIBLE) statt Routen still abzuschneiden.
            if (in.nRoutes + (int)pl.nRoutes > ZONE_ROUTE_MAX) {
                pl.mode = ZE_IMPOSSIBLE; pl.natSource = 0; pl.nRoutes = 0;
                snprintf(pl.reason, ZP_REASON_LEN, "Routen-Kapazitaet erschoepft (max. %d) -- Policy nicht installiert", ZONE_ROUTE_MAX);
                g_cache[i].valid = false;
                continue;
            }
            int pi = in.nPairs++; pairOfPlan[i] = pi;
            ZoneCommitPair& pr = in.pairs[pi]; pr.inp = sNif; pr.outp = dNif;
            strncpy(pr.zc.srcId, pl.srcId, ZC_ID_LEN - 1); strncpy(pr.zc.dstId, pl.dstId, ZC_ID_LEN - 1);
            strncpy(pr.zc.inIface, s->ifaceId, ZC_ID_LEN - 1); strncpy(pr.zc.outIface, d->ifaceId, ZC_ID_LEN - 1);
            pr.zc.mode = (pl.mode == ZE_NAT) ? 2 : 1;
            for (uint8_t r = 0; r < pl.nRoutes; r++) {
                ZoneCommitRoute& zr = in.routes[in.nRoutes++]; zr.zc.net = pl.routes[r].net; zr.zc.len = pl.routes[r].len; zr.zc.pairIdx = (int8_t)pi; zr.zc.block = false; zr.nif = dNif;
                strncpy(zr.ifaceId, d->ifaceId, 11); snprintf(zr.note, sizeof(zr.note), "%s>%s", pl.srcId, pl.dstId);
            }
            g_cache[i].n = pl.nRoutes; memcpy(g_cache[i].routes, pl.routes, sizeof(pl.routes)); strncpy(g_cache[i].dstIface, d->ifaceId, ZP_ID_LEN - 1); g_cache[i].valid = true;
        } else if (pl.mode != ZE_DENY && g_cache[i].valid && in.nRoutes + (int)g_cache[i].n <= ZONE_ROUTE_MAX) {
            // Fail-closed: Zielnetze der zuletzt gueltigen Planung bleiben BLOCK-Routen (nie Standardroute).
            for (uint8_t r = 0; r < g_cache[i].n && in.nRoutes < ZONE_ROUTE_MAX; r++) {
                ZoneCommitRoute& zr = in.routes[in.nRoutes++]; zr.zc.net = g_cache[i].routes[r].net; zr.zc.len = g_cache[i].routes[r].len; zr.zc.pairIdx = -1; zr.zc.block = true; zr.nif = nullptr;
                strncpy(zr.ifaceId, g_cache[i].dstIface, 11); snprintf(zr.note, sizeof(zr.note), "%s down", g_cache[i].dstIface);
            }
        } else if (pl.mode == ZE_DENY) {
            g_cache[i].valid = false;
        }
    }
    for (int i = g_nPlans; i < ZONE_INTENT_MAX; i++) g_cache[i].valid = false;

    // NAT-Domains (distinct Eingangsinterfaces der NAT-Paare) + deren netifs.
    ZcPair zp[ZC_PAIR_MAX]; for (int i = 0; i < in.nPairs; i++) zp[i] = in.pairs[i].zc;
    in.nDomains = zcCollectDomains(zp, in.nPairs, in.domains, ZC_DOMAIN_MAX, &in.domainOverflow);
    for (int d = 0; d < in.nDomains; d++) { in.domainNif[d] = nullptr; for (int i = 0; i < in.nPairs; i++) if (!strncmp(in.pairs[i].zc.inIface, in.domains[d].iface, ZC_ID_LEN)) { in.domainNif[d] = in.pairs[i].inp; break; } }
    in.policyMode = g_nIntents > 0;
    in.keepNaptNif = (wireguardService.isUp() && wireguardService.isServerRole() && wireguardService.config().lanGateway) ? wireguardService.nativeNetif() : nullptr;

    // EIN Commit unter dem Core-Lock: napt-Flags -> Resolver -> Routen/Paare/Policy-Modus.
    zoneHooksCommit(in, w->res);
    g_lastDomains = w->res.nDomains; g_lastDomainOverflow = w->res.domainOverflow;

    // Nicht veroeffentlichte Paare im Plan sichtbar machen (IMPOSSIBLE mit Grund aus dem Commit).
    for (int i = 0; i < g_nPlans; i++) {
        int pi = pairOfPlan[i];
        if (pi < 0 || w->res.pairInstalled[pi]) continue;
        g_plans[i].mode = ZE_IMPOSSIBLE; g_plans[i].natSource = 0;
        strncpy(g_plans[i].reason, w->res.pairReason[pi], ZP_REASON_LEN - 1); g_plans[i].reason[ZP_REASON_LEN - 1] = 0;
    }
    g_applyCount++; g_lastApplyMs = millis(); g_dirty = false;
}

// true = ein noetiger Commit wurde ausgefuehrt (oder es gab nichts zu tun); false = Commit konnte NICHT
// laufen (Mutex belegt oder kein Speicher) -> g_dirty bleibt gesetzt, der loop-Poll holt es nach.
static bool runLocked(bool force) {
    if (!g_mutex) g_mutex = xSemaphoreCreateMutex();
    if (g_mutex && xSemaphoreTake(g_mutex, pdMS_TO_TICKS(2000)) != pdTRUE) return false;
    ZoneWork* w = (ZoneWork*)bigAlloc(sizeof(ZoneWork));
    bool ran = false, need = false;
    if (w) {
        bool doApply = force || g_dirty;
        if (!doApply) {
            int n = zoneAdapterBuild(w->att, NET_ATTACH_MAX);
            uint32_t fp = fingerprint(w->att, n);
            if (fp != g_lastFingerprint) { g_lastFingerprint = fp; doApply = true; }
        } else {
            int n = zoneAdapterBuild(w->att, NET_ATTACH_MAX);
            g_lastFingerprint = fingerprint(w->att, n);
        }
        need = doApply;
        if (doApply) { applyNow(w); ran = true; }   // applyNow setzt g_dirty = false
        free(w);
    }
    if (g_mutex) xSemaphoreGive(g_mutex);
    return need ? ran : true;   // nichts zu tun zaehlt als Erfolg
}

static bool g_ready = false;
void zoneRuntimeBegin() {
    if (!g_intents) g_intents = (ZoneIntentEntry*)heap_caps_calloc(ZONE_INTENT_MAX, sizeof(ZoneIntentEntry), MALLOC_CAP_SPIRAM);
    if (!g_plans)   g_plans   = (ZonePlan*)heap_caps_calloc(ZONE_INTENT_MAX, sizeof(ZonePlan), MALLOC_CAP_SPIRAM);
    if (!g_cache)   g_cache   = (ZoneRouteCache*)heap_caps_calloc(ZONE_INTENT_MAX, sizeof(ZoneRouteCache), MALLOC_CAP_SPIRAM);
    g_ready = g_intents && g_plans && g_cache && zoneHooksInit();
    if (!g_ready) { Serial.println("[zones] PSRAM-Allokation fehlgeschlagen -- Zonen-Runtime deaktiviert"); return; }
    loadIntents(); g_dirty = true; if (!g_mutex) g_mutex = xSemaphoreCreateMutex();
    // Migration (einmalig): alte WireGuard-Option "LAN-Gateway" -> Zonen-Policies wg-server -> Heimnetz
    // (Ziel wifi = wlan-sta-lan, ap = wlan-ap, both = beide), danach ist die alte Option aus, damit nicht
    // zwei konkurrierende Mechanismen (Service-NAPT und Zonen-Commit) dasselbe napt-Flag verwalten.
    {
        Preferences p; p.begin("zones", false);
        bool done = p.getUChar("migLan", 0) != 0;
        if (!done) {
            WireGuardConfig wc = wireguardService.config();
            bool complete = true;   // transaktional: Legacy-Option erst aus, wenn ALLE Ziel-Intents existieren
            if (wc.lanGateway) {
                const char* targets[2] = { nullptr, nullptr }; int nt = 0;
                if (wc.lanTarget == "wifi" || wc.lanTarget == "both") targets[nt++] = "wlan-sta-lan";
                if (wc.lanTarget == "ap"   || wc.lanTarget == "both") targets[nt++] = "wlan-ap";
                bool added = false;
                for (int t = 0; t < nt; t++) {
                    bool have = false; for (int i = 0; i < g_nIntents; i++) if (!strcmp(g_intents[i].src, "wg-server") && !strcmp(g_intents[i].dst, targets[t])) have = true;
                    if (have) continue;
                    if (g_nIntents >= ZONE_INTENT_MAX) { complete = false; break; }   // kein Platz -> Migration NICHT abschliessen
                    ZoneIntentEntry& e = g_intents[g_nIntents++]; memset(&e, 0, sizeof(e));
                    strncpy(e.src, "wg-server", ZP_ID_LEN - 1); strncpy(e.dst, targets[t], ZP_ID_LEN - 1); e.intent = ZI_ALLOW_AUTO; added = true;
                }
                if (added) saveIntents();
                if (complete) {
                    wc.lanGateway = false;
                    wireguardService.saveConfig(wc, "", "");   // Secrets leer = behalten
                    Serial.printf("[zones] Migration: WireGuard LAN-Gateway (%s) -> Zonen-Policy wg-server -> Heimnetz, alte Option aus\r\n", wc.lanTarget.c_str());
                } else {
                    Serial.println("[zones] Migration LAN-Gateway NICHT abgeschlossen: Policy-Kapazitaet voll -- alte Option bleibt aktiv, Versuch beim naechsten Start");
                }
            }
            if (complete) p.putUChar("migLan", 1);
        }
        p.end();
    }
}

void zoneRuntimePoll() {
    if (!g_ready) return;
    uint32_t now = millis();
    if (!g_dirty && (now - g_lastPollMs) < 1000) return;
    g_lastPollMs = now;
    if (g_nIntents == 0 && !g_dirty && g_nPlans == 0) return;
    runLocked(false);
}
bool zoneRuntimeApply() { if (!g_ready) return false; g_dirty = true; return runLocked(true); }

// ---- Intents ---------------------------------------------------------------------------------
String zoneRuntimeSetPolicy(const String& src, const String& dst, const String& intentWord) {
    if (!g_ready) return "Zonen-Runtime deaktiviert (PSRAM-Allokation fehlgeschlagen)";
    bool ok; ZoneIntent in = zoneIntentParse(intentWord, ok);
    if (!ok) return "Intent: allow (ALLOW_AUTO) | deny | route (ROUTE_ONLY) | nat (NAT_ONLY)";
    if (!src.length() || !dst.length() || src.length() >= ZP_ID_LEN || dst.length() >= ZP_ID_LEN) return "Attachment-ids fehlen/zu lang";
    if (src == dst) return "Quelle und Ziel sind dasselbe Attachment";
    NetAttachment tmp;
    if (!netAttachmentById(src, tmp)) return "Quell-Attachment '" + src + "' unbekannt (siehe 'zones')";
    if (!netAttachmentById(dst, tmp)) return "Ziel-Attachment '" + dst + "' unbekannt (siehe 'zones')";
    int idx = -1;
    for (int i = 0; i < g_nIntents; i++) if (src == g_intents[i].src && dst == g_intents[i].dst) idx = i;
    if (idx < 0) { if (g_nIntents >= ZONE_INTENT_MAX) return "maximal " + String(ZONE_INTENT_MAX) + " Policies"; idx = g_nIntents++; memset(&g_intents[idx], 0, sizeof(g_intents[idx])); strncpy(g_intents[idx].src, src.c_str(), ZP_ID_LEN - 1); strncpy(g_intents[idx].dst, dst.c_str(), ZP_ID_LEN - 1); }
    g_intents[idx].intent = in;
    saveIntents(); g_cache[idx].valid = false;
    // Intent ist persistent gespeichert; wenn der Commit gerade nicht laufen kann, holt der loop-Poll ihn nach.
    if (!zoneRuntimeApply()) return "gespeichert, aber Installation verschoben (Runtime belegt oder kein Speicher) -- wird im Hintergrund nachgeholt";
    return "";
}
String zoneRuntimeDelPolicy(const String& src, const String& dst) {
    if (!g_ready) return "Zonen-Runtime deaktiviert (PSRAM-Allokation fehlgeschlagen)";
    for (int i = 0; i < g_nIntents; i++) {
        if (src != g_intents[i].src || dst != g_intents[i].dst) continue;
        for (int k = i; k + 1 < g_nIntents; k++) { g_intents[k] = g_intents[k + 1]; g_cache[k] = g_cache[k + 1]; }
        g_nIntents--; g_cache[g_nIntents].valid = false;
        saveIntents();
        if (!zoneRuntimeApply()) return "entfernt, aber Installation verschoben (Runtime belegt oder kein Speicher) -- wird im Hintergrund nachgeholt";
        return "";
    }
    return "keine solche Policy";
}
int zoneRuntimeIntentCount() { return g_ready ? g_nIntents : 0; }
String zoneRuntimeDesiredCidrsFrom(const String& srcAttachment) {
    if (!g_ready) return "";
    String r;
    for (int i = 0; i < g_nIntents; i++) {
        if (srcAttachment != g_intents[i].src || g_intents[i].intent == ZI_DENY) continue;
        String rest = g_intents[i].desired;
        while (rest.length()) {
            int c = rest.indexOf(','); String one = c < 0 ? rest : rest.substring(0, c); rest = c < 0 ? String("") : rest.substring(c + 1); one.trim();
            if (!one.length() || (", " + r + ", ").indexOf(", " + one + ", ") >= 0) continue;
            if (r.length()) { r += ", "; }
            r += one;
        }
    }
    return r;
}
String zoneRuntimeReachableCidrsFrom(const String& srcAttachment) {
    if (!g_ready) return "";
    String r; char b[24];
    for (int i = 0; i < g_nIntents && i < g_nPlans; i++) {
        if (srcAttachment != g_intents[i].src) continue;
        const ZonePlan& p = g_plans[i];
        if (p.mode != ZE_ROUTE && p.mode != ZE_NAT) continue;
        for (uint8_t k = 0; k < p.nRoutes; k++) {
            zpFormatPrefix(p.routes[k], b, sizeof(b)); String c(b);
            if ((", " + r + ", ").indexOf(", " + c + ", ") >= 0) continue;   // Duplikat
            if (r.length()) { r += ", "; }
            r += c;
        }
    }
    return r;
}
bool zoneRuntimePlanFor(const String& src, const String& dst, String& mode, String& reason, String& natSource) {
    if (!g_ready) return false;
    for (int i = 0; i < g_nIntents && i < g_nPlans; i++) {
        if (src != g_intents[i].src || dst != g_intents[i].dst) continue;
        const ZonePlan& p = g_plans[i];
        mode = zoneEffectiveName(p.mode); reason = p.reason;
        natSource = ""; if (p.natSource) { char b[20]; snprintf(b, sizeof(b), "%u.%u.%u.%u", (unsigned)(p.natSource >> 24) & 255u, (unsigned)(p.natSource >> 16) & 255u, (unsigned)(p.natSource >> 8) & 255u, (unsigned)p.natSource & 255u); natSource = b; }
        return true;
    }
    return false;
}

// ---- Anzeige ---------------------------------------------------------------------------------
static String ipStr(uint32_t v) { char b[20]; snprintf(b, sizeof(b), "%u.%u.%u.%u", (unsigned)(v >> 24) & 255u, (unsigned)(v >> 16) & 255u, (unsigned)(v >> 8) & 255u, (unsigned)v & 255u); return String(b); }
static String routesCsv(const ZonePlan& p) { String r; char b[24]; for (uint8_t i = 0; i < p.nRoutes; i++) { zpFormatPrefix(p.routes[i], b, sizeof(b)); if (r.length()) r += ", "; r += b; } return r; }

String zoneRuntimeText() {
    if (!g_ready) return "Zonen-Runtime deaktiviert (PSRAM-Allokation fehlgeschlagen)";
    String t = "Zonen-Policies (persistent nur der Intent; Plan = Laufzeit, Commit #" + String((unsigned long)g_applyCount) + ", NAT-Domains " + String(g_lastDomains) + (g_lastDomainOverflow ? " UEBERLAUF" : "") + ")\r\n";
    if (g_commitError.length()) t += "  !! " + g_commitError + "\r\n";
    if (!g_nIntents) t += "  (keine) -- Forward-Policy inaktiv, Stock-Verhalten\r\n";
    for (int i = 0; i < g_nIntents; i++) {
        t += String("  ") + g_intents[i].src + " -> " + g_intents[i].dst + "  Intent " + zoneIntentName(g_intents[i].intent);
        if (g_intents[i].desired[0]) t += String("  [gewuenscht: ") + g_intents[i].desired + "]";
        if (g_intents[i].desiredOverflow) t += "  !! gewuenschte Netze passen nicht in den Speicher (alter Stand behalten)";
        if (i < g_nPlans) {
            const ZonePlan& p = g_plans[i];
            t += String("  =>  ") + zoneEffectiveName(p.mode) + "  (" + p.reason + ")";
            if (p.nRoutes) t += "  Routen: " + routesCsv(p);
            if (p.natSource) t += "  SNAT " + ipStr(p.natSource);
        }
        t += "\r\n";
    }
    t += "Konsole: zones policy <quelle> <ziel> allow|deny|route|nat | zones policy del <quelle> <ziel> | zones apply";
    return t;
}
static String jsonEsc(const String& s) { String o; for (size_t i = 0; i < s.length(); i++) { char c = s[i]; if (c == '"' || c == '\\') o += '\\'; if ((uint8_t)c < 0x20) continue; o += c; } return o; }
String zoneRuntimeJson() {
    if (!g_ready) return "{\"error\":\"Zonen-Runtime deaktiviert (PSRAM)\"}";
    String j = "{\"applyCount\":" + String((unsigned long)g_applyCount) + ",\"lastApplyMs\":" + String((unsigned long)g_lastApplyMs) + ",\"policyMode\":" + (g_nIntents ? "true" : "false")
             + ",\"natDomains\":" + String(g_lastDomains) + ",\"natDomainOverflow\":" + (g_lastDomainOverflow ? "true" : "false")
             + ",\"commitError\":\"" + jsonEsc(g_commitError) + "\",\"clientRoutesWg\":\"" + jsonEsc(zoneRuntimeDesiredCidrsFrom("wg-server")) + "\",\"policies\":[";
    for (int i = 0; i < g_nIntents; i++) {
        if (i) j += ",";
        j += String("{\"src\":\"") + g_intents[i].src + "\",\"dst\":\"" + g_intents[i].dst + "\",\"intent\":\"" + zoneIntentName(g_intents[i].intent) + "\"";
        j += String(",\"desired\":\"") + g_intents[i].desired + "\",\"desiredOverflow\":" + (g_intents[i].desiredOverflow ? "true" : "false");
        if (i < g_nPlans) {
            const ZonePlan& p = g_plans[i]; char b[24];
            j += String(",\"mode\":\"") + zoneEffectiveName(p.mode) + "\",\"reason\":\"" + jsonEsc(p.reason) + "\",\"routes\":[";
            for (uint8_t r = 0; r < p.nRoutes; r++) { zpFormatPrefix(p.routes[r], b, sizeof(b)); if (r) j += ","; j += "\""; j += b; j += "\""; }
            j += "],\"natSource\":\""; if (p.natSource) j += ipStr(p.natSource); j += "\",\"mtuHint\":" + String((unsigned)p.mtuHint);
        }
        j += "}";
    }
    j += "],\"lwip\":"; j += zoneLwipJson(); j += "}";
    return j;
}

#else
// ============================================================================
// Stub: Netzzonen nicht im Build enthalten (WEIRDOS_FEATURE_ROUTER=0).
// Dieselben Symbole wie zone_runtime.h mit trivialen Koerpern: kein Zustand, kein NVS, keine Referenz auf
// Adapter, lwIP-Hooks, Registry oder WireGuard -- damit wirft --gc-sections zone_planner.cpp/zone_commit.cpp
// gleich mit heraus. Konsumenten (Konsole 'zones ...', /zones.json, WireGuard-Client-Konfig, Diagnose)
// kompilieren und linken unveraendert und bekommen eine ehrliche "nicht im Build"-Antwort.
// ============================================================================
static const char* const kZoneNotBuilt = "Netzzonen nicht im Build enthalten (WEIRDOS_FEATURE_ROUTER=0)";

void   zoneRuntimeBegin() {}
void   zoneRuntimePoll()  {}
bool   zoneRuntimeApply() { return false; }

String zoneRuntimeSetPolicy(const String& src, const String& dst, const String& intentWord) { (void)src; (void)dst; (void)intentWord; return kZoneNotBuilt; }
String zoneRuntimeDelPolicy(const String& src, const String& dst) { (void)src; (void)dst; return kZoneNotBuilt; }
int    zoneRuntimeIntentCount() { return 0; }

bool   zoneRuntimePlanFor(const String& src, const String& dst, String& mode, String& reason, String& natSource) { (void)src; (void)dst; (void)mode; (void)reason; (void)natSource; return false; }
// Keine Zonen -> keine Ziel-Netze fuer WireGuard-AllowedIPs (Client-Konfig enthaelt nur Tunnel-IP + LAN-Gateway).
String zoneRuntimeReachableCidrsFrom(const String& srcAttachment) { (void)srcAttachment; return ""; }
String zoneRuntimeDesiredCidrsFrom(const String& srcAttachment)   { (void)srcAttachment; return ""; }

String zoneRuntimeText() { return "Netzzonen: nicht im Build enthalten (WEIRDOS_FEATURE_ROUTER=0)"; }
String zoneRuntimeJson() { return String("{\"builtIn\":false,\"error\":\"") + kZoneNotBuilt + "\",\"policyMode\":false,\"policies\":[]}"; }
#endif // WEIRDOS_FEATURE_ROUTER
