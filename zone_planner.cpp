// ============================================================================
// zone_planner.cpp -- Netzzonen: Policy-Planner (Phase 0.2). Reine Datenlogik, host-testbar
// (tests/zone_planner_selftest.cpp). Kein Arduino, kein lwIP.
// ============================================================================
#include "zone_planner.h"
#include <string.h>
#include <stdio.h>

// ---- Prefix-Helfer -----------------------------------------------------------
uint32_t zpMask(uint8_t len) {
    if (len == 0) return 0;
    if (len >= 32) return 0xFFFFFFFFu;
    return ~((1u << (32 - len)) - 1u);
}

bool zpPrefixContains(const ZpPrefix& outer, const ZpPrefix& inner) {
    if (inner.len < outer.len) return false;
    return (inner.net & zpMask(outer.len)) == (outer.net & zpMask(outer.len));
}

bool zpSetCovers(const ZpPrefixSet& set, const ZpPrefix& p) {
    if (!set.known) return false;
    if (set.any) return true;
    for (uint8_t i = 0; i < set.n; i++) if (zpPrefixContains(set.items[i], p)) return true;
    return false;
}

void zpSetInit(ZpPrefixSet& s, bool known, bool any) {
    memset(&s, 0, sizeof(s));
    s.known = known; s.any = any;
}

bool zpSetAdd(ZpPrefixSet& s, uint32_t net, uint8_t len) {
    if (len > 32) return false;
    if (len == 0) { s.any = true; s.known = true; return true; }
    if (s.n >= ZP_PREFIX_MAX) { s.overflow = true; return false; }   // explizit merken, nie still abschneiden
    s.items[s.n].net = net & zpMask(len);
    s.items[s.n].len = len;
    s.n++; s.known = true;
    return true;
}

void zpAttachmentInit(ZpAttachment& a, const char* id, ZpKind kind) {
    memset(&a, 0, sizeof(a));
    strncpy(a.id, id ? id : "", ZP_ID_LEN - 1);
    strncpy(a.ifaceId, id ? id : "", ZP_ID_LEN - 1);   // Vorgabe: eigenes Interface; Adapter setzt das native
    a.kind = kind;
    a.runtimeSupported = true;
    zpSetInit(a.srcNets, false, false);
    zpSetInit(a.acceptSrc, false, false);
    zpSetInit(a.reach, false, false);
    zpSetInit(a.returnTo, false, false);
}

int zpFormatPrefix(const ZpPrefix& p, char* out, size_t outLen) {
    return snprintf(out, outLen, "%u.%u.%u.%u/%u",
                    (unsigned)(p.net >> 24) & 255u, (unsigned)(p.net >> 16) & 255u,
                    (unsigned)(p.net >> 8) & 255u, (unsigned)p.net & 255u, (unsigned)p.len);
}

static void fmtIp(uint32_t ip, char* out, size_t outLen) {
    snprintf(out, outLen, "%u.%u.%u.%u", (unsigned)(ip >> 24) & 255u, (unsigned)(ip >> 16) & 255u,
             (unsigned)(ip >> 8) & 255u, (unsigned)ip & 255u);
}

const char* zoneIntentName(ZoneIntent i) {
    switch (i) {
        case ZI_DENY: return "DENY";
        case ZI_ALLOW_AUTO: return "ALLOW_AUTO";
        case ZI_ROUTE_ONLY: return "ROUTE_ONLY";
        case ZI_NAT_ONLY: return "NAT_ONLY";
    }
    return "?";
}
const char* zoneEffectiveName(ZoneEffective e) {
    switch (e) {
        case ZE_DENY: return "DENY";
        case ZE_ROUTE: return "ROUTE";
        case ZE_NAT: return "NAT";
        case ZE_IMPOSSIBLE: return "IMPOSSIBLE";
    }
    return "?";
}
const char* zpKindName(ZpKind k) {
    switch (k) {
        case ZP_LAN: return "lan";
        case ZP_UPLINK: return "uplink";
        case ZP_WG_SERVER: return "wg-server";
        case ZP_WG_CLIENT: return "wg-client";
        case ZP_IPSEC: return "ipsec";
        case ZP_IPSEC_SERVER: return "ipsec-server";
    }
    return "?";
}

// ---- Stufe 1: eine Paarung ----------------------------------------------------
static void planInit(ZonePlan& p, ZoneIntent intent, const ZpAttachment& src, const ZpAttachment& dst) {
    memset(&p, 0, sizeof(p));
    strncpy(p.srcId, src.id, ZP_ID_LEN - 1);
    strncpy(p.dstId, dst.id, ZP_ID_LEN - 1);
    p.intent = intent;
    p.mode = ZE_IMPOSSIBLE;
    p.mtuHint = dst.mtu;
}

static void setReason(ZonePlan& p, const char* r) {
    strncpy(p.reason, r, ZP_REASON_LEN - 1);
    p.reason[ZP_REASON_LEN - 1] = 0;
}

// Erster Quell-Prefix, den das Ziel NICHT als Absender annimmt (fuer den Grundtext).
static bool firstUncovered(const ZpPrefixSet& srcNets, const ZpPrefixSet& cap, ZpPrefix& out) {
    if (srcNets.any) {
        if (cap.known && cap.any) return false;
        out.net = 0; out.len = 0; return true;
    }
    for (uint8_t i = 0; i < srcNets.n; i++) {
        if (!zpSetCovers(cap, srcNets.items[i])) { out = srcNets.items[i]; return true; }
    }
    return false;
}

ZonePlan zonePlanOne(ZoneIntent intent, const ZpAttachment& src, const ZpAttachment& dst) {
    ZonePlan p; planInit(p, intent, src, dst);

    // DENY ist ein echter Plan (Filter verwirft), auch wenn Quelle/Ziel gerade fehlen.
    if (intent == ZI_DENY) { p.mode = ZE_DENY; setReason(p, "getrennt (Intent DENY)"); return p; }

    if (intent != ZI_ALLOW_AUTO && intent != ZI_ROUTE_ONLY && intent != ZI_NAT_ONLY) {
        setReason(p, "unbekannter Intent (fail-closed)"); return p;
    }
    if (strcmp(src.id, dst.id) == 0) { setReason(p, "Quelle und Ziel sind dasselbe Attachment"); return p; }
    // Fehlende Runtime ist ein eigener, dauerhafter Grund (nicht "gerade down"): nie eine Fake-Route.
    if (!src.runtimeSupported) { char r[ZP_REASON_LEN]; snprintf(r, sizeof(r), "nicht verfuegbar: Runtime fuer %s noch nicht implementiert", src.id); setReason(p, r); return p; }
    if (!dst.runtimeSupported) { char r[ZP_REASON_LEN]; snprintf(r, sizeof(r), "nicht verfuegbar: Runtime fuer %s noch nicht implementiert", dst.id); setReason(p, r); return p; }
    if (!src.up) { setReason(p, "Quelle nicht aktiv"); return p; }
    if (!dst.up) { setReason(p, "Ziel nicht aktiv"); return p; }
    if (src.srcNets.overflow || src.acceptSrc.overflow || src.reach.overflow || src.returnTo.overflow ||
        dst.srcNets.overflow || dst.acceptSrc.overflow || dst.reach.overflow || dst.returnTo.overflow) {
        char r[ZP_REASON_LEN];
        snprintf(r, sizeof(r), "Capability-Menge ueberschreitet Kapazitaet (max. %d Prefixe je Attachment) -- Planung verweigert", ZP_PREFIX_MAX);
        setReason(p, r); return p;
    }
    if (src.kind == ZP_UPLINK) {
        setReason(p, "Verkehr aus dem Internet nur ueber Freigaben (Firewall & NAT), nicht ueber Zonen");
        return p;
    }
    if (!src.srcNets.known || (!src.srcNets.any && src.srcNets.n == 0)) {
        setReason(p, "Quelle meldet kein Quellnetz"); return p;
    }
    if (!dst.reach.known || (!dst.reach.any && dst.reach.n == 0)) {
        setReason(p, "Ziel meldet keine erreichbaren Netze (TSr/AllowedIPs/on-link fehlen)"); return p;
    }

    // Routen = erreichbare Ziel-Prefixe (any = Standardroute -> nicht als Route installieren, E3).
    if (!dst.reach.any) {
        for (uint8_t i = 0; i < dst.reach.n && p.nRoutes < ZP_ROUTES_MAX; i++) p.routes[p.nRoutes++] = dst.reach.items[i];
    }

    // Routing ohne NAT: Ziel nimmt ALLE Quellnetze als Absender an UND kennt den Rueckweg.
    ZpPrefix bad; bool canRoute = true; const char* why = nullptr;
    if (firstUncovered(src.srcNets, dst.acceptSrc, bad)) {
        canRoute = false;
        why = dst.acceptSrc.known ? "Ziel akzeptiert Quelle nicht als Absender" : "Absender-Akzeptanz des Ziels unbekannt";
    } else if (firstUncovered(src.srcNets, dst.returnTo, bad)) {
        canRoute = false;
        why = dst.returnTo.known ? "Ziel kennt keinen Rueckweg zur Quelle" : "Rueckweg des Ziels unbekannt";
    }
    bool canNat = (dst.local != 0) && dst.kind != ZP_LAN ? true : (dst.local != 0);

    char pb[24]; if (!canRoute) zpFormatPrefix(bad, pb, sizeof(pb));
    char detail[128];   // ZP_REASON_LEN (160) laesst Platz fuer das Praefix ("weder Routing noch NAT: " usw.)
    if (!canRoute) {
        if (dst.kind == ZP_IPSEC && dst.acceptSrc.known && !dst.acceptSrc.any && dst.acceptSrc.n == 1 && dst.acceptSrc.items[0].len == 32) {
            char lb[24]; zpFormatPrefix(dst.acceptSrc.items[0], lb, sizeof(lb));
            snprintf(detail, sizeof(detail), "Gateway erlaubt nur %s als Absender (TSi), Quelle %s", lb, pb);
        } else if (dst.kind == ZP_UPLINK) {
            snprintf(detail, sizeof(detail), "Uplink: oeffentliches Netz ohne Rueckweg zu %s", pb);
        } else {
            snprintf(detail, sizeof(detail), "%s: %s", why ? why : "?", pb);
        }
    } else {
        detail[0] = 0;
    }

    switch (intent) {
        case ZI_ROUTE_ONLY:
            if (canRoute) { p.mode = ZE_ROUTE; setReason(p, "geroutet ohne NAT (Ziel akzeptiert Quelle, Rueckweg bekannt)"); }
            else { p.mode = ZE_IMPOSSIBLE; char r[ZP_REASON_LEN]; snprintf(r, sizeof(r), "Rueckroute fehlt: %s", detail); setReason(p, r); }
            break;
        case ZI_NAT_ONLY:
            if (canNat) { p.mode = ZE_NAT; p.natSource = dst.local; setReason(p, "NAT erzwungen (Intent NAT_ONLY)"); }
            else { p.mode = ZE_IMPOSSIBLE; setReason(p, "NAT nicht moeglich: Geraet hat keine Adresse im Ziel"); }
            break;
        default: // ALLOW_AUTO
            if (canRoute) { p.mode = ZE_ROUTE; setReason(p, "geroutet ohne NAT (Ziel akzeptiert Quelle, Rueckweg bekannt)"); }
            else if (canNat) {
                p.mode = ZE_NAT; p.natSource = dst.local;
                char r[ZP_REASON_LEN]; snprintf(r, sizeof(r), "NAT: %s", detail); setReason(p, r);
            } else {
                p.mode = ZE_IMPOSSIBLE;
                char r[ZP_REASON_LEN]; snprintf(r, sizeof(r), "weder Routing noch NAT: %s", detail); setReason(p, r);
            }
            break;
    }
    if (p.mode == ZE_NAT && p.natSource) {
        // Grund um die NAT-Quelle ergaenzen (Anzeige "Uebersetzung x -> y").
        char ns[20]; fmtIp(p.natSource, ns, sizeof(ns));
        size_t l = strlen(p.reason);
        if (l + 24 < ZP_REASON_LEN) snprintf(p.reason + l, ZP_REASON_LEN - l, " [Quelle -> %s]", ns);
    }
    return p;
}

// ---- Stufe 2: Policy-Menge ------------------------------------------------------
static const ZpAttachment* findAtt(const ZpAttachment* att, int nAtt, const char* id) {
    for (int i = 0; i < nAtt; i++) if (strncmp(att[i].id, id, ZP_ID_LEN) == 0) return &att[i];
    return nullptr;
}

int zoneCompilePolicies(const ZonePolicyIn* pol, int nPol,
                        const ZpAttachment* att, int nAtt,
                        ZonePlan* out, int maxOut, bool allowMixedNatRoute) {
    if (!pol || !out || nPol <= 0 || maxOut <= 0) return 0;
    int n = nPol < maxOut ? nPol : maxOut;

    for (int i = 0; i < n; i++) {
        const ZpAttachment* s = findAtt(att, nAtt, pol[i].srcId);
        const ZpAttachment* d = findAtt(att, nAtt, pol[i].dstId);
        if (!s || !d) {
            memset(&out[i], 0, sizeof(ZonePlan));
            strncpy(out[i].srcId, pol[i].srcId, ZP_ID_LEN - 1);
            strncpy(out[i].dstId, pol[i].dstId, ZP_ID_LEN - 1);
            out[i].intent = pol[i].intent;
            if (pol[i].intent == ZI_DENY) { out[i].mode = ZE_DENY; setReason(out[i], "getrennt (Intent DENY)"); }
            else { out[i].mode = ZE_IMPOSSIBLE; setReason(out[i], !s ? "Quell-Attachment unbekannt" : "Ziel-Attachment unbekannt"); }
            continue;
        }
        out[i] = zonePlanOne(pol[i].intent, *s, *d);
    }

    // Duplikate: die spaetere Regel derselben Paarung wird verworfen (einmalig, aendert sich nicht mehr).
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < i; j++) {
            if (strncmp(out[i].srcId, out[j].srcId, ZP_ID_LEN) == 0 && strncmp(out[i].dstId, out[j].dstId, ZP_ID_LEN) == 0) {
                out[i].mode = ZE_IMPOSSIBLE; out[i].nRoutes = 0; out[i].natSource = 0;
                setReason(out[i], "doppelte Regel fuer dieselbe Paarung (erste gilt)");
                break;
            }
        }
    }

    // Cross-Regeln bis zum Fixpunkt: jede Invalidierung kann eine andere ROUTE einseitig machen,
    // deshalb NAT/ROUTE-Mischung und Symmetrie wiederholen, bis sich nichts mehr aendert. Der
    // finale PlanSet erfuellt damit beide Invarianten (max. n Runden, jede Runde invalidiert >= 1).
    for (int round = 0; round <= n; round++) {
        bool changed = false;

        // esp-lwIP-NAPT (0.4): NAT-Domain = natives Eingangsinterface (napt-Flag). Antworten werden nur
        // auf Interfaces OHNE napt-Flag zurueckuebersetzt -> ein Interface darf nicht zugleich NAT-Eingang
        // und NAT-Ausgang sein. Die spaetere Policy verliert (deterministisch: fruehere gewinnt).
        for (int i = 0; i < n; i++) {
            if (out[i].mode != ZE_NAT) continue;
            const ZpAttachment* si = findAtt(att, nAtt, out[i].srcId);
            const ZpAttachment* di = findAtt(att, nAtt, out[i].dstId);
            if (!si || !di) continue;
            for (int j = 0; j < i; j++) {
                if (out[j].mode != ZE_NAT) continue;
                const ZpAttachment* sj = findAtt(att, nAtt, out[j].srcId);
                const ZpAttachment* dj = findAtt(att, nAtt, out[j].dstId);
                if (!sj || !dj) continue;
                bool conflict = (strncmp(si->ifaceId, dj->ifaceId, ZP_ID_LEN) == 0)    // mein Eingang = fremder Ausgang
                             || (strncmp(di->ifaceId, sj->ifaceId, ZP_ID_LEN) == 0);   // mein Ausgang = fremder Eingang
                if (conflict) {
                    out[i].mode = ZE_IMPOSSIBLE; out[i].nRoutes = 0; out[i].natSource = 0; changed = true;
                    char r[ZP_REASON_LEN];
                    snprintf(r, sizeof(r), "NAT-Eingang und NAT-Ausgang auf demselben Interface (%s) nicht unterstuetzt (esp-lwIP NAPT), Regel %s -> %s gilt",
                             (strncmp(si->ifaceId, dj->ifaceId, ZP_ID_LEN) == 0) ? si->ifaceId : di->ifaceId, out[j].srcId, out[j].dstId);
                    setReason(out[i], r);
                    break;
                }
            }
        }

        // NAT + ROUTE auf demselben Ziel: ohne per-Policy-NAT verliert ROUTE.
        if (!allowMixedNatRoute) {
            for (int i = 0; i < n; i++) {
                if (out[i].mode != ZE_ROUTE) continue;
                for (int j = 0; j < n; j++) {
                    if (j == i || out[j].mode != ZE_NAT) continue;
                    if (strncmp(out[j].dstId, out[i].dstId, ZP_ID_LEN) == 0) {
                        out[i].mode = ZE_IMPOSSIBLE; out[i].nRoutes = 0; changed = true;
                        char r[ZP_REASON_LEN];
                        snprintf(r, sizeof(r), "NAT und Routing auf %s gleichzeitig nicht unterstuetzt (Interface-NAPT)", out[i].dstId);
                        setReason(out[i], r);
                        break;
                    }
                }
            }
        }

        // Phase 1: Routing nur symmetrisch. A->B ROUTE braucht B->A ROUTE (fehlend/invalidiert = DENY).
        for (int i = 0; i < n; i++) {
            if (out[i].mode != ZE_ROUTE) continue;
            bool reverseRoute = false;
            for (int j = 0; j < n; j++) {
                if (j == i) continue;
                if (strncmp(out[j].srcId, out[i].dstId, ZP_ID_LEN) == 0 && strncmp(out[j].dstId, out[i].srcId, ZP_ID_LEN) == 0 && out[j].mode == ZE_ROUTE) {
                    reverseRoute = true; break;
                }
            }
            if (!reverseRoute) {
                out[i].mode = ZE_IMPOSSIBLE; out[i].nRoutes = 0; changed = true;
                char r[ZP_REASON_LEN];
                snprintf(r, sizeof(r), "Phase 1: Routing nur symmetrisch, %s -> %s ist nicht geroutet", out[i].dstId, out[i].srcId);
                setReason(out[i], r);
            }
        }

        if (!changed) break;
    }
    return n;
}
