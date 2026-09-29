// ============================================================================
// zone_planner_adapter.cpp -- Registry -> Planner (Phase 0.2, read-only).
//
// Semantik (PO-Review 0.1/0.2):
//   srcNets  = Adressbereiche, aus denen Pakete ueber das Quell-Attachment in den Forwarder
//              eintreten: LAN on-link, IPsec = ausgehandelter entfernter TSr, WireGuard = Peer-
//              AllowedIPs (Server: serverseitig; Client: AllowedIPs des entfernten Peers).
//              Die lokale Tunnel-IP ist nur local/natSource.
//   reach    = erreichbare Prefixe mit routingEligible == true (Standardroute -> "any";
//              CP-SUBNET nur mit TSr-Deckung, entscheidet die Registry).
//   Ueberlauf einer Prefix-Menge wird nicht abgeschnitten, sondern markiert (overflow) -> der
//   Planner liefert IMPOSSIBLE mit Grund.
// Baustein ROUTER (WEIRDOS_FEATURE_ROUTER): bei 0 bleibt nur der Stub am Dateiende (Header unveraendert).
// ============================================================================
#include "weirdos_features.h"
#include "zone_planner_adapter.h"
#if WEIRDOS_FEATURE_ROUTER
#include "network_registry.h"

static bool parseIp(const String& s, uint32_t& out) {
    IPAddress ip; if (!ip.fromString(s)) return false;
    out = ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) | ((uint32_t)ip[2] << 8) | ip[3];
    return true;
}
// CSV "a.b.c.d/n, any, ..." -> Set. known = (Eingabe nicht leer) && knownFlag. Ueberlauf bleibt im Set markiert.
static void fillSet(ZpPrefixSet& s, const String& csv, bool knownFlag) {
    zpSetInit(s, false, false);
    if (!knownFlag) return;
    String rest = csv; bool anyItem = false;
    while (rest.length()) {
        int c = rest.indexOf(','); String one = (c < 0) ? rest : rest.substring(0, c); one.trim();
        rest = (c < 0) ? String("") : rest.substring(c + 1);
        if (!one.length()) continue;
        if (one == "any" || one == "0.0.0.0/0") { zpSetAdd(s, 0, 0); anyItem = true; continue; }
        int sl = one.indexOf('/'); uint32_t net; int p = 32;
        if (sl > 0) { if (!parseIp(one.substring(0, sl), net)) continue; p = one.substring(sl + 1).toInt(); }
        else if (!parseIp(one, net)) continue;
        if (p < 0 || p > 32) continue;
        zpSetAdd(s, net, (uint8_t)p); anyItem = true;
    }
    s.known = anyItem || s.overflow;
}

int zoneAdapterBuild(ZpAttachment* out, int maxOut) {
    NetAttachment at[NET_ATTACH_MAX]; int na = 0;
    netAttachmentsBuild(at, NET_ATTACH_MAX, na);
    ReachablePrefix pf[NET_PREFIX_MAX]; int np = 0;
    netReachablePrefixesBuild(pf, NET_PREFIX_MAX, np);

    int n = 0;
    for (int i = 0; i < na && n < maxOut; i++) {
        ZpAttachment& z = out[n];
        ZpKind kind = ZP_LAN;
        switch (at[i].kind) {
            case NATT_LAN: kind = ZP_LAN; break;
            case NATT_UPLINK: kind = ZP_UPLINK; break;
            case NATT_WG_SERVER: kind = ZP_WG_SERVER; break;
            case NATT_WG_CLIENT: kind = ZP_WG_CLIENT; break;
            case NATT_IPSEC: kind = ZP_IPSEC; break;
            case NATT_IPSEC_SERVER: kind = ZP_IPSEC_SERVER; break;
        }
        zpAttachmentInit(z, at[i].id.c_str(), kind);
        strncpy(z.ifaceId, at[i].ifaceId.c_str(), ZP_ID_LEN - 1);   // NAT-Domain = natives Interface
        z.up = at[i].up; z.runtimeSupported = at[i].runtimeSupported; z.mtu = at[i].mtu; z.localLen = at[i].localPrefix;
        uint32_t local = 0; if (at[i].local.length() && parseIp(at[i].local, local)) z.local = local;

        // Capabilities der Gegenseite.
        fillSet(z.acceptSrc, at[i].acceptSrc, at[i].acceptSrcKnown);
        fillSet(z.returnTo,  at[i].returnTo,  at[i].returnToKnown);

        // reach = routingfaehige Prefixe; srcNets = Eintrittsbereiche je Art (siehe Kopf).
        zpSetInit(z.reach, false, false);
        zpSetInit(z.srcNets, false, false);
        uint8_t srcBit = 0;
        switch (kind) {
            case ZP_LAN:       srcBit = NPFX_BIT(NPFX_ONLINK); break;
            case ZP_IPSEC:     srcBit = NPFX_BIT(NPFX_TSR); break;
            case ZP_WG_SERVER: srcBit = NPFX_BIT(NPFX_ALLOWEDIPS); break;
            case ZP_WG_CLIENT: srcBit = NPFX_BIT(NPFX_ALLOWEDIPS); break;
            case ZP_UPLINK:    srcBit = 0; break;   // nie Quelle
            case ZP_IPSEC_SERVER: srcBit = 0; break;   // Quellnetze = vergebene Client-Adressen -- gibt es erst mit dem Responder
        }
        for (int k = 0; k < np; k++) {
            if (pf[k].attachmentId != at[i].id) continue;
            uint32_t net; if (!parseIp(pf[k].net, net)) continue;
            if (pf[k].routingEligible) zpSetAdd(z.reach, net, pf[k].prefix);
            else if (pf[k].sourceMask & NPFX_BIT(NPFX_DEFAULT)) zpSetAdd(z.reach, 0, 0);   // Uplink: alles erreichbar, keine Zonenroute
            if (srcBit && (pf[k].sourceMask & srcBit) && pf[k].prefix > 0) zpSetAdd(z.srcNets, net, pf[k].prefix);
        }
        n++;
    }
    return n;
}

ZoneIntent zoneIntentParse(const String& s, bool& ok) {
    String t = s; t.trim(); t.toLowerCase(); ok = true;
    if (t == "deny" || t == "getrennt") return ZI_DENY;
    if (t == "allow" || t == "allow_auto" || t == "auto" || t == "") return ZI_ALLOW_AUTO;
    if (t == "route" || t == "route_only") return ZI_ROUTE_ONLY;
    if (t == "nat" || t == "nat_only") return ZI_NAT_ONLY;
    ok = false; return ZI_DENY;
}

// Beide Sichten: (1) Paarung technisch (zonePlanOne, nur Capabilities), (2) Phase-1-Policyset
// mit genau dieser einen Regel (Cross-Regeln: eine einseitige ROUTE wird hier IMPOSSIBLE, weil
// die Gegenrichtung im Ein-Regel-Snapshot fehlt). Solange keine Zonen-Policies persistent sind,
// ist (2) nur die Vorschau der Phase-1-Restriktion.
struct PairPlans { ZonePlan pair; ZonePlan set; bool ok; };
static PairPlans planPair(const String& src, const String& dst, ZoneIntent intent) {
    PairPlans r; memset(&r, 0, sizeof(r));
    // Attachments auf den Heap (~350 B je Eintrag): Konsolen-/HTTP-Task-Stacks sind klein.
    ZpAttachment* att = (ZpAttachment*)malloc(sizeof(ZpAttachment) * NET_ATTACH_MAX);
    if (!att) return r;
    int n = zoneAdapterBuild(att, NET_ATTACH_MAX);
    ZonePolicyIn pol; memset(&pol, 0, sizeof(pol));
    strncpy(pol.srcId, src.c_str(), ZP_ID_LEN - 1); strncpy(pol.dstId, dst.c_str(), ZP_ID_LEN - 1); pol.intent = intent;
    r.ok = zoneCompilePolicies(&pol, 1, att, n, &r.set, 1, true /* per-Policy-NAT wie die Runtime */) == 1;
    const ZpAttachment* s = nullptr; const ZpAttachment* d = nullptr;
    for (int i = 0; i < n; i++) { if (src == att[i].id) s = &att[i]; if (dst == att[i].id) d = &att[i]; }
    if (s && d) r.pair = zonePlanOne(intent, *s, *d);
    else { r.pair = r.set; }
    free(att);
    return r;
}
static String routesCsv(const ZonePlan& p) {
    String r; char b[24];
    for (uint8_t i = 0; i < p.nRoutes; i++) { zpFormatPrefix(p.routes[i], b, sizeof(b)); if (r.length()) r += ", "; r += b; }
    return r;
}
static String ipStr(uint32_t v) {
    char b[20]; snprintf(b, sizeof(b), "%u.%u.%u.%u", (unsigned)(v >> 24) & 255u, (unsigned)(v >> 16) & 255u, (unsigned)(v >> 8) & 255u, (unsigned)v & 255u);
    return String(b);
}

String zonePlanText(const String& src, const String& dst, ZoneIntent intent) {
    PairPlans pp = planPair(src, dst, intent);
    if (!pp.ok) return "Planner: kein Ergebnis";
    String t;
    t += "Verbindung " + src + " -> " + dst + "  Intent " + zoneIntentName(intent) + "\r\n";
    t += "Paarung technisch (nur Capabilities):\r\n";
    t += "  effektiv:  " + String(zoneEffectiveName(pp.pair.mode)) + "\r\n";
    t += "  Grund:     " + String(pp.pair.reason) + "\r\n";
    if (pp.pair.nRoutes) t += "  Routen:    " + routesCsv(pp.pair) + " ueber " + dst + "\r\n";
    if (pp.pair.natSource) t += "  NAT-Quelle " + ipStr(pp.pair.natSource) + "\r\n";
    if (pp.pair.mtuHint) t += "  MTU-Hinweis " + String((unsigned)pp.pair.mtuHint) + "\r\n";
    t += "Phase-1-Policyset (nur diese Regel, Cross-Regeln angewendet):\r\n";
    t += "  effektiv:  " + String(zoneEffectiveName(pp.set.mode)) + "\r\n";
    t += "  Grund:     " + String(pp.set.reason) + "\r\n";
    t += "  (Vorschau: nichts installiert -- Phase 0.5)";
    return t;
}

static String jsonEsc(const String& s) {
    String o; for (size_t i = 0; i < s.length(); i++) { char c = s[i]; if (c == '"' || c == '\\') o += '\\'; if ((uint8_t)c < 0x20) continue; o += c; }
    return o;
}
static String planJsonObj(const ZonePlan& p) {
    String j = "{\"mode\":\""; j += zoneEffectiveName(p.mode);
    j += "\",\"reason\":\""; j += jsonEsc(p.reason);
    j += "\",\"routes\":["; char b[24];
    for (uint8_t i = 0; i < p.nRoutes; i++) { zpFormatPrefix(p.routes[i], b, sizeof(b)); if (i) j += ","; j += "\""; j += b; j += "\""; }
    j += "],\"natSource\":\""; if (p.natSource) j += ipStr(p.natSource);
    j += "\",\"mtuHint\":"; j += String((unsigned)p.mtuHint);
    j += "}";
    return j;
}
String zonePlanJson(const String& src, const String& dst, ZoneIntent intent) {
    PairPlans pp = planPair(src, dst, intent);
    String j = "{\"src\":\"" + jsonEsc(src) + "\",\"dst\":\"" + jsonEsc(dst) + "\",\"intent\":\"" + zoneIntentName(intent) + "\"";
    if (!pp.ok) { j += ",\"error\":\"kein Ergebnis\"}"; return j; }
    j += ",\"pair\":"; j += planJsonObj(pp.pair);        // technisch (nur Capabilities)
    j += ",\"policyset\":"; j += planJsonObj(pp.set);    // Phase-1-Restriktion mit genau dieser Regel
    j += ",\"installed\":false}";
    return j;
}

String zoneAttachmentsText() {
    NetAttachment at[NET_ATTACH_MAX]; int na = 0; netAttachmentsBuild(at, NET_ATTACH_MAX, na);
    ReachablePrefix pf[NET_PREFIX_MAX]; int np = 0; netReachablePrefixesBuild(pf, NET_PREFIX_MAX, np);
    String t = "Attachments (stabile L3-Endpunkte):\r\n";
    for (int i = 0; i < na; i++) {
        char l[160];
        snprintf(l, sizeof(l), "  %-16s %-10s %-9s %-5s %s/%u  MTU %u  Adresse: %s", at[i].id.c_str(), at[i].ifaceId.c_str(),
                 netAttachKindName(at[i].kind), at[i].up ? "up" : "down", at[i].local.length() ? at[i].local.c_str() : "-",
                 (unsigned)at[i].localPrefix, (unsigned)at[i].mtu, netAddrSourceName(at[i].addrSource));
        t += l; t += "\r\n";
        if (!at[i].up) t += "    Zustand: " + (at[i].runtimeSupported ? String("") : String("KEINE RUNTIME -- ")) + at[i].stateNote + (at[i].configured ? "" : " (Rolle nicht konfiguriert)") + "\r\n";
        t += "    akzeptiert Absender: " + (at[i].acceptSrcKnown ? at[i].acceptSrc : String("unbekannt"));
        t += "  Rueckweg zu: " + (at[i].returnToKnown ? at[i].returnTo : String("unbekannt")) + "\r\n";
        for (int k = 0; k < np; k++) {
            if (pf[k].attachmentId != at[i].id) continue;
            t += "    erreichbar " + pf[k].net + "/" + String((unsigned)pf[k].prefix) + "  (" + netPrefixSourcesText(pf[k].sourceMask) + ")";
            if (!pf[k].routingEligible) t += "  KEINE Zonenroute: " + pf[k].reason;
            t += "\r\n";
        }
    }
    t += "Planner-Vorschau: 'zones plan <quelle> <ziel> [allow|deny|route|nat]'";
    return t;
}

#else
// ============================================================================
// Stub: Netzzonen nicht im Build enthalten (WEIRDOS_FEATURE_ROUTER=0).
// Dieselben Symbole wie zone_planner_adapter.h; keine Referenz auf Registry oder Planner (zone_planner.cpp
// faellt so beim Linken heraus). Nur der Intent-Parser bleibt funktional: er ist eine reine Wortliste ohne
// Zustand, und Konsole ('zones plan') wie /zones-plan.json sollen die "nicht im Build"-Antwort liefern statt
// einer irrefuehrenden "Intent unbekannt"-Meldung.
// ============================================================================
static const char* const kZoneNotBuilt = "Netzzonen nicht im Build enthalten (WEIRDOS_FEATURE_ROUTER=0)";

int zoneAdapterBuild(ZpAttachment* out, int maxOut) { (void)out; (void)maxOut; return 0; }

ZoneIntent zoneIntentParse(const String& s, bool& ok) {
    String t = s; t.trim(); t.toLowerCase(); ok = true;
    if (t == "deny" || t == "getrennt") return ZI_DENY;
    if (t == "allow" || t == "allow_auto" || t == "auto" || t == "") return ZI_ALLOW_AUTO;
    if (t == "route" || t == "route_only") return ZI_ROUTE_ONLY;
    if (t == "nat" || t == "nat_only") return ZI_NAT_ONLY;
    ok = false; return ZI_DENY;
}

String zonePlanText(const String& src, const String& dst, ZoneIntent intent) { (void)src; (void)dst; (void)intent; return "Netzzonen: nicht im Build enthalten (WEIRDOS_FEATURE_ROUTER=0)"; }
String zonePlanJson(const String& src, const String& dst, ZoneIntent intent) { (void)src; (void)dst; (void)intent; return String("{\"builtIn\":false,\"error\":\"") + kZoneNotBuilt + "\",\"installed\":false}"; }
String zoneAttachmentsText() { return "Netzzonen: nicht im Build enthalten (WEIRDOS_FEATURE_ROUTER=0)"; }
#endif // WEIRDOS_FEATURE_ROUTER
