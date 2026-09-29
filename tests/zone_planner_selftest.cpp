// ============================================================================
// tests/zone_planner_selftest.cpp -- Host-Selftest fuer den Netzzonen-Planner (Phase 0.2).
// Baut OHNE Arduino: g++ -std=c++11 -I.. ../zone_planner.cpp zone_planner_selftest.cpp
// Prueft den Contract aus NETWORK-ZONES-UX-PLAN.md Abschnitt 4/13:
//   IPsec TSi /32 -> NAT; IPsec TSi breit -> ROUTE; WireGuard mit/ohne Client-Konfig;
//   Uplink -> NAT; ROUTE_ONLY ohne Rueckroute -> IMPOSSIBLE; asymmetrisches Routing -> abgelehnt;
//   NAT + ROUTE auf demselben Ziel -> abgelehnt; DENY = expliziter Plan; fehlendes Attachment
//   fail-closed; Uplink als Quelle -> IMPOSSIBLE; CP-SUBNET ohne TSr-Deckung keine Route.
// ============================================================================
#include "zone_planner.h"
#include <stdio.h>
#include <string.h>

static int g_fails = 0;
#define CHECK(cond, name) do { if (cond) printf("ok   %s\n", name); else { printf("FAIL %s\n", name); g_fails++; } } while (0)

static uint32_t ip(unsigned a, unsigned b, unsigned c, unsigned d) { return (a << 24) | (b << 16) | (c << 8) | d; }

// Attachments wie sie der Adapter aus der Registry liefern wuerde.
static void mkLan(ZpAttachment& a, const char* id, uint32_t local, uint8_t len, bool gatewayOfLan) {
    zpAttachmentInit(a, id, ZP_LAN); strncpy(a.ifaceId, gatewayOfLan ? "wifi-ap" : "wifi-sta", ZP_ID_LEN - 1); a.up = true; a.local = local; a.localLen = len; a.mtu = 1500;
    zpSetAdd(a.srcNets, local, len);
    zpSetInit(a.acceptSrc, true, true);            // LAN filtert Absender nicht
    zpSetAdd(a.reach, local, len);                 // on-link
    zpSetInit(a.returnTo, gatewayOfLan, gatewayOfLan);   // AP: wir sind Gateway -> Rueckweg bekannt; STA-LAN: unbekannt
}
static void mkUplink(ZpAttachment& a, const char* id, uint32_t local) {
    zpAttachmentInit(a, id, ZP_UPLINK); strncpy(a.ifaceId, "modem-ppp", ZP_ID_LEN - 1); a.up = true; a.local = local; a.localLen = 32; a.mtu = 1500;
    zpSetInit(a.srcNets, false, false);
    zpSetInit(a.acceptSrc, false, false);
    zpSetInit(a.reach, true, true);                // Standardroute
    zpSetInit(a.returnTo, false, false);
}
static void mkWgServer(ZpAttachment& a, uint32_t local, bool clientConfigKnown, bool clientConfigHasLan, uint32_t lanNet) {
    zpAttachmentInit(a, "wg-server", ZP_WG_SERVER); strncpy(a.ifaceId, "wg0", ZP_ID_LEN - 1); a.up = true; a.local = local; a.localLen = 24; a.mtu = 1420;
    // Quellnetze = serverseitige Peer-AllowedIPs (was die Clients senden duerfen), NICHT das Tunnelnetz/lokale IP.
    zpSetAdd(a.srcNets, ip(10, 9, 0, 2), 32);
    zpSetAdd(a.srcNets, ip(10, 9, 0, 3), 32);
    zpSetAdd(a.reach, ip(10, 9, 0, 2), 32);                 // Peer-AllowedIPs (serverseitig)
    zpSetAdd(a.reach, ip(10, 9, 0, 3), 32);
    if (clientConfigKnown) {
        zpSetAdd(a.acceptSrc, local, 32);                   // Client-Konfig-AllowedIPs: Server-IP/32 ...
        zpSetAdd(a.returnTo, local, 32);
        if (clientConfigHasLan) { zpSetAdd(a.acceptSrc, lanNet, 24); zpSetAdd(a.returnTo, lanNet, 24); }
    } else {
        zpSetInit(a.acceptSrc, false, false);
        zpSetInit(a.returnTo, false, false);
    }
}
static void mkIpsec(ZpAttachment& a, uint32_t local, uint8_t tsiLen, uint32_t tsiNet, bool up) {
    zpAttachmentInit(a, "ipsec-client", ZP_IPSEC); strncpy(a.ifaceId, "ipsec0", ZP_ID_LEN - 1); a.up = up; a.local = local; a.localLen = 32; a.mtu = 1400;
    zpSetAdd(a.srcNets, ip(192, 168, 110, 0), 24);          // Quellnetze = ausgehandelter entfernter TSr (Pakete AUS dem Tunnel), nicht die lokale Tunnel-IP
    zpSetAdd(a.acceptSrc, tsiNet, tsiLen);                  // TSi
    zpSetAdd(a.returnTo, tsiNet, tsiLen);                   // TSi (Gateway routet dorthin zurueck)
    zpSetAdd(a.reach, ip(192, 168, 110, 0), 24);            // TSr
}

int main() {
    // --- Prefix-Helfer ---------------------------------------------------------
    { ZpPrefix o = { ip(192, 168, 110, 0), 24 }, i = { ip(192, 168, 110, 7), 32 }, j = { ip(192, 168, 111, 0), 24 };
      CHECK(zpPrefixContains(o, i), "prefix contains host");
      CHECK(!zpPrefixContains(o, j), "prefix excludes neighbour net");
      CHECK(!zpPrefixContains(i, o), "host does not contain net");
      ZpPrefix anyp = { 0, 0 }; CHECK(zpPrefixContains(anyp, o), "0/0 contains everything");
      ZpPrefixSet s; zpSetInit(s, false, false); CHECK(!zpSetCovers(s, i), "unknown set covers nothing (fail-closed)");
      zpSetInit(s, true, true); CHECK(zpSetCovers(s, i), "any set covers host"); }

    ZpAttachment ap, staLan, uplink, wgKnown, wgUnknown, ipsec32, ipsecWide, ipsecDown;
    mkLan(ap, "wlan-ap", ip(192, 168, 4, 1), 24, true);
    mkLan(staLan, "wlan-sta-lan", ip(192, 168, 178, 23), 24, false);
    mkUplink(uplink, "modem-uplink", ip(100, 64, 1, 2));
    mkWgServer(wgKnown, ip(10, 9, 0, 1), true, true, ip(192, 168, 4, 0));
    mkWgServer(wgUnknown, ip(10, 9, 0, 1), false, false, 0);
    mkIpsec(ipsec32, ip(10, 99, 0, 7), 32, ip(10, 99, 0, 7), true);
    mkIpsec(ipsecWide, ip(10, 99, 0, 7), 16, ip(10, 0, 0, 0), true);   // Gateway akzeptiert 10.0.0.0/16? nein: 10.0.0.0/16 deckt 10.9.0.0/24 nicht
    zpSetInit(ipsecWide.acceptSrc, true, false); zpSetAdd(ipsecWide.acceptSrc, ip(10, 0, 0, 0), 8);
    zpSetInit(ipsecWide.returnTo, true, false);  zpSetAdd(ipsecWide.returnTo, ip(10, 0, 0, 0), 8);
    mkIpsec(ipsecDown, ip(10, 99, 0, 7), 32, ip(10, 99, 0, 7), false);

    // --- Stufe 1 ----------------------------------------------------------------
    ZonePlan p;
    p = zonePlanOne(ZI_DENY, wgKnown, ipsec32);
    CHECK(p.mode == ZE_DENY, "DENY ist ein expliziter Plan");
    p = zonePlanOne(ZI_ALLOW_AUTO, wgKnown, ipsec32);
    CHECK(p.mode == ZE_NAT && p.natSource == ip(10, 99, 0, 7), "WG -> IPsec TSi/32: NAT auf Tunnel-IP");
    CHECK(strstr(p.reason, "TSi") != nullptr, "  Grund nennt TSi");
    CHECK(p.nRoutes == 1 && p.routes[0].net == ip(192, 168, 110, 0) && p.routes[0].len == 24, "  Route = TSr");
    p = zonePlanOne(ZI_ALLOW_AUTO, wgKnown, ipsecWide);
    CHECK(p.mode == ZE_ROUTE, "WG -> IPsec TSi breit (10/8): ROUTE");
    p = zonePlanOne(ZI_ROUTE_ONLY, wgKnown, ipsec32);
    CHECK(p.mode == ZE_IMPOSSIBLE && strstr(p.reason, "Rueckroute") != nullptr, "ROUTE_ONLY ohne Rueckroute: IMPOSSIBLE");
    p = zonePlanOne(ZI_NAT_ONLY, wgKnown, ipsecWide);
    CHECK(p.mode == ZE_NAT, "NAT_ONLY erzwingt NAT trotz Routing-Moeglichkeit");
    p = zonePlanOne(ZI_ALLOW_AUTO, ap, uplink);
    CHECK(p.mode == ZE_NAT && p.nRoutes == 0, "LAN -> Uplink: NAT, keine Route (Standardroute)");
    p = zonePlanOne(ZI_ALLOW_AUTO, uplink, ap);
    CHECK(p.mode == ZE_IMPOSSIBLE, "Uplink als Quelle: IMPOSSIBLE (Freigaben)");
    p = zonePlanOne(ZI_ALLOW_AUTO, ap, wgKnown);
    CHECK(p.mode == ZE_ROUTE, "AP -> WG-Server mit Client-Konfig (LAN in AllowedIPs): ROUTE");
    p = zonePlanOne(ZI_ALLOW_AUTO, ap, wgUnknown);
    CHECK(p.mode == ZE_NAT, "AP -> WG-Server ohne bekannte Client-Konfig: NAT (unbekannt = nein)");
    p = zonePlanOne(ZI_ALLOW_AUTO, wgKnown, staLan);
    CHECK(p.mode == ZE_NAT, "WG -> WLAN-STA-LAN: NAT (Rueckweg im fremden LAN unbekannt)");
    p = zonePlanOne(ZI_ALLOW_AUTO, wgKnown, ap);
    CHECK(p.mode == ZE_ROUTE, "WG -> AP: ROUTE (wir sind Gateway des AP-Netzes)");
    p = zonePlanOne(ZI_ALLOW_AUTO, wgKnown, ipsecDown);
    CHECK(p.mode == ZE_IMPOSSIBLE, "Ziel down: IMPOSSIBLE");
    p = zonePlanOne(ZI_ALLOW_AUTO, ap, ap);
    CHECK(p.mode == ZE_IMPOSSIBLE, "Quelle == Ziel: IMPOSSIBLE");
    p = zonePlanOne((ZoneIntent)7, ap, uplink);
    CHECK(p.mode == ZE_IMPOSSIBLE, "unbekannter Intent: fail-closed");
    // Rolle ohne Runtime (IPsec-Server heute): eigener dauerhafter Grund, nie eine Route/NAT.
    { ZpAttachment srv; zpAttachmentInit(srv, "ipsec-server", ZP_IPSEC_SERVER); srv.runtimeSupported = false; srv.up = false;
      p = zonePlanOne(ZI_ALLOW_AUTO, srv, ipsec32);
      CHECK(p.mode == ZE_IMPOSSIBLE && strstr(p.reason, "Runtime") != nullptr && strstr(p.reason, "ipsec-server") != nullptr, "runtime fehlt (Quelle): IMPOSSIBLE mit Runtime-Grund");
      p = zonePlanOne(ZI_ALLOW_AUTO, wgKnown, srv);
      CHECK(p.mode == ZE_IMPOSSIBLE && strstr(p.reason, "Runtime") != nullptr, "runtime fehlt (Ziel): IMPOSSIBLE mit Runtime-Grund");
      srv.up = true;   // selbst wenn jemand up setzt: ohne Runtime bleibt es IMPOSSIBLE
      p = zonePlanOne(ZI_ALLOW_AUTO, wgKnown, srv);
      CHECK(p.mode == ZE_IMPOSSIBLE, "runtime fehlt schlaegt up"); }

    // --- Stufe 2 ----------------------------------------------------------------
    ZpAttachment att[6] = { ap, staLan, uplink, wgKnown, ipsec32, ipsecWide };
    strncpy(att[5].id, "ipsec-wide", ZP_ID_LEN - 1);
    ZonePolicyIn pol[6]; ZonePlan out[6]; int n;
    #define POL(i, s, d, in) do { memset(&pol[i], 0, sizeof(pol[i])); strncpy(pol[i].srcId, s, ZP_ID_LEN - 1); strncpy(pol[i].dstId, d, ZP_ID_LEN - 1); pol[i].intent = in; } while (0)

    // Hauptfall Phase 1: nur WG -> IPsec erlaubt.
    POL(0, "wg-server", "ipsec-client", ZI_ALLOW_AUTO);
    n = zoneCompilePolicies(pol, 1, att, 6, out, 6, false);
    CHECK(n == 1 && out[0].mode == ZE_NAT, "compile: WG -> IPsec = NAT");

    // Asymmetrisches Routing: AP -> WG ROUTE ohne WG -> AP -> abgelehnt; mit Gegenrichtung erlaubt.
    POL(0, "wlan-ap", "wg-server", ZI_ALLOW_AUTO);
    n = zoneCompilePolicies(pol, 1, att, 6, out, 6, false);
    CHECK(out[0].mode == ZE_IMPOSSIBLE && strstr(out[0].reason, "symmetrisch") != nullptr, "compile: einseitiges Routing abgelehnt (Phase 1)");
    POL(1, "wg-server", "wlan-ap", ZI_ALLOW_AUTO);
    n = zoneCompilePolicies(pol, 2, att, 6, out, 6, false);
    CHECK(out[0].mode == ZE_ROUTE && out[1].mode == ZE_ROUTE, "compile: symmetrisches Routing erlaubt");
    POL(1, "wg-server", "wlan-ap", ZI_DENY);
    n = zoneCompilePolicies(pol, 2, att, 6, out, 6, false);
    CHECK(out[0].mode == ZE_IMPOSSIBLE && out[1].mode == ZE_DENY, "compile: ROUTE gegen DENY abgelehnt, DENY bleibt Plan");

    // NAT + ROUTE auf demselben Ziel: AP <-> WG symmetrisch geroutet, dazu STA-LAN -> WG mit NAT.
    // Die ROUTE-Policy auf das NAT-Ziel verliert, NAT bleibt; mit Nachweis-Flag bleibt ROUTE.
    POL(0, "wlan-ap", "wg-server", ZI_ALLOW_AUTO);      // ROUTE
    POL(1, "wg-server", "wlan-ap", ZI_ALLOW_AUTO);      // ROUTE (Gegenrichtung)
    POL(2, "wlan-sta-lan", "wg-server", ZI_NAT_ONLY);   // NAT auf dasselbe Ziel wg-server
    n = zoneCompilePolicies(pol, 3, att, 6, out, 6, false);
    CHECK(out[2].mode == ZE_NAT, "compile: NAT-Policy bleibt");
    CHECK(out[0].mode == ZE_IMPOSSIBLE && strstr(out[0].reason, "Interface-NAPT") != nullptr, "compile: ROUTE auf NAT-Ziel abgelehnt (Mischung)");
    // Fixpunkt: die Gegenrichtung ist jetzt einseitig und muss ebenfalls fail-closed werden (Phase-1-Invariante).
    CHECK(out[1].mode == ZE_IMPOSSIBLE && strstr(out[1].reason, "symmetrisch") != nullptr, "compile: Gegenrichtung nach Mischkonflikt ebenfalls IMPOSSIBLE (Fixpunkt)");
    { int routes = 0; for (int i = 0; i < n; i++) if (out[i].mode == ZE_ROUTE) routes++; CHECK(routes == 0, "compile: finaler PlanSet ohne einseitige ROUTE"); }
    n = zoneCompilePolicies(pol, 3, att, 6, out, 6, true);
    CHECK(out[0].mode == ZE_ROUTE && out[1].mode == ZE_ROUTE, "compile: Mischung mit Nachweis-Flag erlaubt symmetrisches ROUTE");
    CHECK(strstr(out[0].reason, "Interface-NAPT") == nullptr, "  Grund ohne NAPT-Hinweis");

    // IPsec als QUELLE: Pakete aus dem Tunnel tragen TSr-Adressen (192.168.110.x), nicht die Tunnel-IP.
    p = zonePlanOne(ZI_ALLOW_AUTO, ipsec32, ap);
    CHECK(p.mode == ZE_ROUTE, "IPsec -> AP: ROUTE (AP akzeptiert TSr-Absender, wir sind Gateway)");
    p = zonePlanOne(ZI_ALLOW_AUTO, ipsec32, wgUnknown);
    CHECK(p.mode == ZE_NAT && p.natSource == ip(10, 9, 0, 1), "IPsec -> WG ohne Client-Konfig: NAT auf WG-Server-IP");

    // Kapazitaet: mehr Prefixe als ZP_PREFIX_MAX -> overflow -> Planung verweigert, nie still abgeschnitten.
    { ZpAttachment big; mkLan(big, "big-lan", ip(10, 50, 0, 1), 24, true);
      bool okAll = true; for (int k = 0; k < ZP_PREFIX_MAX + 2; k++) okAll = zpSetAdd(big.reach, ip(10, 60, k, 0), 24) && okAll;
      CHECK(!okAll && big.reach.overflow, "capacity: zpSetAdd meldet Ueberlauf");
      p = zonePlanOne(ZI_ALLOW_AUTO, ap, big);
      CHECK(p.mode == ZE_IMPOSSIBLE && strstr(p.reason, "Kapazitaet") != nullptr, "capacity: Plan mit uebergelaufener Menge IMPOSSIBLE"); }

    // 0.4: NAT-Domain = natives Interface. NAT in beide Richtungen zwischen denselben Interfaces ist unmoeglich
    // (Eingang mit napt-Flag kann keine Antworten zurueckuebersetzen); die spaetere Regel verliert.
    POL(0, "wg-server", "ipsec-client", ZI_ALLOW_AUTO);   // NAT wg0 -> ipsec0
    POL(1, "ipsec-client", "wg-server", ZI_NAT_ONLY);     // NAT ipsec0 -> wg0 (Konflikt)
    n = zoneCompilePolicies(pol, 2, att, 6, out, 6, true);
    CHECK(out[0].mode == ZE_NAT, "natdomain: erste NAT-Regel gilt");
    CHECK(out[1].mode == ZE_IMPOSSIBLE && strstr(out[1].reason, "NAT-Eingang") != nullptr, "natdomain: Gegenrichtung NAT abgelehnt (Eingang = Ausgang)");
    // per-Policy-NAT (allowMixed): ROUTE wg<->ap und NAT wg->ipsec koexistieren, weil der Forward-Pfad je Paar entscheidet.
    POL(0, "wlan-ap", "wg-server", ZI_ALLOW_AUTO);
    POL(1, "wg-server", "wlan-ap", ZI_ALLOW_AUTO);
    POL(2, "wg-server", "ipsec-client", ZI_ALLOW_AUTO);
    n = zoneCompilePolicies(pol, 3, att, 6, out, 6, true);
    CHECK(out[0].mode == ZE_ROUTE && out[1].mode == ZE_ROUTE && out[2].mode == ZE_NAT, "per-policy NAT: ROUTE-Paar + NAT aus demselben Eingang koexistieren");
    // Uplink als NAT-Ausgang fuer AP UND als NAT-Ausgang fuer WG: erlaubt (zwei Eingaenge, ein Ausgang).
    POL(0, "wlan-ap", "modem-uplink", ZI_ALLOW_AUTO);
    POL(1, "wg-server", "modem-uplink", ZI_ALLOW_AUTO);
    n = zoneCompilePolicies(pol, 2, att, 6, out, 6, true);
    CHECK(out[0].mode == ZE_NAT && out[1].mode == ZE_NAT, "natdomain: zwei NAT-Eingaenge auf denselben Ausgang erlaubt");

    // Duplikate + fehlende Attachments.
    POL(0, "wg-server", "ipsec-client", ZI_ALLOW_AUTO);
    POL(1, "wg-server", "ipsec-client", ZI_DENY);
    POL(2, "wg-server", "gibtsnicht", ZI_ALLOW_AUTO);
    POL(3, "gibtsnicht", "wlan-ap", ZI_DENY);
    n = zoneCompilePolicies(pol, 4, att, 6, out, 6, false);
    CHECK(out[0].mode == ZE_NAT && out[1].mode == ZE_IMPOSSIBLE, "compile: Duplikat verworfen, erste gilt");
    CHECK(out[2].mode == ZE_IMPOSSIBLE && strstr(out[2].reason, "unbekannt") != nullptr, "compile: fehlendes Ziel fail-closed");
    CHECK(out[3].mode == ZE_DENY, "compile: DENY mit fehlender Quelle bleibt DENY");

    // Formatierung.
    { char b[24]; ZpPrefix q = { ip(192, 168, 110, 0), 24 }; zpFormatPrefix(q, b, sizeof(b)); CHECK(strcmp(b, "192.168.110.0/24") == 0, "format prefix"); }

    if (g_fails) { printf("ZONE PLANNER SELFTEST FAILED (%d)\n", g_fails); return 1; }
    printf("ZONE PLANNER SELFTEST OK\n");
    return 0;
}
