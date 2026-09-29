// ============================================================================
// zone_planner.h -- Netzzonen: Policy-Planner (Phase 0.2, reine Datenlogik).
//
// Contract (NETWORK-ZONES-UX-PLAN.md, Abschnitt 4 + 13):
//   * Eingabe = Intent (was der Benutzer will) + Attachments (stabile L3-Endpunkte mit
//     Capabilities) -- KEINE Interface-Typ-Abfragen, keine lwIP-Typen, kein Arduino.
//   * Ausgabe = PolicyPlan mit effektivem Modus DENY | ROUTE | NAT | IMPOSSIBLE, Grund,
//     Routen, NAT-Quelladresse. DENY ist ein expliziter Plan, nie "kein Plan".
//     Fehlender/unbekannter Zustand ist fail-closed (IMPOSSIBLE bzw. DENY).
//   * Zweistufig: zonePlanOne() entscheidet eine Attachment-Paarung zustandsfrei;
//     zoneCompilePolicies() prueft Cross-Policy-Regeln (symmetrisches Routing in Phase 1,
//     NAT/ROUTE-Mischung auf demselben Ziel, Duplikate, fehlende Attachments).
//
// Capabilities eines Ziel-Attachments (das Netz, ueber das Verkehr das Geraet verlaesst):
//   acceptSrc  = egressAcceptsSource: welche Quell-Prefixe die Gegenseite als Absender
//                annimmt (IPsec: TSi; WireGuard-Server: AllowedIPs der von uns erzeugten
//                Client-Konfiguration; LAN: beliebig; Uplink: keine).
//   reach      = egressAcceptsDestination: welche Ziel-Prefixe erreichbar sind (IPsec: TSr;
//                WireGuard: serverseitige Peer-AllowedIPs; LAN: on-link; Uplink: alles).
//   returnTo   = returnPathKnown: zu welchen Quell-Prefixen die Gegenseite den Rueckweg kennt
//                (IPsec: TSi; WireGuard-Server: Client-Konfig-AllowedIPs; LAN: beliebig).
//   "unbekannt" (known = false) zaehlt wie "nein".
// Dieselben Daten (z. B. TSi) koennen heute zwei Capabilities speisen; der Contract haelt sie
// trotzdem getrennt, damit andere Netztypen (IPv6, mehrere Child-SAs) sie getrennt fuellen.
// ============================================================================
#ifndef ZONE_PLANNER_H
#define ZONE_PLANNER_H

#include <stdint.h>
#include <stddef.h>

#define ZP_ID_LEN      16
#define ZP_PREFIX_MAX  8
#define ZP_REASON_LEN  160
#define ZP_ROUTES_MAX  8

enum ZoneIntent : uint8_t {
    ZI_DENY       = 0,   // kein Verkehr (Phase 1)
    ZI_ALLOW_AUTO = 1,   // erlauben, Planner waehlt ROUTE oder NAT (Phase 1)
    ZI_ROUTE_ONLY = 2,   // nur ohne NAT; sonst IMPOSSIBLE (Same-Zone-Automatik; Benutzer ab Phase 2)
    ZI_NAT_ONLY   = 3,   // immer NAT (Phase 2)
};

enum ZoneEffective : uint8_t {
    ZE_DENY       = 0,   // Forward-Filter verwirft
    ZE_ROUTE      = 1,   // Routen beidseitig, kein NAT
    ZE_NAT        = 2,   // NAPT, Quelle = Adresse des Geraets im Ziel
    ZE_IMPOSSIBLE = 3,   // nichts installiert, Grund anzeigen
};

enum ZpKind : uint8_t {
    ZP_LAN       = 0,   // lokales Netz, Geraet ist Gateway (WLAN-AP, WLAN-STA-LAN)
    ZP_UPLINK    = 1,   // Internet-Uplink (Modem, WLAN als Uplink) -- nur Ziel, nie Quelle
    ZP_WG_SERVER = 2,   // WireGuard, wir sind Server
    ZP_WG_CLIENT = 3,   // WireGuard, wir sind Client
    ZP_IPSEC     = 4,   // IPsec-Client (ipsec0): wir haengen an einem fremden Gateway (TSi/TSr)
    ZP_IPSEC_SERVER = 5,// IPsec-Server/Responder: fremde Clients haengen an uns (Quellnetze = vergebene Client-Adressen/TSi)
};

struct ZpPrefix {
    uint32_t net;   // Host-Byte-Order, auf die Prefixlaenge maskiert
    uint8_t  len;   // 0..32
};

// Liste von Prefixen mit "beliebig"/"bekannt"-Flags. known=false -> Capability unbekannt.
struct ZpPrefixSet {
    ZpPrefix items[ZP_PREFIX_MAX];
    uint8_t  n;
    bool     any;       // 0.0.0.0/0 (alles)
    bool     known;     // false = keine Aussage moeglich (zaehlt wie "nein")
    bool     overflow;  // zpSetAdd() hat ein Prefix NICHT aufnehmen koennen -> Menge unvollstaendig
                        // -> jede Planung mit diesem Attachment ist IMPOSSIBLE (kein stilles Abschneiden)
};

struct ZpAttachment {
    char        id[ZP_ID_LEN];
    char        ifaceId[ZP_ID_LEN];   // natives Interface = NAT-Domain (mehrere Attachments koennen es teilen)
    ZpKind      kind;
    bool        up;
    bool        runtimeSupported;   // false = Rolle hat (noch) keine Runtime -> jede Planung IMPOSSIBLE mit eigenem Grund
    uint32_t    local;       // Adresse des Geraets in diesem Netz (0 = keine)
    uint8_t     localLen;    // Prefixlaenge der lokalen Adresse (Tunnel /32, LAN /24 ...)
    uint16_t    mtu;
    // srcNets = Adressbereiche, aus denen Pakete UEBER DIESES ATTACHMENT in den Forwarder eintreten:
    //   LAN = on-link Prefix; IPsec = ausgehandelter entfernter TSr; WireGuard-Server = serverseitige
    //   Peer-AllowedIPs; WireGuard-Client = AllowedIPs des entfernten Peers. Die lokale Tunnel-IP ist
    //   KEIN Quellnetz (sie ist local / natSource).
    ZpPrefixSet srcNets;
    ZpPrefixSet acceptSrc;   // egressAcceptsSource (als Ziel)
    ZpPrefixSet reach;       // egressAcceptsDestination (als Ziel)
    ZpPrefixSet returnTo;    // returnPathKnown (als Ziel)
};

struct ZonePlan {
    char          srcId[ZP_ID_LEN];
    char          dstId[ZP_ID_LEN];
    ZoneIntent    intent;
    ZoneEffective mode;
    char          reason[ZP_REASON_LEN];
    ZpPrefix      routes[ZP_ROUTES_MAX];   // Ziel-Prefixe, die ueber dst installiert wuerden (leer bei Uplink/any)
    uint8_t       nRoutes;
    uint32_t      natSource;               // Quelladresse bei NAT (0 sonst)
    uint16_t      mtuHint;                 // MTU des Ziel-Attachments (0 = unbekannt)
};

struct ZonePolicyIn {
    char       srcId[ZP_ID_LEN];
    char       dstId[ZP_ID_LEN];
    ZoneIntent intent;
};

// Hilfsfunktionen (auch fuer Adapter/Tests).
uint32_t zpMask(uint8_t len);
bool     zpPrefixContains(const ZpPrefix& outer, const ZpPrefix& inner);
bool     zpSetCovers(const ZpPrefixSet& set, const ZpPrefix& p);   // any || ein Element enthaelt p; known noetig
void     zpSetInit(ZpPrefixSet& s, bool known, bool any);
bool     zpSetAdd(ZpPrefixSet& s, uint32_t net, uint8_t len);      // maskiert; false wenn voll
void     zpAttachmentInit(ZpAttachment& a, const char* id, ZpKind kind);
int      zpFormatPrefix(const ZpPrefix& p, char* out, size_t outLen);   // "a.b.c.d/len"

// Stufe 1: eine Paarung, zustandsfrei und deterministisch.
ZonePlan zonePlanOne(ZoneIntent intent, const ZpAttachment& src, const ZpAttachment& dst);

// Stufe 2: alle Policies gegen einen Registry-Snapshot. Liefert je Eingabe-Policy genau einen
// Plan (gleiche Reihenfolge). Nicht genannte Paarungen gelten als DENY (fail-closed).
// Cross-Regeln werden bis zum Fixpunkt wiederholt: Duplikate -> NAT/ROUTE-Mischung -> Symmetrie,
// und nach jeder Invalidierung erneut, bis sich nichts mehr aendert. Der finale PlanSet erfuellt
// damit alle Phase-1-Invarianten (keine einseitige ROUTE bleibt stehen).
//   allowMixedNatRoute: false = konservative Regel "NAT und ROUTE auf demselben Ziel-Attachment
//   verboten"; true = per-Policy-NAT (0.4: Forward-Pfad entscheidet je (inp, outp), ob NAPT
//   uebersetzt) -- dann gilt nur noch die esp-lwIP-Grenze: ein natives Interface kann NAT-EINGANG
//   (napt-Flag, private Seite) ODER NAT-AUSGANG (Antworten werden nur auf Interfaces ohne napt-Flag
//   zurueckuebersetzt) sein, nie beides. Diese Regel gilt immer (ifaceId = NAT-Domain).
int zoneCompilePolicies(const ZonePolicyIn* pol, int nPol,
                        const ZpAttachment* att, int nAtt,
                        ZonePlan* out, int maxOut, bool allowMixedNatRoute);

const char* zoneIntentName(ZoneIntent i);
const char* zoneEffectiveName(ZoneEffective e);
const char* zpKindName(ZpKind k);

#endif // ZONE_PLANNER_H
