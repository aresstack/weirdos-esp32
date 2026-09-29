// ============================================================================
// network_registry.h -- Registry konkreter Netzwerk-Interfaces (Stufe 7.2) und -- seit
// Netzzonen Phase 0.1 -- der stabilen L3-Endpunkte (Attachments) mit ihren erreichbaren
// Prefixen. Rein lesender Live-Snapshot + Lookup - KEINE Routing-/Default-Route-Aenderung.
//
// Drei getrennte Ebenen (NETWORK-ZONES-UX-PLAN.md 2.1):
//   NetIface        natives Interface (modem-ecm, modem-ppp, wifi-sta, wifi-ap, wg0, ipsec0):
//                   KEIN Prefix, KEINE Zone, KEIN TSr -- absichtlich unveraendert.
//   NetAttachment   stabiler L3-Endpunkt des Geraets auf einem Interface: lokale Adresse,
//                   MTU, Herkunft der Adresse, Capabilities fuer den Planner. Die Zone
//                   (Phase 1, persistent) haengt an der Attachment-id, nicht am Interface.
//   ReachablePrefix ueber ein Attachment erreichbares Netz mit Herkunft (on-link, TSr,
//                   CP-SUBNET, AllowedIPs, Standardroute). IPsec: lokale CP-Adresse 10.x/32
//                   und entferntes TSr 192.168.x/24 sind verschiedene Objekte.
// ============================================================================
#ifndef NETWORK_REGISTRY_H
#define NETWORK_REGISTRY_H

#include <Arduino.h>

// Capability-/Rollen-Bits: WOFUER kann ein Interface stehen (nicht: was es GERADE ist).
enum : uint8_t {
    NETROLE_WAN = 1,   // taugt als Internet-Uplink (INTERNET_UPLINK)
    NETROLE_LAN = 2,   // taugt als lokales Netz (z.B. wifi-ap)
};

struct NetIface {
    String  id;      // "modem-ecm" | "modem-ppp" | "wifi-sta" | "wifi-ap" | "wg0" | "ipsec0"
    String  kind;    // "cellular" | "wifi" | "vpn"
    bool    up;      // Link aktuell oben?
    String  ip;      // aktuelle IPv4 ("" wenn down/unbekannt)
    uint8_t roles;   // NETROLE_WAN | NETROLE_LAN (Capabilities; 0 = keine)
    String  label;   // menschenlesbar, z.B. "Mobilfunk (EC200A) - ECM" / "WLAN - <SSID>"
    String  device;  // zugehoeriges Geraet (peripheral_registry), z.B. "EC200A" ("" wenn keins)
    String  port;    // Hardware-Port/Bus, z.B. "USB0" ("" wenn keiner)
};

// Snapshot der konkreten Interfaces aus dem Live-Zustand (read-only). Fuellt out[],
// setzt count. Keine Nebenwirkung aufs Routing.
void netRegistryBuild(NetIface out[], int maxOut, int& count);

// Interface per id nachschlagen; true wenn gefunden (out gefuellt).
bool netInterfaceById(const String& id, NetIface& out);

// ---- Netzzonen Phase 0.1: Attachments + erreichbare Prefixe ---------------------------
#define NET_ATTACH_MAX 16
#define NET_PREFIX_MAX 32

enum NetAttachKind : uint8_t {
    NATT_LAN          = 0,   // lokales Netz, das Geraet hat eine Adresse darin (AP: Gateway; STA: Teilnehmer)
    NATT_UPLINK       = 1,   // Internet-Uplink-Kandidat (Uplink-Gruppe, keine Zone)
    NATT_WG_SERVER    = 2,   // WireGuard, wir sind Server (Clients haengen an uns)
    NATT_WG_CLIENT    = 3,   // WireGuard, wir sind Client (fremder Server)
    NATT_IPSEC        = 4,   // IPsec-Client (ipsec0): wir haengen an einem fremden Gateway
    NATT_IPSEC_SERVER = 5,   // IPsec-Server/Responder: fremde Clients haengen an uns (Runtime heute NICHT implementiert)
};
// VPN-Rollen sind IMMER vier getrennte Attachments (wg-server, wg-client, ipsec-server, ipsec-client),
// auch wenn sie gerade nicht aktiv sind: up=false ist ein Zustand, kein Grund, das Attachment aus dem
// Modell zu nehmen (persistente Policies zeigen sonst ploetzlich auf "unbekannt"). Der Zustand ist
// explizit: configured (Rolle konfiguriert), runtimeSupported (Runtime vorhanden), up (Endpunkt
// aktiv/routingfaehig), stateNote (Grund, warum nicht up).

enum NetAddrSource : uint8_t {
    NADDR_NONE   = 0,
    NADDR_CONFIG = 1,   // konfiguriert (AP-Adresse, WireGuard-Tunnel-IP, IPsec-Tunnel-IP aus dem Profil)
    NADDR_DHCP   = 2,   // per DHCP bezogen (WLAN-Client)
    NADDR_CP     = 3,   // vom IPsec-Gateway per IKE Config Mode zugewiesen
    NADDR_TSI    = 4,   // vom IPsec-Gateway ueber den verengten TSi bestimmt
    NADDR_PEER   = 5,   // vom Netz zugewiesen (PPP/ECM-Uplink)
};

enum NetPrefixSource : uint8_t {
    NPFX_ONLINK     = 0,   // eigenes Subnetz des Interfaces
    NPFX_DEFAULT    = 1,   // Standardroute (Uplink), 0.0.0.0/0 -- wird nie als Zonenroute installiert
    NPFX_TSR        = 2,   // ausgehandelter IPsec-Traffic-Selektor (Wahrheit fuer Routing)
    NPFX_CPSUBNET   = 3,   // vom IPsec-Gateway gemeldetes INTERNAL_IP4_SUBNET (nur Information, keine Route ohne TSr-Deckung)
    NPFX_ALLOWEDIPS = 4,   // WireGuard: serverseitige Peer-AllowedIPs bzw. Client-AllowedIPs
};

struct NetAttachment {
    String         id;            // fachlich stabil: "wlan-ap", "wlan-sta-lan", "wlan-sta-uplink", "modem-uplink", "wg-server", "wg-client", "ipsec-client"
    String         ifaceId;       // NetIface.id
    String         label;
    NetAttachKind  kind;
    bool           up;
    bool           configured;       // Rolle ist konfiguriert (z. B. WireGuard-Modus, IPsec-Profil)
    bool           runtimeSupported; // Runtime fuer diese Rolle vorhanden (IPsec-Server: false)
    String         stateNote;        // Grund, warum nicht up ("" wenn up)
    String         local;         // Adresse des Geraets in diesem Netz ("" wenn keine)
    uint8_t        localPrefix;   // Prefixlaenge der lokalen Adresse (Tunnel 32, LAN 24 ...)
    uint16_t       mtu;           // 0 = unbekannt
    NetAddrSource  addrSource;
    // Capabilities fuer den Planner, als CSV "a.b.c.d/n[, ...]" oder "any"; known=false = keine Aussage.
    String         acceptSrc;     // egressAcceptsSource: Absender, die die Gegenseite annimmt (IPsec TSi, WG Client-Konfig-AllowedIPs)
    bool           acceptSrcKnown;
    String         returnTo;      // returnPathKnown: Quellnetze, zu denen die Gegenseite den Rueckweg kennt
    bool           returnToKnown;
};

// Bitmaske der Herkuenfte: dasselbe Prefix kann mehrere Quellen haben (z. B. TSr UND CP-SUBNET);
// Provenance geht beim Zusammenfuehren nicht verloren.
#define NPFX_BIT(s) ((uint8_t)(1u << (s)))

struct ReachablePrefix {
    String   attachmentId;
    String   net;            // "a.b.c.d"
    uint8_t  prefix;         // 0..32
    uint8_t  sourceMask;     // NPFX_BIT(NPFX_ONLINK) | ... (mind. ein Bit)
    bool     routingEligible;// darf als Zonenroute dienen? (false: nur Standardroute, oder CP-SUBNET ohne TSr-Deckung)
    String   reason;         // Grund, wenn routingEligible == false ("" sonst)
};

void netAttachmentsBuild(NetAttachment out[], int maxOut, int& count);
void netReachablePrefixesBuild(ReachablePrefix out[], int maxOut, int& count);
bool netReachablePrefixOverflow();   // true, wenn der letzte Build NET_PREFIX_MAX erreicht hat (Diagnose)
bool netAttachmentById(const String& id, NetAttachment& out);

const char* netAttachKindName(NetAttachKind k);
const char* netAddrSourceName(NetAddrSource s);
const char* netPrefixSourceName(NetPrefixSource s);
String      netPrefixSourcesText(uint8_t mask);   // "ausgehandelt (TSr) + vom Gateway gemeldet (CP-SUBNET)"

// Interfaces + Attachments + Prefixe als JSON (Verifikation: /net-interfaces.json).
String netRegistryJson();

#endif // NETWORK_REGISTRY_H
