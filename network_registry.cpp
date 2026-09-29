// ============================================================================
// network_registry.cpp -- Konkrete Interfaces, Attachments und erreichbare Prefixe aus dem
// Live-Zustand (read-only). Liest ECM/PPP/WLAN/WireGuard/IPsec-Status ueber die bestehenden
// Accessoren; aendert nichts am Routing. Keine Persistenz.
// ============================================================================
#include "weirdos_features.h"    // WEIRDOS_FEATURE_WIFI: WLAN-Interfaces/-Anbindungen nur mit WLAN-Baustein
#include "network_registry.h"
#if WEIRDOS_FEATURE_WIFI
#include <WiFi.h>                // WiFi.status()/localIP()/softAPIP() (WLAN-Funk) -- ohne Baustein nicht im Bild
#endif
#include "ec200a_modem.h"        // pppIsUp/pppIpStr
#include "ec200a_ecm.h"          // ec200aEcm/ecmWanIp
#include "peripheral_registry.h" // periphModemPort (Port des Modem-Geraets)
#include "ipsec_runtime.h"       // 8.2f: ipsec0 (IPsec-Tunnel als Schnittstelle) + tunnelNetInfo
#include "wireguard_service.h"   // 7.5: wg0 (WireGuard-Tunnel als Schnittstelle)
#include "network_platform.h"    // netIfaceSubnetCidr (Prefixlaenge des wg-netif)

void netRegistryBuild(NetIface out[], int maxOut, int& count) {
    count = 0;
    // IPsec-Tunnel (WeirdIKE) als konkrete Schnittstelle ipsec0: kein WAN, kein LAN -- ein
    // Punkt-zu-Punkt-Netz ins entfernte VPN (Rolle "vpn"); Dienste koennen darauf lauschen.
    if (count < maxOut) {
        bool up = ipsecRuntime.tunnelUp();
        NetIface& n = out[count++];
        n.id = "ipsec0"; n.kind = "vpn"; n.up = up; n.ip = up ? ipsecRuntime.tunnelIp() : String("");
        n.roles = 0; n.label = String("IPsec-Tunnel (ipsec0)") + (up ? " - " + ipsecRuntime.tunnelRoute() : String(""));
        n.device = ""; n.port = "";
    }
    // 7.5 / Zonen 0.1: WireGuard-Tunnel als konkrete Schnittstelle wg0 (Server- oder Client-Rolle).
    if (count < maxOut) {
        bool up = wireguardService.isUp();
        NetIface& n = out[count++];
        n.id = "wg0"; n.kind = "vpn"; n.up = up; n.ip = up ? wireguardService.tunnelLocalIp() : String("");
        n.roles = 0;
        n.label = String("WireGuard-Tunnel (wg0) - ") + (wireguardService.isServerRole() ? "Server" : "Client");
        n.device = ""; n.port = "";
    }
    // Mobilfunk-Datenpfade sind KONKRETE Interfaces (kein erfundenes "Mobilfunk-WAN"). WAN-faehig.
    if (count < maxOut) {
        bool up = ec200aEcm.isUp();
        NetIface& n = out[count++];
        n.id = "modem-ecm"; n.kind = "cellular"; n.up = up; n.ip = up ? ecmWanIp() : String("");
        n.roles = NETROLE_WAN; n.label = "Mobilfunk (EC200A) - ECM"; n.device = "EC200A"; n.port = periphModemPort;
    }
    if (count < maxOut) {
        bool up = pppIsUp();
        NetIface& n = out[count++];
        n.id = "modem-ppp"; n.kind = "cellular"; n.up = up; n.ip = up ? pppIpStr() : String("");
        n.roles = NETROLE_WAN; n.label = "Mobilfunk (EC200A) - PPP"; n.device = "EC200A"; n.port = periphModemPort;
    }
#if WEIRDOS_FEATURE_WIFI
    if (count < maxOut) {
        bool up = (WiFi.status() == WL_CONNECTED);
        NetIface& n = out[count++];
        n.id = "wifi-sta"; n.kind = "wifi"; n.up = up; n.ip = up ? WiFi.localIP().toString() : String("");
        n.roles = NETROLE_WAN; n.label = String("WLAN") + (up ? " - " + WiFi.SSID() : String("")); n.device = "WiFi"; n.port = "";
    }
    // SoftAP ist ein konkretes LAN-Interface (Rolle LAN) -- strukturell fuer den Zone/Forwarding-Layer.
    if (count < maxOut) {
        bool up = (WiFi.getMode() & WIFI_MODE_AP) != 0;
        NetIface& n = out[count++];
        n.id = "wifi-ap"; n.kind = "wifi"; n.up = up; n.ip = up ? WiFi.softAPIP().toString() : String("");
        n.roles = NETROLE_LAN; n.label = "WLAN-AccessPoint"; n.device = "WiFi"; n.port = "";
    }
#endif   // ohne WLAN-Baustein gibt es die Interfaces wifi-sta/wifi-ap nicht (netInterfaceById -> false; Egress/WAN-Policy fallen auf Mobilfunk)
}

bool netInterfaceById(const String& id, NetIface& out) {
    NetIface ifs[8];
    int n = 0;
    netRegistryBuild(ifs, 8, n);
    for (int i = 0; i < n; i++) {
        if (ifs[i].id == id) { out = ifs[i]; return true; }
    }
    return false;
}

// ---- Helfer ------------------------------------------------------------------------------
static uint8_t maskToPrefix(const IPAddress& m) {
    uint32_t v = ((uint32_t)m[0] << 24) | ((uint32_t)m[1] << 16) | ((uint32_t)m[2] << 8) | m[3];
    uint8_t p = 0; while (p < 32 && (v & (0x80000000u >> p))) p++;
    return p;
}
static String netOf(const IPAddress& ip, uint8_t prefix) {
    uint32_t v = ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) | ((uint32_t)ip[2] << 8) | ip[3];
    uint32_t mask = prefix == 0 ? 0 : (prefix >= 32 ? 0xFFFFFFFFu : ~((1u << (32 - prefix)) - 1u));
    v &= mask;
    char b[20]; snprintf(b, sizeof(b), "%u.%u.%u.%u", (unsigned)(v >> 24) & 255u, (unsigned)(v >> 16) & 255u, (unsigned)(v >> 8) & 255u, (unsigned)v & 255u);
    return String(b);
}
static void attInit(NetAttachment& a, const char* id, const char* iface, NetAttachKind kind, const char* label) {
    a.id = id; a.ifaceId = iface; a.kind = kind; a.label = label; a.up = false; a.local = ""; a.localPrefix = 0;
    a.configured = true; a.runtimeSupported = true; a.stateNote = "";
    a.mtu = 0; a.addrSource = NADDR_NONE; a.acceptSrc = ""; a.acceptSrcKnown = false; a.returnTo = ""; a.returnToKnown = false;
}
// "a.b.c.d/n" -> net + prefix (false wenn unparsbar). "any"/"0.0.0.0/0" -> prefix 0.
static bool parseCidr(const String& s, String& net, uint8_t& prefix) {
    String t = s; t.trim();
    if (t == "any" || t == "0.0.0.0/0") { net = "0.0.0.0"; prefix = 0; return true; }
    int sl = t.indexOf('/');
    IPAddress ip;
    if (sl < 0) { if (!ip.fromString(t)) return false; net = t; prefix = 32; return true; }
    if (!ip.fromString(t.substring(0, sl))) return false;
    int p = t.substring(sl + 1).toInt(); if (p < 0 || p > 32) return false;
    prefix = (uint8_t)p; net = netOf(ip, prefix);
    return true;
}
static bool g_prefixOverflow = false;   // hat der letzte Build die globale Prefix-Kapazitaet (NET_PREFIX_MAX) erreicht?
static void addPrefix(ReachablePrefix out[], int maxOut, int& count, const String& att, const String& cidr, NetPrefixSource src) {
    String net; uint8_t p;
    if (!parseCidr(cidr, net, p)) return;
    // Gleiches Prefix, andere Herkunft: Provenance zusammenfuehren (sourceMask), nicht verlieren.
    for (int i = 0; i < count; i++) if (out[i].attachmentId == att && out[i].net == net && out[i].prefix == p) { out[i].sourceMask |= NPFX_BIT(src); return; }
    if (count >= maxOut) { g_prefixOverflow = true; return; }   // global voll: sichtbar melden, nicht still verwerfen
    ReachablePrefix& r = out[count++]; r.attachmentId = att; r.net = net; r.prefix = p; r.sourceMask = NPFX_BIT(src);
    r.routingEligible = true; r.reason = "";
}
// Nach dem Sammeln: Routing-Eignung bestimmen. Standardroute nie als Zonenroute (E3); CP-SUBNET nur,
// wenn ein ausgehandelter TSr desselben Attachments es deckt (PO-Regel Fassung 4).
static bool cidrContains(const String& outerNet, uint8_t outerLen, const String& innerNet, uint8_t innerLen) {
    IPAddress o, i; if (!o.fromString(outerNet) || !i.fromString(innerNet) || innerLen < outerLen) return false;
    uint32_t ov = ((uint32_t)o[0] << 24) | ((uint32_t)o[1] << 16) | ((uint32_t)o[2] << 8) | o[3];
    uint32_t iv = ((uint32_t)i[0] << 24) | ((uint32_t)i[1] << 16) | ((uint32_t)i[2] << 8) | i[3];
    uint32_t mask = outerLen == 0 ? 0 : (outerLen >= 32 ? 0xFFFFFFFFu : ~((1u << (32 - outerLen)) - 1u));
    return (ov & mask) == (iv & mask);
}
static void finalizeEligibility(ReachablePrefix out[], int count) {
    for (int i = 0; i < count; i++) {
        ReachablePrefix& r = out[i];
        r.routingEligible = true; r.reason = "";
        if (r.sourceMask == NPFX_BIT(NPFX_DEFAULT)) { r.routingEligible = false; r.reason = "Standardroute wird nicht als Zonenroute installiert (Full Tunnel nicht implementiert)"; continue; }
        if (r.sourceMask == NPFX_BIT(NPFX_CPSUBNET)) {
            bool covered = false;
            for (int k = 0; k < count && !covered; k++) {
                if (k == i || out[k].attachmentId != r.attachmentId || !(out[k].sourceMask & NPFX_BIT(NPFX_TSR))) continue;
                covered = cidrContains(out[k].net, out[k].prefix, r.net, r.prefix);
            }
            if (!covered) { r.routingEligible = false; r.reason = "nicht durch ausgehandelten TSr gedeckt (nur vom Gateway gemeldet)"; }
        }
    }
}
static void addPrefixCsv(ReachablePrefix out[], int maxOut, int& count, const String& att, const String& csv, NetPrefixSource src) {
    String rest = csv;
    while (rest.length()) {
        int c = rest.indexOf(','); String one = (c < 0) ? rest : rest.substring(0, c); one.trim();
        if (one.length()) addPrefix(out, maxOut, count, att, one, src);
        rest = (c < 0) ? String("") : rest.substring(c + 1);
    }
}

// ---- Attachments -------------------------------------------------------------------------
void netAttachmentsBuild(NetAttachment out[], int maxOut, int& count) {
    count = 0;
#if WEIRDOS_FEATURE_WIFI
    // WLAN-AP: wir sind Gateway des AP-Netzes -> Absender beliebig, Rueckweg bekannt (Clients routen zu uns).
    if (count < maxOut) {
        NetAttachment& a = out[count++]; attInit(a, "wlan-ap", "wifi-ap", NATT_LAN, "WLAN-AccessPoint (eigenes Netz)");
        a.up = (WiFi.getMode() & WIFI_MODE_AP) != 0;
        if (a.up) { a.local = WiFi.softAPIP().toString(); a.localPrefix = maskToPrefix(WiFi.softAPSubnetMask()); a.addrSource = NADDR_CONFIG; a.mtu = 1500; }
        a.acceptSrc = "any"; a.acceptSrcKnown = true; a.returnTo = "any"; a.returnToKnown = true;
    }
    // WLAN-Client: EIN Interface, ZWEI Attachments -- Teilnehmer im fremden LAN (Zone Heimnetz) und Uplink-Kandidat.
    bool staUp = (WiFi.status() == WL_CONNECTED);
    if (count < maxOut) {
        NetAttachment& a = out[count++]; attInit(a, "wlan-sta-lan", "wifi-sta", NATT_LAN, "WLAN-Client: Netz des fremden Routers");
        a.up = staUp;
        if (staUp) { a.local = WiFi.localIP().toString(); a.localPrefix = maskToPrefix(WiFi.subnetMask()); a.addrSource = NADDR_DHCP; a.mtu = 1500; }
        // Das fremde LAN filtert Absender nicht (any), kennt aber KEINEN Rueckweg zu unseren Tunnel-/AP-Netzen.
        a.acceptSrc = "any"; a.acceptSrcKnown = true; a.returnTo = ""; a.returnToKnown = false;
    }
    if (count < maxOut) {
        NetAttachment& a = out[count++]; attInit(a, "wlan-sta-uplink", "wifi-sta", NATT_UPLINK, "WLAN-Client als Internet-Uplink");
        a.up = staUp;
        if (staUp) { a.local = WiFi.localIP().toString(); a.localPrefix = 32; a.addrSource = NADDR_DHCP; a.mtu = 1500; }
    }
#else
    // Baustein WIFI fehlt (WEIRDOS_FEATURE_WIFI=0): die drei WLAN-Anbindungen bleiben als Eintraege
    // SICHTBAR -- Zonen-UI und Konsole zeigen den Grund statt einer Luecke, gespeicherte Zonen-Intents
    // auf wlan-* bleiben gueltig, aber "nicht verfuegbar" -- dasselbe Muster wie ipsec-server ohne
    // Runtime: runtimeSupported=false, nie up, ohne Adresse/Capabilities (Planner: IMPOSSIBLE).
    {
        static const char* const kNoWifi = "WLAN nicht im Build enthalten (WEIRDOS_FEATURE_WIFI=0)";
        if (count < maxOut) {
            NetAttachment& a = out[count++]; attInit(a, "wlan-ap", "wifi-ap", NATT_LAN, "WLAN-AccessPoint (eigenes Netz)");
            a.configured = false; a.runtimeSupported = false; a.stateNote = kNoWifi;
        }
        if (count < maxOut) {
            NetAttachment& a = out[count++]; attInit(a, "wlan-sta-lan", "wifi-sta", NATT_LAN, "WLAN-Client: Netz des fremden Routers");
            a.configured = false; a.runtimeSupported = false; a.stateNote = kNoWifi;
        }
        if (count < maxOut) {
            NetAttachment& a = out[count++]; attInit(a, "wlan-sta-uplink", "wifi-sta", NATT_UPLINK, "WLAN-Client als Internet-Uplink");
            a.configured = false; a.runtimeSupported = false; a.stateNote = kNoWifi;
        }
    }
#endif
    // Mobilfunk-Uplink: das aktive Datenlink-Interface (ECM oder PPP).
    if (count < maxOut) {
        bool ecm = ec200aEcm.isUp(), ppp = pppIsUp();
        NetAttachment& a = out[count++]; attInit(a, "modem-uplink", ecm ? "modem-ecm" : "modem-ppp", NATT_UPLINK, "Mobilfunk als Internet-Uplink");
        a.up = ecm || ppp;
        if (a.up) { a.local = ecm ? ecmWanIp() : pppIpStr(); a.localPrefix = 32; a.addrSource = NADDR_PEER; a.mtu = (uint16_t)ipsecRuntime.uplinkMtu(); }
    }
    // WireGuard: IMMER beide Rollen als getrennte Attachments. Das vendorte Backend ist heute eine
    // einzige Instanz (ein statisches WireGuard-Objekt, ein netif) -> es kann nur EINE Rolle gleichzeitig
    // laufen; die andere ist "configured=false / nicht up" mit Grund, verschwindet aber nicht.
    {
        bool serverRole = wireguardService.isServerRole();
        bool ifUp = wireguardService.ifaceUp();
        String cidr = ifUp ? netIfaceSubnetCidr("wg0") : String("");
        int sl = cidr.indexOf('/'); uint8_t pfx = (sl > 0) ? (uint8_t)cidr.substring(sl + 1).toInt() : 32;
        if (count < maxOut) {
            NetAttachment& a = out[count++]; attInit(a, "wg-server", "wg0", NATT_WG_SERVER, "WireGuard-Server (eigener Tunnel)");
            a.configured = serverRole; a.runtimeSupported = true;
            a.up = serverRole && ifUp;   // Server lauscht -> up, auch ohne verbundenen Peer (Policies/Routen vorab installiert)
            if (a.up) { a.local = wireguardService.tunnelLocalIp(); a.localPrefix = pfx; a.addrSource = NADDR_CONFIG; a.mtu = 1420; }
            else a.stateNote = serverRole ? "WireGuard-Server nicht gestartet" : "WireGuard-Backend laeuft im Client-Modus (eine Instanz)";
            // Gegenseite = unsere Clients mit der von uns erzeugten Konfiguration: deren AllowedIPs sagen,
            // welche Absender sie annehmen und wohin sie zurueckrouten.
            String cc = serverRole ? wireguardService.clientConfigCidrs() : String("");
            a.acceptSrc = cc; a.acceptSrcKnown = cc.length() > 0;
            a.returnTo = cc;  a.returnToKnown = cc.length() > 0;
        }
        if (count < maxOut) {
            NetAttachment& a = out[count++]; attInit(a, "wg-client", "wg0", NATT_WG_CLIENT, "WireGuard-Client (fremder Server)");
            a.configured = !serverRole; a.runtimeSupported = true;
            a.up = !serverRole && ifUp;
            if (a.up) { a.local = wireguardService.tunnelLocalIp(); a.localPrefix = pfx; a.addrSource = NADDR_CONFIG; a.mtu = 1420; }
            else a.stateNote = !serverRole ? "WireGuard-Client nicht verbunden" : "WireGuard-Backend laeuft im Server-Modus (eine Instanz)";
            // Fremder Server: seine Peer-AllowedIPs fuer uns kennen wir nicht -> unbekannt (= nein).
            a.acceptSrcKnown = false; a.returnToKnown = false;
        }
    }
    // IPsec: IMMER beide Rollen. Client (ipsec0) hat die WeirdIKE-Runtime; Server/Responder ist heute nur
    // Konfiguration/UI (IpsecService::runtimeAvailable() gilt nur fuer mode=client) -> runtimeSupported=false,
    // ehrlich als "nicht verfuegbar" statt Fake-Zonenroute.
    {
        const IpsecConfig& ic = ipsecService.config();
        if (count < maxOut) {
            NetAttachment& a = out[count++]; attInit(a, "ipsec-client", "ipsec0", NATT_IPSEC, "IPsec-Client (Tunnel zum Gateway)");
            a.configured = (ic.mode == "client"); a.runtimeSupported = true;
            IpsecNetInfo ni;
            if (ipsecRuntime.tunnelNetInfo(ni) && ni.up) {
                a.up = true; a.local = ni.local; a.localPrefix = 32; a.mtu = (uint16_t)ni.mtu;
                a.addrSource = ni.addrSource == 2 ? NADDR_CP : (ni.addrSource == 3 ? NADDR_TSI : (ni.addrSource == 1 ? NADDR_CONFIG : NADDR_NONE));
                // TSi = was das Gateway als Absender annimmt UND wohin es zurueckroutet. "" = Bereich nicht prefix-foermig -> unbekannt.
                a.acceptSrc = ni.tsi; a.acceptSrcKnown = ni.tsi.length() > 0;
                a.returnTo = ni.tsi;  a.returnToKnown = ni.tsi.length() > 0;
            } else a.stateNote = a.configured ? "IPsec-Tunnel nicht aufgebaut" : "IPsec-Profil steht auf Server-Modus";
        }
        if (count < maxOut) {
            NetAttachment& a = out[count++]; attInit(a, "ipsec-server", "ipsec-srv", NATT_IPSEC_SERVER, "IPsec-Server (Clients haengen an uns)");
            a.configured = (ic.mode == "server"); a.runtimeSupported = false; a.up = false;
            a.stateNote = "IPsec-Server-Runtime noch nicht implementiert (nur Konfiguration, Pool " + ic.poolSubnet + ")";
            // Kein Endpunkt, keine Capabilities: Quellnetze waeren die tatsaechlich vergebenen Client-Adressen /
            // ausgehandelten TSi, NICHT blind das Pool-CIDR -- das gibt es erst mit dem Responder.
            a.acceptSrcKnown = false; a.returnToKnown = false;
        }
    }
}

bool netAttachmentById(const String& id, NetAttachment& out) {
    NetAttachment at[NET_ATTACH_MAX]; int n = 0;
    netAttachmentsBuild(at, NET_ATTACH_MAX, n);
    for (int i = 0; i < n; i++) if (at[i].id == id) { out = at[i]; return true; }
    return false;
}

// ---- Erreichbare Prefixe ------------------------------------------------------------------
bool netReachablePrefixOverflow() { return g_prefixOverflow; }
void netReachablePrefixesBuild(ReachablePrefix out[], int maxOut, int& count) {
    g_prefixOverflow = false;
    count = 0;
#if WEIRDOS_FEATURE_WIFI
    if (WiFi.getMode() & WIFI_MODE_AP) {
        uint8_t p = maskToPrefix(WiFi.softAPSubnetMask());
        addPrefix(out, maxOut, count, "wlan-ap", netOf(WiFi.softAPIP(), p) + "/" + String(p), NPFX_ONLINK);
    }
    if (WiFi.status() == WL_CONNECTED) {
        uint8_t p = maskToPrefix(WiFi.subnetMask());
        addPrefix(out, maxOut, count, "wlan-sta-lan", netOf(WiFi.localIP(), p) + "/" + String(p), NPFX_ONLINK);
        addPrefix(out, maxOut, count, "wlan-sta-uplink", "0.0.0.0/0", NPFX_DEFAULT);
    }
#endif   // ohne WLAN-Baustein keine wlan-*-Prefixe
    if (ec200aEcm.isUp() || pppIsUp()) addPrefix(out, maxOut, count, "modem-uplink", "0.0.0.0/0", NPFX_DEFAULT);
    if (wireguardService.ifaceUp()) {
        bool server = wireguardService.isServerRole();
        String att = server ? "wg-server" : "wg-client";   // Prefixe nur fuer die Rolle, die das Backend gerade faehrt
        String cidr = netIfaceSubnetCidr("wg0");
        if (cidr.length()) addPrefix(out, maxOut, count, att, cidr, NPFX_ONLINK);
        // Server: Peer-AllowedIPs (Client-Tunnel-IPs /32); Client: was wir durch den Tunnel routen (AllowedIPs des Servers).
        addPrefixCsv(out, maxOut, count, att, wireguardService.peerAllowedCidrs(), NPFX_ALLOWEDIPS);
    }
    IpsecNetInfo ni;
    if (ipsecRuntime.tunnelNetInfo(ni) && ni.up) {
        for (int i = 0; i < ni.nTsr; i++) addPrefix(out, maxOut, count, "ipsec-client", ni.tsr[i], NPFX_TSR);
        for (int i = 0; i < ni.nCpSub; i++) addPrefix(out, maxOut, count, "ipsec-client", ni.cpSub[i], NPFX_CPSUBNET);
    }
    // IPsec-Server: Pool-CIDR nur als Information (keine Runtime -> nie routingfaehig, s. finalizeEligibility).
    { const IpsecConfig& ic = ipsecService.config(); if (ic.mode == "server" && ic.poolSubnet.length()) addPrefix(out, maxOut, count, "ipsec-server", ic.poolSubnet, NPFX_ONLINK); }
    finalizeEligibility(out, count);
    for (int i = 0; i < count; i++) if (out[i].attachmentId == "ipsec-server") { out[i].routingEligible = false; out[i].reason = "IPsec-Server-Runtime noch nicht implementiert (konfigurierter Pool, keine vergebenen Adressen)"; }
}

// ---- Namen -------------------------------------------------------------------------------
const char* netAttachKindName(NetAttachKind k) {
    switch (k) {
        case NATT_LAN: return "lan";
        case NATT_UPLINK: return "uplink";
        case NATT_WG_SERVER: return "wg-server";
        case NATT_WG_CLIENT: return "wg-client";
        case NATT_IPSEC: return "ipsec";
        case NATT_IPSEC_SERVER: return "ipsec-server";
    }
    return "?";
}
const char* netAddrSourceName(NetAddrSource s) {
    switch (s) {
        case NADDR_NONE: return "keine";
        case NADDR_CONFIG: return "konfiguriert";
        case NADDR_DHCP: return "DHCP";
        case NADDR_CP: return "vom Gateway per IKE Config Mode";
        case NADDR_TSI: return "vom Gateway (TSi)";
        case NADDR_PEER: return "vom Netz zugewiesen";
    }
    return "?";
}
const char* netPrefixSourceName(NetPrefixSource s) {
    switch (s) {
        case NPFX_ONLINK: return "on-link";
        case NPFX_DEFAULT: return "Standardroute";
        case NPFX_TSR: return "ausgehandelt (TSr)";
        case NPFX_CPSUBNET: return "vom Gateway gemeldet (CP-SUBNET, nur Information)";
        case NPFX_ALLOWEDIPS: return "AllowedIPs";
    }
    return "?";
}
String netPrefixSourcesText(uint8_t mask) {
    String t;
    for (uint8_t s = 0; s <= NPFX_ALLOWEDIPS; s++) {
        if (!(mask & NPFX_BIT(s))) continue;
        if (t.length()) t += " + ";
        t += netPrefixSourceName((NetPrefixSource)s);
    }
    return t.length() ? t : String("?");
}

// ---- JSON --------------------------------------------------------------------------------
static String jsonEsc(const String& s) {
    String o; o.reserve(s.length() + 4);
    for (size_t i = 0; i < s.length(); i++) { char c = s[i]; if (c == '"' || c == '\\') o += '\\'; if ((uint8_t)c < 0x20) continue; o += c; }
    return o;
}

String netRegistryJson() {
    NetIface ifs[8];
    int n = 0;
    netRegistryBuild(ifs, 8, n);
    String j = "{\"interfaces\":[";
    for (int i = 0; i < n; i++) {
        if (i) j += ",";
        j += "{\"id\":\"";     j += ifs[i].id;
        j += "\",\"kind\":\""; j += ifs[i].kind;
        j += "\",\"up\":";     j += ifs[i].up ? "true" : "false";
        j += ",\"ip\":\"";     j += ifs[i].ip;
        j += "\",\"roles\":";  j += String((unsigned)ifs[i].roles);
        j += ",\"wan\":";      j += (ifs[i].roles & NETROLE_WAN) ? "true" : "false";
        j += ",\"lan\":";      j += (ifs[i].roles & NETROLE_LAN) ? "true" : "false";
        j += ",\"label\":\"";  j += jsonEsc(ifs[i].label);
        j += "\",\"device\":\"";j += ifs[i].device;
        j += "\",\"port\":\""; j += ifs[i].port;
        j += "\"}";
    }
    j += "],\"attachments\":[";
    NetAttachment at[NET_ATTACH_MAX]; int na = 0;
    netAttachmentsBuild(at, NET_ATTACH_MAX, na);
    for (int i = 0; i < na; i++) {
        if (i) j += ",";
        j += "{\"id\":\"";         j += at[i].id;
        j += "\",\"iface\":\"";    j += at[i].ifaceId;
        j += "\",\"kind\":\"";     j += netAttachKindName(at[i].kind);
        j += "\",\"up\":";         j += at[i].up ? "true" : "false";
        j += ",\"configured\":";   j += at[i].configured ? "true" : "false";
        j += ",\"runtimeSupported\":"; j += at[i].runtimeSupported ? "true" : "false";
        j += ",\"stateNote\":\"";  j += jsonEsc(at[i].stateNote); j += "\"";
        j += ",\"local\":\"";      j += at[i].local;
        j += "\",\"prefix\":";     j += String((unsigned)at[i].localPrefix);
        j += ",\"mtu\":";          j += String((unsigned)at[i].mtu);
        j += ",\"addrSource\":\""; j += netAddrSourceName(at[i].addrSource);
        j += "\",\"acceptSrc\":\"";j += jsonEsc(at[i].acceptSrc);
        j += "\",\"acceptSrcKnown\":"; j += at[i].acceptSrcKnown ? "true" : "false";
        j += ",\"returnTo\":\"";   j += jsonEsc(at[i].returnTo);
        j += "\",\"returnToKnown\":"; j += at[i].returnToKnown ? "true" : "false";
        j += ",\"label\":\"";      j += jsonEsc(at[i].label);
        j += "\"}";
    }
    j += "],\"prefixes\":[";
    ReachablePrefix pf[NET_PREFIX_MAX]; int np = 0;
    netReachablePrefixesBuild(pf, NET_PREFIX_MAX, np);
    for (int i = 0; i < np; i++) {
        if (i) j += ",";
        j += "{\"attachment\":\""; j += pf[i].attachmentId;
        j += "\",\"net\":\"";      j += pf[i].net;
        j += "\",\"prefix\":";     j += String((unsigned)pf[i].prefix);
        j += ",\"source\":\"";     j += netPrefixSourcesText(pf[i].sourceMask);
        j += "\",\"sources\":[";
        { bool first = true; for (uint8_t s = 0; s <= NPFX_ALLOWEDIPS; s++) { if (!(pf[i].sourceMask & NPFX_BIT(s))) continue; if (!first) j += ","; first = false;
              j += "\""; j += (s == NPFX_ONLINK ? "onlink" : s == NPFX_DEFAULT ? "default" : s == NPFX_TSR ? "tsr" : s == NPFX_CPSUBNET ? "cpsubnet" : "allowedips"); j += "\""; } }
        j += "],\"routingEligible\":"; j += pf[i].routingEligible ? "true" : "false";
        j += ",\"reason\":\"";     j += jsonEsc(pf[i].reason);
        j += "\"}";
    }
    j += "],\"prefixOverflow\":"; j += netReachablePrefixOverflow() ? "true" : "false";   // globale Kapazitaet (NET_PREFIX_MAX) erreicht?
    j += "}";
    return j;
}
