// ============================================================================
// network_platform.cpp -- Aufloesung NetIface-id -> natives lwIP-netif.
// Hier (und NUR hier) treffen die fachlichen Interface-Namen auf lwIP/esp_netif.
// ============================================================================
#include "network_platform.h"
#include "ec200a_ecm.h"     // ecmNetifHandle()
#include "ec200a_modem.h"   // pppNetifHandle()
#include "wireguard_service.h"   // Zonen 0.1: wg0 -> nativeNetif()
#include "ipsec_runtime.h"       // Zonen 0.1: ipsec0 -> nativeNetif()

#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "lwip/netif.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip4.h"          // 7.9.4: ip4_route / ip4_route_src (Forward-Diagnose)
#include "lwip/tcpip.h"        // 7.6: LOCK_TCPIP_CORE (CONFIG_LWIP_TCPIP_CORE_LOCKING)
#include "lwip/lwip_napt.h"    // 7.6: ip_napt_enable_netif
#include <cstdio>

static struct netif* resolveNetif(const String& id) {
    if (id == "modem-ecm") return ecmNetifHandle();
    if (id == "modem-ppp") return pppNetifHandle();
    if (id == "wifi-sta") {
        esp_netif_t* sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        return sta ? (struct netif*)esp_netif_get_netif_impl(sta) : nullptr;
    }
    if (id == "wifi-ap") {   // 7.8: eigener AccessPoint der MCU (LAN-Gateway-Ziel)
        esp_netif_t* ap = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
        return ap ? (struct netif*)esp_netif_get_netif_impl(ap) : nullptr;
    }
    // Zonen 0.1: Tunnel-Interfaces ueber ihre Dienste (kein Suchen nach dynamischen Namen).
    if (id == "wg0")    return (struct netif*)wireguardService.nativeNetif();
    if (id == "ipsec0") return (struct netif*)ipsecRuntime.nativeNetif();
    return nullptr;
}

void* netIfaceNativeHandle(const String& id) {
    return (void*)resolveNetif(id);
}

String netIfaceNativeName(const String& id) {
    struct netif* n = resolveNetif(id);
    if (!n) return "";
    char b[8];
    snprintf(b, sizeof(b), "%c%c%u", n->name[0], n->name[1], (unsigned)n->num);
    return String(b);
}

// 7.9.4: Diagnose des Rueckwegs. Findet das wg-netif (name "wg") + fragt lwIP, welches
// Interface es fuer typische Ziele waehlt. Unter LOCK_TCPIP_CORE (ip4_route/netif-Zugriff).
static String routeNetifName(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    ip4_addr_t dst; IP4_ADDR(&dst, a, b, c, d);
    struct netif* r = ip4_route(&dst);
    if (!r) return "none";
    char nm[8]; snprintf(nm, sizeof(nm), "%c%c%u", r->name[0], r->name[1], (unsigned)r->num);
    return String(nm);
}
// 7.9.7: Route MIT Quelle (nutzt den ESP-Hook ip4_route_src, da LWIP_HOOK_IP4_ROUTE_SRC aktiv).
static String routeSrcNetifName(uint8_t sa, uint8_t sb, uint8_t sc, uint8_t sd,
                                uint8_t da, uint8_t db, uint8_t dc, uint8_t dd) {
    ip4_addr_t s, d; IP4_ADDR(&s, sa, sb, sc, sd); IP4_ADDR(&d, da, db, dc, dd);
    struct netif* r = ip4_route_src(&s, &d);
    if (!r) return "none";
    char nm[8]; snprintf(nm, sizeof(nm), "%c%c%u", r->name[0], r->name[1], (unsigned)r->num);
    return String(nm);
}

String wgRouteDiagJson() {
    String j = "{";
    LOCK_TCPIP_CORE();
    struct netif* wg = nullptr;
    for (struct netif* n = netif_list; n; n = n->next) {
        if (n->name[0] == 'w' && n->name[1] == 'g') { wg = n; break; }
    }
    if (wg) {
        char nm[8]; snprintf(nm, sizeof(nm), "%c%c%u", wg->name[0], wg->name[1], (unsigned)wg->num);
        ip4_addr_t a = *netif_ip4_addr(wg), m = *netif_ip4_netmask(wg);
        j += "\"wg\":\"";   j += nm; j += "\",";
        j += "\"up\":";     j += netif_is_up(wg) ? "true" : "false"; j += ",";
        j += "\"link\":";   j += netif_is_link_up(wg) ? "true" : "false"; j += ",";
        j += "\"ip\":\"";   j += ip4addr_ntoa(&a); j += "\",";
        j += "\"mask\":\""; j += ip4addr_ntoa(&m); j += "\",";
    } else {
        j += "\"wg\":\"none\",";
    }
    j += "\"route_client\":\""; j += routeNetifName(10, 9, 0, 2);    j += "\",";
    j += "\"route_lanpc\":\"";  j += routeNetifName(172, 17, 1, 18); j += "\",";
    j += "\"route_src_pc\":\""; j += routeSrcNetifName(10, 9, 0, 2, 172, 17, 1, 18); j += "\"";
    UNLOCK_TCPIP_CORE();
    j += "}";
    return j;
}

void netIfacePrepareEgress(const String& id) {
    // ECM setzt die Carrier-DNS global; ohne Route-Pin scheitert getaddrinfo, wenn die
    // Default-Route woanders liegt. Hier gekapselt - kein ECM-Wissen im Consumer.
    if (id == "modem-ecm") ecmSetDefaultRoute();
    // modem-ppp: pppapi_set_default haelt es ohnehin. wifi-sta: WLAN ist ohnehin Default.
}

// 7.6: NAPT auf dem LAN-Interface. Unter LOCK_TCPIP_CORE (netif/ip-State), da aus dem
// wg_conn-Task gerufen. ip_napt_enable_netif legt bei Bedarf die NAPT-Tabelle an.
bool netIfaceSetNapt(const String& id, bool enable) {
    struct netif* n = resolveNetif(id);
    if (!n) return false;
    LOCK_TCPIP_CORE();
    int ok = ip_napt_enable_netif(n, enable ? 1 : 0);
    UNLOCK_TCPIP_CORE();
    return ok != 0;
}

// 7.9.8: NAPT auf einem nativen netif-Handle (das WG-Input-netif). esp-lwip: ip4_forward ruft
// NAPT nur, wenn das OUTPUT-netif kein NAPT hat, und ip_napt_forward braucht das INPUT-netif mit
// NAPT-Flag. Also gehoert das Flag aufs wg-netif; die NAT-Adresse ist die IP des Ausgangs (st1/ap).
bool netIfaceSetNaptNative(void* nativeHandle, bool enable) {
    struct netif* n = (struct netif*)nativeHandle;
    if (!n) return false;
    LOCK_TCPIP_CORE();
    int ok = ip_napt_enable_netif(n, enable ? 1 : 0);
    UNLOCK_TCPIP_CORE();
    return ok != 0;
}

// 7.6: LAN-Subnetz als CIDR aus ip&netmask des Interfaces.
String netIfaceSubnetCidr(const String& id) {
    struct netif* n = resolveNetif(id);
    if (!n || !netif_is_up(n)) return "";
    uint32_t ip   = ip4_addr_get_u32(netif_ip4_addr(n));
    uint32_t mask = ip4_addr_get_u32(netif_ip4_netmask(n));
    if (mask == 0) return "";
    ip4_addr_t net; ip4_addr_set_u32(&net, ip & mask);
    // Praefixlaenge aus der Maske (Host-Byte-Order).
    int prefix = 0; uint32_t m = lwip_ntohl(mask);
    while (m & 0x80000000UL) { prefix++; m <<= 1; }
    char b[24];
    snprintf(b, sizeof(b), "%s/%d", ip4addr_ntoa(&net), prefix);
    return String(b);
}
