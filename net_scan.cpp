// ============================================================================
// net_scan.cpp -- 7.10: LAN-Host-Scan + Ping (esp_ping) von der MCU aus.
// ============================================================================
#include "weirdos_features.h"      // WEIRDOS_FEATURE_NETSCAN -- der Schalter dieses Bausteins
                                   // (+ WEIRDOS_FEATURE_WIFI: Funk-Recon 7.13-7.15 nur mit WLAN-Baustein; L3/L4 immer)
#include "net_scan.h"               // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
#if WEIRDOS_FEATURE_NETSCAN
// ============================================================================
// Echte Implementierung (WEIRDOS_FEATURE_NETSCAN=1)
// ============================================================================
#include "bt_scan.h"        // 8.0: btBusy() - BLE-Scan und WLAN-Funk-Recon nicht gleichzeitig
#include "network_registry.h"     // D1: Ziele/Attachments/Prefixe aus der Registry
#include "network_platform.h"     // D1: netIfaceNativeHandle (Interface-id -> netif)
#include "zone_lwip_hooks.h"      // D1: zoneRouteMatch (Zonenroute fuer eine Ziel-IP)
#include "zone_runtime.h"         // D1: zoneRuntimePlanFor (installierte Forward-Policy)
#include "zone_planner_adapter.h" // D1: zonePlanJson (Planner-Vorschau einer Quelle)

#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#if WEIRDOS_FEATURE_WIFI
#include "esp_wifi.h"       // 7.13: Passiv-Monitor (Promiscuous-Mode) -- Funk, nur mit WLAN-Baustein
#endif
#include "lwip/ip_addr.h"
#include "lwip/ip4_addr.h"
#include "lwip/inet.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"    // 7.12: ARP-Host-Discovery (Layer 2)
#include "lwip/tcpip.h"     // LOCK_TCPIP_CORE
#include "lwip/sockets.h"   // 7.11: TCP/UDP connect-scan (lwip_socket/connect/select)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <fcntl.h>
#include <errno.h>
#include <vector>

extern "C" {
#include "ping/ping_sock.h"
}

// ---- gemeinsamer Zustand (per Mutex geschuetzt) ----
struct ScanHost { String ip; String mac; String vendor; long ms; };   // ms=-1: per ARP, kein Ping-Reply
static std::vector<ScanHost> s_hosts;

// OUI->Hersteller (best effort, kuratierte Liste) + Erkennung zufaelliger/privater MACs.
static String ouiVendor(const uint8_t* mac) {
    if (mac[0] & 0x02) return "zufaellig";   // locally administered = randomisierte MAC (Handys)
    uint32_t o = ((uint32_t)mac[0] << 16) | ((uint32_t)mac[1] << 8) | mac[2];
    switch (o) {
        case 0x240AC4: case 0x246F28: case 0x30AEA4: case 0x7C9EBD: case 0xA4CF12:
        case 0xCC50E3: case 0xDC4F22: case 0x083AF2: return "Espressif";
        case 0xB827EB: case 0xDCA632: case 0xE45F01: case 0x28CDC1: return "Raspberry Pi";
        case 0x3810D5: case 0x9CC7A6: case 0xE0286D: case 0xC80E14: case 0x246511: return "AVM";
        case 0x3C0754: case 0xF0DBF8: case 0xA85C2C: case 0xDC2B2A: case 0x001451: return "Apple";
        case 0x8425DB: case 0xC81479: case 0x340286: return "Samsung";
        case 0x3CA9F4: case 0x7CB27D: case 0xA0A8CD: return "Intel";
        case 0x50C7BF: case 0xEC086B: case 0x54AF97: return "TP-Link";
        default: return "";
    }
}

static String macStr(const struct eth_addr* m) {
    char b[18];
    snprintf(b, sizeof(b), "%02x:%02x:%02x:%02x:%02x:%02x",
             m->addr[0], m->addr[1], m->addr[2], m->addr[3], m->addr[4], m->addr[5]);
    return String(b);
}
static volatile bool     s_running = false;
static volatile uint32_t s_total = 0, s_scanned = 0;
static SemaphoreHandle_t s_lock = nullptr;

static void lockInit() { if (!s_lock) s_lock = xSemaphoreCreateMutex(); }
static void lock()     { if (s_lock) xSemaphoreTake(s_lock, portMAX_DELAY); }
static void unlock()   { if (s_lock) xSemaphoreGive(s_lock); }

// ---- Einzel-Ping (synchron) -------------------------------------------------
struct PingCtx { volatile bool success; volatile uint32_t ms; SemaphoreHandle_t done; };
static void ps_success(esp_ping_handle_t h, void* args) {
    PingCtx* c = (PingCtx*)args;
    uint32_t t = 0; esp_ping_get_profile(h, ESP_PING_PROF_TIMEGAP, &t, sizeof(t));
    c->ms = t; c->success = true;
}
static void ps_end(esp_ping_handle_t h, void* args) {
    PingCtx* c = (PingCtx*)args; xSemaphoreGive(c->done);
}

// ipv4Be = Ziel-IPv4 in Network-Byte-Order. true wenn geantwortet. s_pingLastErr unterscheidet
// "keine Antwort" (0) von "Session konnte nicht angelegt werden" (esp_err_t != 0, Ressourcen).
static int s_pingLastErr = 0;
static bool pingOne(uint32_t ipv4Be, uint32_t timeout_ms, uint32_t* rttMs) {
    s_pingLastErr = 0;
    PingCtx ctx; ctx.success = false; ctx.ms = 0; ctx.done = xSemaphoreCreateBinary();
    if (!ctx.done) { s_pingLastErr = -1; return false; }

    esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
    ip_addr_t target; memset(&target, 0, sizeof(target));
    IP_SET_TYPE(&target, IPADDR_TYPE_V4);
    ip4_addr_set_u32(ip_2_ip4(&target), ipv4Be);
    cfg.target_addr  = target;
    cfg.count        = 1;
    cfg.interval_ms  = 10;
    cfg.timeout_ms   = timeout_ms;
    cfg.task_stack_size = 3072;

    esp_ping_callbacks_t cbs;
    cbs.cb_args         = &ctx;
    cbs.on_ping_success = ps_success;
    cbs.on_ping_timeout = nullptr;
    cbs.on_ping_end     = ps_end;

    esp_ping_handle_t h;
    esp_err_t e = esp_ping_new_session(&cfg, &cbs, &h);
    if (e != ESP_OK) { s_pingLastErr = (int)e; vSemaphoreDelete(ctx.done); return false; }
    esp_ping_start(h);
    xSemaphoreTake(ctx.done, pdMS_TO_TICKS(timeout_ms + 1000));
    esp_ping_delete_session(h);
    if (rttMs) *rttMs = ctx.ms;
    vSemaphoreDelete(ctx.done);
    return ctx.success;
}

// ============================================================================
// D1/D2: Zielmodell + Host-Sweep (ARP nur als lokale L2-Capability, sonst ICMP), Resolve
// ============================================================================
static String s_target, s_mode, s_egress, s_attachment, s_error;

// Parallel-Ping: n Sessions gleichzeitig (jede esp_ping-Session hat einen eigenen Task mit 3 KB
// internem Stack -> Batch klein halten, internes RAM ist knapp).
#define SWEEP_PING_BATCH 3   // Hardware-Befund: 4 parallele Sessions + 11 offene Sockets (HTTP-Polling) -> einzelne Session-Fehler (Socket-Tabelle 16)
// Rueckgabe: Zahl der Ziele, fuer die KEINE Session gestartet werden konnte (Ressourcen); probed[i]=false
// fuer diese -- der Aufrufer prueft sie seriell nach, statt sie als "down" zu verbuchen.
static int pingBatch(const uint32_t* ipsBe, int n, uint32_t timeout_ms, bool* up, uint32_t* rtt, bool* probed) {
    PingCtx ctx[SWEEP_PING_BATCH]; esp_ping_handle_t h[SWEEP_PING_BATCH]; bool started[SWEEP_PING_BATCH];
    int failed = 0;
    for (int i = 0; i < n; i++) {
        up[i] = false; rtt[i] = 0; started[i] = false; probed[i] = false;
        ctx[i].success = false; ctx[i].ms = 0; ctx[i].done = xSemaphoreCreateBinary();
        if (!ctx[i].done) { failed++; continue; }
        esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
        ip_addr_t target; memset(&target, 0, sizeof(target)); IP_SET_TYPE(&target, IPADDR_TYPE_V4);
        ip4_addr_set_u32(ip_2_ip4(&target), ipsBe[i]);
        cfg.target_addr = target; cfg.count = 1; cfg.interval_ms = 10; cfg.timeout_ms = timeout_ms; cfg.task_stack_size = 3072;
        esp_ping_callbacks_t cbs; cbs.cb_args = &ctx[i]; cbs.on_ping_success = ps_success; cbs.on_ping_timeout = nullptr; cbs.on_ping_end = ps_end;
        if (esp_ping_new_session(&cfg, &cbs, &h[i]) == ESP_OK) { esp_ping_start(h[i]); started[i] = true; }
        else failed++;
    }
    for (int i = 0; i < n; i++) {
        if (!ctx[i].done) continue;
        if (started[i]) { xSemaphoreTake(ctx[i].done, pdMS_TO_TICKS(timeout_ms + 1000)); esp_ping_delete_session(h[i]); up[i] = ctx[i].success; rtt[i] = ctx[i].ms; probed[i] = true; }
        vSemaphoreDelete(ctx[i].done);
    }
    return failed;
}

// Ziel aufloesen: CIDR oder Attachment[@netz/prefix] -> Netz, eigene Adresse, Ausgangs-netif, L2 moeglich?
struct SweepTarget { uint32_t net_h, mask_h, own_h; uint8_t prefix; struct netif* nif; bool l2; String label, egress, attachment; };
static uint32_t prefixMask(uint8_t p) { return p == 0 ? 0 : (p >= 32 ? 0xFFFFFFFFu : ~((1u << (32 - p)) - 1u)); }
// Hostzahl ohne Netz-/Broadcast, 64-Bit-sicher (auch /0 = 4294967294 -> wird abgelehnt).
static uint64_t hostCount(uint8_t prefix) { if (prefix >= 32) return 1; if (prefix == 31) return 2; return (1ULL << (32 - prefix)) - 2ULL; }
// L2 (ARP) nur, wenn das GESAMTE Ziel innerhalb des on-link-Prefixes des Interfaces liegt.
static bool wholeTargetOnLink(const struct netif* nif, uint32_t net_h, uint8_t prefix) {
    if (!nif || !(nif->flags & NETIF_FLAG_ETHARP)) return false;
    uint32_t nip = lwip_ntohl(ip4_addr_get_u32(netif_ip4_addr(nif))), nmask = lwip_ntohl(ip4_addr_get_u32(netif_ip4_netmask(nif)));
    if (!nmask) return false;
    uint8_t ifp = 0; while (ifp < 32 && (nmask & (0x80000000u >> ifp))) ifp++;
    return prefix >= ifp && ((nip & nmask) == (net_h & nmask));   // Ziel-Prefix ist Teilmenge des Interface-Netzes
}
static String nifNameStr(const struct netif* n) { if (!n) return "-"; char b[8]; snprintf(b, sizeof(b), "%c%c%u", n->name[0], n->name[1], (unsigned)n->num); return String(b); }
// netif -> NetIface-id (ueber die Registry-Aufloesung; "" wenn unbekannt)
static String ifaceIdForNetif(const struct netif* n) {
    if (!n) return "";
    NetIface ifs[8]; int cnt = 0; netRegistryBuild(ifs, 8, cnt);
    for (int i = 0; i < cnt; i++) if (netIfaceNativeHandle(ifs[i].id) == (void*)n) return ifs[i].id;
    return "";
}
static bool parseCidrH(const String& s, uint32_t& net_h, uint8_t& prefix) {
    String t = s; t.trim(); int sl = t.indexOf('/'); if (sl <= 0) return false;
    ip4_addr_t a; if (!ip4addr_aton(t.substring(0, sl).c_str(), &a)) return false;
    int p = t.substring(sl + 1).toInt(); if (p < 0 || p > 32) return false;
    prefix = (uint8_t)p; net_h = lwip_ntohl(ip4_addr_get_u32(&a)) & prefixMask(prefix);
    return true;
}
// Attachment fuer eine Ziel-IP bestimmen: ueber die ReachablePrefixes der Attachments auf dem
// Ausgangsinterface (laengste Deckung gewinnt; Standardroute = Uplink-Attachment). NICHT nur ueber
// netif* -- wlan-sta traegt wlan-sta-lan UND wlan-sta-uplink.
static bool attachmentForTarget(const struct netif* nif, uint32_t ipH, bool isDefault, NetAttachment* outAtt, ReachablePrefix* outPfx) {
    String iface = ifaceIdForNetif(nif);
    if (!iface.length()) return false;
    NetAttachment at[NET_ATTACH_MAX]; int na = 0; netAttachmentsBuild(at, NET_ATTACH_MAX, na);
    ReachablePrefix pf[NET_PREFIX_MAX]; int np = 0; netReachablePrefixesBuild(pf, NET_PREFIX_MAX, np);
    int bestAtt = -1, bestPfx = -1, bestLen = -1;
    for (int k = 0; k < na; k++) {
        if (at[k].ifaceId != iface) continue;
        for (int i = 0; i < np; i++) {
            if (pf[i].attachmentId != at[k].id) continue;
            ip4_addr_t n; if (!ip4addr_aton(pf[i].net.c_str(), &n)) continue;
            uint32_t nh = lwip_ntohl(ip4_addr_get_u32(&n)); uint32_t m = prefixMask(pf[i].prefix);
            bool covers = (pf[i].prefix == 0) ? isDefault : ((ipH & m) == (nh & m));   // Standardroute deckt nur, wenn lwIP sie auch nahm
            if (!covers) continue;
            if ((int)pf[i].prefix > bestLen) { bestLen = pf[i].prefix; bestAtt = k; bestPfx = i; }
        }
    }
    if (bestAtt < 0) {   // kein Prefix deckt: Uplink-Attachment wenn Standardroute, sonst erstes Nicht-Uplink
        for (int k = 0; k < na; k++) if (at[k].ifaceId == iface && ((at[k].kind == NATT_UPLINK) == isDefault)) { bestAtt = k; break; }
        if (bestAtt < 0) for (int k = 0; k < na; k++) if (at[k].ifaceId == iface) { bestAtt = k; break; }
        if (bestAtt < 0) return false;
    }
    if (outAtt) *outAtt = at[bestAtt];
    if (outPfx) { if (bestPfx >= 0) *outPfx = pf[bestPfx]; else { outPfx->attachmentId = ""; outPfx->net = ""; outPfx->prefix = 0; outPfx->sourceMask = 0; outPfx->routingEligible = false; outPfx->reason = ""; } }
    return true;
}

static String resolveTarget(const String& targetIn, SweepTarget& t) {
    String target = targetIn; target.trim();
    if (!target.length()) target = "wlan-sta-lan";
    t.nif = nullptr; t.l2 = false; t.own_h = 0;
    int at = target.indexOf('@');
    bool isCidr = (at < 0) && target.indexOf('/') > 0;
    if (isCidr) {
        if (!parseCidrH(target, t.net_h, t.prefix)) return "Ungueltiges Netz (a.b.c.d/n)";
        t.mask_h = prefixMask(t.prefix);
        // Ausgang ueber die normale Routingentscheidung (inkl. Zonenroute), erste Host-Adresse als Probe.
        uint32_t probeH = t.net_h + (t.prefix >= 31 ? 0 : 1);
        ip4_addr_t probe; ip4_addr_set_u32(&probe, lwip_htonl(probeH));
        bool isDefault = false;
        LOCK_TCPIP_CORE(); t.nif = ip4_route(&probe); isDefault = t.nif && (t.nif == netif_default); UNLOCK_TCPIP_CORE();
        if (!t.nif) return "Kein Ausgang fuer dieses Netz (keine Route, oder Zonenroute BLOCK)";
        NetAttachment a; if (attachmentForTarget(t.nif, probeH, isDefault, &a, nullptr)) t.attachment = a.id;
        t.own_h = lwip_ntohl(ip4_addr_get_u32(netif_ip4_addr(t.nif)));
        t.l2 = wholeTargetOnLink(t.nif, t.net_h, t.prefix);
        t.label = target;
    } else {
        // "attachment" (nur eindeutig bei genau einem geeigneten Prefix) oder "attachment@a.b.c.d/n" (explizit).
        String attId = at > 0 ? target.substring(0, at) : target; attId.trim();
        String want = at > 0 ? target.substring(at + 1) : String(""); want.trim();
        NetAttachment a;
        if (!netAttachmentById(attId, a)) return "Unbekanntes Ziel: CIDR (a.b.c.d/n), Attachment-id oder attachment@netz/prefix (siehe 'net targets')";
        if (!a.up) return "Attachment '" + attId + "' ist nicht aktiv";
        ReachablePrefix pf[NET_PREFIX_MAX]; int np = 0; netReachablePrefixesBuild(pf, NET_PREFIX_MAX, np);
        int candidates = 0, chosen = -1; String list;
        for (int i = 0; i < np; i++) {
            if (pf[i].attachmentId != a.id || !pf[i].routingEligible || pf[i].prefix == 0) continue;
            String cidr = pf[i].net + "/" + String((unsigned)pf[i].prefix);
            candidates++; if (list.length()) list += ", "; list += cidr;
            if (want.length()) { if (cidr == want) chosen = i; }
            else if (chosen < 0) chosen = i;
        }
        if (candidates == 0) return "Attachment '" + attId + "' hat kein routingfaehiges Netz (siehe 'net targets')";
        if (want.length() && chosen < 0) return "Netz '" + want + "' gehoert nicht zu '" + attId + "' (moeglich: " + list + ")";
        if (!want.length() && candidates > 1) return "'" + attId + "' hat mehrere Netze -- bitte eindeutig: " + attId + "@<netz>  (moeglich: " + list + ")";
        ip4_addr_t n; if (!ip4addr_aton(pf[chosen].net.c_str(), &n)) return "Prefix unlesbar";
        t.net_h = lwip_ntohl(ip4_addr_get_u32(&n)); t.prefix = pf[chosen].prefix; t.mask_h = prefixMask(t.prefix);
        t.nif = (struct netif*)netIfaceNativeHandle(a.ifaceId);
        if (!t.nif) return "Interface von '" + attId + "' nicht aufloesbar";
        ip4_addr_t own; if (a.local.length() && ip4addr_aton(a.local.c_str(), &own)) t.own_h = lwip_ntohl(ip4_addr_get_u32(&own));
        t.l2 = wholeTargetOnLink(t.nif, t.net_h, t.prefix);
        t.attachment = a.id;
        t.label = a.id + "@" + pf[chosen].net + "/" + String((unsigned)t.prefix);
    }
    t.egress = nifNameStr(t.nif);
    return "";
}

struct SweepArgs { SweepTarget t; bool arp; };
struct Found { uint32_t ipBe; uint8_t mac[6]; };

static volatile uint32_t s_unprobed = 0;   // Ziele ohne Ergebnis (Ressourcenfehler) -> Sweep "unvollstaendig"

static void sweepTask(void* arg) {
    SweepArgs* a = (SweepArgs*)arg;
    const SweepTarget& t = a->t;
    // 64-Bit-Iteration: kein Wrap am oberen IPv4-Ende (255.255.255.255), keine Endlosschleife.
    uint64_t first = (uint64_t)t.net_h + (t.prefix >= 31 ? 0 : 1);
    uint64_t last  = (t.prefix >= 31) ? (uint64_t)(t.net_h | ~t.mask_h) : ((uint64_t)(t.net_h | ~t.mask_h) - 1);
    uint32_t done = 0;
    if (a->arp) {
        // Lokales L2: ARP-Discovery in Batches (findet auch Ping-/TCP-tote Hosts), danach Ping fuer RTT.
        const int BATCH = 6;
        for (uint64_t base = first; base <= last && s_running; ) {
            uint32_t ips[BATCH]; int n = 0;
            for (; n < BATCH && base <= last; base++) { if ((uint32_t)base == t.own_h) { done++; continue; } ips[n++] = (uint32_t)base; done++; }
            LOCK_TCPIP_CORE();
            for (int k = 0; k < n; k++) { ip4_addr_t x; ip4_addr_set_u32(&x, lwip_htonl(ips[k])); etharp_request(t.nif, &x); }
            UNLOCK_TCPIP_CORE();
            vTaskDelay(pdMS_TO_TICKS(350));
            Found found[BATCH]; int fn = 0;
            LOCK_TCPIP_CORE();
            for (int k = 0; k < n; k++) {
                ip4_addr_t x; ip4_addr_set_u32(&x, lwip_htonl(ips[k]));
                struct eth_addr* mac = nullptr; const ip4_addr_t* ipr = nullptr;
                if (etharp_find_addr(t.nif, &x, &mac, &ipr) >= 0 && mac) { found[fn].ipBe = lwip_htonl(ips[k]); memcpy(found[fn].mac, mac->addr, 6); fn++; }
            }
            UNLOCK_TCPIP_CORE();
            for (int j = 0; j < fn; j++) {
                ip4_addr_t x; ip4_addr_set_u32(&x, found[j].ipBe); struct eth_addr e; memcpy(e.addr, found[j].mac, 6);
                lock(); s_hosts.push_back({ String(ip4addr_ntoa(&x)), macStr(&e), ouiVendor(found[j].mac), -1 }); unlock();
            }
            s_scanned = done;
            if (n == 0) break;
        }
        lock(); size_t hn = s_hosts.size(); unlock();
        for (size_t i = 0; i < hn && s_running; i++) {
            lock(); String ipStr = s_hosts[i].ip; unlock();
            ip4_addr_t x; uint32_t rtt = 0;
            if (ip4addr_aton(ipStr.c_str(), &x) && pingOne(ip4_addr_get_u32(&x), 300, &rtt)) { lock(); s_hosts[i].ms = (long)rtt; unlock(); }
        }
    } else {
        // L3: ICMP-Sweep in kleinen Parallel-Batches durch das normale Routing (auch Tunnel/Zonenroute).
        for (uint64_t base = first; base <= last && s_running; ) {
            uint32_t ips[SWEEP_PING_BATCH]; int n = 0;
            for (; n < SWEEP_PING_BATCH && base <= last; base++) { if ((uint32_t)base == t.own_h) { done++; continue; } ips[n++] = lwip_htonl((uint32_t)base); done++; }
            if (n == 0) break;
            bool up[SWEEP_PING_BATCH]; uint32_t rtt[SWEEP_PING_BATCH]; bool probed[SWEEP_PING_BATCH];
            pingBatch(ips, n, 250, up, rtt, probed);
            for (int k = 0; k < n; k++) {
                if (!probed[k]) {   // Ressourcenfehler: bis zu 3x seriell nachpruefen (Sockets/Tasks werden frei), sonst unvollstaendig (nie still "down")
                    bool ok = false;
                    for (int tries = 0; tries < 3 && !ok; tries++) { vTaskDelay(pdMS_TO_TICKS(60)); uint32_t r2 = 0; if (pingOne(ips[k], 250, &r2)) { up[k] = true; rtt[k] = r2; ok = true; } else if (s_pingLastErr == 0) ok = true; }
                    if (ok) probed[k] = true; else s_unprobed = s_unprobed + 1;
                }
                if (up[k]) { ip4_addr_t x; ip4_addr_set_u32(&x, ips[k]); lock(); s_hosts.push_back({ String(ip4addr_ntoa(&x)), "", "", (long)rtt[k] }); unlock(); }
            }
            s_scanned = done;
        }
    }
    s_running = false;
    delete a;
    vTaskDelete(nullptr);
}

String netScanStartTarget(const String& target, const String& modeIn) {
    lockInit();
    if (s_running) return "Sweep laeuft bereits";
    String mode = modeIn; mode.trim(); mode.toLowerCase(); if (!mode.length()) mode = "auto";
    if (mode != "auto" && mode != "arp" && mode != "icmp") return "Modus: auto | arp | icmp";
    SweepArgs* a = new SweepArgs();
    String err = resolveTarget(target, a->t);
    if (err.length()) { delete a; lock(); s_error = err; unlock(); return err; }
    uint64_t hosts = hostCount(a->t.prefix);
    if (hosts > NET_SWEEP_MAX) {
        delete a;
        String e = "Netz enthaelt " + String((unsigned long)hosts) + " Hosts; maximal " + String(NET_SWEEP_MAX) + " je Sweep -- kleineres Netz angeben (max. /23)";
        lock(); s_error = e; unlock(); return e;
    }
    if (mode == "arp" && !a->t.l2) { String e = "ARP nur auf lokalen Layer-2-Netzen (Ausgang " + a->t.egress + " ist kein Ethernet/WLAN oder Netz nicht on-link) -- 'icmp' oder 'auto'"; delete a; lock(); s_error = e; unlock(); return e; }
    a->arp = (mode == "arp") || (mode == "auto" && a->t.l2);
    lock();
    s_target = a->t.label; s_mode = a->arp ? "arp" : "icmp"; s_egress = a->t.egress; s_attachment = a->t.attachment; s_error = "";
    s_hosts.clear(); s_total = (uint32_t)hosts; s_scanned = 0; s_unprobed = 0;
    unlock();
    s_running = true;
    if (xTaskCreatePinnedToCore(sweepTask, "net_scan", 4096, a, 4, nullptr, 1) != pdPASS) { s_running = false; delete a; return "Task-Start fehlgeschlagen"; }
    return "";
}
void netScanStart() { netScanStartTarget("wlan-sta-lan", "auto"); }

static String jsonEscS(const String& s) { String o; for (size_t i = 0; i < s.length(); i++) { char c = s[i]; if (c == '"' || c == '\\') o += '\\'; if ((uint8_t)c < 0x20) continue; o += c; } return o; }

String netScanJson() {
    lockInit();
    lock();
    String j = "{\"running\":"; j += s_running ? "true" : "false";
    j += ",\"total\":";   j += String((uint32_t)s_total);
    j += ",\"scanned\":"; j += String((uint32_t)s_scanned);
    j += ",\"target\":\""; j += s_target; j += "\",\"subnet\":\""; j += s_target;   // subnet = Alias (alte UI)
    j += "\",\"mode\":\""; j += s_mode; j += "\",\"egress\":\""; j += s_egress; j += "\",\"attachment\":\""; j += s_attachment;
    j += "\",\"error\":\""; j += jsonEscS(s_error);
    j += "\",\"unprobed\":"; j += String((uint32_t)s_unprobed); j += ",\"incomplete\":"; j += (s_unprobed ? "true" : "false");   // Ressourcenfehler -> ehrlich als unvollstaendig
    j += ",\"hosts\":[";
    for (size_t i = 0; i < s_hosts.size(); i++) {
        if (i) j += ",";
        j += "{\"ip\":\""; j += s_hosts[i].ip;
        j += "\",\"mac\":\""; j += s_hosts[i].mac;
        j += "\",\"vendor\":\""; j += s_hosts[i].vendor;
        j += "\",\"ms\":"; j += String(s_hosts[i].ms); j += "}";
    }
    j += "]}";
    unlock();
    return j;
}

String netScanTargetsJson() {
    NetAttachment at[NET_ATTACH_MAX]; int na = 0; netAttachmentsBuild(at, NET_ATTACH_MAX, na);
    ReachablePrefix pf[NET_PREFIX_MAX]; int np = 0; netReachablePrefixesBuild(pf, NET_PREFIX_MAX, np);
    String j = "["; bool first = true;
    for (int i = 0; i < np; i++) {
        if (!pf[i].routingEligible || pf[i].prefix == 0) continue;
        const NetAttachment* a = nullptr; for (int k = 0; k < na; k++) if (at[k].id == pf[i].attachmentId) a = &at[k];
        if (!a || !a->up) continue;
        struct netif* n = (struct netif*)netIfaceNativeHandle(a->ifaceId);
        bool l2 = false;
        { ip4_addr_t x; if (n && ip4addr_aton(pf[i].net.c_str(), &x)) l2 = wholeTargetOnLink(n, lwip_ntohl(ip4_addr_get_u32(&x)), pf[i].prefix); }
        uint64_t hosts = hostCount(pf[i].prefix);
        if (!first) j += ","; first = false;
        // target = eindeutige Ziel-Identitaet (Attachment + konkretes Prefix) fuer /net-scan-start und 'net sweep'.
        j += "{\"target\":\"" + a->id + "@" + pf[i].net + "/" + String((unsigned)pf[i].prefix) + "\",\"attachment\":\"" + a->id + "\",\"iface\":\"" + a->ifaceId + "\",\"net\":\"" + pf[i].net + "\",\"prefix\":" + String((unsigned)pf[i].prefix)
           + ",\"hosts\":" + String((unsigned long)hosts) + ",\"l2\":" + (l2 ? "true" : "false") + ",\"tooBig\":" + (hosts > NET_SWEEP_MAX ? "true" : "false")
           + ",\"source\":\"" + jsonEscS(netPrefixSourcesText(pf[i].sourceMask)) + "\"}";
    }
    j += "]";
    return j;
}

// Lokaler Routing-Befund (Verkehr VOM P4) + optional Forward-Policy einer Quelle (getrennt!).
String netDiagResolveJson(const String& ipIn, const String& fromIn) {
    String ip = ipIn; ip.trim(); String from = fromIn; from.trim();
    ip4_addr_t a;
    if (!ip4addr_aton(ip.c_str(), &a)) return "{\"ok\":false,\"msg\":\"Ungueltige IP\"}";
    uint32_t ipH = lwip_ntohl(ip4_addr_get_u32(&a));
    struct netif* nif = nullptr; bool isDefault = false; String egressIp;
    LOCK_TCPIP_CORE();
    nif = ip4_route(&a);
    if (nif) { isDefault = (nif == netif_default); egressIp = ip4addr_ntoa(netif_ip4_addr(nif)); }
    UNLOCK_TCPIP_CORE();
    String iface = ifaceIdForNetif(nif);
    // Attachment ueber Ziel + Prefix-Deckung (nicht nur netif): wlan-sta-lan vs. wlan-sta-uplink.
    NetAttachment att; ReachablePrefix cov; bool haveAtt = nif && attachmentForTarget(nif, ipH, isDefault, &att, &cov);
    String attId = haveAtt ? att.id : String("");
    bool coveredByPrefix = haveAtt && cov.net.length() && cov.prefix > 0;
    String covered = coveredByPrefix ? (cov.net + "/" + String((unsigned)cov.prefix)) : String("");
    String coveredSrc = coveredByPrefix ? netPrefixSourcesText(cov.sourceMask) : String("");
    bool tsrCovered = coveredByPrefix && (cov.sourceMask & NPFX_BIT(NPFX_TSR));   // ausschliesslich echte TSr-Deckung
    // Zonenroute?
    String zNet, zIface; bool zBlock = false; bool zHit = zoneRouteMatch(ipH, zNet, zIface, zBlock);
    String kind = !nif ? "keine" : (zHit ? (zBlock ? "zone-block" : "zone") : (isDefault && !coveredByPrefix ? "default" : "onlink"));
    String j = "{\"ok\":true,\"ip\":\"" + ip + "\",\"local\":{";
    j += "\"egress\":\"" + nifNameStr(nif) + "\",\"iface\":\"" + iface + "\",\"attachment\":\"" + attId + "\",\"attachmentKnown\":" + (haveAtt ? "true" : "false") + ",\"egressIp\":\"" + egressIp + "\"";
    j += ",\"routeKind\":\"" + kind + "\",\"zoneRoute\":\"" + zNet + "\",\"zoneBlock\":" + (zBlock ? "true" : "false");
    j += ",\"covered\":\"" + covered + "\",\"coveredSource\":\"" + jsonEscS(coveredSrc) + "\",\"defaultRoute\":" + ((isDefault && !coveredByPrefix) ? "true" : "false");
    if (haveAtt && att.kind == NATT_IPSEC) j += ",\"tsrCovered\":" + String(tsrCovered ? "true" : "false");
    j += ",\"note\":\"Verkehr vom P4 selbst durchlaeuft keine Zonen-Policy (nur Routing)\"}";
    if (from.length()) {
        j += ",\"from\":{\"attachment\":\"" + from + "\",\"dst\":\"" + attId + "\"";
        String mode, reason, nat; bool have = attId.length() && zoneRuntimePlanFor(from, attId, mode, reason, nat);
        j += ",\"policy\":{\"installed\":" + String(have ? "true" : "false") + ",\"mode\":\"" + (have ? mode : String("DENY")) + "\",\"reason\":\"" + jsonEscS(have ? reason : String("keine Policy fuer diese Paarung -> DENY (fail-closed)")) + "\",\"natSource\":\"" + nat + "\"}";
        if (attId.length()) { j += ",\"preview\":"; j += zonePlanJson(from, attId, ZI_ALLOW_AUTO); }
        j += "}";
    }
    j += "}";
    return j;
}

String netPingJson(const String& ip) {
    ip4_addr_t a;
    if (!ip4addr_aton(ip.c_str(), &a)) return "{\"ok\":false,\"msg\":\"Ungueltige IP\"}";
    uint32_t rtt = 0;
    bool up = pingOne(ip4_addr_get_u32(&a), 800, &rtt);
    String j = "{\"ok\":true,\"ip\":\""; j += ip; j += "\",\"up\":";
    j += up ? "true" : "false"; j += ",\"ms\":"; j += String(rtt); j += "}";
    return j;
}

// ============================================================================
// 7.11: TCP-Port-Scan (connect-scan, parallele Sockets + select-Timeout)
// ============================================================================
struct PsArgs { uint32_t ipBe; bool udp; std::vector<uint16_t> ports; };
struct PsResult { uint16_t port; uint8_t state; };   // 1=offen, 2=offen|gefiltert (nur UDP)
static std::vector<PsResult> s_psOpen;
static volatile bool     s_psRunning = false;
static volatile bool     s_psUdp = false;
static volatile uint32_t s_psTotal = 0, s_psScanned = 0;
static String            s_psIp;
static volatile int      s_psFrom = 0, s_psTo = 0;   // tatsaechlich gescannter Bereich (0/0 = Common-Liste)
static SemaphoreHandle_t ps_lock = nullptr;
static void psLockInit() { if (!ps_lock) ps_lock = xSemaphoreCreateMutex(); }
static void psLock()     { if (ps_lock) xSemaphoreTake(ps_lock, portMAX_DELAY); }
static void psUnlock()   { if (ps_lock) xSemaphoreGive(ps_lock); }

static const char* portSvc(uint16_t p) {
    switch (p) {
        case 21: return "ftp"; case 22: return "ssh"; case 23: return "telnet"; case 25: return "smtp";
        case 53: return "dns"; case 80: return "http"; case 110: return "pop3"; case 135: return "msrpc";
        case 139: return "netbios"; case 143: return "imap"; case 161: return "snmp"; case 389: return "ldap";
        case 443: return "https"; case 445: return "smb"; case 587: return "smtp"; case 631: return "ipp";
        case 993: return "imaps"; case 995: return "pop3s"; case 1433: return "mssql"; case 1883: return "mqtt";
        case 2049: return "nfs"; case 3306: return "mysql"; case 3389: return "rdp"; case 5000: return "upnp";
        case 5060: return "sip"; case 5432: return "postgres"; case 5900: return "vnc"; case 6379: return "redis";
        case 8000: return "http-alt"; case 8080: return "http-alt"; case 8123: return "homeassistant";
        case 8443: return "https-alt"; case 8888: return "http-alt"; case 9000: return "http-alt";
        case 9100: return "printer"; case 11434: return "ollama"; case 32400: return "plex"; case 51820: return "wireguard";
        default: return "";
    }
}

// UDP-Probe: 0=geschlossen (ICMP port-unreachable), 1=offen (Antwort), 2=offen|gefiltert (Timeout).
static int udpProbe(uint32_t ipBe, uint16_t port, uint32_t timeout_ms) {
    int s = lwip_socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return 2;
    struct timeval tv; tv.tv_sec = timeout_ms / 1000; tv.tv_usec = (timeout_ms % 1000) * 1000;
    lwip_setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET; sa.sin_port = lwip_htons(port); sa.sin_addr.s_addr = ipBe;
    lwip_connect(s, (struct sockaddr*)&sa, sizeof(sa));   // "connected" UDP -> ICMP-Fehler kommt als ECONNREFUSED
    // dienstspezifische Probes provozieren eine Antwort (=> sicher offen)
    static const uint8_t ntp[48] = { 0x1b };
    static const uint8_t dns[]   = { 0,0, 1,0, 0,1, 0,0, 0,0, 0,0, 0, 0,1, 0,1 };   // Root-Query Typ A
    static const uint8_t gen[2]  = { 0, 0 };
    const uint8_t* probe = gen; int plen = sizeof(gen);
    if (port == 123) { probe = ntp; plen = sizeof(ntp); }
    else if (port == 53) { probe = dns; plen = sizeof(dns); }
    lwip_send(s, probe, plen, 0);
    uint8_t buf[64];
    int r = lwip_recv(s, buf, sizeof(buf), 0);
    int state;
    if (r > 0) state = 1;
    else if (r < 0 && errno == ECONNREFUSED) state = 0;
    else state = 2;   // Timeout (EWOULDBLOCK) oder anderer Fehler
    lwip_close(s);
    return state;
}

static void portScanTask(void* arg) {
    PsArgs* a = (PsArgs*)arg;
    if (a->udp) {
        // UDP: sequenziell (connectionless, ICMP-Fehler pro Socket). Nur nicht-geschlossene melden.
        for (size_t i = 0; i < a->ports.size() && s_psRunning; i++) {
            int st = udpProbe(a->ipBe, a->ports[i], 500);
            if (st != 0) { psLock(); s_psOpen.push_back({ a->ports[i], (uint8_t)st }); psUnlock(); }
            s_psScanned = i + 1;
        }
    } else {
        // TCP: batch-weise nicht-blockierende connect() + select() mit Timeout.
        const int BATCH = 6; const int TO_MS = 500;
        size_t i = 0;
        while (i < a->ports.size() && s_psRunning) {
            int socks[BATCH]; uint16_t pts[BATCH]; int n = 0;
            for (; n < BATCH && i < a->ports.size(); i++) {
                int s = lwip_socket(AF_INET, SOCK_STREAM, 0);
                if (s < 0) break;
                int fl = lwip_fcntl(s, F_GETFL, 0); lwip_fcntl(s, F_SETFL, fl | O_NONBLOCK);
                struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
                sa.sin_family = AF_INET; sa.sin_port = lwip_htons(a->ports[i]); sa.sin_addr.s_addr = a->ipBe;
                lwip_connect(s, (struct sockaddr*)&sa, sizeof(sa));
                socks[n] = s; pts[n] = a->ports[i]; n++;
            }
            fd_set wf; FD_ZERO(&wf); int maxfd = 0;
            for (int k = 0; k < n; k++) { FD_SET(socks[k], &wf); if (socks[k] > maxfd) maxfd = socks[k]; }
            struct timeval tv; tv.tv_sec = TO_MS / 1000; tv.tv_usec = (TO_MS % 1000) * 1000;
            lwip_select(maxfd + 1, NULL, &wf, NULL, &tv);
            for (int k = 0; k < n; k++) {
                if (FD_ISSET(socks[k], &wf)) {
                    int err = 1; socklen_t l = sizeof(err);
                    lwip_getsockopt(socks[k], SOL_SOCKET, SO_ERROR, &err, &l);
                    if (err == 0) { psLock(); s_psOpen.push_back({ pts[k], 1 }); psUnlock(); }
                }
                lwip_close(socks[k]);
            }
            s_psScanned += n;
        }
    }
    s_psRunning = false;
    delete a;
    vTaskDelete(nullptr);
}

String netPortScanStart(const String& ip, int fromPort, int toPort, bool udp) {
    psLockInit();
    if (s_psRunning) return "Portscan laeuft bereits";
    ip4_addr_t a;
    if (!ip4addr_aton(ip.c_str(), &a)) return "Ungueltige IP";
    if (fromPort > 0 || toPort > 0) {
        if (fromPort < 1 || toPort < fromPort || toPort > 65535) return "Bereich: von <= bis, 1..65535";
        int cap = udp ? NET_PORTSCAN_MAX_UDP : NET_PORTSCAN_MAX_TCP;
        if (toPort - fromPort + 1 > cap) return "Bereich " + String(fromPort) + "-" + String(toPort) + " = " + String(toPort - fromPort + 1) + " Ports; maximal " + String(cap) + (udp ? " UDP" : " TCP") + " je Lauf -- in Bloecken scannen (z. B. " + String(fromPort) + "-" + String(fromPort + cap - 1) + ")";
    }
    PsArgs* args = new PsArgs();
    args->ipBe = ip4_addr_get_u32(&a);
    args->udp  = udp;
    if (fromPort <= 0 || toPort <= 0) {
        if (udp) {
            static const uint16_t UDP_COMMON[] = {
                53,67,68,69,123,137,138,161,162,500,514,520,623,631,1194,1434,1701,1812,1900,
                4500,5060,5353,11211,32410,32412,32414,51820 };
            for (size_t k = 0; k < sizeof(UDP_COMMON) / sizeof(UDP_COMMON[0]); k++) args->ports.push_back(UDP_COMMON[k]);
        } else {
            static const uint16_t COMMON[] = {
                21,22,23,25,53,80,81,110,111,135,139,143,161,389,443,445,465,514,515,587,631,993,995,
                1080,1194,1433,1723,1883,2049,2082,2083,3000,3128,3306,3389,5000,5060,5432,5555,5900,
                5901,6379,7070,8000,8006,8008,8080,8081,8123,8443,8888,9000,9090,9100,9200,10000,11434,32400,49152,51820 };
            for (size_t k = 0; k < sizeof(COMMON) / sizeof(COMMON[0]); k++) args->ports.push_back(COMMON[k]);
        }
    } else {
        for (int p = fromPort; p <= toPort; p++) args->ports.push_back((uint16_t)p);   // Bereich ist bereits geprueft, nie gekappt
    }
    psLock(); s_psIp = ip; s_psUdp = udp; s_psOpen.clear(); s_psTotal = args->ports.size(); s_psScanned = 0; s_psFrom = (fromPort > 0) ? fromPort : 0; s_psTo = (fromPort > 0) ? toPort : 0; psUnlock();
    s_psRunning = true;
    if (xTaskCreatePinnedToCore(portScanTask, "portscan", 4096, args, 4, nullptr, 1) != pdPASS) {
        s_psRunning = false; delete args; return "Task-Start fehlgeschlagen";
    }
    return "";
}

String netPortScanJson() {
    psLockInit(); psLock();
    String j = "{\"running\":"; j += s_psRunning ? "true" : "false";
    j += ",\"ip\":\""; j += s_psIp; j += "\"";
    j += ",\"proto\":\""; j += s_psUdp ? "udp" : "tcp"; j += "\"";
    j += ",\"from\":"; j += String((int)s_psFrom); j += ",\"to\":"; j += String((int)s_psTo); j += ",\"common\":"; j += (s_psFrom == 0) ? "true" : "false";
    j += ",\"total\":";   j += String((uint32_t)s_psTotal);
    j += ",\"scanned\":"; j += String((uint32_t)s_psScanned);
    j += ",\"open\":[";
    for (size_t i = 0; i < s_psOpen.size(); i++) {
        if (i) j += ",";
        j += "{\"port\":"; j += String(s_psOpen[i].port);
        j += ",\"svc\":\""; j += portSvc(s_psOpen[i].port); j += "\"";
        j += ",\"state\":\""; j += (s_psOpen[i].state == 1 ? "offen" : "offen|gefiltert"); j += "\"}";
    }
    j += "]}";
    psUnlock();
    return j;
}

// ============================================================================
// Funk-Recon (7.13 Passiv-Monitor, 7.14 Kanal-Uebersicht, 7.15 Tiefen-Kanal-Scan): braucht den
// WLAN-Funk (esp_wifi Promiscuous/Scan/Kanalwechsel) -> Baustein WIFI. Ohne ihn liefern die Stubs
// am Dateiende "nicht im Build enthalten"; die L3/L4-Werkzeuge oben sind davon unabhaengig.
// ============================================================================
#if WEIRDOS_FEATURE_WIFI

// ============================================================================
// 7.13: Passiv-Monitor (WLAN-Promiscuous) - sendende Geraete per MAC + RSSI
// ============================================================================
#define SNIFF_MAX 48
struct SniffDev { uint8_t mac[6]; int8_t rssi; uint32_t count; uint8_t type; };
static SniffDev s_sn[SNIFF_MAX];
static volatile int s_snCount = 0;
static volatile bool s_snRunning = false;
static volatile uint32_t s_snLeft = 0;
static volatile uint32_t s_pkt = 0;   // 7.15: Paketzaehler (Tiefen-Kanal-Scan)
static portMUX_TYPE s_snMux = portMUX_INITIALIZER_UNLOCKED;

static void sniffCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    wifi_promiscuous_pkt_t* p = (wifi_promiscuous_pkt_t*)buf;
    if (p->rx_ctrl.sig_len < 16) return;
    const uint8_t* addr2 = p->payload + 10;   // Transmitter-MAC (SA/TA)
    if (addr2[0] & 0x01) return;               // Multicast/Broadcast als Quelle ignorieren
    int8_t rssi = p->rx_ctrl.rssi;
    portENTER_CRITICAL(&s_snMux);
    s_pkt++;
    int i;
    for (i = 0; i < s_snCount; i++) {
        if (memcmp(s_sn[i].mac, addr2, 6) == 0) { s_sn[i].count++; s_sn[i].rssi = rssi; s_sn[i].type = (uint8_t)type; break; }
    }
    if (i == s_snCount && s_snCount < SNIFF_MAX) {
        memcpy(s_sn[s_snCount].mac, addr2, 6); s_sn[s_snCount].rssi = rssi;
        s_sn[s_snCount].count = 1; s_sn[s_snCount].type = (uint8_t)type; s_snCount++;
    }
    portEXIT_CRITICAL(&s_snMux);
}

static void sniffTask(void* arg) {
    int secs = (int)(intptr_t)arg;
    portENTER_CRITICAL(&s_snMux); s_snCount = 0; portEXIT_CRITICAL(&s_snMux);
    wifi_promiscuous_filter_t filt;
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(sniffCb);
    if (esp_wifi_set_promiscuous(true) != ESP_OK) { s_snRunning = false; vTaskDelete(nullptr); return; }
    for (int t = 0; t < secs && s_snRunning; t++) { s_snLeft = secs - t; vTaskDelay(pdMS_TO_TICKS(1000)); }
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    s_snLeft = 0;
    s_snRunning = false;
    vTaskDelete(nullptr);
}

void netSniffStart(int seconds) {
    if (s_snRunning) return;
    if (btBusy()) return;   // 8.0: kein Promiscuous parallel zum BLE-Scan (gemeinsames Funkteil)
    if (seconds < 2) seconds = 2; if (seconds > 30) seconds = 30;
    s_snRunning = true; s_snLeft = seconds;
    if (xTaskCreatePinnedToCore(sniffTask, "sniff", 4096, (void*)(intptr_t)seconds, 4, nullptr, 0) != pdPASS) {
        s_snRunning = false;
    }
}

String netSniffJson() {
    SniffDev tmp[SNIFF_MAX]; int cnt;
    portENTER_CRITICAL(&s_snMux);
    cnt = s_snCount; if (cnt > SNIFF_MAX) cnt = SNIFF_MAX;
    memcpy(tmp, s_sn, (size_t)cnt * sizeof(SniffDev));
    portEXIT_CRITICAL(&s_snMux);

    String j = "{\"running\":"; j += s_snRunning ? "true" : "false";
    j += ",\"left\":"; j += String((uint32_t)s_snLeft);
    j += ",\"devices\":[";
    for (int i = 0; i < cnt; i++) {
        if (i) j += ",";
        char m[18];
        snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x",
                 tmp[i].mac[0], tmp[i].mac[1], tmp[i].mac[2], tmp[i].mac[3], tmp[i].mac[4], tmp[i].mac[5]);
        String macS(m);
        // MAC mit ARP-Scan-Ergebnissen korrelieren -> IP wo bekannt
        String ip = "";
        lock();
        for (size_t k = 0; k < s_hosts.size(); k++) { if (s_hosts[k].mac.equalsIgnoreCase(macS)) { ip = s_hosts[k].ip; break; } }
        unlock();
        const char* ty = (tmp[i].type == WIFI_PKT_MGMT) ? "mgmt" : "data";
        j += "{\"mac\":\""; j += macS; j += "\",\"ip\":\""; j += ip; j += "\"";
        j += ",\"vendor\":\""; j += ouiVendor(tmp[i].mac); j += "\"";
        j += ",\"rssi\":"; j += String((int)tmp[i].rssi);
        j += ",\"count\":"; j += String(tmp[i].count);
        j += ",\"type\":\""; j += ty; j += "\"}";
    }
    j += "]}";
    return j;
}

// ============================================================================
// 7.14: Kanal-Uebersicht (WLAN-Scan aggregiert je Kanal + Empfehlung)
// ============================================================================
static int s_chAp[14];
static int s_chBest[14];
static volatile bool s_chRunning = false;
struct ApRec { char ssid[33]; uint8_t ch; int8_t rssi; };
static ApRec s_chApList[40];
static volatile int s_chApN = 0;   // wird ZULETZT gesetzt -> Leser sieht konsistente Daten

static void chScanTask(void*) {
    for (int i = 0; i < 14; i++) { s_chAp[i] = 0; s_chBest[i] = -128; }
    s_chApN = 0;
    wifi_scan_config_t cfg; memset(&cfg, 0, sizeof(cfg)); cfg.show_hidden = true;
    if (esp_wifi_scan_start(&cfg, true) == ESP_OK) {   // blockierend (~2-4s, STA hoppt kurz)
        uint16_t n = 0; esp_wifi_scan_get_ap_num(&n);
        if (n > 60) n = 60;
        if (n > 0) {
            wifi_ap_record_t* recs = (wifi_ap_record_t*)malloc((size_t)n * sizeof(wifi_ap_record_t));
            if (recs) {
                esp_wifi_scan_get_ap_records(&n, recs);
                int apn = 0;
                for (int k = 0; k < n; k++) {
                    int ch = recs[k].primary;
                    if (ch >= 1 && ch <= 13) { s_chAp[ch]++; if (recs[k].rssi > s_chBest[ch]) s_chBest[ch] = recs[k].rssi; }
                    if (apn < 40) {
                        strncpy(s_chApList[apn].ssid, (const char*)recs[k].ssid, 32);
                        s_chApList[apn].ssid[32] = 0;
                        s_chApList[apn].ch = recs[k].primary;
                        s_chApList[apn].rssi = recs[k].rssi;
                        apn++;
                    }
                }
                free(recs);
                s_chApN = apn;   // zuletzt
            }
        }
    }
    s_chRunning = false;
    vTaskDelete(nullptr);
}

void netChannelScanStart() {
    if (s_chRunning) return;
    s_chRunning = true;
    if (xTaskCreatePinnedToCore(chScanTask, "chscan", 4096, nullptr, 4, nullptr, 0) != pdPASS) s_chRunning = false;
}

String netChannelScanJson() {
    // Ueberlappungsgewichtete Stoerlast je Kanal (2.4 GHz: Nachbarkanaele stoeren bis +-4).
    float score[14];
    for (int c = 1; c <= 13; c++) {
        float s = 0;
        for (int d = 1; d <= 13; d++) {
            int gap = c - d; if (gap < 0) gap = -gap;
            if (gap <= 4 && s_chAp[d] > 0) s += s_chAp[d] * ((5.0f - gap) / 5.0f);
        }
        score[c] = s;
    }
    int rec = 1; float best = 1e9f; int cand[3] = { 1, 6, 11 };
    for (int i = 0; i < 3; i++) if (score[cand[i]] < best) { best = score[cand[i]]; rec = cand[i]; }

    String j = "{\"running\":"; j += s_chRunning ? "true" : "false";
    j += ",\"recommend\":"; j += String(rec);
    j += ",\"channels\":[";
    for (int c = 1; c <= 13; c++) {
        if (c > 1) j += ",";
        j += "{\"ch\":"; j += String(c);
        j += ",\"aps\":"; j += String(s_chAp[c]);
        j += ",\"rssi\":"; j += String(s_chAp[c] > 0 ? s_chBest[c] : -128);
        j += ",\"score\":"; j += String((int)(score[c] * 10 + 0.5f));   // *10, damit UI keine Floats braucht
        j += "}";
    }
    j += "],\"aps\":[";
    int apn = s_chApN; if (apn > 40) apn = 40;
    for (int i = 0; i < apn; i++) {
        if (i) j += ",";
        String ss = s_chApList[i].ssid; ss.replace("\\", "\\\\"); ss.replace("\"", "\\\"");
        j += "{\"ssid\":\""; j += ss; j += "\",\"ch\":"; j += String(s_chApList[i].ch);
        j += ",\"rssi\":"; j += String((int)s_chApList[i].rssi); j += "}";
    }
    j += "]}";
    return j;
}

// ============================================================================
// 7.15: Tiefen-Kanal-Scan - Channel-Hopping im Promiscuous-Mode -> aktive
// Geraete + Traffic je Kanal. ACHTUNG: trennt das eigene WLAN waehrend des
// Sweeps (~17s). Ergebnisse werden gespeichert und nach dem Reconnect angezeigt.
// ============================================================================
static int s_dchDev[14], s_dchPkt[14];
static volatile bool s_dchRunning = false;
static volatile int  s_dchCur = 0;

static void deepChTask(void*) {
    for (int i = 0; i < 14; i++) { s_dchDev[i] = 0; s_dchPkt[i] = 0; }
    uint8_t home = 0; wifi_second_chan_t sec;
    esp_wifi_get_channel(&home, &sec);
    wifi_promiscuous_filter_t filt;
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(sniffCb);
    if (esp_wifi_set_promiscuous(true) != ESP_OK) { s_dchRunning = false; vTaskDelete(nullptr); return; }
    for (int ch = 1; ch <= 13 && s_dchRunning; ch++) {
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        portENTER_CRITICAL(&s_snMux); s_snCount = 0; s_pkt = 0; portEXIT_CRITICAL(&s_snMux);
        s_dchCur = ch;
        vTaskDelay(pdMS_TO_TICKS(1300));
        portENTER_CRITICAL(&s_snMux); s_dchDev[ch] = s_snCount; s_dchPkt[ch] = (int)s_pkt; portEXIT_CRITICAL(&s_snMux);
    }
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    if (home >= 1 && home <= 13) esp_wifi_set_channel(home, WIFI_SECOND_CHAN_NONE);
    esp_wifi_connect();   // STA wieder verbinden
    s_dchCur = 0;
    s_dchRunning = false;
    vTaskDelete(nullptr);
}

void netDeepChScanStart() {
    if (s_dchRunning || s_snRunning) return;   // nicht parallel zum Passiv-Monitor
    if (btBusy()) return;   // 8.0: kein Channel-Hopping parallel zum BLE-Scan (gemeinsames Funkteil)
    s_dchRunning = true; s_dchCur = 0;
    if (xTaskCreatePinnedToCore(deepChTask, "deepch", 4096, nullptr, 4, nullptr, 0) != pdPASS) s_dchRunning = false;
}

// 8.0: Funk-Recon aktiv? (Promiscuous-Passiv-Monitor oder Tiefen-Kanal-Scan mit Channel-Hopping).
// Der Kanal-Survey (esp_wifi_scan) ist ein normaler AP-Scan und koexistiert mit BLE - nicht enthalten.
bool netReconBusy() { return s_snRunning || s_dchRunning; }

String netDeepChScanJson() {
    String j = "{\"running\":"; j += s_dchRunning ? "true" : "false";
    j += ",\"cur\":"; j += String((int)s_dchCur);
    j += ",\"channels\":[";
    for (int c = 1; c <= 13; c++) {
        if (c > 1) j += ",";
        j += "{\"ch\":"; j += String(c);
        j += ",\"devices\":"; j += String(s_dchDev[c]);
        j += ",\"pkts\":"; j += String(s_dchPkt[c]); j += "}";
    }
    j += "]}";
    return j;
}

#else
// ============================================================================
// Stub: Funk-Recon nicht im Build (WEIRDOS_FEATURE_WIFI=0). Dieselben Symbole, triviale
// Koerper: die .ino-Routen (/net-sniff*, /net-chscan*, /net-deepch*), die Konsole und bt_scan
// (netReconBusy) referenzieren sie weiter. Kein esp_wifi, kein Task, keine Puffer. Das JSON
// traegt dieselben Grundfelder wie oben (running/left/cur + leere Listen) plus "error", damit
// das Diagnose-JS (ui_netscan.cpp) nichts auswerten muss, was es nicht kennt.
// ============================================================================
static const char* const kNetReconNoWifi = "WLAN nicht im Build enthalten (WEIRDOS_FEATURE_WIFI=0)";
void   netSniffStart(int)      {}
String netSniffJson()          { return String("{\"running\":false,\"left\":0,\"devices\":[],\"error\":\"") + kNetReconNoWifi + "\"}"; }
void   netChannelScanStart()   {}
String netChannelScanJson()    { return String("{\"running\":false,\"recommend\":1,\"channels\":[],\"aps\":[],\"error\":\"") + kNetReconNoWifi + "\"}"; }
void   netDeepChScanStart()    {}
String netDeepChScanJson()     { return String("{\"running\":false,\"cur\":0,\"channels\":[],\"error\":\"") + kNetReconNoWifi + "\"}"; }
bool   netReconBusy()          { return false; }
#endif // WEIRDOS_FEATURE_WIFI (Funk-Recon)
#else
// ============================================================================
// Stub (WEIRDOS_FEATURE_NETSCAN=0): keine Netzwerk-Diagnose im Build (Host-Sweep, Ping, Routing-
// Befund, Portscan, Passiv-Monitor, Kanalscan). Jede Header-Funktion bleibt definiert, damit .ino /
// serial_console / bt_scan unveraendert linken; JSON-Antworten sind gueltig und nennen den Grund.
// Kein lwIP-Socket-/ARP-/Ping-Code, kein Promiscuous-Mode, kein Worker-Task.
// ============================================================================
static const char* kNetScanNotBuilt = "Netzwerk-Diagnose nicht im Build enthalten (WEIRDOS_FEATURE_NETSCAN=0)";
static String netScanNotBuiltJson() {
    return String("{\"ok\":false,\"running\":false,\"msg\":\"") + kNetScanNotBuilt + "\"}";
}
String netScanStartTarget(const String& target, const String& mode) { (void)target; (void)mode; return String(kNetScanNotBuilt); }
void   netScanStart() {}
String netScanJson() { return netScanNotBuiltJson(); }
String netScanTargetsJson() { return String("{\"ok\":false,\"targets\":[],\"msg\":\"") + kNetScanNotBuilt + "\"}"; }
String netDiagResolveJson(const String& ip, const String& from) { (void)ip; (void)from; return netScanNotBuiltJson(); }
String netPingJson(const String& ip) { (void)ip; return netScanNotBuiltJson(); }
String netPortScanStart(const String& ip, int fromPort, int toPort, bool udp) { (void)ip; (void)fromPort; (void)toPort; (void)udp; return String(kNetScanNotBuilt); }
String netPortScanJson() { return netScanNotBuiltJson(); }
void   netSniffStart(int seconds) { (void)seconds; }
String netSniffJson() { return netScanNotBuiltJson(); }
void   netChannelScanStart() {}
String netChannelScanJson() { return netScanNotBuiltJson(); }
void   netDeepChScanStart() {}
String netDeepChScanJson() { return netScanNotBuiltJson(); }
bool   netReconBusy() { return false; }   // kein Funk-Recon moeglich -> BLE (bt_scan) nie blockiert
#endif // WEIRDOS_FEATURE_NETSCAN
