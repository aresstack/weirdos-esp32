#include "usb_net_service.h"

#include "weirdos_features.h"
#include "soc/soc_caps.h"

#if SOC_USB_OTG_SUPPORTED && defined(CONFIG_TINYUSB_ENABLED) && WEIRDOS_FEATURE_USB_DEVICE && WEIRDOS_FEATURE_USB_NCM

#include "tusb.h"
#include "class/net/net_device.h"
#include "portable/synopsys/dwc2/dwc2_type.h"   // Registerzugriff fuer den TX-Haenger-Watchdog
#include "esp_log.h"
#include <cstring>

#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/ethip6.h"
#include "lwip/tcpip.h"
#include "lwip/pbuf.h"
#include "lwip/ip4_addr.h"
#include "lwip/udp.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#include <Arduino.h>                  // String fuer die logEvent-Deklaration
void logEvent(const String& text);    // App-Ereignis-Ringpuffer (Definition in der .ino)

// Kruemelspur fuer die PANIC-Diagnose (ueberlebt den Reboot im RTC-RAM, Muster
// g_httpRenderStage): jeder Schritt des NCM-RX/TX-Pfads setzt seinen Code, das
// Boot-Event gibt nach einem PANIC den letzten erreichten Schritt aus.
//  10..13 = recv_cb (Start/pbuf/vor input/nach input)   20..21 = linkOutput
//  30..33 = pump (Start/vor xmit/nach xmit/idle)        40..41 = xmit_cb
//  50..51 = Klasse ep_out (Start/validiert)             60..63 = Klasse ep_in
//  70     = can_xmit
extern "C" { RTC_NOINIT_ATTR volatile uint32_t g_ncmCrumb; }
// Zweite Spur fuer den USB-Task selbst (80=vor tud_task, 81=danach/vor Video-pump,
// 82=vor usbnet::pump, 83=danach). Kombination nach PANIC: NCM=21 + USB=81/82/83
// -> USB-Task lief weiter, Crash im tcpip-Thread; NCM=21 + USB=80 -> Crash in
// tud_task (Klasse/dcd) parallel zum Sendeweg.
extern "C" { RTC_NOINIT_ATTR volatile uint32_t g_usbTaskCrumb; }

namespace cam { namespace usbnet {
namespace {

constexpr char TAG[] = "usbnet";

// 192.168.7.1/24 fuer den ESP; der PC bekommt .2 per DHCP. /24 aus dem privaten
// Bereich, kollidiert selten mit dem Heimnetz des PCs.
constexpr uint32_t kIp   = 0xC0A80701;  // 192.168.7.1
constexpr uint32_t kMask = 0xFFFFFF00;  // 255.255.255.0

struct netif s_netif;
struct udp_pcb* s_dhcpPcb = nullptr;
bool         s_up = false;
char         s_ipText[16] = "192.168.7.1";
QueueHandle_t s_txq = nullptr;           // pbuf* vom tcpip-Thread an den USB-Task
constexpr int kTxQueueDepth = 8;

// Ausgehendes Ethernet-Frame -> Warteschlange. Laeuft im lwIP-tcpip-Thread. Die NCM-Klasse
// (tud_network_can_xmit/xmit) ist nicht thread-sicher gegen tud_task(); deshalb wird hier
// NUR eingereiht (pbuf_ref, Refcount ist unter SYS_LIGHTWEIGHT_PROT thread-sicher) und im
// USB-Task gesendet (pump()). Voll oder USB nicht bereit -> verwerfen; TCP sendet erneut.
err_t linkOutput(struct netif* nif, struct pbuf* p) {
    (void)nif;
    g_ncmCrumb = 20;
    if (!s_txq || !tud_ready()) {
        static int s_txDropLog = 0;
        if (s_txDropLog < 4) { s_txDropLog++; logEvent("NCM: TX verworfen (USB nicht bereit)"); }
        return ERR_OK;
    }
    static int s_txQueuedLog = 0;
    if (s_txQueuedLog < 8) { s_txQueuedLog++; logEvent(String("NCM: TX anstehend ") + p->tot_len + " B"); }
    pbuf_ref(p);
    if (xQueueSend(s_txq, &p, 0) != pdTRUE) { pbuf_free(p); }
    g_ncmCrumb = 21;
    return ERR_OK;
}

// --- Mini-DHCP-Server (ein Client, feste Lease) ------------------------------------
// Der IDF-dhcps stuerzt auf diesem rohen USB-netif beim Beantworten des Discover ab
// (PANIC im Antwortpfad; Experiment 2026-09-30: ohne dhcps voellig stabil unter
// Discover-Dauerbeschuss, mit dhcps Reboot-Schleife im Sekundentakt). Fuer den
// Punkt-zu-Punkt-USB-Link genuegt ein fester Responder: DISCOVER -> OFFER,
// REQUEST -> ACK, immer 192.168.7.2, Lease 24 h. Antworten gehen als Broadcast
// (kein Unicast-/Static-ARP-Trick wie im IDF-Server noetig). Alles laeuft im
// tcpip-Thread (udp_recv-Callback) ueber die reine lwIP-API.
void dhcpMiniReply(const uint8_t* req, uint8_t msgType) {
    uint8_t r[300];
    memset(r, 0, sizeof(r));
    r[0] = 2; r[1] = 1; r[2] = 6;                        // BOOTREPLY, Ethernet, hlen 6
    memcpy(&r[4], &req[4], 4);                           // xid spiegeln
    memcpy(&r[10], &req[10], 2);                         // flags spiegeln
    const uint8_t srv[4] = {192,168,7,1}, cli[4] = {192,168,7,2}, mask[4] = {255,255,255,0};
    memcpy(&r[16], cli, 4);                              // yiaddr: die vergebene Adresse
    memcpy(&r[20], srv, 4);                              // siaddr
    memcpy(&r[28], &req[28], 16);                        // chaddr spiegeln
    r[236] = 0x63; r[237] = 0x82; r[238] = 0x53; r[239] = 0x63;   // DHCP-Magic
    uint16_t i = 240;
    auto put = [&](uint8_t opt, const uint8_t* v, uint8_t n) {
        r[i++] = opt; r[i++] = n; memcpy(&r[i], v, n); i = (uint16_t)(i + n);
    };
    put(53, &msgType, 1);                                // OFFER bzw. ACK
    put(54, srv, 4);                                     // Server-Identifier
    const uint8_t lease[4] = {0x00, 0x01, 0x51, 0x80};   // 86400 s
    put(51, lease, 4);
    put(1, mask, 4);                                     // Subnetz
    put(3, srv, 4);                                      // Gateway = der ESP
    put(6, srv, 4);                                      // DNS = der ESP
    r[i++] = 255;
    struct pbuf* p = pbuf_alloc(PBUF_TRANSPORT, sizeof(r), PBUF_RAM);
    if (!p) { logEvent("NCM: DHCP-Antwort ohne pbuf"); return; }
    pbuf_take(p, r, sizeof(r));
    ip_addr_t bcast;
    ip_addr_set_ip4_u32_val(bcast, PP_HTONL(0xFFFFFFFFUL));
    const err_t e = udp_sendto_if_src(s_dhcpPcb, p, &bcast, 68, &s_netif, &s_netif.ip_addr);
    pbuf_free(p);
    logEvent(String("NCM: DHCP-Antwort Typ ") + (int)msgType + " err " + (int)e);
}

void dhcpMiniRecv(void* arg, struct udp_pcb* pcb, struct pbuf* p, const ip_addr_t* addr, u16_t port) {
    (void)arg; (void)pcb; (void)addr; (void)port;
    if (!p) return;
    {
        static int s_dhcpRxLog = 0;
        if (s_dhcpRxLog < 6) { s_dhcpRxLog++; logEvent(String("NCM: UDP:67-Paket ") + p->tot_len + " B"); }
    }
    uint8_t buf[576];
    const uint16_t want = (uint16_t)((p->tot_len < sizeof(buf)) ? p->tot_len : sizeof(buf));
    const uint16_t len = pbuf_copy_partial(p, buf, want, 0);
    pbuf_free(p);
    if (len < 244 || buf[0] != 1) return;                // nur BOOTREQUEST
    if (!(buf[236] == 0x63 && buf[237] == 0x82 && buf[238] == 0x53 && buf[239] == 0x63)) return;
    uint8_t type = 0;
    for (uint16_t i = 240; i + 1 < len && buf[i] != 255; ) {
        const uint8_t opt = buf[i], olen = buf[i + 1];
        if (opt == 0) { i++; continue; }                 // Padding
        if ((uint32_t)i + 2 + olen > len) break;
        if (opt == 53 && olen >= 1) { type = buf[i + 2]; break; }
        i = (uint16_t)(i + 2 + olen);
    }
    if (type == 1)      dhcpMiniReply(buf, 2);           // DISCOVER -> OFFER
    else if (type == 3) dhcpMiniReply(buf, 5);           // REQUEST  -> ACK
}

err_t netifInit(struct netif* nif) {
    nif->name[0] = 'u'; nif->name[1] = 's';
    nif->mtu = 1500;
    nif->hwaddr_len = 6;
    memcpy(nif->hwaddr, tud_network_mac_address, 6);
    nif->hwaddr[5] ^= 0x01;   // ESP-Seite != Host-Seite
    nif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
    nif->output = etharp_output;
#if LWIP_IPV6
    nif->output_ip6 = ethip6_output;
#endif
    nif->linkoutput = linkOutput;
    return ERR_OK;
}

} // namespace

bool begin() {
    if (s_up) return true;
    if (!s_txq) s_txq = xQueueCreate(kTxQueueDepth, sizeof(struct pbuf*));
    if (!s_txq) { ESP_LOGE(TAG, "Sendewarteschlange nicht anlegbar"); return false; }

    ip4_addr_t ip, mask, gw;
    ip4_addr_set_u32(&ip,   lwip_htonl(kIp));
    ip4_addr_set_u32(&mask, lwip_htonl(kMask));
    ip4_addr_set_u32(&gw,   lwip_htonl(kIp));   // der ESP ist selbst das Gateway des PCs

    // netif-Liste und DHCP-Server (UDP-PCB) gehoeren dem tcpip-Thread: wie ec200a_ecm
    // unter LOCK_TCPIP_CORE (CONFIG_LWIP_TCPIP_CORE_LOCKING), sonst Wettlauf mit dem Stack.
    LOCK_TCPIP_CORE();
    struct netif* added = netif_add(&s_netif, &ip, &mask, &gw, nullptr, netifInit, tcpip_input);
    if (added) {
        netif_set_up(&s_netif);
        netif_set_link_up(&s_netif);
        // Mini-DHCP: gibt dem PC die 192.168.7.2 (s. dhcpMiniRecv oben; der IDF-dhcps
        // stuerzt auf diesem netif ab). IP_ANY + bind_netif: Broadcasts sicher empfangen,
        // aber nur von diesem netif; SOF_BROADCAST erlaubt die Broadcast-Antwort.
        s_dhcpPcb = udp_new();
        if (s_dhcpPcb) {
            ip_set_option(s_dhcpPcb, SOF_BROADCAST);
            // Exakt das Bind-Rezept des IDF-dhcps (der auf diesem Stack nachweislich
            // empfing): erst ans netif binden, dann an dessen konkrete IP -- ein
            // ANY-Bind bekam die 0.0.0.0->255.255.255.255:67-Discover hier NICHT.
            udp_bind_netif(s_dhcpPcb, &s_netif);
            const err_t be = udp_bind(s_dhcpPcb, &s_netif.ip_addr, 67);
            udp_recv(s_dhcpPcb, dhcpMiniRecv, nullptr);
            logEvent(String("NCM: Mini-DHCP lauscht (bind err ") + (int)be + ")");
        } else {
            ESP_LOGW(TAG, "DHCP-PCB nicht anlegbar -- PC braucht dann eine statische IP");
        }
    }
    UNLOCK_TCPIP_CORE();
    if (!added) {
        ESP_LOGE(TAG, "netif_add fehlgeschlagen");
        return false;
    }

    ip4addr_ntoa_r(&ip, s_ipText, sizeof(s_ipText));
    s_up = true;
    ESP_LOGI(TAG, "USB-Netz aktiv: %s/24, DHCP fuer den PC", s_ipText);
    return true;
}

void end() {
    if (!s_up) return;
    LOCK_TCPIP_CORE();
    if (s_dhcpPcb) { udp_remove(s_dhcpPcb); s_dhcpPcb = nullptr; }
    netif_set_down(&s_netif);
    netif_remove(&s_netif);
    UNLOCK_TCPIP_CORE();
    s_up = false;
    // Wartende Frames verwerfen
    struct pbuf* p = nullptr;
    while (s_txq && xQueueReceive(s_txq, &p, 0) == pdTRUE) pbuf_free(p);
}

bool active() { return s_up; }
const char* deviceIpText() { return s_ipText; }

// Im USB-Task (neben tud_task): so viele wartende Frames senden, wie die NCM-Klasse
// annimmt. tud_network_can_xmit() holt sich dabei den naechsten NTB-Puffer -- deshalb
// unmittelbar vor tud_network_xmit() aufrufen. Passt der Frame gerade nicht, bleibt er
// vorn in der Schlange (naechster Umlauf, <= 2 ms spaeter).
void pump() {
    if (!s_txq || !s_up) return;
    struct pbuf* p = nullptr;
    bool blocked = false;
    while (xQueuePeek(s_txq, &p, 0) == pdTRUE) {
        g_ncmCrumb = 30;
        if (!tud_ready()) { xQueueReceive(s_txq, &p, 0); pbuf_free(p); continue; }   // Host weg: verwerfen
        if (!tud_network_can_xmit(p->tot_len)) { blocked = true; break; }
        xQueueReceive(s_txq, &p, 0);
        g_ncmCrumb = 31;
        tud_network_xmit(p, 0);   // kopiert ueber tud_network_xmit_cb und gibt den pbuf dort frei
        g_ncmCrumb = 32;
        static int s_txSentLog = 0;
        if (s_txSentLog < 8) { s_txSentLog++; logEvent("NCM: TX gesendet"); }
    }
    g_ncmCrumb = 33;

    // TX-Haenger-Sicherheitsnetz: Vor dem Kickoff-Guard in ncm_device_patched.c
    // (Fix 2) konnte der ISR den FIFO-Push zerreissen -- der einzige Sende-NTB kam
    // nie frei (DIEPTSIZ: XFERSIZE 0 bei vollem PKTCNT), can_xmit blieb ewig false.
    // Mit dem Fix darf das nicht mehr auftreten; falls doch, liefert der Dump die
    // DWC2-Register in den Event-Ring und reaktiviert versuchsweise den
    // Nachfuell-Interrupt.
    static uint32_t s_blockSinceMs = 0;
    static bool s_hangDumped = false;
    if (blocked) {
        const uint32_t now = millis();
        if (!s_blockSinceMs) { s_blockSinceMs = now; }
        else if (now - s_blockSinceMs > 1200 && !s_hangDumped) {
            s_hangDumped = true;
            dwc2_regs_t* r = (dwc2_regs_t*)0x60080000UL;   // S3 FS-OTG (DWC2_FS_REG_BASE)
            const uint32_t ctl = r->epin[2].diepctl;        // Daten-IN-EP ist 0x82 in diesem Build
            const uint32_t siz = r->epin[2].dieptsiz;
            logEvent(String("NCM tx-hang: DIEPCTL2=") + String(ctl, HEX)
                     + " DIEPTSIZ2=" + String(siz, HEX)
                     + " EMPMSK=" + String((uint32_t)r->diepempmsk, HEX)
                     + " GINTSTS=" + String((uint32_t)r->gintsts, HEX));
            r->diepempmsk |= (1u << 2);
            logEvent("NCM tx-hang: EMPMSK Bit2 reaktiviert (Experiment)");
        }
    } else { s_blockSinceMs = 0; s_hangDumped = false; }
}

}} // namespace cam::usbnet

// ---- TinyUSB-NCM-Callbacks (die vorkompilierte net-Klasse ruft sie) --------------------------------
// MAC des Geraets (lokal verwaltet: bit1 im ersten Byte gesetzt, unicast).
uint8_t tud_network_mac_address[6] = { 0x02, 0x57, 0x45, 0x49, 0x52, 0x44 };  // "WEIRD"

extern "C" bool tud_network_recv_cb(const uint8_t* src, uint16_t size) {
    using namespace cam::usbnet;
    g_ncmCrumb = 10;
    {
        static int s_rxFrameLog = 0;
        if (s_rxFrameLog < 8) { s_rxFrameLog++; logEvent(String("NCM: RX Frame ") + size + " B"); }
    }
    if (!size) { tud_network_recv_renew(); return true; }
    struct pbuf* p = pbuf_alloc(PBUF_RAW, size, PBUF_POOL);
    if (!p) return false;   // kein Puffer -> spaeter erneut versuchen
    g_ncmCrumb = 11;
    pbuf_take(p, src, size);
    g_ncmCrumb = 12;
    // tcpip_input uebernimmt den pbuf (gibt ihn selbst frei).
    if (s_netif.input(p, &s_netif) != ERR_OK)
        pbuf_free(p);
    g_ncmCrumb = 13;
    tud_network_recv_renew();
    return true;
}

extern "C" uint16_t tud_network_xmit_cb(uint8_t* dst, void* ref, uint16_t arg) {
    (void)arg;
    g_ncmCrumb = 40;
    struct pbuf* p = static_cast<struct pbuf*>(ref);
    const uint16_t len = pbuf_copy_partial(p, dst, p->tot_len, 0);
    pbuf_free(p);   // die in linkOutput genommene Referenz
    g_ncmCrumb = 41;
    return len;
}

extern "C" void tud_network_init_cb(void) {
    // Das netif steht schon (begin()); NCM meldet hier nur "bereit". Diagnose-Marker:
    // feuert bei Stack-Init und Bus-Reset -- zeigt, ob der Host die Klasse neu aufsetzt.
    logEvent("NCM: Klasse initialisiert (Stack/Bus-Reset)");
}

// Bruecke fuer die Diagnosekopie der NCM-Klasse (ncm_device_diag.c, C-Datei):
// jeder Control-Request/Lebenszyklus-Schritt landet im App-Ereignisring, den der
// Konsolen-Dump ausgibt -- das Geraet protokolliert so Windows' UsbNcm-Start selbst.
extern "C" void ncmDiagLog(const char* tag, long a, long b, long c) {
    logEvent(String(tag) + " " + a + " " + b + " " + c);
}

#endif  // gated
