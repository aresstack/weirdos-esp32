#include "usb_net_service.h"

#include "weirdos_features.h"
#include "soc/soc_caps.h"

#if SOC_USB_OTG_SUPPORTED && defined(CONFIG_TINYUSB_ENABLED) && WEIRDOS_FEATURE_USB_DEVICE && WEIRDOS_FEATURE_USB_NCM

#include "tusb.h"
#include "class/net/net_device.h"
#include "esp_log.h"
#include <cstring>

#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/ethip6.h"
#include "lwip/tcpip.h"
#include "lwip/pbuf.h"
#include "lwip/ip4_addr.h"
#include "dhcpserver/dhcpserver.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

namespace cam { namespace usbnet {
namespace {

constexpr char TAG[] = "usbnet";

// 192.168.7.1/24 fuer den ESP; der PC bekommt .2 per DHCP. /24 aus dem privaten
// Bereich, kollidiert selten mit dem Heimnetz des PCs.
constexpr uint32_t kIp   = 0xC0A80701;  // 192.168.7.1
constexpr uint32_t kMask = 0xFFFFFF00;  // 255.255.255.0

struct netif s_netif;
dhcps_t*     s_dhcps = nullptr;
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
    if (!s_txq || !tud_ready()) return ERR_OK;
    pbuf_ref(p);
    if (xQueueSend(s_txq, &p, 0) != pdTRUE) { pbuf_free(p); }
    return ERR_OK;
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
        // DHCP-Server: gibt dem PC eine Adresse aus 192.168.7.0/24 (ab .2), Gateway = der ESP.
        s_dhcps = dhcps_new();
        if (s_dhcps && dhcps_start(s_dhcps, &s_netif, ip) != ERR_OK) {
            ESP_LOGW(TAG, "DHCP-Server nicht gestartet -- PC braucht dann eine statische IP");
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
    if (s_dhcps) { dhcps_stop(s_dhcps, &s_netif); dhcps_delete(s_dhcps); s_dhcps = nullptr; }
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
    while (xQueuePeek(s_txq, &p, 0) == pdTRUE) {
        if (!tud_ready()) { xQueueReceive(s_txq, &p, 0); pbuf_free(p); continue; }   // Host weg: verwerfen
        if (!tud_network_can_xmit(p->tot_len)) break;
        xQueueReceive(s_txq, &p, 0);
        tud_network_xmit(p, 0);   // kopiert ueber tud_network_xmit_cb und gibt den pbuf dort frei
    }
}

}} // namespace cam::usbnet

// ---- TinyUSB-NCM-Callbacks (die vorkompilierte net-Klasse ruft sie) --------------------------------
// MAC des Geraets (lokal verwaltet: bit1 im ersten Byte gesetzt, unicast).
uint8_t tud_network_mac_address[6] = { 0x02, 0x57, 0x45, 0x49, 0x52, 0x44 };  // "WEIRD"

extern "C" bool tud_network_recv_cb(const uint8_t* src, uint16_t size) {
    using namespace cam::usbnet;
    if (!size) { tud_network_recv_renew(); return true; }
    struct pbuf* p = pbuf_alloc(PBUF_RAW, size, PBUF_POOL);
    if (!p) return false;   // kein Puffer -> spaeter erneut versuchen
    pbuf_take(p, src, size);
    // tcpip_input uebernimmt den pbuf (gibt ihn selbst frei).
    if (s_netif.input(p, &s_netif) != ERR_OK)
        pbuf_free(p);
    tud_network_recv_renew();
    return true;
}

extern "C" uint16_t tud_network_xmit_cb(uint8_t* dst, void* ref, uint16_t arg) {
    (void)arg;
    struct pbuf* p = static_cast<struct pbuf*>(ref);
    const uint16_t len = pbuf_copy_partial(p, dst, p->tot_len, 0);
    pbuf_free(p);   // die in linkOutput genommene Referenz
    return len;
}

extern "C" void tud_network_init_cb(void) {
    // Nichts: das netif steht schon (begin()); NCM meldet hier nur "bereit".
}

#endif  // gated
