// ============================================================================
// ec200a_ecm.cpp  --  CDC-ECM-Host-Datenpfad (Alternative zu PPPoS)
//
// Rohe Ethernet-Frames ueber USB-Bulk (kein RNDIS-Header, kein HDLC). Spiegelt
// die bewaehrte PPP-Bulk-Pumpe (mehrere Transfers in flight) und haengt einen
// rohen lwIP-Ethernet-netif ein (wie PPP seinen g_pppNetif) + DHCP + Default.
//
// STATUS: live verifiziert (Enumeration, Discovery, QNETDEVCTL, DHCP/Routing und NIC-Modus mit
// oeffentlicher IP + Inbound). ECM ist die PRODUKTIONS-Datenschicht (Default); PPP bleibt als
// Kompatibilitaets-/Rueckfallpfad. Offen: A/B-Durchsatz ECM vs. PPP, Ingress-Backpressure bei
// grossen WireGuard-Transfers (problems.md).
//
// Baustein MODEM (weirdos_features.h): ECM ist der Datenpfad des Modems und faellt mit
// WEIRDOS_FEATURE_MODEM=0 weg -- dann bleibt nur der Stub am Ende dieser Datei.
// ============================================================================
#include "weirdos_features.h"   // WEIRDOS_FEATURE_MODEM -- der Schalter dieses Bausteins (ECM ist Teil von MODEM)
#include "ec200a_ecm.h"         // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
#if WEIRDOS_FEATURE_MODEM
// ============================================================================
// Echte Implementierung (WEIRDOS_FEATURE_MODEM=1) -- unveraendert
// ============================================================================
#include "ec200a_modem.h"
#include "modem_sim.h"        // modemEnsureSimReady (SIM-PIN vor dem Datenkanal, gemeinsam mit PPP)
#include "modem_clock.h"      // modemClockSync (Wanduhr aus dem Netz, gemeinsam mit PPP)
#include "esp_heap_caps.h"    // Heap-Lage im Log, wenn der RX-Task nicht anlegbar ist

#include "usb/usb_host.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_mac.h"

#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/dhcp.h"
#include "lwip/pbuf.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip6_addr.h"
#include "lwip/dns.h"

Ec200aEcm ec200aEcm;

// ---- entdeckte Topologie (aus dem Config-Descriptor, nichts hartkodiert) ----
static int      g_commIf = -1, g_dataIf = -1, g_dataAlt = 1;
static uint8_t  g_intInEp = 0, g_bulkInEp = 0, g_bulkOutEp = 0;
static uint16_t g_bulkMps = 64;

// ---- Bulk-Pools (analog PPP: mehrere Transfers gleichzeitig in flight) ------
// Tiefe 6, NICHT 16 (gleiche Lehre wie beim PPP-Pool): 16 * 1600 * 2 = ~50 KB INTERNES
// DMA-RAM (usb_host_transfer_alloc kann kein PSRAM) erschoepfen unter Modem+AP+STA den
// internen Heap -> Webserver-Freeze. Durchsatz ist antennen-/signalbegrenzt, nicht
// pipeline-tiefen-begrenzt (Projekt-Memory) -> 6 kostet nur ~20 KB und reicht.
static const int ECM_TX_N = 6;
static const int ECM_RX_N = 6;
static const int ECM_BUF  = 1600;             // >=1514, Vielfaches von 64 (25*64)

static usb_transfer_t* g_ecmTx[ECM_TX_N] = { 0 };
static usb_transfer_t* g_ecmRx[ECM_RX_N] = { 0 };
static QueueHandle_t   g_ecmTxFree = NULL;    // freie OUT-Transfers
static QueueHandle_t   g_ecmRxDone = NULL;    // fertige IN-Transfers -> RX-Task
static TaskHandle_t    g_ecmRxTask = NULL;
static volatile bool   g_ecmRun    = false;

static struct netif    g_ecmNetif;
static bool            g_ecmNetifAdded = false;
static uint8_t         g_ecmMac[6] = { 0x02, 0xEC, 0x20, 0x0A, 0x00, 0x01 };
static SemaphoreHandle_t g_ecmCtrlSem = NULL;

volatile uint32_t g_ecmTxBytes = 0, g_ecmRxBytes = 0;   // nicht static: Speedtest liest sie
static String     g_ecmWanIp = "";                      // oeffentliche WAN-IPv4 (NIC) / DHCP-IP
static String     g_ecmWanIp6 = "";                     // globale WAN-IPv6 (NIC, aus CGPADDR) -> statisch aufs netif
static String     g_ecmDns1 = "", g_ecmDns2 = "";       // DNS aus CGCONTRDP (NIC-Mode)
static String     g_ecmGw = "", g_ecmMask = "";         // Gateway (Feld 3) + Maske (Feld 2, Oktette 5-8) aus CGCONTRDP
static int        g_ecmNat = 0;                         // 0=Routing (DHCP), 1=NIC (statische WAN-IP)
// Source of Truth = die tatsaechliche netif-IP (NIC-statisch ODER DHCP). Der separate
// g_ecmWanIp-Cache kann nach einem Re-begin divergieren (leer, obwohl das netif eine IP
// hat) - das war der DynDNS-"wartet ewig"-Bug. Read-only, keine Aenderung des Datenpfads.
String ecmWanIp() {
    if (!g_ecmNetifAdded) return "";
    const ip4_addr_t* a = netif_ip4_addr(&g_ecmNetif);
    if (!a || ip4_addr_isany_val(*a)) return "";
    char b[24];
    ip4addr_ntoa_r(a, b, sizeof(b));
    return String(b);
}

// Globale (nicht link-lokale) IPv6 des ECM-netif, "" wenn noch keine da. Auf Mobilfunk
// per SLAAC/RA vergeben; kann ein paar Sekunden nach Link-up dauern. Read-only.
String ecmWanIp6() {
    if (!g_ecmNetifAdded) return "";
    String out = "";
    LOCK_TCPIP_CORE();
    for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        if (!ip6_addr_isvalid(netif_ip6_addr_state(&g_ecmNetif, i))) continue;
        const ip6_addr_t* a6 = netif_ip6_addr(&g_ecmNetif, i);
        if (ip6_addr_islinklocal(a6)) continue;       // fe80:: interessiert nicht
        out = String(ip6addr_ntoa(a6));               // erste globale -> das ist der Connect-Ziel
        break;
    }
    UNLOCK_TCPIP_CORE();
    return out;
}

// ECM als Default-Route erzwingen (ESP-Outbound -> Mobilfunk, Quell-IP = WAN-IP).
// Noetig fuer DynDNS: sonst geht der Request ueber WLAN und der Provider sieht die
// Heim-IP als Quelle. Lokaler UI-Zugriff (WLAN, inbound) bleibt unberuehrt. begin()
// setzt die Default-Route nur beim ERSTEN netif-Anlegen - holt WLAN sie sich danach
// zurueck (Reconnect/DHCP-Renew), muss sie vor dem Update erneut gesetzt werden.
void ecmSetDefaultRoute() {
    if (!g_ecmNetifAdded) return;
    LOCK_TCPIP_CORE();
    netif_set_default(&g_ecmNetif);
    UNLOCK_TCPIP_CORE();
}
// IP des aktuellen Default-netif (Diagnose: ECM-WAN = ok, 172.x = WLAN = falsch).
String ecmDefaultRouteIp() {
    struct netif* d = netif_default;
    if (!d) return "";
    char b[24];
    ip4addr_ntoa_r(netif_ip4_addr(d), b, sizeof(b));
    return String(b);
}

// Rohes lwIP-netif des ECM-Pfads (nullptr wenn nicht aktiv). Fuer die WireGuard-
// Underlay-Bindung (7.4b): ECM ist ein rohes netif, kein esp_netif.
struct netif* ecmNetifHandle() {
    return g_ecmNetifAdded ? &g_ecmNetif : nullptr;
}

// N-tes in Anfuehrungszeichen stehendes Feld einer AT-Antwort (1-basiert).
static String atQuoted(const String& s, int n) {
    int pos = 0;
    for (int i = 0; i < n; i++) {
        int q1 = s.indexOf('"', pos);   if (q1 < 0) return "";
        int q2 = s.indexOf('"', q1 + 1); if (q2 < 0) return "";
        if (i == n - 1) return s.substring(q1 + 1, q2);
        pos = q2 + 1;
    }
    return "";
}
// CGCONTRDP kann "IP.MASK" (8 Oktette) liefern -> nur die ersten 4 Oktette (die IP).
static String firstIpv4(String ip) {
    int dots = 0, cut = -1;
    for (int k = 0; k < (int)ip.length(); k++)
        if (ip[k] == '.') { if (++dots == 4) { cut = k; break; } }
    return (cut > 0) ? ip.substring(0, cut) : ip;
}

// ---- Forward-Deklarationen (Callbacks vor Verwendung) -----------------------
static void  ecmTxCb(usb_transfer_t* t);
static void  ecmRxCb(usb_transfer_t* t);
static err_t ecmLinkOutput(struct netif* n, struct pbuf* p);
static err_t ecmNetifInit(struct netif* n);
static void  ecmRxTask(void* arg);

// ===========================================================================
// 1) Discovery: CDC-ECM Comm-IF (0x02/0x06) + Data-IF (0x0A, alt>=1 Bulk)
// ===========================================================================
static bool ecmDiscover(usb_device_handle_t dev) {
    const usb_config_desc_t* cfg = NULL;
    if (usb_host_get_active_config_descriptor(dev, &cfg) != ESP_OK || !cfg) return false;
    const uint8_t* p = (const uint8_t*)cfg;
    int total = cfg->wTotalLength, off = 0;
    int curCls = -1, curAlt = -1;

    g_commIf = g_dataIf = -1;
    g_intInEp = g_bulkInEp = g_bulkOutEp = 0;

    while (off + 2 <= total) {
        uint8_t bLen = p[off], bType = p[off + 1];
        if (bLen == 0) break;
        if (bType == 0x04 && off + 9 <= total) {          // Interface-Descriptor
            uint8_t ifNum = p[off + 2];
            curAlt = p[off + 3];
            curCls = p[off + 5];
            uint8_t sub = p[off + 6];
            if (curCls == ECM_IF_CLASS_COMM && sub == ECM_IF_SUBCLASS && g_commIf < 0) g_commIf = ifNum;
            if (curCls == ECM_IF_CLASS_DATA) g_dataIf = ifNum;
        } else if (bType == 0x05 && off + 7 <= total) {   // Endpoint-Descriptor
            uint8_t a = p[off + 2], attr = p[off + 3];
            uint16_t mps = p[off + 4] | (p[off + 5] << 8);
            uint8_t tt = attr & 3;                        // 2=bulk, 3=interrupt
            if (curCls == ECM_IF_CLASS_COMM && tt == 3 && (a & 0x80)) g_intInEp = a;
            if (curCls == ECM_IF_CLASS_DATA && tt == 2 && curAlt >= 1) {
                g_dataAlt = curAlt;
                if (a & 0x80) { g_bulkInEp = a; g_bulkMps = mps; }
                else            g_bulkOutEp = a;
            }
        }
        off += bLen;
    }
    return (g_commIf >= 0 && g_dataIf >= 0 && g_bulkInEp && g_bulkOutEp);
}

// ===========================================================================
// 2) Control: SET_ETHERNET_PACKET_FILTER (bmReqType 0x21, bReq 0x43)
// ===========================================================================
static void ecmCtrlCb(usb_transfer_t* t) {
    if (t->context) xSemaphoreGive((SemaphoreHandle_t)t->context);
}
static bool ecmSetPacketFilter(usb_device_handle_t dev, uint16_t filter) {
    usb_host_client_handle_t cli = modemUsbClientHandle();
    if (!cli || !dev) return false;
    if (!g_ecmCtrlSem) g_ecmCtrlSem = xSemaphoreCreateBinary();
    usb_transfer_t* t = NULL;
    if (usb_host_transfer_alloc(sizeof(usb_setup_packet_t), 0, &t) != ESP_OK || !t) return false;
    usb_setup_packet_t* s = (usb_setup_packet_t*)t->data_buffer;
    s->bmRequestType = 0x21;                              // Host->Device | Class | Interface
    s->bRequest      = CDC_SET_ETHERNET_PACKET_FILTER;
    s->wValue        = filter;
    s->wIndex        = (g_commIf >= 0) ? (uint16_t)g_commIf : 0;
    s->wLength       = 0;
    t->num_bytes        = sizeof(usb_setup_packet_t);
    t->bEndpointAddress = 0x00;                           // Control-EP0
    t->device_handle    = dev;
    t->callback         = ecmCtrlCb;
    t->context          = g_ecmCtrlSem;
    t->timeout_ms       = 1000;
    bool ok = false;
    if (usb_host_transfer_submit_control(cli, t) == ESP_OK) {
        if (xSemaphoreTake(g_ecmCtrlSem, pdMS_TO_TICKS(1500)) == pdTRUE)
            ok = (t->status == USB_TRANSFER_STATUS_COMPLETED);
    }
    usb_host_transfer_free(t);
    return ok;
}

// ===========================================================================
// 3) Datenpfad TX/RX (Bulk-Pools) + lwIP-Ethernet-netif
// ===========================================================================
static void ecmTxCb(usb_transfer_t* t) {
    if (t->status == USB_TRANSFER_STATUS_COMPLETED) g_ecmTxBytes += t->actual_num_bytes;
    if (g_ecmTxFree) xQueueSend(g_ecmTxFree, &t, 0);
}
static void ecmRxCb(usb_transfer_t* t) {
    if (g_ecmRxDone) xQueueSend(g_ecmRxDone, &t, 0);
}

// lwIP -> Bulk-OUT: rohes Ethernet-Frame (etharp hat den Header schon gebaut).
static err_t ecmLinkOutput(struct netif* n, struct pbuf* p) {
    (void)n;
    usb_device_handle_t dev = modemDeviceHandle();
    if (!dev || !g_ecmTxFree || !g_ecmRun) return ERR_IF;
    if (p->tot_len > ECM_BUF) return ERR_MEM;
    usb_transfer_t* t = NULL;
    if (xQueueReceive(g_ecmTxFree, &t, pdMS_TO_TICKS(200)) != pdTRUE) return ERR_WOULDBLOCK;
    u16_t len = pbuf_copy_partial(p, t->data_buffer, p->tot_len, 0);
    t->num_bytes        = len;
    t->bEndpointAddress = g_bulkOutEp;
    t->device_handle    = dev;
    t->callback         = ecmTxCb;
    t->context          = NULL;
    if (usb_host_transfer_submit(t) != ESP_OK) { xQueueSend(g_ecmTxFree, &t, 0); return ERR_IF; }
    return ERR_OK;
}

static err_t ecmNetifInit(struct netif* n) {
    n->name[0] = 'e'; n->name[1] = 'c';
    n->output     = etharp_output;      // IP -> ARP -> Eth-Header -> linkoutput
    n->linkoutput = ecmLinkOutput;      // Eth-Frame -> Bulk-OUT
    n->mtu        = 1500;
    n->hwaddr_len = 6;
    memcpy(n->hwaddr, g_ecmMac, 6);
    n->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET
             | NETIF_FLAG_IGMP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

// Bulk-IN -> je fertiger Transfer = 1 Ethernet-Frame -> lwIP (tcpip_input).
static void ecmRxTask(void* arg) {
    (void)arg;
    usb_device_handle_t dev = modemDeviceHandle();
    int live = 0;
    for (int i = 0; i < ECM_RX_N; i++) {
        usb_transfer_t* t = g_ecmRx[i];
        if (!t) continue;
        t->num_bytes        = ECM_BUF;
        t->bEndpointAddress = g_bulkInEp;
        t->device_handle    = dev;
        t->callback         = ecmRxCb;
        t->context          = NULL;
        if (dev && usb_host_transfer_submit(t) == ESP_OK) live++;
    }
    while (live > 0) {
        usb_transfer_t* t = NULL;
        if (xQueueReceive(g_ecmRxDone, &t, portMAX_DELAY) != pdTRUE) continue;
        bool resubmit = false;
        if (g_ecmRun && t->status == USB_TRANSFER_STATUS_COMPLETED) {
            int n = t->actual_num_bytes;
            if (n > 0) {
                struct pbuf* p = pbuf_alloc(PBUF_RAW, n, PBUF_POOL);
                if (p) {
                    pbuf_take(p, t->data_buffer, n);
                    if (g_ecmNetif.input(p, &g_ecmNetif) != ERR_OK) pbuf_free(p);
                    g_ecmRxBytes += n;
                }
            }
            dev = modemDeviceHandle();
            if (dev) {
                t->num_bytes     = ECM_BUF;
                t->device_handle = dev;
                t->callback      = ecmRxCb;
                t->context       = NULL;
                if (usb_host_transfer_submit(t) == ESP_OK) resubmit = true;
            }
        }
        if (!resubmit) live--;
    }
    g_ecmRxTask = NULL;
    vTaskDelete(NULL);
}

// ===========================================================================
// begin/stop/status
// ===========================================================================
// Nicht-reentrant: begin() wird aus handleModemConnect (Web-Thread) UND ecmSuperTask
// aufgerufen. Parallele begin() erzeugen doppelte USB-Claims (live diagnostiziert, 6c13852).
// Nicht-blockierender Mutex weist den Doppelaufruf ab. NUR dieser Schutz - keine sonstige
// Aenderung an begin()/USB/RX/TX.
static SemaphoreHandle_t g_ecmBeginMtx = NULL;
struct EcmBeginGuard {
    bool held = false;
    EcmBeginGuard()  { if (g_ecmBeginMtx) held = (xSemaphoreTake(g_ecmBeginMtx, 0) == pdTRUE); }
    ~EcmBeginGuard() { if (held) xSemaphoreGive(g_ecmBeginMtx); }
};

bool Ec200aEcm::begin() {
    if (up_) return true;
    if (!g_ecmBeginMtx) g_ecmBeginMtx = xSemaphoreCreateMutex();
    EcmBeginGuard bg;                       // gibt den Mutex auf JEDEM return-Pfad frei
    if (!bg.held) { Serial.println("[ECM] begin() laeuft bereits - Doppelaufruf abgewiesen"); return false; }
    usb_device_handle_t dev = modemDeviceHandle();
    if (!dev) { Serial.println("[ECM] kein Modem-Handle (am aktiven Hub?)"); return false; }

    if (!ecmDiscover(dev)) {
        Serial.printf("[ECM] Discovery fehlgeschlagen (commIf=%d dataIf=%d bulkIn=%02X bulkOut=%02X). "
                      "Modem nicht im ECM-Modus (usbnet!=1).\n",
                      g_commIf, g_dataIf, g_bulkInEp, g_bulkOutEp);
        // AUTO-PROVISIONING (einmalig je Boot): ECM ist die Produktions-Datenschicht. Steht das
        // Modem noch auf RNDIS (usbnet=3, Auslieferung/Windows), wird es hier selbst umgestellt und
        // neu gestartet -- ueber denselben IF3-AT-Pfad, den der manuelle Wechsel (Datenschicht-Tab)
        // seit dem Live-Test nutzt. Der Supervisor ruft begin() nach der Re-Enumeration erneut auf.
        // Nur einmal, damit ein Modem, das ECM wirklich nicht kann, nicht in einer Reboot-Schleife
        // haengt (dann bleibt der Fehler stehen und der Nutzer kann auf PPP zurueck).
        static bool autoSwitched = false;
        if (!autoSwitched) {
            autoSwitched = true;
            Serial.println("[ECM] -> automatisch: AT+QCFG=\"usbnet\",1 + Modem-Reboot (einmalig)");
            Serial.println(ecmSwitchModemUsbnet(1));
            Serial.println(modemReset());   // AT+CFUN=1,1 -> Re-Enumeration als CDC-ECM
        }
        return false;
    }
    Serial.printf("[ECM] gefunden: commIf=%d intIn=%02X | dataIf=%d alt=%d bulkIn=%02X bulkOut=%02X mps=%u\n",
                  g_commIf, g_intInEp, g_dataIf, g_dataAlt, g_bulkInEp, g_bulkOutEp, g_bulkMps);

    // Stale RX auf IF3 leeren (URCs/verspaetete Antworten vom Boot-Autoconnect), sonst
    // haengt die Antwort eine Runde nach ("CGDCONT: Timeout", OK erscheint beim naechsten
    // Kommando) - genau der Lag aus dem Log. Ein paar Leer-ATs draenieren den Puffer.
    for (int i = 0; i < 4; i++) modemAtTest(3, 0x0F, 0x86, "AT");

    // PDP-Kontext 1 mit gewaehltem Typ + APN setzen, BEVOR der Datenkanal hochkommt.
    // Der PPP-Pfad macht das im Dial; ECM tat es bisher nicht -> IPv6 haette am zufaellig
    // persistierten Modem-Kontext gehangen. IPv6 braucht IPV4V6 (PPP kann kein IPv6, ECM schon).
    {
        String pdp = (modemPdpType == "IPV4V6") ? String("IPV4V6") : String("IP");
        String apn = modemApn.length() ? modemApn : String("internet");
        String cg  = modemAtTest(3, 0x0F, 0x86, "AT+CGDCONT=1,\"" + pdp + "\",\"" + apn + "\"");
        Serial.printf("[ECM] CGDCONT(1,%s,%s): %s\n", pdp.c_str(), apn.c_str(), cg.c_str());
        // Authentifizierung (Benutzer/Passwort, PAP/CHAP) fuer Kontext 1 -- Paritaet zu PPP (dort
        // ppp_set_auth). Der ECM-Datenkanal (QNETDEVCTL) nutzt die Kontext-Parameter aus QICSGP:
        //   AT+QICSGP=<ctx>,<type 1=IPv4|3=IPv4v6>,"<apn>","<user>","<pass>",<auth 0=keine|1=PAP|2=CHAP>
        // Ohne Auth (Normalfall DE) ist das ein No-op mit leeren Feldern.
        {
            int auth    = (modemAuth == "2") ? 2 : (modemAuth == "1") ? 1 : 0;
            int ctxType = (modemPdpType == "IPV4V6") ? 3 : 1;
            String qi = modemAtTest(3, 0x0F, 0x86, "AT+QICSGP=1," + String(ctxType) + ",\"" + apn + "\",\"" +
                                    modemUser + "\",\"" + modemPass + "\"," + String(auth));
            Serial.printf("[ECM] QICSGP(1,%d,auth=%d): %s\n", ctxType, auth, qi.c_str());
        }
    }

    // Datenkanal am Modem aktivieren (ECM): PDP-Kontext -> USB-Netz bruecken. Resettet
    // sich bei jedem Modem-Reboot -> hier setzen. Muss VOR dem ECM-Claim laufen (IF3 frei).
    // Datenkanal: type=3 = auto-connect + PERSISTENT (uebersteht Modem-Reboot),
    // besser als =1 (once, das resettet). Alles noch mit freiem IF3-AT.
    // SIM bereit? Gemeinsamer Pfad mit PPP (modem_sim.*): bei "SIM PIN" wird die konfigurierte PIN
    // genau einmal je Boot gesendet (PUK-Schutz) und auf READY gewartet. Ohne bereite SIM kein
    // Datenkanal -- der Supervisor versucht es spaeter erneut (dann ohne weiteren PIN-Versuch).
    {
        String simSt = modemEnsureSimReady(3, 0x0F, 0x86);
        if (!simSt.startsWith("READY")) {
            Serial.printf("[ECM] SIM nicht bereit: %s\n", simSt.c_str());
            modemReleaseInterface(3);
            return false;
        }
    }
    String qn = modemAtTest(3, 0x0F, 0x86, "AT+QNETDEVCTL=3,1");
    Serial.printf("[ECM] QNETDEVCTL(3): %s\n", qn.c_str());

    // Arbeitsmodus des NIC: 0=Routing (Modem NATet, DHCP gibt 192.168.43.100),
    // 1=NIC (Host bekommt die oeffentliche WAN-IP -> KEIN DHCP, statisch aus CGCONTRDP).
    String nn = modemAtTest(3, 0x0F, 0x86, "AT+QCFG=\"nat\"");
    g_ecmNat = (nn.indexOf("\"nat\",1") >= 0) ? 1 : 0;
    // Konfigurierte Betriebsart (WAN > Modem > Anschluss) durchsetzen: weicht das Modem ab, einmalig
    // umstellen + Modem-Reboot (persistent im Modem); der Supervisor startet ECM danach neu.
    {
        int wantNat = (modemNatMode == "routing") ? 0 : 1;
        static bool natSwitched = false;
        if (g_ecmNat != wantNat && !natSwitched) {
            natSwitched = true;
            Serial.printf("[ECM] NIC-Betriebsart nat=%d, konfiguriert %d -> umstellen + Modem-Reboot (einmalig)\n",
                          g_ecmNat, wantNat);
            Serial.println(ecmSwitchModemNat(wantNat));
            Serial.println(modemReset());
            modemReleaseInterface(3);
            return false;
        }
    }

    // Netzparameter (IP + DNS) vom Netz holen; nach QNETDEVCTL braucht der PDP evtl.
    // ein paar Sekunden bis die IP steht -> mehrfach versuchen.
    g_ecmWanIp = ""; g_ecmDns1 = ""; g_ecmDns2 = ""; g_ecmWanIp6 = ""; g_ecmGw = ""; g_ecmMask = "";
    for (int i = 0; i < 12; i++) {
        String rd = modemAtTest(3, 0x0F, 0x86, "AT+CGCONTRDP=1");
        String ipm = atQuoted(rd, 2);                // Feld 2 = local IP, 3GPP-Form "a.b.c.d.m.m.m.m"
        String ip  = firstIpv4(ipm);
        if (ip.length() && ip != "0.0.0.0") {
            g_ecmWanIp = ip;
            if (ipm.length() > ip.length() + 1) g_ecmMask = ipm.substring(ip.length() + 1);   // Maske (8-Oktett-Form)
            g_ecmGw   = atQuoted(rd, 3);             // Feld 3 = Gateway (3GPP 27.007: gw_addr)
            g_ecmDns1 = atQuoted(rd, 4);             // Feld 4/5 = DNS prim/sek
            g_ecmDns2 = atQuoted(rd, 5);
            break;
        }
        delay(700);
    }
    // Globale IPv6 aus CGPADDR (dual-stack: Feld1=IPv4, Feld2=IPv6). Im NIC-Mode gibt es
    // kein RA -> die v6 kommt NICHT per SLAAC, sondern muss (wie die IPv4) statisch aufs
    // netif. Ein paar Versuche, da die v6 nach QNETDEVCTL evtl. verzoegert steht.
    for (int i = 0; i < 8; i++) {
        String pa = modemAtTest(3, 0x0F, 0x86, "AT+CGPADDR=1");
        String v6 = atQuoted(pa, 2);                 // Feld 2 = IPv6 (":" enthalten)
        if (v6.indexOf(':') >= 0) { g_ecmWanIp6 = v6; break; }
        delay(600);
    }
    Serial.printf("[ECM] nat=%d WAN=%s DNS=%s/%s\n", g_ecmNat, g_ecmWanIp.c_str(),
                  g_ecmDns1.c_str(), g_ecmDns2.c_str());
    if (g_ecmWanIp6.length())
        Serial.printf("[ECM] WAN-IPv6=[%s]  URL http://[%s]/\n", g_ecmWanIp6.c_str(), g_ecmWanIp6.c_str());
    else
        Serial.println("[ECM] WAN-IPv6=(keine - Kontext IPV4V6? Netz gibt v6?)");

    // Vor dem Snapshot auf Netz-Registrierung warten - genau wie PPP. Der Boot-
    // Autoconnect kann bereits eine WAN-IP haben, waehrend QNWINFO/CEREG/QENG noch
    // NO SERVICE/0/leer liefern; dieser falsche Snapshot bliebe sonst waehrend
    // aktivem ECM stehen (die UI macht dann bewusst keine Live-AT-Abfrage).
    modemWaitRegistered(3, 0x0F, 0x86, 20);

    // RF-Snapshot holen, solange IF3 noch geclaimt ist (Band/Frequenz/Signal/IDs fuer die
    // Mobilfunk-Info-Seite) - genau wie beim PPP-Connect. Danach wird IF3 freigegeben.
    modemRfQeng  = modemAtTest(3, 0x0F, 0x86, "AT+QENG=\"servingcell\"");
    modemRfQnw   = modemAtTest(3, 0x0F, 0x86, "AT+QNWINFO");
    modemRfCops  = modemAtTest(3, 0x0F, 0x86, "AT+COPS?");
    modemRfCsq   = modemAtTest(3, 0x0F, 0x86, "AT+CSQ");
    modemRfAti   = modemAtTest(3, 0x0F, 0x86, "ATI");
    modemRfImei  = modemAtTest(3, 0x0F, 0x86, "AT+CGSN");
    modemRfIccid = modemAtTest(3, 0x0F, 0x86, "AT+QCCID");
    modemRfImsi  = modemAtTest(3, 0x0F, 0x86, "AT+CIMI");
    modemRfCpin  = modemAtTest(3, 0x0F, 0x86, "AT+CPIN?");
    modemRfCereg = modemAtTest(3, 0x0F, 0x86, "AT+CEREG?");
    modemRfMs    = millis();
    modemClockSync(3, 0x0F, 0x86);   // Wanduhr aus dem Netz (TLS/ACME), solange IF3 frei ist

    // AT-IF (IF3) freigeben - FS-Host-Channel-Budget (nur ein serielles IF gleichzeitig).
    modemReleaseInterface(3);

    if (!modemClaimInterface((uint8_t)g_commIf, 0)) {
        Serial.println("[ECM] commIf claim fehlgeschlagen"); return false;
    }
    if (!modemClaimInterface((uint8_t)g_dataIf, (uint8_t)g_dataAlt)) {
        Serial.println("[ECM] dataIf(alt) claim fehlgeschlagen");
        modemReleaseInterface((uint8_t)g_commIf);
        return false;
    }

    if (!ecmSetPacketFilter(dev, ECM_PF_DIRECTED | ECM_PF_BROADCAST | ECM_PF_ALL_MULTICAST))
        Serial.println("[ECM] WARN: SET_ETHERNET_PACKET_FILTER fehlgeschlagen (fahre fort)");

    // Bulk-Pools
    if (!g_ecmTxFree) g_ecmTxFree = xQueueCreate(ECM_TX_N,     sizeof(usb_transfer_t*));
    if (!g_ecmRxDone) g_ecmRxDone = xQueueCreate(ECM_RX_N + 2, sizeof(usb_transfer_t*));
    for (int i = 0; i < ECM_TX_N; i++) if (!g_ecmTx[i]) usb_host_transfer_alloc(ECM_BUF, 0, &g_ecmTx[i]);
    for (int i = 0; i < ECM_RX_N; i++) if (!g_ecmRx[i]) usb_host_transfer_alloc(ECM_BUF, 0, &g_ecmRx[i]);
    xQueueReset(g_ecmTxFree);
    for (int i = 0; i < ECM_TX_N; i++) if (g_ecmTx[i]) xQueueSend(g_ecmTxFree, &g_ecmTx[i], 0);

    // MAC lokal administriert aus der Chip-MAC ableiten
    uint8_t base[6] = { 0 };
    esp_read_mac(base, ESP_MAC_WIFI_STA);
    g_ecmMac[0] = 0x02;
    for (int i = 1; i < 6; i++) g_ecmMac[i] = base[i];

    // Rohes lwIP-Ethernet-netif. NIC-Mode (nat=1): STATISCH mit der WAN-IP (kein
    // DHCP-Server im Modem). Routing-Mode: DHCP (holt 192.168.43.100). Das Netz gibt
    // KEIN Gateway (Point-to-Point, Modem macht Proxy-ARP) -> Gateway = <netz>.1 raten,
    // Netmask /24; DNS aus CGCONTRDP.
    ip4_addr_t sip;
    bool nicStatic = (g_ecmNat == 1 && g_ecmWanIp.length()
                      && ip4addr_aton(g_ecmWanIp.c_str(), &sip));
    if (!g_ecmNetifAdded) {
        LOCK_TCPIP_CORE();
        if (nicStatic) {
            // Routingparameter: ZUERST das, was das Modem in CGCONTRDP meldet (3GPP: local_addr_and_
            // subnet_mask + gw_addr) -- das ist die autoritative Quelle. Nur wenn das Modem keinen
            // brauchbaren Gateway liefert (leer/0.0.0.0/= eigene IP), die bisherige Heuristik
            // (/24 + <netz>.1, per Proxy-ARP des Modems beantwortet) -- mit Log "geraten", damit ein
            // Ausfall bei anderem Praefix nicht mehr stumm bleibt.
            ip4_addr_t nm, gw, gwm, nmm;
            uint32_t a = lwip_ntohl(ip4_addr_get_u32(&sip));
            bool gwFromModem = g_ecmGw.length() && ip4addr_aton(g_ecmGw.c_str(), &gwm)
                               && !ip4_addr_isany_val(gwm) && !ip4_addr_cmp(&gwm, &sip);
            bool maskFromModem = g_ecmMask.length() && ip4addr_aton(g_ecmMask.c_str(), &nmm) && !ip4_addr_isany_val(nmm);
            if (gwFromModem) {
                gw = gwm;
                // Maske: vom Modem (Mobilfunk meist /32 = Punkt-zu-Punkt); damit ist der Gateway
                // "off-link" und lwIP ARPt ihn -- das Modem antwortet per Proxy-ARP. Ohne Maske /32.
                if (maskFromModem) nm = nmm; else IP4_ADDR(&nm, 255, 255, 255, 255);
                Serial.printf("[ECM] Routing vom Modem: IP %s Maske %s Gateway %s\n",
                              g_ecmWanIp.c_str(), ip4addr_ntoa(&nm), g_ecmGw.c_str());
            } else {
                IP4_ADDR(&nm, 255, 255, 255, 0);
                ip4_addr_set_u32(&gw, lwip_htonl((a & 0xFFFFFF00u) | 1u));   // <netz>.1
                Serial.printf("[ECM] Routing GERATEN (Modem meldet kein Gateway: '%s'): /24 + %s\n",
                              g_ecmGw.c_str(), ip4addr_ntoa(&gw));
            }
            netif_add(&g_ecmNetif, &sip, &nm, &gw, NULL, ecmNetifInit, tcpip_input);
            netif_set_up(&g_ecmNetif);
            netif_set_link_up(&g_ecmNetif);
            ip_addr_t d;
            if (g_ecmDns1.length() && ipaddr_aton(g_ecmDns1.c_str(), &d)) dns_setserver(0, &d);
            if (g_ecmDns2.length() && ipaddr_aton(g_ecmDns2.c_str(), &d)) dns_setserver(1, &d);
            netif_set_default(&g_ecmNetif);
        } else {
            ip4_addr_t z; ip4_addr_set_zero(&z);
            netif_add(&g_ecmNetif, &z, &z, &z, NULL, ecmNetifInit, tcpip_input);
            netif_set_up(&g_ecmNetif);
            netif_set_link_up(&g_ecmNetif);
            dhcp_start(&g_ecmNetif);
            netif_set_default(&g_ecmNetif);
        }
        // IPv6 (Mobilfunk-IPv6 ist NICHT genattet -> global direkt erreichbar; kein lwIP-
        // Rebuild noetig, LWIP_IPV6/AUTOCONFIG sind im Core =y - anders als PPP).
        //  - Routing-Mode (nat=0): Modem ist Router -> SLAAC/RA vergibt die globale v6.
        //  - NIC-Mode (nat=1): KEIN RA -> die globale v6 statisch aus CGPADDR setzen (wie
        //    die statische IPv4). SLAAC waere hier wirkungslos (wartet auf ein RA, das nie kommt).
        netif_create_ip6_linklocal_address(&g_ecmNetif, 1);
        netif_set_ip6_autoconfig_enabled(&g_ecmNetif, g_ecmNat ? 0 : 1);
        if (g_ecmNat && g_ecmWanIp6.length()) {
            ip6_addr_t a6;
            if (ip6addr_aton(g_ecmWanIp6.c_str(), &a6)) {
                s8_t idx6 = -1;
                netif_add_ip6_address(&g_ecmNetif, &a6, &idx6);
                if (idx6 >= 0) netif_ip6_addr_set_state(&g_ecmNetif, idx6, IP6_ADDR_PREFERRED);
            }
        }
        UNLOCK_TCPIP_CORE();
        g_ecmNetifAdded = true;
    }
    Serial.printf("[ECM] netif: %s\n", nicStatic ? "STATISCH (NIC, WAN-IP am Host)" : "DHCP (Routing)");

    g_ecmRun = true;
    // RX-Task ZUERST und geprueft -- erst dann "up". Scheitert die Task-Erzeugung (interner Heap),
    // gaebe es sonst einen Falsch-Gruen-Zustand: netif up + Default-Route, aber niemand liest USB-IN
    // -> Blackhole ohne Fehlermeldung. Dann alles zurueckrollen und ehrlich false liefern.
    if (!g_ecmRxTask &&
        xTaskCreatePinnedToCore(ecmRxTask, "ecm_rx", 4096, NULL, 6, &g_ecmRxTask, 1) != pdPASS) {
        g_ecmRxTask = NULL;
        g_ecmRun = false;
        Serial.printf("[ECM] RX-Task nicht anlegbar (intern frei %uk, groesster %uk) -> ECM abgebrochen\n",
                      (unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024),
                      (unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) / 1024));
        stop();   // netif/Interfaces/Transfers wieder abbauen (gleicher Pfad wie beim regulaeren Ende)
        return false;
    }
    up_ = true;

    Serial.println("[ECM] up - DHCP laeuft, netif = default. Durchsatz auf der Durchsatz-Seite messen.");
    return true;
}

void Ec200aEcm::stop() {
    g_ecmRun = false;
    up_ = false;
    g_ecmWanIp = "";
    usb_device_handle_t dev = modemDeviceHandle();
    // In-flight Bulk-Transfers HART abbrechen, sonst bleibt das Interface belegt
    // (ESP_ERR_INVALID_STATE) und der naechste Re-Claim scheitert (PPP-Lektion).
    if (dev && g_bulkInEp)  { usb_host_endpoint_halt(dev, g_bulkInEp);  usb_host_endpoint_flush(dev, g_bulkInEp);  usb_host_endpoint_clear(dev, g_bulkInEp); }
    if (dev && g_bulkOutEp) { usb_host_endpoint_halt(dev, g_bulkOutEp); usb_host_endpoint_flush(dev, g_bulkOutEp); usb_host_endpoint_clear(dev, g_bulkOutEp); }
    for (int i = 0; i < 40 && g_ecmRxTask; i++) vTaskDelay(pdMS_TO_TICKS(50));  // RX-Task auslaufen lassen (<=2s)
    if (g_ecmNetifAdded) {
        LOCK_TCPIP_CORE();
        dhcp_stop(&g_ecmNetif);
        netif_set_down(&g_ecmNetif);
        netif_remove(&g_ecmNetif);
        UNLOCK_TCPIP_CORE();
        g_ecmNetifAdded = false;
    }
    if (g_dataIf >= 0) modemReleaseInterface((uint8_t)g_dataIf);
    if (g_commIf >= 0) modemReleaseInterface((uint8_t)g_commIf);

    // Transfer-Pools freigeben (~51 KB internes DMA-RAM). SONST koexistieren die
    // ECM-Pools mit den PPP-Pools -> Heap-Erschoepfung (heapmin ~584 B) -> Kamera
    // bekommt keine Puffer -> Stream friert ein. Nur freigeben, wenn der RX-Task
    // wirklich weg ist (sonst use-after-free).
    if (!g_ecmRxTask) {
        for (int i = 0; i < ECM_TX_N; i++) if (g_ecmTx[i]) { usb_host_transfer_free(g_ecmTx[i]); g_ecmTx[i] = NULL; }
        for (int i = 0; i < ECM_RX_N; i++) if (g_ecmRx[i]) { usb_host_transfer_free(g_ecmRx[i]); g_ecmRx[i] = NULL; }
        if (g_ecmTxFree) { vQueueDelete(g_ecmTxFree); g_ecmTxFree = NULL; }
        if (g_ecmRxDone) { vQueueDelete(g_ecmRxDone); g_ecmRxDone = NULL; }
    }
}

// Modem physisch weg (Reboot/Unplug): NUR die lwIP-Seite + Flags aufraeumen.
// KEINE USB-Endpoint-/Interface-Ops (Handle ist tot) - das macht die DEV_GONE-Routine
// im Treiber (releast g_ifClaimed[] + device_close). Der RX-Task laeuft aus, sobald
// seine Transfers mit Fehler zurueckkommen (g_ecmRun=false -> kein Resubmit).
void Ec200aEcm::onGone() {
    g_ecmRun = false;
    up_ = false;
    g_ecmWanIp = "";
    if (g_ecmNetifAdded) {
        LOCK_TCPIP_CORE();
        dhcp_stop(&g_ecmNetif);
        netif_set_down(&g_ecmNetif);
        netif_remove(&g_ecmNetif);
        UNLOCK_TCPIP_CORE();
        g_ecmNetifAdded = false;
    }
}
void ecmOnDeviceGone() { ec200aEcm.onGone(); }

bool Ec200aEcm::isUp() const { return up_; }

String Ec200aEcm::statusText() const {
    if (!up_) return "ECM aus";
    char ip[24] = "0.0.0.0";
    if (g_ecmNetifAdded) ip4addr_ntoa_r(netif_ip4_addr(&g_ecmNetif), ip, sizeof(ip));
    return String("ECM up, IP ") + ip;
}

String Ec200aEcm::rateJson() const {
    return String("\"ecmup\":") + (up_ ? "true" : "false")
         + ",\"ecmtx\":" + String((uint32_t)g_ecmTxBytes)
         + ",\"ecmrx\":" + String((uint32_t)g_ecmRxBytes);
}

// ===========================================================================
// Supervisor + Modem-Umschalter
// ===========================================================================
static TaskHandle_t  g_ecmSup    = NULL;
static volatile bool g_ecmSupRun = false;

// PPP-Rueckfall: schlaegt der ECM-Start bei ANWESENDEM Modem 3x hintereinander fehl (Discovery/
// Claim/Datenkanal -- NICHT SIM-Probleme, die traefen PPP genauso), laeuft der Supervisor aus und
// startet den PPP-Supervisor. PPP geht ueber IF4 in BEIDEN USB-Kompositionen (usbnet=1 wie =3),
// braucht also keinen weiteren Modem-Reboot. Die Datenschicht-EINSTELLUNG bleibt ECM; ein
// manuelles "Verbinden"/"mode ecm" setzt den Rueckfall zurueck und versucht ECM erneut.
static volatile bool g_ecmFallback   = false;
static int           g_ecmFailStreak = 0;
bool ecmFallbackActive() { return g_ecmFallback; }
void ecmFallbackReset()  { g_ecmFallback = false; g_ecmFailStreak = 0; }

static void ecmSuperTask(void* arg) {
    (void)arg;
    while (g_ecmSupRun) {
        // Auto-Start/Auto-Retry nur, wenn WeirdOS-"Automatisch verbinden" (modemAutoStart)
        // aktiv ist - gleiche Semantik wie der PPP-Supervisor. Bewusstes "Trennen" bleibt
        // getrennt, weil handleModemDisconnect ecmStopSupervisor() ruft (Task laeuft aus).
        if (modemAutoStart && !ec200aEcm.isUp() && modemDeviceHandle()) {
            bool ok = ec200aEcm.begin();
            if (ok) {
                g_ecmFailStreak = 0;
            } else {
                const String& sim = modemSimLastStatus();
                bool simProblem = sim.length() && !sim.startsWith("READY");
                if (!simProblem && ++g_ecmFailStreak >= 3 && !g_ecmFallback) {
                    g_ecmFallback = true;
                    Serial.println("[ECM] 3x fehlgeschlagen (kein SIM-Problem) -> RUECKFALL auf PPP. "
                                   "Einstellung bleibt ECM; 'Verbinden' bzw. 'mode ecm' versucht ECM erneut.");
                    g_ecmSupRun = false;
                    startPppSupervisor();
                    break;
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(4000));
    }
    g_ecmSup = NULL;
    vTaskDelete(NULL);
}
void ecmStartSupervisor() {
    g_ecmSupRun = true;   // ERST das Run-Flag setzen: laeuft der alte Task nach einem
                          // ecmStopSupervisor() noch (g_ecmSup != NULL), wird er dadurch
                          // wiederbelebt statt auszulaufen (Trennen->Verbinden-Bug).
    if (g_ecmSup) return;
    xTaskCreatePinnedToCore(ecmSuperTask, "ecm_sup", 4096, NULL, 5, &g_ecmSup, 1);
}
void ecmStopSupervisor() { g_ecmSupRun = false; }

String ecmSwitchModemNat(int nat) {
    // AT+QCFG="nat",<0=Routing|1=NIC>: persistent im Modem, wirkt nach Modem-Reboot.
    String r = modemAtTest(3, 0x0F, 0x86, "AT+QCFG=\"nat\"," + String(nat));
    return String("nat=") + String(nat) + (nat ? " (NIC)" : " (Routing)") + " gesetzt (" + r + ") - wirkt nach Modem-Reboot.";
}

String ecmSwitchModemUsbnet(int mode) {
    // Nur den usbnet-Modus setzen (pending). Wirkt erst nach dem Modem-Reboot; der
    // Datenkanal (QNETDEVCTL) wird nach dem Reboot in ec200aEcm::begin() aktiviert.
    String r1 = modemAtTest(3, 0x0F, 0x86, "AT+QCFG=\"usbnet\"," + String(mode));
    return "usbnet=" + String(mode) + " gesetzt (" + r1 + ") - wirkt nach Modem-Reboot.";
}

#else  // !WEIRDOS_FEATURE_MODEM
// ============================================================================
// Stub: CDC-ECM-Datenpfad nicht im Build enthalten (WEIRDOS_FEATURE_MODEM=0)
//
// Gleiche Klasse, gleiches globales Objekt, jede freie Funktion aus ec200a_ecm.h trivial: kein
// usb_host_*, keine Transfer-Pools, kein Ethernet-netif, kein Supervisor-Task, kein AT. up_ bleibt
// false -> isUp() false, statusText "nicht im Build". Konsumenten: .ino (DynDNS/Status-JSON),
// network_registry, network_platform, peripheral_registry, serial_console, modem_datalink.
//
// ecmDefaultRouteIp() ist KEIN Modem-Wissen (liest nur netif_default) und bleibt fuer die
// DynDNS-Egress-Diagnose der .ino (auch ueber WLAN) funktional, solange ein IP-Stack im Build ist.
// ============================================================================
#if WEIRDOS_FEATURE_NET
#include "lwip/netif.h"       // netif_default (reine Diagnose, kein ECM)
#include "lwip/ip4_addr.h"    // ip4addr_ntoa_r
#endif

static const char* const kEcmNotBuilt = "Modem nicht im Build enthalten (WEIRDOS_FEATURE_MODEM=0)";

Ec200aEcm ec200aEcm;
volatile uint32_t g_ecmTxBytes = 0, g_ecmRxBytes = 0;   // Byte-Zaehler bleiben 0 (Speedtest/Online-Monitor)

bool   Ec200aEcm::begin()            { return false; }
void   Ec200aEcm::stop()             {}
void   Ec200aEcm::onGone()           {}
bool   Ec200aEcm::isUp() const       { return false; }
String Ec200aEcm::statusText() const { return "ECM: nicht im Build enthalten"; }
// JSON-Fragment mit denselben Schluesseln wie der Treiber (sendModemJson haengt es ein).
String Ec200aEcm::rateJson() const   { return "\"ecmup\":false,\"ecmtx\":0,\"ecmrx\":0"; }

String ecmWanIp()           { return ""; }
String ecmWanIp6()          { return ""; }
void   ecmSetDefaultRoute() {}
#if WEIRDOS_FEATURE_NET
// Identisch zum Treiber: IP des aktuellen Default-netif (Diagnose: WLAN-Egress fuer DynDNS).
String ecmDefaultRouteIp() {
    struct netif* d = netif_default;
    if (!d) return "";
    char b[24];
    ip4addr_ntoa_r(netif_ip4_addr(d), b, sizeof(b));
    return String(b);
}
#else
String ecmDefaultRouteIp() { return ""; }
#endif
struct netif* ecmNetifHandle() { return nullptr; }   // network_platform: "modem-ecm" -> kein netif

void   ecmStartSupervisor() {}
void   ecmStopSupervisor()  {}
bool   ecmFallbackActive()  { return false; }        // modem_datalink: nie ein PPP-Rueckfall
void   ecmFallbackReset()   {}
void   ecmOnDeviceGone()    {}
String ecmSwitchModemUsbnet(int mode) { (void)mode; return kEcmNotBuilt; }
String ecmSwitchModemNat(int nat)     { (void)nat;  return kEcmNotBuilt; }

#endif // WEIRDOS_FEATURE_MODEM
