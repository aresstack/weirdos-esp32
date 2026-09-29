// ============================================================================
// ipsec_runtime.cpp -- siehe ipsec_runtime.h. Portiert vom CI-bewiesenen esp_natt_itest.c.
//
// Baustein IPSEC (weirdos_features.h): bei WEIRDOS_FEATURE_IPSEC=0 bleibt nur der Stub am Ende
// dieser Datei. Sie ist (neben ipsec_trust_store.cpp) die EINZIGE Uebersetzungseinheit, die den
// vendored WeirdIKE-Kern (src/weirdike/*.c) referenziert -- ohne diese Referenzen wirft
// --gc-sections den Kern samt seiner Puffer aus Flash und RAM.
// ============================================================================
#include "weirdos_features.h"
#include "ipsec_runtime.h"
#if WEIRDOS_FEATURE_IPSEC
#include "ipsec_crypto_caps.h"   // UI-Kennungen -> IANA-IDs (typisierte WeirdIKE-Policy), Namen fuer den Status
#include "vpn_status.h"    // fillVpnStatus: Runtime-Anteil des einheitlichen VPN-Status
#include "egress_policy.h"
#include "network_registry.h"
#include <Network.h>       // bounded DNS (Network.hostByName = WiFi.hostByName im Core 3.x) statt blockierendem
                           // getaddrinfo -- ohne WiFi.h, damit WEIRDOS_FEATURE_WIFI=0 die WLAN-Library nicht mitzieht

#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include "lwip/netif.h"      // 8.2f: ipsec0 -- der Tunnel als lwIP-Netzwerkschnittstelle
#include "lwip/tcpip.h"
#include "lwip/pbuf.h"
#include "lwip/ip4_addr.h"
#include <freertos/queue.h>
#include <esp_heap_caps.h>
#include <esp_system.h>   // esp_reset_reason: Absturz-Lokalisierung nach Panic/WDT-Reset
#include <freertos/task.h>
#include <esp_random.h>   // esp_fill_random: TRNG fuer den ESP-IV (kein AES/DMA/Heap)
#include <mbedtls/aes.h>   // crypttest: Hardware-AES-Vergleich
#include "aes_soft.h"      // Software-AES (Referenz + Rueckfall)
#include "aes_engine.h"    // umschaltbarer AES-Treiber (HW-Blockmodus ohne DMA / Software)
#ifndef IPPROTO_ESP
#define IPPROTO_ESP 50   // lwIP definiert nur IP/ICMP/TCP/UDP/RAW -- ESP ist IANA-Protokoll 50
#endif

// Explizite Pfade -> unabhaengig von der Arduino-Include-Path-Heuristik fuer verschachtelte src/.
// (Quoted-Includes IN den WeirdIKE-Headern loesen relativ zu src/weirdike/ auf.)
extern "C" {
#include "src/weirdike/weirdike.h"
#include "src/weirdike/esp_session.h"
#include "src/weirdike/ike_natt.h"
#include "src/weirdike/crypto_mbedtls.h"
}
#include "ipsec_trust_store.h"   // Trust-Modell: Host-Truststore (ESP-IDF-Bundle) + Modus-Kennungen (C++-Linkage, daher AUSSERHALB des extern "C")

IpsecRuntime ipsecRuntime;

// ---- Absturz-Lokalisierung (HW-Gate 2026-09-04) --------------------------------------------------
// Auf dem P4 geht der Panic-Text ueber USB-Serial-JTAG verloren (nur "G" von "Guru Meditation" kommt
// an, dann resettet der Panic-Watchdog: rst:0x10 CHIP_LP_WDT_RESET) -- kein Backtrace, kein Coredump.
// Gleiches In-Band-Muster wie g_wgCrashStage: RTC_NOINIT ueberlebt den Panic/WDT-Reset. Jeder Schritt
// der Runtime setzt den Marker (+ IKE-Zustand, freier loop-Stack, Uptime); nach dem Reset meldet
// ipsecRuntimeBootReport() auf der Konsole/Diagnose EXAKT den letzten Schritt = die Absturzstelle.
RTC_NOINIT_ATTR volatile uint32_t g_ipsecCrashStage;      // 0 = IPsec war nicht am Zug
RTC_NOINIT_ATTR volatile uint32_t g_ipsecCrashIkeState;   // weirdike_state() beim Marker
RTC_NOINIT_ATTR volatile uint32_t g_ipsecCrashStackMin;   // kleinster freier loop-Stack (Bytes) seit Boot
RTC_NOINIT_ATTR volatile uint32_t g_ipsecCrashMs;         // millis() beim Marker
static String g_ipsecLastCrash;                           // Bericht des letzten Resets (Diagnose-JSON)
static inline void ipsecStage(uint32_t s, uint32_t ikeState = 0xFFFFFFFFu) {
    g_ipsecCrashStage = s;
    if (ikeState != 0xFFFFFFFFu) g_ipsecCrashIkeState = ikeState;
    uint32_t hw = (uint32_t)uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t);
    if (hw < g_ipsecCrashStackMin) g_ipsecCrashStackMin = hw;
    g_ipsecCrashMs = millis();
}
static const char* ipsecStageName(uint32_t s) {
    switch (s) {
        case 1:  return "start: Egress/Bind";
        case 2:  return "start: Crypto-Init";
        case 3:  return "start: weirdike_new";
        case 4:  return "start: weirdike_start (DNS + IKE_SA_INIT senden)";
        case 5:  return "start: fertig";
        case 10: return "poll: weirdike_poll (Timer/Retransmit/DPD/Rekey)";
        case 11: return "poll: Zustand auswerten";
        case 12: return "poll: esp_session_init (CHILD_ESTABLISHED)";
        case 13: return "poll: Raw-Socket Proto 50 oeffnen";
        case 14: return "poll: tunBringUp (ipsec0 anlegen)";
        case 15: return "poll: Rekey -> neue Session";
        case 16: return "poll: tunPumpTx (seal + senden)";
        case 17: return "poll: Raw-ESP empfangen";
        case 18: return "poll: IKE-Socket lesen";
        case 19: return "poll: weirdike_input_datagram";
        case 20: return "poll: ESP entschluesseln (esp_session_open)";
        case 21: return "poll: inneres Paket -> lwIP (tunDeliver)";
        case 22: return "poll: fertig";
        case 30: return "stop: tunDown";
        case 31: return "stop: DELETE senden/warten";
        case 32: return "stop: weirdike_free";
        case 33: return "stop: fertig";
        case 40: return "testPing";
        default: return "?";
    }
}
void ipsecRuntimeBootReport() {
    esp_reset_reason_t rr = esp_reset_reason();
    bool crash = (rr == ESP_RST_PANIC || rr == ESP_RST_INT_WDT || rr == ESP_RST_TASK_WDT || rr == ESP_RST_WDT);
    if (crash && g_ipsecCrashStage != 0 && g_ipsecCrashStage < 100) {
        char b[200];
        snprintf(b, sizeof(b), "Reset %s: letzter IPsec-Schritt %lu (%s), IKE-Zustand %lu, loop-Stack min %lu B, t=%lu ms",
                 rr == ESP_RST_PANIC ? "PANIC" : rr == ESP_RST_INT_WDT ? "INT_WDT" : rr == ESP_RST_TASK_WDT ? "TASK_WDT" : "WDT",
                 (unsigned long)g_ipsecCrashStage, ipsecStageName(g_ipsecCrashStage), (unsigned long)g_ipsecCrashIkeState,
                 (unsigned long)g_ipsecCrashStackMin, (unsigned long)g_ipsecCrashMs);
        g_ipsecLastCrash = b;
        Serial.printf("[ipsec] %s\r\n", b);
    } else if (crash) {
        Serial.println(F("[ipsec] Reset durch Panic/WDT, aber IPsec war nicht am Zug (Marker 0)."));
    }
    g_ipsecCrashStage = 0; g_ipsecCrashIkeState = 0; g_ipsecCrashStackMin = 0xFFFFFFFFu; g_ipsecCrashMs = 0;
}
// Paketpuffer NICHT auf dem loop-Task-Stack (16 KB): RX-Datagramm, Klartext und Raw-ESP lagen bisher
// als 3 x 1600 B auf dem Stack -- zusaetzlich zu den 1500-B-Nachrichtenpuffern im WeirdIKE-Kern.
// Einziger Benutzer ist der loop-Task (supervise), daher statisch zulaessig.
static uint8_t s_rxBuf[1600];    // IKE-Socket / ESP-in-UDP Datagramm
static uint8_t s_rawBuf[1600];   // rohes Proto-50-Paket (inkl. IP-Header)
static uint8_t s_ptBuf[1600];    // entschluesseltes inneres Paket

// ---- WeirdIKE-Speichermodell auf dem P4 (Workspace-Refactor 2026-09-07) --------------------------
// Der Kern legt NICHTS Nachrichtengrosses mehr auf den Stack: kleiner, langlebiger Protokollzustand
// im Kontext, grosse Arbeitsbereiche (Transkript, Caches, RX/TX/Crypto-Scratch) im Workspace. Der
// Kern kennt kein PSRAM -- die Platzierung entscheidet DIESER Provider je Art:
//     CONTEXT   -> internes RAM (klein, heiss)          WORKSPACE -> PSRAM (gross)
// Groesse und Alignment kommen aus weirdike_mem_req(); Rueckfall fuer den Workspace = irgendein RAM.
static void* rt_mem_alloc(void*, size_t bytes, size_t align, weirdike_mem_kind_t kind) {
    if (align < 4) align = 4;
    uint32_t caps = (kind == WEIRDIKE_MEM_WORKSPACE) ? (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
                                                     : (MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    void* p = heap_caps_aligned_alloc(align, bytes, caps);
    if (!p && kind == WEIRDIKE_MEM_WORKSPACE) p = heap_caps_aligned_alloc(align, bytes, MALLOC_CAP_8BIT);
    return p;
}
static void rt_mem_free(void*, void* p, weirdike_mem_kind_t) { heap_caps_free(p); }
static const weirdike_mem_t g_ikeMem = { nullptr, rt_mem_alloc, rt_mem_free };
// ESP-Empfangs-Scratch je Session (aktuell + Vorgaenger waehrend des Rekey-Overlaps): host-platziert
// im PSRAM, der Klartext wird dort entschluesselt/geprueft und erst nach dem Replay-Commit kopiert.
static uint8_t* espScratch(int idx) {
    static uint8_t* s[2] = { nullptr, nullptr };
    if (idx < 0 || idx > 1) return nullptr;
    if (!s[idx]) {
        s[idx] = (uint8_t*)heap_caps_malloc(ESP_MAX_PACKET, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!s[idx]) s[idx] = (uint8_t*)malloc(ESP_MAX_PACKET);
    }
    return s[idx];
}

// ---- singleton runtime state (the transport C-callbacks reach it) ----------
namespace {

struct RtState {
    bool                 active = false;
    // crypto
    weirdike_mbedtls_ctx mc;
    weirdike_crypto_t    cr;
    // transport (we own the socket)
    weirdike_transport_t tr;
    int                  fd = -1;
    // ESP-Datenpfad OHNE NAT: rohes IP-Protokoll 50 (SOCK_RAW). Mit NAT laeuft ESP in UDP/4500 ueber
    // g.fd. Der P4 am Telekom-APN hat eine oeffentliche IP -> die Gegenstelle handelt kein NAT-T aus.
    int                  rawFd = -1;
    char                 bindIp[64] = {0};   // egress source IP (WLAN-STA/Modem)
    uint16_t             curPort = 0;        // 500, then 4500 after NAT-T switch
    uint8_t              peerIp[4] = {0};    // resolved gateway
    bool                 peerResolved = false;
    // core + esp
    weirdike_ctx        *ike = nullptr;
    esp_session_t        sess;
    bool                 espReady = false;
    // AP5 Rekey: waehrend der Ueberlappung bleibt die VORHERIGE Child-SA fuer den Empfang aktiv
    // (Pakete, die noch auf der alten SA unterwegs sind, gehen nicht verloren). Senden nur ueber sess.
    esp_session_t        sessPrev;
    bool                 prevReady = false;
    int                  sessIdx = 0;          // welcher der zwei ESP-Scratches gehoert zu sess (der andere zu sessPrev)
    uint32_t             childGen = 0;         // zuletzt installierte Child-SA-Generation (WeirdIKE)
    // PEER-Verhalten (nicht unsere Faehigkeit): die Gegenstelle hat einen PFS-Child-Rekey ohne D-H/KE
    // beantwortet -> Kern lehnt ab und baut kontrolliert neu auf. Wird ueber Neuverbindungen gehalten,
    // bis PFS abgeschaltet wird oder ein PFS-Rekey gelingt (HW-Befund FRITZ!Box 6860, 2026-09-07).
    bool                 peerPfsRejected = false;
    bool                 pfsWanted = false;    // PFS in der aktiven Konfiguration
    String               trustMode;            // Trust-Modell der aktiven Konfiguration (public|public-plus|own|none), leer = PSK
    // diagnostics (NO secrets)
    String               lastError;
    String               offer;             // ERLAUBTE Policy dieses Versuchs (Text, Diagnose)
    String               lastState;
    uint32_t             espTx = 0, espRx = 0, replayDrops = 0, icvErrors = 0;
    // raw UDP-Sicht (Debug): unterscheidet TX/RX/Parse. IKE_SA_INIT ist unverschluesselt -> ok.
    uint32_t             txPackets = 0, txBytes = 0, rxPackets = 0, rxBytes = 0;
    char                 lastRxFrom[24] = {0};
    uint16_t             lastRxLen = 0;
    uint8_t              lastRxHdr[64] = {0};   // genug fuer IKE-Header + kleine Notify-Payload
    uint16_t             lastRxHdrLen = 0;
    uint16_t             pingId = 0x4242;
    uint16_t             pingSeq = 0;
    // 8.2f: Konfigurationswerte fuer die Tunnel-Schnittstelle (leer = automatisch vom Gateway)
    String               cfgLocalTunnelIp;
    String               cfgRemoteSubnets;
} g;

// ---- 8.2f: ipsec0 -- der Tunnel als lwIP-Netzwerkschnittstelle ---------------------------------
// Ausgehend: lwIP ruft tunOutput() im tcpip-Thread mit dem fertigen IPv4-Paket; dort darf kein
// Socket-API laufen -> Paket in PSRAM kopieren, in eine Queue, der loop-Task (poll) verschluesselt
// (esp_session_seal) und sendet (UDP/4500 oder Proto 50). Eingehend: entschluesseltes inneres IPv4
// -> pbuf -> tcpip_input (thread-sicher). Routing: lwIP waehlt das netif ueber (Ziel & Maske) ==
// (IP & Maske) -> ipsec0 bekommt die Tunnel-IP und die Maske des gerouteten Netzes. Automatisch =
// das /24 der zugewiesenen Tunnel-IP, wenn das Gateway TSr nicht einschraenkt; nie eine Standardroute.
#define TUN_MTU      1400   // ESP-Overhead (IV/ICV/Padding/UDP) unter der PPP-MTU halten -> keine Fragmente
#define TUN_TXQ_LEN  64     // grosse Seite = Segment-Burst von lwIP; Queue muss den Burst puffern
#define TUN_TX_BATCH 64     // pro poll() die Queue moeglichst leeren (nicht nur 8) -> kein Ueberlauf
static struct netif   g_tun;
static bool           g_tunAdded = false, g_tunUp = false;
static QueueHandle_t  g_tunTxQ = nullptr;
static ip4_addr_t     g_tunIp, g_tunMask;
static uint32_t       g_tunTxPk = 0, g_tunRxPk = 0, g_tunDrop = 0;
static uint32_t       g_dropQ = 0, g_dropSeal = 0, g_dropSend = 0, g_dropMem = 0;   // tunDrop nach Ursache
static uint16_t       g_tunMaxLen = 0, g_sealErrLen = 0;   // groesstes inneres Paket / Groesse beim letzten seal-Fehler
static int            g_sealErrRc = 0;
static String         g_tunNote;   // warum keine/welche Route (Diagnose)
static uint8_t        g_tunAddrSrc = 0;   // Zonen 0.1: Herkunft der Tunnel-Adresse (1 konfiguriert, 2 CP, 3 TSi)
static int            g_tunMtuOverride = 0;   // Konsole: ipsec mtu <n> (Experiment, bis Neustart)

static err_t tunOutput(struct netif* nif, struct pbuf* p, const ip4_addr_t* dst) {
    (void)nif; (void)dst;
    if (!g_tunTxQ || !g_tunUp || p->tot_len > 1500) { g_tunDrop++; g_dropMem++; return ERR_IF; }
    uint8_t* buf = (uint8_t*)heap_caps_malloc(2 + p->tot_len, MALLOC_CAP_SPIRAM);
    if (!buf) buf = (uint8_t*)malloc(2 + p->tot_len);
    if (!buf) { g_tunDrop++; g_dropMem++; return ERR_MEM; }
    buf[0] = (uint8_t)(p->tot_len >> 8); buf[1] = (uint8_t)p->tot_len;
    pbuf_copy_partial(p, buf + 2, p->tot_len, 0);
    if (xQueueSend(g_tunTxQ, &buf, 0) != pdTRUE) { free(buf); g_tunDrop++; g_dropQ++; return ERR_WOULDBLOCK; }
    return ERR_OK;
}
static err_t tunInit(struct netif* nif) {
    nif->name[0] = 'i'; nif->name[1] = 'p';
    nif->output = tunOutput;
    nif->mtu = (u16_t)(g_tunMtuOverride ? g_tunMtuOverride : TUN_MTU);
    nif->flags = NETIF_FLAG_LINK_UP;      // Punkt-zu-Punkt: kein ARP, kein Broadcast
    nif->hwaddr_len = 0;
    return ERR_OK;
}
static void tunUp(const ip4_addr_t& ip, const ip4_addr_t& mask) {
    if (!g_tunTxQ) g_tunTxQ = xQueueCreate(TUN_TXQ_LEN, sizeof(uint8_t*));
    ip4_addr_t gw; ip4_addr_set_zero(&gw);
    LOCK_TCPIP_CORE();   // wie ec200a_ecm.cpp (Core-Locking im Core aus -> gleiche Vorgehensweise)
    if (!g_tunAdded) { netif_add(&g_tun, &ip, &mask, &gw, NULL, tunInit, tcpip_input); g_tunAdded = true; }
    else netif_set_addr(&g_tun, &ip, &mask, &gw);
    netif_set_up(&g_tun); netif_set_link_up(&g_tun);
    UNLOCK_TCPIP_CORE();
    g_tunIp = ip; g_tunMask = mask; g_tunUp = true;
}
static void tunDown() {
    if (g_tunAdded) { LOCK_TCPIP_CORE(); netif_set_link_down(&g_tun); netif_set_down(&g_tun); UNLOCK_TCPIP_CORE(); }
    g_tunUp = false;
    uint8_t* b; while (g_tunTxQ && xQueueReceive(g_tunTxQ, &b, 0) == pdTRUE) free(b);
}
static void tunDeliver(const uint8_t* ip, size_t len) {   // inneres IPv4 (Klartext) -> lwIP
    if (!g_tunUp) return;
    struct pbuf* p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
    if (!p) { g_tunDrop++; return; }
    pbuf_take(p, ip, (u16_t)len);
    if (g_tun.input(p, &g_tun) != ERR_OK) { pbuf_free(p); g_tunDrop++; return; }
    g_tunRxPk++;
}
// Prefix-Laenge aus einem zusammenhaengenden Bereich start..end (TSr), -1 wenn kein CIDR-Block.
static int rangePrefix(const uint8_t s[4], const uint8_t e[4]) {
    uint32_t a = ((uint32_t)s[0] << 24) | (s[1] << 16) | (s[2] << 8) | s[3];
    uint32_t b = ((uint32_t)e[0] << 24) | (e[1] << 16) | (e[2] << 8) | e[3];
    uint32_t x = a ^ b;
    if (x == 0xFFFFFFFFu) return 0;           // 0.0.0.0 .. 255.255.255.255 = /0
    int host = 0; while (host < 32 && ((x >> host) & 1u)) host++;
    if (host >= 32) return 0;
    if ((x >> host) != 0) return -1;          // kein reiner Suffix-Bereich
    if ((a & ((1u << host) - 1u)) != 0) return -1;
    return 32 - host;
}

// ---- P4-HW-AES-Umgehung: der Hardware-AES holt fuer grosse CBC-Bloecke DMA-Deskriptoren aus dem
//      internen Heap; unter Last (Kamera/H.264/Web) scheitert das mit -1 und verklemmt die Engine
//      (danach auch der CTR_DRBG-Zufall). Beweis: seal-Fehler bei 1400 UND danach bei 125 B; der
//      IKE-Handshake (System leer) laeuft. Loesung: der aes_cbc-Adapter rechnet in reiner SOFTWARE
//      (aes_soft), voellig ohne Hardware-Engine/DMA/Heap. Gilt fuer IKE + ESP (IKE ist low-volume).
static int rt_aes_cbc(void* ctx, int enc, const uint8_t* key, size_t klen, const uint8_t iv[16],
                      const uint8_t* in, size_t len, uint8_t* out) {
    (void)ctx;
    return aesEngineCbc(enc, key, klen, iv, in, len, out);   // Backend: HW-Block (Vorgabe) / Software
}
// Zufall aus dem echten Hardware-TRNG (esp_random) -- EIGENER Block, unabhaengig vom AES/der Krypto-
// DMA/dem Heap. Grund: der mbedTLS-CTR_DRBG erzeugt Zufall per Hardware-AES; unter Last scheitert der
// (wie aes_cbc) und esp_session_seal bricht am IV-Zufall ab (rc=-1) -- das war die eigentliche
// Restursache, die weder Software- noch Block-AES allein behob.
static int rt_random(void* ctx, uint8_t* out, size_t len) {
    (void)ctx;
    esp_fill_random(out, len);   // TRNG; laut IDF kryptografisch sicher, wenn RF/entropy laeuft (hier ja)
    return 0;
}
static void installAesInPlaceFix() {
    if (g.cr.aes_cbc == rt_aes_cbc && g.cr.random == rt_random) return;   // schon installiert (Reconnect)
    g.cr.aes_cbc = rt_aes_cbc;
    g.cr.random  = rt_random;
}

// bounded IKE log ring (last N lines) -- fed by weirdike via pf.log. NO secrets (the core never
// logs PSK/keys/plaintext; only state transitions + error/notify text).
#define RT_LOG_N 24
String   g_log[RT_LOG_N];
int      g_logHead = 0, g_logCount = 0;
static void rt_log(void *ctx, int level, const char *msg) {
    (void)ctx;
    g_log[g_logHead] = String("[") + level + "] " + (msg ? msg : "");
    g_logHead = (g_logHead + 1) % RT_LOG_N;
    if (g_logCount < RT_LOG_N) g_logCount++;
    // WEIRDIKE_LOG_ERROR (level 0) -> ins sichtbare "Fehler"-Feld spiegeln (z.B. peer error ...).
    if (level == 0 && msg) g.lastError = msg;
}

// ---- transport callbacks (BSD/lwIP sockets bound to the egress source IP) ----
static int t_open(void *c, uint16_t port) {
    (void)c;
    if (g.fd >= 0) { close(g.fd); g.fd = -1; }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port   = htons(port);
    a.sin_addr.s_addr = g.bindIp[0] ? inet_addr(g.bindIp) : htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); return -1; }
    g.fd = fd; g.curPort = port;
    return 0;
}
static int t_resolve(void *c, const char *host, weirdike_endpoint_t *out) {
    (void)c;
    memset(out, 0, sizeof(*out));
    struct in_addr ia;
    if (inet_pton(AF_INET, host, &ia) == 1) {
        memcpy(out->ip, &ia, 4);
    } else {
        // BOUNDED DNS: der Arduino-Resolver wartet auf den async lwIP-DNS mit internem Timeout
        // (Sekunden) statt des ~14 s BLOCKIERENDEN getaddrinfo(). Ohne funktionierendes WAN fror
        // der Autostart-connect() sonst bei JEDEM Versuch den loop()/Boot ein (Ursache bewiesen).
        IPAddress ip;
        // hostByName kann bei NXDOMAIN "true" mit 0.0.0.0 liefern (hardware-beobachtet: SA_INIT ging
        // sechsmal an 0.0.0.0). 0.0.0.0/255.255.255.255 sind nie ein Gateway -> klarer Fehler.
        if (!Network.hostByName(host, ip) || (uint32_t)ip == 0 || (uint32_t)ip == 0xFFFFFFFFu) {
            g.lastError = String("DNS: '") + host + "' nicht aufloesbar";
            return -1;
        }
        out->ip[0] = ip[0]; out->ip[1] = ip[1]; out->ip[2] = ip[2]; out->ip[3] = ip[3];
    }
    memcpy(g.peerIp, out->ip, 4); g.peerResolved = true;
    return 0;
}
static int t_local(void *c, weirdike_endpoint_t *out) {
    (void)c;
    memset(out, 0, sizeof(*out));
    if (!g.bindIp[0]) return -1;               // must be concrete, never 0.0.0.0 (NAT-D)
    struct in_addr ia;
    if (inet_pton(AF_INET, g.bindIp, &ia) != 1) return -1;
    memcpy(out->ip, &ia, 4);
    out->port = g.curPort;
    return 0;
}
static int t_send(void *c, const weirdike_endpoint_t *d, const uint8_t *b, size_t n) {
    (void)c;
    if (g.fd < 0) return -1;
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_port = htons(d->port); memcpy(&a.sin_addr, d->ip, 4);
    int ok = (sendto(g.fd, b, n, 0, (struct sockaddr *)&a, sizeof(a)) == (ssize_t)n) ? 0 : -1;
    if (ok == 0) { g.txPackets++; g.txBytes += (uint32_t)n; }
    return ok;
}
static void t_close(void *c) { (void)c; if (g.fd >= 0) { close(g.fd); g.fd = -1; } }

// ---- config helpers ---------------------------------------------------------
// EXPLIZIT, keine Inhaltserkennung: der Typ kommt aus der Konfiguration ("Senden als"/"Erwarten als").
// sourceip (eigene) / none (Server) = WeirdIKE ID NONE (IDi aus Quell-IP bzw. IDr des Servers
// akzeptieren). "auto" (Alt-Zustand) kommt hier nicht an -- validate() blockiert den Start.
static uint8_t idTypeOf(const String& t, const String& val) {
    (void)val;
    if (t == "ipv4")   return WEIRDIKE_ID_IPV4_ADDR;
    if (t == "fqdn")   return WEIRDIKE_ID_FQDN;
    if (t == "rfc822") return WEIRDIKE_ID_RFC822_ADDR;
    if (t == "keyid")  return WEIRDIKE_ID_KEY_ID;
    return WEIRDIKE_ID_NONE;   // sourceip / none / eapuser (NONE + EAP: der Core nimmt die EAP-Identity als IDi)
}
// Fill weirdike_id_t from (type,value). idbuf must outlive weirdike_new (deep-copied at init).
static void makeId(weirdike_id_t& id, uint8_t type, const String& val, uint8_t* idbuf, size_t cap, size_t& outlen) {
    outlen = 0; id.type = (weirdike_id_type_t)type; id.data = nullptr; id.len = 0;
    if (type == WEIRDIKE_ID_NONE) return;
    if (type == WEIRDIKE_ID_IPV4_ADDR) {
        struct in_addr ia;
        if (val.length() && inet_pton(AF_INET, val.c_str(), &ia) == 1 && cap >= 4) {
            memcpy(idbuf, &ia, 4); id.data = idbuf; id.len = 4; outlen = 4;
        }
        return;
    }
    size_t n = val.length(); if (n > cap) n = cap;
    memcpy(idbuf, val.c_str(), n); id.data = idbuf; id.len = n; outlen = n;
}
// Parse "a.b.c.d/prefix" (or single IP => /32) into a TS IPv4 range. Empty => any.
static void parseTs(weirdike_ts_t& ts, const String& cidr) {
    memset(&ts, 0, sizeof(ts));
    ts.address_family = 4; ts.ip_protocol = 0; ts.start_port = 0; ts.end_port = 0xFFFF;
    String s = cidr; s.trim();
    if (s.length() == 0) { memset(ts.end_addr, 0xFF, 4); return; }   // any
    int slash = s.indexOf('/');
    String ipp = (slash < 0) ? s : s.substring(0, slash);
    int prefix = (slash < 0) ? 32 : s.substring(slash + 1).toInt();
    if (prefix < 0) prefix = 0; if (prefix > 32) prefix = 32;
    struct in_addr ia;
    if (inet_pton(AF_INET, ipp.c_str(), &ia) != 1) { memset(ts.end_addr, 0xFF, 4); return; }
    uint32_t ip = ntohl(ia.s_addr);
    uint32_t mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
    uint32_t start = ip & mask, end = ip | ~mask;
    ts.start_addr[0] = start >> 24; ts.start_addr[1] = start >> 16; ts.start_addr[2] = start >> 8; ts.start_addr[3] = start;
    ts.end_addr[0]   = end   >> 24; ts.end_addr[1]   = end   >> 16; ts.end_addr[2]   = end   >> 8; ts.end_addr[3]   = end;
}

// ---- inner ICMP (for testPing) ---------------------------------------------
static uint16_t inCksum(const uint8_t *d, size_t len) {
    uint32_t s = 0; for (size_t i = 0; i + 1 < len; i += 2) s += ((uint32_t)d[i] << 8) | d[i + 1];
    if (len & 1) s += (uint32_t)d[len - 1] << 8; while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)(~s & 0xffff);
}
static size_t buildIcmp(uint8_t *buf, const char *src, const char *dst, int reply,
                        uint16_t id, uint16_t seq, const uint8_t *pl, size_t pll) {
    uint8_t *ip = buf, *ic = buf + 20; size_t icl = 8 + pll, tot = 20 + icl;
    ic[0] = reply ? 0 : 8; ic[1] = 0; ic[2] = 0; ic[3] = 0;
    ic[4] = id >> 8; ic[5] = id; ic[6] = seq >> 8; ic[7] = seq;
    if (pll) memcpy(ic + 8, pl, pll);
    uint16_t c = inCksum(ic, icl); ic[2] = c >> 8; ic[3] = c;
    ip[0] = 0x45; ip[1] = 0; ip[2] = tot >> 8; ip[3] = tot; ip[4] = 0; ip[5] = 0; ip[6] = 0x40; ip[7] = 0;
    ip[8] = 64; ip[9] = 1; ip[10] = 0; ip[11] = 0;
    inet_pton(AF_INET, src, ip + 12); inet_pton(AF_INET, dst, ip + 16);
    uint16_t icc = inCksum(ip, 20); ip[10] = icc >> 8; ip[11] = icc;
    return tot;
}

} // namespace

// ---- lifecycle -------------------------------------------------------------
// ---- Proposal policy: WeirdOS settings (ipsec_crypto_caps ids, CSV) -> typed WeirdIKE policy ----
// One LANCOM "IKE hash" tick = one PRF AND one INTEG entry (independent allow-lists, so several ticks
// also allow the cross combinations). Returns "" or an error text (unknown id / empty list /
// too many entries) -- the caller refuses to start on error (no silent default).
static String buildPolicy(const IpsecConfig& cfg, weirdike_ike_policy_t& ike, weirdike_child_policy_t& child) {
    memset(&ike, 0, sizeof(ike)); memset(&child, 0, sizeof(child));
    const IpsecAlgo* rows[WEIRDIKE_POLICY_MAX];
    String bad; int n;

    n = ipsecAlgoResolve(IpsecAlgoGroup::IkeEnc, cfg.ikeEnc, rows, WEIRDIKE_POLICY_MAX, bad);
    if (n < 0) return "unbekannte IKE-SA-Verschluesselung '" + bad + "'";
    if (n == 0) return "keine IKE-SA-Verschluesselung gewaehlt";
    for (int i = 0; i < n; i++) { ike.encr[i].id = rows[i]->iana; ike.encr[i].key_bits = rows[i]->keyBits; }
    ike.n_encr = (size_t)n;

    n = ipsecAlgoResolve(IpsecAlgoGroup::IkeHash, cfg.ikeHash, rows, WEIRDIKE_POLICY_MAX, bad);
    if (n < 0) return "unbekannter IKE-SA-Hash '" + bad + "'";
    if (n == 0) return "kein IKE-SA-Hash gewaehlt";
    for (int i = 0; i < n; i++) { ike.prf[i] = rows[i]->iana; ike.integ[i] = rows[i]->iana2; }
    ike.n_prf = ike.n_integ = (size_t)n;

    n = ipsecAlgoResolve(IpsecAlgoGroup::Dh, cfg.ikeDh, rows, WEIRDIKE_POLICY_MAX, bad);
    if (n < 0) return "unbekannte DH-Gruppe '" + bad + "'";
    if (n == 0) return "keine DH-Gruppe gewaehlt";
    // B1: mehrere Gruppen = Alternativen im Angebot; der KE geht fuer die kleinste erlaubte Gruppe raus,
    // verlangt das Gateway eine andere (INVALID_KE_PAYLOAD), sendet WeirdIKE SA_INIT damit erneut (CI: dhmulti).
    for (int i = 0; i < n; i++) ike.dh[i] = rows[i]->iana;
    ike.n_dh = (size_t)n;

    n = ipsecAlgoResolve(IpsecAlgoGroup::EspEnc, cfg.espEnc, rows, WEIRDIKE_POLICY_MAX, bad);
    if (n < 0) return "unbekannte Child-SA-Verschluesselung '" + bad + "'";
    if (n == 0) return "keine Child-SA-Verschluesselung gewaehlt";
    for (int i = 0; i < n; i++) { child.encr[i].id = rows[i]->iana; child.encr[i].key_bits = rows[i]->keyBits; }
    child.n_encr = (size_t)n;

    n = ipsecAlgoResolve(IpsecAlgoGroup::EspHash, cfg.espHash, rows, WEIRDIKE_POLICY_MAX, bad);
    if (n < 0) return "unbekannter Child-SA-Hash '" + bad + "'";
    if (n == 0) return "kein Child-SA-Hash gewaehlt";
    for (int i = 0; i < n; i++) child.integ[i] = rows[i]->iana;
    child.n_integ = (size_t)n;

    if (cfg.pfs && !ipsecPfsSupported()) return "PFS ist in dieser WeirdIKE-Version nicht verfuegbar";
    return "";
}

// Human-readable "allowed" text of a policy (Diagnose > Angebotenes Proposal). Alternatives in {a|b}.
static String policyText(const weirdike_ike_policy_t& ike, const weirdike_child_policy_t& child) {
    auto join = [](const String* v, size_t n) { String s; for (size_t i = 0; i < n; i++) { if (i) s += "|"; s += v[i]; } return n > 1 ? "{" + s + "}" : s; };
    String enc[WEIRDIKE_POLICY_MAX], prf[WEIRDIKE_POLICY_MAX], ig[WEIRDIKE_POLICY_MAX], dh[WEIRDIKE_POLICY_MAX];
    for (size_t i = 0; i < ike.n_encr;  i++) enc[i] = ipsecEncrName(ike.encr[i].id, ike.encr[i].key_bits);
    for (size_t i = 0; i < ike.n_prf;   i++) prf[i] = ipsecPrfName(ike.prf[i]);
    for (size_t i = 0; i < ike.n_integ; i++) ig[i]  = ipsecIntegName(ike.integ[i]);
    for (size_t i = 0; i < ike.n_dh;    i++) dh[i]  = ipsecDhName(ike.dh[i]);
    String s = "IKE " + join(enc, ike.n_encr) + " / " + join(prf, ike.n_prf) + " / " + join(ig, ike.n_integ) + " / " + join(dh, ike.n_dh);
    String cenc[WEIRDIKE_POLICY_MAX], cig[WEIRDIKE_POLICY_MAX];
    for (size_t i = 0; i < child.n_encr;  i++) cenc[i] = ipsecEncrName(child.encr[i].id, child.encr[i].key_bits);
    for (size_t i = 0; i < child.n_integ; i++) cig[i]  = ipsecIntegName(child.integ[i]);
    s += " ; ESP " + join(cenc, child.n_encr) + " / " + join(cig, child.n_integ) + " / NO_ESN";
    return s;
}

// Negotiated suites (from weirdike_get_diag, no secrets) as text. "" when not (yet) negotiated.
static String ikeSuiteText(const weirdike_diag_t& d) {
    if (!d.have_ike_suite) return "";
    return ipsecEncrName(d.ike_encr, d.ike_encr_key_bits) + "/" + ipsecPrfName(d.ike_prf) + "/" +
           ipsecIntegName(d.ike_integ) + "/" + ipsecDhName(d.ike_dh);
}
static String childSuiteText(const weirdike_diag_t& d) {
    if (!d.child_sa_ok) return "";
    return ipsecEncrName(d.child_encr, d.child_encr_key_bits) + "/" + ipsecIntegName(d.child_integ);
}

String IpsecRuntime::start(const IpsecConfig& cfg, const String& psk, const String& eapPass) {
    stop();
    ipsecStage(1, 0);
    // 1) egress -> concrete source IP (bind), same mechanism as WAN-bound HTTPS
    NetIface ifc;
    if (!egressResolve(cfg.underlay, ifc) || ifc.ip.length() == 0) {
        g.lastError = "Underlay '" + cfg.underlay + "' nicht verfuegbar (kein up-Interface mit IP)";
        return g.lastError;
    }
    strncpy(g.bindIp, ifc.ip.c_str(), sizeof(g.bindIp) - 1); g.bindIp[sizeof(g.bindIp) - 1] = 0;

    // 2) crypto (ESP-IDF mbedTLS)
    ipsecStage(2);
    if (weirdike_crypto_mbedtls_init(&g.mc) != 0) { g.lastError = "Crypto/DRBG init fehlgeschlagen"; return g.lastError; }
    weirdike_crypto_mbedtls_bind(&g.mc, &g.cr);
    installAesInPlaceFix();   // P4-HW-AES scheitert unter Last -> ESP+IKE nutzen Software-AES (aes_soft)

    // 3) transport: we own the socket; core does external RX (recv=NULL) -> we demux in poll()
    memset(&g.tr, 0, sizeof(g.tr));
    g.tr.open = t_open; g.tr.resolve = t_resolve; g.tr.local_endpoint = t_local;
    g.tr.send = t_send; g.tr.close = t_close; g.tr.recv = nullptr;

    // 4) config mapping
    static String host; host = cfg.serverHost;      // stable during weirdike_new (deep-copied)
    static uint8_t liBuf[256], riBuf[256];
    size_t liLen = 0, riLen = 0;
    weirdike_config_t wc; memset(&wc, 0, sizeof(wc));
    wc.server_host = host.c_str();
    wc.server_port = cfg.serverPort ? cfg.serverPort : 500;
    // Authentifizierung: PSK oder Benutzer+Passwort (EAP-MSCHAPv2, AP7/AP8). Bei EAP weist sich der
    // Server ZUERST mit einem Zertifikat aus (RFC 7296 2.16); OB ihm vertraut wird, entscheidet das
    // Trust-Modell (cfg.trustMode -> weirdike_trust_mode_t): eigene Anker (caPem), Host-Truststore
    // (ESP-IDF-Bundle, ipsec_trust_store) mit/ohne Zusatz (caPem = Zusatz-Anker, extraPem = Ketten-
    // material) oder bewusst keine Vertrauenspruefung. Die IKE-AUTH-Signatur prueft der Core immer.
    static String eapUser, eapPw, caPem, extraPem;   // stabil waehrend weirdike_new (deep-copied); eapPw danach geloescht
    if (cfg.auth == "eap") {
        eapUser = cfg.eapUser; eapPw = eapPass; caPem = cfg.caPem; extraPem = cfg.extraPem;
        wc.auth = WEIRDIKE_AUTH_EAP_MSCHAPV2;
        wc.eap_identity = (const uint8_t *)eapUser.c_str(); wc.eap_identity_len = eapUser.length();
        wc.eap_password = (const uint8_t *)eapPw.c_str();   wc.eap_password_len = eapPw.length();
        wc.trust_mode = ipsecTrustModeId(cfg.trustMode);
        wc.ca_pem    = caPem.length()    ? caPem.c_str()    : nullptr; wc.ca_pem_len    = caPem.length();
        wc.extra_pem = extraPem.length() ? extraPem.c_str() : nullptr; wc.extra_pem_len = extraPem.length();
        // Host-Truststore nur anhaengen, wenn das Modell ihn nutzt. Fehlt er, bleibt er weg und der
        // Core lehnt den Start ehrlich ab ("no fallback") statt still auf die PEM-Anker zu wechseln.
        weirdike_mbedtls_host_store_t hs;
        bool wantHost = wc.trust_mode == (int)WEIRDIKE_TRUST_HOST_STORE || wc.trust_mode == (int)WEIRDIKE_TRUST_HOST_STORE_PLUS_PEM;
        if (wantHost && ipsecHostTrustStore(hs)) weirdike_crypto_mbedtls_set_host_store(&g.mc, &hs);
        else weirdike_crypto_mbedtls_set_host_store(&g.mc, nullptr);
        g.trustMode = cfg.trustMode;
        rt_log(nullptr, 1, (String("ipsec: Trust-Modell: ") + ipsecTrustModeLabel(cfg.trustMode)
                            + (wantHost ? (g.mc.has_host ? " [Host-Truststore verfuegbar]" : " [Host-Truststore NICHT verfuegbar -> Start wird abgelehnt]") : "")).c_str());
    } else {
        wc.auth = WEIRDIKE_AUTH_PSK;
        wc.psk = (const uint8_t *)psk.c_str(); wc.psk_len = psk.length();
    }
    // AP6: leere Tunnel-IP = automatisch vom Gateway beziehen (IKEv2 Configuration Payload).
    { String t = cfg.localTunnelIp; t.trim(); wc.request_cp = t.length() ? 0 : 1; }
    wc.enable_nat_t = cfg.natT ? 1 : 0;
    makeId(wc.local_id,  idTypeOf(cfg.localIdType,  cfg.localId),  cfg.localId,  liBuf, sizeof(liBuf), liLen);
    makeId(wc.remote_id, idTypeOf(cfg.remoteIdType, cfg.remoteId), cfg.remoteId, riBuf, sizeof(riBuf), riLen);
    parseTs(wc.local_ts,  cfg.localTunnelIp);        // TSi: our tunnel address (/32) or any
    // E2: mehrere Zielnetze (CSV) -> erstes = remote_ts, weitere (bis 3) = remote_ts_extra (ein TSr-Payload
    // mit mehreren Selektoren, RFC 7296 3.13). Vorher wurde die ganze CSV als EIN Netz gelesen und damit
    // still zu 0.0.0.0/0. Geroutet wird auf ipsec0 weiterhin nur das erste Netz (siehe tunConfigure).
    {
        String rs = cfg.remoteSubnets; rs.trim();
        int c = rs.indexOf(','); String first = (c < 0) ? rs : rs.substring(0, c); first.trim();
        parseTs(wc.remote_ts, first);                // TSr #1
        wc.n_remote_ts_extra = 0;
        String rest = (c < 0) ? String("") : rs.substring(c + 1);
        while (rest.length() && wc.n_remote_ts_extra < WEIRDIKE_TS_MAX - 1) {
            int c2 = rest.indexOf(','); String one = (c2 < 0) ? rest : rest.substring(0, c2); one.trim();
            rest = (c2 < 0) ? String("") : rest.substring(c2 + 1);
            if (!one.length()) continue;
            parseTs(wc.remote_ts_extra[wc.n_remote_ts_extra], one);
            wc.n_remote_ts_extra++;
        }
    }
    g.cfgLocalTunnelIp = cfg.localTunnelIp; g.cfgRemoteSubnets = cfg.remoteSubnets;   // fuer ipsec0 (8.2f)
    g_tunNote = ""; g_tunTxPk = g_tunRxPk = g_tunDrop = 0;

    // 4b) proposal policy: the LANCOM-style allow-lists the user SAVED (ipsec_crypto_caps ids) ->
    //     typed WeirdIKE policy (IANA ids). NEVER NULL here (NULL would be the WeirdIKE default and
    //     silently ignore the settings) and NO fallback: an untranslatable or unrunnable policy is
    //     an error the user sees. Static storage: weirdike_new deep-copies, but keep it simple.
    static weirdike_ike_policy_t   ikePol;
    static weirdike_child_policy_t childPol;
    {
        String perr = buildPolicy(cfg, ikePol, childPol);
        if (perr.length()) { g.lastError = "IKEv2-Richtlinie: " + perr; return g.lastError; }
        int pc = weirdike_policy_check(&ikePol, &childPol);
        if (pc != 0) {
            static const char* lists[] = { "?", "IKE-SA-Verschluesselung", "IKE-SA-PRF", "IKE-SA-Integritaet", "DH-Gruppe",
                                           "Child-SA-Verschluesselung", "Child-SA-Integritaet" };
            g.lastError = String("IKEv2-Richtlinie: ") + lists[(pc >= -6 && pc <= -1) ? -pc : 0]
                        + " enthaelt etwas, das diese WeirdIKE-Version nicht ausfuehren kann (Code " + String(pc) + ")";
            return g.lastError;
        }
        wc.ike_policy   = &ikePol;
        wc.child_policy = &childPol;
        // AP5: PFS = Child-Rekey mit neuem D-H (die gewaehlte IKE-Gruppe); Lifetime-Vorgabe von WeirdIKE (55 min).
        wc.pfs_group = (cfg.pfs && ipsecPfsSupported()) ? ikePol.dh[0] : 0;
        // C1/C2/D: Lebensdauern + Liveness aus der Konfiguration (0 = WeirdIKE-Vorgabe)
        wc.ike_lifetime_s   = cfg.ikeLifetimeS;
        wc.child_lifetime_s = cfg.childLifetimeS;
        wc.child_lifetime_kb= (uint32_t)cfg.childLifetimeMb * 1024u;
        wc.dpd_disable      = cfg.dpd ? 0 : 1;
        wc.dpd_interval_s   = cfg.dpdIntervalS;
        wc.dpd_retries      = cfg.dpdRetries;
        wc.natt_keepalive_s = cfg.nattKeepaliveS;
        g.pfsWanted = wc.pfs_group != 0;
        if (!g.pfsWanted) g.peerPfsRejected = false;   // Befund gilt nur, solange PFS verlangt wird
        g.offer = policyText(ikePol, childPol) + (wc.pfs_group ? " PFS" : "");   // "erlaubt" (Diagnose)
    }

    static weirdike_platform_t pf; memset(&pf, 0, sizeof(pf));   // stdlib alloc
    pf.log = rt_log;   // IKE state/notify/error -> bounded ring (diagJson), keine Secrets
    // IKE-Log NICHT loeschen: nach einem kontrollierten Neuaufbau (z.B. abgelehnte Rekey-Antwort) muss
    // die Diagnose des VORHERIGEN Versuchs sichtbar bleiben. Nur ein Trenner je Verbindungsversuch.
    rt_log(nullptr, 1, "--- neuer Verbindungsversuch ---");

    ipsecStage(3);
    g.ike = weirdike_new(&wc, &g.cr, &g.tr, &pf, &g_ikeMem);   // Kontext intern, Workspace PSRAM
    // Passwort nur waehrend weirdike_new (deep-copy) im Speicher halten.
    for (size_t i = 0; i < eapPw.length(); i++) eapPw.setCharAt(i, 0);
    eapPw = "";
    if (!g.ike) { weirdike_crypto_mbedtls_free(&g.mc); g.lastError = (cfg.auth == "eap")
        ? "weirdike_new fehlgeschlagen (EAP: Benutzer/Passwort pruefen; Trust-Modell 'Eigener Vertrauensanker' braucht ein Anker-PEM)" : "weirdike_new fehlgeschlagen (Config?)"; return g.lastError; }
    // Reset VOR weirdike_start(): start() sendet bereits das erste SA_INIT ueber t_send -> darf nicht
    // hinterher auf 0 geloescht werden (sonst verschwindet TX#1 aus den Zaehlern).
    g.espReady = false; g.lastError = "";
    g.espTx = g.espRx = g.replayDrops = g.icvErrors = 0;
    g.txPackets = g.txBytes = g.rxPackets = g.rxBytes = 0; g.lastRxLen = 0; g.lastRxHdrLen = 0; g.lastRxFrom[0] = 0;
    ipsecStage(4);
    if (weirdike_start(g.ike, millis()) != 0) {
        // Ein Adapter (z.B. t_resolve: DNS) hat ggf. schon einen konkreten Grund hinterlegt -> behalten.
        if (!g.lastError.length())
            g.lastError = String("weirdike_start fehlgeschlagen (") + weirdike_state_str(weirdike_state(g.ike)) + ")";
        weirdike_free(g.ike); g.ike = nullptr; weirdike_crypto_mbedtls_free(&g.mc); return g.lastError;
    }
    g.active = true;
    ipsecStage(5, (uint32_t)weirdike_state(g.ike));
    return "";
}

static void ikeDrainSocket();   // definiert bei poll() (Socket-Demux), hier fuer den gebundenen DELETE-Wait
// Graceful (AP4.8): bei stehender IKE-SA einen verschluesselten DELETE senden und GEBUNDEN auf die
// Antwort warten (typisch < 100 ms; Deckel 1,5 s, damit die UI nie haengt). Danach in jedem Fall
// lokal sauber schliessen. Laeuft im loop-Task (supervise), der einzige Besitzer der Runtime.
void IpsecRuntime::stop() {
    if (g.active || g.ike) ipsecStage(30);
    tunDown();
    if (g.espReady) { esp_session_deinit(&g.sess); g.espReady = false; }
    if (g.ike) {
        weirdike_state_t st = weirdike_state(g.ike);
        if (st == WEIRDIKE_STATE_ESTABLISHED || st == WEIRDIKE_STATE_CHILD_ESTABLISHED) {
            ipsecStage(31, (uint32_t)st);
            if (weirdike_disconnect(g.ike, millis()) == 0) {
                uint32_t t0 = millis();
                while (weirdike_state(g.ike) != WEIRDIKE_STATE_CLOSED && millis() - t0 < 1500) {
                    ikeDrainSocket();
                    weirdike_poll(g.ike, millis());
                    delay(10);
                }
                Serial.printf("[ipsec] DELETE %s (%lu ms)\r\n",
                              weirdike_state(g.ike) == WEIRDIKE_STATE_CLOSED ? "bestaetigt" : "ohne Antwort -> lokal geschlossen",
                              (unsigned long)(millis() - t0));
            }
        }
    }
    if (g.ike) { ipsecStage(32); weirdike_free(g.ike); g.ike = nullptr; weirdike_crypto_mbedtls_free(&g.mc); }
    if (g.fd >= 0) { close(g.fd); g.fd = -1; }
    if (g.rawFd >= 0) { close(g.rawFd); g.rawFd = -1; }
    if (g.active) ipsecStage(33);
    g.active = false; g.curPort = 0; g.peerResolved = false;
}

// ---- ESP-Transport: UDP/4500 (NAT-T) oder rohes IP-Proto 50 (kein NAT) ---------------------------
static bool espUsesUdp() { return g.curPort == 4500; }
static bool espOpenRaw() {
    if (g.rawFd >= 0) return true;
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ESP);
    if (fd < 0) { g.lastError = String("ESP: SOCK_RAW(50) nicht verfuegbar (errno ") + errno + ")"; return false; }
    struct sockaddr_in a; memset(&a, 0, sizeof(a)); a.sin_family = AF_INET;
    a.sin_addr.s_addr = g.bindIp[0] ? inet_addr(g.bindIp) : htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); g.lastError = "ESP: bind SOCK_RAW fehlgeschlagen"; return false; }
    int fl = fcntl(fd, F_GETFL, 0); if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    g.rawFd = fd;
    return true;
}
static int      g_espSendErrno = 0;   // letzter Sendefehler (Diagnose: tunDrop-Ursache)
static uint16_t g_espSendErrLen = 0;  // Groesse des Pakets, das nicht rausging
static bool espSend(const uint8_t* esp, size_t len) {
    struct sockaddr_in dst; memset(&dst, 0, sizeof(dst)); dst.sin_family = AF_INET; memcpy(&dst.sin_addr, g.peerIp, 4);
    int fd; if (espUsesUdp()) { dst.sin_port = htons(4500); fd = g.fd; } else { if (!espOpenRaw()) return false; fd = g.rawFd; }
    ssize_t s = sendto(fd, esp, len, 0, (struct sockaddr *)&dst, sizeof(dst));   // raw: lwIP setzt den IP-Header
    if (s == (ssize_t)len) return true;
    g_espSendErrno = errno; g_espSendErrLen = (uint16_t)len;   // z.B. ENOMEM (Pbuf) / EMSGSIZE (zu gross)
    return false;
}
// Ein rohes Proto-50-Paket lesen: liefert Offset des ESP-Headers hinter dem IP-Header, 0 = nichts.
static ssize_t espRecvRaw(uint8_t* buf, size_t cap, size_t& off) {
    if (g.rawFd < 0) return 0;
    struct sockaddr_in from; socklen_t fl = sizeof(from);
    ssize_t n = recvfrom(g.rawFd, buf, cap, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
    if (n < 20) return 0;
    size_t ihl = (size_t)(buf[0] & 0x0F) * 4;
    if (ihl < 20 || buf[9] != IPPROTO_ESP || (size_t)n <= ihl) return 0;
    if (memcmp(&from.sin_addr, g.peerIp, 4) != 0) return 0;   // nur vom Gateway
    off = ihl;
    return n;
}
static void espDeliver(const uint8_t* esp, size_t len) {
    uint8_t* pt = s_ptBuf; size_t ptl = 0; uint8_t nh = 0;
    ipsecStage(20);
    // AP5: nach einem Rekey laufen kurz ZWEI eingehende SAs -- per SPI die passende Session waehlen
    // (esp_session_open lehnt eine fremde SPI billig vor der Krypto ab).
    esp_session_t* s = &g.sess;
    if (g.prevReady) {
        uint32_t spi = 0, seq = 0;
        if (esp_peek_header(esp, len, &spi, &seq) == 0 && spi == g.sessPrev.inbound_spi) s = &g.sessPrev;
    }
    if (esp_session_open(s, esp, len, &nh, pt, sizeof(s_ptBuf), &ptl) == 0) {
        g.espRx++;
        if (g.ike) weirdike_child_traffic(g.ike, (uint32_t)len);   // C2: Byte-Lifetime der Child-SA (RX)
        ipsecStage(21);
        if (nh == ESP_NH_IPV4) tunDeliver(pt, ptl);   // 8.2f: inneres Paket in den lwIP-Stack
    } else g.replayDrops++;   // dup/old/ICV
}
// loop-Task: von lwIP eingereihte Tunnel-Pakete verschluesseln + senden.
// ESP-Ausgabepuffer im DMA-faehigen INTERNEN RAM (nicht auf dem Task-Stack!): der HW-AES des P4
// verschluesselt grosse Bloecke ueber die Krypto-GDMA; ein Stack-/PSRAM-Puffer ist fuer diese DMA
// nicht erreichbar -> mbedtls_aes gibt -1 (nur bei GROSSEN Paketen; kleine laufen ueber die CPU) und
// verklemmt dabei die AES-Engine, sodass danach auch der CTR_DRBG-Zufall scheitert. Ein einmal
// reservierter, 16-Byte-ausgerichteter DMA-Puffer behebt beides. Payload wird von esp_seal hinein
// kopiert und in-place verschluesselt -> Quelle darf im PSRAM liegen.
static uint8_t* g_espBuf = nullptr;
static uint8_t* espOutBuf() {
    if (!g_espBuf) g_espBuf = (uint8_t*)heap_caps_aligned_alloc(16, 1600, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
    return g_espBuf;
}
static void tunPumpTx() {
    if (!g_tunTxQ || !g.espReady) return;
    uint8_t* esp = espOutBuf();
    if (!esp) return;
    ipsecStage(16);
    uint8_t* b;
    for (int i = 0; i < TUN_TX_BATCH && xQueueReceive(g_tunTxQ, &b, 0) == pdTRUE; i++) {
        size_t len = ((size_t)b[0] << 8) | b[1];
        size_t espLen = 0;
        if (len > g_tunMaxLen) g_tunMaxLen = (uint16_t)len;
        int sc = esp_session_seal(&g.sess, ESP_NH_IPV4, b + 2, len, esp, 1600, &espLen);
        if (sc != 0) {
            g_tunDrop++; g_dropSeal++; g_sealErrLen = (uint16_t)len; g_sealErrRc = sc;
            if (g_dropSeal <= 3)   // die ersten Faelle auf die Konsole: Groesse + Protokoll + TCP-Ports
                Serial.printf("[ipsec] seal-FEHLER rc=%d len=%u proto=%u %s\r\n", sc, (unsigned)len, (unsigned)b[2 + 9],
                              (len >= 2 + 24 && b[2 + 9] == 6) ? (String("tcp ") + (((unsigned)b[2 + 20] << 8) | b[2 + 21]) + "->" + (((unsigned)b[2 + 22] << 8) | b[2 + 23])).c_str() : "");
        }
        else if (!espSend(esp, espLen)) { g_tunDrop++; g_dropSend++; }
        else                      { g.espTx++; g_tunTxPk++; if (g.ike) weirdike_child_traffic(g.ike, (uint32_t)espLen); }   // C2: Byte-Lifetime (TX)
        free(b);
    }
}
// Tunnel-Schnittstelle nach CHILD_ESTABLISHED hochfahren: Adresse = vom Gateway eingeschraenktes TSi
// (Host) oder konfigurierte Tunnel-IP; Route = konfigurierte Netze, sonst vom Gateway eingeschraenktes
// TSr, sonst automatisch das /24 der Tunnel-IP. NIE 0.0.0.0/0 (keine Standardroute durch den Tunnel).
static void tunBringUp() {
    weirdike_child_sa_t ch;
    ipsecStage(14);
    if (!g.ike || weirdike_get_child_sa(g.ike, &ch) != 0) return;
    ip4_addr_t ip; bool haveIp = false; String ipSrc;
    // AP6: vom Gateway ZUGEWIESENE Adresse (Configuration Payload) hat Vorrang -- das ist die
    // tatsaechlich ausgehandelte Tunnel-IP, nicht der konfigurierte Wunsch.
    weirdike_cp_t cp; bool haveCp = (weirdike_get_cp(g.ike, &cp) == 0);
    if (haveCp && cp.have_address) {
        IP4_ADDR(&ip, cp.address[0], cp.address[1], cp.address[2], cp.address[3]);
        haveIp = !ip4_addr_isany_val(ip); if (haveIp) ipSrc = "vom Gateway zugewiesen (CP)";
    }
    if (!haveIp && ch.local_ts.address_family == 4 && memcmp(ch.local_ts.start_addr, ch.local_ts.end_addr, 4) == 0) {
        IP4_ADDR(&ip, ch.local_ts.start_addr[0], ch.local_ts.start_addr[1], ch.local_ts.start_addr[2], ch.local_ts.start_addr[3]);
        haveIp = !ip4_addr_isany_val(ip); if (haveIp) ipSrc = "TSi";
    }
    if (!haveIp && g.cfgLocalTunnelIp.length()) { haveIp = ip4addr_aton(g.cfgLocalTunnelIp.c_str(), &ip) != 0; if (haveIp) ipSrc = "konfiguriert"; }
    ip4_addr_t mask; int prefix = -1; String src;
    String rs = g.cfgRemoteSubnets; rs.trim();
    // AP6: vom Gateway gemeldetes INTERNAL_IP4_SUBNET (erstes) = erreichbares Netz, wenn nichts konfiguriert.
    if (haveCp && cp.subnet_count > 0 && (rs.length() == 0 || rs == "0.0.0.0/0")) {
        uint32_t m = ((uint32_t)cp.subnet_mask[0][0] << 24) | ((uint32_t)cp.subnet_mask[0][1] << 16) | ((uint32_t)cp.subnet_mask[0][2] << 8) | cp.subnet_mask[0][3];
        int p = 0; while (p < 32 && (m & (0x80000000u >> p))) p++;
        char sb[24]; snprintf(sb, sizeof(sb), "%u.%u.%u.%u/%d", cp.subnet[0][0], cp.subnet[0][1], cp.subnet[0][2], cp.subnet[0][3], p);
        rs = sb;
    }
    if (rs.length()) {   // erstes konfiguriertes Netz (nur EIN Netz je Schnittstelle in diesem Stand)
        int c = rs.indexOf(','); String one = (c < 0) ? rs : rs.substring(0, c); one.trim();
        int sl = one.indexOf('/'); ip4_addr_t n;
        if (sl > 0 && ip4addr_aton(one.substring(0, sl).c_str(), &n)) { prefix = one.substring(sl + 1).toInt(); src = "konfiguriert " + one; }
    }
    if (prefix < 0 && ch.remote_ts.address_family == 4) {
        int p = rangePrefix(ch.remote_ts.start_addr, ch.remote_ts.end_addr);
        if (p > 0) { prefix = p; src = "vom Gateway (TSr)"; }   // p == 0 waere 0.0.0.0/0 -> nicht als Route
    }
    // F: vom Gateway gemeldete Netzmaske (INTERNAL_IP4_NETMASK) vor dem /24-Rateversuch
    if (prefix <= 0 && haveCp && cp.have_netmask) {
        uint32_t m = ((uint32_t)cp.netmask[0] << 24) | ((uint32_t)cp.netmask[1] << 16) | ((uint32_t)cp.netmask[2] << 8) | cp.netmask[3];
        int p = 0; while (p < 32 && (m & (0x80000000u >> p))) p++;
        if (p > 0 && p < 32) { prefix = p; src = "vom Gateway (CP-Netzmaske)"; }
    }
    if (prefix <= 0 && haveIp) { prefix = 24; src = "automatisch: /24 der Tunnel-IP"; }
    memset(&ch, 0, sizeof(ch));
    if (!haveIp) { g_tunNote = "keine Tunnel-Adresse (Gateway schraenkt TSi nicht ein, keine Tunnel-IP konfiguriert)"; return; }
    if (prefix <= 0 || prefix > 32) { g_tunNote = "kein routbares Netz"; return; }
    ip4_addr_set_u32(&mask, lwip_htonl(prefix == 32 ? 0xFFFFFFFFu : ~((1u << (32 - prefix)) - 1u)));
    tunUp(ip, mask);
    g_tunAddrSrc = (ipSrc == "TSi") ? 3 : (ipSrc == "konfiguriert" ? 1 : 2);   // Zonen 0.1: Herkunft der Tunnel-Adresse
    char ipb[20]; ip4addr_ntoa_r(&ip, ipb, sizeof(ipb));
    g_tunNote = String("ipsec0 ") + ipb + "/" + prefix + " (Adresse " + ipSrc + ", Netz " + src + ")";
    if (haveCp && cp.dns_count) {
        char db[20]; snprintf(db, sizeof(db), "%u.%u.%u.%u", cp.dns[0][0], cp.dns[0][1], cp.dns[0][2], cp.dns[0][3]);
        g_tunNote += String(", DNS ") + db;   // gemeldet; Resolver-Anbindung folgt (Diagnose/Status)
    }
    Serial.printf("[ipsec] %s\r\n", g_tunNote.c_str());
}

// IKE-Socket lesen und demuxen (NAT-T: IKE mit Non-ESP-Marker / ESP-in-UDP / Keepalive). Wird vom
// loop-Task in poll() UND beim gracefullen stop() (Warten auf die DELETE-Antwort) benutzt.
static void ikeDrainSocket() {
    if (g.fd < 0 || !g.ike) return;
    for (int i = 0; i < 8; i++) {
        uint8_t* buf = s_rxBuf; struct sockaddr_in from; socklen_t fl = sizeof(from);
        ipsecStage(18);
        ssize_t n = recvfrom(g.fd, buf, sizeof(s_rxBuf), MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
        if (n <= 0) break;
        // raw RX-Sicht (Debug)
        g.rxPackets++; g.rxBytes += (uint32_t)n;
        { const uint8_t *fi = (const uint8_t *)&from.sin_addr;
          snprintf(g.lastRxFrom, sizeof(g.lastRxFrom), "%u.%u.%u.%u:%u", fi[0], fi[1], fi[2], fi[3], (unsigned)ntohs(from.sin_port)); }
        g.lastRxLen = (uint16_t)n;
        g.lastRxHdrLen = (uint16_t)((n < 64) ? n : 64);
        memcpy(g.lastRxHdr, buf, g.lastRxHdrLen);
        weirdike_endpoint_t ep; memset(&ep, 0, sizeof(ep)); memcpy(ep.ip, &from.sin_addr, 4); ep.port = ntohs(from.sin_port);
        if (g.curPort != 4500) { ipsecStage(19, (uint32_t)weirdike_state(g.ike)); weirdike_input_datagram(g.ike, buf, (size_t)n, &ep); continue; }
        size_t off = 0;
        switch (natt_classify(buf, (size_t)n, &off)) {
            case NATT_DATAGRAM_IKE: ipsecStage(19, (uint32_t)weirdike_state(g.ike)); weirdike_input_datagram(g.ike, buf, (size_t)n, &ep); break;
            case NATT_DATAGRAM_ESP: {
                if (!g.espReady) break;
                espDeliver(buf + off, (size_t)n - off);
                break;
            }
            default: break;   // keepalive / malformed
        }
    }
}

// ESP-Datenpfad abbauen (Child-SA weg / IKE-SA weg / Liveness-Fehler): ipsec0 runter, Session-Keys
// wipen. Die IKE-Instanz bleibt fuer die Diagnose bestehen, bis endIke() sie freigibt.
static void espTearDown(const char* why) {
    if (!g.espReady) return;
    tunDown();
    esp_session_deinit(&g.sess);
    if (g.prevReady) { esp_session_deinit(&g.sessPrev); g.prevReady = false; }
    g.espReady = false; g.childGen = 0;
    Serial.printf("[ipsec] ESP/ipsec0 abgebaut: %s\r\n", why);
}
// IKE-Instanz + Sockets freigeben; g.active=false -> supervise() darf (bei "Automatisch verbinden")
// neu starten. lastError bleibt als Grund sichtbar.
static void endIke(const String& why) {
    espTearDown(why.c_str());
    if (g.ike) { weirdike_free(g.ike); g.ike = nullptr; weirdike_crypto_mbedtls_free(&g.mc); }
    if (g.fd >= 0) { close(g.fd); g.fd = -1; }
    if (g.rawFd >= 0) { close(g.rawFd); g.rawFd = -1; }
    g.active = false; g.curPort = 0; g.peerResolved = false;
    g.lastError = why;
    Serial.printf("[ipsec] beendet: %s\r\n", why.c_str());
}

void IpsecRuntime::poll() {
    if (!g.active || !g.ike) return;
    ipsecStage(10, (uint32_t)weirdike_state(g.ike));
    weirdike_poll(g.ike, millis());

    // AP4: Reaktion auf Kontrollebene -- Child-SA vom Peer geloescht, IKE-SA vom Peer geloescht
    // (CLOSED) oder Liveness-Fehler NACH dem Aufbau (DPD-Timeout -> FAILED). Ein FAILED VOR dem
    // Aufbau (Handshake/AUTH) bleibt wie bisher fuer die Diagnose stehen (kein Auto-Restart).
    {
        weirdike_state_t st = weirdike_state(g.ike);
        ipsecStage(11, (uint32_t)st);
        if (g.espReady && (st != WEIRDIKE_STATE_CHILD_ESTABLISHED || weirdike_child_deleted(g.ike)))
            espTearDown(st == WEIRDIKE_STATE_CHILD_ESTABLISHED ? "Child-SA vom Gateway geloescht (DELETE)" : weirdike_state_str(st));
        if (st == WEIRDIKE_STATE_CLOSED || st == WEIRDIKE_STATE_FAILED) {
            // Peer-Befund VOR dem Freigeben des Kontexts sichern (ueberlebt den Neuaufbau).
            weirdike_diag_t pd; if (weirdike_get_diag(g.ike, &pd) == 0 && pd.peer_pfs_rejected) g.peerPfsRejected = true;
        }
        if (st == WEIRDIKE_STATE_CLOSED) {
            // CLOSED kommt auch, wenn der KERN selbst per DELETE geschlossen hat (z.B. abgelehnte
            // Child-Rekey-Antwort -> kontrollierter Neuaufbau). Dann steht der echte Grund bereits in
            // lastError (Fehlerzeile des Kerns) -- nicht mit "Gateway hat beendet" ueberschreiben.
            endIke(g.lastError.length() ? g.lastError : String("Gateway hat die IKE-SA beendet (DELETE)"));
            return;
        }
        if (st == WEIRDIKE_STATE_FAILED) {
            weirdike_diag_t d; weirdike_get_diag(g.ike, &d);
            if (d.reached_state >= (int)WEIRDIKE_STATE_ESTABLISHED) { endIke("Verbindung verloren (DPD: Gateway antwortet nicht)"); return; }
        }
    }

    // once the CHILD SA is up, stand up the ESP data plane
    if (!g.espReady && weirdike_state(g.ike) == WEIRDIKE_STATE_CHILD_ESTABLISHED) {
        weirdike_child_sa_t child;
        ipsecStage(12);
        if (weirdike_get_child_sa(g.ike, &child) == 0 &&
            esp_session_init(&g.sess, &child, &g.cr, espScratch(g.sessIdx), ESP_MAX_PACKET) == 0) {
            g.espReady = true; g.childGen = weirdike_child_generation(g.ike);
        }
        memset(&child, 0, sizeof(child));
        if (g.espReady && !espUsesUdp()) { ipsecStage(13); espOpenRaw(); }   // kein NAT -> ESP als IP-Proto 50
        if (g.espReady) tunBringUp();                     // 8.2f: Tunnel als Netzwerkschnittstelle
    }
    // AP5 Rekey: neue Child-SA-Generation -> bisherige Session wird zur Empfangs-Session (Ueberlappung),
    // neue Keys fuer Senden+Empfangen; ipsec0 bleibt oben (Adressen/Route unveraendert).
    if (g.espReady && weirdike_child_generation(g.ike) != g.childGen) {
        weirdike_child_sa_t child;
        ipsecStage(15);
        if (weirdike_get_child_sa(g.ike, &child) == 0) {
            if (g.prevReady) esp_session_deinit(&g.sessPrev);
            g.sessPrev = g.sess; g.prevReady = true;      // alte SA nur noch fuer RX (behaelt ihren Scratch)
            g.sessIdx ^= 1;                                // die neue Session bekommt den anderen Scratch
            if (esp_session_init(&g.sess, &child, &g.cr, espScratch(g.sessIdx), ESP_MAX_PACKET) == 0) {
                g.childGen = weirdike_child_generation(g.ike);
                if (g.pfsWanted) g.peerPfsRejected = false;   // ein gelungener PFS-Rekey widerlegt den Befund
                Serial.printf("[ipsec] Child-SA neu geschluesselt (Generation %lu), alte SA bleibt kurz fuer RX\r\n", (unsigned long)g.childGen);
            } else {
                g.sess = g.sessPrev; g.prevReady = false; g.sessIdx ^= 1;   // Init-Fehler: alte Session weiterverwenden
                Serial.println("[ipsec] Rekey: esp_session_init fehlgeschlagen -- alte SA bleibt aktiv");
            }
        }
        memset(&child, 0, sizeof(child));
    }
    // Ueberlappung beendet (DELETE der alten SA ausgetauscht) -> Empfangs-Session der alten SA freigeben.
    if (g.prevReady) {
        weirdike_child_sa_t pv;
        if (weirdike_get_child_sa_prev(g.ike, &pv) != 0) { esp_session_deinit(&g.sessPrev); g.prevReady = false; }
        memset(&pv, 0, sizeof(pv));
    }
    tunPumpTx();   // von lwIP geroutete Pakete -> ESP

    // ESP ohne NAT-T: rohe Proto-50-Pakete vom Gateway
    if (g.espReady && !espUsesUdp()) {
        for (int i = 0; i < 8; i++) {
            uint8_t* rb = s_rawBuf; size_t off = 0;
            ipsecStage(17);
            ssize_t n = espRecvRaw(rb, sizeof(s_rawBuf), off);
            if (n <= 0) break;
            g.rxPackets++; g.rxBytes += (uint32_t)n;
            espDeliver(rb + off, (size_t)n - off);
        }
    }

    // read our socket (external RX) and demux
    ikeDrainSocket();
    ipsecStage(22);
}

bool IpsecRuntime::rekeyNow() {
    if (!g.active || !g.ike || !g.espReady) return false;
    return weirdike_rekey_child(g.ike, millis()) == 0;
}
// IKE-SA-Rekey: neue IKE-SA (eigene SPIs/Schluessel, Message-IDs ab 0) im zweiten Kern-Slot, die
// Child-SA/ESP-Session bleibt unveraendert (Datenpfad merkt nichts), alte IKE-SA wird per DELETE
// abgebaut. Ergebnis sichtbar ueber diag "ikeGen" (Generation +1).
bool IpsecRuntime::ikeRekeyNow() {
    if (!g.active || !g.ike) return false;
    return weirdike_rekey_ike(g.ike, millis()) == 0;
}

bool IpsecRuntime::isUp() const     { return g.active && g.espReady; }
bool IpsecRuntime::peerPfsRejected() const { return g.peerPfsRejected; }
bool IpsecRuntime::isActive() const { return g.active; }
String IpsecRuntime::stateText() const {
    if (!g.active || !g.ike) return "inaktiv";
    return weirdike_state_str(weirdike_state(g.ike));
}

IpsecPingResult IpsecRuntime::testPing(const String& targetIp) {
    IpsecPingResult r;
    ipsecStage(40);
    if (!g.active || !g.ike) { r.stage = "not-started"; r.detail = "Runtime nicht aktiv"; return r; }
    if (!g.espReady)         { r.stage = weirdike_state_str(weirdike_state(g.ike)); r.detail = "CHILD_SA noch nicht bereit"; return r; }
    if (!g.peerResolved) { r.stage = "no-peer"; r.detail = "Gateway-IP unbekannt"; return r; }
    if (!espUsesUdp() && !espOpenRaw()) { r.stage = "raw-esp"; r.detail = g.lastError; return r; }

    // inner source = das TSi, das die FRITZ tatsaechlich NARROWED/zugewiesen hat (aus der CHILD-SA),
    // NICHT der angebotene config-Wert. Der Peer routet die Antwort nur fuer eine innere Quell-IP
    // INNERHALB des ausgehandelten TSi zurueck. Fallback auf localTunnelIp nur, wenn TS unbrauchbar.
    char tsiBuf[20] = {0}, tsrBuf[40] = {0};
    {
        weirdike_child_sa_t ch;
        if (weirdike_get_child_sa(g.ike, &ch) == 0) {
            if (ch.local_ts.address_family == 4)
                snprintf(tsiBuf, sizeof(tsiBuf), "%u.%u.%u.%u",
                         ch.local_ts.start_addr[0], ch.local_ts.start_addr[1], ch.local_ts.start_addr[2], ch.local_ts.start_addr[3]);
            if (ch.remote_ts.address_family == 4)
                snprintf(tsrBuf, sizeof(tsrBuf), "%u.%u.%u.%u-%u.%u.%u.%u",
                         ch.remote_ts.start_addr[0], ch.remote_ts.start_addr[1], ch.remote_ts.start_addr[2], ch.remote_ts.start_addr[3],
                         ch.remote_ts.end_addr[0], ch.remote_ts.end_addr[1], ch.remote_ts.end_addr[2], ch.remote_ts.end_addr[3]);
        }
        memset(&ch, 0, sizeof(ch));   // geheime CHILD-Keys sofort wischen
    }
    String src = strlen(tsiBuf) ? String(tsiBuf) : ipsecService.config().localTunnelIp;
    if (src.length() == 0) { r.stage = "no-tunnel-ip"; r.detail = "kein TSi (weder ausgehandelt noch localTunnelIp)"; return r; }
    const uint8_t pl[8] = { 'W','e','i','r','d','I','K','E' };
    uint8_t inner[128];
    size_t innerLen = buildIcmp(inner, src.c_str(), targetIp.c_str(), 0, g.pingId, ++g.pingSeq, pl, sizeof(pl));

    uint8_t esp[256]; size_t espLen = 0;
    int sc = esp_session_seal(&g.sess, ESP_NH_IPV4, inner, innerLen, esp, sizeof(esp), &espLen);
    if (sc != 0) { r.stage = "seal"; r.detail = (sc == ESP_SESSION_EXHAUSTED) ? "ESP-Sequenzraum erschoepft (Rekey noetig)" : "esp_session_seal Fehler"; return r; }
    r.txSeq = g.sess.tx_seq.next - 1;

    uint32_t t0 = millis();
    if (!espSend(esp, espLen)) { r.stage = "send"; r.detail = espUsesUdp() ? "sendto ESP/UDP-4500 fehlgeschlagen" : ("sendto ESP/Proto-50 fehlgeschlagen: " + g.lastError); return r; }
    g.espTx++;

    // wait for a matching ESP reply (up to ~2s) on the transport in use (UDP/4500 or raw proto 50),
    // still feeding IKE datagrams to the core
    bool udp = espUsesUdp();
    int wfd = udp ? g.fd : g.rawFd;
    while (millis() - t0 < 2000) {
        fd_set rf; FD_ZERO(&rf); FD_SET(wfd, &rf);
        struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 100000;
        if (select(wfd + 1, &rf, nullptr, nullptr, &tv) <= 0) continue;
        uint8_t* rb = s_rawBuf; ssize_t n; size_t off = 0;
        if (udp) {
            n = recv(g.fd, rb, sizeof(s_rawBuf), 0);
            if (n <= 0) continue;
            if (natt_classify(rb, (size_t)n, &off) != NATT_DATAGRAM_ESP) {
                if (off && natt_classify(rb, (size_t)n, &off) == NATT_DATAGRAM_IKE) weirdike_input_datagram(g.ike, rb, (size_t)n, nullptr);
                continue;
            }
        } else {
            n = espRecvRaw(rb, sizeof(s_rawBuf), off);
            if (n <= 0) continue;
        }
        g.rxPackets++; g.rxBytes += (uint32_t)n;
        uint8_t* pt = s_ptBuf; size_t ptl = 0; uint8_t nh = 0;
        if (esp_session_open(&g.sess, rb + off, (size_t)n - off, &nh, pt, sizeof(s_ptBuf), &ptl) != 0) { g.icvErrors++; continue; }
        g.espRx++;
        // validate inner ICMP echo reply target->src, same id/seq/payload
        if (nh == ESP_NH_IPV4 && ptl >= 28 && pt[9] == 1) {
            const uint8_t *icmp = pt + ((pt[0] & 0x0f) * 4);
            uint16_t rid = (icmp[4] << 8) | icmp[5], rseq = (icmp[6] << 8) | icmp[7];
            if (icmp[0] == 0 && rid == g.pingId && rseq == g.pingSeq) {
                r.ok = true; r.rttMs = millis() - t0; r.rxSeq = g.sess.rx_replay.highest;
                r.stage = "ok"; r.detail = "ICMP echo reply verifiziert";
                return r;
            }
        }
        if (nh == ESP_NH_IPV4) tunDeliver(pt, ptl);   // fremdes Paket waehrend des Wartens -> lwIP, nicht verwerfen
    }
    r.stage = "timeout";
    r.detail = String("keine gueltige ESP-Antwort (2s); inner src=") + src + " -> " + targetIp +
               " (ausgehandeltes TSr=" + (strlen(tsrBuf) ? tsrBuf : "?") + ")";
    return r;
}

// ---- diagnostics (NO secrets) ----------------------------------------------
static String jescR(const String& s) {
    String o; for (size_t i = 0; i < s.length(); i++) { char c = s[i]; if (c == '"' || c == '\\') { o += '\\'; o += c; } else if ((uint8_t)c >= 0x20) o += c; } return o;
}
void IpsecRuntime::fillVpnStatus(VpnStatus& s) const {
    if (!g.active) return;
    if (g.bindIp[0]) s.underlay = String(g.bindIp);
    if (g.peerResolved) {
        char pip[20]; snprintf(pip, sizeof(pip), "%u.%u.%u.%u", g.peerIp[0], g.peerIp[1], g.peerIp[2], g.peerIp[3]);
        s.peer = pip;
    }
    // Einstellungen = ERLAUBT (Policy); Status = TATSAECHLICH AUSGEHANDELT (weirdike_get_diag),
    // fuer IKE-SA UND Child-SA -- nichts davon ist hier hartkodiert.
    String d, childSuite;
    if (g.ike) {
        weirdike_diag_t wd;
        if (weirdike_get_diag(g.ike, &wd) == 0) {
            String ik = ikeSuiteText(wd);
            if (ik.length()) { d += "IKE " + ik; if (wd.nat_detected) d += ", NAT-T"; }
            childSuite = childSuiteText(wd);
        }
    }
    if (g.espReady) {
        d += (d.length() ? ", " : "") + String("CHILD-SA aktiv (ESP ") + (childSuite.length() ? childSuite : String("?")) + ")";
        s.hasTraffic = true;
        s.txPackets = g.espTx; s.rxPackets = g.espRx;
        s.txBytes = g.txBytes; s.rxBytes = g.rxBytes;
    }
    if (g.curPort == 4500 && d.indexOf("NAT-T") < 0) d += (d.length() ? ", " : "") + String("UDP-4500");
    if (g.espReady) {
        if (g_tunUp) { char ipb[20]; ip4addr_ntoa_r(&g_tunIp, ipb, sizeof(ipb)); s.tunnelIp = ipb; }
        if (g_tunNote.length()) d += ", " + g_tunNote;
        if (g_tunUp) d += " TX/RX " + String(g_tunTxPk) + "/" + String(g_tunRxPk) + (g_tunDrop ? (" drop " + String(g_tunDrop)) : String(""));
    }
    // Bekannte funktionale Einschraenkung der Runtime -- KEIN Fehlerzustand, solange der Tunnel steht:
    // WeirdIKE beantwortet noch kein INFORMATIONAL (DPD/DELETE) und kein CREATE_CHILD_SA (Rekey/PFS).
    // Ehrlicher Faehigkeitsstand (HW-Gate 2026-09-07): DPD/INFORMATIONAL, Child-SA-Rekey und IKE-SA-Rekey
    // sind implementiert und auf dem P4 gegen die FRITZ!Box bewiesen (Generationen im Diagnose-JSON).
    if (g.espReady) d += " - DPD, Child-SA-Rekey und IKE-SA-Rekey aktiv (hardwarebewiesen)";
    // PFS: FAEHIGKEIT des Clients und VERHALTEN der Gegenstelle getrennt ausweisen.
    d += String(" | PFS: ") + (ipsecPfsSupported() ? "unterstuetzt" : "nicht implementiert") + ", Konfiguration: " + (g.pfsWanted ? "an" : "aus");
    if (g.peerPfsRejected) {
        d += ", Peer: PFS beim letzten Child-Rekey nicht akzeptiert";
        s.error = "Die Gegenstelle hat PFS beim Child-SA-Rekey nicht akzeptiert (Child-SA ohne D-H/KE ausgewaehlt). "
                  "Der Tunnel wurde aus Sicherheitsgruenden neu aufgebaut. Fuer diese Gegenstelle sollte PFS deaktiviert werden.";
    }
    s.detail = s.detail.length() ? (s.detail + " | " + d) : d;   // Dienst-Hinweise (z.B. Neustart erforderlich) davor
    if (g.lastError.length()) s.error = g.lastError;
}

String IpsecRuntime::diagJson() const {
    String j = "{";
    j += "\"active\":"; j += g.active ? "true" : "false"; j += ",";
    j += "\"state\":\""; j += stateText(); j += "\",";
    j += "\"bindIp\":\""; j += jescR(String(g.bindIp)); j += "\",";
    j += "\"ikePort\":"; j += String(g.curPort); j += ",";
    j += "\"natT\":"; j += (g.curPort == 4500) ? "true" : "false"; j += ",";
    char pip[20] = {0}; snprintf(pip, sizeof(pip), "%u.%u.%u.%u", g.peerIp[0], g.peerIp[1], g.peerIp[2], g.peerIp[3]);
    j += "\"peerIp\":\""; j += g.peerResolved ? pip : ""; j += "\",";
    j += "\"childUp\":"; j += g.espReady ? "true" : "false";
    j += ",\"espTransport\":\""; j += g.espReady ? (espUsesUdp() ? "ESP-in-UDP/4500 (NAT-T)" : "ESP roh, IP-Protokoll 50 (kein NAT)") : "-"; j += "\"";
    j += ",\"tunnel\":\""; j += jescR(g_tunNote); j += "\"";
    j += ",\"lastCrash\":\""; j += jescR(g_ipsecLastCrash); j += "\"";   // letzter Panic/WDT-Reset mit IPsec am Zug
    j += ",\"loopStackMin\":"; j += String((unsigned long)(g_ipsecCrashStackMin == 0xFFFFFFFFu ? 0 : g_ipsecCrashStackMin));
    {   // Speichermodell: Kontext (intern) + Workspace (PSRAM) -- Bedarf laut Kern
        weirdike_mem_req_t rq; if (weirdike_mem_req(NULL, &rq) == 0) {
            j += ",\"ikeCtxBytes\":"; j += String((unsigned long)rq.context_bytes);
            j += ",\"ikeWsBytes\":";  j += String((unsigned long)rq.workspace_bytes);
        }
    }
    {   // AP6: zugewiesene Werte (Configuration Payload) -- nur was WIRKLICH ausgehandelt wurde
        weirdike_cp_t cp; bool hc = g.ike && weirdike_get_cp(g.ike, &cp) == 0;
        char a[20] = {0}, d[20] = {0};
        if (hc && cp.have_address) snprintf(a, sizeof(a), "%u.%u.%u.%u", cp.address[0], cp.address[1], cp.address[2], cp.address[3]);
        if (hc && cp.dns_count)    snprintf(d, sizeof(d), "%u.%u.%u.%u", cp.dns[0][0], cp.dns[0][1], cp.dns[0][2], cp.dns[0][3]);
        j += ",\"cpDomain\":\""; j += (hc && cp.dns_domain_len) ? jescR(String(cp.dns_domain)) : String(""); j += "\"";   // F: DNS-Suchdomaene
        j += ",\"cpAddress\":\""; j += a; j += "\",\"cpDns\":\""; j += d; j += "\",\"cpSubnets\":"; j += String((unsigned)(hc ? cp.subnet_count : 0));
        j += ",\"childGen\":"; j += String((unsigned long)(g.ike ? weirdike_child_generation(g.ike) : 0));
        j += ",\"ikeGen\":";   j += String((unsigned long)(g.ike ? weirdike_ike_generation(g.ike) : 0));   /* 1 = aus IKE_AUTH, +1 je IKE-SA-Rekey */
        j += ",\"pfsWanted\":"; j += g.pfsWanted ? "true" : "false";
        j += ",\"trustMode\":\""; j += g.trustMode; j += "\"";   // Trust-Modell der laufenden Konfiguration (leer = PSK)
        j += ",\"peerPfsRejected\":"; j += g.peerPfsRejected ? "true" : "false";   /* Peer-Verhalten, nicht unsere Faehigkeit */
    }
    j += ",\"tunUp\":"; j += g_tunUp ? "true" : "false";
    j += ",\"tunTx\":"; j += String(g_tunTxPk); j += ",\"tunRx\":"; j += String(g_tunRxPk); j += ",\"tunDrop\":"; j += String(g_tunDrop);
    j += ",\"dropQ\":"; j += String(g_dropQ); j += ",\"dropSeal\":"; j += String(g_dropSeal);
    j += ",\"dropSend\":"; j += String(g_dropSend); j += ",\"dropMem\":"; j += String(g_dropMem);
    j += ",\"tunMaxLen\":"; j += String(g_tunMaxLen); j += ",\"sealErrLen\":"; j += String(g_sealErrLen); j += ",\"sealErrRc\":"; j += String(g_sealErrRc);
    j += ",\"tunMtu\":"; j += String(g_tunAdded ? (int)g_tun.mtu : 0);
    j += ",\"sendErrno\":"; j += String(g_espSendErrno); j += ",\"sendErrLen\":"; j += String(g_espSendErrLen);
    j += ",\"sendErrTxt\":\""; j += jescR(g_espSendErrno ? String(strerror(g_espSendErrno)) : String("-")); j += "\"";
    if (g.espReady) {
        weirdike_child_sa_t ch;
        if (g.ike && weirdike_get_child_sa(g.ike, &ch) == 0) {
            char sb[12]; snprintf(sb, sizeof(sb), "%08x", (unsigned)ch.inbound_spi);  j += ",\"inSpi\":\""; j += sb; j += "\"";
            snprintf(sb, sizeof(sb), "%08x", (unsigned)ch.outbound_spi); j += ",\"outSpi\":\""; j += sb; j += "\"";
            memset(&ch, 0, sizeof(ch));
        }
        j += ",\"espTx\":"; j += String(g.espTx);
        j += ",\"espRx\":"; j += String(g.espRx);
        j += ",\"txSeq\":"; j += String((unsigned)g.sess.tx_seq.next - 1);
        j += ",\"rxHighest\":"; j += String((unsigned)g.sess.rx_replay.highest);
        j += ",\"replayDrops\":"; j += String(g.replayDrops);
        j += ",\"icvErrors\":"; j += String(g.icvErrors);
    }
    j += ",\"txPackets\":"; j += String(g.txPackets);
    j += ",\"txBytes\":";   j += String(g.txBytes);
    j += ",\"rxPackets\":"; j += String(g.rxPackets);
    j += ",\"rxBytes\":";   j += String(g.rxBytes);
    j += ",\"lastRxFrom\":\""; j += jescR(String(g.lastRxFrom)); j += "\"";
    j += ",\"lastRxLen\":"; j += String(g.lastRxLen);
    j += ",\"lastRxHdr\":\"";
    { static const char *hx = "0123456789abcdef";
      for (int i = 0; i < g.lastRxHdrLen; i++) { j += hx[g.lastRxHdr[i] >> 4]; j += hx[g.lastRxHdr[i] & 0xF]; } }
    j += "\"";
    // ERLAUBT: the policy actually handed to WeirdIKE for this attempt (helps NO_PROPOSAL_CHOSEN triage).
    j += ",\"offeredProposal\":\""; j += jescR(g.offer); j += "\"";
    // AUSGEHANDELT: the IKE-SA and Child-SA suites the peer actually SELECTED + the AUTH/child
    // outcome (no secrets), straight from weirdike_get_diag() -- nothing hard-coded.
    if (g.ike) {
        weirdike_diag_t d;
        if (weirdike_get_diag(g.ike, &d) == 0) {
            String ik = ikeSuiteText(d), ch = childSuiteText(d);
            j += ",\"ikeSuite\":\"";   j += ik.length() ? jescR(ik) : String("(not negotiated)"); j += "\"";
            j += ",\"childSuite\":\""; j += ch.length() ? jescR(ch) : String("(not negotiated)"); j += "\"";
            j += ",\"natDetected\":"; j += d.nat_detected ? "true" : "false";
            j += ",\"ikeAuthOk\":";  j += (d.auth_done && d.ike_auth_ok) ? "true" : "false";
            // IKE_AUTH-Ergebnis semantisch getrennt (WeirdIKE diag): ikeAuthReject = die Gegenstelle hat
            // UNSERE Authentifizierung abgelehnt (Error-Notify, kein AUTH von ihr); authLocalFail = ihr
            // AUTH war da, unsere Pruefung scheiterte; childReject NUR bei abgelehnter Child-SA nach
            // erfolgreichem IKE_AUTH. lastNotify/-Name = letzter Error-Notify (ueberlebt FAILED).
            if (d.auth_done) {
                j += ",\"ikeAuthReject\":"; j += d.ike_auth_rejected ? "true" : "false";
                j += ",\"authLocalFail\":"; j += d.auth_local_fail ? "true" : "false";
                j += ",\"childGen\":"; j += String((unsigned long)d.child_generation);
                j += ",\"childRekeyDh\":"; j += String((unsigned)d.child_rekey_dh);   // D-H-Gruppe der letzten Child-Rekey-Antwort (0 = kein PFS)
                j += ",\"childRekeyKe\":"; j += d.child_rekey_ke ? "true" : "false";
                j += ",\"childBytes\":"; j += String((unsigned long)d.child_bytes);
                // E2: die vom Gateway zurueckgegebene (genarrowte) TSr-Menge der aktuellen Child-SA
                { weirdike_child_sa_t ch; if (weirdike_get_child_sa(g.ike, &ch) == 0) {
                    j += ",\"childTsr\":[";
                    for (size_t i = 0; i < ch.n_remote_ts && i < WEIRDIKE_TS_MAX; i++) {
                        const weirdike_ts_t& t = ch.remote_ts_list[i];
                        char b[40]; snprintf(b, sizeof(b), "%s%u.%u.%u.%u-%u.%u.%u.%u", i ? "," : "",
                                             t.start_addr[0], t.start_addr[1], t.start_addr[2], t.start_addr[3],
                                             t.end_addr[0], t.end_addr[1], t.end_addr[2], t.end_addr[3]);
                        j += "\""; j += b; j += "\"";
                    }
                    j += "]";
                    memset(&ch, 0, sizeof(ch));   // enthaelt Schluessel -> sofort loeschen
                } }
                if (d.child_notify) { j += ",\"childReject\":"; j += String((unsigned)d.child_notify); }
            }
            if (d.last_notify) {
                const char* nn = weirdike_notify_name(d.last_notify);
                j += ",\"lastNotify\":"; j += String((unsigned)d.last_notify);
                j += ",\"lastNotifyName\":\""; j += nn ? nn : "?"; j += "\"";
            }
        }
    }
    j += ",\"lastError\":\""; j += jescR(g.lastError); j += "\"";
    j += ",\"log\":[";
    for (int i = 0; i < g_logCount; i++) {
        int idx = (g_logHead - g_logCount + i + RT_LOG_N * 2) % RT_LOG_N;
        if (i) j += ",";
        j += "\""; j += jescR(g_log[idx]); j += "\"";
    }
    j += "]";
    j += "}";
    return j;
}

// ---- 8.2f: Zugriff fuer Interface-Registry / Uebersicht ----
bool   IpsecRuntime::tunnelUp() const { return g_tunUp; }
String IpsecRuntime::tunnelIp() const {
    if (!g_tunUp) return "";
    char ipb[20]; ip4addr_ntoa_r(&g_tunIp, ipb, sizeof(ipb)); return String(ipb);
}
String IpsecRuntime::tunnelRoute() const { return g_tunNote; }
bool IpsecRuntime::tunnelContains(const String& ip) const {
    if (!g_tunUp) return false;
    ip4_addr_t a;
    if (!ip4addr_aton(ip.c_str(), &a)) return false;
    return ip4_addr_net_eq(&a, &g_tunIp, &g_tunMask);
}
// ---- Zonen 0.1: Netzsicht fuer die Registry (Attachment + erreichbare Prefixe getrennt) ----
static String tsToCidr(const weirdike_ts_t& t) {
    if (t.address_family != 4) return "";
    int p = rangePrefix(t.start_addr, t.end_addr);
    if (p < 0) return "";                                   // kein Prefix-Bereich -> unbekannt
    if (p == 0) return "any";
    uint32_t a = ((uint32_t)t.start_addr[0] << 24) | ((uint32_t)t.start_addr[1] << 16) | ((uint32_t)t.start_addr[2] << 8) | t.start_addr[3];
    char b[24]; snprintf(b, sizeof(b), "%u.%u.%u.%u/%d", (unsigned)(a >> 24) & 255u, (unsigned)(a >> 16) & 255u, (unsigned)(a >> 8) & 255u, (unsigned)a & 255u, p);
    return String(b);
}
bool IpsecRuntime::tunnelNetInfo(IpsecNetInfo& out) const {
    out = IpsecNetInfo();
    out.up = g_tunUp;
    if (!g_tunUp || !g.ike) return g_tunUp;
    { char ipb[20]; ip4addr_ntoa_r(&g_tunIp, ipb, sizeof(ipb)); out.local = ipb; }
    out.addrSource = g_tunAddrSrc;
    out.mtu = g_tunAdded ? g_tun.mtu : TUN_MTU;
    weirdike_child_sa_t ch;
    if (weirdike_get_child_sa(g.ike, &ch) == 0) {
        out.tsi = tsToCidr(ch.local_ts);
        for (size_t i = 0; i < ch.n_remote_ts && i < WEIRDIKE_TS_MAX && out.nTsr < 4; i++) {
            String c = tsToCidr(ch.remote_ts_list[i]);
            if (c.length()) out.tsr[out.nTsr++] = c;
        }
        if (out.nTsr == 0) { String c = tsToCidr(ch.remote_ts); if (c.length()) out.tsr[out.nTsr++] = c; }
        memset(&ch, 0, sizeof(ch));   // enthaelt Schluessel -> sofort loeschen
    }
    weirdike_cp_t cp;
    if (weirdike_get_cp(g.ike, &cp) == 0) {
        for (size_t i = 0; i < cp.subnet_count && out.nCpSub < 4; i++) {
            uint32_t m = ((uint32_t)cp.subnet_mask[i][0] << 24) | ((uint32_t)cp.subnet_mask[i][1] << 16) | ((uint32_t)cp.subnet_mask[i][2] << 8) | cp.subnet_mask[i][3];
            int p = 0; while (p < 32 && (m & (0x80000000u >> p))) p++;
            char sb[24]; snprintf(sb, sizeof(sb), "%u.%u.%u.%u/%d", cp.subnet[i][0], cp.subnet[i][1], cp.subnet[i][2], cp.subnet[i][3], p);
            out.cpSub[out.nCpSub++] = sb;
        }
    }
    return true;
}
void* IpsecRuntime::nativeNetif() const { return g_tunAdded ? (void*)&g_tun : nullptr; }

// ---- Diagnose/Experiment: Tunnel-MTU zur Laufzeit (wirkt auf NEUE TCP-Verbindungen ueber die MSS) ----
int IpsecRuntime::tunnelMtu() const { return g_tunAdded ? g_tun.mtu : TUN_MTU; }
bool IpsecRuntime::setTunnelMtu(int mtu) {
    if (mtu < 576 || mtu > 1500) return false;
    if (g_tunAdded) { LOCK_TCPIP_CORE(); g_tun.mtu = (u16_t)mtu; UNLOCK_TCPIP_CORE(); }
    g_tunMtuOverride = mtu;
    return true;
}
int IpsecRuntime::uplinkMtu() const {
    struct netif* d = netif_default;
    return d ? d->mtu : 0;
}

// ---- Krypto-Selbsttest (Diagnose): die drei Primitiven aus esp_seal einzeln auf `len` Byte ----
// Beantwortet, warum esp_session_seal bei vollen 1400-B-Segmenten rc=-1 liefert (kleine gehen durch).
String IpsecRuntime::cryptoSelfTest(int len) {
    if (len < 16 || len > 1600) len = 1408;
    if (len % 16) len += 16 - (len % 16);
    static uint8_t inb[1616], outb[1616];
    for (int i = 0; i < len; i++) inb[i] = (uint8_t)i;
    uint8_t key[32]; memset(key, 0x11, sizeof(key));
    uint8_t iv[16];  memset(iv, 0x22, sizeof(iv));
    uint8_t mac[32];
    const int N = 10;
    int fR = 0, fA = 0, fH = 0, fSw = 0, lastR = 0, lastA = 0;
    for (int k = 0; k < N; k++) {
        int r = g.cr.random ? g.cr.random(g.cr.ctx, iv, 16) : -99; if (r) { fR++; lastR = r; }
        int a = g.cr.aes_cbc ? g.cr.aes_cbc(g.cr.ctx, 1, key, 32, iv, inb, (size_t)len, outb) : -99; if (a) { fA++; lastA = a; }
        int h = g.cr.hmac_sha256 ? g.cr.hmac_sha256(g.cr.ctx, key, 32, inb, (size_t)len, mac) : -99; if (h) fH++;
        // Vergleich: SOFTWARE-AES (eigener mbedtls-Kontext, ohne HW-Peripherie-Sharing)
        mbedtls_aes_context sw; mbedtls_aes_init(&sw); uint8_t iv2[16]; memset(iv2, 0x22, 16);
        int s = mbedtls_aes_setkey_enc(&sw, key, 256);
        if (s == 0) s = mbedtls_aes_crypt_cbc(&sw, MBEDTLS_AES_ENCRYPT, (size_t)len, iv2, inb, outb);
        mbedtls_aes_free(&sw); if (s) fSw++;
    }
    return String("crypttest len=") + len + " x" + N + "  random_fail=" + fR + "(rc" + lastR + ")  aes_fail=" + fA + "(rc" + lastA + ")  hmac_fail=" + fH + "  mbedtls_aes_direkt_fail=" + fSw;
}

#else  // !WEIRDOS_FEATURE_IPSEC
// Stub: IPsec nicht im Build enthalten (WEIRDOS_FEATURE_IPSEC=0)
// Kein Socket, kein lwIP-netif ipsec0, kein WeirdIKE: jede Methode aus ipsec_runtime.h meldet
// "nicht da" (false / 0 / "" / nullptr). Verbraucher: Netz-Registry (ipsec0-Sicht), Zonen
// (access_policy, network_platform), Konsole, Web-UI (PFS-Hinweis), IpsecService.
#include "lwip/netif.h"   // uplinkMtu(): MTU des Default-Interfaces -- keine IPsec-Eigenschaft (siehe unten)

IpsecRuntime ipsecRuntime;

String IpsecRuntime::start(const IpsecConfig&, const String&, const String&) { return "IPsec nicht im Build enthalten (WEIRDOS_FEATURE_IPSEC=0)"; }
void   IpsecRuntime::stop() {}
void   IpsecRuntime::poll() {}
bool   IpsecRuntime::rekeyNow() { return false; }
bool   IpsecRuntime::ikeRekeyNow() { return false; }
bool   IpsecRuntime::isUp() const { return false; }
bool   IpsecRuntime::peerPfsRejected() const { return false; }
bool   IpsecRuntime::isActive() const { return false; }
String IpsecRuntime::stateText() const { return "nicht im Build enthalten"; }
String IpsecRuntime::diagJson() const { return "{\"ok\":false,\"builtIn\":false}"; }
void   IpsecRuntime::fillVpnStatus(VpnStatus&) const {}

IpsecPingResult IpsecRuntime::testPing(const String&) {
    IpsecPingResult r;
    r.ok = false; r.stage = "not built"; r.detail = "IPsec nicht im Build enthalten (WEIRDOS_FEATURE_IPSEC=0)";
    return r;
}

// ipsec0 existiert nicht: down, keine Adresse, kein Netz, kein netif.
bool   IpsecRuntime::tunnelUp() const { return false; }
String IpsecRuntime::tunnelIp() const { return ""; }
String IpsecRuntime::tunnelRoute() const { return ""; }
bool   IpsecRuntime::tunnelContains(const String&) const { return false; }
int    IpsecRuntime::tunnelMtu() const { return 0; }
bool   IpsecRuntime::setTunnelMtu(int) { return false; }
// Bewusst KEIN 0-Stub: network_registry.cpp nimmt diesen Wert als MTU des Modem-Uplinks
// (Attachment "modem-uplink", nicht ipsec0) -> Zonen-Planner mtuHint / Diagnose. Die Auskunft
// haengt nicht an IPsec, nur an lwIP -- deshalb hier dieselbe Antwort wie in der echten Runtime.
int    IpsecRuntime::uplinkMtu() const { struct netif* d = netif_default; return d ? d->mtu : 0; }
bool   IpsecRuntime::tunnelNetInfo(IpsecNetInfo& out) const { out = IpsecNetInfo(); return false; }
void*  IpsecRuntime::nativeNetif() const { return nullptr; }
String IpsecRuntime::cryptoSelfTest(int) { return "IPsec nicht im Build enthalten (WEIRDOS_FEATURE_IPSEC=0)"; }

// Kein RTC-Marker ohne Runtime -> nichts zu melden.
void ipsecRuntimeBootReport() {}

#endif // WEIRDOS_FEATURE_IPSEC
