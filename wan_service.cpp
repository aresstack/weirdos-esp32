// ============================================================================
// wan_service.cpp -- siehe wan_service.h. Hintergrund-Internet-Check (eigener
// Task, kurzer TCP-Timeout) -> blockiert nie loop()/Webserver.
// ============================================================================
#include "wan_service.h"
#include "wan_policy.h"          // WanPolicy = EINZIGE System-WAN-Wahl (wanResolve)
#include "network_registry.h"

#include <WiFi.h>
#include <lwip/sockets.h>        // gebundene TCP-Probe (bind an Interface-Quell-IP)
#include <fcntl.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

WanService wanService;

namespace {
// Gemeinsamer Zustand: der Task schreibt, der Webserver liest. POD/char-Puffer
// statt String -> keine String-Thread-Sicherheitsprobleme; ein zerrissener Lese-
// zugriff auf iface/ip waere hoechstens kosmetisch.
struct WanState {
    volatile bool     up          = false;
    volatile bool     inet        = false;
    volatile bool     ever        = false;
    volatile uint32_t lastMs      = 0;
    char              iface[20]   = {0};
    char              ip[20]      = {0};
    volatile bool     started     = false;
} g;

void copyStr(char* dst, size_t cap, const String& s) {
    size_t n = s.length(); if (n >= cap) n = cap - 1;
    memcpy(dst, s.c_str(), n); dst[n] = 0;
}

// Erreichbarkeits-Probe, GEBUNDEN an die Quell-IP des gewaehlten WAN-Interface:
// bind(srcIp) -> Egress ueber genau dieses netif (derselbe hardwarebewiesene Ansatz wie
// http_transport_esp32.cpp/connectBound). So testet die Probe wirklich das ausgewaehlte WAN
// und nicht die lwIP-Default-Route. Cloudflare/Google DNS auf TCP/53 nehmen Verbindungen an;
// IP-Literale -> keine Namensaufloesung noetig.
bool tcpProbeBound(const char* srcIp, const char* dstIp, uint16_t port, int timeoutMs) {
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return false;
    struct timeval tv; tv.tv_sec = timeoutMs / 1000; tv.tv_usec = (timeoutMs % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in local; memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET; local.sin_port = 0;
    local.sin_addr.s_addr = inet_addr(srcIp);
    if (local.sin_addr.s_addr == 0 || local.sin_addr.s_addr == INADDR_NONE) { close(fd); return false; }
    if (bind(fd, (struct sockaddr*)&local, sizeof(local)) != 0) { close(fd); return false; }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    struct sockaddr_in dst; memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET; dst.sin_port = htons(port);
    dst.sin_addr.s_addr = inet_addr(dstIp);

    int cr = connect(fd, (struct sockaddr*)&dst, sizeof(dst));
    bool ok = (cr == 0);
    if (cr < 0 && errno == EINPROGRESS) {
        fd_set wset; FD_ZERO(&wset); FD_SET(fd, &wset);
        struct timeval ctv = tv;
        if (select(fd + 1, nullptr, &wset, nullptr, &ctv) > 0) {
            int soerr = 0; socklen_t l = sizeof(soerr);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &l);
            ok = (soerr == 0);
        }
    }
    close(fd);
    return ok;
}

void wanTask(void*) {
    for (;;) {
        NetIface ni;
        // WanPolicy (WAN -> Uplink) ist die EINZIGE System-WAN-Wahl -- nicht mehr
        // networkMode.config().wan/egressResolve (das war die konkurrierende zweite Wahrheit).
        bool up = wanResolve(ni) && ni.up && ni.ip.length() > 0;
        g.up = up;
        copyStr(g.iface, sizeof(g.iface), up ? ni.id : String("-"));
        copyStr(g.ip,    sizeof(g.ip),    up ? ni.ip : String("-"));

        // Probe an die Quell-IP DIESES Interface gebunden -> testet wirklich das gewaehlte WAN.
        bool inet = up && (tcpProbeBound(ni.ip.c_str(), "1.1.1.1", 53, 3000)
                        || tcpProbeBound(ni.ip.c_str(), "8.8.8.8", 53, 3000));
        g.inet = inet; g.lastMs = millis(); g.ever = true;

        // Online seltener, offline haeufiger nachpruefen (schnellere Erholung).
        vTaskDelay(pdMS_TO_TICKS(inet ? 20000 : 8000));
    }
}
} // namespace

void WanService::begin() {
    if (g.started) return;
    // started erst NACH erfolgreicher Task-Erzeugung: scheitert sie (interner Heap), bleibt ein
    // erneuter begin() moeglich statt eines dauerhaft toten WAN-Checks bis zum Neustart.
    if (xTaskCreate(wanTask, "wancheck", 6144, nullptr, 1, nullptr) != pdPASS) {
        Serial.println("[WAN] Pruef-Task nicht anlegbar (interner Heap) -> naechster begin() versucht es erneut");
        return;
    }
    g.started = true;
}

bool     WanService::everChecked()  const { return g.ever; }
bool     WanService::wanUp()        const { return g.up; }
bool     WanService::internetOk()   const { return g.inet; }
String   WanService::ifaceId()      const { return String(g.iface); }
String   WanService::ip()           const { return String(g.ip); }
uint32_t WanService::lastCheckAgeMs() const { return g.ever ? (millis() - g.lastMs) : 0; }

String WanService::statusJson() const {
    String j = "{";
    j += "\"wanUp\":";       j += (g.up ? "true" : "false"); j += ",";
    j += "\"iface\":\"";     j += String(g.iface); j += "\",";
    j += "\"ip\":\"";        j += String(g.ip); j += "\",";
    j += "\"internetOk\":";  j += (g.inet ? "true" : "false"); j += ",";
    j += "\"everChecked\":"; j += (g.ever ? "true" : "false"); j += ",";
    j += "\"ageMs\":";       j += String((unsigned long)lastCheckAgeMs());
    j += "}";
    return j;
}
