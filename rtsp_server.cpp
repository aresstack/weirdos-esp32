// ============================================================================
// rtsp_server.cpp -- RTSP/RTP-Server (siehe rtsp_server.h). Standards:
//   RFC 2326 RTSP 1.0 (OPTIONS/DESCRIBE/SETUP/PLAY/PAUSE/TEARDOWN/GET_PARAMETER, Session/CSeq,
//            Transport-Aushandlung, interleaved TCP 10.12), RFC 4566 SDP, RFC 3550 RTP/RTCP (SR+SDES),
//   RFC 2435 RTP/JPEG (Typ 0/1, Q=255 mit In-Band-Quantisierungstabellen, Restart-Marker-Header),
//   RFC 6184 RTP/H.264 (Single-NAL + FU-A, packetization-mode=1, sprop-parameter-sets),
//   RFC 2617 Basic-Auth (Stream-Schluessel).
//
// Ein Worker-Task bedient Kontrollkanal UND Medien aller Sitzungen (max. 2) per select():
//   * JPEG: derselbe Verteiler wie der HTTP-MJPEG-Client (cameraStream.copyLatest, Consumer-API --
//     der eingefrorene MJPEG-Task wird NICHT beruehrt), ein Frame -> alle spielenden /mjpeg-Sitzungen.
//   * H.264: dieselbe Kette wie /video.mp4 (Roh-Ausleihe -> PPA RGB565->YUV420 -> HW-Encoder), aber mit
//     RTP-Senke statt fMP4. Bewusst NICHT mit h264RunSession verschmolzen (der bewiesene fMP4-Pfad bleibt
//     unangetastet); dieselbe Exklusivitaet ueber g_h264ActiveRef (ein HW-Encoder).
// ============================================================================
#include "weirdos_features.h"        // WEIRDOS_FEATURE_RTSP -- der Schalter dieses Bausteins
#include "rtsp_server.h"             // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
#if WEIRDOS_FEATURE_RTSP
// ============================================================================
// Echte Implementierung (WEIRDOS_FEATURE_RTSP=1)
// ============================================================================
#include "web_ui.h"                  // streamKey, multiStreamEnabled, cameraReady, cameraTargetFps, h264Kbit
#include "camera_stream_service.h"   // cameraStream (JPEG-Consumer-API + Roh-Ausleihe)
#include "camera_manager.h"          // cameraManager (Modus fuer H.264)
#include "camera_frame.h"
#include "ppa_converter.h"
#include "h264_encoder.h"
#include "access_policy.h"           // accessAllowed("stream", ip)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <esp_heap_caps.h>
#include <esp_timer.h>
#include <esp_random.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>

extern volatile size_t g_h264ActiveRef;   // Exklusivitaet des HW-Encoders (wie camera_server.cpp)
extern volatile bool   g_h264Stop;
extern volatile uint32_t g_h264StatFps, g_h264StatKbit, g_h264StatSkips;
void logEvent(const String& text);

RtspServer rtspServer;

// ---- Grenzen / Konstanten --------------------------------------------------------------------
#define RTSP_MAX_SESSIONS   2
#define RTSP_RX_MAX         1024
#define RTSP_TIMEOUT_S      60
#define RTP_MTU_UDP         1400            // Payload je RTP-Paket ueber UDP (RFC 2435/6184: MTU-abhaengig)
#define RTP_MTU_TCP         4096            // interleaved: groessere Pakete = weniger Overhead
#define RTP_PT_JPEG         26
#define RTP_PT_H264         96
#define RTCP_INTERVAL_MS    5000
#define RTSP_IDLE_EXIT_MS   3000            // Worker beendet sich, wenn so lange keine Sitzung mehr

enum Mount : uint8_t { M_NONE = 0, M_MJPEG = 1, M_H264 = 2 };

struct RtspSession {
    bool     used = false;
    int      fd = -1;
    char     ip[48] = {0};
    char     rx[RTSP_RX_MAX]; size_t rxLen = 0;
    uint8_t  mount = M_NONE;
    bool     setup = false, playing = false;
    bool     tcp = true; uint8_t chRtp = 0, chRtcp = 1;
    int      udpRtp = -1, udpRtcp = -1; uint16_t cliRtp = 0, cliRtcp = 0; uint16_t srvRtp = 0;
    struct sockaddr_in cliAddr;
    uint32_t sessionId = 0, ssrc = 0;
    uint16_t seq = 0;
    uint32_t pkts = 0, octets = 0;
    uint32_t lastRtcpMs = 0, lastActMs = 0;
    uint32_t lastTs = 0;
    uint16_t reqW = 0, reqH = 0;   // /h264?w=&h=
};
static RtspSession* s_sess = nullptr;        // [RTSP_MAX_SESSIONS] im PSRAM (rx-Puffer je Sitzung)
static SemaphoreHandle_t s_lock = nullptr;   // schuetzt s_sess zwischen poll() (loop) und Worker
static uint32_t s_totalClients = 0;
static bool     s_allowUdp = false;

// Paketpuffer (PSRAM): Interleaved-Header(4) + RTP(12) + JPEG-Header(8) + Restart(4) + Quant(4+128) + Payload
static uint8_t* s_pkt = nullptr; static const size_t s_pktCap = 4 + 12 + 8 + 4 + 132 + RTP_MTU_TCP + 16;
// JPEG-Frame (PSRAM, waechst)
static uint8_t* s_jpg = nullptr; static size_t s_jpgCap = 0; static uint32_t s_jpgSeq = 0;
static bool     s_jpegConsumer = false;
// SPS/PPS-Cache fuer SDP (sprop-parameter-sets), gefuellt sobald der Encoder einmal ein IDR lieferte
static uint8_t  s_sps[128]; static size_t s_spsLen = 0;
static uint8_t  s_pps[64];  static size_t s_ppsLen = 0;

static inline uint32_t rtpNow90k() { return (uint32_t)((esp_timer_get_time() * 9) / 100); }
static inline void be16(uint8_t* p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xFF; }
static inline void be32(uint8_t* p, uint32_t v) { p[0] = v >> 24; p[1] = (v >> 16) & 0xFF; p[2] = (v >> 8) & 0xFF; p[3] = v & 0xFF; }

// ---- Socket-Helfer ----------------------------------------------------------------------------
static bool sendAll(int fd, const uint8_t* d, size_t n) {
    while (n) {
        int w = send(fd, d, n, 0);
        if (w < 0 && errno == EWOULDBLOCK) { vTaskDelay(pdMS_TO_TICKS(2)); continue; }
        if (w <= 0) return false;
        d += w; n -= (size_t)w;
    }
    return true;
}
static void closeSession(RtspSession& s) {
    if (s.fd >= 0) { shutdown(s.fd, SHUT_RDWR); close(s.fd); }
    if (s.udpRtp >= 0)  close(s.udpRtp);
    if (s.udpRtcp >= 0) close(s.udpRtcp);
    s = RtspSession();
}
static int playingCount(uint8_t mount) { int n = 0; for (int i = 0; i < RTSP_MAX_SESSIONS; i++) if (s_sess[i].used && s_sess[i].playing && s_sess[i].mount == mount) n++; return n; }
static int usedCount() { int n = 0; for (int i = 0; i < RTSP_MAX_SESSIONS; i++) if (s_sess[i].used) n++; return n; }

// ---- RTP/RTCP-Versand -------------------------------------------------------------------------
// rtp zeigt auf s_pkt + 4 (RTP-Header-Start); len = RTP-Paketlaenge. Interleaved: "$" ch len16 davor.
static bool rtpSend(RtspSession& s, uint8_t* rtp, size_t len, bool rtcp) {
    if (s.tcp) {
        uint8_t* h = rtp - 4; h[0] = '$'; h[1] = rtcp ? s.chRtcp : s.chRtp; be16(h + 2, (uint16_t)len);
        return sendAll(s.fd, h, len + 4);
    }
    int fd = rtcp ? s.udpRtcp : s.udpRtp;
    struct sockaddr_in to = s.cliAddr; to.sin_port = htons(rtcp ? s.cliRtcp : s.cliRtp);
    return sendto(fd, rtp, len, 0, (struct sockaddr*)&to, sizeof(to)) == (int)len;
}
static bool rtpSendPayload(RtspSession& s, uint8_t pt, bool marker, uint32_t ts, size_t payloadLen) {
    // Payload liegt bereits ab s_pkt + 16 (RTP-Header 12 Byte ab s_pkt + 4)
    uint8_t* r = s_pkt + 4;
    r[0] = 0x80; r[1] = (uint8_t)((marker ? 0x80 : 0) | pt);
    be16(r + 2, s.seq++); be32(r + 4, ts); be32(r + 8, s.ssrc);
    s.pkts++; s.octets += (uint32_t)payloadLen; s.lastTs = ts;
    return rtpSend(s, r, 12 + payloadLen, false);
}
static void rtcpSenderReport(RtspSession& s) {
    uint8_t* r = s_pkt + 4;
    // SR (RFC 3550 6.4.1)
    r[0] = 0x80; r[1] = 200; be16(r + 2, 6); be32(r + 4, s.ssrc);
    uint64_t us = (uint64_t)esp_timer_get_time();
    time_t now = time(nullptr);
    uint32_t ntpSec, ntpFrac = (uint32_t)(((us % 1000000ULL) << 32) / 1000000ULL);
    if (now > 1600000000) ntpSec = (uint32_t)now + 2208988800UL; else ntpSec = (uint32_t)(us / 1000000ULL);
    be32(r + 8, ntpSec); be32(r + 12, ntpFrac); be32(r + 16, rtpNow90k()); be32(r + 20, s.pkts); be32(r + 24, s.octets);
    // SDES CNAME (RFC 3550 6.5)
    char cname[40]; int cl = snprintf(cname, sizeof(cname), "weirdos-%08lx", (unsigned long)s.ssrc);
    size_t itemLen = 2 + (size_t)cl; size_t chunk = 4 + itemLen + 1; while (chunk % 4) chunk++;
    uint8_t* d = r + 28;
    d[0] = 0x81; d[1] = 202; be16(d + 2, (uint16_t)(chunk / 4)); be32(d + 4, s.ssrc);
    d[8] = 1; d[9] = (uint8_t)cl; memcpy(d + 10, cname, cl); memset(d + 10 + cl, 0, chunk - 4 - 2 - cl);
    rtpSend(s, r, 28 + 4 + chunk, true);
    s.lastRtcpMs = millis();
}

// ---- RFC 2435: JPEG analysieren + paketieren ---------------------------------------------------
struct JpegInfo { uint16_t w, h; uint8_t type; uint16_t dri; const uint8_t* q[2]; uint8_t nq; const uint8_t* scan; size_t scanLen; bool ok; const char* err; };
static JpegInfo jpegParse(const uint8_t* d, size_t n) {
    JpegInfo j; memset(&j, 0, sizeof(j)); j.err = "";
    if (n < 4 || d[0] != 0xFF || d[1] != 0xD8) { j.err = "kein JPEG (SOI)"; return j; }
    size_t p = 2;
    while (p + 4 <= n) {
        if (d[p] != 0xFF) { p++; continue; }
        uint8_t m = d[p + 1];
        if (m == 0xD8 || (m >= 0xD0 && m <= 0xD7) || m == 0x01 || m == 0xFF) { p += (m == 0xFF) ? 1 : 2; continue; }
        if (m == 0xD9) break;
        size_t segLen = ((size_t)d[p + 2] << 8) | d[p + 3];
        if (segLen < 2 || p + 2 + segLen > n) { j.err = "Segment-Laenge"; return j; }
        const uint8_t* s = d + p + 4; size_t sl = segLen - 2;
        if (m == 0xC0) {                 // SOF0 Baseline
            if (sl < 6) { j.err = "SOF0"; return j; }
            j.h = ((uint16_t)s[1] << 8) | s[2]; j.w = ((uint16_t)s[3] << 8) | s[4];
            uint8_t nc = s[5];
            if (nc != 3 || sl < 6 + 9) { j.err = "kein 3-Komponenten-JPEG (RFC 2435: nur YCbCr)"; return j; }
            uint8_t hs = s[7] >> 4, vs = s[7] & 0x0F;   // Sampling der Y-Komponente
            if (hs == 2 && vs == 1) j.type = 0; else if (hs == 2 && vs == 2) j.type = 1;
            else { j.err = "Chroma-Subsampling nicht 4:2:2/4:2:0 (RFC 2435 Typ 0/1)"; return j; }
        } else if (m == 0xC1 || m == 0xC2 || m == 0xC3 || m == 0xC9 || m == 0xCA) { j.err = "nur Baseline-JPEG (SOF0) in RTP/JPEG"; return j; }
        else if (m == 0xDB) {            // DQT (ggf. mehrere Tabellen je Segment)
            size_t o = 0;
            while (o < sl) {
                uint8_t pq = s[o] >> 4, tq = s[o] & 0x0F;
                if (pq != 0) { j.err = "16-Bit-Quantisierungstabelle (RFC 2435: 8 Bit)"; return j; }
                if (o + 65 > sl) { j.err = "DQT"; return j; }
                if (tq < 2) { j.q[tq] = s + o + 1; if (j.nq < tq + 1) j.nq = tq + 1; }
                o += 65;
            }
        } else if (m == 0xDD) {          // DRI
            if (sl >= 2) j.dri = ((uint16_t)s[0] << 8) | s[1];
        } else if (m == 0xDA) {          // SOS: danach beginnt der Scan bis EOI
            j.scan = s + sl; size_t e = n;
            for (size_t k = n; k >= 2; k--) if (d[k - 2] == 0xFF && d[k - 1] == 0xD9) { e = k - 2; break; }   // EOI von hinten
            size_t so = (size_t)(j.scan - d);
            j.scanLen = (e > so) ? e - so : 0;
            break;
        }
        p += 2 + segLen;
    }
    if (!j.w || !j.h || !j.scan || !j.scanLen) { j.err = "SOF0/SOS fehlt"; return j; }
    if (j.w > 2040 || j.h > 2040) { j.err = "Bild groesser als 2040 px (RFC 2435: Breite/Hoehe in 8-px-Einheiten, 1 Byte)"; return j; }
    if (j.nq < 1 || !j.q[0]) { j.err = "keine Quantisierungstabelle"; return j; }
    if (!j.q[1]) j.q[1] = j.q[0];   // nur eine Tabelle -> Chroma = Luma
    j.ok = true; return j;
}
static bool rtpSendJpeg(RtspSession& s, const JpegInfo& j, uint32_t ts) {
    size_t mtu = s.tcp ? RTP_MTU_TCP : RTP_MTU_UDP;
    uint8_t type = j.type + (j.dri ? 64 : 0);
    size_t off = 0;
    while (off < j.scanLen) {
        uint8_t* pl = s_pkt + 16; size_t hl = 0;
        // Main header (RFC 2435 3.1)
        pl[0] = 0; pl[1] = (uint8_t)(off >> 16); pl[2] = (uint8_t)(off >> 8); pl[3] = (uint8_t)off;
        pl[4] = type; pl[5] = 255; pl[6] = (uint8_t)(j.w / 8); pl[7] = (uint8_t)(j.h / 8); hl = 8;
        if (j.dri) { be16(pl + hl, j.dri); pl[hl + 2] = 0xFF; pl[hl + 3] = 0xFF; hl += 4; }   // F=1,L=1,count=0x3FFF
        if (off == 0) {  // Quantization Table header nur im ersten Paket (Q >= 128)
            pl[hl] = 0; pl[hl + 1] = 0; be16(pl + hl + 2, 128); hl += 4;
            memcpy(pl + hl, j.q[0], 64); memcpy(pl + hl + 64, j.q[1], 64); hl += 128;
        }
        size_t room = mtu - hl; size_t chunk = j.scanLen - off; if (chunk > room) chunk = room;
        memcpy(pl + hl, j.scan + off, chunk);
        off += chunk;
        if (!rtpSendPayload(s, RTP_PT_JPEG, off >= j.scanLen, ts, hl + chunk)) return false;
    }
    return true;
}

// ---- RFC 6184: Annex-B-AU -> NAL-Einheiten -> Single-NAL / FU-A ---------------------------------
static bool rtpSendNal(RtspSession& s, const uint8_t* nal, size_t len, bool lastOfAu, uint32_t ts) {
    size_t mtu = s.tcp ? RTP_MTU_TCP : RTP_MTU_UDP;
    uint8_t* pl = s_pkt + 16;
    if (len <= mtu) { memcpy(pl, nal, len); return rtpSendPayload(s, RTP_PT_H264, lastOfAu, ts, len); }
    uint8_t ind = (nal[0] & 0xE0) | 28, typ = nal[0] & 0x1F;
    size_t off = 1;
    while (off < len) {
        size_t chunk = len - off; if (chunk > mtu - 2) chunk = mtu - 2;
        bool first = (off == 1), last = (off + chunk >= len);
        pl[0] = ind; pl[1] = (uint8_t)((first ? 0x80 : 0) | (last ? 0x40 : 0) | typ);
        memcpy(pl + 2, nal + off, chunk); off += chunk;
        if (!rtpSendPayload(s, RTP_PT_H264, lastOfAu && last, ts, chunk + 2)) return false;
    }
    return true;
}
// Start-Codes finden; SPS/PPS cachen; jede NAL an alle spielenden /h264-Sitzungen.
static void h264SendAu(const uint8_t* au, size_t len, uint32_t ts) {
    const uint8_t* nals[16]; size_t nlen[16]; int nn = 0;
    size_t i = 0;
    while (i + 3 < len && nn < 16) {
        if (au[i] == 0 && au[i + 1] == 0 && (au[i + 2] == 1 || (au[i + 2] == 0 && i + 3 < len && au[i + 3] == 1))) {
            size_t st = i + (au[i + 2] == 1 ? 3 : 4);
            if (nn > 0) nlen[nn - 1] = (size_t)(au + i - nals[nn - 1]);
            nals[nn++] = au + st; i = st;
        } else i++;
    }
    if (nn > 0) nlen[nn - 1] = (size_t)(au + len - nals[nn - 1]);
    for (int k = 0; k < nn; k++) {
        while (nlen[k] > 1 && nals[k][nlen[k] - 1] == 0) nlen[k]--;   // trailing zero bytes vor dem naechsten Start-Code
        uint8_t t = nals[k][0] & 0x1F;
        if (t == 7 && nlen[k] <= sizeof(s_sps)) { memcpy(s_sps, nals[k], nlen[k]); s_spsLen = nlen[k]; }
        if (t == 8 && nlen[k] <= sizeof(s_pps)) { memcpy(s_pps, nals[k], nlen[k]); s_ppsLen = nlen[k]; }
    }
    for (int si = 0; si < RTSP_MAX_SESSIONS; si++) {
        RtspSession& s = s_sess[si];
        if (!s.used || !s.playing || s.mount != M_H264) continue;
        for (int k = 0; k < nn; k++) {
            if (nlen[k] == 0) continue;
            if (!rtpSendNal(s, nals[k], nlen[k], k == nn - 1, ts)) { logEvent(String("RTSP: Senden an ") + s.ip + " fehlgeschlagen (H.264)"); closeSession(s); break; }
        }
    }
}

static void b64(const uint8_t* d, size_t n, char* out, size_t cap) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < n && o + 5 < cap; i += 3) {
        uint32_t v = (uint32_t)d[i] << 16 | (i + 1 < n ? (uint32_t)d[i + 1] << 8 : 0) | (i + 2 < n ? d[i + 2] : 0);
        out[o++] = T[(v >> 18) & 63]; out[o++] = T[(v >> 12) & 63];
        out[o++] = (i + 1 < n) ? T[(v >> 6) & 63] : '='; out[o++] = (i + 2 < n) ? T[v & 63] : '=';
    }
    out[o] = 0;
}

// ---- RTSP-Antworten -----------------------------------------------------------------------------
static void rtspReply(RtspSession& s, int code, const char* text, int cseq, const String& extraHeaders, const String& body, const char* ctype) {
    String r = String("RTSP/1.0 ") + code + " " + text + "\r\nCSeq: " + cseq + "\r\nServer: WeirdOS RTSP/1.0\r\n";
    if (s.sessionId && code < 300 && s.setup) r += String("Session: ") + String(s.sessionId, HEX) + ";timeout=" + RTSP_TIMEOUT_S + "\r\n";
    r += extraHeaders;
    if (body.length()) { r += String("Content-Type: ") + ctype + "\r\nContent-Length: " + body.length() + "\r\n"; }
    r += "\r\n"; r += body;
    sendAll(s.fd, (const uint8_t*)r.c_str(), r.length());
}
static String hdr(const char* req, const char* name) {   // Header-Wert (case-insensitive), "" wenn fehlt
    const char* p = req; size_t nl = strlen(name);
    while ((p = strchr(p, '\n')) != nullptr) {
        p++;
        if (strncasecmp(p, name, nl) == 0 && p[nl] == ':') {
            p += nl + 1; while (*p == ' ') p++;
            const char* e = strpbrk(p, "\r\n");
            return e ? String(p).substring(0, (int)(e - p)) : String(p);
        }
    }
    return "";
}
static bool authOk(const char* req) {
    if (!streamKey.length()) return true;
    String a = hdr(req, "Authorization"); if (!a.startsWith("Basic ")) return false;
    String enc = a.substring(6); enc.trim();
    uint8_t out[96]; size_t o = 0; uint32_t v = 0; int bits = 0;
    for (size_t i = 0; i < enc.length() && o < sizeof(out) - 1; i++) {
        char c = enc[i]; int x;
        if (c >= 'A' && c <= 'Z') x = c - 'A'; else if (c >= 'a' && c <= 'z') x = c - 'a' + 26; else if (c >= '0' && c <= '9') x = c - '0' + 52; else if (c == '+') x = 62; else if (c == '/') x = 63; else break;
        v = (v << 6) | (uint32_t)x; bits += 6; if (bits >= 8) { bits -= 8; out[o++] = (uint8_t)((v >> bits) & 0xFF); }
    }
    out[o] = 0;
    const char* colon = strchr((const char*)out, ':');
    if (!colon) return false;
    // Benutzername: ist einer KONFIGURIERT, muss er exakt stimmen (VLC fragt beide Felder ab --
    // "wird ignoriert" war Murks-Semantik). Leer konfiguriert = Benutzername egal, nur der
    // Schluessel zaehlt (kompatibel zu bestehenden URLs rtsp://x:<key>@...).
    if (streamUser.length()) {
        const String gotUser = String((const char*)out).substring(0, (int)(colon - (const char*)out));
        if (gotUser != streamUser) return false;
    }
    return streamKey == String(colon + 1);
}
static String localIpOf(int fd) {
    struct sockaddr_in6 a; socklen_t al = sizeof(a); char ip[48] = "0.0.0.0";
    if (getsockname(fd, (struct sockaddr*)&a, &al) == 0) {
        if (a.sin6_family == AF_INET) inet_ntop(AF_INET, &((struct sockaddr_in*)&a)->sin_addr, ip, sizeof(ip));
        else { inet_ntop(AF_INET6, &a.sin6_addr, ip, sizeof(ip)); const char* m = strstr(ip, "::ffff:"); if (m) memmove(ip, m + 7, strlen(m + 7) + 1); }
    }
    return String(ip);
}
static uint8_t mountFromUrl(const String& url, uint16_t* w, uint16_t* h) {
    // rtsp://host:port/<mount>[?w=&h=][/track0]
    int p = url.indexOf("://"); String path = (p >= 0) ? url.substring(url.indexOf('/', p + 3)) : url;
    if (path.length() == 0 || path[0] != '/') return M_NONE;
    String q; int qi = path.indexOf('?'); if (qi >= 0) { q = path.substring(qi + 1); path = path.substring(0, qi); }
    if (path.endsWith("/track0")) path = path.substring(0, path.length() - 7);
    while (path.endsWith("/") && path.length() > 1) path.remove(path.length() - 1);
    if (w && h) { int a = q.indexOf("w="); int b = q.indexOf("h="); *w = a >= 0 ? (uint16_t)q.substring(a + 2).toInt() : 0; *h = b >= 0 ? (uint16_t)q.substring(b + 2).toInt() : 0; }
    if (path == "/mjpeg") return M_MJPEG;
#if WEIRDOS_FEATURE_H264
    if (path == "/h264")  return M_H264;
#else
    // Ohne H.264-Baustein (S3: kein HW-Encoder) den Mount gar nicht erst anbieten:
    // sauberes 404 im DESCRIBE statt Session-Abbruch nach PLAY (VLC zeigte sonst nur
    // "kann Adresse nicht oeffnen" ohne Grund; Befund 2026-10-01).
    if (path == "/h264") {
        static bool s_h264Note = false;
        if (!s_h264Note) { s_h264Note = true; logEvent("RTSP: /h264 angefragt -- H.264 nicht im Build (HW-Encoder nur P4), 404"); }
        return M_NONE;
    }
#endif
    return M_NONE;
}
static String sdpFor(RtspSession& s, uint8_t mount) {
    String ip = localIpOf(s.fd);
    String sdp = String("v=0\r\no=- ") + String((unsigned long)esp_random()) + " 1 IN IP4 " + ip + "\r\ns=WeirdOS " + (mount == M_H264 ? "H.264" : "MJPEG") +
                 "\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\na=control:*\r\na=range:npt=now-\r\na=tool:WeirdOS\r\n";
    int fps = cameraTargetFps; if (fps < 1) fps = 1;
    if (mount == M_MJPEG) {
        sdp += "m=video 0 RTP/AVP 26\r\na=rtpmap:26 JPEG/90000\r\na=framerate:" + String(fps) + "\r\na=control:track0\r\n";
    } else {
        sdp += "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=fmtp:96 packetization-mode=1";
        if (s_spsLen >= 4 && s_ppsLen) {   // profile-level-id + sprop, sobald einmal bekannt (sonst in-band, RFC 6184 8.2)
            char pl[8]; snprintf(pl, sizeof(pl), "%02X%02X%02X", s_sps[1], s_sps[2], s_sps[3]);
            char sb[192], pb[96]; b64(s_sps, s_spsLen, sb, sizeof(sb)); b64(s_pps, s_ppsLen, pb, sizeof(pb));
            sdp += String(";profile-level-id=") + pl + ";sprop-parameter-sets=" + sb + "," + pb;
        }
        sdp += "\r\na=framerate:" + String(fps) + "\r\na=control:track0\r\n";
    }
    return sdp;
}
static String contentBase(const String& url) { String cb = url; int qi = cb.indexOf('?'); if (qi >= 0) cb = cb.substring(0, qi); if (!cb.endsWith("/")) cb += "/"; return cb; }

// ---- RTSP-Request bearbeiten ---------------------------------------------------------------------
static void handleRequest(RtspSession& s, char* req) {
    char method[16] = {0}, url[200] = {0};
    if (sscanf(req, "%15s %199s", method, url) != 2) { rtspReply(s, 400, "Bad Request", 0, "", "", ""); return; }
    int cseq = hdr(req, "CSeq").toInt();
    s.lastActMs = millis();
    String surl(url);
    if (!strcmp(method, "OPTIONS")) { rtspReply(s, 200, "OK", cseq, "Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, GET_PARAMETER, SET_PARAMETER\r\n", "", ""); return; }
    if (!authOk(req)) { rtspReply(s, 401, "Unauthorized", cseq, "WWW-Authenticate: Basic realm=\"WeirdOS\"\r\n", "", ""); return; }
    if (!strcmp(method, "DESCRIBE")) {
        uint16_t w = 0, h = 0; uint8_t m = mountFromUrl(surl, &w, &h);
        if (m == M_NONE) { rtspReply(s, 404, "Not Found", cseq, "", "", ""); return; }
        if (!cameraReady) { rtspReply(s, 503, "Service Unavailable", cseq, "", "", ""); return; }
        if (m == M_H264 && !H264Encoder::hwAvailable()) { rtspReply(s, 503, "Service Unavailable", cseq, "", "", ""); return; }
        s.mount = m; s.reqW = w; s.reqH = h;
        rtspReply(s, 200, "OK", cseq, "Content-Base: " + contentBase(surl) + "\r\n", sdpFor(s, m), "application/sdp");
        return;
    }
    if (!strcmp(method, "SETUP")) {
        uint16_t w = 0, h = 0; uint8_t m = mountFromUrl(surl, &w, &h);
        if (m == M_NONE) { rtspReply(s, 404, "Not Found", cseq, "", "", ""); return; }
        if (s.playing) { rtspReply(s, 455, "Method Not Valid in This State", cseq, "", "", ""); return; }
        s.mount = m; if (w) s.reqW = w; if (h) s.reqH = h;
        String tr = hdr(req, "Transport"); tr.toLowerCase();
        bool wantTcp = tr.indexOf("rtp/avp/tcp") >= 0 || tr.indexOf("interleaved") >= 0;
        bool wantUdp = !wantTcp && tr.indexOf("rtp/avp") >= 0;
        if (tr.indexOf("multicast") >= 0) { rtspReply(s, 461, "Unsupported Transport", cseq, "", "", ""); return; }
        if (!s.sessionId) s.sessionId = esp_random() | 1;
        s.ssrc = esp_random(); s.seq = (uint16_t)esp_random();
        if (wantTcp) {
            int ii = tr.indexOf("interleaved="); if (ii >= 0) { s.chRtp = (uint8_t)tr.substring(ii + 12).toInt(); s.chRtcp = s.chRtp + 1; }
            s.tcp = true; s.setup = true;
            int one = 1; setsockopt(s.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            rtspReply(s, 200, "OK", cseq, String("Transport: RTP/AVP/TCP;unicast;interleaved=") + s.chRtp + "-" + s.chRtcp + ";ssrc=" + String(s.ssrc, HEX) + "\r\n", "", "");
            return;
        }
        if (wantUdp) {
            if (!s_allowUdp) { rtspReply(s, 461, "Unsupported Transport", cseq, "", "", ""); return; }   // Client faellt auf TCP zurueck
            int cp = tr.indexOf("client_port="); if (cp < 0) { rtspReply(s, 461, "Unsupported Transport", cseq, "", "", ""); return; }
            s.cliRtp = (uint16_t)tr.substring(cp + 12).toInt(); s.cliRtcp = s.cliRtp + 1;
            int a = socket(AF_INET, SOCK_DGRAM, 0), b = socket(AF_INET, SOCK_DGRAM, 0);   // gerader RTP-Port (RFC 3550 11)
            uint16_t base = 0;
            if (a >= 0 && b >= 0) {
                for (uint16_t p = 40000; p < 40040; p += 2) {
                    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa)); sa.sin_family = AF_INET; sa.sin_addr.s_addr = INADDR_ANY; sa.sin_port = htons(p);
                    struct sockaddr_in sb = sa; sb.sin_port = htons(p + 1);
                    if (bind(a, (struct sockaddr*)&sa, sizeof(sa)) == 0 && bind(b, (struct sockaddr*)&sb, sizeof(sb)) == 0) { base = p; break; }
                }
            }
            if (!base) { if (a >= 0) close(a); if (b >= 0) close(b); rtspReply(s, 461, "Unsupported Transport", cseq, "", "", ""); return; }
            s.udpRtp = a; s.udpRtcp = b; s.srvRtp = base; s.tcp = false; s.setup = true;
            rtspReply(s, 200, "OK", cseq, String("Transport: RTP/AVP;unicast;client_port=") + s.cliRtp + "-" + s.cliRtcp + ";server_port=" + base + "-" + (base + 1) + ";ssrc=" + String(s.ssrc, HEX) + "\r\n", "", "");
            return;
        }
        rtspReply(s, 461, "Unsupported Transport", cseq, "", "", "");
        return;
    }
    // Ab hier Sitzung noetig
    String sid = hdr(req, "Session"); int sc = sid.indexOf(';'); if (sc >= 0) sid = sid.substring(0, sc); sid.trim();
    if (!s.setup || (uint32_t)strtoul(sid.c_str(), nullptr, 16) != s.sessionId) {
        if (!strcmp(method, "GET_PARAMETER") || !strcmp(method, "SET_PARAMETER")) { rtspReply(s, 200, "OK", cseq, "", "", ""); return; }
        rtspReply(s, 454, "Session Not Found", cseq, "", "", ""); return;
    }
    if (!strcmp(method, "PLAY")) {
        if (s.mount == M_H264 && g_h264ActiveRef != 0 && playingCount(M_H264) == 0) { rtspReply(s, 503, "Service Unavailable", cseq, "", "", ""); return; }
        s.playing = true; s.lastRtcpMs = 0;
        rtspReply(s, 200, "OK", cseq, "Range: npt=now-\r\nRTP-Info: url=" + contentBase(surl) + "track0;seq=" + s.seq + ";rtptime=" + rtpNow90k() + "\r\n", "", "");
        logEvent(String("RTSP: PLAY ") + (s.mount == M_H264 ? "/h264" : "/mjpeg") + " von " + s.ip + (s.tcp ? " (TCP interleaved)" : " (UDP)"));
        return;
    }
    if (!strcmp(method, "PAUSE"))    { s.playing = false; rtspReply(s, 200, "OK", cseq, "", "", ""); return; }
    if (!strcmp(method, "TEARDOWN")) { rtspReply(s, 200, "OK", cseq, "Connection: close\r\n", "", ""); logEvent(String("RTSP: TEARDOWN von ") + s.ip); closeSession(s); return; }
    if (!strcmp(method, "GET_PARAMETER") || !strcmp(method, "SET_PARAMETER")) { rtspReply(s, 200, "OK", cseq, "", "", ""); return; }
    rtspReply(s, 405, "Method Not Allowed", cseq, "Allow: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, GET_PARAMETER\r\n", "", "");
}

// ---- H.264-Sitzung des Workers (Roh-Ausleihe -> PPA -> Encoder -> RTP) --------------------------
struct H264Rt { bool on = false; PpaConverter* ppa = nullptr; H264Encoder* enc = nullptr; uint16_t tw = 0, th = 0; uint32_t fps = 0; uint16_t restoreW = 0, restoreH = 0; uint32_t lastSeq = 0; int waitMs = 0; uint32_t frames = 0, errs = 0; int64_t statUs = 0; uint32_t statF = 0, statB = 0; };
static H264Rt s_h;
static bool h264Start(uint16_t reqW, uint16_t reqH) {
    if (g_h264ActiveRef != 0) return false;   // HTTP-Pfad/andere Sitzung haelt den Encoder
    uint16_t cw = 0, ch = 0; cameraManager.currentMode(cw, ch);
    uint16_t tw = reqW ? reqW : cw, th = reqH ? reqH : ch;
    tw &= ~15; th &= ~15; if (tw < 160) tw = 160; if (th < 128) th = 128; if (tw > 1920) tw = 1920; if (th > 1088) th = 1088;
    uint16_t rW = 0, rH = 0;
    if (cw < tw || ch < th) {   // Sensor hochschalten wie /video.mp4 (kleinster Modus, der abdeckt)
        CameraVideoMode modes[16]; int nm = cameraManager.enumModes(modes, 16); int best = -1; uint32_t bestPx = 0xFFFFFFFFu;
        for (int i = 0; i < nm; i++) { if (modes[i].width < tw || modes[i].height < th) continue; uint32_t px = (uint32_t)modes[i].width * modes[i].height; if (px < bestPx) { bestPx = px; best = i; } }
        if (best < 0) { logEvent("RTSP H.264: kein Kamera-Modus fuer die Zielgroesse"); return false; }
        rW = cw; rH = ch;
        if (!cameraManager.setMode(modes[best].width, modes[best].height)) { logEvent("RTSP H.264: Kamera-Modus nicht umschaltbar"); return false; }
    }
    uint32_t fps = (uint32_t)cameraTargetFps; if (fps < 1) fps = 1; if (fps > 30) fps = 30;
    g_h264ActiveRef = (size_t)1152 * ((tw + 15) / 16);
    s_h.ppa = new PpaConverter(); s_h.enc = new H264Encoder();
    bool ok = s_h.ppa && s_h.enc && s_h.ppa->begin() && s_h.enc->begin(tw, th, (uint8_t)fps, (uint32_t)h264Kbit * 1000UL, (uint8_t)fps, H264PixFmt::YUV420_OUEV);
    if (!ok) {
        logEvent(String("RTSP H.264: Encoder-Start fehlgeschlagen (err ") + (s_h.enc ? s_h.enc->lastError() : -1) + ")");
        if (s_h.ppa) { s_h.ppa->end(); delete s_h.ppa; s_h.ppa = nullptr; }
        if (s_h.enc) { s_h.enc->end(); delete s_h.enc; s_h.enc = nullptr; }
        g_h264ActiveRef = 0; return false;
    }
    s_h.tw = tw; s_h.th = th; s_h.fps = fps; s_h.restoreW = rW; s_h.restoreH = rH;
    s_h.lastSeq = cameraStream.rawSequence();   // VOR addRawClient lesen (siehe camera_server.cpp)
    cameraStream.addRawClient();
    s_h.waitMs = 0; s_h.frames = 0; s_h.errs = 0; s_h.statUs = esp_timer_get_time(); s_h.statF = 0; s_h.statB = 0; s_h.on = true;
    Serial.printf("RTSP H.264 gestartet: %ux%u @%ufps, %u kbit/s\n", tw, th, (unsigned)fps, (unsigned)h264Kbit);
    return true;
}
static void h264Stop() {
    if (!s_h.on) return;
    cameraStream.removeRawClient();
    if (s_h.ppa) { s_h.ppa->end(); delete s_h.ppa; s_h.ppa = nullptr; }
    if (s_h.enc) { s_h.enc->end(); delete s_h.enc; s_h.enc = nullptr; }
    if (s_h.restoreW && s_h.restoreH) { uint16_t cw = 0, ch = 0; cameraManager.currentMode(cw, ch); if (cw != s_h.restoreW || ch != s_h.restoreH) cameraManager.setMode(s_h.restoreW, s_h.restoreH); }
    g_h264StatFps = 0; g_h264StatKbit = 0; g_h264StatSkips = 0;
    g_h264ActiveRef = 0; s_h.on = false;
    Serial.printf("RTSP H.264 beendet (%u Frames, %u Encode-Fehler)\n", (unsigned)s_h.frames, (unsigned)s_h.errs);
}
// Ein Schritt: liegt ein neuer Rohframe vor -> encodieren + senden.
static void h264Step() {
    if (cameraStream.rawSequence() == s_h.lastSeq) {
        if (++s_h.waitMs > 2500) { s_h.waitMs = 0; logEvent("RTSP H.264: ~5 s kein Rohframe vom Verteiler"); }
        return;
    }
    s_h.waitMs = 0;
    const CameraFrame* f = cameraStream.rawBorrowLatest(&s_h.lastSeq);
    if (!f || !f->data || f->pixelFormat != CAMERA_PIXEL_FORMAT_RGB565) { if (f) cameraStream.rawReturn(); return; }
    const uint8_t* yuv = nullptr; size_t yuvLen = 0;
    bool pOk = s_h.ppa->rgb565ToYuv420(f->data, f->width, f->height, s_h.tw, s_h.th, &yuv, &yuvLen);
    const uint8_t* nal = nullptr; size_t nalLen = 0; bool key = false;
    bool eOk = pOk && s_h.enc->encode(yuv, yuvLen, &nal, &nalLen, &key);
    cameraStream.rawReturn();
    if (!eOk || nalLen == 0) { if (pOk) { s_h.enc->forceIdr(); s_h.errs++; } return; }
    h264SendAu(nal, nalLen, rtpNow90k());
    s_h.frames++; s_h.statF++; s_h.statB += (uint32_t)nalLen;
    int64_t now = esp_timer_get_time();
    if (now - s_h.statUs >= 1000000LL) { double sec = (double)(now - s_h.statUs) / 1e6; g_h264StatFps = (uint32_t)(s_h.statF / sec + 0.5); g_h264StatKbit = (uint32_t)(s_h.statB * 8.0 / sec / 1000.0 + 0.5); s_h.statUs = now; s_h.statF = 0; s_h.statB = 0; }
}

// ---- Server ------------------------------------------------------------------------------------
bool RtspServer::begin(uint16_t port, bool allowUdp) {
    if (!s_lock) s_lock = xSemaphoreCreateMutex();
    if (!s_pkt)  s_pkt  = (uint8_t*)heap_caps_malloc(s_pktCap, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_sess) s_sess = (RtspSession*)heap_caps_calloc(RTSP_MAX_SESSIONS, sizeof(RtspSession), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_pkt || !s_sess || !s_lock) { Serial.println("RTSP: kein PSRAM/Mutex fuer den Server"); return false; }
    for (int i = 0; i < RTSP_MAX_SESSIONS; i++) new (&s_sess[i]) RtspSession();
    allowUdp_ = allowUdp; s_allowUdp = allowUdp; port_ = port;
    if (listenFd_ >= 0) return true;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { Serial.println("RTSP: socket() fehlgeschlagen"); return false; }
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa)); sa.sin_family = AF_INET; sa.sin_addr.s_addr = INADDR_ANY; sa.sin_port = htons(port);
    if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0 || listen(fd, 2) != 0) { Serial.printf("RTSP: Port %u nicht belegbar\n", (unsigned)port); close(fd); return false; }
    int fl = fcntl(fd, F_GETFL, 0); fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    listenFd_ = fd;
    Serial.printf("RTSP-Server auf Port %u (rtsp://<ip>:%u/mjpeg, /h264; Transport %s).\n", (unsigned)port, (unsigned)port, allowUdp ? "TCP+UDP" : "nur TCP interleaved");
    return true;
}
void RtspServer::stop() {
    if (s_lock) xSemaphoreTake(s_lock, portMAX_DELAY);
    if (s_sess) for (int i = 0; i < RTSP_MAX_SESSIONS; i++) if (s_sess[i].used) closeSession(s_sess[i]);
    if (listenFd_ >= 0) { close(listenFd_); listenFd_ = -1; }
    if (s_lock) xSemaphoreGive(s_lock);
}
int RtspServer::clientCount() const { return s_sess ? usedCount() : 0; }

bool RtspServer::acceptOne() {
    struct sockaddr_in6 a; socklen_t al = sizeof(a);
    int fd = accept(listenFd_, (struct sockaddr*)&a, &al);
    if (fd < 0) return false;
    char ip[48] = {0};
    if (a.sin6_family == AF_INET) inet_ntop(AF_INET, &((struct sockaddr_in*)&a)->sin_addr, ip, sizeof(ip));
    else { inet_ntop(AF_INET6, &a.sin6_addr, ip, sizeof(ip)); const char* m = strstr(ip, "::ffff:"); if (m) memmove(ip, m + 7, strlen(m + 7) + 1); }
    int limit = multiStreamEnabled ? RTSP_MAX_SESSIONS : 1;
    if (!accessAllowed("stream", String(ip))) { logEvent(String("RTSP: Zugriff aus Zone verweigert: ") + ip); close(fd); return false; }
    if (usedCount() >= limit) { const char* m = "RTSP/1.0 503 Service Unavailable\r\nCSeq: 0\r\n\r\n"; send(fd, m, strlen(m), 0); close(fd); return false; }
    RtspSession* s = nullptr; for (int i = 0; i < RTSP_MAX_SESSIONS; i++) if (!s_sess[i].used) { s = &s_sess[i]; break; }
    if (!s) { close(fd); return false; }
    *s = RtspSession(); s->used = true; s->fd = fd; strlcpy(s->ip, ip, sizeof(s->ip)); s->lastActMs = millis();
    memset(&s->cliAddr, 0, sizeof(s->cliAddr)); s->cliAddr.sin_family = AF_INET;
    if (a.sin6_family == AF_INET) s->cliAddr.sin_addr = ((struct sockaddr_in*)&a)->sin_addr; else inet_pton(AF_INET, ip, &s->cliAddr.sin_addr);
    struct timeval tv = { 3, 0 }; setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int fl = fcntl(fd, F_GETFL, 0); fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    s_totalClients++;
    Serial.printf("RTSP: Client %s verbunden\n", ip);
    return true;
}
static void rtspTaskTrampoline(void*) { rtspServer.taskLoop(); vTaskDelete(nullptr); }
bool RtspServer::startWorker() {
    if (taskRunning_) return true;
    taskRunning_ = true;
    // Interner Stack (PPA/HW-Encoder wie der H.264-Worker des HTTP-Pfads), Core 1, Prio 3.
    if (xTaskCreatePinnedToCore(rtspTaskTrampoline, "rtsp", 16384, nullptr, tskIDLE_PRIORITY + 3, nullptr, 1) != pdPASS) {
        taskRunning_ = false;
        Serial.printf("RTSP: Worker-Task nicht anlegbar (intern frei %uk)\n", (unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024));
        return false;
    }
    return true;
}
void RtspServer::poll() {
    if (listenFd_ < 0 || taskRunning_) return;
    static uint32_t last = 0; uint32_t now = millis(); if (now - last < 100) return; last = now;
    if (!s_lock || xSemaphoreTake(s_lock, 0) != pdTRUE) return;
    if (acceptOne() && !startWorker()) { for (int i = 0; i < RTSP_MAX_SESSIONS; i++) if (s_sess[i].used) closeSession(s_sess[i]); }
    xSemaphoreGive(s_lock);
}

void RtspServer::taskLoop() {
    uint32_t idleSince = millis();
    for (;;) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
        // ---- Kontrollkanal: select ueber Listener + Sitzungen (+ UDP-RTCP zum Leeren) ----
        fd_set rf; FD_ZERO(&rf); int maxfd = listenFd_; if (listenFd_ >= 0) FD_SET(listenFd_, &rf);
        for (int i = 0; i < RTSP_MAX_SESSIONS; i++) { RtspSession& s = s_sess[i]; if (!s.used) continue; FD_SET(s.fd, &rf); if (s.fd > maxfd) maxfd = s.fd; if (s.udpRtcp >= 0) { FD_SET(s.udpRtcp, &rf); if (s.udpRtcp > maxfd) maxfd = s.udpRtcp; } }
        bool media = playingCount(M_MJPEG) > 0 || playingCount(M_H264) > 0;
        struct timeval tv; tv.tv_sec = 0; tv.tv_usec = media ? 2000 : 50000;
        int r = select(maxfd + 1, &rf, nullptr, nullptr, &tv);
        if (r > 0) {
            if (listenFd_ >= 0 && FD_ISSET(listenFd_, &rf)) acceptOne();
            for (int i = 0; i < RTSP_MAX_SESSIONS; i++) {
                RtspSession& s = s_sess[i];
                if (!s.used) continue;
                if (s.udpRtcp >= 0 && FD_ISSET(s.udpRtcp, &rf)) { uint8_t dump[64]; recv(s.udpRtcp, dump, sizeof(dump), 0); }
                if (!FD_ISSET(s.fd, &rf)) continue;
                int n = recv(s.fd, s.rx + s.rxLen, RTSP_RX_MAX - 1 - s.rxLen, 0);
                if (n <= 0) { if (n == 0 || errno != EWOULDBLOCK) { Serial.printf("RTSP: Client %s getrennt\n", s.ip); closeSession(s); } continue; }
                s.rxLen += (size_t)n; s.rx[s.rxLen] = 0;
                // Interleaved RTCP vom Client ('$' ch len ...) verwerfen
                while (s.rxLen && s.rx[0] == '$') { if (s.rxLen < 4) break; size_t l = 4 + (((size_t)(uint8_t)s.rx[2] << 8) | (uint8_t)s.rx[3]); if (s.rxLen < l) break; memmove(s.rx, s.rx + l, s.rxLen - l); s.rxLen -= l; s.rx[s.rxLen] = 0; }
                char* end;
                while (s.used && (end = strstr(s.rx, "\r\n\r\n")) != nullptr) {
                    size_t reqLen = (size_t)(end - s.rx) + 4;
                    int cl = hdr(s.rx, "Content-Length").toInt(); if (cl > 0) { if (s.rxLen < reqLen + (size_t)cl) break; reqLen += (size_t)cl; }
                    char save = s.rx[reqLen]; s.rx[reqLen] = 0;
                    handleRequest(s, s.rx);
                    if (!s.used) break;
                    s.rx[reqLen] = save; memmove(s.rx, s.rx + reqLen, s.rxLen - reqLen); s.rxLen -= reqLen; s.rx[s.rxLen] = 0;
                }
                if (s.used && s.rxLen >= RTSP_RX_MAX - 1) closeSession(s);   // Muell/zu lang
            }
        }
        // ---- Sitzungs-Timeout (nur UDP: TCP meldet den Abbruch selbst) ----
        uint32_t now = millis();
        for (int i = 0; i < RTSP_MAX_SESSIONS; i++) { RtspSession& s = s_sess[i]; if (s.used && !s.tcp && s.setup && now - s.lastActMs > (RTSP_TIMEOUT_S + 30) * 1000UL) { logEvent(String("RTSP: Sitzung ") + s.ip + " ohne Keepalive -> beendet"); closeSession(s); } }

        // ---- Medien ----
        int nJ = playingCount(M_MJPEG), nH = playingCount(M_H264);
        if (nJ > 0 && !s_jpegConsumer) { s_jpgSeq = cameraStream.latestSequence(); cameraStream.addClient(); s_jpegConsumer = true; }
        if (nJ == 0 && s_jpegConsumer) { cameraStream.removeClient(); s_jpegConsumer = false; }
        if (nJ > 0) {
            size_t len = cameraStream.copyLatest(&s_jpg, &s_jpgCap, &s_jpgSeq);
            if (len > 0) {
                JpegInfo j = jpegParse(s_jpg, len);
                if (!j.ok) { static uint32_t lastWarn = 0; if (now - lastWarn > 10000) { lastWarn = now; logEvent(String("RTSP MJPEG: Frame nicht RTP/JPEG-faehig: ") + j.err); } }
                else { uint32_t ts = rtpNow90k(); for (int i = 0; i < RTSP_MAX_SESSIONS; i++) { RtspSession& s = s_sess[i]; if (s.used && s.playing && s.mount == M_MJPEG) { if (!rtpSendJpeg(s, j, ts)) { logEvent(String("RTSP: Senden an ") + s.ip + " fehlgeschlagen (MJPEG)"); closeSession(s); } } } }
            }
        }
        if (nH > 0 && !s_h.on) {
            uint16_t w = 0, h = 0; for (int i = 0; i < RTSP_MAX_SESSIONS; i++) if (s_sess[i].used && s_sess[i].playing && s_sess[i].mount == M_H264) { w = s_sess[i].reqW; h = s_sess[i].reqH; break; }
            if (!h264Start(w, h)) { for (int i = 0; i < RTSP_MAX_SESSIONS; i++) if (s_sess[i].used && s_sess[i].playing && s_sess[i].mount == M_H264) closeSession(s_sess[i]); }
        }
        if (nH == 0 && s_h.on) h264Stop();
        if (s_h.on) { if (g_h264Stop) { h264Stop(); for (int i = 0; i < RTSP_MAX_SESSIONS; i++) if (s_sess[i].used && s_sess[i].mount == M_H264) closeSession(s_sess[i]); } else h264Step(); }
        // ---- RTCP Sender Reports ----
        for (int i = 0; i < RTSP_MAX_SESSIONS; i++) { RtspSession& s = s_sess[i]; if (s.used && s.playing && (s.lastRtcpMs == 0 || now - s.lastRtcpMs > RTCP_INTERVAL_MS)) rtcpSenderReport(s); }

        int nc = usedCount();
        if (nc) idleSince = now;
        xSemaphoreGive(s_lock);
        if (!nc && now - idleSince > RTSP_IDLE_EXIT_MS) break;
        if (!media) vTaskDelay(pdMS_TO_TICKS(5));
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (s_h.on) h264Stop();
    if (s_jpegConsumer) { cameraStream.removeClient(); s_jpegConsumer = false; }
    taskRunning_ = false;
    xSemaphoreGive(s_lock);
    Serial.println("RTSP: Worker beendet (keine Clients)");
}

String RtspServer::statusJson() {
    String j = String("{\"running\":") + (running() ? "true" : "false") + ",\"port\":" + port_ + ",\"udp\":" + (allowUdp_ ? "true" : "false") +
               ",\"worker\":" + (taskRunning_ ? "true" : "false") + ",\"totalClients\":" + s_totalClients + ",\"h264\":" + (s_h.on ? "true" : "false") + ",\"clients\":[";
    bool first = true;
    if (s_sess) for (int i = 0; i < RTSP_MAX_SESSIONS; i++) {
        RtspSession& s = s_sess[i];
        if (!s.used) continue;
        if (!first) j += ","; first = false;
        j += String("{\"ip\":\"") + s.ip + "\",\"mount\":\"" + (s.mount == M_H264 ? "h264" : s.mount == M_MJPEG ? "mjpeg" : "-") + "\",\"transport\":\"" + (s.tcp ? "tcp" : "udp") + "\",\"playing\":" + (s.playing ? "true" : "false") + ",\"packets\":" + s.pkts + ",\"bytes\":" + s.octets + "}";
    }
    j += "]}";
    return j;
}
String RtspServer::statusText() {
    String t = String("rtsp  : ") + (running() ? "laeuft" : "aus") + " Port " + port_ + " Transport " + (allowUdp_ ? "TCP+UDP" : "nur TCP") + " Worker " + (taskRunning_ ? "aktiv" : "ruht") + " Clients " + clientCount() + "\r\n";
    if (s_sess) for (int i = 0; i < RTSP_MAX_SESSIONS; i++) { RtspSession& s = s_sess[i]; if (s.used) t += String("  ") + s.ip + " " + (s.mount == M_H264 ? "/h264" : "/mjpeg") + " " + (s.tcp ? "tcp" : "udp") + (s.playing ? " PLAY" : " ") + " Pakete " + s.pkts + " Bytes " + s.octets + "\r\n"; }
    return t;
}

#else
// ============================================================================
// Stub: nicht im Build enthalten (WEIRDOS_FEATURE_RTSP=0).
// Dieselben Symbole wie oben, triviale Koerper: die Querkonsumenten (Composition Root,
// Konsole) referenzieren rtspServer und muessen weiter linken. Kein Socket, kein Task,
// kein PSRAM -- sockets/FreeRTOS/Encoder werden hier nicht einmal eingebunden, der
// Linker wirft den ganzen Rest heraus. running()/workerRunning() (inline im Header)
// melden ueber die Vorgaben listenFd_=-1 / taskRunning_=false korrekt "aus".
// ============================================================================
RtspServer rtspServer;

bool   RtspServer::begin(uint16_t, bool) { Serial.println("RTSP: nicht im Build enthalten (WEIRDOS_FEATURE_RTSP=0)"); return false; }
void   RtspServer::stop() {}
void   RtspServer::poll() {}
void   RtspServer::taskLoop() {}
int    RtspServer::clientCount() const { return 0; }
String RtspServer::statusJson() { return String("{\"ok\":false,\"builtIn\":false,\"error\":\"RTSP nicht im Build enthalten (WEIRDOS_FEATURE_RTSP=0)\"}"); }
String RtspServer::statusText() { return String("RTSP: nicht im Build enthalten"); }
// Private Helfer: nie aufgerufen, aber definiert -- das Klassenlayout ist mit dem Header geteilt.
bool   RtspServer::acceptOne()   { return false; }
bool   RtspServer::startWorker() { return false; }
#endif
