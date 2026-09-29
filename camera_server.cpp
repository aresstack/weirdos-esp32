// ============================================================================
// camera_server.cpp -- Kamera-HTTP: MJPEG-Stream-Server (eigener esp_http_server
// auf streamPort/streamPath) + /capture-Handler (Port-80-Route, hierher delegiert).
//
// Reine Code-Verschiebung aus der .ino: Verhalten, Auth, WAN-Schutz, Cache-Header,
// Stream-Key, Multi-Client-Limit und Async-Tasks sind identisch. "Ein Frame fuer
// alle": der zentrale Capture-Task lebt in CameraStreamService; die HTTP-Stream-
// Tasks unten sind reiner Transport (addClient/copyLatest/removeClient).
// ============================================================================
#include "weirdos_features.h"     // WEIRDOS_FEATURE_VIDEO_HTTP -- der Schalter dieses Bausteins
#include "camera_server.h"        // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
#if WEIRDOS_FEATURE_VIDEO_HTTP
#include "web_ui.h"                // server, streamKey/streamEnabled/multiStreamEnabled/
                                   // streamPort/streamPath, cameraReady, sendNoCacheHeaders,
                                   // isAuthenticated
#include "camera_stream_service.h" // globaler Verteiler cameraStream (FrameSource-basiert)
#include "camera_manager.h"        // cameraManager (Modus-Wahl fuer H.264; Frames kommen ueber cameraStream)
#include "ppa_converter.h"         // RGB565 -> YUV420 (HW)
#include "access_policy.h"         // Zugangsregel je Dienst: Stream im VPN / Internet freigegeben?
#include <sys/socket.h>
#include <arpa/inet.h>
#include "h264_encoder.h"          // YUV420 -> H.264-NAL (HW)
#include "h264_fmp4.h"             // NAL -> fragmentiertes MP4 (Browser/MSE)
#include "h264_guard.h"            // exklusive Video-Reserve (alle internen Encoder-Puffer) + Cache-Sync-Fehlerzaehler
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"         // vTaskDelay
#include "freertos/queue.h"        // Job-Queue des dauerhaften H.264-Workers

#include <esp_heap_caps.h>
#if WEIRDOS_FEATURE_TLS_SERVER
#include <esp_https_server.h>      // Phase-1-TLS-PoC: HTTPS-MJPEG-Stream (httpd_ssl_*)
#endif
#include "tls_selfsigned.h"        // On-Device self-signed Cert/Key (kein Git-Secret)
#include <cstring>
#include <cstdio>
#include <cstdlib>   // atoi/malloc/free (Query-Parsing ?w=&h=)
#include <esp_timer.h>   // esp_timer_get_time (echte Frame-Dauer fuer fMP4-Timestamps)
#include "lwip/sockets.h" // setsockopt TCP_NODELAY auf dem H.264-Stream-Socket (Latenz)

CameraServer cameraServer;

// Vom H.264-Handler gesetzt: interner ref-Puffer des laufenden Streams -> der Descriptor rechnet ihn
// bei der Aufloesungs-Verfuegbarkeit zurueck (sonst waehrend des Streams alles ausgegraut).
extern volatile size_t g_h264ActiveRef;
extern volatile bool   g_h264Stop;   // neuer Request signalisiert dem laufenden H.264-Task das Ende

static const int MAX_STREAM_CLIENTS = 3;

static const char* STREAM_CONTENT_TYPE =
    "multipart/x-mixed-replace;boundary=frame";

static const char* STREAM_BOUNDARY = "\r\n--frame\r\n";

static const char* STREAM_PART_HEADER =
    "Content-Type: image/jpeg\r\nContent-Length: %u\r\n\r\n";


// Sendet die publizierten Frames an einen einzelnen Client. Kopiert den
// gemeinsamen Puffer vor dem Senden, damit der Verteiler waehrend des
// (langsamen) WLAN-Sendens nicht blockiert wird.
static void mjpegStreamTask(void* argument) {
    httpd_req_t* request = (httpd_req_t*)argument;

    char partHeader[64];
    uint8_t* clientBuffer = NULL;
    size_t clientCapacity = 0;
    // Zusammenhaengender Sendepuffer (Boundary+Header+JPEG) -> EIN Send pro Frame.
    // Unter TLS entscheidend: statt 3 winziger Records (Boundary 11B / Header ~35B /
    // JPEG) je mit GCM-Tag + HW-AES-Interrupt + eigenem TCP-Segment, wird alles ein
    // zusammenhaengender Datenstrom, den mbedTLS in effiziente 16-KB-Records teilt.
    uint8_t* sendBuffer = NULL;
    size_t sendCapacity = 0;
    const size_t boundaryLen = strlen(STREAM_BOUNDARY);
    size_t frameLength = 0;
    uint32_t lastSequence = 0;
    int32_t waitedForFrameMs = 0;
    uint32_t framesSent = 0;   // Diagnose: wie viele Frames kamen durch, bevor der Transport abriss

    httpd_resp_set_type(
        request,
        STREAM_CONTENT_TYPE
    );

    httpd_resp_set_hdr(
        request,
        "Cache-Control",
        "no-store"
    );

    Serial.print("MJPEG stream client connected (");
    Serial.print(cameraStream.clientCount());
    Serial.println(" active).");

    while (true) {
        // Auf einen neuen Frame des Verteilers warten.
        if (cameraStream.latestSequence() == lastSequence) {
            vTaskDelay(pdMS_TO_TICKS(5));

            waitedForFrameMs += 5;

            if (waitedForFrameMs >= 5000) {
                Serial.println("MJPEG stream: no frames from distributor.");
                // DIAGNOSE: 5 s kein neuer Frame -> der Kamera-Capture-Task liefert nichts
                // (SVGA-Capture scheitert transient) -- NICHT die Stream-Puffer. Trennt die
                // beiden Hypothesen in EINEM Repro.
                logEvent("Kamera-Stream: 5s kein neuer Frame vom Verteiler -> Kamera liefert nicht");
                break;
            }

            continue;
        }

        waitedForFrameMs = 0;

        // Neuesten Frame holen; copyLatest prueft Groesse, WAECHST den Client-Puffer bei
        // Bedarf und kopiert -- alles UNTER EINEM Lock. Damit kann sich len_ zwischen
        // Groessenpruefung und memcpy nicht mehr aendern (frueher fror der HD-Stream hier
        // lautlos ein: latestLen()-Snapshot < aktuelles len_ beim Kopieren -> Frame passte
        // nicht -> copyLatest=0, ohne realloc-Fehler und ohne 5s-Timeout).
        frameLength = cameraStream.copyLatest(&clientBuffer, &clientCapacity, &lastSequence);

        if (frameLength == 0) {
            // kein neuer Frame passte (zu klein/Wettlauf) -> kurz warten, neu.
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }

        int headerLength = snprintf(
            partHeader,
            sizeof(partHeader),
            STREAM_PART_HEADER,
            frameLength
        );

        // Boundary + Part-Header + JPEG in EINEN zusammenhaengenden Puffer legen und
        // mit einem einzigen send_chunk rausschicken (siehe sendBuffer-Kommentar oben).
        size_t needLen = boundaryLen + (size_t)headerLength + frameLength;
        if (needLen > sendCapacity) {
            uint8_t* grown = (uint8_t*)heap_caps_realloc(sendBuffer, needLen, MALLOC_CAP_SPIRAM);
            if (grown) { sendBuffer = grown; sendCapacity = needLen; }
        }
        if (needLen > sendCapacity) {
            // PSRAM gab den zusammenhaengenden Block nicht her -> Frame ueberspringen,
            // Verbindung offen lassen (naechster Frame ist evtl. kleiner).
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        memcpy(sendBuffer, STREAM_BOUNDARY, boundaryLen);
        memcpy(sendBuffer + boundaryLen, partHeader, headerLength);
        memcpy(sendBuffer + boundaryLen + headerLength, clientBuffer, frameLength);

        unsigned long tSend = millis();
        esp_err_t rF = httpd_resp_send_chunk(request, (const char*)sendBuffer, needLen);
        unsigned long sendMs = millis() - tSend;
        framesSent++;

        if (rF != ESP_OK) {
            // ESP_ERR_HTTPD_RESP_SEND (0xB006) = der Browser hat die Verbindung geschlossen
            // (Tab-Wechsel/Stop/Reconnect) -> NORMALES Stream-Ende, nicht loggen. Nur andere
            // Codes sind echte Fehler.
            esp_err_t err = rF;
            if (err != ESP_ERR_HTTPD_RESP_SEND) {
                logEvent(String("Kamera-Stream: Sendefehler 0x") + String((unsigned)err, HEX)
                    + " nach " + String((unsigned long)framesSent) + " Frames, Frame "
                    + String((unsigned)(frameLength / 1024)) + "k");
            }
            break;
        }

        // Nur auffaellig langsame Sends melden (>800 ms). Interner Heap mitloggen: ist der
        // groesste Block dabei winzig -> WiFi-TX-DMA-Hunger (Speicher). Ist er komfortabel ->
        // der Sendepuffer staut aus einem anderen Grund (lwIP-/Funk-Contention, nicht Speicher).
        if (sendMs > 800) {
            logEvent(String("Kamera-Stream: langsamer Send ") + String(sendMs) + "ms, Frame "
                + String((unsigned)(frameLength / 1024)) + "k nach " + String((unsigned long)framesSent)
                + " Frames | intern frei "
                + String((unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024)) + "k groesster "
                + String((unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) / 1024)) + "k");
        }
    }

    if (clientBuffer != NULL) {
        heap_caps_free(clientBuffer);
    }
    if (sendBuffer != NULL) {
        heap_caps_free(sendBuffer);
    }

    httpd_req_async_handler_complete(request);

    cameraStream.removeClient();

    Serial.print("MJPEG stream client disconnected (");
    Serial.print(cameraStream.clientCount());
    Serial.println(" active).");

    vTaskDelete(NULL);
}


// Liest einen Query-Parameter aus der Roh-URL des esp_http_server.
static bool streamQueryKeyMatches(httpd_req_t* request) {
    if (streamKey.length() == 0) {
        return true;
    }

    size_t qlen = httpd_req_get_url_query_len(request) + 1;

    if (qlen <= 1) {
        return false;
    }

    char* query = (char*)malloc(qlen);

    if (query == NULL) {
        return false;
    }

    bool ok = false;

    if (httpd_req_get_url_query_str(request, query, qlen) == ESP_OK) {
        char value[64];

        if (httpd_query_key_value(query, "key", value, sizeof(value)) == ESP_OK) {
            ok = (streamKey == value);
        }
    }

    free(query);
    return ok;
}


// Zugangsregel (access_policy): Stream aus der Zone des Aufrufers (LAN/VPN/Internet) freigegeben?
// Nur ein Gate am Handler-Eingang -- der MJPEG-Datenpfad selbst bleibt unangetastet.
static bool streamZoneAllowed(httpd_req_t* request) {
    int fd = httpd_req_to_sockfd(request);
    struct sockaddr_in6 a; socklen_t al = sizeof(a);
    if (fd < 0 || getpeername(fd, (struct sockaddr*)&a, &al) != 0) return false;
    char ip[48] = {0};
    if (a.sin6_family == AF_INET) inet_ntop(AF_INET, &((struct sockaddr_in*)&a)->sin_addr, ip, sizeof(ip));
    else { inet_ntop(AF_INET6, &a.sin6_addr, ip, sizeof(ip)); const char* m = strstr(ip, "::ffff:"); if (m) memmove(ip, m + 7, strlen(m + 7) + 1); }
    return accessAllowed("stream", String(ip));
}
static esp_err_t sendZoneDenied(httpd_req_t* request) {
    httpd_resp_set_status(request, "403 Forbidden");
    httpd_resp_set_type(request, "text/plain");
    httpd_resp_send(request, "Videostream aus dieser Zone nicht freigegeben (System > Sicherheit > Zugriff je Dienst).", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t handleMjpegStream(httpd_req_t* request) {
    if (!streamZoneAllowed(request)) return sendZoneDenied(request);
    if (!streamQueryKeyMatches(request)) {
        httpd_resp_set_status(request, "403 Forbidden");
        httpd_resp_set_type(request, "text/plain");
        httpd_resp_send(request, "Stream-Schluessel erforderlich.",
                        HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    int allowedClients = multiStreamEnabled ? MAX_STREAM_CLIENTS : 1;

    if (cameraStream.clientCount() >= allowedClients) {
        httpd_resp_set_status(request, "503 Service Unavailable");
        httpd_resp_set_type(request, "text/plain");

        httpd_resp_send(
            request,
            multiStreamEnabled
                ? "Zu viele gleichzeitige Streams."
                : "Stream bereits belegt. Mehrfach-Streams lassen sich in "
                  "der Kamera-Konfiguration aktivieren.",
            HTTPD_RESP_USE_STRLEN
        );

        return ESP_OK;
    }

    httpd_req_t* asyncRequest = NULL;

    if (httpd_req_async_handler_begin(request, &asyncRequest) != ESP_OK) {
        return ESP_FAIL;
    }

    cameraStream.addClient();   // +1 Consumer; startet den Verteiler-Task bei Bedarf

    BaseType_t created = xTaskCreate(
        mjpegStreamTask,
        "mjpeg_client",
        8192,
        asyncRequest,
        tskIDLE_PRIORITY + 1,
        NULL
    );

    if (created != pdPASS) {
        cameraStream.removeClient();

        httpd_req_async_handler_complete(asyncRequest);

        return ESP_FAIL;
    }

    return ESP_OK;
}


// ---------------------------------------------------------------------------
// H.264-fMP4-Stream (Browser/MSE): ISP-RGB565 -> PPA(YUV420) -> HW-H.264 -> fMP4.
// Blockierender Handler auf Port 81 (Video-Server) -> blockiert NUR den Video-Server, nie die
// Management-UI (Port 80, eigener esp_http_server). Ein Client (der einzige Kamera-Rohpfad).
// Testaufloesung 320x240 (passt in den aktuellen internen Heap; PPA skaliert von 800x800 herunter).
// Voraussetzung: KEIN aktiver MJPEG-Stream (der belegt sonst den einzigen Kamera-Puffer).
// ---------------------------------------------------------------------------
// Argumente an den H.264-Worker-Task (heap-alloziert, im Task freigegeben).
// restoreW/H: Kamera-Modus, der VOR dem automatischen Hochschalten aktiv war (0 = nicht geschaltet).
// Der Task schaltet am Stream-Ende dorthin zurueck -- der Sensor laeuft nur fuer die Dauer eines
// H.264-Streams, der ihn braucht, in FHD. Vorher (seit 13dbda0) blieb er dauerhaft in FHD: MJPEG,
// ISP-Datenrate (x3,2) und alle PPA-Skalierungen liefen danach aus 1920x1080 statt aus dem
// konfigurierten Modus -- genau ab da traten der 320x320-Muell (PPA rundet ungerade 1/16-Brueche
// fuer YUV420 ab) und die P-Frame-Artefakte in Folgesitzungen auf.
struct H264StreamArgs { httpd_req_t* req; uint16_t tw; uint16_t th; uint32_t fps; uint16_t restoreW; uint16_t restoreH; };

// Der eigentliche H.264-Stream laeuft in EINEM EIGENEN Task (wie mjpegStreamTask), NICHT im
// geteilten Port-81-httpd-Task. Kritisch: der blockierende while(true)-Loop darf den httpd-Task
// nicht belegen -- sonst haengt nach einem Client-Abbruch der ganze Port 81 (MJPEG + H.264 tot,
// nur /capture auf Port 80 geht) bis zum Powercycle. So bleibt der httpd-Task immer frei.
// Eine H.264-Sitzung (ein Client) -- laeuft im dauerhaften Worker-Task h264WorkerTask (unten), NICHT
// mehr in einem je Verbindung neu erzeugten Task: das Anlegen eines 16-KB-Stacks aus dem internen
// Heap scheiterte beim schnellen Reconnect sporadisch (alter Stack noch nicht vom Idle-Task
// freigegeben, Haupt-Heap nach der Video-Reserve nur ~49 KB am Stueck) -> ESP_FAIL -> Socket zu ->
// "H.264-Verbindung fehlgeschlagen" ohne Spur im Log. Der Worker wird EINMAL beim Boot angelegt.
static void h264RunSession(H264StreamArgs* a) {
    httpd_req_t* request = a->req;
    uint16_t tw = a->tw, th = a->th; uint32_t fps = a->fps;
    uint16_t restoreW = a->restoreW, restoreH = a->restoreH;
    free(a);

    PpaConverter ppa;
    H264Encoder  enc;
    Fmp4Muxer    mux;
    // Referenzpuffer: der Encoder alloziert intern (enc.begin -> esp_h264_enc_hw_new); die Boot-Reserve
    // ist eine eigene Heap-Region (h264_guard.h), auf die heap_caps_malloc genau fuer diesen grossen
    // Block ausweicht -- nichts freizugeben, nichts zurueckzuholen.
    // Ziel-Bitrate aus der Konfiguration (Server > Video > Stream), NICHT fest: der LTE-Uplink
    // (Cat-4, gemessen 6-8 Mbit/s) soll ausgenutzt werden; bei Stau regelt die adaptive Bildrate.
    uint32_t bitrate = (uint32_t)h264Kbit * 1000UL;
    bool begun = ppa.begin() &&
                 enc.begin(tw, th, (uint8_t)fps, bitrate, (uint8_t)fps, H264PixFmt::YUV420_OUEV);
    if (!begun || !mux.begin(tw, th, 90000, fps)) {
        int err = enc.lastError();
        ppa.end(); enc.end(); mux.end();
        g_h264ActiveRef = 0;
        httpd_resp_set_status(request, "503 Service Unavailable");
        httpd_resp_set_type(request, "text/plain");
        char msg[112];
        snprintf(msg, sizeof(msg),
                 "H.264 %ux%u passt nicht in den internen Heap (err %d). Diagnose > Heap-Map: H.264-Reserve setzen.",
                 tw, th, err);
        httpd_resp_send(request, msg, HTTPD_RESP_USE_STRLEN);
        httpd_req_async_handler_complete(request);
        return;   // zurueck in die Job-Schleife des Workers
    }

    httpd_resp_set_type(request, "video/mp4");
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    // UI auf Port 80, Stream auf Port 81 -> Cross-Origin. Das MJPEG-<img> darf das CORS-frei, der
    // MSE-fetch() NICHT -> ohne diesen Header lehnt der Browser ab ("Verbindung fehlgeschlagen").
    httpd_resp_set_hdr(request, "Access-Control-Allow-Origin", "*");
    // Latenz: TCP_NODELAY. Ohne das haelt Nagle den Rest jedes Frame-Segments zurueck, bis das ACK des
    // vorigen Segments da ist -- ueber LTE 50-100 ms je Frame, die sich als Verzoegerung aufaddieren.
    {
        int fd = httpd_req_to_sockfd(request);
        int one = 1;
        if (fd >= 0) setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }

    Serial.printf("H264 fMP4 stream client connected (%ux%u @%ufps, %u kbit/s).\n",
                  tw, th, (unsigned)fps, (unsigned)(bitrate / 1000));
    bool initSent = false;
    uint32_t framesSent = 0;
    int64_t lastFrameUs = 0;
    esp_err_t rc = ESP_OK;

    // DERSELBE Verteiler wie der MJPEG-Pfad (CameraStreamService): der Capture-Task ist der einzige
    // Besitzer der Kamera, taktet auf die Ziel-Bildrate und setzt die globale Frame-Politik um
    // (veraltete Frames verwerfen ja/nein -- Server > Video > Bild). Dieser Task ist wie der MJPEG-
    // Client reiner Transport: auf einen neuen Frame warten, holen, verarbeiten, senden. Roh-Kanal =
    // zero-copy (der Verteiler haelt die Ausleihe, bis rawReturn()). Timestamps sind Wanduhr
    // (durTicks) -> variable Bildrate ist fuer MSE unkritisch.
    // REIHENFOLGE IST ENTSCHEIDEND (Log 03.09.2026 02:10, "5s kein neuer Rohframe", 0 Segmente):
    // lastSequence MUSS VOR addRawClient() gelesen werden. Laeuft der Capture-Task noch (schneller
    // Reconnect, MJPEG-Nachlauf) und ist er hoeher priorisiert (Prio 5, Core 1), veroeffentlicht er
    // sofort nach addRawClient() den ersten Rohframe (rawSeq_++). Wurde lastSequence erst DANACH
    // gelesen, wartet dieser Task auf einen Frame, der nie kommt, und der Capture-Task wartet auf
    // die Rueckgabe des Frames, den nie jemand ausgeliehen hat -> gegenseitiges Warten bis zum
    // 5-s-Timeout. Vor addRawClient gelesen, ist jeder danach veroeffentlichte Frame "neuer".
    uint32_t lastSequence = cameraStream.rawSequence();
    cameraStream.addRawClient();
    int32_t  waitedForFrameMs = 0;
    // Dynamische Bildrate (Politik "veraltete Frames verwerfen", Server > Video > Bild): dauert der Send
    // eines Segments laenger als ein Frame-Intervall, ist der Uplink voll -> die naechsten Frames werden
    // AUSGELASSEN, proportional zur Ueberschreitung (1 Intervall zu lang = 1 Frame auslassen), gedeckelt
    // auf fps-1. Ausgelassen wird VOR Konvertierung/Encoder, indem der Frame ausgeliehen und sofort
    // zurueckgegeben wird -- NICHT am Kamera-Ring (der fruehere Ringpuffer-Drain im Verteiler erzeugte
    // hardware-bewiesen die rosa P-Frame-Drift, s. camera_stream_service.cpp). Nicht integrierend:
    // jeder Send entscheidet neu -> kein Kollaps auf 1 fps, schnelle Erholung.
    const int64_t frameUs = 1000000LL / (fps ? fps : 1);
    int      skipLeft  = 0;
    uint32_t statSkips = 0;
    uint32_t encErrors = 0;   // Encode-Fehler dieser Sitzung (jeder erzwingt einen IDR; die ersten 10 im Log)
    // Statistik je Sekunde (Diagnose > Video zeigt sie an).
    int64_t  statStartUs = esp_timer_get_time();
    uint32_t statFrames = 0, statBytes = 0;

    // Live-Stream bis Client-Abbruch (send_chunk-Fehler). No-Frame-Timeout (5 s) wie beim MJPEG-Client.
    while (true) {
        if (g_h264Stop) break;   // neuer Stream/Umschaltung -> diesen zuegig beenden (Slot freigeben)
        // Auf einen neuen Frame des Verteilers warten (identisch zum MJPEG-Client).
        if (cameraStream.rawSequence() == lastSequence) {
            vTaskDelay(pdMS_TO_TICKS(5));
            waitedForFrameMs += 5;
            if (waitedForFrameMs >= 5000) {
                logEvent("H.264-Stream: 5s kein neuer Rohframe vom Verteiler -> Kamera liefert nicht");
                rc = ESP_FAIL; break;
            }
            continue;
        }
        waitedForFrameMs = 0;
        const CameraFrame* f = cameraStream.rawBorrowLatest(&lastSequence);
        if (f && skipLeft > 0) {          // Bandbreite: diesen Frame auslassen (Kamera-Puffer sofort zurueck)
            cameraStream.rawReturn();
            skipLeft--; statSkips++;
            continue;
        }
        if (!f || !f->data || f->pixelFormat != CAMERA_PIXEL_FORMAT_RGB565) {
            if (f) cameraStream.rawReturn();
            vTaskDelay(pdMS_TO_TICKS(5));
            continue;
        }
        const uint8_t* yuv = nullptr; size_t yuvLen = 0;
        bool pOk = ppa.rgb565ToYuv420(f->data, f->width, f->height, tw, th, &yuv, &yuvLen);
        const uint8_t* nal = nullptr; size_t nalLen = 0; bool key = false;
        bool eOk = pOk && enc.encode(yuv, yuvLen, &nal, &nalLen, &key);
        cameraStream.rawReturn();   // Kamera-Puffer sofort zurueck -> der Verteiler holt den naechsten
        if (pOk && (!eOk || nalLen == 0)) {
            // Encode-Fehler (Overflow/Timeout/leer): der HW-Encoder hat den Frame verarbeitet, seine
            // Referenz ist aktualisiert -- der Decoder bekommt ihn aber nicht. Ohne Gegenmassnahme
            // driftet jeder weitere P-Frame bis zum naechsten Keyframe (rosa/lila Artefakte, sporadisch).
            // Frueher wurde hier STILL uebersprungen. Jetzt: naechster Frame = IDR + Ereignis-Log.
            enc.forceIdr();
            encErrors++;
            if (encErrors <= 10) {
                logEvent(String("H.264: Encode-Fehler ") + enc.lastError() + " (Frame " + String(framesSent)
                    + ", NAL " + String((unsigned)nalLen) + " B) -> naechster Frame IDR");
            }
            vTaskDelay(pdMS_TO_TICKS(5)); continue;
        }
        if (!eOk || nalLen == 0) { vTaskDelay(pdMS_TO_TICKS(5)); continue; }   // PPA-Fehler: nichts encodiert

        mux.feed(nal, nalLen, key);
        if (!initSent) {
            if (!mux.hasInit()) { vTaskDelay(pdMS_TO_TICKS(1000 / fps)); continue; }  // auf erstes IDR warten
            const uint8_t* iseg = nullptr; size_t ilen = 0;
            if (mux.initSegment(&iseg, &ilen)) {
                if (httpd_resp_send_chunk(request, (const char*)iseg, ilen) != ESP_OK) { rc = ESP_FAIL; break; }
                initSent = true;
            }
        }
        // Echte Frame-Dauer (Wanduhr) -> Medienzeit driftet nicht hinter die Realzeit -> kein Delay-Stau.
        int64_t nowUs = esp_timer_get_time();
        uint32_t durTicks = 0;
        if (lastFrameUs > 0) {
            int64_t dus = nowUs - lastFrameUs;
            if (dus < 1000) dus = 1000; if (dus > 2000000) dus = 2000000;
            durTicks = (uint32_t)((dus * 90000) / 1000000);
        }
        lastFrameUs = nowUs;

        const uint8_t* mseg = nullptr; size_t mlen = 0;
        if (mux.mediaSegment(&mseg, &mlen, durTicks)) {
            // Der Send blockiert, wenn der Uplink voll ist -- danach liefert der Verteiler den neuesten
            // Frame (Politik "veraltete verwerfen") bzw. den naechsten (Rueckstau). Kein Pacing hier:
            // die Ziel-Bildrate taktet der Capture-Task, wie beim MJPEG-Client.
            int64_t t0 = esp_timer_get_time();
            if (httpd_resp_send_chunk(request, (const char*)mseg, mlen) != ESP_OK) { rc = ESP_FAIL; break; }
            framesSent++; statFrames++; statBytes += (uint32_t)mlen;
            int64_t sendUs = esp_timer_get_time() - t0;
            if (cameraStream.dropStale() && sendUs > frameUs) {
                int n = (int)(sendUs / frameUs);          // Intervalle Ueberschreitung -> so viele auslassen
                if (n > (int)fps - 1) n = (int)fps - 1;
                skipLeft = n;
            }
        }
        // Statistik je Sekunde veroeffentlichen (skips = vom Verteiler verworfene Rohframes).
        int64_t nowStat = esp_timer_get_time();
        if (nowStat - statStartUs >= 1000000LL) {
            double sec = (double)(nowStat - statStartUs) / 1e6;
            g_h264StatFps   = (uint32_t)(statFrames / sec + 0.5);
            g_h264StatKbit  = (uint32_t)(statBytes * 8.0 / sec / 1000.0 + 0.5);
            g_h264StatSkips = statSkips; statSkips = 0;   // ausgelassene Frames je Sekunde (Bandbreite)
            statStartUs = nowStat; statFrames = 0; statBytes = 0;
        }
    }
    g_h264StatFps = 0; g_h264StatKbit = 0; g_h264StatSkips = 0;
    cameraStream.removeRawClient();   // Ausleihe freigeben, Capture-Task ggf. beenden

    if (rc == ESP_OK) httpd_resp_send_chunk(request, NULL, 0);   // sauberes Stream-Ende
    ppa.end(); enc.end(); mux.end();   // Encoder-Block geht in die Guard-Region zurueck (eigener Heap)
    // Sensor zurueck in den Modus von vor dem Stream (nur wenn hochgeschaltet wurde). Der Capture-
    // Task gibt die Roh-Ausleihe beim Ende unter seinem Lock frei; setMode() wartet darauf (<1 s).
    if (restoreW && restoreH) {
        uint16_t cw = 0, ch = 0; cameraManager.currentMode(cw, ch);
        if (cw != restoreW || ch != restoreH) {
            bool ok = cameraManager.setMode(restoreW, restoreH);
            Serial.printf("H264: Kamera-Modus %ux%u -> %ux%u zurueck (Stream-Ende) -> %s\n",
                          cw, ch, restoreW, restoreH, ok ? "ok" : "FEHLGESCHLAGEN (siehe Log)");
        }
    }
    g_h264ActiveRef = 0;   // ERST nach Encoder-Freigabe -> ein neu startender Stream kollidiert nicht
                           // mit dem noch gehaltenen HW-Encoder (esp_h264_enc_hw_new waere sonst belegt).
    httpd_req_async_handler_complete(request);
    Serial.printf("H264 fMP4 stream client disconnected (%u Segmente, %u Encode-Fehler, %u Cache-Sync-Fehler gesamt).\n",
                  (unsigned)framesSent, (unsigned)encErrors, (unsigned)h264GuardCacheErrors());
}

// Dauerhafter H.264-Worker: wartet auf Jobs (H264StreamArgs*) und faehrt je Job eine Sitzung.
// Einmal beim Boot angelegt (Stack 16 KB intern, solange der Heap noch am Stueck ist), fest auf
// Core 1 wie cam_cap/loopTask (Encoder-Interrupt immer auf demselben Core). Prio 3: ueber loopTask/
// MJPEG-Client, strikt unter Modem/USB.
static QueueHandle_t s_h264Jobs   = nullptr;
static bool          s_h264Worker = false;
static void h264WorkerTask(void*) {
    for (;;) {
        H264StreamArgs* a = nullptr;
        if (xQueueReceive(s_h264Jobs, &a, portMAX_DELAY) == pdTRUE && a) h264RunSession(a);
    }
}
static void h264WorkerEnsure() {
    if (s_h264Worker) return;
    if (!s_h264Jobs) s_h264Jobs = xQueueCreate(1, sizeof(H264StreamArgs*));
    if (!s_h264Jobs) { Serial.println("H264: Job-Queue nicht anlegbar -> H.264 aus"); return; }
    BaseType_t ok = xTaskCreatePinnedToCore(h264WorkerTask, "h264_worker", 16384, nullptr, tskIDLE_PRIORITY + 3, nullptr, 1);
    s_h264Worker = (ok == pdPASS);
    Serial.printf("H264: Worker-Task %s (intern frei %uk, groesster %uk)\n", s_h264Worker ? "bereit" : "NICHT anlegbar",
                  (unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024),
                  (unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) / 1024));
}

static esp_err_t handleH264Fmp4(httpd_req_t* request) {
    if (!streamZoneAllowed(request)) return sendZoneDenied(request);
    if (!streamQueryKeyMatches(request)) {
        httpd_resp_set_status(request, "403 Forbidden");
        httpd_resp_set_type(request, "text/plain");
        httpd_resp_send(request, "Stream-Schluessel erforderlich.", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }
    if (!cameraReady || !H264Encoder::hwAvailable()) {
        httpd_resp_set_status(request, "503 Service Unavailable");
        httpd_resp_set_type(request, "text/plain");
        httpd_resp_send(request, "H.264 nicht verfuegbar.", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }
    // Nur EIN H.264-Stream (ein Kamera-Rohpfad). Laeuft schon einer (Aufloesungs-Umschaltung), ihn
    // aktiv beenden und kurz auf die Freigabe warten -> sauberes Umschalten statt Race/"belegt".
    if (g_h264ActiveRef != 0) {
        g_h264Stop = true;
        for (int i = 0; i < 120 && g_h264ActiveRef != 0; i++) vTaskDelay(pdMS_TO_TICKS(10));  // <=1,2s
        if (g_h264ActiveRef != 0) {   // haengt noch (z.B. blockierender Send auf totem Socket)
            httpd_resp_set_status(request, "503 Service Unavailable");
            httpd_resp_set_type(request, "text/plain");
            httpd_resp_send(request, "H.264-Stream wird noch beendet, bitte erneut.", HTTPD_RESP_USE_STRLEN);
            return ESP_OK;
        }
    }
    g_h264Stop = false;   // fuer den neuen Task freigeben

    uint32_t fps = (uint32_t)cameraTargetFps;   // FPS aus der Video-Konfig (Bild-Tab)
    if (fps < 1) fps = 1; if (fps > 30) fps = 30;

    // Aufloesung: ?w=&h=, sonst Default 400x400 (= 800*8/16, PPA-exakt + /16 -> voll gefuellt, kein Saum).
    uint16_t reqW = 0, reqH = 0;
    {
        size_t qlen = httpd_req_get_url_query_len(request) + 1;
        if (qlen > 1) {
            char* q = (char*)malloc(qlen);
            if (q) {
                if (httpd_req_get_url_query_str(request, q, qlen) == ESP_OK) {
                    char v[16];
                    if (httpd_query_key_value(q, "w", v, sizeof(v)) == ESP_OK) reqW = (uint16_t)atoi(v);
                    if (httpd_query_key_value(q, "h", v, sizeof(v)) == ESP_OK) reqH = (uint16_t)atoi(v);
                }
                free(q);
            }
        }
    }
    uint16_t tw = reqW ? reqW : 400;
    uint16_t th = reqH ? reqH : 400;
    tw &= ~15; th &= ~15;
    if (tw < 160) tw = 160; if (th < 128) th = 128;
    if (tw > 1920) tw = 1920; if (th > 1088) th = 1088;

    // Kamera-Modus automatisch passend waehlen: die PPA skaliert nur herunter, also muss der Sensor
    // mindestens tw x th liefern. Ist der aktive Modus kleiner, auf den KLEINSTEN vom Backend
    // gemeldeten Modus umschalten, der die Zielgroesse abdeckt (P4: 800x800 -> 1280x960 -> 1920x1080;
    // Umschaltung ~1 s, HW-bestaetigt). Kein Modus gross genug -> ehrliche 503 statt schwarzem Bild.
    uint16_t restoreW = 0, restoreH = 0;   // != 0 -> der Task schaltet am Ende dorthin zurueck
    {
        uint16_t cw = 0, ch = 0; cameraManager.currentMode(cw, ch);
        if (cw < tw || ch < th) {
            restoreW = cw; restoreH = ch;
            CameraVideoMode modes[16];
            int nm = cameraManager.enumModes(modes, 16);
            int best = -1; uint32_t bestPx = 0xFFFFFFFFu;
            for (int i = 0; i < nm; i++) {
                if (modes[i].width < tw || modes[i].height < th) continue;
                uint32_t px = (uint32_t)modes[i].width * modes[i].height;
                if (px < bestPx) { bestPx = px; best = i; }
            }
            if (best < 0) {
                httpd_resp_set_status(request, "503 Service Unavailable");
                httpd_resp_set_type(request, "text/plain");
                httpd_resp_send(request, "Kein Kamera-Modus liefert diese Groesse (Sensor zu klein fuer die H.264-Aufloesung).", HTTPD_RESP_USE_STRLEN);
                return ESP_OK;
            }
            Serial.printf("H264: Kamera-Modus %ux%u -> %ux%u fuer Ziel %ux%u\n", cw, ch, modes[best].width, modes[best].height, tw, th);
            if (!cameraManager.setMode(modes[best].width, modes[best].height)) {
                httpd_resp_set_status(request, "503 Service Unavailable");
                httpd_resp_set_type(request, "text/plain");
                httpd_resp_send(request, "Kamera-Modus konnte nicht umgeschaltet werden (siehe serielles Log).", HTTPD_RESP_USE_STRLEN);
                return ESP_OK;
            }
        }
    }

    // Slot claimen (ref-Groesse) -> Descriptor rechnet sie ein; der Task setzt sie bei Fehler/Ende auf 0.
    g_h264ActiveRef = (size_t)1152 * ((tw + 15) / 16);

    // Jeder Fehlerpfad antwortet mit 503 + Klartext + Log (frueher ESP_FAIL: httpd schloss den Socket
    // ohne Antwort -> Browser "H.264-Verbindung fehlgeschlagen" ohne jede Spur).
    h264WorkerEnsure();   // lazy: erst beim ersten H.264-Request (Link hat beim Boot Vorrang)
    if (!s_h264Worker) {
        g_h264ActiveRef = 0;
        Serial.println("H264: kein Worker-Task (Anlage fehlgeschlagen, interner Heap) -> 503");
        httpd_resp_set_status(request, "503 Service Unavailable");
        httpd_resp_set_type(request, "text/plain");
        httpd_resp_send(request, "H.264-Worker beim Start nicht anlegbar (interner Heap) -- Neustart noetig.", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }
    httpd_req_t* asyncRequest = NULL;
    if (httpd_req_async_handler_begin(request, &asyncRequest) != ESP_OK) {
        g_h264ActiveRef = 0;
        Serial.printf("H264: async_handler_begin FEHLGESCHLAGEN (intern frei %uk, groesster %uk)\n",
                      (unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024),
                      (unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) / 1024));
        httpd_resp_set_status(request, "503 Service Unavailable");
        httpd_resp_set_type(request, "text/plain");
        httpd_resp_send(request, "H.264: Anfrage-Kontext nicht anlegbar (interner Heap), bitte erneut.", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }
    H264StreamArgs* a = (H264StreamArgs*)malloc(sizeof(H264StreamArgs));
    if (!a) {
        g_h264ActiveRef = 0;
        Serial.println("H264: Job-Struct malloc FEHLGESCHLAGEN -> 503");
        httpd_resp_set_status(asyncRequest, "503 Service Unavailable");
        httpd_resp_set_type(asyncRequest, "text/plain");
        httpd_resp_send(asyncRequest, "H.264: kein Heap fuer den Job, bitte erneut.", HTTPD_RESP_USE_STRLEN);
        httpd_req_async_handler_complete(asyncRequest);
        return ESP_OK;
    }
    a->req = asyncRequest; a->tw = tw; a->th = th; a->fps = fps;
    a->restoreW = restoreW; a->restoreH = restoreH;

    // Job an den dauerhaften Worker (Queue-Tiefe 1; der Handler hat oben auf das Ende der vorigen
    // Sitzung gewartet, die Queue ist also frei).
    if (xQueueSend(s_h264Jobs, &a, pdMS_TO_TICKS(200)) != pdTRUE) {
        free(a); g_h264ActiveRef = 0;
        Serial.println("H264: Job-Queue belegt -> 503");
        httpd_resp_set_status(asyncRequest, "503 Service Unavailable");
        httpd_resp_set_type(asyncRequest, "text/plain");
        httpd_resp_send(asyncRequest, "H.264-Worker noch belegt, bitte erneut.", HTTPD_RESP_USE_STRLEN);
        httpd_req_async_handler_complete(asyncRequest);
        return ESP_OK;
    }
    return ESP_OK;
}


extern String streamType;   // "off" | "http" | "rtsp" (Server > Video): RTSP ersetzt diesen Server
void CameraServer::begin() {
    if (streamType == "rtsp") {
        Serial.println("HTTP-Stream-Server aus: Stream-Transport RTSP gewaehlt (rtsp_server).");
        return;
    }
    if (!streamEnabled) {
        Serial.println("MJPEG stream server disabled by configuration.");
        return;
    }

    if (streamServer_ != nullptr) {
        // Bereits gestartet (z.B. nach einem Reconnect) - nicht doppelt.
        return;
    }

    cameraStream.begin();   // Verteiler-Mutex anlegen (idempotent)
    // H.264-Worker NICHT hier: sein 16-KB-Stack beim Boot nahm dem PPP-Start (USB-Transfers, PPP-
    // Kontrollblock) den internen Heap (mit HTTPS: Boot 64k frei / 30k am Stueck -> Link blieb aus).
    // Er wird beim ERSTEN H.264-Request angelegt (h264WorkerEnsure im Handler); scheitert das,
    // antwortet der Handler ehrlich mit 503 -- der Mobilfunk-Link hat Vorrang vor Video.

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();

    config.server_port = streamPort;
    // KRITISCH: HTTPD_DEFAULT_CONFIG() setzt ctrl_port = 32768 (interner UDP-Control-Port).
    // Der Management-Server (WeirdHttpEsp HTTP) belegt 32768 ebenfalls -> Kollision -> httpd_start
    // schlaegt fehl ("could not be started") -> Port 81 startet nie -> Video schwarz. Daher hier
    // ein EIGENER Control-Port. Belegung: Mgmt HTTP 32768 / Mgmt HTTPS 32769 / Video HTTP 32770 /
    // Video HTTPS 32771. Das sind NICHT die sichtbaren TCP-Ports (80/81/443), nur die UDP-Control-Ports.
    config.ctrl_port   = 32770;
    // lwIP-Socket-Budget (16 gesamt, siehe .ino bei setMaxOpenSockets): Stream-Server hoechstens 2
    // gleichzeitige Clients (ein MJPEG + ein H.264), statt IDF-Default 7 -- sonst laeuft die Tabelle
    // voll und weder Web noch Tunnel nehmen neue Verbindungen an.
    config.max_open_sockets = 2;

    // Der H.264-fMP4-Handler ist blockierend und baut MP4-Boxen + ruft PPA/Encoder -> tieferer
    // Call-Stack als der MJPEG-Async-Pfad. Default 4096 ist knapp -> anheben. Zweiter URI-Handler
    // (Stream + /video.mp4) -> max_uri_handlers reicht (Default 8).
    config.stack_size  = 8192;
    // Task-Stack in PSRAM statt Internal-RAM (Default task_caps = MALLOC_CAP_INTERNAL). Der interne,
    // ZUSAMMENHAENGENDE RAM ist die knappe Ressource fuer den H.264-ref-Puffer (~1152*ceil(w/16));
    // HTTP-Task-Stacks brauchen kein Internal -> ab nach PSRAM, gibt zusammenhaengenden Internal frei.
    config.task_caps   = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;

    // Nicht mehr benoetigte Verbindungen automatisch aufraeumen, damit
    // haengende Clients keinen Socket-Slot dauerhaft blockieren.
    config.lru_purge_enable = true;

    // esp_http_server speichert nur den uri-Zeiger (kopiert nicht) -> stabilen
    // Puffer statt streamPath.c_str() verwenden, der bei Reassign dangeln koennte.
    static char streamPathBuf[64];
    strlcpy(streamPathBuf, streamPath.c_str(), sizeof(streamPathBuf));

    httpd_uri_t streamUri = {
        .uri = streamPathBuf,
        .method = HTTP_GET,
        .handler = handleMjpegStream,
        .user_ctx = NULL
    };

    esp_err_t sr = httpd_start(&streamServer_, &config);
    if (sr == ESP_OK) {
        httpd_register_uri_handler(
            streamServer_,
            &streamUri
        );

        // H.264-fMP4-Stream fuer den Browser (MSE) am selben Video-Server.
        httpd_uri_t h264Uri = {
            .uri = "/video.mp4",
            .method = HTTP_GET,
            .handler = handleH264Fmp4,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(streamServer_, &h264Uri);

        Serial.printf("MJPEG stream server started on port %d (%s, +/video.mp4 H.264).\n", streamPort, streamPathBuf);
    } else {
        streamServer_ = nullptr;
        Serial.printf("MJPEG stream server could not be started: %s (0x%x)\n",
                      esp_err_to_name(sr), (unsigned)sr);
    }
}


// Phase-1-TLS-PoC: derselbe MJPEG-Stream zusaetzlich ueber TLS. Bewusst NUR der
// Stream (er nutzt bereits esp_http_server; esp_https_server sitzt offiziell
// darauf, gleiche URI-Handler-API). Damit laesst sich isoliert der TLS-Aufpreis
// bei identischem FHD-Stream messen (HTTP:streamPort vs HTTPS:securePort), OHNE
// die Arduino-WebServer-Control-Plane (/ , /dev/*, PIN) anzufassen.
void CameraServer::beginTls(uint16_t securePort) {
    if (!streamEnabled) {
        return;   // Meldung kommt bereits aus begin()
    }
    if (streamServerTls_ != nullptr) {
        return;   // idempotent
    }
#if !WEIRDOS_FEATURE_TLS_SERVER
    // Baustein TLS_SERVER abgewaehlt: kein esp_https_server im Image -> nur der HTTP-Stream (begin()).
    (void)securePort;
    Serial.println("MJPEG HTTPS stream server: HTTPS-Server nicht im Build enthalten (WEIRDOS_FEATURE_TLS_SERVER=0).");
    return;
#else

    // Self-signed Cert/Key EINMAL pro Boot erzeugen und halten (stabil ueber
    // Reconnects). Kein privater Schluessel im Repo -> On-Device generiert.
    static String certPem;
    static String keyPem;
    if (certPem.length() == 0) {
        if (!weirdosGenSelfSignedCert(certPem, keyPem, nullptr)) {
            Serial.println("MJPEG HTTPS stream server: cert gen failed, TLS disabled.");
            return;
        }
    }

    cameraStream.begin();   // Verteiler-Mutex (idempotent)

    static char streamPathBufTls[64];
    strlcpy(streamPathBufTls, streamPath.c_str(), sizeof(streamPathBufTls));

    httpd_ssl_config_t sslcfg = HTTPD_SSL_CONFIG_DEFAULT();
    sslcfg.servercert     = (const uint8_t*)certPem.c_str();
    sslcfg.servercert_len = certPem.length() + 1;   // PEM inkl. abschliessendem NUL
    sslcfg.prvtkey_pem    = (const uint8_t*)keyPem.c_str();
    sslcfg.prvtkey_len    = keyPem.length() + 1;
    sslcfg.port_secure    = securePort;
    sslcfg.httpd.lru_purge_enable = true;
    // TLS-Handshake (mbedTLS) braucht mehr Stack als der Default (10240).
    sslcfg.httpd.stack_size = 20480;
    sslcfg.httpd.ctrl_port  = 32771;   // eigener Control-Port (Belegung s. begin(); HTTPD_SSL default 32769 kollidiert mit Mgmt-HTTPS)

    esp_err_t r = httpd_ssl_start(&streamServerTls_, &sslcfg);
    if (r == ESP_OK) {
        httpd_uri_t streamUri = {
            .uri = streamPathBufTls,
            .method = HTTP_GET,
            .handler = handleMjpegStream,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(streamServerTls_, &streamUri);
        Serial.printf("MJPEG HTTPS stream server started on port %d (%s).\n",
                      securePort, streamPathBufTls);
    } else {
        streamServerTls_ = nullptr;
        Serial.printf("MJPEG HTTPS stream server could not be started (0x%x).\n", r);
    }
#endif // WEIRDOS_FEATURE_TLS_SERVER
}


void CameraServer::stop() {
    if (streamServer_ != nullptr) {
        httpd_stop(streamServer_);
        streamServer_ = nullptr;
        Serial.println("MJPEG stream server stopped.");
    }
#if WEIRDOS_FEATURE_TLS_SERVER
    if (streamServerTls_ != nullptr) {
        httpd_ssl_stop(streamServerTls_);
        streamServerTls_ = nullptr;
        Serial.println("MJPEG HTTPS stream server stopped.");
    }
#endif
}


// handleCapture() ENTFERNT: /capture laeuft jetzt als neutraler WeirdHttp-Handler
// (handleCaptureFrame in der .ino) ueber cameraManager/FrameSource -- dieselbe Quelle
// wie der MJPEG-Stream. Der alte esp_camera_fb_get()-Pfad war am P4 (V4L2) fachlich
// falsch (Shim lieferte immer NULL). Damit ist camera_server.cpp frei vom Arduino-
// WebServer `server` (Vorbereitung Phase 3: WeirdHttpEsp-Flip).

#else
// ============================================================================
// Stub: HTTP-Videostream nicht im Build enthalten (WEIRDOS_FEATURE_VIDEO_HTTP=0).
// Dieselben Symbole wie oben, triviale Koerper: der Composition Root (startVideoTransport)
// referenziert cameraServer und muss weiter linken. Kein esp_http_server, kein
// esp_https_server, kein MJPEG-/H.264-Task, kein /video.mp4 -- web_ui/cameraStream/
// h264_*/ppa/tls_selfsigned werden hier nicht einmal eingebunden, der Linker wirft den
// ganzen Rest heraus. streamRunning()/streamTlsRunning() (inline im Header) melden ueber
// die Vorgaben streamServer_=nullptr / streamServerTls_=nullptr korrekt "aus".
// /capture (handleCaptureFrame) lebt in der .ino und wird dort separat gegated.
// ============================================================================
#include <Arduino.h>   // Serial

CameraServer cameraServer;

void CameraServer::begin() {
    Serial.println("Video-Server (HTTP/MJPEG): nicht im Build enthalten (WEIRDOS_FEATURE_VIDEO_HTTP=0)");
}
void CameraServer::beginTls(uint16_t) {}   // Meldung kommt bereits aus begin()
void CameraServer::stop() {}
#endif // WEIRDOS_FEATURE_VIDEO_HTTP
