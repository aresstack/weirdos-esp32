// ============================================================================
// rtsp_server.h -- RTSP-Server (RFC 2326) fuer den Kamera-Stream, standardkonform:
//   * SDP (RFC 4566) je Mountpunkt, RTP (RFC 3550) mit RTCP Sender Reports,
//   * /mjpeg : RTP/JPEG (RFC 2435, PT 26)  -- dieselben JPEG-Frames wie der HTTP-MJPEG-Stream,
//   * /h264  : RTP/H.264 (RFC 6184, PT 96, packetization-mode=1, FU-A) -- der HW-Encoder,
//              optional ?w=&h= wie /video.mp4; SPS/PPS in-band vor jedem IDR (+ sprop im SDP,
//              sobald einmal bekannt),
//   * Transport: RTP/AVP/TCP interleaved (RFC 2326 10.12) als Vorgabe -> EIN Socket je Client
//              (RTP + RTCP laufen im RTSP-TCP-Kanal); RTP/AVP ueber UDP nur, wenn freigegeben
//              (kostet 2 weitere Sockets je Client),
//   * Zugriff: Stream-Schluessel als HTTP-Basic (RFC 2617) auf RTSP, Zonen-Regel wie der HTTP-Stream.
//
// Topologie: RTSP ERSETZT den HTTP-Stream-Server (Port 81) -- der Nutzer waehlt Aus | HTTP | RTSP
// (Server > Video). Das Socket-Budget bleibt dadurch gleich (ein Listener + ein Socket je Client).
// Kein eigener Task beim Boot: begin() legt nur den Listener an; poll() aus loop() nimmt den ersten
// Client an und startet dann den Worker-Task (interner Stack, wie der H.264-Worker des HTTP-Pfads).
// Der Worker beendet sich, wenn kein Client mehr da ist (Stack wieder frei).
// Einzelbilder gibt es in RTSP nicht (Streaming-Kontrollprotokoll); /capture auf Port 80 bleibt.
// ============================================================================
#pragma once
#include <Arduino.h>

class RtspServer {
public:
    bool   begin(uint16_t port, bool allowUdp);   // Listener anlegen (idempotent); false = Port belegt
    void   stop();                                 // Listener + alle Sitzungen schliessen
    void   poll();                                 // aus loop(): accept + Worker lazy starten
    bool   running() const { return listenFd_ >= 0; }
    bool   workerRunning() const { return taskRunning_; }
    int    clientCount() const;
    String statusJson();                           // {running,port,udp,clients:[{ip,mount,transport,playing,packets,bytes}],...}
    String statusText();                           // fuer die Konsole ('video')
    void   taskLoop();                             // intern (Worker-Task)
private:
    int           listenFd_ = -1;
    uint16_t      port_     = 554;
    bool          allowUdp_ = false;
    volatile bool taskRunning_ = false;
    bool acceptOne();                              // ein wartender Client -> Sitzung (false = keiner/abgelehnt)
    bool startWorker();
};
extern RtspServer rtspServer;
