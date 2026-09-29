// ============================================================================
// camera_server.h  --  Besitzt/koordiniert die Kamera-HTTP-Endpunkte.
//
// WICHTIG - die Listener-Topologie bleibt unveraendert; CameraServer vereinigt
// NICHTS, er besitzt nur:
//   * /capture ist ein neutraler WeirdHttp-Handler (handleCaptureFrame in der .ino)
//     ueber cameraManager/FrameSource -- NICHT mehr hier (kein esp_camera-Legacy).
//   * MJPEG laeuft als SEPARATER esp_http_server auf streamPort/streamPath;
//     CameraServer besitzt dessen Handle und Lebenszyklus (begin/stop).
//
// Auth/WAN-Schutz/Cache-Header/Stream-Key/Multi-Client-Limit/Async-Tasks/Port/
// Pfad/Endpoints sind unveraendert (reine Code-Verschiebung). Der Verteiler
// (CameraStreamService) bleibt transport-/FrameSource-neutral; Sensorparameter
// bleiben bei CameraManager/Device - nicht hier.
// ============================================================================
#ifndef CAMERA_SERVER_H
#define CAMERA_SERVER_H

#include <esp_http_server.h>

class CameraServer {
public:
    void begin();   // MJPEG-esp_http_server auf streamPort/streamPath starten (idempotent)
    // Phase-1-TLS-PoC: identischer MJPEG-Stream zusaetzlich ueber esp_https_server
    // (Default 443, self-signed On-Device-Cert). Erlaubt A/B-Durchsatzvergleich
    // HTTP:streamPort vs HTTPS:443 bei identischem FHD-Stream. Isoliert - beruehrt
    // NICHT die Arduino-WebServer-Control-Plane (die migriert erst in Phase 2).
    void beginTls(uint16_t securePort = 443);
    void stop();    // MJPEG-Server (HTTP + TLS) stoppen (Lebenszyklus-Besitz)
    bool streamRunning() const { return streamServer_ != nullptr; }
    bool streamTlsRunning() const { return streamServerTls_ != nullptr; }

private:
    httpd_handle_t streamServer_ = nullptr;
    httpd_handle_t streamServerTls_ = nullptr;   // esp_https_server (Phase-1-TLS-PoC)
};

// Globale Instanz (wie server/cameraManager/cameraStream).
extern CameraServer cameraServer;

#endif // CAMERA_SERVER_H
