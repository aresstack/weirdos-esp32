// ============================================================================
// weird_http_esp.h  --  WeirdHttp-Adapter auf esp_http_server / esp_https_server.
//
// EIN Code, beide Transporte: begin() startet je nach tls_ entweder httpd_start()
// (HTTP) oder httpd_ssl_start() (HTTPS, Cert/Key via useTlsCert()). Dieselbe
// Route-Tabelle und Handler-Semantik in beiden Faellen -> Basis fuer:
//   ManagementServer = Esp + HTTPS,  SetupServer = Esp + HTTP,  usw.
//
// Routing: eigener Matcher (Segment-Vergleich mit {name}-Path-Params) hinter
// EINEM Wildcard-Handler pro Methode. Gibt exakt dieselbe {name}-Semantik wie der
// Arduino-Adapter (UriBraces), unabhaengig von esp_http_server-Eigenheiten.
// ============================================================================
#ifndef WEIRD_HTTP_ESP_H
#define WEIRD_HTTP_ESP_H

#include "weird_http.h"
#include <esp_http_server.h>
#include <vector>

class WeirdHttpEsp : public WeirdHttpServer {
public:
    WeirdHttpEsp(uint16_t port, bool tls) : port_(port), tls_(tls) {}

    // Cert/Key (PEM) fuer den TLS-Modus setzen (z.B. aus tls_selfsigned).
    void useTlsCert(const String& certPem, const String& keyPem) {
        certPem_ = certPem; keyPem_ = keyPem;
    }

    // Socket-Budget begrenzen (der P4 ist socket-/heap-knapp, wenn mehrere Server
    // gleichzeitig laufen). Default bewusst klein.
    void setMaxOpenSockets(uint8_t n) { maxSockets_ = n; }
    // Fuer ZWEITE Instanzen (z.B. Port-80-Listener neben Management-HTTPS): eigener interner
    // UDP-Control-Port (Belegung: Mgmt 32768/9, Video 32770/1, Port-80-Hilfsserver 32772) und
    // kleinerer Task-Stack (nur Redirect + ACME-Challenge, kein App-Render). 0 = Default.
    void setCtrlPort(uint16_t p)   { ctrlPort_ = p; }
    void setStackSize(uint32_t s)  { stackSize_ = s; }

    // Port + Transport VOR begin() setzen (Management HTTP:80 <-> HTTPS:443, ohne alle
    // Routen neu registrieren zu muessen). Nach begin() ohne Wirkung.
    void configure(uint16_t port, bool tls) { if (!handle_) { port_ = port; tls_ = tls; } }
    bool isTls() const { return tls_; }

    // Fehlercode des letzten begin() (ESP_OK bei Erfolg) - fuer Diagnose.
    esp_err_t lastError() const { return lastError_; }

    void route(HttpMethod method, const char* pattern, WeirdHttpHandler handler) override;
    void onNotFound(WeirdHttpHandler handler) override;
    void routeUpload(HttpMethod method, const char* pattern,
                     WeirdHttpUploadHandler onChunk, WeirdHttpHandler onFinish) override;
    void begin() override;
    void loop() override {}   // esp_http_server hat eigene Tasks -> nichts zu tun

    bool running() const { return handle_ != nullptr; }

    // Vom Wildcard-Trampolin aufgerufen (public, damit die C-Trampolinfunktion es erreicht).
    esp_err_t dispatch(httpd_req_t* req);

private:
    struct Route {
        HttpMethod        method;
        std::vector<String> segs;    // Pattern-Segmente; "{name}" = Parameter
        WeirdHttpHandler  handler;
        // Upload-Routen: statt handler laeuft onChunk (Body-Stream) + onFinish (Antwort).
        bool                   isUpload = false;
        WeirdHttpUploadHandler onChunk;
        WeirdHttpHandler       onFinish;
    };

    uint16_t         port_;
    bool             tls_;
    uint8_t          maxSockets_ = 4;
    uint16_t         ctrlPort_   = 0;    // 0 = Default je Transport (32768 HTTP / 32769 HTTPS)
    uint32_t         stackSize_  = 0;    // 0 = Default (16384 HTTP / 20480 HTTPS)
    esp_err_t        lastError_  = ESP_OK;
    String           certPem_, keyPem_;
    httpd_handle_t   handle_ = nullptr;
    std::vector<Route> routes_;
    WeirdHttpHandler   notFound_;

    void registerWildcards();
};

#endif // WEIRD_HTTP_ESP_H
