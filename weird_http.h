// ============================================================================
// weird_http.h  --  WeirdOS neutraler HTTP-Service-Layer (backend-unabhaengig)
//
// Ziel: die fachlichen Handler kennen NUR dieses Interface, nicht den konkreten
// Webserver. Zwei Adapter implementieren es:
//   * WeirdHttpArduino  -> Arduino WebServer   (S3, HTTP; delegiert an globalen server)
//   * WeirdHttpEsp      -> esp_http_server / esp_https_server (P4, HTTP ODER HTTPS)
//
// Bewusst KEIN Arduino-WebServer-Klon (kein impliziter "current request", kein
// server.arg/send-Nachbau). Wir definieren die HTTP-Semantik von WeirdOS und
// schreiben je einen Adapter. Nur was WeirdOS wirklich braucht:
//   Routing, Path-Parameter, Query/Form, Body, Header, Cookies, Response,
//   Redirect, Chunked-Streaming, Client-IP.
// Auth ist NICHT hier -> App-Ebene (requireSession umschliesst Handler, liest
// nur req.cookie()/req.clientIp()). Backend-Spezialfaelle (Upload/OTA) duerfen
// die Adapter intern loesen.
//
// Der Stream-Server (MJPEG) bleibt bewusst roher esp_http_server in
// camera_server.cpp (durchsatzkritisch) und laeuft NICHT ueber diesen Layer.
// ============================================================================
#ifndef WEIRD_HTTP_H
#define WEIRD_HTTP_H

#include <Arduino.h>
#include <functional>

enum class HttpMethod { GET, POST, PUT, PATCH, DEL, ANY };

// --- Request: nur Lesezugriffe, backend-neutral ----------------------------
class WeirdHttpRequest {
public:
    virtual ~WeirdHttpRequest() {}

    virtual HttpMethod method() const = 0;
    virtual String     path() const = 0;

    // Query- ODER Formular-Parameter (wie das bisherige server.arg()).
    virtual bool   hasArg(const char* name) const = 0;
    virtual String arg(const char* name) const = 0;

    // Benannter Path-Parameter aus der Route ("/dev/{device}" -> pathParam("device")).
    virtual String pathParam(const char* name) const = 0;

    // GEMEINSAMER VERTRAG: header() ist nur fuer die Header garantiert, die der
    // Arduino-WebServer via collectHeaders() sammelt (sonst liefert er ""). WeirdOS
    // sammelt: Host, User-Agent, Accept, Cookie. Der Esp-Adapter liefert zwar jeden
    // Header, aber Handler duerfen sich nur auf diese Menge verlassen (Backend-Paritaet).
    virtual String header(const char* name) const = 0;  // "" wenn nicht vorhanden/nicht gesammelt
    virtual String cookie(const char* name) const = 0;  // exakt geparst (weirdHttpParseCookie)
    virtual String body() const = 0;                    // roher Request-Body (POST)
    virtual String clientIp() const = 0;                // Peer-IP (fuer WAN-/Auth-Pruefung)
};

// --- Response: Einmal-Antwort ODER Chunked-Streaming ------------------------
class WeirdHttpResponse {
public:
    virtual ~WeirdHttpResponse() {}

    // Statuscode wird IMMER explizit an send()/beginChunked()/redirect() uebergeben
    // (kein separater status()-Zustand -> keine Halb-API, an die sich Handler klammern).
    virtual void header(const char* name, const String& value) = 0; // vor send()/beginChunked()

    // Einmal-Antwort (Body komplett im Speicher).
    virtual void send(int code, const char* contentType, const String& body) = 0;
    void sendJson(const String& b) { send(200, "application/json", b); }
    void sendHtml(const String& b) { send(200, "text/html; charset=utf-8", b); }
    void sendText(const String& b) { send(200, "text/plain; charset=utf-8", b); }
    virtual void redirect(const String& location, int code = 302) = 0;

    // Inkrementell zusammengebaute Antwort (Ersatz fuer die vielen sendContent()):
    //   beginChunked(...) -> write() ... write() -> end()
    virtual bool beginChunked(int code, const char* contentType) = 0;
    virtual bool write(const char* data, size_t len) = 0;
    bool write(const String& s) { return write(s.c_str(), s.length()); }
    bool write(const char* s)   { return write(s, strlen(s)); }
    virtual void end() = 0;
};

typedef std::function<void(WeirdHttpRequest&, WeirdHttpResponse&)> WeirdHttpHandler;

// --- Upload: gestreamter Request-Body (bewusster Backend-Sonderfall) --------
// Multipart-/Body-Upload (settings-import, OTA-Firmware) laesst sich NICHT sinnvoll
// als ein grosser String-Handler abbilden (Firmware waere komplett im RAM). Statt
// dessen ein neutraler Lifecycle: Start -> N x Write(chunk) -> End (oder Abort),
// danach ein normaler Finish-Handler fuer die Antwort. Beide Adapter implementieren
// das: Arduino ueber server.upload(), Esp ueber httpd_req_recv() im Stream.
enum class UploadPhase { Start, Write, End, Abort };
struct WeirdHttpUpload {
    UploadPhase    phase;
    const uint8_t* data  = nullptr;   // gueltig bei Write
    size_t         len   = 0;         // gueltig bei Write
    size_t         total = 0;         // kumulierte Bytes (bei End)
};
// onChunk laeuft pro Phase; die Antwort kommt NICHT hier, sondern im Finish-Handler.
typedef std::function<void(WeirdHttpRequest&, const WeirdHttpUpload&)> WeirdHttpUploadHandler;

// --- Geteilte Helfer (identische Semantik auf beiden Adaptern) --------------
// Exakter, semikolon-getrennter Cookie-Parse. Vergleicht den Namen GENAU (kein
// Substring-Treffer innerhalb eines anderen Cookie-Namens) -> auth-tauglich.
String weirdHttpParseCookie(const String& cookieHeader, const char* name);
// "200" -> "200 OK" etc. (esp_http_server verlangt Status als Text).
const char* weirdHttpStatusText(int code);
// application/x-www-form-urlencoded Dekodierung (%XX + '+' -> Space). Der Arduino-
// WebServer dekodiert arg()-Werte selbst; httpd_query_key_value NICHT -> der Esp-
// Adapter ruft dies auf, damit arg() auf beiden Backends identische Werte liefert.
String weirdHttpUrlDecode(const String& s);

// --- Server: Routing + Lebenszyklus, backend-neutral -----------------------
class WeirdHttpServer {
public:
    virtual ~WeirdHttpServer() {}

    // pattern: fester Pfad oder mit {name}-Segmenten ("/dev/{device}").
    virtual void route(HttpMethod method, const char* pattern, WeirdHttpHandler handler) = 0;
    virtual void onNotFound(WeirdHttpHandler handler) = 0;

    // Upload-Route: onChunk bekommt den Body gestreamt (Start/Write/End/Abort),
    // onFinish sendet danach die Antwort. Fester Pfad (keine {name}-Parameter noetig).
    virtual void routeUpload(HttpMethod method, const char* pattern,
                             WeirdHttpUploadHandler onChunk, WeirdHttpHandler onFinish) = 0;

    virtual void begin() = 0;
    virtual void loop() {}   // Arduino: handleClient(); esp_http_server: no-op
};

#endif // WEIRD_HTTP_H
