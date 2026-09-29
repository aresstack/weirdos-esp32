// ============================================================================
// camera_device.h  --  Hardware-Abstraktion einer Kamera (Interface)
//
// Implementierungen:
//   Esp32S3DvpCamera   (heute) -> OV3660 via esp_camera (DVP)
//   Esp32P4MipiCamera  (spaeter) -> ESP-Video / MIPI-CSI
// Der Rest der App (Stream, AI) kennt NUR dieses Interface, nie esp_camera.
// ============================================================================
#ifndef CAMERA_DEVICE_H
#define CAMERA_DEVICE_H

#include "camera_frame.h"

// Generische, geraeteunabhaengige Sensor-/Bild-Parameter. Jedes CameraDevice
// meldet seine eigene Liste (DVP-OV3660 anders als P4-MIPI); die Web-UI rendert
// sie einheitlich (Slider fuer INT, Schalter fuer BOOL). Werte sind int; BOOL
// nutzt 0/1.
enum CameraParamKind { CAM_PARAM_INT, CAM_PARAM_BOOL };

struct CameraParamInfo {
    const char*     key;    // stabiler Bezeichner, z.B. "brightness" (POST-Schluessel)
    const char*     label;  // UI-Beschriftung
    int             min;    // fuer INT (BOOL: 0)
    int             max;    // fuer INT (BOOL: 1)
    CameraParamKind kind;
    int             value;  // aktueller Wert (vom Geraet gefuellt)
};

// Ein konkreter, vom Backend gemeldeter Capture-Modus = Schnittmenge aus dem, was
// Sensor UND Capture-Hardware/ISP wirklich koennen (auf dem P4 exakt das, was V4L2
// auf /dev/video0 enumeriert). NEUTRAL - keine esp_camera-/V4L2-Typen. Die Video-
// Pipeline/UI baut die Aufloesungswahl AUS DIESER Liste, NICHT aus einer festen
// Tabelle -> der Dropdown aendert sich automatisch mit Sensor/Board.
struct CameraVideoMode {
    uint16_t          width;
    uint16_t          height;
    CameraPixelFormat pixelFormat;   // Sensor-/Capture-Format (RAW -> GRAYSCALE-Platzhalter)
    uint16_t          maxFps;        // 0 = unbekannt (ENUM_FRAMEINTERVALS lieferte nichts)
    bool              enumerated;    // true = echt via V4L2-Enumeration; false = Active-Mode-Fallback
};

class CameraDevice {
public:
    virtual ~CameraDevice() {}

    virtual bool         begin() = 0;             // Hardware initialisieren (einmalig)
    virtual bool         isReady() const = 0;

    // Aktuelles Bild holen (nullptr = keins verfuegbar). Der zurueckgegebene
    // Frame gehoert weiter dem Geraet und MUSS mit releaseFrame() freigegeben
    // werden, bevor der naechste geholt wird.
    virtual CameraFrame* acquireFrame() = 0;
    virtual void         releaseFrame(CameraFrame* frame) = 0;

    // Wie acquireFrame(), aber liefert den ROHEN ISP-Frame (RGB565/YUYV), NICHT JPEG -- fuer den
    // H.264-HW-Encoder, der Rohbilder braucht. Gleiche Ownership/releaseFrame()-Regel. Default:
    // nicht unterstuetzt (nullptr) -- nur der P4 (esp_video/V4L2) liefert Rohframes zero-copy.
    virtual CameraFrame* acquireRawFrame() { return nullptr; }

    // Diagnose: welche Pixel-Ausgabeformate kann der Capture-Pfad (ISP/V4L2) ueberhaupt liefern?
    // Schreibt bis maxOut rohe FourCC-Codes; Rueckgabe = Anzahl. Default 0 (nicht unterstuetzt).
    // Klaert, ob der ISP YUV420 direkt kann (dann keine Farbkonversion fuer H.264 noetig).
    virtual int enumPixelFormats(uint32_t* outFourcc, int maxOut) const { (void)outFourcc; (void)maxOut; return 0; }

    // ---- Native Capture-Modi (dynamische Aufloesungswahl) ----
    // Jedes Geraet meldet SEINE effektiven Modi (Sensor ∩ Capture-HW/ISP). Default:
    // keine (Altgeraete). Rueckgabe = Anzahl geschriebener Eintraege (<= maxOut).
    // Die Web-UI baut den Aufloesungs-Dropdown ausschliesslich hieraus.
    virtual int enumModes(CameraVideoMode* out, int maxOut) const { (void)out; (void)maxOut; return 0; }

    // Eine Capture-Aufloesung (aus enumModes()) setzen -- die GENERISCHE Apply-Seite.
    // Jedes Backend mappt intern auf seinen Mechanismus (S3: set_framesize; P4: V4L2 S_FMT).
    // true = gesetzt (oder bereits aktiv). Default: nicht unterstuetzt. Kein framesize_t/
    // Boardwissen oberhalb des Backends. Nur wirklich unterstuetzte Modi duerfen ok liefern.
    virtual bool setMode(uint16_t width, uint16_t height) { (void)width; (void)height; return false; }

    // Aktuell aktive Capture-Aufloesung (fuer den Geraete-Descriptor). false = unbekannt.
    virtual bool currentMode(uint16_t& width, uint16_t& height) const { (void)width; (void)height; return false; }

    // ---- Einstellbare Parameter (fuer die Web-UI) ----
    // Default: keine (abwaertskompatibel). Geraete ueberschreiben.
    virtual int  paramCount() const { return 0; }
    virtual bool paramAt(int index, CameraParamInfo& out) const { (void)index; (void)out; return false; }
    virtual bool setParam(const char* key, int value) { (void)key; (void)value; return false; }

    // ---- Laufzeit-JPEG-Qualitaet (geraeteneutral) ----
    // Die UI arbeitet in der esp_camera-Skala 0..63 (0 = beste). Jedes Backend mappt intern auf
    // seine eigene Skala (S3 nutzt den esp_camera-Sensor direkt; der P4-HW-Encoder hat 1..100,
    // hoeher = besser). Default: nicht laufzeit-setzbar (der Aufrufer meldet das ehrlich).
    virtual bool qualityRuntimeSettable() const { return false; }
    virtual void setJpegQualityUi(int ui0to63) { (void)ui0to63; }   // 0..63 (0=best) -> intern gemappt
    virtual int  jpegQualityUi() const { return -1; }               // aktuell, UI-Skala; -1 = unbekannt
};

#endif // CAMERA_DEVICE_H
