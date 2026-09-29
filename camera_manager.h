// ============================================================================
// camera_manager.h  --  Besitzt genau EIN CameraDevice und dessen Lebenszyklus
//
// Einzige Anlaufstelle der App fuer die Kamera: Init, Bereitschaft, Frame
// holen/freigeben. Welche konkrete Kamera dahintersteckt (heute S3-DVP,
// spaeter P4-MIPI), entscheidet allein der Manager - Stream-Service und AI
// kennen nur diese Fassade.
// ============================================================================
#ifndef CAMERA_MANAGER_H
#define CAMERA_MANAGER_H

#include <sdkconfig.h>   // CONFIG_IDF_TARGET_ESP32P4/S3 fuer die Geraete-Weiche
#include "camera_device.h"
#include "esp32s3_camera_device.h"
#include "esp32p4_camera_device.h"
#include "frame_source.h"   // CameraManager ist eine FrameSource (Capability)
#include <cstdint>

// CameraManager erfuellt die generische FrameSource-Capability: Konsumenten wie der
// Stream-Service haengen nur an FrameSource, nicht am konkreten Manager.
class CameraManager : public FrameSource {
public:
    // Bereits aufgeloeste Startparameter (PSRAM-Budget/Fallback entscheidet
    // weiterhin der Aufrufer und reicht das Ergebnis hier herein).
    struct Config {
        uint16_t frameSize;      // S3-DVP: Start-Aufloesung (roher framesize_t-Wert)
        uint16_t maxFrameSize;   // S3-DVP: hoechste Aufloesung -> Puffergroesse
        uint16_t width;          // P4-MIPI: Start-Breite  (S3 ignoriert)
        uint16_t height;         // P4-MIPI: Start-Hoehe   (S3 ignoriert)
        uint8_t  jpegQuality;    // LIVE-Qualitaet, 0..63 (0 = beste)
        uint8_t  bufferQuality;  // Puffer-Dimensionierung; 0 = groesster
        uint8_t  fbCount;        // Anzahl Framebuffer (1..2)
    };

    CameraManager();

    bool begin(const Config& config);   // waehlt + initialisiert das Geraet
    bool isReady() const override;

    // Delegieren an das Geraet. Ein Frame gleichzeitig in flight. (FrameSource)
    CameraFrame* acquireFrame() override;
    void         releaseFrame(CameraFrame* frame) override;

    // Roher ISP-Frame (kein JPEG) fuer den H.264-Encoder. nullptr = Geraet liefert keine Rohframes.
    CameraFrame* acquireRawFrame() override { return device_ ? device_->acquireRawFrame() : nullptr; }

    // Diagnose: ISP/V4L2-Ausgabeformate (FourCC). 0 = nicht unterstuetzt.
    int enumPixelFormats(uint32_t* outFourcc, int maxOut) const {
        return device_ ? device_->enumPixelFormats(outFourcc, maxOut) : 0;
    }

    // Native Capture-Modi des aktiven Geraets (Sensor ∩ Capture-HW) -> dynamischer Dropdown.
    int  enumModes(CameraVideoMode* out, int maxOut) const;

    // Eine Capture-Aufloesung setzen (generischer Apply-Port; Backend mappt intern).
    bool setMode(uint16_t width, uint16_t height);

    // Aktuell aktive Capture-Aufloesung des aktiven Geraets (false = unbekannt).
    bool currentMode(uint16_t& width, uint16_t& height) const;

    // Einstellbare Parameter des aktiven Geraets (fuer die Web-UI).
    int  paramCount() const;
    bool paramAt(int index, CameraParamInfo& out) const;
    bool setParam(const char* key, int value);

    // Laufzeit-JPEG-Qualitaet (geraeteneutral, UI-Skala 0..63). Passthrough ans aktive Geraet.
    bool qualityRuntimeSettable() const { return device_ ? device_->qualityRuntimeSettable() : false; }
    void setJpegQualityUi(int ui0to63)  { if (device_) device_->setJpegQualityUi(ui0to63); }
    int  jpegQualityUi() const          { return device_ ? device_->jpegQualityUi() : -1; }

    // Zugriff auf das konkrete Geraet fuer Sonderfaelle (z. B. Sensor-Tuning),
    // bis solche Belange ins Interface wandern. nullptr vor begin().
    CameraDevice* device() { return device_; }

private:
    // Ziel-abhaengig genau EINE konkrete Kamera. device_ zeigt generisch darauf.
#if defined(CONFIG_IDF_TARGET_ESP32P4)
    Esp32P4MipiCamera concrete_;   // MIPI-CSI am ESP32-P4
#else
    Esp32S3DvpCamera  concrete_;   // OV3660/DVP am ESP32-S3
#endif
    CameraDevice*     device_;
    bool              ready_;
};

// Globale Instanz - wie server/preferences. Beruehrt keine Hardware, bis
// begin() aufgerufen wird.
extern CameraManager cameraManager;

#endif // CAMERA_MANAGER_H
