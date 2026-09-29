// ============================================================================
// esp32s3_camera_device.h  --  Konkrete Kamera: OV3660 am XIAO ESP32-S3 Sense
//
// Kapselt esp_camera (paralleler DVP-Bus) hinter dem CameraDevice-Interface.
// Bewusst FREI von esp_camera/camera_fb_t/framesize_t/pixformat_t -> diese
// Typen verlassen die .cpp nicht. Aufloesungen werden als roher framesize_t-
// Zahlenwert (uint16_t) hereingereicht; die App besitzt weiterhin ihre
// FRAME_SIZE_OPTIONS-Tabelle und uebergibt (uint16_t)option.size.
//
// Spaeter: Esp32P4MipiCamera als zweite CameraDevice-Implementierung, ohne
// dass Stream-Service oder AI-Detektor etwas davon merken.
// ============================================================================
#ifndef ESP32S3_CAMERA_DEVICE_H
#define ESP32S3_CAMERA_DEVICE_H

#include "camera_device.h"
#include <cstdint>

class Esp32S3DvpCamera : public CameraDevice {
public:
    // Startparameter fuer begin(). Spiegelt die bisherigen Sketch-Defaults;
    // die App reicht ihre geladenen NVS-Werte hier hinein.
    struct Config {
        uint16_t frameSize;      // Start-Aufloesung  (roher framesize_t-Wert)
        uint16_t maxFrameSize;   // hoechste Aufloesung -> dimensioniert den Puffer
        uint8_t  jpegQuality;    // LIVE-Qualitaet (sensor set_quality), 0..63 (0 = beste)
        uint8_t  bufferQuality;  // Puffer-Dimensionierung (config.jpeg_quality); 0 = groesster
        uint8_t  fbCount;        // Anzahl Framebuffer (1..2)
    };

    Esp32S3DvpCamera();
    ~Esp32S3DvpCamera() override;

    // Vor begin() aufrufen. Ohne configure() gelten interne Defaults.
    void configure(const Config& config);

    bool begin() override;              // esp_camera_init + Sensorabstimmung + Selbsttest
    bool isReady() const override;

    // Ein Frame gleichzeitig "in flight": acquireFrame() liefert nullptr,
    // solange der vorherige nicht per releaseFrame() zurueckgegeben wurde.
    CameraFrame* acquireFrame() override;
    void         releaseFrame(CameraFrame* frame) override;

    // Native Capture-Aufloesungen aus dem esp_camera-Sensor (bis zum Sensor-Maximum).
    int  enumModes(CameraVideoMode* out, int maxOut) const override;

    // Aufloesung setzen: w×h intern auf framesize_t abbilden -> set_framesize (bis Maximum).
    bool setMode(uint16_t width, uint16_t height) override;

    // OV3660-Sensortunables (Helligkeit/Kontrast/Saettigung/AEC/AGC/AWB/Spiegeln...).
    int  paramCount() const override;
    bool paramAt(int index, CameraParamInfo& out) const override;
    bool setParam(const char* key, int value) override;

private:
    Config      config_;
    bool        ready_;
    CameraFrame frame_;     // wiederverwendet -> stabiler Zeiger fuer den Konsumenten
    void*       rawFrame_;  // camera_fb_t* opak gehalten (Header bleibt esp_camera-frei)
    uint32_t    sequence_;
};

#endif // ESP32S3_CAMERA_DEVICE_H
