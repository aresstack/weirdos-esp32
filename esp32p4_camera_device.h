// ============================================================================
// esp32p4_camera_device.h  --  MIPI-CSI-Kamera am ESP32-P4 (esp_video / V4L2)
//
// Implementiert dasselbe CameraDevice-Interface wie Esp32S3DvpCamera, nutzt aber
// den P4-Pfad (esp_video, V4L2-ioctls, MIPI-CSI) statt esp_camera/DVP. Der Header
// ist target-neutral; die eigentliche Logik in der .cpp steht unter
// #if CONFIG_IDF_TARGET_ESP32P4 -> auf dem S3-Build kompiliert sie zu Stubs
// (das Geraet wird dort nie ausgewaehlt). NUR auf echter P4-Hardware baubar/testbar.
// ============================================================================
#ifndef ESP32P4_CAMERA_DEVICE_H
#define ESP32P4_CAMERA_DEVICE_H

#include "camera_device.h"
#include <cstdint>
#include <cstddef>

class Esp32P4MipiCamera : public CameraDevice {
public:
    struct Config {
        uint16_t width;        // z.B. 1920
        uint16_t height;       // z.B. 1080
        uint8_t  jpegQuality;  // 0..63 (0 = beste), falls Sensor/ISP JPEG liefert
        uint8_t  fbCount;      // V4L2-Puffer (mmap)
    };

    Esp32P4MipiCamera();
    ~Esp32P4MipiCamera() override;

    void configure(const Config& config);

    bool begin() override;
    bool isReady() const override;

    CameraFrame* acquireFrame() override;   // VIDIOC_DQBUF
    CameraFrame* acquireRawFrame() override; // VIDIOC_DQBUF ohne JPEG -> roher ISP-Frame (H.264)
    void         releaseFrame(CameraFrame* frame) override;  // VIDIOC_QBUF
    int          enumPixelFormats(uint32_t* outFourcc, int maxOut) const override; // VIDIOC_ENUM_FMT

    int  enumModes(CameraVideoMode* out, int maxOut) const override;   // V4L2 ENUM_FMT/FRAMESIZES/FRAMEINTERVALS
    bool setMode(uint16_t width, uint16_t height) override;            // Laufzeit-Umschaltung (V4L2 S_FMT)
    bool currentMode(uint16_t& width, uint16_t& height) const override;

    int  paramCount() const override;
    bool paramAt(int index, CameraParamInfo& out) const override;
    bool setParam(const char* key, int value) override;      // VIDIOC_S_CTRL

    // Laufzeit-JPEG-Qualitaet: der P4-HW-Encoder kann sie pro Frame lesen -> live setzbar.
    bool qualityRuntimeSettable() const override { return true; }
    void setJpegQualityUi(int ui0to63) override;             // UI 0..63 (0=best) -> P4 1..100
    int  jpegQualityUi() const override;                     // P4 1..100 -> UI 0..63

private:
    Config      config_;
    bool        ready_;
    CameraFrame frame_;
    int         fd_;            // V4L2-Device (/dev/video0), -1 = zu
    uint32_t    curPixFmt_;     // tatsaechlich ausgehandeltes V4L2-Pixelformat (0 = unbekannt)
    // Slice 2: ISP-Frame (RGB565/YUV) -> HW-JPEG-Encoder -> JPEG fuer den Stream.
    // Typen bewusst generisch (void*/int), damit der Header auf dem S3 kompiliert.
    bool        jpegCapable_;   // STATISCHE Faehigkeit: ISP-Ausgang ist JPEG-encoder-tauglich
                                // (in begin() erkannt). Wird von Laufzeitfehlern NIE veraendert.
                                // Der Runtime-JPEG-Pfad ist "aktiv" gdw. jpegEnc_ && jpegBuf_.
    uint32_t    inFourcc_;      // V4L2-FourCC des /dev/video0-Ausgangs
    int         jpegSrcType_;   // jpeg_enc_input_format_t (als int gehalten)
    void*       jpegEnc_;       // jpeg_encoder_handle_t
    uint8_t*    jpegBuf_;       // DMA-faehiger JPEG-Ausgabepuffer
    size_t      jpegCap_;       // Groesse des Ausgabepuffers
    volatile int curBufIndex_;  // aktuell gedequeuter Puffer (-1 = keiner) -- Poll aus setMode
    uint32_t    sequence_;
    int         jpegQuality_;   // P4-HW-Encoder-Skala 1..100 (hoeher = besser/groesser); pro Frame gelesen
    static const int MAX_BUFS = 4;
    void*       bufPtr_[MAX_BUFS];
    size_t      bufLen_[MAX_BUFS];
    int         bufCount_;

    // Synchronisation acquireFrame()/releaseFrame() <-> setMode(): waehrend der Laufzeit-
    // Umschaltung (Teardown/Reconfigure) darf kein Capture-Buffer benutzt/ausgeliehen sein.
    void*          lock_;         // SemaphoreHandle_t (opak, damit der Header FreeRTOS-frei bleibt)
    volatile bool  reconfiguring_;// true = Umschaltung laeuft -> acquireFrame() liefert nullptr

    // Gemeinsame Capture-Sequenz (S_FMT + REQBUFS/mmap + STREAMON + JPEG-Encoder + Probe).
    // begin() und setMode() nutzen GENAU DIESEN Pfad -> keine Duplikat-/Drift-Gefahr.
    bool applyCaptureFormat(uint16_t width, uint16_t height);
    void teardownCapture();   // NUR V4L2/CSI-Capture abbauen (STREAMOFF + munmap + REQBUFS(0)).
                              // Beruehrt den JPEG-Encoder NICHT (eigener Lifecycle, s.u.).
    // JPEG-Encoder-Lifecycle UNABHAENGIG vom Capture: Encoder wird einmal erzeugt und ueber
    // Aufloesungswechsel behalten (jpeg_encoder_process bekommt Geometrie pro Frame). Der
    // Ausgabepuffer waechst bei Bedarf transaktional (neu vor frei). Gibt false, wenn der
    // JPEG-Pfad NICHT bereitsteht (obwohl jpegCapable_) -> Aufrufer behandelt Switch als Fehler.
    bool ensureJpegEncoder(uint16_t width, uint16_t height);
};

#endif // ESP32P4_CAMERA_DEVICE_H
