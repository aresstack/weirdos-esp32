// ============================================================================
// h264_encoder.h  --  Duenner Wrapper um den HW-H.264-Encoder des ESP32-P4
//
// Erste Phase des H.264-Video-Blocks: die Encoder-Grundlage (esp_h264_enc_single_hw).
// H.264 loest das MJPEG-Bandbreiten-/interne-Heap-Problem strukturell (Inter-Frame-
// Kompression -> ~10x kleinere Frames als MJPEG). NUR auf dem P4 real (HW-Encoder);
// andere Targets kompilieren zu Stubs (hwAvailable() == false).
//
// NOCH NICHT verdrahtet (eigene, hardware-validierte Folgephasen):
//   Phase 2: Kamera-ISP-Ausgang (RGB565/YUV) -> Encoder-Input (pic_type muss passen).
//   Phase 3: Transport (fMP4/MSE fuer den Browser ODER RTSP) statt MJPEG-multipart.
//   Phase 4: UI (Codec-Dropdown mit HW-Erkennung + <video>/MSE-Playback).
// ============================================================================
#ifndef H264_ENCODER_H
#define H264_ENCODER_H

#include <cstdint>
#include <cstddef>

// Roh-Eingabeformate. WICHTIG (empirisch am P4 verifiziert): der HW-Encoder akzeptiert auf diesem
// Build NUR YUV420_OUEV (= O_UYY_E_VYY); RGB565/YUYV/... liefern ESP_H264_ERR_ARG. Die anderen
// Werte bleiben fuer den (spaeteren) Rev-3-Pfad / SW-Encoder erhalten. Standardpfad: PPA konvertiert
// RGB565->YUV420 und wir fuettern YUV420_OUEV.
enum class H264PixFmt { YUV420_OUEV, RGB565_LE, YUYV, UYVY, BGR888 };

class H264Encoder {
public:
    H264Encoder();
    ~H264Encoder();

    // Encoder anlegen + oeffnen. fmt = Roh-Eingabeformat; MUSS zum ISP-Ausgang passen (der P4-ISP
    // liefert RGB565 -> Default). bitrate in bit/s (z.B. 1_500_000 fuer LTE), gop = IDR-Abstand in
    // Frames (0 -> = fps).
    bool begin(uint16_t width, uint16_t height, uint8_t fps, uint32_t bitrate,
               uint8_t gop = 0, H264PixFmt fmt = H264PixFmt::YUV420_OUEV);
    void end();
    bool isReady() const { return ready_; }

    // Ein Rohbild encodieren. *out zeigt in den internen NAL-Ausgabepuffer (gueltig bis zum
    // naechsten encode()/end()). *keyframe = true bei IDR. Rueckgabe false = Encode-Fehler.
    // raw muss DMA-faehig + im begin()-pic_type-Format sein (Kamera-mmap-Puffer erfuellt das).
    bool encode(const uint8_t* raw, size_t rawLen, const uint8_t** out, size_t* outLen, bool* keyframe);

    // Laufzeit-Anpassung (Grundlage fuer adaptives LTE-Streaming, Phase spaeter).
    void setBitrate(uint32_t bitrate);
    void setFps(uint8_t fps);
    // Naechsten Frame als IDR erzwingen. PFLICHT nach jedem encode()-Fehler: der HW-Encoder hat den
    // Frame dann bereits verarbeitet (Referenz aktualisiert), der Decoder hat ihn aber nie bekommen --
    // jeder weitere P-Frame driftet bis zum naechsten Keyframe. esp_h264 1.3.0 hat kein force_idr;
    // Umweg: GOP zwischen gop und gop+1 umschalten (enc_process: gop != hw_hd->gop -> IDR).
    void forceIdr();

    // "supported": besitzt dieses Target ueberhaupt den HW-H.264-Encoder (P4 = true)? Reine
    // Build-/Lib-Eigenschaft -- sagt NICHT, dass begin() auf dieser HW erfolgreich war. Fuers
    // UI-Dropdown (H.264 anbieten vs. ausgegraut).
    static bool hwAvailable();

    // Diagnose nach einem fehlgeschlagenen begin()/encode(): exakter esp_h264_err_t-Code und in
    // welchem Schritt (1=hw_new, 2=open, 3=NAL-Puffer-Alloc, 4=encode/process). 0 = kein Fehler.
    int lastError() const { return lastErr_; }
    int lastStage() const { return lastStage_; }

    // Capability-Scan: welche Roh-Eingabeformate akzeptiert der HW-Encoder bei (w,h) UEBERHAUPT?
    // probeFormat() ruft esp_h264_enc_hw_new() mit dem idx-ten Kandidaten und gibt den esp_h264_err_t
    // zurueck (0 = akzeptiert). *name = Klartextname. So findet /h264probe empirisch das HW-Format,
    // statt es zu raten. Nicht-P4: count 0.
    static int probeFormatCount();
    static int probeFormat(uint16_t width, uint16_t height, int idx, const char** name);

private:
    void*    enc_;      // esp_h264_enc_handle_t (opak, damit der Header IDF-frei bleibt)
    void*    param_;    // esp_h264_enc_param_handle_t (fuer Laufzeit-Setter)
    uint8_t* outBuf_;   // 16-Byte-aligned PSRAM-NAL-Ausgabepuffer
    size_t   outCap_;
    uint16_t w_, h_;
    uint32_t pts_;      // monoton steigend
    uint8_t  gop_;      // konfigurierter IDR-Abstand (forceIdr toggelt gop/gop+1)
    bool     gopAlt_;   // aktuell gop+1 gesetzt?
    bool     ready_;
    int      lastErr_;  // letzter esp_h264_err_t (0 = OK)
    int      lastStage_;// wo (s.o.)
};

#endif // H264_ENCODER_H
