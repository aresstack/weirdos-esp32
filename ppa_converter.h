// ============================================================================
// ppa_converter.h  --  HW-Farbraum-/Skalierungs-Konverter (ESP32-P4 PPA-SRM)
//
// Der P4-ISP liefert RGB565 (bewusst so, weil das direkt in den stabilen HW-JPEG-Pfad geht).
// Der P4-HW-H.264-Encoder akzeptiert aber NUR YUV420 (O_UYY_E_VYY) als Eingang (empirisch
// verifiziert: alle anderen Formate -> ESP_H264_ERR_ARG). Statt CPU-Konvertierung macht der
// Pixel Processing Accelerator (PPA) RGB565->YUV420 + optionales Downscale in EINEM HW-Schritt.
//
// Damit bleibt der Architekturvertrag sauber: EIN Capture-Owner (RGB565) -> Fan-out
//   RGB565 --HW-JPEG--> MJPEG/Snapshot
//   RGB565 --PPA------> YUV420 --HW-H.264--> H264-Stream
// Nur auf dem P4 real; andere Targets kompilieren zu Stubs (hwAvailable() == false).
// ============================================================================
#ifndef PPA_CONVERTER_H
#define PPA_CONVERTER_H

#include <cstdint>
#include <cstddef>

class PpaConverter {
public:
    PpaConverter();
    ~PpaConverter();

    bool begin();          // PPA-SRM-Client registrieren
    void end();
    bool isReady() const { return ready_; }

    // src = RGB565 (srcW*srcH*2 B, DMA/PSRAM-faehig, z.B. der ISP-mmap-Puffer). Ausgabe YUV420
    // (dstW*dstH*3/2) in den internen, cache-aligned PSRAM-Puffer. *out gueltig bis zum naechsten
    // Aufruf/end(). dstW/dstH sollten 16er-Vielfache sein (H.264-Macroblocks). Blockierend.
    // scaleDown=false (Default): zentraler Crop + exakter k/16-Scale (findCropScale) -> voll gefuellt.
    // scaleDown=true: naive Ganzbild-Skalierung srcW->dstW (block=src, scale=dst/src) -- NUR fuer die
    // /ppatest-Diagnose der PPA-Scale-Geometrie (kann unterfuellen).
    bool rgb565ToYuv420(const uint8_t* src, uint16_t srcW, uint16_t srcH,
                        uint16_t dstW, uint16_t dstH,
                        const uint8_t** out, size_t* outLen, bool scaleDown = false);

    // Diagnose: Ausgabe vorher mit sentinel (0x5A) fuellen, naive Skalierung, danach zaehlen, welche
    // Bytes/Breite/Hoehe die PPA WIRKLICH schreibt. Zeigt die Macroblock-/64px-Regel (DIG-734).
    bool diagScale(const uint8_t* src, uint16_t srcW, uint16_t srcH, uint16_t dstW, uint16_t dstH,
                   size_t* writtenBytes, size_t* lastByte, uint16_t* filledW, uint16_t* filledH);

    static bool hwAvailable();   // P4 = true (PPA vorhanden)

private:
    bool ensureOut(size_t need);
    void*    client_;   // ppa_client_handle_t (opak, damit der Header IDF-frei bleibt)
    uint8_t* outBuf_;   // cache-aligned PSRAM-YUV420-Ausgabepuffer
    size_t   outCap_;
    bool     ready_;
};

#endif // PPA_CONVERTER_H
