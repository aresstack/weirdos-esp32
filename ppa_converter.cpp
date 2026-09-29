// ============================================================================
// ppa_converter.cpp  --  siehe ppa_converter.h
//
// Baustein-Schalter WEIRDOS_FEATURE_H264 (weirdos_features.h): die PPA ist der Zulieferer des
// HW-H.264-Encoders (RGB565 -> YUV420), darum haengt sie am selben Schalter.
//   1 = echte Implementierung (driver/ppa.h, PPA-SRM) -- unveraendert.
//   0 = Stub am Dateiende (hwAvailable()=false, begin()=false).
// Der Schalter ist SoC-geklammert (ausserhalb des P4 hart 0), der fruehere Target-Test
// CONFIG_IDF_TARGET_ESP32P4 steckt also im Schalter: EINE Bedingung, kein zweiter Stub.
// ============================================================================
#include "weirdos_features.h"
#include "ppa_converter.h"

#if WEIRDOS_FEATURE_H264
#include "driver/ppa.h"
#include "esp_heap_caps.h"
#include "esp_err.h"
#include "esp_log.h"
#include <cstring>

static const char* TAGPPA = "ppaconv";
#define PPA_OUT_ALIGN 128   // externer (PSRAM) Puffer: an L2-Cache-Line ausrichten (Groesse + Adresse)

// Groesstmoeglichen Crop <= src finden, so dass crop * k/16 == dst EXAKT (k in 1..16). Die PPA
// quantisiert den Scale auf 1/16 -> nur so entsteht genau dst ohne unbeschriebenen Rand. EIN
// gemeinsamer Scale fuer beide Achsen (sonst verzerrt: 800x800 aus 1920x1080 wuerde horizontal 0,5 /
// vertikal 1,0 skaliert). Kleinstes k = groesster Crop = maximales Blickfeld; auf der laengeren Achse
// wird mittig beschnitten (kein Letterbox). false, wenn kein k beide Achsen exakt abdeckt.
static bool findCropScaleUniform(uint16_t dstW, uint16_t dstH, uint16_t srcW, uint16_t srcH,
                                 uint16_t& cropW, uint16_t& cropH, float& scale) {
    // NUR GERADE k: der IDF-PPA-Treiber (ppa_srm.c) maskiert fuer YUV420-Ausgabe das niedrigste Bit
    // des 1/16-Bruchs ("scale_frag & ~1"). 5/16 wird so still zu 4/16: 320x320 aus 1024x1024-Crop
    // ergab 256x256 -- der Rest des Encoder-Eingabepuffers blieb Muell (bunter Rand/Rauschen).
    for (int k = 2; k <= 16; k += 2) {
        if (((int)dstW * 16) % k || ((int)dstH * 16) % k) continue;   // Crops muessen ganzzahlig sein
        int cw = (int)dstW * 16 / k, ch = (int)dstH * 16 / k;
        if (cw <= (int)srcW && ch <= (int)srcH) {
            cropW = (uint16_t)cw; cropH = (uint16_t)ch; scale = (float)k / 16.0f;
            return true;
        }
    }
    return false;
}

PpaConverter::PpaConverter() : client_(nullptr), outBuf_(nullptr), outCap_(0), ready_(false) {}
PpaConverter::~PpaConverter() { end(); }

bool PpaConverter::hwAvailable() { return true; }

bool PpaConverter::begin() {
    if (ready_) return true;
    ppa_client_config_t cc = {};
    cc.oper_type            = PPA_OPERATION_SRM;
    cc.max_pending_trans_num = 1;                       // blockierend -> 1 reicht
    cc.data_burst_length    = PPA_DATA_BURST_LENGTH_128;
    ppa_client_handle_t h = nullptr;
    esp_err_t e = ppa_register_client(&cc, &h);
    if (e != ESP_OK || !h) { ESP_LOGE(TAGPPA, "ppa_register_client=%d (%s)", (int)e, esp_err_to_name(e)); return false; }
    client_ = h; ready_ = true;
    return true;
}

void PpaConverter::end() {
    if (client_) { ppa_unregister_client((ppa_client_handle_t)client_); client_ = nullptr; }
    if (outBuf_) { heap_caps_free(outBuf_); outBuf_ = nullptr; }
    outCap_ = 0; ready_ = false;
}

bool PpaConverter::ensureOut(size_t need) {
    size_t cap = (need + PPA_OUT_ALIGN - 1) & ~((size_t)PPA_OUT_ALIGN - 1);   // auf Cache-Line runden
    if (outBuf_ && outCap_ >= cap) return true;
    if (outBuf_) { heap_caps_free(outBuf_); outBuf_ = nullptr; outCap_ = 0; }
    // DMA-faehig anlegen (MALLOC_CAP_DMA): dieser Puffer wird von der PPA per DMA beschrieben UND vom
    // H.264-Encoder per DMA gelesen -> ohne DMA-/cache-kohaerenten Speicher liest der Encoder veraltete
    // Cache-Daten (esp_cache_msync-Fehler) -> lila Macroblock-Korruption. 128-Byte-aligned bleibt.
    // FAIL CLOSED: kein Fallback auf Speicher ohne DMA-Cap. Ein Puffer, den PPA/H.264-DMA nicht
    // erreichen, "funktioniert" scheinbar und liefert dann Muell (siehe LP-SRAM-Befund). Lieber
    // ehrlich kein Stream als ein stiller Bildfehler.
    outBuf_ = (uint8_t*)heap_caps_aligned_alloc(PPA_OUT_ALIGN, cap, MALLOC_CAP_SPIRAM | MALLOC_CAP_DMA | MALLOC_CAP_8BIT);
    if (!outBuf_) { ESP_LOGE(TAGPPA, "kein DMA-faehiger PSRAM-Puffer (%u B)", (unsigned)cap); return false; }
    outCap_ = cap;
    return true;
}

bool PpaConverter::rgb565ToYuv420(const uint8_t* src, uint16_t srcW, uint16_t srcH,
                                  uint16_t dstW, uint16_t dstH,
                                  const uint8_t** out, size_t* outLen, bool scaleDown) {
    if (!ready_ || !src || !out || !outLen) return false;

    uint16_t cropW, cropH, offX, offY; float sx, sy;
    if (scaleDown) {
        // Naive Ganzbild-Skalierung (nur Diagnose): PPA quantisiert scale auf 1/16 -> kann unterfuellen.
        cropW = srcW; cropH = srcH; offX = 0; offY = 0;
        sx = (float)dstW / (float)srcW; sy = (float)dstH / (float)srcH;
    } else {
        // Produktionspfad: EIN Scale fuer beide Achsen, groesster Crop <= src mit EXAKTEM k/16-Scale,
        // der genau dst ergibt (400x400 aus 800x800 -> Crop 800x800 * 0,5 = volles Blickfeld; 800x800
        // aus 1920x1080 -> Crop 800x800 mittig * 1,0). Ausgabe voll gefuellt, nie verzerrt.
        if (!findCropScaleUniform(dstW, dstH, srcW, srcH, cropW, cropH, sx)) {
            ESP_LOGE(TAGPPA, "%ux%u aus %ux%u nicht exakt per 1/16-PPA-Scale darstellbar", dstW, dstH, srcW, srcH);
            return false;
        }
        sy = sx;
        offX = (srcW - cropW) / 2; offY = (srcH - cropH) / 2;
    }

    size_t need = (size_t)dstW * dstH * 3 / 2;   // YUV420
    if (!ensureOut(need)) { ESP_LOGE(TAGPPA, "out-Puffer-Alloc %u fehlgeschlagen", (unsigned)need); return false; }

    ppa_srm_oper_config_t op = {};
    op.in.buffer         = src;
    op.in.pic_w          = srcW;   op.in.pic_h  = srcH;
    op.in.block_w        = cropW;  op.in.block_h = cropH;
    op.in.block_offset_x = offX;   op.in.block_offset_y = offY;
    op.in.srm_cm         = PPA_SRM_COLOR_MODE_RGB565;

    op.out.buffer         = outBuf_;
    op.out.buffer_size    = outCap_;
    op.out.pic_w          = dstW; op.out.pic_h = dstH;
    op.out.block_offset_x = 0;    op.out.block_offset_y = 0;
    op.out.srm_cm         = PPA_SRM_COLOR_MODE_YUV420;
    op.out.yuv_range      = PPA_COLOR_RANGE_LIMIT;                 // H.264-Standard (BT.601 limited)
    op.out.yuv_std        = PPA_COLOR_CONV_STD_RGB_YUV_BT601;

    op.rotation_angle    = PPA_SRM_ROTATION_ANGLE_0;
    op.scale_x           = sx;    // exakter k/16-Scale (crop*k/16 == dst)
    op.scale_y           = sy;
    op.mirror_x          = false; op.mirror_y = false;
    op.rgb_swap          = false;
    op.byte_swap         = false;   // ggf. true, falls ISP-RGB565-Byteorder gedreht ist (HW-Test)
    op.alpha_update_mode = PPA_ALPHA_NO_CHANGE;
    op.mode              = PPA_TRANS_MODE_BLOCKING;

    esp_err_t e = ppa_do_scale_rotate_mirror((ppa_client_handle_t)client_, &op);
    if (e != ESP_OK) { ESP_LOGW(TAGPPA, "ppa SRM=%d (%s)", (int)e, esp_err_to_name(e)); return false; }
    *out = outBuf_; *outLen = need;
    return true;
}

bool PpaConverter::diagScale(const uint8_t* src, uint16_t srcW, uint16_t srcH, uint16_t dstW, uint16_t dstH,
                             size_t* writtenBytes, size_t* lastByte, uint16_t* filledW, uint16_t* filledH) {
    size_t need = (size_t)dstW * dstH * 3 / 2;
    if (!ensureOut(need)) return false;
    memset(outBuf_, 0x5A, need);                     // sentinel
    const uint8_t* out = nullptr; size_t outLen = 0;
    if (!rgb565ToYuv420(src, srcW, srcH, dstW, dstH, &out, &outLen, /*scaleDown=*/true)) return false;

    size_t written = 0, last = 0;
    for (size_t i = 0; i < need; i++) if (outBuf_[i] != 0x5A) { written++; last = i; }
    size_t rowBytes = (size_t)dstW * 3 / 2;          // O_UYY_E_VYY: 1.5*W Bytes/Zeile
    size_t row0last = 0;
    for (size_t i = 0; i < rowBytes && i < need; i++) if (outBuf_[i] != 0x5A) row0last = i;
    *filledW = (uint16_t)(((row0last + 1) * 2) / 3);
    *filledH = (uint16_t)((last + 1) / (rowBytes ? rowBytes : 1));
    *writtenBytes = written; *lastByte = last;
    return true;
}

#else   // ------------------------------------------------------------------
// Stub: nicht im Build enthalten (WEIRDOS_FEATURE_H264=0; auf Nicht-P4 immer). Keine PPA ->
// dieselben Symbole, triviale Koerper (hwAvailable() false -> /ppatest meldet "keine PPA").
PpaConverter::PpaConverter() : client_(nullptr), outBuf_(nullptr), outCap_(0), ready_(false) {}
PpaConverter::~PpaConverter() {}
bool PpaConverter::hwAvailable() { return false; }
bool PpaConverter::begin() { return false; }
void PpaConverter::end() {}
bool PpaConverter::rgb565ToYuv420(const uint8_t*, uint16_t, uint16_t, uint16_t, uint16_t,
                                  const uint8_t**, size_t*, bool) { return false; }
bool PpaConverter::diagScale(const uint8_t*, uint16_t, uint16_t, uint16_t, uint16_t,
                             size_t*, size_t*, uint16_t*, uint16_t*) { return false; }
#endif // WEIRDOS_FEATURE_H264
