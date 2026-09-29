// ============================================================================
// h264_encoder.cpp  --  siehe h264_encoder.h
// ============================================================================
#include "h264_encoder.h"
#include <sdkconfig.h>

#if defined(CONFIG_IDF_TARGET_ESP32P4)
// ---------------------------------------------------------------------------
// Echter P4-Pfad: HW-H.264-Encoder (esp_h264_enc_single_hw)
// ---------------------------------------------------------------------------
#include "esp_h264_enc_single_hw.h"   // esp_h264_enc_hw_new / _get_param_hd
#include "esp_h264_enc_single.h"      // esp_h264_enc_open/process/close/del
#include "esp_h264_enc_param.h"       // esp_h264_enc_set_bitrate/_fps
#include "esp_h264_types.h"           // cfg/in/out-Frame, Formate, Fehler-/Frame-Typen
#include "esp_h264_alloc.h"           // esp_h264_calloc_prefer / esp_h264_free
#include "esp_heap_caps.h"
#include "esp_log.h"

static const char* TAGH264 = "h264";

H264Encoder::H264Encoder()
    : enc_(nullptr), param_(nullptr), outBuf_(nullptr), outCap_(0),
      w_(0), h_(0), pts_(0), gop_(0), gopAlt_(false), ready_(false), lastErr_(0), lastStage_(0) {}

H264Encoder::~H264Encoder() { end(); }

bool H264Encoder::hwAvailable() { return true; }   // P4 hat den HW-Encoder (Build-/Lib-Eigenschaft)

// Kandidaten-Eingangsformate fuer den Capability-Scan (probeFormat). Reihenfolge = Praeferenz:
// YUV420 zuerst (der native P4-HW-Eingang laut process-Doku: raw_len = w*h*1.5), dann die
// packed-YUV/RGB-Varianten. Welche hw_new wirklich akzeptiert, entscheidet die Hardware.
struct H264FmtCand { esp_h264_raw_format_t fmt; const char* name; };
static const H264FmtCand kFmtCands[] = {
    { ESP_H264_RAW_FMT_O_UYY_E_VYY, "O_UYY_E_VYY_YUV420" },
    { ESP_H264_RAW_FMT_I420,        "I420" },
    { ESP_H264_RAW_FMT_YUYV,        "YUYV" },
    { ESP_H264_RAW_FMT_UYVY,        "UYVY" },
    { ESP_H264_RAW_FMT_VUY,         "VUY" },
    { ESP_H264_RAW_FMT_RGB565_LE,   "RGB565_LE" },
    { ESP_H264_RAW_FMT_BGR888,      "BGR888" },
};

int H264Encoder::probeFormatCount() { return (int)(sizeof(kFmtCands) / sizeof(kFmtCands[0])); }

int H264Encoder::probeFormat(uint16_t width, uint16_t height, int idx, const char** name) {
    if (idx < 0 || idx >= probeFormatCount()) { if (name) *name = "?"; return -99; }
    if (name) *name = kFmtCands[idx].name;
    esp_h264_enc_cfg_t cfg = {};
    cfg.pic_type   = kFmtCands[idx].fmt;
    cfg.gop = 30; cfg.fps = 15;
    cfg.res.width  = width; cfg.res.height = height;
    cfg.rc.bitrate = 1000000; cfg.rc.qp_min = 25; cfg.rc.qp_max = 45;
    esp_h264_enc_handle_t enc = nullptr;
    esp_h264_err_t e = esp_h264_enc_hw_new(&cfg, &enc);
    if (e == ESP_H264_ERR_OK && enc) esp_h264_enc_del(enc);   // nur Faehigkeit testen -> gleich wieder weg
    return (int)e;
}

static inline esp_h264_raw_format_t mapPixFmt(H264PixFmt f) {
    switch (f) {
        case H264PixFmt::YUV420_OUEV: return ESP_H264_RAW_FMT_O_UYY_E_VYY;  // einziger HW-Eingang am P4
        case H264PixFmt::YUYV:        return ESP_H264_RAW_FMT_YUYV;
        case H264PixFmt::UYVY:        return ESP_H264_RAW_FMT_UYVY;
        case H264PixFmt::BGR888:      return ESP_H264_RAW_FMT_BGR888;
        default:                      return ESP_H264_RAW_FMT_RGB565_LE;
    }
}

bool H264Encoder::begin(uint16_t width, uint16_t height, uint8_t fps, uint32_t bitrate,
                        uint8_t gop, H264PixFmt fmt) {
    if (ready_) return true;
    w_ = width; h_ = height; pts_ = 0; lastErr_ = 0; lastStage_ = 0; gopAlt_ = false;

    esp_h264_enc_cfg_t cfg = {};
    cfg.pic_type   = mapPixFmt(fmt);   // ISP-Ausgang -> Encoder-Eingang (RGB565/YUYV direkt, keine Konvertierung)
    cfg.gop        = gop ? gop : (fps ? fps : 30);  // IDR-Abstand ~1s
    cfg.fps        = fps ? fps : 15;
    cfg.res.width  = width;
    cfg.res.height = height;
    cfg.rc.bitrate = bitrate ? bitrate : 1500000;   // Default 1,5 Mbit/s
    cfg.rc.qp_min  = 25;
    cfg.rc.qp_max  = 45;
    gop_ = cfg.gop;

    esp_h264_enc_handle_t enc = nullptr;
    lastStage_ = 1;
    esp_h264_err_t e = esp_h264_enc_hw_new(&cfg, &enc);
    if (e != ESP_H264_ERR_OK || !enc) {
        lastErr_ = (int)e;
        ESP_LOGE(TAGH264, "esp_h264_enc_hw_new: %d (fmt=0x%08x %ux%u)", (int)e,
                 (unsigned)cfg.pic_type, width, height);
        return false;
    }
    enc_ = enc;

    lastStage_ = 2;
    e = esp_h264_enc_open(enc);
    if (e != ESP_H264_ERR_OK) {
        lastErr_ = (int)e;
        ESP_LOGE(TAGH264, "esp_h264_enc_open: %d", (int)e);
        esp_h264_enc_del(enc); enc_ = nullptr; return false;
    }

    // Param-Handle fuer Laufzeit-Setter (Bitrate/FPS) merken (best effort).
    esp_h264_enc_param_hw_handle_t ph = nullptr;
    if (esp_h264_enc_hw_get_param_hd(enc, &ph) == ESP_H264_ERR_OK) param_ = ph;

    // NAL-Ausgabepuffer: gross genug fuer einen kompletten IDR = Rohframe-Groesse (Espressif-Referenz:
    // verhindert ESP_H264_ERR_OVERFLOW beim ersten Keyframe). Der HW-Codec macht esp_cache_msync auf
    // DIESEN Puffer -> ADRESSE UND GROESSE muessen auf die Cache-Line (128 B = 0x80) ausgerichtet sein,
    // sonst "esp_cache_msync: not aligned with cache line size". Also 128-aligned allozieren + Groesse
    // auf 128 aufrunden (16 war falsch -> Crash beim Encode). PSRAM schont den internen DMA-Heap.
    lastStage_ = 3;
    size_t want = (size_t)width * height * 2;   // Rohframe-Groesse -> overflow-fest
    if (want < 65536) want = 65536;
    want = (want + 127) & ~((size_t)127);       // auf Cache-Line (128 B) aufrunden
    // DMA-faehig (MALLOC_CAP_DMA): der HW-Encoder schreibt hier per DMA, die CPU liest zum Senden ->
    // ohne DMA-/cache-kohaerenten Speicher liest die CPU veraltete Cache-Daten (esp_cache_msync-Fehler)
    // -> korrupte NAL -> lila Artefakte beim Decoder.
    // FAIL CLOSED: nur DMA-faehiger PSRAM. Kein Fallback auf Speicher, den die H.264-DMA nicht
    // erreicht -- der wuerde scheinbar funktionieren und korrupte NALs liefern (LP-SRAM-Befund).
    outBuf_ = (uint8_t*)heap_caps_aligned_alloc(128, want, MALLOC_CAP_SPIRAM | MALLOC_CAP_DMA | MALLOC_CAP_8BIT);
    if (!outBuf_) {
        lastErr_ = (int)ESP_H264_ERR_MEM;
        ESP_LOGE(TAGH264, "NAL-Puffer-Alloc fehlgeschlagen (%u B)", (unsigned)want);
        esp_h264_enc_close(enc); esp_h264_enc_del(enc); enc_ = nullptr; return false;
    }
    outCap_ = want;

    lastStage_ = 0;
    ready_ = true;
    ESP_LOGI(TAGH264, "HW-H.264 %ux%u @%ufps %ubps GOP%u, NAL-Puffer %uKB (PSRAM)",
             width, height, cfg.fps, (unsigned)cfg.rc.bitrate, cfg.gop, (unsigned)(outCap_ / 1024));
    return true;
}

void H264Encoder::end() {
    if (enc_) {
        esp_h264_enc_close((esp_h264_enc_handle_t)enc_);
        esp_h264_enc_del((esp_h264_enc_handle_t)enc_);
        enc_ = nullptr;
    }
    if (outBuf_) { esp_h264_free(outBuf_); outBuf_ = nullptr; }
    param_ = nullptr; outCap_ = 0; ready_ = false;
}

bool H264Encoder::encode(const uint8_t* raw, size_t rawLen, const uint8_t** out, size_t* outLen, bool* keyframe) {
    if (!ready_ || !raw || !out || !outLen) return false;

    esp_h264_enc_in_frame_t in = {};
    in.raw_data.buffer = (uint8_t*)raw;
    in.raw_data.len    = (uint32_t)rawLen;
    in.pts             = pts_;

    esp_h264_enc_out_frame_t of = {};
    of.raw_data.buffer = outBuf_;
    of.raw_data.len    = (uint32_t)outCap_;

    esp_h264_err_t e = esp_h264_enc_process((esp_h264_enc_handle_t)enc_, &in, &of);
    if (e != ESP_H264_ERR_OK) {
        lastErr_ = (int)e; lastStage_ = 4;
        // ESP_H264_ERR_OVERFLOW = NAL groesser als outBuf_ -> Puffer waechst schon in Rohframe-Groesse
        // (begin), sollte praktisch nicht vorkommen; falls doch, sieht man es hier eindeutig.
        ESP_LOGW(TAGH264, "encode process: %d (outCap=%u)", (int)e, (unsigned)outCap_);
        return false;
    }
    pts_++;
    *out    = outBuf_;
    *outLen = of.length;
    if (keyframe) *keyframe = (of.frame_type == ESP_H264_FRAME_TYPE_IDR ||
                              of.frame_type == ESP_H264_FRAME_TYPE_I);
    return of.length > 0;
}

void H264Encoder::setBitrate(uint32_t bitrate) {
    if (param_) esp_h264_enc_set_bitrate((esp_h264_enc_param_handle_t)param_, bitrate);
}
void H264Encoder::setFps(uint8_t fps) {
    if (param_) esp_h264_enc_set_fps((esp_h264_enc_param_handle_t)param_, fps);
}
void H264Encoder::forceIdr() {
    if (!param_ || gop_ == 0) return;
    gopAlt_ = !gopAlt_;
    // Anderer GOP-Wert als der im HW-Handle gemerkte -> enc_process macht den naechsten Frame zum IDR
    // (inkl. SPS/PPS) und uebernimmt den neuen Wert. gop+1 statt gop ist als IDR-Abstand unerheblich.
    esp_h264_enc_set_gop((esp_h264_enc_param_handle_t)param_, (uint8_t)(gop_ + (gopAlt_ ? 1 : 0)));
}

#else   // ------------------------------------------------------------------
// Nicht-P4: kein HW-H.264-Encoder -> Stubs (das Feature wird dort nie angeboten).
H264Encoder::H264Encoder()
    : enc_(nullptr), param_(nullptr), outBuf_(nullptr), outCap_(0),
      w_(0), h_(0), pts_(0), gop_(0), gopAlt_(false), ready_(false), lastErr_(0), lastStage_(0) {}
H264Encoder::~H264Encoder() {}
bool H264Encoder::hwAvailable() { return false; }
int  H264Encoder::probeFormatCount() { return 0; }
int  H264Encoder::probeFormat(uint16_t, uint16_t, int, const char** name) { if (name) *name = "?"; return -99; }
bool H264Encoder::begin(uint16_t, uint16_t, uint8_t, uint32_t, uint8_t, H264PixFmt) { return false; }
void H264Encoder::end() {}
bool H264Encoder::encode(const uint8_t*, size_t, const uint8_t**, size_t*, bool*) { return false; }
void H264Encoder::setBitrate(uint32_t) {}
void H264Encoder::setFps(uint8_t) {}
void H264Encoder::forceIdr() {}
#endif
