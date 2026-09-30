// ============================================================================
// esp32s3_camera_device.cpp  --  esp_camera-Wrapper (nur hier ist esp_camera bekannt)
//
// Bildet den bewaehrten Init-Pfad aus tryCameraInit() ab: Pins der
// CAMERA_MODEL_XIAO_ESP32S3-Belegung, Puffer im PSRAM auf die Maximal-
// aufloesung dimensioniert, OV3660-Sensorabstimmung, Selbsttest ueber den
// DVP-Datenpfad. Die PSRAM-Budget-/Fallback-Logik bleibt (vorerst) in der App.
// ============================================================================
#include "weirdos_features.h"        // WEIRDOS_FEATURE_CAMERA -- der Schalter dieses Bausteins
#include "esp32s3_camera_device.h"   // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
#if WEIRDOS_FEATURE_CAMERA
// ============================================================================
// Echte Implementierung (WEIRDOS_FEATURE_CAMERA=1): esp_camera/DVP-Pfad, nur auf Nicht-P4
// ============================================================================
#include <sdkconfig.h>   // CONFIG_IDF_TARGET_ESP32P4 -> auf P4 ist dieses DVP-Geraet inaktiv

// Dieses Geraet ist der esp_camera/DVP-Pfad (XIAO ESP32-S3). Auf dem ESP32-P4
// (MIPI/V4L2) gibt es weder esp_camera.h noch dieses Geraet -> gesamter Body
// ausgeklammert, damit der P4-Build gruen bleibt (dort waehlt CameraManager
// Esp32P4MipiCamera; Esp32S3DvpCamera wird nie instanziiert).
#if !defined(CONFIG_IDF_TARGET_ESP32P4)

#include "esp_camera.h"
#include "esp_log.h"

// Pinbelegung CAMERA_MODEL_XIAO_ESP32S3 (identisch zu den CAM_PIN_*-Defines
// im Sketch). Bewusst hier dupliziert: der Wrapper ist board-spezifisch und
// soll ohne Sketch-Header eigenstaendig kompilieren.
namespace {
constexpr int PIN_PWDN  = -1;
constexpr int PIN_RESET = -1;
constexpr int PIN_XCLK  = 10;
constexpr int PIN_SIOD  = 40;
constexpr int PIN_SIOC  = 39;
constexpr int PIN_D7    = 48;
constexpr int PIN_D6    = 11;
constexpr int PIN_D5    = 12;
constexpr int PIN_D4    = 14;
constexpr int PIN_D3    = 16;
constexpr int PIN_D2    = 18;
constexpr int PIN_D1    = 17;
constexpr int PIN_D0    = 15;
constexpr int PIN_VSYNC = 38;
constexpr int PIN_HREF  = 47;
constexpr int PIN_PCLK  = 13;

const char* TAG = "cam";

// Rohes esp_camera-Pixelformat -> neutrales CameraPixelFormat.
CameraPixelFormat mapPixelFormat(pixformat_t format) {
    switch (format) {
        case PIXFORMAT_JPEG:      return CAMERA_PIXEL_FORMAT_JPEG;
        case PIXFORMAT_RGB565:    return CAMERA_PIXEL_FORMAT_RGB565;
        case PIXFORMAT_RGB888:    return CAMERA_PIXEL_FORMAT_RGB888;
        case PIXFORMAT_YUV422:    return CAMERA_PIXEL_FORMAT_YUV422;
        case PIXFORMAT_GRAYSCALE: return CAMERA_PIXEL_FORMAT_GRAYSCALE;
        default:                  return CAMERA_PIXEL_FORMAT_JPEG;
    }
}
}  // namespace


Esp32S3DvpCamera::Esp32S3DvpCamera()
    : config_{ (uint16_t)FRAMESIZE_SVGA, (uint16_t)FRAMESIZE_UXGA, 12, 0, 2 },
      ready_(false),
      frame_{ nullptr, 0, 0, 0, CAMERA_PIXEL_FORMAT_JPEG, 0 },
      rawFrame_(nullptr),
      sequence_(0) {}


Esp32S3DvpCamera::~Esp32S3DvpCamera() {
    if (rawFrame_ != nullptr) {
        esp_camera_fb_return(static_cast<camera_fb_t*>(rawFrame_));
        rawFrame_ = nullptr;
    }
    if (ready_) {
        esp_camera_deinit();
        ready_ = false;
    }
}


void Esp32S3DvpCamera::configure(const Config& config) {
    config_ = config;
}


bool Esp32S3DvpCamera::begin() {
    camera_config_t config = {};

    config.ledc_channel = LEDC_CHANNEL_0;
    config.ledc_timer   = LEDC_TIMER_0;

    config.pin_d0 = PIN_D0;
    config.pin_d1 = PIN_D1;
    config.pin_d2 = PIN_D2;
    config.pin_d3 = PIN_D3;
    config.pin_d4 = PIN_D4;
    config.pin_d5 = PIN_D5;
    config.pin_d6 = PIN_D6;
    config.pin_d7 = PIN_D7;

    config.pin_xclk  = PIN_XCLK;
    config.pin_pclk  = PIN_PCLK;
    config.pin_vsync = PIN_VSYNC;
    config.pin_href  = PIN_HREF;

    config.pin_sccb_sda = PIN_SIOD;
    config.pin_sccb_scl = PIN_SIOC;

    config.pin_pwdn  = PIN_PWDN;
    config.pin_reset = PIN_RESET;

    config.xclk_freq_hz = 20000000;
    config.pixel_format = PIXFORMAT_JPEG;
    config.grab_mode    = CAMERA_GRAB_LATEST;
    config.fb_location  = CAMERA_FB_IN_PSRAM;

    // Puffer auf die Maximalaufloesung + BUFFER-Qualitaet dimensionieren, damit
    // jede spaetere (kleinere) Live-Qualitaet hineinpasst (kein Ueberlauf).
    config.jpeg_quality = config_.bufferQuality;
    config.frame_size   = static_cast<framesize_t>(config_.maxFrameSize);
    config.fb_count     = config_.fbCount;

    esp_err_t result = esp_camera_init(&config);
    if (result != ESP_OK) {
        ESP_LOGE(TAG, "esp_camera_init failed: 0x%x", result);
        return false;
    }

    sensor_t* sensor = esp_camera_sensor_get();

    // OV3660 liefert ab Werk ein kopfstehendes Bild mit ueberzogener Saettigung.
    if (sensor != nullptr && sensor->id.PID == OV3660_PID) {
        sensor->set_vflip(sensor, 1);
        sensor->set_brightness(sensor, 1);
        sensor->set_saturation(sensor, -2);
    }

    if (sensor != nullptr) {
        sensor->set_framesize(sensor, static_cast<framesize_t>(config_.frameSize));
        sensor->set_quality(sensor, config_.jpegQuality);
    }

    // Selbsttest: esp_camera_init beweist nur den SCCB-Steuerkanal; die
    // Bilddaten laufen ueber den separaten parallelen DVP-Bus. Ein Probe-Frame
    // zeigt, ob der Datenpfad tatsaechlich liefert.
    camera_fb_t* probe = esp_camera_fb_get();
    if (probe == nullptr) {
        ESP_LOGE(TAG, "self-test failed: no frame on the DVP data bus");
        esp_camera_deinit();
        return false;
    }
    ESP_LOGI(TAG, "self-test OK, frame %u bytes", (unsigned)probe->len);
    esp_camera_fb_return(probe);

    ready_ = true;
    return true;
}


bool Esp32S3DvpCamera::isReady() const {
    return ready_;
}


CameraFrame* Esp32S3DvpCamera::acquireFrame() {
    if (!ready_ || rawFrame_ != nullptr) {
        // Noch ein Frame in flight -> Vertrag verlangt vorheriges releaseFrame().
        return nullptr;
    }

    camera_fb_t* fb = esp_camera_fb_get();
    if (fb == nullptr) {
        return nullptr;
    }

    rawFrame_          = fb;
    frame_.data        = fb->buf;
    frame_.size        = fb->len;
    frame_.width       = (uint16_t)fb->width;
    frame_.height      = (uint16_t)fb->height;
    frame_.pixelFormat = mapPixelFormat(fb->format);
    frame_.sequence    = ++sequence_;

    return &frame_;
}


void Esp32S3DvpCamera::releaseFrame(CameraFrame* frame) {
    (void)frame;  // stets der interne frame_ -> Zeiger nur zur Interface-Symmetrie
    if (rawFrame_ != nullptr) {
        esp_camera_fb_return(static_cast<camera_fb_t*>(rawFrame_));
        rawFrame_ = nullptr;
    }
    frame_.data = nullptr;
    frame_.size = 0;
}


// ---- Einstellbare OV3660-Parameter (fuer die Web-UI) ----
// Aufloesung + JPEG-Qualitaet bleiben in der bestehenden Kamera-UI; hier NUR die
// Sensor-Tunables (Bild/Belichtung/Weissabgleich/Spiegeln/Testbild).
namespace {
enum DvpParamId {
    DP_BRIGHTNESS, DP_CONTRAST, DP_SATURATION, DP_SHARPNESS, DP_DENOISE,
    DP_SPECIAL_EFFECT, DP_WB_MODE, DP_AWB, DP_AWB_GAIN, DP_AEC, DP_AEC2,
    DP_AE_LEVEL, DP_AEC_VALUE, DP_AGC, DP_AGC_GAIN, DP_GAINCEILING,
    DP_BPC, DP_WPC, DP_RAW_GMA, DP_LENC, DP_HMIRROR, DP_VFLIP, DP_DCW, DP_COLORBAR
};
struct DvpParamDesc { DvpParamId id; const char* key; const char* label; int mn, mx; CameraParamKind kind; };
const DvpParamDesc DVP_PARAMS[] = {
    { DP_BRIGHTNESS,     "brightness",     "Helligkeit",           -2,   2, CAM_PARAM_INT  },
    { DP_CONTRAST,       "contrast",       "Kontrast",             -2,   2, CAM_PARAM_INT  },
    { DP_SATURATION,     "saturation",     "Saettigung",           -2,   2, CAM_PARAM_INT  },
    { DP_SHARPNESS,      "sharpness",      "Schaerfe",             -2,   2, CAM_PARAM_INT  },
    { DP_DENOISE,        "denoise",        "Rauschunterdrueckung",  0,   8, CAM_PARAM_INT  },
    { DP_SPECIAL_EFFECT, "special_effect", "Effekt",                0,   6, CAM_PARAM_INT  },
    { DP_WB_MODE,        "wb_mode",        "Weissabgleich-Modus",   0,   4, CAM_PARAM_INT  },
    { DP_AWB,            "awb",            "Auto-Weissabgleich",    0,   1, CAM_PARAM_BOOL },
    { DP_AWB_GAIN,       "awb_gain",       "AWB-Verstaerkung",      0,   1, CAM_PARAM_BOOL },
    { DP_AEC,            "aec",            "Auto-Belichtung",       0,   1, CAM_PARAM_BOOL },
    { DP_AEC2,           "aec2",           "AEC DSP",               0,   1, CAM_PARAM_BOOL },
    { DP_AE_LEVEL,       "ae_level",       "Belichtungskorrektur", -2,   2, CAM_PARAM_INT  },
    { DP_AEC_VALUE,      "aec_value",      "Belichtungszeit",       0,1200, CAM_PARAM_INT  },
    { DP_AGC,            "agc",            "Auto-Gain",             0,   1, CAM_PARAM_BOOL },
    { DP_AGC_GAIN,       "agc_gain",       "Gain",                  0,  30, CAM_PARAM_INT  },
    { DP_GAINCEILING,    "gainceiling",    "Gain-Obergrenze",       0,   6, CAM_PARAM_INT  },
    { DP_BPC,            "bpc",            "Black-Pixel-Korrektur", 0,   1, CAM_PARAM_BOOL },
    { DP_WPC,            "wpc",            "White-Pixel-Korrektur", 0,   1, CAM_PARAM_BOOL },
    { DP_RAW_GMA,        "raw_gma",        "Gamma (raw)",           0,   1, CAM_PARAM_BOOL },
    { DP_LENC,           "lenc",           "Objektivkorrektur",     0,   1, CAM_PARAM_BOOL },
    { DP_HMIRROR,        "hmirror",        "Horizontal spiegeln",   0,   1, CAM_PARAM_BOOL },
    { DP_VFLIP,          "vflip",          "Vertikal spiegeln",     0,   1, CAM_PARAM_BOOL },
    { DP_DCW,            "dcw",            "DCW (Downsize EN)",     0,   1, CAM_PARAM_BOOL },
    { DP_COLORBAR,       "colorbar",       "Farbbalken (Test)",     0,   1, CAM_PARAM_BOOL },
};
const int DVP_PARAM_COUNT = sizeof(DVP_PARAMS) / sizeof(DVP_PARAMS[0]);

int dvpGet(sensor_t* s, DvpParamId id) {
    const camera_status_t& st = s->status;
    switch (id) {
        case DP_BRIGHTNESS:     return st.brightness;
        case DP_CONTRAST:       return st.contrast;
        case DP_SATURATION:     return st.saturation;
        case DP_SHARPNESS:      return st.sharpness;
        case DP_DENOISE:        return st.denoise;
        case DP_SPECIAL_EFFECT: return st.special_effect;
        case DP_WB_MODE:        return st.wb_mode;
        case DP_AWB:            return st.awb;
        case DP_AWB_GAIN:       return st.awb_gain;
        case DP_AEC:            return st.aec;
        case DP_AEC2:           return st.aec2;
        case DP_AE_LEVEL:       return st.ae_level;
        case DP_AEC_VALUE:      return st.aec_value;
        case DP_AGC:            return st.agc;
        case DP_AGC_GAIN:       return st.agc_gain;
        case DP_GAINCEILING:    return st.gainceiling;
        case DP_BPC:            return st.bpc;
        case DP_WPC:            return st.wpc;
        case DP_RAW_GMA:        return st.raw_gma;
        case DP_LENC:           return st.lenc;
        case DP_HMIRROR:        return st.hmirror;
        case DP_VFLIP:          return st.vflip;
        case DP_DCW:            return st.dcw;
        case DP_COLORBAR:       return st.colorbar;
    }
    return 0;
}

bool dvpSet(sensor_t* s, DvpParamId id, int v) {
    switch (id) {
        case DP_BRIGHTNESS:     return s->set_brightness(s, v) == 0;
        case DP_CONTRAST:       return s->set_contrast(s, v) == 0;
        case DP_SATURATION:     return s->set_saturation(s, v) == 0;
        case DP_SHARPNESS:      return s->set_sharpness(s, v) == 0;
        case DP_DENOISE:        return s->set_denoise(s, v) == 0;
        case DP_SPECIAL_EFFECT: return s->set_special_effect(s, v) == 0;
        case DP_WB_MODE:        return s->set_wb_mode(s, v) == 0;
        case DP_AWB:            return s->set_whitebal(s, v) == 0;
        case DP_AWB_GAIN:       return s->set_awb_gain(s, v) == 0;
        case DP_AEC:            return s->set_exposure_ctrl(s, v) == 0;
        case DP_AEC2:           return s->set_aec2(s, v) == 0;
        case DP_AE_LEVEL:       return s->set_ae_level(s, v) == 0;
        case DP_AEC_VALUE:      return s->set_aec_value(s, v) == 0;
        case DP_AGC:            return s->set_gain_ctrl(s, v) == 0;
        case DP_AGC_GAIN:       return s->set_agc_gain(s, v) == 0;
        case DP_GAINCEILING:    return s->set_gainceiling(s, (gainceiling_t)v) == 0;
        case DP_BPC:            return s->set_bpc(s, v) == 0;
        case DP_WPC:            return s->set_wpc(s, v) == 0;
        case DP_RAW_GMA:        return s->set_raw_gma(s, v) == 0;
        case DP_LENC:           return s->set_lenc(s, v) == 0;
        case DP_HMIRROR:        return s->set_hmirror(s, v) == 0;
        case DP_VFLIP:          return s->set_vflip(s, v) == 0;
        case DP_DCW:            return s->set_dcw(s, v) == 0;
        case DP_COLORBAR:       return s->set_colorbar(s, v) == 0;
    }
    return false;
}
}  // namespace

// Native Capture-Aufloesungen: die Standard-Framesizes von VGA bis zum Sensor-Maximum
// (esp_camera-resolution-Tabelle liefert die echten w×h). Dynamisch am Sensor-Maximum
// abgeleitet -- keine feste App-Tabelle, dieselbe CameraVideoMode-Abstraktion wie der P4.
int Esp32S3DvpCamera::enumModes(CameraVideoMode* out, int maxOut) const {
    if (!out || maxOut <= 0) return 0;
    int n = 0;
    // Standard-Querformat-Framesizes VGA..QXGA (OV3660-Bereich); esp_camera-resolution-
    // Tabelle liefert die echten w×h. Dynamisch aus der Sensor-Lib, keine App-Tabelle.
    for (int fs = (int)FRAMESIZE_VGA; fs <= (int)FRAMESIZE_QXGA && n < maxOut; fs++) {
        uint16_t w = resolution[fs].width, h = resolution[fs].height;
        if (!w || !h || w < h) continue;   // nur Querformat
        out[n].width = w; out[n].height = h;
        out[n].pixelFormat = CAMERA_PIXEL_FORMAT_JPEG;   // DVP-Ausgang ist JPEG
        out[n].maxFps      = 0;      // unbekannt (nicht als reale fps deuten)
        out[n].enumerated  = true;
        n++;
    }
    return n;
}

// Generischer Apply-Port: w×h intern auf einen esp_camera-framesize_t abbilden (resolution-
// Tabelle) und via set_framesize setzen. Auf das konfigurierte Maximum begrenzt (PSRAM-
// Budget). Die App/UI kennt kein framesize_t -- das bleibt hier im Backend.
bool Esp32S3DvpCamera::setMode(uint16_t width, uint16_t height) {
    if (!ready_) return false;
    sensor_t* s = esp_camera_sensor_get();
    if (!s) return false;
    for (int fs = 0; fs < (int)FRAMESIZE_INVALID; fs++) {
        if (resolution[fs].width == width && resolution[fs].height == height) {
            if (config_.maxFrameSize && fs > (int)config_.maxFrameSize) return false;  // ueber Maximum
            return s->set_framesize(s, (framesize_t)fs) == 0;
        }
    }
    return false;   // keine passende esp_camera-Aufloesung
}

// LIVE-Sensoraufloesung fuer alle, die dem Host eine feste Groesse ansagen
// muessen (UVC-Deskriptor): aus sensor->status.framesize ueber die
// resolution-Tabelle. NICHT config_.frameSize -- der Startwert kann per
// setMode()/NVS laengst ueberholt sein.
bool Esp32S3DvpCamera::currentMode(uint16_t& width, uint16_t& height) const {
    if (!ready_) return false;
    sensor_t* s = esp_camera_sensor_get();
    if (!s) return false;
    const int fs = (int)s->status.framesize;
    if (fs < 0 || fs >= (int)FRAMESIZE_INVALID) return false;
    width  = (uint16_t)resolution[fs].width;
    height = (uint16_t)resolution[fs].height;
    return true;
}

int Esp32S3DvpCamera::paramCount() const {
    return ready_ ? DVP_PARAM_COUNT : 0;
}

bool Esp32S3DvpCamera::paramAt(int index, CameraParamInfo& out) const {
    if (index < 0 || index >= DVP_PARAM_COUNT) return false;
    sensor_t* s = esp_camera_sensor_get();
    if (!s) return false;
    const DvpParamDesc& d = DVP_PARAMS[index];
    out.key   = d.key;
    out.label = d.label;
    out.min   = d.mn;
    out.max   = d.mx;
    out.kind  = d.kind;
    out.value = dvpGet(s, d.id);
    return true;
}

bool Esp32S3DvpCamera::setParam(const char* key, int value) {
    sensor_t* s = esp_camera_sensor_get();
    if (!s || !key) return false;
    for (int i = 0; i < DVP_PARAM_COUNT; i++) {
        if (strcmp(key, DVP_PARAMS[i].key) == 0) {
            int v = value;
            if (v < DVP_PARAMS[i].mn) v = DVP_PARAMS[i].mn;
            if (v > DVP_PARAMS[i].mx) v = DVP_PARAMS[i].mx;
            return dvpSet(s, DVP_PARAMS[i].id, v);
        }
    }
    return false;
}

#endif  // !CONFIG_IDF_TARGET_ESP32P4  (S3-DVP-Geraet; auf P4 leer)

#else
// ============================================================================
// Stub: Kamera nicht im Build enthalten (WEIRDOS_FEATURE_CAMERA=0), alle Targets
// CameraManager haelt dieses Geraet auf Nicht-P4-Targets BY VALUE -> die Klasse muss
// vollstaendig sein (Konstruktor/Destruktor/alle Overrides), auch wenn sie nie ein Bild
// liefert. Kein esp_camera.h hier -> die esp32-camera-Komponente bleibt aus dem Build.
// ============================================================================
Esp32S3DvpCamera::Esp32S3DvpCamera()
    : config_{ 0, 0, 12, 0, 2 },
      ready_(false),
      frame_{ nullptr, 0, 0, 0, CAMERA_PIXEL_FORMAT_JPEG, 0 },
      rawFrame_(nullptr),
      sequence_(0) {}
Esp32S3DvpCamera::~Esp32S3DvpCamera() {}
void         Esp32S3DvpCamera::configure(const Config& config) { config_ = config; }
bool         Esp32S3DvpCamera::begin() { return false; }
bool         Esp32S3DvpCamera::isReady() const { return false; }
CameraFrame* Esp32S3DvpCamera::acquireFrame() { return nullptr; }
void         Esp32S3DvpCamera::releaseFrame(CameraFrame* frame) { (void)frame; }
int          Esp32S3DvpCamera::enumModes(CameraVideoMode* out, int maxOut) const { (void)out; (void)maxOut; return 0; }
bool         Esp32S3DvpCamera::setMode(uint16_t width, uint16_t height) { (void)width; (void)height; return false; }
int          Esp32S3DvpCamera::paramCount() const { return 0; }
bool         Esp32S3DvpCamera::paramAt(int index, CameraParamInfo& out) const { (void)index; (void)out; return false; }
bool         Esp32S3DvpCamera::setParam(const char* key, int value) { (void)key; (void)value; return false; }
#endif  // WEIRDOS_FEATURE_CAMERA
