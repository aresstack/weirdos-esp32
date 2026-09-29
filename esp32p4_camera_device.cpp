// ============================================================================
// esp32p4_camera_device.cpp
//
// Zwei Welten:
//  #if CONFIG_IDF_TARGET_ESP32P4  -> echte MIPI-CSI-Aufnahme ueber esp_video/V4L2
//  sonst (z.B. S3)                -> Stubs, damit der Build gruen bleibt
//                                    (auf S3 wird dieses Geraet nie ausgewaehlt).
//
// ACHTUNG: Der P4-Zweig ist auf diesem S3-Setup NICHT kompilier-/testbar. Er ist
// der echte V4L2-Ablauf (S_FMT/REQBUFS/mmap/QBUF/STREAMON/DQBUF + S_CTRL), aber
// die board-spezifische esp_video_init()-Konfig (CSI-Lanes, Sensor, SCCB/I2C)
// muss auf echter P4-Hardware verifiziert werden -> unten als TODO markiert.
// ============================================================================
#include "weirdos_features.h"        // WEIRDOS_FEATURE_CAMERA -- der Schalter dieses Bausteins
#include "esp32p4_camera_device.h"   // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
#if WEIRDOS_FEATURE_CAMERA
// ============================================================================
// Echte Implementierung (WEIRDOS_FEATURE_CAMERA=1): P4-Pfad ODER Nicht-P4-Stubs (wie bisher)
// ============================================================================
#include <sdkconfig.h>   // CONFIG_IDF_TARGET_ESP32P4 (sonst faellt der Build auf die Stubs)
#include <cstring>

#if defined(CONFIG_IDF_TARGET_ESP32P4)
// ---------------------------------------------------------------------------
// Echter P4-Pfad (esp_video / V4L2)
// ---------------------------------------------------------------------------
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "linux/videodev2.h"
#include "esp_video_init.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_heap_caps.h"        // heap_caps_* fuer Heap-Diagnose (Mode-Switch/JPEG-Fehler)
#include "driver/jpeg_encode.h"   // HW-JPEG-Encoder (V4L2-JPEG-Geraet ist in dieser Lib aus)
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"      // Mutex fuer acquireFrame()<->setMode()-Synchronisation
#include "freertos/task.h"        // vTaskDelay
#include "esp_cam_sensor_types.h" // esp_cam_sensor_format_t (Sensor-Modus-Descriptor)
#include "esp_video_ioctl.h"      // VIDIOC_S_SENSOR_FMT / VIDIOC_G_SENSOR_FMT
#include <cstdlib>                // free()
#include <cstdio>                 // printf (Modus-Wechsel-Zeile; Serial ist hier nicht deklariert)

// P4-HW-JPEG-Qualitaet (1-100, hoeher = besser/GROESSER). 80 ergab bei 800x800 ~58 KB/Frame
// -> bei 10 fps ~5 Mbit/s, weit ueber einem LTE-Uplink (~1,5 Mbit/s): die Frames stauen sich in
// den lwIP-Sendepuffern (interner DMA-Heap) -> Fragmentierung bis ~1 KB groesster Block + sehr
// langsame Sends. 45 halbiert die Frame-Groesse (~28 KB) bei noch brauchbarer Qualitaet und macht
// den Stream ueber LTE tragbar (zusaetzlich FPS im UI senken). Runtime-Umschaltung folgt spaeter.
static const int P4_JPEG_QUALITY = 45;

// Aus unserer neu gebauten ov5647.o exportiert (tools/build-camsensor.ps1): die vollen
// Sensor-Format-Descriptoren (mit regs/isp_info/mipi). Das P4-Backend ist der OV5647-
// spezifische Layer -> Kopplung hier ok; generische Schichten (/dev, CameraDevice) bleiben sauber.
extern "C" const esp_cam_sensor_format_t* weirdos_ov5647_formats(int* count);

// WEAK-Rueckfall fuer den STOCK-Core: dort gibt es die injizierte ov5647.c.obj nicht, und der Link
// scheiterte bisher an genau diesem Symbol. Mit der gepatchten Lib (tools/build-camsensor.ps1)
// zieht der Linker das ov5647-Archiv-Member ohnehin (Treiber) -- dessen STARKE Definition gewinnt
// dann gegen diesen weak-Stub. Ohne Patch liefert der Stub "keine Liste" und die Aufrufer nehmen
// ihre dokumentierten Fallbacks (V4L2-Enum bzw. kein FHD-Sensorwechsel). So bleibt der P4 in der
// CI mit dem unveraenderten Core baubar.
extern "C" {
__attribute__((weak)) const esp_cam_sensor_format_t* weirdos_ov5647_formats(int* count) {
    if (count) *count = 0;
    return nullptr;
}
}

// Vollen Sensor-Descriptor (mit regs/isp_info/mipi) nach Breite/Hoehe finden; nullptr wenn keiner.
static const esp_cam_sensor_format_t* p4FindSensorFormat(uint16_t w, uint16_t h) {
    int c = 0;
    const esp_cam_sensor_format_t* sf = weirdos_ov5647_formats(&c);
    for (int i = 0; i < c; i++)
        if ((uint16_t)sf[i].width == w && (uint16_t)sf[i].height == h) return &sf[i];
    return nullptr;
}

static const char* TAGP4 = "camP4";

// Lock-Helfer (lock_ ist ein SemaphoreHandle_t, opak als void* im Header gehalten).
#define P4_LOCK()    do { if (lock_) xSemaphoreTake((SemaphoreHandle_t)lock_, portMAX_DELAY); } while (0)
#define P4_UNLOCK()  do { if (lock_) xSemaphoreGive((SemaphoreHandle_t)lock_); } while (0)

// Waveshare ESP32-P4-Pico: MIPI-CSI (2 Lanes) mit SCCB/I2C an SCL=GPIO8 / SDA=GPIO7.
// Der OV5647-Treiber muss im Core einkompiliert + per Kconfig aktiv sein; esp_video
// findet ihn per Auto-Detection ueber SCCB. Einmalige Board-Init (idempotent).
#define P4_CSI_SCCB_PORT   0
#define P4_CSI_SCCB_SCL    8
#define P4_CSI_SCCB_SDA    7
#define P4_CSI_SCCB_FREQ   100000   // 100 kHz zum Bring-up

static bool p4EnsureVideoInit() {
    static bool done = false, ok = false;
    if (done) return ok;
    done = true;

    esp_video_init_sccb_config_t sccb = {};
    sccb.init_sccb          = true;
    sccb.i2c_config.port    = P4_CSI_SCCB_PORT;
    sccb.i2c_config.scl_pin = (gpio_num_t)P4_CSI_SCCB_SCL;
    sccb.i2c_config.sda_pin = (gpio_num_t)P4_CSI_SCCB_SDA;
    sccb.freq               = P4_CSI_SCCB_FREQ;

    esp_video_init_csi_config_t csi = {};
    csi.sccb_config = sccb;
    csi.reset_pin   = GPIO_NUM_NC;   // -1: kein Reset-Pin verdrahtet
    csi.pwdn_pin    = GPIO_NUM_NC;   // -1: kein Powerdown-Pin verdrahtet

    esp_video_init_config_t cfg = {};
    cfg.csi = &csi;

    ESP_LOGI(TAGP4, "SCCB init: port %d, SCL=GPIO%d SDA=GPIO%d @ %d Hz, OV5647-Auto-Detect ...",
             P4_CSI_SCCB_PORT, P4_CSI_SCCB_SCL, P4_CSI_SCCB_SDA, P4_CSI_SCCB_FREQ);
    esp_err_t err = esp_video_init(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAGP4, "esp_video_init: %s (0x%x) -> Sensor NICHT erkannt "
                 "(SCCB-Pins? FPC-Kabel/-Richtung? OV5647 im Core aktiv?)", esp_err_to_name(err), err);
        ok = false; return false;
    }
    ESP_LOGI(TAGP4, "esp_video_init OK -> OV5647 ueber SCCB gebunden, CSI/ISP bereit");
    ok = true; return true;
}

// --- OV5647-Treiber aus der schon vorhandenen esp_cam_sensor-Lib (2.3.0) ERZWINGEN ---
// Der OV5647-Treiber IST vorkompiliert enthalten (Symbol ov5647_detect, Kconfig
// CAMERA_OV5647=y, 800x800 RAW8). ABER: seine Auto-Detect-Registrierung liegt in
// ov5647.o und kommt nur in den finalen Link, wenn ein Symbol daraus referenziert
// wird (esp_cam_sensor-Header: "-u <sensor>_detect"). Die anderen Sensoren haben
// dieses -u im CMake, OV5647 im Arduino-Build NICHT -> ov5647.o (samt seiner
// .esp_cam_sensor_detect_fn-Section) wird verworfen -> OV5647 fehlt in der
// Detect-Liste. Eine einzige Referenz zieht das Objekt rein -> esp_video_init()
// findet OV5647 dann automatisch (Adresse 0x36, PID 0x5647). Signatur egal, wird
// nie aufgerufen -- es zaehlt nur die Symbol-Referenz (extern "C" -> kein Mangling).
extern "C" void* ov5647_detect(void* config);
extern "C" void* const __attribute__((used)) weirdos_keep_ov5647 = (void*)&ov5647_detect;

// V4L2-FourCC -> neutrales Frame-Format (Bring-up: RAW/Bayer landet mangels
// Enum-Eintrag auf GRAYSCALE-Platzhalter; JPEG/RGB bleiben korrekt).
static CameraPixelFormat p4MapPixFmt(uint32_t v4l2) {
    switch (v4l2) {
        case V4L2_PIX_FMT_JPEG:   return CAMERA_PIXEL_FORMAT_JPEG;
        case V4L2_PIX_FMT_RGB565: return CAMERA_PIXEL_FORMAT_RGB565;
        case V4L2_PIX_FMT_RGB24:  return CAMERA_PIXEL_FORMAT_RGB888;
        default:                  return CAMERA_PIXEL_FORMAT_GRAYSCALE;
    }
}

// V4L2-CID-Mapping fuer die Web-UI (geraeteabhaengig; Sensor muss die CIDs koennen).
namespace {
struct P4ParamDesc { const char* key; const char* label; int mn, mx; CameraParamKind kind; uint32_t cid; };
const P4ParamDesc P4_PARAMS[] = {
    { "brightness", "Helligkeit",  -2, 2, CAM_PARAM_INT,  V4L2_CID_BRIGHTNESS },
    { "contrast",   "Kontrast",    -2, 2, CAM_PARAM_INT,  V4L2_CID_CONTRAST },
    { "saturation", "Saettigung",  -2, 2, CAM_PARAM_INT,  V4L2_CID_SATURATION },
    { "hue",        "Farbton",   -180,180, CAM_PARAM_INT,  V4L2_CID_HUE },
    { "gain",       "Gain",         0,100, CAM_PARAM_INT,  V4L2_CID_GAIN },
    { "exposure",   "Belichtung",   0,1000,CAM_PARAM_INT,  V4L2_CID_EXPOSURE },
    { "hflip",      "Horizontal spiegeln", 0,1, CAM_PARAM_BOOL, V4L2_CID_HFLIP },
    { "vflip",      "Vertikal spiegeln",   0,1, CAM_PARAM_BOOL, V4L2_CID_VFLIP },
};
const int P4_PARAM_COUNT = sizeof(P4_PARAMS) / sizeof(P4_PARAMS[0]);
}  // namespace

Esp32P4MipiCamera::Esp32P4MipiCamera()
    : config_{ 1920, 1080, 12, 2 }, ready_(false), frame_{}, fd_(-1),
      curPixFmt_(0), jpegCapable_(false), inFourcc_(0), jpegSrcType_(0),
      jpegEnc_(nullptr), jpegBuf_(nullptr), jpegCap_(0),
      curBufIndex_(-1), sequence_(0), jpegQuality_(P4_JPEG_QUALITY), bufCount_(0),
      lock_(nullptr), reconfiguring_(false) {
    for (int i = 0; i < MAX_BUFS; i++) { bufPtr_[i] = nullptr; bufLen_[i] = 0; }
}

// UI-Skala 0..63 (0 = beste) -> P4-HW-Encoder-Skala 1..100 (hoeher = besser). Linear invertiert.
// Wird pro Frame in cfg.image_quality gelesen -> Aenderung wirkt sofort beim naechsten Frame.
void Esp32P4MipiCamera::setJpegQualityUi(int ui0to63) {
    if (ui0to63 < 0) ui0to63 = 0;
    if (ui0to63 > 63) ui0to63 = 63;
    int q = 100 - (ui0to63 * 99) / 63;   // ui 0 -> 100 (beste), ui 63 -> 1 (kleinste)
    if (q < 1) q = 1;
    if (q > 100) q = 100;
    jpegQuality_ = q;
}
int Esp32P4MipiCamera::jpegQualityUi() const {
    return ((100 - jpegQuality_) * 63) / 99;   // Rueckabbildung P4 1..100 -> UI 0..63
}

Esp32P4MipiCamera::~Esp32P4MipiCamera() {
    if (jpegEnc_) jpeg_del_encoder_engine((jpeg_encoder_handle_t)jpegEnc_);
    if (jpegBuf_) free(jpegBuf_);
    if (fd_ >= 0) {
        int t = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        ioctl(fd_, VIDIOC_STREAMOFF, &t);
        close(fd_);
    }
}

void Esp32P4MipiCamera::configure(const Config& c) { config_ = c; }

bool Esp32P4MipiCamera::begin() {
    if (!lock_) lock_ = xSemaphoreCreateMutex();   // Capture-Sync (acquireFrame<->setMode)

    // 1) Board-/Sensor-Bring-up: MIPI-CSI + SCCB + OV5647-Auto-Detect. Ohne das
    //    existiert /dev/video0 gar nicht (das war der eigentliche "nicht erkannt"-Grund).
    if (!p4EnsureVideoInit()) return false;

    // 2) Capture-Device oeffnen (jetzt real vorhanden).
    // O_NONBLOCK: VIDIOC_DQBUF darf NICHT unbegrenzt blockieren -- acquireFrame() haelt dabei
    // den Kamera-Mutex, den setMode() braucht. Nonblocking -> DQBUF liefert EAGAIN statt zu
    // haengen; der Capture-Task (captureLoop) delayt bei Null-Frame ohnehin >=5ms.
    fd_ = open("/dev/video0", O_RDWR | O_NONBLOCK);
    if (fd_ < 0) { ESP_LOGE(TAGP4, "/dev/video0 open fehlgeschlagen (CSI-Capture-Device fehlt)"); return false; }

    // 3) Wer haengt am Device? driver/card beweisen die Sensor-Bindung.
    struct v4l2_capability cap; memset(&cap, 0, sizeof(cap));
    if (ioctl(fd_, VIDIOC_QUERYCAP, &cap) == 0)
        ESP_LOGI(TAGP4, "/dev/video0: driver='%s' card='%s'", (const char*)cap.driver, (const char*)cap.card);

    // 4) Formate ENUMERIEREN. Mit aktivem ISP liefert /dev/video0 einen verarbeiteten
    //    Ausgang (RGB565/YUV) -- den koennen wir dem HW-JPEG-Encoder fuettern. Wir
    //    waehlen das beste encoder-taugliche Format; gibt es nur RAW, faellt der Pfad
    //    auf Rohframe zurueck (dann noch kein Bild, aber sauber diagnostizierbar).
    struct FmtPref { uint32_t v4l2; int jpg; const char* name; };
    static const FmtPref PREF[] = {
        { V4L2_PIX_FMT_RGB565, (int)JPEG_ENCODE_IN_FORMAT_RGB565, "RGB565" },
        { V4L2_PIX_FMT_YUYV,   (int)JPEG_ENCODE_IN_FORMAT_YUV422, "YUYV"   },
        { V4L2_PIX_FMT_RGB24,  (int)JPEG_ENCODE_IN_FORMAT_RGB888, "RGB888" },
    };
    uint32_t avail[16]; int navail = 0;
    struct v4l2_fmtdesc fdsc; memset(&fdsc, 0, sizeof(fdsc));
    fdsc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    for (fdsc.index = 0; navail < 16 && ioctl(fd_, VIDIOC_ENUM_FMT, &fdsc) == 0; fdsc.index++) {
        avail[navail++] = fdsc.pixelformat;
        ESP_LOGI(TAGP4, "  fmt[%u] '%c%c%c%c' (%s)", fdsc.index,
                 (char)(fdsc.pixelformat & 0xff), (char)((fdsc.pixelformat >> 8) & 0xff),
                 (char)((fdsc.pixelformat >> 16) & 0xff), (char)((fdsc.pixelformat >> 24) & 0xff),
                 (const char*)fdsc.description);
    }
    if (navail == 0) {
        ESP_LOGE(TAGP4, "kein Pixelformat gemeldet -> Sensor nicht am CSI gebunden");
        close(fd_); fd_ = -1; return false;
    }
    uint32_t chosen = 0; jpegCapable_ = false; jpegSrcType_ = 0;
    for (unsigned p = 0; p < sizeof(PREF)/sizeof(PREF[0]) && !chosen; p++)
        for (int i = 0; i < navail; i++)
            if (avail[i] == PREF[p].v4l2) {
                chosen = PREF[p].v4l2; jpegSrcType_ = PREF[p].jpg; jpegCapable_ = true;
                ESP_LOGI(TAGP4, "JPEG-Pfad: ISP-Ausgang %s -> HW-JPEG-Encoder", PREF[p].name);
                break;
            }
    if (!chosen) {
        chosen = avail[0];
        ESP_LOGW(TAGP4, "kein ISP-Format fuer JPEG (nur RAW?) -> Rohframe, noch kein Bild");
    }
    inFourcc_ = chosen;

    // Aufloesung + Puffer/Stream/Encoder aufsetzen. GENAU DIESE Sequenz nutzt auch setMode()
    // zur Laufzeit-Umschaltung (kein Duplikat). Start-Modus 800x800 = Default-Format des
    // OV5647-Treibers (sdkconfig CONFIG_CAMERA_OV5647_MIPI_DEFAULT_FMT_RAW8_800X800_50FPS). Weitere
    // Modi (u.a. 1920x1080) kommen zur Laufzeit ueber setMode() aus der exportierten Format-Tabelle
    // (weirdos_ov5647_formats) -- so laeuft MJPEG in FHD. V4L2 liest die Geometrie zurueck.
    if (!applyCaptureFormat(800, 800)) {
        // Symmetrischer Lebenszyklus wie setMode(): halb aufgebaute Puffer (REQBUFS/mmap/STREAMON)
        // ueber denselben Teardown abbauen, dann schliessen -- sonst bleiben Mappings/Treiber-Puffer
        // haengen und ein spaeterer Neuversuch startet auf Resten.
        teardownCapture();
        close(fd_); fd_ = -1;
        return false;
    }

    // Diagnose: die vom V4L2-Device wirklich gemeldeten Capture-Modi einmal ins Log.
    // Das ist die Wahrheit fuer den dynamischen Aufloesungs-Dropdown (kein festes Table).
    CameraVideoMode modes[12];
    int nm = enumModes(modes, 12);
    ESP_LOGI(TAGP4, "enumModes: %d Capture-Modus/e gemeldet (siehe oben)", nm);

    ready_ = true;
    ESP_LOGI(TAGP4, "capture ready");
    return true;
}

// Setzt Format+Aufloesung und richtet Puffer/Stream/JPEG-Encoder ein. Erwartet ein
// offenes fd_ und ein bereits gewaehltes inFourcc_/jpegCapable_ (aus begin()). Gibt bei
// jedem ioctl-Fehler false zurueck OHNE fd_ zu schliessen (das macht der Aufrufer).
bool Esp32P4MipiCamera::applyCaptureFormat(uint16_t w, uint16_t h) {
    struct v4l2_format fmt; memset(&fmt, 0, sizeof(fmt));
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width       = w;
    fmt.fmt.pix.height      = h;
    fmt.fmt.pix.pixelformat = inFourcc_;
    if (ioctl(fd_, VIDIOC_S_FMT, &fmt) != 0) { ESP_LOGE(TAGP4, "S_FMT %ux%u", w, h); return false; }
    // V4L2 passt Groesse/Format an das an, was der Sensor-Modus wirklich kann -> zuruecklesen.
    config_.width  = fmt.fmt.pix.width;
    config_.height = fmt.fmt.pix.height;
    curPixFmt_     = fmt.fmt.pix.pixelformat;
    ESP_LOGI(TAGP4, "aktives Format: %ux%u '%c%c%c%c', %u B/Frame",
             fmt.fmt.pix.width, fmt.fmt.pix.height,
             (char)(curPixFmt_ & 0xff), (char)((curPixFmt_ >> 8) & 0xff),
             (char)((curPixFmt_ >> 16) & 0xff), (char)((curPixFmt_ >> 24) & 0xff),
             fmt.fmt.pix.sizeimage);

    struct v4l2_requestbuffers req; memset(&req, 0, sizeof(req));
    req.count  = config_.fbCount > MAX_BUFS ? MAX_BUFS : config_.fbCount;
    req.type   = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;
    if (ioctl(fd_, VIDIOC_REQBUFS, &req) != 0) { ESP_LOGE(TAGP4, "REQBUFS"); return false; }
    bufCount_ = req.count;

    for (int i = 0; i < bufCount_; i++) {
        struct v4l2_buffer buf; memset(&buf, 0, sizeof(buf));
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE; buf.memory = V4L2_MEMORY_MMAP; buf.index = i;
        if (ioctl(fd_, VIDIOC_QUERYBUF, &buf) != 0) { ESP_LOGE(TAGP4, "QUERYBUF"); return false; }
        bufLen_[i] = buf.length;
        bufPtr_[i] = mmap(nullptr, buf.length, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, buf.m.offset);
        if (bufPtr_[i] == MAP_FAILED) { bufPtr_[i] = nullptr; ESP_LOGE(TAGP4, "mmap"); return false; }
        if (ioctl(fd_, VIDIOC_QBUF, &buf) != 0) { ESP_LOGE(TAGP4, "QBUF init"); return false; }
    }

    int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (ioctl(fd_, VIDIOC_STREAMON, &type) != 0) { ESP_LOGE(TAGP4, "STREAMON"); return false; }

    // JPEG-Encoder bereitstellen (Encoder PERSISTENT, Puffer waechst transaktional -- NICHT
    // pro Mode-Switch neu erzeugen). Bei jpegCapable_ ist ein funktionierender JPEG-Pfad
    // Pflicht -> sonst Format ablehnen (setMode() stellt den alten Modus wieder her).
    if (!ensureJpegEncoder(w, h)) {
        ESP_LOGE(TAGP4, "JPEG-Pfad nicht bereit fuer %ux%u -> Capture-Format abgelehnt", w, h);
        return false;
    }

    // Probe: EINEN Frame holen (beweist CSI/ISP) und -- wenn JPEG-faehig -- durch einen
    // ECHTEN Encode verifizieren, dass der komplette JPEG-Pfad steht. Nur dann meldet
    // setMode() Erfolg (kein "Mode ok, aber Distributor bekommt keine JPEGs" mehr).
    bool verified = false;
    for (int tries = 0; tries < 20 && !verified; tries++) {
        struct v4l2_buffer pb; memset(&pb, 0, sizeof(pb));
        pb.type = V4L2_BUF_TYPE_VIDEO_CAPTURE; pb.memory = V4L2_MEMORY_MMAP;
        if (ioctl(fd_, VIDIOC_DQBUF, &pb) == 0) {
            if (jpegCapable_ && jpegEnc_ && jpegBuf_) {
                jpeg_encode_cfg_t cfg = {};
                cfg.width = config_.width; cfg.height = config_.height;
                cfg.src_type = (jpeg_enc_input_format_t)jpegSrcType_;
                cfg.sub_sample = JPEG_DOWN_SAMPLING_YUV420; cfg.image_quality = jpegQuality_; cfg.pixel_reverse = false;
                uint32_t outLen = 0;
                esp_err_t e = jpeg_encoder_process((jpeg_encoder_handle_t)jpegEnc_, &cfg,
                                  (const uint8_t*)bufPtr_[pb.index], pb.bytesused, jpegBuf_, jpegCap_, &outLen);
                ioctl(fd_, VIDIOC_QBUF, &pb);
                if (e == ESP_OK && outLen > 0) {
                    ESP_LOGI(TAGP4, "JPEG-Pfad verifiziert: %ux%u -> %u B JPEG", config_.width, config_.height, (unsigned)outLen);
                    verified = true;
                } else {
                    ESP_LOGE(TAGP4, "JPEG-Verify-Encode=%d (in %u B) -> Format abgelehnt", (int)e, pb.bytesused);
                    return false;   // transaktional -> Aufrufer restauriert
                }
            } else {
                ESP_LOGI(TAGP4, "erster Frame: %u Bytes (buf %u) -> CSI/ISP laeuft (RAW-Pfad)", pb.bytesused, pb.index);
                ioctl(fd_, VIDIOC_QBUF, &pb);
                verified = true;
            }
            break;
        }
        usleep(50000);   // O_NONBLOCK: DQBUF gibt EAGAIN -> hier warten, bis der erste Frame da ist
        if (tries == 19) ESP_LOGW(TAGP4, "noch kein Frame nach STREAMON -- Format NICHT verifiziert");
    }
    if (jpegCapable_ && !verified) return false;   // JPEG-faehig, aber kein verifizierter Frame
    return true;
}

// JPEG-Encoder-Lifecycle, UNABHAENGIG vom Capture. Encoder wird einmal erzeugt und behalten;
// nur der Ausgabepuffer waechst bei Bedarf (nie verkleinern), und zwar transaktional:
// neuen gueltigen Puffer beschaffen, DANN erst den alten ersetzen. Ein transienter Alloc-
// Fehler laesst jpegCapable_ UNANGETASTET (der naechste Versuch darf es erneut aufbauen).
bool Esp32P4MipiCamera::ensureJpegEncoder(uint16_t w, uint16_t h) {
    if (!jpegCapable_) return true;   // RAW-Pfad -> kein Encoder noetig, kein Fehler

    if (!jpegEnc_) {
        jpeg_encode_engine_cfg_t ec = {}; ec.intr_priority = 0; ec.timeout_ms = 70;
        jpeg_encoder_handle_t hh = nullptr;
        esp_err_t e = jpeg_new_encoder_engine(&ec, &hh);
        if (e != ESP_OK || !hh) {
            ESP_LOGE(TAGP4, "jpeg_new_encoder_engine=%d -> KEIN JPEG (intern frei %uk groesster %uk)",
                     (int)e, (unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024),
                     (unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) / 1024));
            return false;   // jpegCapable_ BLEIBT -> nicht dauerhaft vergiftet
        }
        jpegEnc_ = (void*)hh;
        ESP_LOGI(TAGP4, "HW-JPEG-Encoder erzeugt (persistent ueber Mode-Switches)");
    }

    // Outbuf gross genug fuer w×h? Nur WACHSEN. Transaktional (neu vor frei).
    size_t need = ((size_t)w * h > 800u * 800u) ? (size_t)w * h : 256u * 1024u;
    if (!jpegBuf_ || jpegCap_ < need) {
        jpeg_encode_memory_alloc_cfg_t mc = {}; mc.buffer_direction = JPEG_ENC_ALLOC_OUTPUT_BUFFER;
        size_t got = 0;
        uint8_t* nb = (uint8_t*)jpeg_alloc_encoder_mem(need, &mc, &got);
        if (!nb) {
            ESP_LOGE(TAGP4, "JPEG-Outbuf-Alloc %uk fehlgeschlagen (PSRAM frei %uk groesster %uk) -> alter Puffer bleibt",
                     (unsigned)(need / 1024),
                     (unsigned)(heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024),
                     (unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM) / 1024));
            return false;   // alten (kleineren) Puffer NICHT freigeben -> kein Nullzustand
        }
        if (jpegBuf_) free(jpegBuf_);
        jpegBuf_ = nb; jpegCap_ = got ? got : need;
        ESP_LOGI(TAGP4, "JPEG-Outbuf %uk bereit", (unsigned)(jpegCap_ / 1024));
    }
    return jpegBuf_ != nullptr;
}

// Capture abbauen (fuer die Laufzeit-Umschaltung): Stream stoppen, Puffer freigeben,
// Treiber-Puffer zurueckgeben, JPEG-Encoder freigeben. fd_ bleibt offen.
void Esp32P4MipiCamera::teardownCapture() {
    if (fd_ < 0) return;
    int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    ioctl(fd_, VIDIOC_STREAMOFF, &type);
    for (int i = 0; i < bufCount_; i++)
        if (bufPtr_[i]) { munmap(bufPtr_[i], bufLen_[i]); bufPtr_[i] = nullptr; bufLen_[i] = 0; }
    bufCount_ = 0; curBufIndex_ = -1;
    struct v4l2_requestbuffers req; memset(&req, 0, sizeof(req));
    req.count = 0; req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE; req.memory = V4L2_MEMORY_MMAP;
    ioctl(fd_, VIDIOC_REQBUFS, &req);
    // JPEG-Encoder + Ausgabepuffer bewusst NICHT anfassen -> eigener Lifecycle, bleibt ueber
    // Mode-Switches bestehen (kein Alloc/Free-Zyklus pro Wechsel, kein irreversibles Vergiften).
}

// Generischer Apply-Port: Capture-Aufloesung zur Laufzeit umschalten. Nur wirklich
// enumerierte Modi (keine erfundenen Aufloesungen). Ist w×h bereits aktiv -> No-op (der
// aktuelle 800x800-only-Build laeuft immer hier durch -> nichts aendert sich).
// HINWEIS Phase 2/3: bei >1 Modus braucht der Umschalt-Pfad noch eine Sperre gegen
// acquireFrame() (Stream-Task) -- heute dormant, da nur ein Modus existiert.
bool Esp32P4MipiCamera::setMode(uint16_t w, uint16_t h) {
    P4_LOCK();
    if (!ready_ || fd_ < 0) { P4_UNLOCK(); return false; }
    if (w == config_.width && h == config_.height) { P4_UNLOCK(); return true; }   // schon aktiv -> No-op

    // Ziel-Sensor-Format (voller Descriptor mit regs/isp_info/mipi) aus der Sensor-Liste.
    const esp_cam_sensor_format_t* target = p4FindSensorFormat(w, h);
    if (!target) { ESP_LOGW(TAGP4, "setMode: %ux%u nicht in Sensor-Formatliste -> abgelehnt", w, h); P4_UNLOCK(); return false; }

    // Heap-Diagnose VOR dem Switch (erkennt monotonen internen Heap-Verlust ueber Wechsel).
    ESP_LOGI(TAGP4, "setMode %ux%u->%ux%u | vor: intern frei %uk groesster %uk | PSRAM frei %uk groesster %uk",
             config_.width, config_.height, w, h,
             (unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024),
             (unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) / 1024),
             (unsigned)(heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024),
             (unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM) / 1024));

    // Ab jetzt liefert acquireFrame() nullptr; auf die Rueckgabe eines evtl. ausgeliehenen
    // Frames warten (Lock dabei freigeben, damit releaseFrame() laufen kann). Bis ~1s.
    reconfiguring_ = true;
    bool freed = (curBufIndex_ < 0);
    for (int i = 0; i < 200 && !freed; i++) {
        P4_UNLOCK(); vTaskDelay(pdMS_TO_TICKS(5)); P4_LOCK();
        freed = (curBufIndex_ < 0);
    }
    if (!freed) {
        reconfiguring_ = false;
        ESP_LOGW(TAGP4, "setMode: Frame haengt in flight -> Umschaltung abgebrochen");
        P4_UNLOCK();
        return false;
    }

    // Lebenszyklus (wie common_video_set_sensor_format vorsieht): Capture/Stream AUS ->
    // Sensor-Format setzen (schaltet Sensor-Registersatz + rekonfiguriert ISP) -> Capture neu.
    uint16_t oldW = config_.width, oldH = config_.height;
    teardownCapture();
    if (ioctl(fd_, VIDIOC_S_SENSOR_FMT, (void*)target) != 0) {
        ESP_LOGE(TAGP4, "VIDIOC_S_SENSOR_FMT %ux%u fehlgeschlagen -> Restore", w, h);
        const esp_cam_sensor_format_t* back = p4FindSensorFormat(oldW, oldH);
        if (back) ioctl(fd_, VIDIOC_S_SENSOR_FMT, (void*)back);
        if (!applyCaptureFormat(oldW, oldH)) ready_ = false;
        reconfiguring_ = false; P4_UNLOCK(); return false;
    }
    if (applyCaptureFormat(w, h)) {   // S_FMT liest die neue Geometrie zurueck (config_ = w×h)
        // Eine Zeile je Umschaltung ueber stdout (ESP_LOGI ist im Sketch-Build unsichtbar).
        printf("[p4cam] Sensor-Modus %ux%u -> %ux%u aktiv\n", oldW, oldH, config_.width, config_.height);
        reconfiguring_ = false;
        ESP_LOGI(TAGP4, "setMode -> Sensor %ux%u aktiv | nach: intern frei %uk groesster %uk | PSRAM frei %uk",
                 config_.width, config_.height,
                 (unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024),
                 (unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) / 1024),
                 (unsigned)(heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024));
        P4_UNLOCK();
        return true;
    }
    // Capture-Setup fehlgeschlagen -> alten Sensor-Modus + Capture wiederherstellen.
    ESP_LOGE(TAGP4, "setMode: applyCaptureFormat %ux%u fehlgeschlagen -> Restore %ux%u", w, h, oldW, oldH);
    teardownCapture();
    const esp_cam_sensor_format_t* back = p4FindSensorFormat(oldW, oldH);
    if (back) ioctl(fd_, VIDIOC_S_SENSOR_FMT, (void*)back);
    if (!applyCaptureFormat(oldW, oldH)) {
        ready_ = false;
        ESP_LOGE(TAGP4, "setMode: Restore %ux%u fehlgeschlagen -> Kamera unavailable", oldW, oldH);
    }
    reconfiguring_ = false;
    P4_UNLOCK();
    return false;
}

bool Esp32P4MipiCamera::isReady() const { return ready_; }

bool Esp32P4MipiCamera::currentMode(uint16_t& w, uint16_t& h) const {
    if (!ready_) return false;
    w = config_.width; h = config_.height;   // vom letzten S_FMT zurueckgelesen
    return true;
}

CameraFrame* Esp32P4MipiCamera::acquireFrame() {
    P4_LOCK();
    // Waehrend einer Umschaltung (reconfiguring_) oder solange schon ein Frame ausgecheckt
    // ist, KEIN neuer DQBUF -> setMode() kann die Puffer gefahrlos ab-/aufbauen.
    if (!ready_ || reconfiguring_ || curBufIndex_ >= 0) { P4_UNLOCK(); return nullptr; }
    struct v4l2_buffer buf; memset(&buf, 0, sizeof(buf));
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE; buf.memory = V4L2_MEMORY_MMAP;
    if (ioctl(fd_, VIDIOC_DQBUF, &buf) != 0) { P4_UNLOCK(); return nullptr; }
    curBufIndex_    = buf.index;   // ab hier ist der Puffer ausgeliehen -> setMode() wartet darauf
    frame_.width    = config_.width;
    frame_.height   = config_.height;
    frame_.sequence = ++sequence_;

    // ISP-Frame -> HW-JPEG-Encoder -> fertiger JPEG-Frame. Runtime-Pfad aktiv gdw. Encoder +
    // Puffer vorhanden (jpegCapable_ ist die statische Faehigkeit, hier nicht mehr abgefragt).
    if (jpegEnc_ && jpegBuf_) {
        jpeg_encode_cfg_t cfg = {};
        cfg.width         = config_.width;
        cfg.height        = config_.height;
        cfg.src_type      = (jpeg_enc_input_format_t)jpegSrcType_;
        cfg.sub_sample    = JPEG_DOWN_SAMPLING_YUV420;
        cfg.image_quality = jpegQuality_;
        cfg.pixel_reverse = false;
        uint32_t outLen = 0;
        esp_err_t e = jpeg_encoder_process((jpeg_encoder_handle_t)jpegEnc_, &cfg,
                          (const uint8_t*)bufPtr_[buf.index], buf.bytesused,
                          jpegBuf_, jpegCap_, &outLen);
        if (e == ESP_OK && outLen > 0) {
            frame_.data        = jpegBuf_;
            frame_.size        = outLen;
            frame_.pixelFormat = CAMERA_PIXEL_FORMAT_JPEG;
            P4_UNLOCK();
            return &frame_;   // gueltig bis releaseFrame() (curBufIndex_>=0 haelt setMode() ab)
        }
        ESP_LOGW(TAGP4, "jpeg_encoder_process=%d (in %u B) -> Rohframe", (int)e, buf.bytesused);
    }
    // Fallback: Rohframe (kein JPEG-Pfad oder Encode-Fehler).
    frame_.data        = (uint8_t*)bufPtr_[buf.index];
    frame_.size        = buf.bytesused;
    frame_.pixelFormat = p4MapPixFmt(curPixFmt_);
    P4_UNLOCK();
    return &frame_;
}

// Roher ISP-Frame OHNE JPEG-Encode -- fuer den H.264-HW-Encoder (der Rohbilder frisst). Gleiche
// DQBUF-/Lock-/curBufIndex_-Mechanik wie acquireFrame(); releaseFrame() gibt den Puffer identisch
// zurueck (QBUF). Zero-copy: liefert direkt den DMA-faehigen mmap-Puffer im curPixFmt_-Format.
CameraFrame* Esp32P4MipiCamera::acquireRawFrame() {
    P4_LOCK();
    if (!ready_ || reconfiguring_ || curBufIndex_ >= 0) { P4_UNLOCK(); return nullptr; }
    struct v4l2_buffer buf; memset(&buf, 0, sizeof(buf));
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE; buf.memory = V4L2_MEMORY_MMAP;
    if (ioctl(fd_, VIDIOC_DQBUF, &buf) != 0) { P4_UNLOCK(); return nullptr; }
    curBufIndex_       = buf.index;   // ausgeliehen -> setMode() wartet, releaseFrame() gibt zurueck
    frame_.width       = config_.width;
    frame_.height      = config_.height;
    frame_.sequence    = ++sequence_;
    frame_.data        = (uint8_t*)bufPtr_[buf.index];
    frame_.size        = buf.bytesused;
    frame_.pixelFormat = p4MapPixFmt(curPixFmt_);   // roh (RGB565/YUV422) -- NICHT JPEG
    P4_UNLOCK();
    return &frame_;
}

// VIDIOC_ENUM_FMT auf dem offenen /dev/video0 -> welche Pixel-Ausgabeformate der Capture-Pfad
// (Sensor+ISP) anbietet. Read-only, greift den laufenden Stream nicht an. Fuer die H.264-Diagnose:
// kann der ISP YUV420 (NV12/YU12) direkt? -> dann keine PPA-Farbkonversion noetig.
int Esp32P4MipiCamera::enumPixelFormats(uint32_t* outFourcc, int maxOut) const {
    if (fd_ < 0 || !outFourcc || maxOut <= 0) return 0;
    int n = 0;
    for (uint32_t i = 0; n < maxOut; i++) {
        struct v4l2_fmtdesc fdesc; memset(&fdesc, 0, sizeof(fdesc));
        fdesc.index = i; fdesc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        if (ioctl(fd_, VIDIOC_ENUM_FMT, &fdesc) != 0) break;
        outFourcc[n++] = fdesc.pixelformat;
    }
    return n;
}

void Esp32P4MipiCamera::releaseFrame(CameraFrame* frame) {
    (void)frame;
    P4_LOCK();
    if (curBufIndex_ >= 0) {
        struct v4l2_buffer buf; memset(&buf, 0, sizeof(buf));
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE; buf.memory = V4L2_MEMORY_MMAP; buf.index = curBufIndex_;
        ioctl(fd_, VIDIOC_QBUF, &buf);
        curBufIndex_ = -1;   // Puffer zurueck -> setMode() darf jetzt umschalten
        frame_.data = nullptr; frame_.size = 0;
    }
    P4_UNLOCK();
}

int Esp32P4MipiCamera::paramCount() const { return ready_ ? P4_PARAM_COUNT : 0; }

bool Esp32P4MipiCamera::paramAt(int index, CameraParamInfo& out) const {
    if (index < 0 || index >= P4_PARAM_COUNT) return false;
    const P4ParamDesc& d = P4_PARAMS[index];
    out.key = d.key; out.label = d.label; out.min = d.mn; out.max = d.mx; out.kind = d.kind;
    struct v4l2_control ctrl; memset(&ctrl, 0, sizeof(ctrl)); ctrl.id = d.cid;
    out.value = (ioctl(fd_, VIDIOC_G_CTRL, &ctrl) == 0) ? ctrl.value : 0;
    return true;
}

bool Esp32P4MipiCamera::setParam(const char* key, int value) {
    if (!key) return false;
    for (int i = 0; i < P4_PARAM_COUNT; i++) {
        if (strcmp(key, P4_PARAMS[i].key) == 0) {
            struct v4l2_control ctrl; memset(&ctrl, 0, sizeof(ctrl));
            ctrl.id = P4_PARAMS[i].cid; ctrl.value = value;
            return ioctl(fd_, VIDIOC_S_CTRL, &ctrl) == 0;
        }
    }
    return false;
}

// Native Capture-Modi DYNAMISCH aus V4L2 enumerieren: ENUM_FMT x ENUM_FRAMESIZES
// (nur diskrete) x ENUM_FRAMEINTERVALS (fuer max fps). Das ist genau die Schnittmenge
// Sensor∩ISP -- /dev/video0 meldet nur, was die Pipeline wirklich liefern kann. Wird
// ein Sensor-Modus im Core aktiviert (Lib-Rebuild), taucht er hier automatisch auf.
// Fallbacks, falls das esp_video-V4L2 die Enum-ioctls (noch) nicht implementiert.
int Esp32P4MipiCamera::enumModes(CameraVideoMode* out, int maxOut) const {
    if (fd_ < 0 || !out || maxOut <= 0) return 0;

    // Bevorzugt: die ECHTEN Sensor-Modi aus der (in ov5647.o exportierten) Descriptor-Liste.
    // Das ist die Wahrheit fuer /dev/camera0.modes -- V4L2 ENUM_FRAMESIZES meldet nur den
    // AKTIVEN Sensor-Modus, nicht die Formatliste. Fallback unten, falls Accessor nicht gelinkt.
    {
        int scount = 0;
        const esp_cam_sensor_format_t* sf = weirdos_ov5647_formats(&scount);
        if (sf && scount > 0) {
            int m = 0;
            for (int i = 0; i < scount && m < maxOut; i++) {
                out[m].width       = (uint16_t)sf[i].width;
                out[m].height      = (uint16_t)sf[i].height;
                out[m].pixelFormat = CAMERA_PIXEL_FORMAT_GRAYSCALE;  // Sensor liefert RAW/Bayer (Platzhalter)
                out[m].maxFps      = (uint16_t)sf[i].fps;
                out[m].enumerated  = true;
                ESP_LOGI(TAGP4, "  Sensor-Modus %ux%u %u fps [sensor-list]",
                         sf[i].width, sf[i].height, sf[i].fps);
                m++;
            }
            return m;
        }
    }

    int n = 0;
    struct v4l2_fmtdesc fdsc; memset(&fdsc, 0, sizeof(fdsc));
    fdsc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    for (fdsc.index = 0; n < maxOut && ioctl(fd_, VIDIOC_ENUM_FMT, &fdsc) == 0; fdsc.index++) {
        uint32_t pf = fdsc.pixelformat;
        bool anySize = false;
        struct v4l2_frmsizeenum fs; memset(&fs, 0, sizeof(fs));
        fs.pixel_format = pf;
        for (fs.index = 0; n < maxOut && ioctl(fd_, VIDIOC_ENUM_FRAMESIZES, &fs) == 0; fs.index++) {
            if (fs.type != V4L2_FRMSIZE_TYPE_DISCRETE) break;   // nur diskrete Modi anbieten
            anySize = true;
            uint16_t w = (uint16_t)fs.discrete.width, h = (uint16_t)fs.discrete.height;
            uint16_t fps = 0;
            struct v4l2_frmivalenum fi; memset(&fi, 0, sizeof(fi));
            fi.pixel_format = pf; fi.width = w; fi.height = h;
            for (fi.index = 0; ioctl(fd_, VIDIOC_ENUM_FRAMEINTERVALS, &fi) == 0; fi.index++) {
                if (fi.type != V4L2_FRMIVAL_TYPE_DISCRETE) break;
                if (fi.discrete.numerator > 0) {
                    uint16_t f = (uint16_t)(fi.discrete.denominator / fi.discrete.numerator);
                    if (f > fps) fps = f;
                }
            }
            out[n].width = w; out[n].height = h;
            out[n].pixelFormat = p4MapPixFmt(pf); out[n].maxFps = fps;
            out[n].enumerated = true;   // echt via VIDIOC_ENUM_FRAMESIZES
            ESP_LOGI(TAGP4, "  Modus %ux%u '%c%c%c%c' max %u fps [enum]", w, h,
                     (char)(pf & 0xff), (char)((pf >> 8) & 0xff),
                     (char)((pf >> 16) & 0xff), (char)((pf >> 24) & 0xff), fps);
            n++;
        }
        // Format ohne enumerierbare Groessen (ENUM_FRAMESIZES nicht unterstuetzt) ->
        // wenigstens den aktiven Modus dieses Formats melden.
        if (!anySize && n < maxOut && pf == curPixFmt_) {
            out[n].width = config_.width; out[n].height = config_.height;
            out[n].pixelFormat = p4MapPixFmt(pf); out[n].maxFps = 0;
            out[n].enumerated = false;   // Active-Mode-Fallback (ENUM_FRAMESIZES lieferte nichts)
            ESP_LOGW(TAGP4, "  ENUM_FRAMESIZES leer/nicht unterstuetzt -> aktiver Modus %ux%u [fallback]",
                     config_.width, config_.height);
            n++;
        }
    }
    // Letzter Fallback: gar nichts enumeriert -> aktiven Modus als einzigen melden.
    if (n == 0 && curPixFmt_) {
        out[0].width = config_.width; out[0].height = config_.height;
        out[0].pixelFormat = p4MapPixFmt(curPixFmt_); out[0].maxFps = 0;
        out[0].enumerated = false;   // Active-Mode-Fallback
        n = 1;
    }
    return n;
}

#else
// ---------------------------------------------------------------------------
// Nicht-P4-Target (z.B. XIAO-S3): Stubs. Geraet wird hier nie ausgewaehlt. P4_JPEG_QUALITY ist
// nur im P4-Zweig deklariert -> hier Literal (Wert egal, Stub).
// ---------------------------------------------------------------------------
Esp32P4MipiCamera::Esp32P4MipiCamera()
    : config_{ 1920, 1080, 12, 2 }, ready_(false), frame_{}, fd_(-1),
      curPixFmt_(0), jpegCapable_(false), inFourcc_(0), jpegSrcType_(0),
      jpegEnc_(nullptr), jpegBuf_(nullptr), jpegCap_(0),
      curBufIndex_(-1), sequence_(0), jpegQuality_(45), bufCount_(0),
      lock_(nullptr), reconfiguring_(false) {
    for (int i = 0; i < MAX_BUFS; i++) { bufPtr_[i] = nullptr; bufLen_[i] = 0; }
}

// UI-Skala 0..63 (0 = beste) -> P4-HW-Encoder-Skala 1..100 (hoeher = besser). Linear invertiert.
// Wird pro Frame in cfg.image_quality gelesen -> Aenderung wirkt sofort beim naechsten Frame.
void Esp32P4MipiCamera::setJpegQualityUi(int ui0to63) {
    if (ui0to63 < 0) ui0to63 = 0;
    if (ui0to63 > 63) ui0to63 = 63;
    int q = 100 - (ui0to63 * 99) / 63;   // ui 0 -> 100 (beste), ui 63 -> 1 (kleinste)
    if (q < 1) q = 1;
    if (q > 100) q = 100;
    jpegQuality_ = q;
}
int Esp32P4MipiCamera::jpegQualityUi() const {
    return ((100 - jpegQuality_) * 63) / 99;   // Rueckabbildung P4 1..100 -> UI 0..63
}
Esp32P4MipiCamera::~Esp32P4MipiCamera() {}
void Esp32P4MipiCamera::configure(const Config& c) { config_ = c; }
bool Esp32P4MipiCamera::begin() { return false; }
bool Esp32P4MipiCamera::isReady() const { return false; }
CameraFrame* Esp32P4MipiCamera::acquireFrame() { return nullptr; }
CameraFrame* Esp32P4MipiCamera::acquireRawFrame() { return nullptr; }
int Esp32P4MipiCamera::enumPixelFormats(uint32_t*, int) const { return 0; }
void Esp32P4MipiCamera::releaseFrame(CameraFrame*) {}
int Esp32P4MipiCamera::enumModes(CameraVideoMode*, int) const { return 0; }
bool Esp32P4MipiCamera::setMode(uint16_t, uint16_t) { return false; }
bool Esp32P4MipiCamera::currentMode(uint16_t&, uint16_t&) const { return false; }
int Esp32P4MipiCamera::paramCount() const { return 0; }
bool Esp32P4MipiCamera::paramAt(int, CameraParamInfo&) const { return false; }
bool Esp32P4MipiCamera::setParam(const char*, int) { return false; }
#endif

#else
// ============================================================================
// Stub: Kamera nicht im Build enthalten (WEIRDOS_FEATURE_CAMERA=0), alle Targets
// CameraManager haelt dieses Geraet auf dem P4 BY VALUE -> die Klasse muss vollstaendig sein
// (Konstruktor/Destruktor/alle Overrides). Kein esp_video/V4L2/HW-JPEG hier -> keine dieser
// Komponenten (und kein ov5647-Treiber-Anker) wird in einen kameralosen Build gelinkt.
// ============================================================================
Esp32P4MipiCamera::Esp32P4MipiCamera()
    : config_{ 0, 0, 12, 2 }, ready_(false), frame_{}, fd_(-1),
      curPixFmt_(0), jpegCapable_(false), inFourcc_(0), jpegSrcType_(0),
      jpegEnc_(nullptr), jpegBuf_(nullptr), jpegCap_(0),
      curBufIndex_(-1), sequence_(0), jpegQuality_(0), bufCount_(0),
      lock_(nullptr), reconfiguring_(false) {
    for (int i = 0; i < MAX_BUFS; i++) { bufPtr_[i] = nullptr; bufLen_[i] = 0; }
}
Esp32P4MipiCamera::~Esp32P4MipiCamera() {}
void         Esp32P4MipiCamera::configure(const Config& config) { config_ = config; }
bool         Esp32P4MipiCamera::begin() { return false; }
bool         Esp32P4MipiCamera::isReady() const { return false; }
CameraFrame* Esp32P4MipiCamera::acquireFrame() { return nullptr; }
CameraFrame* Esp32P4MipiCamera::acquireRawFrame() { return nullptr; }
void         Esp32P4MipiCamera::releaseFrame(CameraFrame* frame) { (void)frame; }
int          Esp32P4MipiCamera::enumPixelFormats(uint32_t* outFourcc, int maxOut) const { (void)outFourcc; (void)maxOut; return 0; }
int          Esp32P4MipiCamera::enumModes(CameraVideoMode* out, int maxOut) const { (void)out; (void)maxOut; return 0; }
bool         Esp32P4MipiCamera::setMode(uint16_t width, uint16_t height) { (void)width; (void)height; return false; }
bool         Esp32P4MipiCamera::currentMode(uint16_t& width, uint16_t& height) const { (void)width; (void)height; return false; }
int          Esp32P4MipiCamera::paramCount() const { return 0; }
bool         Esp32P4MipiCamera::paramAt(int index, CameraParamInfo& out) const { (void)index; (void)out; return false; }
bool         Esp32P4MipiCamera::setParam(const char* key, int value) { (void)key; (void)value; return false; }
void         Esp32P4MipiCamera::setJpegQualityUi(int ui0to63) { (void)ui0to63; }
int          Esp32P4MipiCamera::jpegQualityUi() const { return -1; }
bool         Esp32P4MipiCamera::applyCaptureFormat(uint16_t width, uint16_t height) { (void)width; (void)height; return false; }
void         Esp32P4MipiCamera::teardownCapture() {}
bool         Esp32P4MipiCamera::ensureJpegEncoder(uint16_t width, uint16_t height) { (void)width; (void)height; return false; }
#endif  // WEIRDOS_FEATURE_CAMERA
