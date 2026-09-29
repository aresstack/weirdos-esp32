// ============================================================================
// camera_manager.cpp
// ============================================================================
#include "weirdos_features.h"   // WEIRDOS_FEATURE_CAMERA -- der Schalter dieses Bausteins
#include "camera_manager.h"     // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
#if WEIRDOS_FEATURE_CAMERA
// ============================================================================
// Echte Implementierung (WEIRDOS_FEATURE_CAMERA=1)
// ============================================================================

CameraManager cameraManager;

CameraManager::CameraManager()
    : device_(&concrete_),
      ready_(false) {}


bool CameraManager::begin(const Config& config) {
#if defined(CONFIG_IDF_TARGET_ESP32P4)
    Esp32P4MipiCamera::Config devConfig;
    devConfig.width       = config.width;
    devConfig.height      = config.height;
    devConfig.jpegQuality = config.jpegQuality;
    devConfig.fbCount     = config.fbCount;
#else
    Esp32S3DvpCamera::Config devConfig;
    devConfig.frameSize     = config.frameSize;
    devConfig.maxFrameSize  = config.maxFrameSize;
    devConfig.jpegQuality   = config.jpegQuality;
    devConfig.bufferQuality = config.bufferQuality;
    devConfig.fbCount       = config.fbCount;
#endif
    concrete_.configure(devConfig);

    ready_ = (device_ != nullptr) && device_->begin();
    return ready_;
}


bool CameraManager::isReady() const {
    return ready_ && device_ != nullptr && device_->isReady();
}


CameraFrame* CameraManager::acquireFrame() {
    if (!ready_ || device_ == nullptr) {
        return nullptr;
    }
    return device_->acquireFrame();
}


void CameraManager::releaseFrame(CameraFrame* frame) {
    if (device_ != nullptr) {
        device_->releaseFrame(frame);
    }
}

int CameraManager::enumModes(CameraVideoMode* out, int maxOut) const {
    return device_ ? device_->enumModes(out, maxOut) : 0;
}

bool CameraManager::setMode(uint16_t width, uint16_t height) {
    return device_ ? device_->setMode(width, height) : false;
}

bool CameraManager::currentMode(uint16_t& width, uint16_t& height) const {
    return device_ ? device_->currentMode(width, height) : false;
}

int CameraManager::paramCount() const {
    return device_ ? device_->paramCount() : 0;
}

bool CameraManager::paramAt(int index, CameraParamInfo& out) const {
    return device_ ? device_->paramAt(index, out) : false;
}

bool CameraManager::setParam(const char* key, int value) {
    return device_ ? device_->setParam(key, value) : false;
}

#else
// ============================================================================
// Stub: Kamera nicht im Build enthalten (WEIRDOS_FEATURE_CAMERA=0)
// Dieselben Symbole, triviale Koerper. Der Manager besitzt KEIN Geraet (device_ = nullptr),
// damit alle Inline-Passthroughs im Header (acquireRawFrame, enumPixelFormats, Qualitaet,
// device()) von selbst inert sind. concrete_ bleibt als Member bestehen (der Header haelt
// das Geraet by value); die Geraete-.cpp liefern dafuer ihre eigenen Stubs.
// ============================================================================
CameraManager cameraManager;

CameraManager::CameraManager()
    : device_(nullptr),
      ready_(false) {}

bool         CameraManager::begin(const Config& config) { (void)config; return false; }
bool         CameraManager::isReady() const { return false; }
CameraFrame* CameraManager::acquireFrame() { return nullptr; }
void         CameraManager::releaseFrame(CameraFrame* frame) { (void)frame; }
int          CameraManager::enumModes(CameraVideoMode* out, int maxOut) const { (void)out; (void)maxOut; return 0; }
bool         CameraManager::setMode(uint16_t width, uint16_t height) { (void)width; (void)height; return false; }
bool         CameraManager::currentMode(uint16_t& width, uint16_t& height) const { (void)width; (void)height; return false; }
int          CameraManager::paramCount() const { return 0; }
bool         CameraManager::paramAt(int index, CameraParamInfo& out) const { (void)index; (void)out; return false; }
bool         CameraManager::setParam(const char* key, int value) { (void)key; (void)value; return false; }
#endif  // WEIRDOS_FEATURE_CAMERA
