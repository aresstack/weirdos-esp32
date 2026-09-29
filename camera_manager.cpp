// ============================================================================
// camera_manager.cpp
// ============================================================================
#include "camera_manager.h"

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
