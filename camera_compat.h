// ============================================================================
// camera_compat.h  --  esp_camera-Kompatibilitaet ueber Board-Grenzen hinweg
//
// Auf Boards MIT der esp32-camera-Lib (XIAO ESP32-S3 / DVP) wird der echte
// Header genutzt. Auf Boards OHNE die Lib (z. B. ESP32-P4 / MIPI-CSI) fehlt
// esp_camera.h komplett -> hier stehen MINIMALE, INERTE Shims, damit der noch
// vorhandene S3-Legacy-Direktcode (Sensor-Steuerung in der .ino, /capture in
// camera_server.cpp) kompiliert. Die ECHTE Kamera laeuft dort ueber
// CameraManager -> Esp32P4MipiCamera (V4L2); diese Stubs liefern nur nullptr,
// d. h. die Direkt-esp_camera-Pfade melden sauber "kein Bild/Sensor" statt zu
// brechen. Ziel: der P4-Build wird gruen; die MIPI-Verdrahtung ist ein eigener
// Slice.  (Wenn diese Direktpfade spaeter ganz ueber CameraManager laufen,
// kann dieser Shim wieder entfallen.)
// ============================================================================
#ifndef CAMERA_COMPAT_H
#define CAMERA_COMPAT_H

#if __has_include("esp_camera.h")
#include "esp_camera.h"
#else

#include <cstddef>
#include <cstdint>

// Nur die Namen, die die App-Tabelle FRAME_SIZE_OPTIONS und die Direktpfade
// tatsaechlich verwenden. Zahlenwerte sind auf Nicht-DVP-Boards belanglos
// (werden nie an Hardware gereicht -- der MIPI-Pfad nutzt width/height).
typedef enum {
    FRAMESIZE_VGA, FRAMESIZE_SVGA, FRAMESIZE_XGA,
    FRAMESIZE_HD,  FRAMESIZE_UXGA, FRAMESIZE_QXGA
} framesize_t;

typedef enum { PIXFORMAT_JPEG } pixformat_t;

typedef struct {
    uint8_t*    buf;
    size_t      len;
    size_t      width;
    size_t      height;
    pixformat_t format;
} camera_fb_t;

typedef struct sensor_s sensor_t;
struct sensor_s {
    int (*set_framesize)(sensor_t* sensor, framesize_t framesize);
    int (*set_quality)(sensor_t* sensor, int quality);
};

// Inerte Stubs: auf Boards ohne DVP-Kamera gibt es keinen Sensor/Frame hier.
static inline camera_fb_t* esp_camera_fb_get()            { return nullptr; }
static inline void         esp_camera_fb_return(camera_fb_t*) {}
static inline sensor_t*    esp_camera_sensor_get()        { return nullptr; }

#endif  // __has_include("esp_camera.h")
#endif  // CAMERA_COMPAT_H
