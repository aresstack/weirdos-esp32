// ============================================================================
// camera_frame.h  --  Neutrales, hardware-unabhaengiges Frame-Modell
//
// Weder esp_camera noch camera_fb_t/framesize_t/pixformat_t duerfen die
// Kamera-Schicht verlassen. Stream-Service und (spaeter) AI-Detektor arbeiten
// ausschliesslich mit CameraFrame -> die konkrete Kamera (S3-DVP heute,
// P4-MIPI spaeter) bleibt austauschbar.
// ============================================================================
#ifndef CAMERA_FRAME_H
#define CAMERA_FRAME_H

#include <cstdint>
#include <cstddef>

enum CameraPixelFormat {
    CAMERA_PIXEL_FORMAT_JPEG,
    CAMERA_PIXEL_FORMAT_RGB565,
    CAMERA_PIXEL_FORMAT_RGB888,
    CAMERA_PIXEL_FORMAT_YUV422,
    CAMERA_PIXEL_FORMAT_GRAYSCALE
};

// Ein Bild. Das Eigentum an data bleibt beim CameraDevice, bis releaseFrame()
// aufgerufen wird (Zero-Copy: derselbe Frame kann an Stream UND AI gehen).
struct CameraFrame {
    uint8_t*          data;
    size_t            size;
    uint16_t          width;
    uint16_t          height;
    CameraPixelFormat pixelFormat;
    uint32_t          sequence;   // monoton steigend -> Konsumenten erkennen neue Frames
};

#endif // CAMERA_FRAME_H
