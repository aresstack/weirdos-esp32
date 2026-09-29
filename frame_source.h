// ============================================================================
// frame_source.h  --  Generische Bildquelle (Capability), transport-/geraeteneutral
//
// Minimale Schnittstelle, die eine Quelle von JPEG/Frames bereitstellt. Bewusst
// KLEIN: nur Bereitschaft + Frame holen/freigeben. Sensor-/Geraeteparameter
// (Helligkeit, Aufloesung, Flip, ...) gehoeren NICHT hierher, sondern zur Kamera-/
// Device-Capability - sonst koennte eine spaetere synthetische Quelle (USB-Decoder,
// RTSP, Vision-Overlay) die Schnittstelle nicht erfuellen.
//
// Konsumenten (z.B. CameraStreamService) haengen nur an FrameSource, nicht mehr am
// konkreten CameraManager. Die Registry loest logische Namen (camera0) hierauf auf.
// ============================================================================
#ifndef FRAME_SOURCE_H
#define FRAME_SOURCE_H

struct CameraFrame;   // nur per Zeiger benutzt -> Vorwaertsdeklaration genuegt

class FrameSource {
public:
    virtual ~FrameSource() = default;

    virtual bool         isReady() const = 0;
    virtual CameraFrame* acquireFrame() = 0;
    virtual void         releaseFrame(CameraFrame* frame) = 0;
    // Rohframe (ISP-Ausgang, z.B. RGB565) fuer Encoder-Pfade (H.264). Default: nicht verfuegbar.
    // Freigabe ebenfalls ueber releaseFrame(). Eine Quelle kann zu jedem Zeitpunkt nur EINEN
    // Frame ausgeliehen haben (JPEG oder roh) -- der Verteiler (CameraStreamService) ist der
    // einzige Besitzer der Capture und serialisiert das.
    virtual CameraFrame* acquireRawFrame() { return nullptr; }
};

#endif // FRAME_SOURCE_H
