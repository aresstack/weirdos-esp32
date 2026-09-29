// ============================================================================
// camera_stream_service.h  --  "Ein Frame fuer alle" (transport-/HTTP-neutral)
//
// Ein zentraler Capture-Task holt jeden Frame genau EINMAL vom CameraManager
// in einen geteilten PSRAM-Puffer; beliebig viele Consumer kopieren daraus
// (copyLatest). Der Service kennt weder esp_http_server noch esp_camera -> die
// HTTP-Stream-Tasks bleiben in der App und rufen nur copyLatest()/addClient().
// ============================================================================
#ifndef CAMERA_STREAM_SERVICE_H
#define CAMERA_STREAM_SERVICE_H

#include "frame_source.h"   // haengt nur noch an der generischen Bildquelle
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include <cstdint>
#include <cstddef>

class CameraStreamService {
public:
    explicit CameraStreamService(FrameSource& source);

    void begin();                 // Mutex anlegen (idempotent)
    void setTargetFps(int fps);   // Live-Bildrate (App reicht ihren Wert herein)

    void addClient();             // +1 Consumer; startet den Capture-Task bei Bedarf
    void removeClient();          // -1 Consumer; Task stoppt bei 0
    int  clientCount() const;

    // Neuesten Frame nach dst kopieren (bis maxLen). Rueckgabe = Laenge
    // (0 = keiner / passt nicht / nicht neuer). *seq: wenn gesetzt, wird nur
    // kopiert, falls der Frame neuer ist als *seq -> danach *seq aktualisiert.
    // Kopiert den neuesten Frame nach *dst und WAECHST *dst/*cap bei Bedarf -- alles
    // unter dem internen Lock (kein Groessen-Wettlauf). *dst muss ein heap_caps_*-Puffer
    // (MALLOC_CAP_SPIRAM) oder NULL sein; *cap seine aktuelle Kapazitaet. 0 = kein neuer Frame.
    size_t   copyLatest(uint8_t** dst, size_t* cap, uint32_t* seq);
    uint32_t latestSequence() const;
    size_t   latestLen() const;   // aktuelle Frame-Laenge (Hint fuer Puffer-Wachstum)

    // ---- Globale Frame-Politik (Server > Video > Bild, neben der Bildrate) ------------------
    // dropStale = true (Default): ein langsamer Consumer bekommt immer den NEUESTEN Frame, was er
    //   verpasst hat, wird verworfen -- Bildrate folgt der Bandbreite, Latenz bleibt bei einem
    //   Frame (das bewaehrte MJPEG-Verhalten).
    // dropStale = false: kein Frame geht verloren -- der Verteiler veroeffentlicht den naechsten
    //   Frame erst, wenn ALLE Consumer den aktuellen abgeholt haben (Rueckstau bis zum Sensor);
    //   Latenz darf wachsen.
    void setDropStale(bool on);
    bool dropStale() const;

    // ---- Roh-Kanal fuer Encoder (H.264): DERSELBE Verteiler, dieselbe Politik, zero-copy ---
    // Der Capture-Task holt den Rohframe, veroeffentlicht ihn (rawSequence steigt) und HAELT die
    // Ausleihe, bis der Consumer rawReturn() ruft; erst dann wird der Treiber-Puffer freigegeben
    // und der naechste geholt (bei dropStale: veraltete Ringpuffer vorher verworfen). Genau ein
    // Roh-Consumer; solange er aktiv ist, liefert die Quelle keine JPEG-Frames (eine Ausleihe je
    // Quelle) -- MJPEG-Clients sehen dann keine neuen Frames.
    void               addRawClient();
    void               removeRawClient();
    const CameraFrame* rawBorrowLatest(uint32_t* seq);   // neuer als *seq? -> Frame (dann *seq gesetzt), sonst nullptr
    void               rawReturn();                      // Consumer fertig -> Capture gibt frei/holt weiter
    uint32_t           rawSequence() const;
    uint32_t           rawDropped() const;               // verworfene Rohframes (Statistik)

private:
    static void captureTrampoline(void* arg);
    void        captureLoop();

    FrameSource&      src_;
    SemaphoreHandle_t mutex_;
    uint8_t*          buf_;
    size_t            cap_;
    size_t            len_;
    volatile uint32_t seq_;
    volatile int      clients_;
    volatile bool     taskRunning_;
    volatile int      targetFps_;
    // Politik + Roh-Kanal
    volatile bool     dropStale_;
    volatile int      jpegAcks_;      // Consumer, die den aktuellen JPEG-Frame abgeholt haben (nur !dropStale)
    volatile int      rawClients_;
    CameraFrame*      rawFrame_;      // aktuell veroeffentlichter/ausgeliehener Rohframe (nullptr = keiner)
    volatile uint32_t rawSeq_;
    volatile bool     rawReturned_;   // Consumer hat den Frame zurueckgegeben
    volatile uint32_t rawDropped_;
};

// Globale Instanz, gebunden an den globalen cameraManager (wie server/preferences).
extern CameraStreamService cameraStream;

#endif // CAMERA_STREAM_SERVICE_H
