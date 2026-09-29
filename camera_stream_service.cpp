// ============================================================================
// camera_stream_service.cpp
//
// Bildet den bewaehrten Verteiler aus dem Sketch nach (gemeinsamer PSRAM-Puffer,
// Capture-Task laeuft nur solange Clients da sind, Pacing auf Ziel-fps), aber
// ueber CameraManager::acquireFrame()/releaseFrame() statt esp_camera direkt.
// ============================================================================
#include "camera_stream_service.h"
#include "camera_manager.h"   // globale FrameSource-Instanz cameraManager
#include "camera_frame.h"     // CameraFrame (Zugriff auf Felder im captureLoop)

#include <Arduino.h>          // String (fuer die logEvent-Deklaration/-Nutzung)
#include <esp_heap_caps.h>
#include <esp_timer.h>
#include <cstring>

void logEvent(const String& text);   // App-Ereignis-Ringpuffer (Def. in der .ino), auch ohne Serial sichtbar

CameraStreamService cameraStream(cameraManager);

CameraStreamService::CameraStreamService(FrameSource& source)
    : src_(source),
      mutex_(nullptr),
      buf_(nullptr),
      cap_(0),
      len_(0),
      seq_(0),
      clients_(0),
      taskRunning_(false),
      targetFps_(10),
      dropStale_(true),
      jpegAcks_(0),
      rawClients_(0),
      rawFrame_(nullptr),
      rawSeq_(0),
      rawReturned_(false),
      rawDropped_(0) {}

void CameraStreamService::setDropStale(bool on) { dropStale_ = on; }
bool CameraStreamService::dropStale() const      { return dropStale_; }

void CameraStreamService::addRawClient()    { rawClients_++; addClient(); }
void CameraStreamService::removeRawClient() {
    rawReturned_ = true;          // ggf. noch ausgeliehenen Frame freigeben lassen
    if (rawClients_ > 0) rawClients_--;
    removeClient();
}
uint32_t CameraStreamService::rawSequence() const { return rawSeq_; }
uint32_t CameraStreamService::rawDropped()  const { return rawDropped_; }

const CameraFrame* CameraStreamService::rawBorrowLatest(uint32_t* seq) {
    if (!rawFrame_ || rawReturned_) return nullptr;
    if (seq && *seq == rawSeq_) return nullptr;   // nicht neuer
    if (seq) *seq = rawSeq_;
    return rawFrame_;
}
void CameraStreamService::rawReturn() { rawReturned_ = true; }

void CameraStreamService::begin() {
    if (!mutex_) mutex_ = xSemaphoreCreateMutex();
}

void CameraStreamService::setTargetFps(int fps) {
    targetFps_ = (fps < 1) ? 1 : fps;
}

int CameraStreamService::clientCount() const { return clients_; }

uint32_t CameraStreamService::latestSequence() const { return seq_; }

size_t CameraStreamService::latestLen() const { return len_; }

void CameraStreamService::addClient() {
    // clients_++ UND die Start-Entscheidung atomar unter mutex_ (captureLoop trifft die
    // Ende-Entscheidung unter demselben Lock) -> kein 0->1-Race, bei dem der alte Task
    // gerade endet, der neue Client taskRunning_=true sieht und KEINEN Task startet.
    bool needStart = false;
    if (mutex_ && xSemaphoreTake(mutex_, portMAX_DELAY) == pdTRUE) {
        clients_++;
        if (!taskRunning_) { taskRunning_ = true; needStart = true; }
        xSemaphoreGive(mutex_);
    } else {
        clients_++;
        if (!taskRunning_) { taskRunning_ = true; needStart = true; }
    }
    if (needStart) {   // Task-Erzeugung ausserhalb des Locks
        BaseType_t ok = xTaskCreatePinnedToCore(captureTrampoline, "cam_cap", 4096, this, 5, nullptr, 1);
        if (ok != pdPASS) {
            // Task NICHT erzeugt -> taskRunning_ unter Lock zuruecknehmen, sonst bliebe
            // clients_>0/taskRunning_=true ohne Task haengen (tot bis Reset). Die aktuell
            // wartenden Clients laufen nach ~5s in ihren "keine Frames"-Timeout + removeClient;
            // weil taskRunning_ jetzt wieder false ist, startet die NAECHSTE Verbindung sauber.
            logEvent(String("Kamera-Stream: Capture-Task-Erzeugung FEHLGESCHLAGEN (intern frei ")
                + String((unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024)) + "k groesster "
                + String((unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) / 1024)) + "k)");
            if (mutex_ && xSemaphoreTake(mutex_, portMAX_DELAY) == pdTRUE) {
                taskRunning_ = false;
                xSemaphoreGive(mutex_);
            } else {
                taskRunning_ = false;
            }
        }
    }
}

void CameraStreamService::removeClient() {
    if (mutex_ && xSemaphoreTake(mutex_, portMAX_DELAY) == pdTRUE) {
        if (clients_ > 0) clients_--;
        xSemaphoreGive(mutex_);
    } else {
        if (clients_ > 0) clients_--;
    }
}

void CameraStreamService::captureTrampoline(void* arg) {
    static_cast<CameraStreamService*>(arg)->captureLoop();
}

void CameraStreamService::captureLoop() {
    bool distReallocFailLogged = false;   // pro Stream-Session einmal loggen (kein Flut-Log)
    bool nonJpegLogged = false;           // Nicht-JPEG-Frame -> einmal diagnostizieren, nicht lautlos
    for (;;) {
        // Ende-Entscheidung race-frei unter mutex_ (derselbe Lock wie addClient): nur beenden,
        // wenn wirklich kein Client mehr da ist. Schliesst das Fenster "clients_>0 aber kein Task".
        bool stop = false;
        if (mutex_ && xSemaphoreTake(mutex_, portMAX_DELAY) == pdTRUE) {
            if (clients_ == 0) {
                // Roh-Ausleihe VOR der Slot-Freigabe zurueckgeben (unter demselben Lock; ein neuer
                // Capture-Task startet erst danach): sonst bleibt der V4L2-Puffer bis zur naechsten
                // Session ausgecheckt und setMode() (Rueckschalten am H.264-Ende) laeuft in den Timeout.
                if (rawFrame_) { src_.releaseFrame(rawFrame_); rawFrame_ = nullptr; rawReturned_ = true; }
                taskRunning_ = false; stop = true;
            }
            xSemaphoreGive(mutex_);
        } else if (clients_ == 0) {
            if (rawFrame_) { src_.releaseFrame(rawFrame_); rawFrame_ = nullptr; rawReturned_ = true; }
            taskRunning_ = false; stop = true;
        }
        if (stop) break;

        int fps = targetFps_ > 0 ? targetFps_ : 1;
        int32_t intervalMs = 1000 / fps;
        int64_t started = esp_timer_get_time();

        // ---- Roh-Kanal (Encoder-Consumer aktiv): zero-copy, eine Ausleihe, gleiche Politik ----
        if (rawClients_ > 0) {
            if (rawFrame_ && !rawReturned_) {          // Consumer arbeitet noch am Frame
                vTaskDelay(pdMS_TO_TICKS(2));
                continue;
            }
            if (rawFrame_) {                           // zurueckgegeben -> Treiber-Puffer frei
                src_.releaseFrame(rawFrame_);
                rawFrame_ = nullptr;
                // KEIN Verwerfen im Roh-Kanal (dropStale_ gilt nur fuer den JPEG-Kanal). Hardware-
                // bewiesen (03.09.2026): mit dem frueheren Ringpuffer-Drain (bis 4x DQBUF/QBUF vor dem
                // naechsten Frame) hatte H.264 in Folgesitzungen rosa driftende P-Frames bis zum
                // naechsten Keyframe; Haken raus -> sauber. Der HW-Encoder braucht aufeinander folgende
                // Frames (Referenz = Vorgaenger); Ausduennen verdoppelt die Bewegung je P-Frame -- genau
                // die "motion-dependent P-frame corruption" aus esp-h264-component Issue #21. Der V4L2-
                // Ring hat ohnehin nur 2 Puffer: der naechste DQBUF ist hoechstens einen Sensor-Frame
                // (33 ms) alt, ein Drain spart nichts. Die Bildrate taktet weiter dieser Task.
            }
            CameraFrame* r = src_.acquireRawFrame();
            if (r) { rawFrame_ = r; rawReturned_ = false; rawSeq_++; }
            // Pacing auf die Ziel-Bildrate (wie beim JPEG-Kanal); min. 5 ms.
            int32_t el = (int32_t)((esp_timer_get_time() - started) / 1000);
            int32_t wt = intervalMs - el;
            if (wt < 5) wt = 5;
            vTaskDelay(pdMS_TO_TICKS(wt));
            continue;
        }
        if (rawFrame_) { src_.releaseFrame(rawFrame_); rawFrame_ = nullptr; }   // Roh-Consumer weg

        // ---- JPEG-Kanal (MJPEG-Clients) -- unveraendertes Verhalten bei dropStale (Default) ----
        // !dropStale: naechsten Frame erst veroeffentlichen, wenn alle Consumer den aktuellen haben.
        if (!dropStale_ && seq_ > 0 && jpegAcks_ < clients_) {
            vTaskDelay(pdMS_TO_TICKS(5));
            continue;
        }

        CameraFrame* f = src_.acquireFrame();
        if (f) {
            if (f->pixelFormat == CAMERA_PIXEL_FORMAT_JPEG && mutex_ &&
                xSemaphoreTake(mutex_, pdMS_TO_TICKS(200)) == pdTRUE) {

                if (f->size > cap_) {
                    uint8_t* grown = (uint8_t*)heap_caps_realloc(buf_, f->size, MALLOC_CAP_SPIRAM);
                    if (grown) {
                        buf_ = grown; cap_ = f->size;
                        distReallocFailLogged = false;   // Erholung -> Fehler darf wieder geloggt werden
                    } else if (!distReallocFailLogged) {
                        // DIAGNOSE: Verteiler-Puffer konnte nicht wachsen -> Frame wird nie kopiert,
                        // seq_ steht -> ALLE Clients schwarz. Genau der "kein Bild"-Pfad.
                        distReallocFailLogged = true;
                        logEvent(String("Kamera-Stream: Verteiler-realloc FEHLGESCHLAGEN, brauche ")
                            + String((unsigned)(f->size / 1024)) + "k, PSRAM groesster "
                            + String((unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM) / 1024))
                            + "k / frei "
                            + String((unsigned)(heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024)) + "k");
                    }
                }
                if (f->size <= cap_) {
                    memcpy(buf_, f->data, f->size);
                    len_ = f->size;
                    seq_++;
                    jpegAcks_ = 0;   // neuer Frame -> Abholungen zaehlen von vorn (nur bei !dropStale relevant)
                }
                xSemaphoreGive(mutex_);
            } else if (f->pixelFormat != CAMERA_PIXEL_FORMAT_JPEG && !nonJpegLogged) {
                // DIAGNOSE: Nicht-JPEG-Frame -> wird verworfen, seq_ steht -> Stream schwarz.
                // Genau der RAW-Fallback-Pfad (frueher lautlos). Gedrosselt: einmal pro Session.
                nonJpegLogged = true;
                logEvent(String("Kamera-Stream: Nicht-JPEG-Frame (fmt=") + (int)f->pixelFormat
                    + ", " + String((unsigned)(f->size / 1024)) + "k) verworfen -> JPEG-Encoder-Pfad down?");
            }
            src_.releaseFrame(f);
        }

        // Pacing auf die Ziel-Bildrate; min. 5 ms verhindert Aushungern des
        // Kamera-Tasks/JPEG-Encoders (bekannte OV3660-Frame-Timeouts).
        int32_t elapsedMs = (int32_t)((esp_timer_get_time() - started) / 1000);
        int32_t waitMs = intervalMs - elapsedMs;
        if (waitMs < 5) waitMs = 5;
        vTaskDelay(pdMS_TO_TICKS(waitMs));
    }
    // taskRunning_ wurde bereits race-frei unter mutex_ (oben) auf false gesetzt.
    vTaskDelete(nullptr);
}

size_t CameraStreamService::copyLatest(uint8_t** dst, size_t* cap, uint32_t* seq) {
    static bool s_growFailLogged = false;   // gedrosselt: echte PSRAM-Erschoepfung ist selten
    size_t out = 0;
    if (!mutex_ || !dst || !cap) return 0;
    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(200)) == pdTRUE) {
        // Groessenpruefung, Wachstum UND Kopie unter EINEM Lock -> len_ kann sich zwischen
        // Pruefung und memcpy nicht mehr aendern (kein TOCTOU-Wettlauf wie beim frueheren
        // latestLen()-Snapshot + separatem realloc).
        if (len_ > 0 && (seq == nullptr || *seq != seq_)) {
            if (len_ > *cap) {
                uint8_t* grown = (uint8_t*)heap_caps_realloc(*dst, len_, MALLOC_CAP_SPIRAM);
                if (grown) { *dst = grown; *cap = len_; s_growFailLogged = false; }
            }
            if (len_ <= *cap) {
                memcpy(*dst, buf_, len_);
                out = len_;
                if (seq) *seq = seq_;
                jpegAcks_++;   // dieser Consumer hat den aktuellen Frame (Rueckstau-Politik bei !dropStale)
            } else if (!s_growFailLogged) {
                // Nur hier landet man noch, wenn der PSRAM WIRKLICH keinen zusammenhaengenden
                // Block der Frame-Groesse mehr hergibt (echte Erschoepfung/Fragmentierung).
                s_growFailLogged = true;
                logEvent(String("Kamera-Stream: Client-Puffer-Wachstum FEHLGESCHLAGEN, brauche ")
                    + String((unsigned)(len_ / 1024)) + "k, PSRAM groesster "
                    + String((unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM) / 1024))
                    + "k / frei "
                    + String((unsigned)(heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024)) + "k");
            }
        }
        xSemaphoreGive(mutex_);
    }
    return out;
}
