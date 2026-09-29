// ============================================================================
// h264_guard.cpp -- siehe h264_guard.h.
// ============================================================================
#include "h264_guard.h"
#include <Arduino.h>
#include <Preferences.h>
#include <esp_heap_caps.h>
#include <esp_heap_caps_init.h>   // heap_caps_add_region_with_caps
#include <heap_memory_layout.h>   // SOC_MEMORY_TYPE_NO_PRIOS
#include <esp_private/esp_cache_private.h>   // esp_cache_get_alignment (dieselbe Funktion, die die esp_h264-Lib ruft)
#include <esp_cache.h>                       // esp_cache_msync (Cache-Sync-Hook unten)

// EXKLUSIV-CAP der Video-Reserve: MALLOC_CAP_PID2 ("PIDs are not currently used", esp_heap_caps.h).
// Kein anderer Code im System fordert dieses Bit an -> nur unser Allocator-Hook (unten) kann aus
// der Region allozieren. Die Region traegt AUSSCHLIESSLICH dieses Bit (kein INTERNAL/8BIT/DMA),
// sonst wuerde jede passende Fremdanfrage sie mitbenutzen (Prio-0-Variante: beim Boot auf 75 KB
// zerlegt; Prio-1-Variante: jede Anfrage, die im Haupt-Heap nicht passt, weicht hinein).
#define VIDEO_RESERVE_CAP MALLOC_CAP_PID2

static uint8_t* s_region       = nullptr;   // reservierter Block (Besitz bleibt bei uns, nie freigeben)
static size_t   s_regionSize   = 0;
static bool     s_registered   = false;
static size_t   s_bootBytes    = 0;
static size_t   s_regionIdle   = 0;         // groesster freier Block der Region direkt nach Registrierung
static bool     s_serverOff    = false;     // Reserve uebersprungen: Video-Server (HTTP-Stream) aus
static uint32_t s_hookHits     = 0;         // Encoder-Bloecke, die aus der Reserve bedient wurden

static const char* kNs  = "cfg";
static const char* kKey = "h264guardkb";

size_t h264RefBytesForWidth(uint16_t width) {
    return (size_t)1152 * (((size_t)width + 15) / 16);
}

size_t h264GuardAutoBytesForWidth(uint16_t width) {
    if (width == 0) return 0;
    // Referenz-Zeilenpuffer (1152 B je 16 px) + Deblocking-Zwischenpuffer db_tmp (128 B je 16 px + 79 B,
    // esp_h264_enc_hw_max_db_tmp_buffer_size) + DMA-Deskriptoren/NAL-Scratch (je 64 B, ~1 KB) +
    // TLSF-Verwaltung der Region (~4 KB) + Ausrichtungsverschnitt. 12 KB Reserve obendrauf.
    // FHD: 138.304 + 15.488 + 12.288 = 166 KB. Alle internen Encoder-Puffer kommen aus dieser Region
    // (Hook unten) -- sonst landen sie im LP-SRAM (siehe guard-Hook).
    size_t mbw = ((size_t)width + 15) / 16;
    return h264RefBytesForWidth(width) + (mbw * 128 + 79 + 64) + 12 * 1024;
}

int h264GuardConfiguredKb() {
    Preferences p;
    p.begin(kNs, true);
    int kb = p.getInt(kKey, H264_GUARD_AUTO);
    p.end();
    if (kb < H264_GUARD_AUTO) kb = H264_GUARD_AUTO;
    if (kb > 400) kb = 400;
    return kb;
}

void h264GuardSetConfiguredKb(int kb) {
    if (kb < H264_GUARD_AUTO) kb = H264_GUARD_AUTO;
    if (kb > 400) kb = 400;
    Preferences p;
    p.begin(kNs, false);
    p.putInt(kKey, kb);
    p.end();
}

void h264GuardBootReserve(size_t autoBytes, bool videoServerOn) {
    int kb = h264GuardConfiguredKb();
    if (!videoServerOn) {
        // Ohne HTTP-Stream-Server gibt es keinen H.264-Endpunkt -> keinen internen Speicher binden.
        // Gleiches Prinzip wie beim WLAN-Stack: Einschalten wirkt ab dem naechsten Neustart.
        s_serverOff = true; s_bootBytes = 0;
        Serial.println("[H264Guard] Video-Server (HTTP-Stream) aus -> keine Video-Reserve (Aenderung wirkt ab Neustart)");
        return;
    }
    if (kb == H264_GUARD_AUTO)  s_bootBytes = autoBytes;
    else if (kb > 0)            s_bootBytes = (size_t)kb * 1024;
    else                        s_bootBytes = 0;
    Serial.printf("[H264Guard] Modus %s -> %u KB\n",
                  kb == H264_GUARD_AUTO ? "automatisch (groesster Kamera-Modus)" : (kb > 0 ? "manuell" : "aus"),
                  (unsigned)(s_bootBytes / 1024));
    if (s_bootBytes == 0) return;

    // Block aus dem internen, DMA-faehigen Heap holen -- und BEHALTEN. Er wird nie mehr an den
    // Haupt-Heap zurueckgegeben, sondern als eigene, exklusive Region registriert.
    s_region = (uint8_t*)heap_caps_aligned_alloc(64, s_bootBytes, MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA | MALLOC_CAP_8BIT);
    if (!s_region) {
        Serial.printf("[H264Guard] reserve %uKB internal -> FEHLGESCHLAGEN (groesster interner Block %uKB)\n",
                      (unsigned)(s_bootBytes / 1024),
                      (unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) / 1024));
        s_bootBytes = 0;
        return;
    }
    s_regionSize = s_bootBytes;

    // Als Heap-Region registrieren (Sub-Region eines bestehenden Heaps ist laut IDF erlaubt, nur
    // Ueberlappung mit Anfang/Ende einer Region nicht). Caps = NUR das Exklusiv-Bit: kein anderer
    // Aufrufer im System kann hier landen, weder plain malloc noch heap_caps_malloc(INTERNAL|DMA).
    // Warum ueberhaupt eine Region und nicht der rohe Block? Der Encoder gibt seine Puffer mit
    // heap_caps_free() zurueck -- das findet den umgebenden Heap (= unsere Region) und legt den
    // Block dort wieder ab. So bleibt die Reserve ueber beliebig viele Streams exklusiv und ganz.
    uint32_t caps[SOC_MEMORY_TYPE_NO_PRIOS] = { VIDEO_RESERVE_CAP, 0, 0 };
    esp_err_t e = heap_caps_add_region_with_caps(caps, (intptr_t)s_region, (intptr_t)(s_region + s_regionSize));
    s_registered = (e == ESP_OK);
    s_regionIdle = s_registered ? heap_caps_get_largest_free_block(VIDEO_RESERVE_CAP) : 0;
    Serial.printf("[H264Guard] Video-Reserve %uKB @%p exklusiv registriert -> %s (nutzbar %uKB, Haupt-Heap groesster Block %uKB)\n",
                  (unsigned)(s_regionSize / 1024), s_region, esp_err_to_name(e),
                  (unsigned)(s_regionIdle / 1024),
                  (unsigned)(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) / 1024));
    if (!s_registered) {
        // Registrierung abgelehnt -> Block zurueckgeben, kein Guard (ehrlich: FHD dann nur, wenn der
        // Haupt-Heap es hergibt). Kein Absturzrisiko.
        heap_caps_free(s_region);
        s_region = nullptr; s_regionSize = 0; s_bootBytes = 0;
    }
}

bool   h264GuardHeld()      { return s_registered; }
size_t h264GuardBytes()     { return s_registered ? s_regionSize : 0; }
size_t h264GuardBootBytes() { return s_bootBytes; }
bool   h264GuardSkippedServerOff() { return s_serverOff; }
size_t h264GuardRegionLargest()    { return s_registered ? heap_caps_get_largest_free_block(VIDEO_RESERVE_CAP) : 0; }
uint32_t h264GuardHookHits()       { return s_hookHits; }

size_t h264GuardEffectiveLargest(size_t activeRefBytes) {
    size_t mainLargest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    if (!s_registered) return mainLargest + activeRefBytes;
    // Laeuft ein Stream, liegt sein Referenzpuffer in der Reserve -> beim Wechsel wird sie wieder
    // ganz frei (Leerlaufwert). Sonst der aktuell groesste freie Block der Region.
    size_t regionAvail = activeRefBytes ? s_regionIdle : heap_caps_get_largest_free_block(VIDEO_RESERVE_CAP);
    return regionAvail > mainLargest ? regionAvail : mainLargest;
}

// ============================================================================
// Allocator-Hook fuer esp_h264 (libespressif__esp_h264.a).
//
// Das Archiv-Objekt esp_h264_alloc.c.obj definiert GENAU diese zwei Funktionen (nm-geprueft) und
// alle Encoder-Objekte rufen sie fuer ihre Puffer. Weil unsere Sketch-Objekte vor dem Archiv
// gelinkt werden und die Symbole bereits definieren, zieht der Linker das Archiv-Objekt nicht --
// kein Doppel-Symbol, kein --wrap noetig. esp_h264_free ist ein Makro auf heap_caps_free.
//
// Original (Disassembly): actual = ALIGN_UP(n*size, cache_align(caps)); ptr = heap_caps_aligned_
// calloc(alignment, 1, actual, caps | MALLOC_CAP_CACHE_ALIGNED); wenn ptr: cache_writeback.
// Hier: grosse INTERNAL-Anfragen (>= 16 KB, d.h. Referenz-/Rekonstruktionspuffer) zuerst aus
// der exklusiven Video-Reserve; passt es nicht (Reserve aus/zu klein/belegt) -> Original-Pfad.
// ============================================================================
// ---- Cache-Sync-Hook der esp_h264-Lib (esp_h264_cache.c.obj definiert GENAU diese zwei Symbole,
// nm-geprueft) -- ebenfalls im Sketch ersetzt. Grund: die Lib IGNORIERT den Rueckgabewert von
// esp_cache_msync. Das serielle Log zeigt "E cache: esp_cache_msync(113): invalid addr or null
// pointer" -- scheitert dort z.B. das Invalidate des NAL-Ausgabepuffers, liest die CPU veraltete
// Cache-Zeilen (Bitstream vom vorigen Frame) -> korrupter NAL -> Decoder-Drift bis zum IDR, ohne
// dass encode() einen Fehler meldet. Hier: gleiche Aufrufe wie im Original, aber Fehler werden mit
// Adresse/Laenge/Richtung geloggt (erste 10). Faellt die Zeile OHNE unseren Eintrag, kommt sie aus
// esp_video/JPEG/PPA (die rufen esp_cache_msync direkt).
static uint32_t s_cacheErrs = 0;
static void guardCacheLog(const char* what, void* addr, uint32_t len, esp_err_t e) {
    if (++s_cacheErrs > 10) return;
    Serial.printf("[H264] cache-%s FEHLER %s: addr=%p len=%u (esp_h264-Lib ignoriert das; Bitstream/Puffer inkonsistent)\n",
                  what, esp_err_to_name(e), addr, (unsigned)len);
}
extern "C" void esp_h264_cache_check_and_writeback(void* addr, uint32_t length) {
    esp_err_t e = esp_cache_msync(addr, length, ESP_CACHE_MSYNC_FLAG_DIR_C2M | ESP_CACHE_MSYNC_FLAG_UNALIGNED);
    if (e != ESP_OK) guardCacheLog("writeback", addr, length, e);
}
extern "C" void esp_h264_cache_check_and_invalidate(void* addr, uint32_t length) {
    esp_err_t e = esp_cache_msync(addr, length, ESP_CACHE_MSYNC_FLAG_DIR_M2C);
    if (e != ESP_OK) guardCacheLog("invalidate", addr, length, e);
}
uint32_t h264GuardCacheErrors() { return s_cacheErrs; }

extern "C" void* esp_h264_aligned_calloc(uint32_t alignment, uint32_t n, uint32_t size,
                                         uint32_t* actual_size, uint32_t caps) {
    size_t cacheAlign = 0;
    if (esp_cache_get_alignment(caps, &cacheAlign) != ESP_OK || cacheAlign == 0) cacheAlign = 1;
    uint32_t bytes = n * size;
    uint32_t actual = (uint32_t)(((size_t)bytes + cacheAlign - 1) & ~(cacheAlign - 1));
    if (actual_size) *actual_size = actual;
    uint32_t align = alignment > cacheAlign ? alignment : (uint32_t)cacheAlign;
    if (align == 0) align = 1;

    void* ptr = nullptr;
    // ALLE internen Encoder-Puffer zuerst aus der Reserve (nicht nur den grossen Referenz-Zeilen-
    // puffer): auch der Deblocking-Zwischenpuffer (db_tmp, ~128 B je 16 px Breite, FHD 15,5 KB) und
    // die DMA-Deskriptoren muessen in DMA-faehigem, cache-syncbarem SRAM liegen.
    if (s_registered && (caps & MALLOC_CAP_INTERNAL)) {
        ptr = heap_caps_aligned_calloc(align, 1, actual, VIDEO_RESERVE_CAP);
        if (ptr) s_hookHits++;
    }
    if (!ptr) {
        // HARDWARE-BEWIESEN (Log 03.09.2026): Fiel der Haupt-Heap fuer eine INTERNAL-Anfrage aus, gab
        // heap_caps den naechsten Heap mit INTERNAL-Cap -- das LP-SRAM (0x5010xxxx, RTC-Speicher).
        // Das ist weder cache-syncbar ("E cache: esp_cache_msync(113): invalid addr", vom Encoder-
        // Writeback des db_tmp @0x501083c0/15488 B) noch fuer die H.264-DMA erreichbar -> der Encoder
        // rekonstruiert sein Referenzbild falsch: Keyframes ok, jeder P-Frame driftet rosa bis zum
        // naechsten IDR, ohne Encode-Fehler. Daher: INTERNAL immer mit MALLOC_CAP_DMA -> LP-SRAM ist
        // ausgeschlossen; passt es nirgends, scheitert hw_new ehrlich (503) statt still zu korrumpieren.
        uint32_t c = caps | MALLOC_CAP_CACHE_ALIGNED;
        if (caps & MALLOC_CAP_INTERNAL) c |= MALLOC_CAP_DMA;
        ptr = heap_caps_aligned_calloc(alignment, 1, actual, c);
    }
    if (ptr) esp_h264_cache_check_and_writeback(ptr, actual);
    return ptr;
}

extern "C" void* esp_h264_calloc_prefer(uint32_t n, uint32_t size, uint32_t* actual_size,
                                        uint32_t caps1, uint32_t caps2) {
    void* ptr = esp_h264_aligned_calloc(4, n, size, actual_size, caps1);
    if (!ptr) ptr = esp_h264_aligned_calloc(4, n, size, actual_size, caps2);
    return ptr;
}
