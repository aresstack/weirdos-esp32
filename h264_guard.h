// ============================================================================
// h264_guard.h -- Boot-Reserve fuer den H.264-Referenzpuffer ("Guard") als EIGENE HEAP-REGION.
//
// PROBLEM: der HW-Encoder (esp_h264_enc_hw) braucht seinen Referenzpuffer aus
// ZUSAMMENHAENGENDEM internem RAM (~1152 Byte je 16 Pixel Breite: 800 -> ~56 KB,
// 1280 -> ~90 KB, 1920 -> ~135 KB). PSRAM zaehlt dafuer nicht. Direkt nach der
// Kamera-Initialisierung ist der groesste freie interne Block noch gross (P4 gemessen
// ~231 KB); USB-Host, Netz, Webserver, PPP-Link, DynDNS-TLS und HTTP-Sitzungen
// zerstueckeln ihn danach auf ~60 KB -- FHD passt dann nicht mehr.
//
// LOESUNG (v3, EXKLUSIVE VIDEO-RESERVE): frueh in setup() -- nur wenn der Video-Server (HTTP-
// Stream) aktiv ist, wie beim WLAN-Stack ab Neustart -- einen Block reservieren und ihn als
// eigene Heap-Region registrieren, deren EINZIGES Cap-Bit MALLOC_CAP_PID2 ist ("PIDs are not
// currently used"). Kein anderer Code fordert dieses Bit an -> niemand ausser uns kann aus der
// Region allozieren; sie bleibt ueber beliebig viele Streams ganz. Der Weg hinein ist der
// Allocator-Hook in h264_guard.cpp: esp_h264_aligned_calloc/_calloc_prefer der esp_h264-Lib
// werden durch eigene Definitionen ersetzt (Archiv-Objekt wird dann nicht gelinkt); grosse
// interne Encoder-Puffer kommen aus der Reserve, alles andere geht den Originalweg. Freigabe
// (heap_caps_free) findet die Region als umgebenden Heap und legt den Block dort wieder ab.
// Vorherige Versuche: v1 (freigeben/zurueckholen) scheiterte an Kleinkram im Block nach dem
// Stream; v2 (Region mit INTERNAL-Caps) wurde vom USB-Host/Netz/Webserver beim Boot aufgebraucht
// (143 -> 75 KB) bzw. haette mit Prio 1 jede Ueberlauf-Anfrage aufgenommen. MJPEG braucht KEINE
// interne Reserve (Bildpuffer im PSRAM, gemeinsam ueber den Verteiler) -- die Reserve ist damit
// die eine Video-Reserve des Systems, genutzt vom jeweils laufenden Encoder.
// v1 (Block freigeben, Encoder alloziert, danach zurueckholen) scheiterte daran, dass beim
// Stream-Ende Kleinkram in der Region lag (z.B. TCP-PCB im TIME_WAIT) -> Rueckholen schlug
// fehl -> naechster Stream ohne Reserve -> 503 und schrumpfende Aufloesungsliste.
//
// WARUM DIE RESERVE ALLE INTERNEN ENCODER-PUFFER TRAGEN MUSS (hardware-bewiesen 03.09.2026): fiel
// eine kleine INTERNAL-Anfrage der Lib (Deblocking-Zwischenpuffer db_tmp, FHD 15,5 KB) im Haupt-
// Heap durch, gab heap_caps das LP-SRAM (0x5010xxxx, RTC) -- nicht cache-syncbar, nicht DMA-
// erreichbar -> Referenzbild des Encoders korrupt -> rosa P-Frame-Drift bis zum IDR, ohne
// Encode-Fehler. Der Hook nimmt deshalb jede INTERNAL-Anfrage zuerst aus der Reserve und
// verlangt sonst INTERNAL|DMA (LP-SRAM ausgeschlossen).
//
// Groesse: NVS "cfg"/"h264guardkb": -1 = AUTOMATISCH (Default: Referenzpuffer des groessten
// vom Kamera-Backend gemeldeten Modus + Reserve fuer die Heap-Verwaltung), 0 = aus, >0 = KB.
// Einstellbar unter Server > Video > Stream bzw. /h264guard?bootkb=N, wirkt ab dem Boot.
// TRADE-OFF: was die Region haelt, fehlt den anderen Diensten dauerhaft.
// ============================================================================
#ifndef H264_GUARD_H
#define H264_GUARD_H

#include <stddef.h>
#include <stdint.h>

// Referenzpuffer-Bedarf des HW-Encoders fuer eine Zielbreite (~1152 Byte je 16 Pixel).
size_t h264RefBytesForWidth(uint16_t width);
// Guard-Auto-Groesse: Referenzpuffer + Reserve fuer Allocator-Header/Ausrichtung/Heap-Verwaltung.
size_t h264GuardAutoBytesForWidth(uint16_t width);

// In setup() nach der Kamera-Initialisierung aufrufen: liest NVS, reserviert und registriert die
// Region. autoBytes = Groesse fuer "Automatisch" (Aufrufer: groesster Kamera-Modus).
// videoServerOn = HTTP-Stream-Server aktiv (streamEnabled); false -> keine Region (Log + UI-Hinweis).
void   h264GuardBootReserve(size_t autoBytes, bool videoServerOn);

#define H264_GUARD_AUTO (-1)
int    h264GuardConfiguredKb();
void   h264GuardSetConfiguredKb(int kb);   // -1..400

bool   h264GuardHeld();            // Region registriert?
size_t h264GuardBytes();           // Groesse der Region (0 wenn keine)
size_t h264GuardBootBytes();       // beim Boot angeforderte Groesse
bool   h264GuardSkippedServerOff(); // beim Boot uebersprungen, weil der Video-Server (HTTP-Stream) aus war
size_t h264GuardRegionLargest();    // groesster freier Block IN der Reserve (0 ohne Region)
uint32_t h264GuardHookHits();       // Encoder-Puffer, die bisher aus der Reserve bedient wurden
uint32_t h264GuardCacheErrors();    // esp_cache_msync-Fehler in den Cache-Sync-Aufrufen der esp_h264-Lib

// Fuer die Verfuegbarkeitsrechnung (Aufloesungsliste): groesster zusammenhaengender interner
// Block, den ein NEUER Encoder bekommen koennte = max(Haupt-Heap, Reserve). Die Reserve traegt
// nur das Exklusiv-Cap, heap_caps_get_largest_free_block(INTERNAL) sieht sie NICHT -> hier
// explizit dazugerechnet; ein laufender Stream belegt die Reserve, wird beim Wechsel aber frei.
size_t h264GuardEffectiveLargest(size_t activeRefBytes);

#endif // H264_GUARD_H
