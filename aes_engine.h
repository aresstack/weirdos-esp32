// aes_engine.h -- EIN AES-CBC-Treiber fuer den IPsec-Tunnel mit umschaltbarem Backend.
//
// Hintergrund: Der ESP-IDF-mbedTLS-AES nutzt fuer grosse CBC-Bloecke die Krypto-DMA und holt dafuer
// Deskriptoren aus dem internen DMA-Heap. Unter Last (Kamera/H.264/Web) scheitert das mit -1 und
// verklemmt die Engine. Dieser Treiber umgeht das:
//   HW_BLOCK : Hardware-AES BLOCKWEISE ueber Register (aes_hal_transform_block), OHNE DMA, ohne Heap.
//              CBC-Verkettung in Software. Hardware-Tempo, kein Heap-/DMA-Risiko. (Vorgabe)
//   SOFT     : reiner Software-AES (aes_soft), voellig ohne Hardware-Block.
//   HW_DMA   : der bisherige mbedTLS-Weg (nur fuer den Vergleich in aesBench).
// Alle drei liefern identische Ergebnisse (gegen NIST-Vektoren geprueft); umschaltbar zur Laufzeit.
#pragma once
#include <Arduino.h>

enum class AesBackend : uint8_t { HW_BLOCK = 0, SOFT = 1, HW_DMA = 2 };

// Aktives Backend fuer aesEngineCbc() (Vorgabe HW_BLOCK). Persistenz macht der Aufrufer (NVS).
void        aesEngineSetBackend(AesBackend b);
AesBackend  aesEngineBackend();
const char* aesBackendName(AesBackend b);

// AES-CBC. enc!=0 = verschluesseln. len Vielfaches von 16, klen 16/24/32. in==out (in-place) ok.
// Rueckgabe 0 = ok, -1 = Fehler. Thread-sicher gegen die mbedTLS/TLS-Nutzung (Hardware-Lock).
int aesEngineCbc(int enc, const uint8_t* key, size_t klen, const uint8_t iv[16],
                 const uint8_t* in, size_t len, uint8_t* out);

// Explizit ein Backend testen (fuer den Bench), unabhaengig vom aktiven.
int aesEngineCbcVia(AesBackend b, int enc, const uint8_t* key, size_t klen, const uint8_t iv[16],
                    const uint8_t* in, size_t len, uint8_t* out);

// Vergleichstest UNTER der aktuellen Last: je Backend N Runden bei `len` Byte; zaehlt Fehler und
// misst die Zeit; nennt den freien internen DMA-Heap. Liefert einen mehrzeiligen Bericht.
String aesBench(int len, int rounds);
