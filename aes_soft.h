// aes_soft.h -- kompakter Software-AES (FIPS-197) in CBC, unabhaengig von der P4-Hardware-AES/
// Krypto-DMA. Grund: der HW-AES holt fuer grosse CBC-Bloecke DMA-Deskriptoren aus dem internen Heap;
// unter Last (Kamera/H.264/Web) scheitert das mit -1 und verklemmt die Engine (auch der CTR_DRBG-
// Zufall faellt dann aus). Der ESP-Datenpfad des Tunnels rechnet AES deshalb rein in Software.
// Unterstuetzt AES-128/192/256, CBC. len muss ein Vielfaches von 16 sein. in==out (in-place) ok.
#pragma once
#include <stdint.h>
#include <stddef.h>

// enc != 0 = verschluesseln, 0 = entschluesseln. iv wird NICHT zurueckgeschrieben (Kopie intern).
// Rueckgabe 0 = ok, -1 = ungueltige Argumente (klen nicht 16/24/32, len nicht durch 16 teilbar).
int aes_soft_cbc(int enc, const uint8_t* key, size_t klen, const uint8_t iv[16],
                 const uint8_t* in, size_t len, uint8_t* out);
