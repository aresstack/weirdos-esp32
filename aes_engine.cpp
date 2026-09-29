// aes_engine.cpp -- siehe aes_engine.h.
#include "weirdos_features.h"      // WEIRDOS_FEATURE_CRYPTO_AES -- der Schalter dieses Bausteins
#include "aes_engine.h"   // Header bleibt UNVERAENDERT (Konsumenten kompilieren weiter)
#if WEIRDOS_FEATURE_CRYPTO_AES
// ============================================================================
// Echte Implementierung (WEIRDOS_FEATURE_CRYPTO_AES=1)
// ============================================================================
#include "aes_soft.h"
#include <esp_heap_caps.h>

extern "C" {
#include "aes/esp_aes.h"     // esp_aes_acquire_hardware / _release_hardware (Takt + globaler Lock)
#include "hal/aes_hal.h"     // aes_hal_setkey / aes_hal_transform_block (Register-Blockmodus, KEINE DMA)
#include "hal/aes_types.h"   // ESP_AES_ENCRYPT / ESP_AES_DECRYPT / AES_BLOCK_BYTES
}
#include <mbedtls/aes.h>     // HW_DMA-Vergleich

static AesBackend s_backend = AesBackend::HW_BLOCK;

void        aesEngineSetBackend(AesBackend b) { s_backend = b; }
AesBackend  aesEngineBackend() { return s_backend; }
const char* aesBackendName(AesBackend b) {
    switch (b) { case AesBackend::HW_BLOCK: return "hw-block (Register, ohne DMA)";
                 case AesBackend::SOFT:     return "software";
                 default:                   return "hw-dma (mbedTLS)"; }
}

// Hardware-AES BLOCKWEISE ueber Register: pro 16-B-Block aes_hal_transform_block (ECB), CBC-Kette in
// Software. Kein DMA, kein Heap. Der Hardware-Lock (acquire/release) serialisiert gegen TLS.
static int hwBlockCbc(int enc, const uint8_t* key, size_t klen, const uint8_t iv[16],
                      const uint8_t* in, size_t len, uint8_t* out) {
    if ((klen != 16 && klen != 24 && klen != 32) || (len % AES_BLOCK_BYTES) != 0) return -1;
    esp_aes_acquire_hardware();
    aes_hal_setkey(key, klen, enc ? ESP_AES_ENCRYPT : ESP_AES_DECRYPT);
    uint8_t chain[16]; memcpy(chain, iv, 16);
    uint8_t blk[16];
    for (size_t off = 0; off < len; off += 16) {
        if (enc) {
            for (int i = 0; i < 16; i++) blk[i] = in[off + i] ^ chain[i];   // P xor C_{i-1}
            aes_hal_transform_block(blk, blk);                              // ECB-Enc
            memcpy(out + off, blk, 16);
            memcpy(chain, blk, 16);                                        // C_i
        } else {
            uint8_t cin[16]; memcpy(cin, in + off, 16);                    // in==out sicher
            aes_hal_transform_block(cin, blk);                            // ECB-Dec
            for (int i = 0; i < 16; i++) out[off + i] = blk[i] ^ chain[i];
            memcpy(chain, cin, 16);
        }
    }
    esp_aes_release_hardware();
    return 0;
}

// bisheriger mbedTLS-Weg (Krypto-DMA) -- nur fuer den Bench-Vergleich.
static int hwDmaCbc(int enc, const uint8_t* key, size_t klen, const uint8_t iv[16],
                    const uint8_t* in, size_t len, uint8_t* out) {
    mbedtls_aes_context a; mbedtls_aes_init(&a);
    uint8_t iv2[16]; memcpy(iv2, iv, 16);
    int rc = enc ? mbedtls_aes_setkey_enc(&a, key, (unsigned)klen * 8)
                 : mbedtls_aes_setkey_dec(&a, key, (unsigned)klen * 8);
    if (rc == 0) rc = mbedtls_aes_crypt_cbc(&a, enc ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, len, iv2, in, out);
    mbedtls_aes_free(&a);
    return rc == 0 ? 0 : -1;
}

int aesEngineCbcVia(AesBackend b, int enc, const uint8_t* key, size_t klen, const uint8_t iv[16],
                    const uint8_t* in, size_t len, uint8_t* out) {
    switch (b) {
        case AesBackend::HW_BLOCK: return hwBlockCbc(enc, key, klen, iv, in, len, out);
        case AesBackend::SOFT:     return aes_soft_cbc(enc, key, klen, iv, in, len, out);
        default:                   return hwDmaCbc(enc, key, klen, iv, in, len, out);
    }
}

int aesEngineCbc(int enc, const uint8_t* key, size_t klen, const uint8_t iv[16],
                 const uint8_t* in, size_t len, uint8_t* out) {
    int rc = aesEngineCbcVia(s_backend, enc, key, klen, iv, in, len, out);
    // Robustheit: faellt das Hardware-Backend aus (z.B. Lock-/Zustandsproblem), NICHT den Tunnel
    // abreissen -> transparent auf Software zurueckfallen (Ergebnis identisch).
    if (rc != 0 && s_backend != AesBackend::SOFT)
        rc = aes_soft_cbc(enc, key, klen, iv, in, len, out);
    return rc;
}

String aesBench(int len, int rounds) {
    if (len < 16) len = 1408; if (len % 16) len += 16 - (len % 16);
    if (rounds < 1) rounds = 100;
    static uint8_t inb[1616], outb[1616], ref[1616];
    for (int i = 0; i < len; i++) inb[i] = (uint8_t)(i * 7 + 1);
    uint8_t key[32]; for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);
    uint8_t iv[16];  for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(0xA0 + i);
    aes_soft_cbc(1, key, 32, iv, inb, len, ref);   // Referenz (korrekt, gegen NIST geprueft)
    String r = String("aesbench len=") + len + " rounds=" + rounds + "\r\n";
    const AesBackend order[3] = { AesBackend::HW_BLOCK, AesBackend::HW_DMA, AesBackend::SOFT };
    for (int k = 0; k < 3; k++) {
        int fail = 0, wrong = 0; uint32_t t0 = micros();
        for (int i = 0; i < rounds; i++) {
            if (aesEngineCbcVia(order[k], 1, key, 32, iv, inb, len, outb) != 0) fail++;
            else if (memcmp(outb, ref, len) != 0) wrong++;
        }
        uint32_t us = micros() - t0;
        size_t dmaFree = heap_caps_get_free_size(MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
        size_t dmaBig  = heap_caps_get_largest_free_block(MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
        r += String("  ") + aesBackendName(order[k]) + ": fail=" + fail + " falsch=" + wrong
           + "  " + (us / (uint32_t)rounds) + " us/op  DMA-Heap frei=" + (unsigned)(dmaFree / 1024) + "k groesster=" + (unsigned)(dmaBig / 1024) + "k\r\n";
    }
    return r;
}
#else
// Stub (WEIRDOS_FEATURE_CRYPTO_AES=0): kein eigener AES-Treiber im Build (kein HW-Block-/DMA-Pfad,
// kein Benchmark). IPSEC braucht CRYPTO_AES (Regel in weirdos_module_rules.h), also ruft hier nur
// noch die Konsole ('ipsec aes'/'aesbench') an -- die Antworten nennen den Grund.
static const char* kAesNotBuilt = "AES-Treiber nicht im Build enthalten (WEIRDOS_FEATURE_CRYPTO_AES=0)";
void        aesEngineSetBackend(AesBackend b) { (void)b; }
AesBackend  aesEngineBackend() { return AesBackend::SOFT; }
const char* aesBackendName(AesBackend b) { (void)b; return kAesNotBuilt; }
int aesEngineCbc(int enc, const uint8_t* key, size_t klen, const uint8_t iv[16],
                 const uint8_t* in, size_t len, uint8_t* out) { (void)enc; (void)key; (void)klen; (void)iv; (void)in; (void)len; (void)out; return -1; }
int aesEngineCbcVia(AesBackend b, int enc, const uint8_t* key, size_t klen, const uint8_t iv[16],
                    const uint8_t* in, size_t len, uint8_t* out) { (void)b; (void)enc; (void)key; (void)klen; (void)iv; (void)in; (void)len; (void)out; return -1; }
String aesBench(int len, int rounds) { (void)len; (void)rounds; return String(kAesNotBuilt); }
#endif // WEIRDOS_FEATURE_CRYPTO_AES
