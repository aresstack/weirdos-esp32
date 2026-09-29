/*
 * WeirdIKE -- src/esp/esp.c : ESP dataplane seal/open (RFC 4303 + RFC 3602).
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "esp.h"
#include <string.h>

static void wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}
/* AES-CBC key sizes accepted by the data plane (A1): 128/192/256 bit. */
static int esp_enc_key_len_ok(size_t n) { return n == 16 || n == 24 || n == 32; }
static int ct_equal_n(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

/* AP9: the ESP integrity algorithm is selected by the (negotiated) INTEG key length, which is
 * unambiguous for the two supported suites: 32 B -> HMAC-SHA2-256-128 (16-B ICV), 20 B ->
 * HMAC-SHA1-96 (12-B ICV). Full HMAC output is 32 / 20 B. Returns 0, or -1 if unsupported. */
typedef int (*esp_hmac_fn)(void *ctx, const uint8_t *key, size_t klen, const uint8_t *in, size_t len, uint8_t *out);
static int esp_integ_select(const weirdike_crypto_t *crypto, size_t integ_key_len,
                            esp_hmac_fn *fn, size_t *icv_len, size_t *full_len) {
    if (integ_key_len == 32 && crypto->hmac_sha256) {
        *fn = (esp_hmac_fn)crypto->hmac_sha256; *icv_len = 16; *full_len = 32; return 0;
    }
    if (integ_key_len == 20 && crypto->hmac_sha1) {
        *fn = (esp_hmac_fn)crypto->hmac_sha1;   *icv_len = 12; *full_len = 20; return 0;
    }
    /* A2: RFC 4868 key = full hash size, ICV = half: HMAC-SHA2-384-192 (48/24), HMAC-SHA2-512-256 (64/32). */
    if (integ_key_len == 48 && crypto->hmac_sha384) {
        *fn = (esp_hmac_fn)crypto->hmac_sha384; *icv_len = 24; *full_len = 48; return 0;
    }
    if (integ_key_len == 64 && crypto->hmac_sha512) {
        *fn = (esp_hmac_fn)crypto->hmac_sha512; *icv_len = 32; *full_len = 64; return 0;
    }
    return -1;
}
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int esp_peek_header(const uint8_t *packet, size_t packet_len, uint32_t *spi, uint32_t *seq) {
    if (!packet || packet_len < ESP_SPI_LEN + ESP_SEQ_LEN) return -1;
    if (spi) *spi = rd32(packet);
    if (seq) *seq = rd32(packet + ESP_SPI_LEN);
    return 0;   /* UNAUTHENTICATED until esp_open() verifies the ICV */
}

int esp_seal(const weirdike_crypto_t *crypto,
             uint32_t spi, uint32_t seq,
             const uint8_t *enc_key, size_t enc_key_len,
             const uint8_t *integ_key, size_t integ_key_len,
             const uint8_t iv[ESP_IV_LEN], uint8_t next_header,
             const uint8_t *payload, size_t payload_len,
             uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!out_len) return -1;
    *out_len = 0;
    if (!crypto || !crypto->aes_cbc) return -1;
    if (!enc_key || !esp_enc_key_len_ok(enc_key_len) || !integ_key) return -1;
    esp_hmac_fn hmac = NULL; size_t icv_len = 0, full_len = 0;
    if (esp_integ_select(crypto, integ_key_len, &hmac, &icv_len, &full_len) != 0) return -1;
    if (!iv || !out) return -1;
    if (payload_len && !payload) return -1;
    if (payload_len > ESP_MAX_PACKET) return -1;

    /* plaintext = payload | padding | PadLength | NextHeader, block-aligned to 16. */
    size_t pad_len = (16 - ((payload_len + 2) % 16)) % 16;
    size_t pt_len  = payload_len + pad_len + 2;
    if (pt_len > ESP_MAX_PACKET) return -1;
    size_t body = ESP_HDR_LEN + pt_len + icv_len;
    if (body > ESP_MAX_PACKET || body > out_cap) return -1;

    wr32(out + 0, spi);
    wr32(out + 4, seq);
    memcpy(out + 8, iv, ESP_IV_LEN);

    uint8_t *ct = out + ESP_HDR_LEN;
    if (payload_len) memcpy(ct, payload, payload_len);
    for (size_t i = 0; i < pad_len; i++) ct[payload_len + i] = (uint8_t)(i + 1);   /* 01 02 .. pad_len */
    ct[payload_len + pad_len]     = (uint8_t)pad_len;
    ct[payload_len + pad_len + 1] = next_header;

    /* encrypt in place (backend copies iv, preserves the IV field) */
    if (crypto->aes_cbc(crypto->ctx, 1, enc_key, enc_key_len, iv, ct, pt_len, ct) != 0) {
        wipe(out + 8, ESP_IV_LEN + pt_len);
        return -1;
    }

    /* ICV = first icv_len B of HMAC(integ_key, SPI | Seq | IV | ciphertext) (RFC 4868 / RFC 2404) */
    uint8_t full[64];
    if (hmac(crypto->ctx, integ_key, integ_key_len, out, ESP_HDR_LEN + pt_len, full) != 0) {
        wipe(full, sizeof(full));
        wipe(out + 8, ESP_IV_LEN + pt_len);
        return -1;
    }
    memcpy(ct + pt_len, full, icv_len);
    wipe(full, sizeof(full));
    (void)full_len;

    *out_len = body;
    return 0;
}

int esp_open_scratch(const weirdike_crypto_t *crypto,
                     uint32_t expected_spi,
                     const uint8_t *enc_key, size_t enc_key_len,
                     const uint8_t *integ_key, size_t integ_key_len,
                     const uint8_t *packet, size_t packet_len,
                     uint8_t *scratch, size_t scratch_cap,
                     uint32_t *seq_out, uint8_t *next_header_out, size_t *payload_len) {
    if (!payload_len) return -1;
    *payload_len = 0;
    if (!crypto || !crypto->aes_cbc) return -1;
    if (!enc_key || !esp_enc_key_len_ok(enc_key_len) || !integ_key) return -1;
    esp_hmac_fn hmac = NULL; size_t icv_len = 0, full_len = 0;
    if (esp_integ_select(crypto, integ_key_len, &hmac, &icv_len, &full_len) != 0) return -1;
    if (!packet || !scratch) return -1;

    /* bounds: header + at least one cipher block + ICV, ciphertext block-aligned */
    if (packet_len > ESP_MAX_PACKET) return -1;
    if (packet_len < ESP_HDR_LEN + 16 + icv_len) return -1;
    size_t ct_len = packet_len - ESP_HDR_LEN - icv_len;
    if (ct_len == 0 || (ct_len % 16) != 0) return -1;
    if (ct_len > scratch_cap) return -1;               /* the scratch must hold the whole ciphertext */

    if (rd32(packet) != expected_spi) return -1;               /* wrong SA */

    const uint8_t *iv  = packet + 8;
    const uint8_t *ct  = packet + ESP_HDR_LEN;
    const uint8_t *icv = packet + packet_len - icv_len;

    /* authenticate FIRST, over SPI|Seq|IV|ciphertext, constant-time over the transmitted ICV */
    uint8_t full[64];
    if (hmac(crypto->ctx, integ_key, integ_key_len, packet, packet_len - icv_len, full) != 0) {
        wipe(full, sizeof(full));
        return -1;
    }
    int ok = ct_equal_n(full, icv, icv_len);
    wipe(full, sizeof(full));
    (void)full_len;
    if (!ok) return -1;                                        /* NEVER decrypt on ICV mismatch */

    uint8_t *pt = scratch;   /* decrypt into the caller's scratch, never onto the stack */
    if (crypto->aes_cbc(crypto->ctx, 0, enc_key, enc_key_len, iv, ct, ct_len, pt) != 0) {
        wipe(pt, ct_len);
        return -1;
    }

    uint8_t pad_len = pt[ct_len - 2];
    uint8_t nh      = pt[ct_len - 1];
    if ((size_t)pad_len + 2 > ct_len) { wipe(pt, ct_len); return -1; }
    size_t in_len = ct_len - pad_len - 2;
    /* RFC 4303: padding bytes MUST be 1, 2, ..., pad_len */
    for (size_t i = 0; i < pad_len; i++) {
        if (pt[in_len + i] != (uint8_t)(i + 1)) { wipe(pt, ct_len); return -1; }
    }
    wipe(pt + in_len, ct_len - in_len);   /* trailer gone; scratch[0..in_len) = the payload */
    *payload_len = in_len;
    if (seq_out) *seq_out = rd32(packet + 4);
    if (next_header_out) *next_header_out = nh;
    return 0;
}

int esp_open(const weirdike_crypto_t *crypto,
             uint32_t expected_spi,
             const uint8_t *enc_key, size_t enc_key_len,
             const uint8_t *integ_key, size_t integ_key_len,
             const uint8_t *packet, size_t packet_len,
             uint8_t *scratch, size_t scratch_cap,
             uint32_t *seq_out, uint8_t *next_header_out,
             uint8_t *payload_out, size_t payload_cap, size_t *payload_len) {
    if (!payload_len) return -1;
    *payload_len = 0;
    if (!payload_out) return -1;
    size_t in_len = 0;
    if (esp_open_scratch(crypto, expected_spi, enc_key, enc_key_len, integ_key, integ_key_len,
                         packet, packet_len, scratch, scratch_cap, seq_out, next_header_out, &in_len) != 0)
        return -1;
    if (in_len > payload_cap) { wipe(scratch, in_len); return -1; }
    if (in_len) memcpy(payload_out, scratch, in_len);
    wipe(scratch, in_len);
    *payload_len = in_len;
    return 0;
}
