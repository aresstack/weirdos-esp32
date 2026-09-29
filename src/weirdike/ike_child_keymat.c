/*
 * WeirdIKE -- src/core/ike_child_keymat.c : first CHILD_SA key derivation (RFC 7296 2.17).
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ike_child_keymat.h"
#include <string.h>

#define CHILD_KEYMAT_LEN 192          /* 2 x (32 + 64): enc_i2r | integ_i2r | enc_r2i | integ_r2i */
#define NONCE_MIN 16                  /* RFC 7296 2.10: nonces are >= 128 bits */
#define NONCE_MAX 256

static void wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

int ike_derive_child_keys_pfs(ike_prf_fn prf, void *ctx, size_t prf_len,
                              const uint8_t *sk_d, size_t sk_d_len,
                              const uint8_t *gir, size_t gir_len,
                              const uint8_t *ni, size_t ni_len,
                              const uint8_t *nr, size_t nr_len,
                              size_t enc_len, size_t integ_len,
                              ike_child_keys_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));     /* no stale key material survives a failure */
    if (!prf || !sk_d || !ni || !nr) return -1;
    if (prf_len == 0 || sk_d_len == 0) return -1;
    if (enc_len == 0 || enc_len > 32 || integ_len > 64) return -1;   /* struct capacity */
    if (ni_len < NONCE_MIN || ni_len > NONCE_MAX) return -1;
    if (nr_len < NONCE_MIN || nr_len > NONCE_MAX) return -1;
    if (gir_len && (!gir || gir_len > 512)) return -1;   /* B2/B3: up to MODP4096 */

    /* RFC 7296 2.17: KEYMAT = prf+(SK_d, Ni | Nr) for the first Child SA and for a rekey without
     * PFS; with PFS (KE in CREATE_CHILD_SA) KEYMAT = prf+(SK_d, g^ir(new) | Ni | Nr). */
    uint8_t seed[512 + NONCE_MAX * 2];
    size_t seed_len = 0;
    if (gir_len) { memcpy(seed, gir, gir_len); seed_len = gir_len; }
    memcpy(seed + seed_len, ni, ni_len); seed_len += ni_len;
    memcpy(seed + seed_len, nr, nr_len); seed_len += nr_len;

    /* KEYMAT = prf+(SK_d, Ni|Nr) using the NEGOTIATED IKE PRF (SHA-1 -> 20-B blocks, SHA-256 ->
     * 32-B, SHA-512 -> 64-B). RFC 7296 2.17: the ESP keys are taken in order
     *   enc_i2r(enc_len) | integ_i2r(integ_len) | enc_r2i(enc_len) | integ_r2i(integ_len)
     * with the NEGOTIATED Child lengths (AES-256 = 32; HMAC-SHA2-256-128 = 32, HMAC-SHA1-96 = 20).
     * The KDF that PRODUCES those keys uses the IKE SA's PRF -- so a SHA-512 IKE must derive the
     * child keys with SHA-512, or the peer can't decrypt our ESP (and vice versa). */
    size_t need = 2 * (enc_len + integ_len);
    uint8_t keymat[CHILD_KEYMAT_LEN];
    int rc = ike_prf_plus(prf, ctx, prf_len, sk_d, sk_d_len, seed, seed_len, keymat, need);
    wipe(seed, sizeof(seed));
    if (rc != 0) { wipe(keymat, sizeof(keymat)); return -1; }   /* out already zeroed */

    size_t o = 0;
    memcpy(out->enc_i2r,   keymat + o, enc_len);   o += enc_len;
    memcpy(out->integ_i2r, keymat + o, integ_len); o += integ_len;
    memcpy(out->enc_r2i,   keymat + o, enc_len);   o += enc_len;
    memcpy(out->integ_r2i, keymat + o, integ_len);
    out->enc_len = enc_len; out->integ_len = integ_len;
    wipe(keymat, sizeof(keymat));
    return 0;
}

int ike_derive_child_keys_ex(ike_prf_fn prf, void *ctx, size_t prf_len,
                             const uint8_t *sk_d, size_t sk_d_len,
                             const uint8_t *ni, size_t ni_len,
                             const uint8_t *nr, size_t nr_len,
                             size_t enc_len, size_t integ_len,
                             ike_child_keys_t *out) {
    return ike_derive_child_keys_pfs(prf, ctx, prf_len, sk_d, sk_d_len, NULL, 0, ni, ni_len, nr, nr_len,
                                     enc_len, integ_len, out);
}

int ike_derive_child_keys(ike_prf_fn prf, void *ctx, size_t prf_len,
                          const uint8_t *sk_d, size_t sk_d_len,
                          const uint8_t *ni, size_t ni_len,
                          const uint8_t *nr, size_t nr_len,
                          ike_child_keys_t *out) {
    /* Legacy fixed layout: AES-CBC-256 + HMAC-SHA2-256-128 (4 x 32 = 128 B). Byte-identical to the
     * pre-AP9 behaviour, so every existing vector/interop stays valid. */
    return ike_derive_child_keys_ex(prf, ctx, prf_len, sk_d, sk_d_len, ni, ni_len, nr, nr_len, 32, 32, out);
}
