/*
 * WeirdIKE -- src/core/ike_keymat.h : IKEv2 SKEYSEED + key schedule (RFC 7296 2.13/2.14). Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Deterministic: inputs in, seven keys out. NO FSM/sockets/ctx. The PRF is injected as a function
 * pointer (identical type to weirdike_crypto_t.hmac_shaX) so this is byte-exactly testable against
 * fixed vectors. Algorithm-agile: PRF output and per-key sizes are parameters, so the same code
 * derives the SHA-256 suite (7*32 = 224 B) and the SHA-512 suite (64|64|64|32|32|64|64 = 384 B).
 */
#ifndef WEIRDIKE_IKE_KEYMAT_H
#define WEIRDIKE_IKE_KEYMAT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Historical 32-byte-output alias (still used by ike_auth/ike_sk/ike_child_keymat callers). */
typedef int (*ike_hmac_sha256_fn)(void *ctx, const uint8_t *key, size_t klen,
                                  const uint8_t *in, size_t len, uint8_t out[32]);
/* Generic PRF/HMAC callback. Identical underlying type to the vtable hmac_shaX (out[N] == out*),
 * so cr.hmac_sha256 / cr.hmac_sha512 are assignable without a cast. The caller guarantees `out` has
 * the PRF's output length. */
typedef int (*ike_prf_fn)(void *ctx, const uint8_t *key, size_t klen,
                          const uint8_t *in, size_t len, uint8_t *out);

#define IKE_PRF_MAX     64   /* largest PRF output we support (HMAC-SHA-512) */
#define IKE_ENCR_MAX    32   /* largest ENCR key (AES-256) */

typedef struct {
    uint8_t sk_d[IKE_PRF_MAX];                       size_t sk_d_len;   /* PRF-key length */
    uint8_t sk_ai[IKE_PRF_MAX], sk_ar[IKE_PRF_MAX];  size_t sk_a_len;   /* INTEG key length */
    uint8_t sk_ei[IKE_ENCR_MAX], sk_er[IKE_ENCR_MAX];size_t sk_e_len;   /* ENCR key length */
    uint8_t sk_pi[IKE_PRF_MAX], sk_pr[IKE_PRF_MAX];  size_t sk_p_len;   /* PRF-key length */
} ike_keys_t;

/* Generic RFC 7296 2.13 prf+ with PRF output = prf_len bytes:
 *   T1 = prf(key, seed | 0x01);  Tn = prf(key, T(n-1) | seed | n);  out = T1 | T2 | ...
 * Writes exactly out_len bytes. Returns 0, or -1 (bad args / seed too long / out too long / prf
 * failure). Zeroizes temporaries; wipes out on failure. */
int ike_prf_plus(ike_prf_fn prf, void *ctx, size_t prf_len,
                 const uint8_t *key, size_t key_len,
                 const uint8_t *seed, size_t seed_len,
                 uint8_t *out, size_t out_len);

/* SKEYSEED = prf(Ni | Nr, g^ir); then prf+(SKEYSEED, Ni | Nr | SPIi | SPIr) split into
 * SK_d(prf_len) | SK_ai(integ) | SK_ar(integ) | SK_ei(encr) | SK_er(encr) | SK_pi(prf) | SK_pr(prf).
 * gir_len MUST be 256 (DH14 modulus; caller left-pads). Sizes bounded by IKE_PRF_MAX/IKE_ENCR_MAX.
 * Returns 0; zeroizes SKEYSEED + all intermediates. */
int ike_derive_keys(ike_prf_fn prf, void *ctx, size_t prf_len,
                    size_t integ_key_len, size_t encr_key_len,
                    const uint8_t *ni, size_t ni_len,
                    const uint8_t *nr, size_t nr_len,
                    const uint8_t *gir, size_t gir_len,
                    const uint8_t spi_i[8], const uint8_t spi_r[8],
                    ike_keys_t *out);

/* IKE-SA REKEY key schedule (RFC 7296 2.18):
 *     SKEYSEED = prf_old(SK_d(old), g^ir(new) | Ni | Nr)
 *     {SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr} = prf+_new(SKEYSEED, Ni | Nr | SPIi | SPIr)
 * The rekey exchange belongs to the OLD IKE SA, so its PRF keys SKEYSEED; the NEW SA's PRF and key
 * lengths produce the keys, with the nonces and SPIs of the CREATE_CHILD_SA exchange (initiator's
 * first). gir = the fresh D-H shared secret (mandatory). Same output contract as ike_derive_keys. */
int ike_derive_keys_rekey(ike_prf_fn prf_old, size_t prf_old_len,
                          const uint8_t *sk_d_old, size_t sk_d_old_len,
                          ike_prf_fn prf_new, void *ctx, size_t prf_new_len,
                          size_t integ_key_len, size_t encr_key_len,
                          const uint8_t *ni, size_t ni_len,
                          const uint8_t *nr, size_t nr_len,
                          const uint8_t *gir, size_t gir_len,
                          const uint8_t spi_i[8], const uint8_t spi_r[8],
                          ike_keys_t *out);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_IKE_KEYMAT_H */
