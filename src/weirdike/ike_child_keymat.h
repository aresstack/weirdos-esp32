/*
 * WeirdIKE -- src/core/ike_child_keymat.h : first CHILD_SA key derivation (RFC 7296 2.17). Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For the initial CHILD_SA created by IKE_AUTH (no separate DH exchange):
 *     KEYMAT = prf+(SK_d, Ni | Nr)
 * (A later CREATE_CHILD_SA with its own KE would instead feed g^ir(new) | Ni | Nr.)
 *
 * RFC 7296 takes ALL keys for the first direction (initiator -> responder) before the second
 * (responder -> initiator); within a direction, encryption key before integrity key. Our fixed suite
 * (AES-CBC-256 + HMAC-SHA2-256-128) needs 4 x 32 = 128 bytes:
 *     enc_i2r[32] | integ_i2r[32] | enc_r2i[32] | integ_r2i[32]
 *
 * This is a pure KDF: no SPIs, no traffic selectors, no ESP. Reuses the tested ike_prf_plus().
 */
#ifndef WEIRDIKE_IKE_CHILD_KEYMAT_H
#define WEIRDIKE_IKE_CHILD_KEYMAT_H

#include <stdint.h>
#include <stddef.h>
#include "ike_keymat.h"   /* ike_prf_fn, ike_prf_plus */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t enc_i2r[32];    /* ESP encryption  initiator -> responder (WeirdIKE OUTBOUND) */
    uint8_t integ_i2r[64];  /* ESP integrity   initiator -> responder (up to HMAC-SHA2-512-256) */
    uint8_t enc_r2i[32];    /* ESP encryption  responder -> initiator (WeirdIKE INBOUND)  */
    uint8_t integ_r2i[64];  /* ESP integrity   responder -> initiator */
    size_t  enc_len;        /* AP9: valid bytes in enc_* (32 for AES-256) */
    size_t  integ_len;      /* AP9: valid bytes in integ_* (32 HMAC-SHA2-256-128, 20 HMAC-SHA1-96) */
} ike_child_keys_t;

/* AP9: same derivation with the NEGOTIATED Child key lengths (RFC 7296 2.17 takes exactly
 * enc_len | integ_len | enc_len | integ_len from prf+). enc_len 1..32, integ_len 0..64. */
int ike_derive_child_keys_ex(ike_prf_fn prf, void *ctx, size_t prf_len,
                             const uint8_t *sk_d, size_t sk_d_len,
                             const uint8_t *ni, size_t ni_len,
                             const uint8_t *nr, size_t nr_len,
                             size_t enc_len, size_t integ_len,
                             ike_child_keys_t *out);

/* AP5: rekey with optional PFS. gir/gir_len = the NEW D-H shared secret from the CREATE_CHILD_SA KE
 * exchange (RFC 7296 2.17: KEYMAT = prf+(SK_d, g^ir | Ni | Nr)); gir_len 0 = no PFS. Ni/Nr are the
 * nonces of THAT CREATE_CHILD_SA exchange (initiator's first). */
int ike_derive_child_keys_pfs(ike_prf_fn prf, void *ctx, size_t prf_len,
                              const uint8_t *sk_d, size_t sk_d_len,
                              const uint8_t *gir, size_t gir_len,
                              const uint8_t *ni, size_t ni_len,
                              const uint8_t *nr, size_t nr_len,
                              size_t enc_len, size_t integ_len,
                              ike_child_keys_t *out);

/* Derive the four ESP keys for the first CHILD_SA. prf + prf_len are the NEGOTIATED IKE-SA PRF and
 * its block/output length (32 SHA-256 / 64 SHA-512); sk_d is sk_d_len bytes (= prf_len, caller-owned,
 * NOT wiped here). ni/nr are the IKE_SA_INIT nonces (16..256 bytes each). The extracted ESP keys stay
 * 4 x 32 (AES-CBC-256 + HMAC-SHA2-256-128) regardless of the PRF. Returns 0 on success; -1 on bad
 * args or PRF failure. On any failure *out is left zeroed. The temporary 128-byte KEYMAT is wiped. */
int ike_derive_child_keys(ike_prf_fn prf, void *ctx, size_t prf_len,
                          const uint8_t *sk_d, size_t sk_d_len,
                          const uint8_t *ni, size_t ni_len,
                          const uint8_t *nr, size_t nr_len,
                          ike_child_keys_t *out);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_IKE_CHILD_KEYMAT_H */
