/*
 * WeirdIKE -- src/core/ike_sk.h : Encrypted (SK{}) payload seal/open (RFC 7296 3.14). Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Crypto envelope ONLY. AES-CBC-256 (ENCR) + an injected INTEG HMAC are callbacks; the IV is caller-
 * supplied (RNG-free, deterministic). Algorithm-agile on the INTEG side: the caller passes the HMAC
 * callback, its full output length, and the transmitted ICV length -- so SHA256-128 (32-B HMAC ->
 * 16-B ICV) and SHA512-256 (64-B HMAC -> 32-B ICV) both work. Encrypt-then-MAC:
 *
 *   plaintext  = InnerPayloads | Padding[pad_len] | PadLength(1)     (block-aligned to 16)
 *   ciphertext = AES-CBC-256(SK_e, IV, plaintext)
 *   ICV        = first icv_len bytes of HMAC(SK_a, IKEhdr | SKhdr | IV | ciphertext)
 *
 * The IKE header Length field MUST already hold the FINAL value (incl. the ICV) in the caller prefix.
 * On RX: bounds -> constant-time ICV verify -> ONLY THEN decrypt -> validate PadLength.
 * Request direction: SK_e=SK_ei, SK_a=SK_ai.  Response direction: SK_e=SK_er, SK_a=SK_ar.
 */
#ifndef WEIRDIKE_IKE_SK_H
#define WEIRDIKE_IKE_SK_H

#include <stdint.h>
#include <stddef.h>
#include "ike_keymat.h"   /* ike_prf_fn (generic HMAC callback) */

#ifdef __cplusplus
extern "C" {
#endif

/* AES-CBC callback: enc!=0 encrypts. iv is 16 B; len is a multiple of 16. Matches weirdike_crypto_t
 * ->aes_cbc. Must not mutate the caller's iv (backends copy it) and must support in-place. */
typedef int (*ike_aes_cbc_fn)(void *ctx, int enc, const uint8_t *key, size_t klen,
                              const uint8_t iv[16], const uint8_t *in, size_t len, uint8_t *out);

#define IKE_SK_IV_LEN   16
#define IKE_SK_ICV_MAX  32   /* SHA512-256 */
#define IKE_SK_MAX_MSG  1500

/* Planner: total = prefix + IV(16) + ciphertext(inner+pad+PadLen, 16-aligned) + ICV(icv_len). */
int ike_sk_calc_size(size_t prefix_len, size_t inner_len, size_t icv_len,
                     size_t *ciphertext_len, size_t *message_len);

/* Seal into `msg` which already holds the authenticated prefix (IKE hdr w/ FINAL Length | SK hdr) in
 * [0,prefix_len). integ_out_len = the HMAC's full output (32/64); icv_len = transmitted ICV (16/32).
 * Returns 0, or -1 on bad args / buffer too small / callback failure. */
int ike_sk_seal(ike_aes_cbc_fn aes, void *aes_ctx,
                ike_prf_fn integ, void *integ_ctx, size_t integ_out_len, size_t icv_len,
                const uint8_t *sk_e, size_t sk_e_len, const uint8_t *sk_a, size_t sk_a_len,
                const uint8_t iv[IKE_SK_IV_LEN],
                uint8_t *msg, size_t prefix_len, size_t msg_cap,
                const uint8_t *inner, size_t inner_len,
                size_t *msg_len);

/* Open. sk_body_off = offset where the IV starts (after IKE hdr + SK generic hdr). Verifies the
 * icv_len-byte ICV constant-time over msg[0 .. msg_len-icv_len) BEFORE decrypting, then decrypts
 * DIRECTLY into inner_out (inner_cap must hold the whole ciphertext incl. padding, i.e. pass a
 * buffer of IKE_SK_MAX_MSG); padding is wiped, *inner_len = payload bytes. Returns 0, or -1 on bad
 * args / bounds / ICV mismatch / bad padding (inner_out wiped). No message-sized stack buffer. */
int ike_sk_open(ike_aes_cbc_fn aes, void *aes_ctx,
                ike_prf_fn integ, void *integ_ctx, size_t integ_out_len, size_t icv_len,
                const uint8_t *sk_e, size_t sk_e_len, const uint8_t *sk_a, size_t sk_a_len,
                const uint8_t *msg, size_t msg_len, size_t sk_body_off,
                uint8_t *inner_out, size_t inner_cap, size_t *inner_len);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_IKE_SK_H */
