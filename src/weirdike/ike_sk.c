/*
 * WeirdIKE -- src/core/ike_sk.c : Encrypted (SK{}) payload seal/open (RFC 7296 3.14). Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ike_sk.h"
#include <string.h>

static void wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* Constant-time compare -- never memcmp() an ICV (timing side channel). */
static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

int ike_sk_calc_size(size_t prefix_len, size_t inner_len, size_t icv_len,
                     size_t *ciphertext_len, size_t *message_len) {
    if (!ciphertext_len || !message_len) return -1;
    *ciphertext_len = 0;
    *message_len = 0;
    if (icv_len == 0 || icv_len > IKE_SK_ICV_MAX) return -1;
    if (inner_len > IKE_SK_MAX_MSG) return -1;
    size_t pad_len = (16 - ((inner_len + 1) % 16)) % 16;
    size_t pt_len  = inner_len + pad_len + 1;            /* multiple of 16 */
    if (pt_len > IKE_SK_MAX_MSG) return -1;
    size_t body = IKE_SK_IV_LEN + pt_len + icv_len;
    if (prefix_len > IKE_SK_MAX_MSG) return -1;
    if (body > IKE_SK_MAX_MSG - prefix_len) return -1;   /* subtraction-safe */
    *ciphertext_len = pt_len;
    *message_len    = prefix_len + body;
    return 0;
}

int ike_sk_seal(ike_aes_cbc_fn aes, void *aes_ctx,
                ike_prf_fn integ, void *integ_ctx, size_t integ_out_len, size_t icv_len,
                const uint8_t *sk_e, size_t sk_e_len, const uint8_t *sk_a, size_t sk_a_len,
                const uint8_t iv[IKE_SK_IV_LEN],
                uint8_t *msg, size_t prefix_len, size_t msg_cap,
                const uint8_t *inner, size_t inner_len,
                size_t *msg_len) {
    if (!aes || !integ || !sk_e || !sk_a || !iv || !msg || !msg_len) return -1;
    *msg_len = 0;
    if (inner_len && !inner) return -1;
    if (icv_len == 0 || icv_len > IKE_SK_ICV_MAX || integ_out_len < icv_len || integ_out_len > 64) return -1;

    size_t pt_len, total;
    if (ike_sk_calc_size(prefix_len, inner_len, icv_len, &pt_len, &total) != 0) return -1;
    if (total > msg_cap) return -1;
    size_t pad_len = pt_len - inner_len - 1;

    uint8_t *ivp = msg + prefix_len;
    uint8_t *ct  = ivp + IKE_SK_IV_LEN;
    uint8_t *icv = ct + pt_len;

    memcpy(ivp, iv, IKE_SK_IV_LEN);
    if (inner_len) memcpy(ct, inner, inner_len);
    if (pad_len)   memset(ct + inner_len, 0, pad_len);   /* padding content unspecified; send 0 */
    ct[inner_len + pad_len] = (uint8_t)pad_len;          /* PadLength */

    if (sk_e_len != 16 && sk_e_len != 24 && sk_e_len != 32) return -1;   /* AES-CBC-128/192/256 (A1) */
    if (aes(aes_ctx, 1, sk_e, sk_e_len, iv, ct, pt_len, ct) != 0) {
        wipe(ivp, IKE_SK_IV_LEN + pt_len);
        return -1;
    }

    /* ICV = first icv_len bytes of HMAC(SK_a, prefix | IV | ciphertext). */
    uint8_t full[64];
    if (integ(integ_ctx, sk_a, sk_a_len, msg, prefix_len + IKE_SK_IV_LEN + pt_len, full) != 0) {
        wipe(full, sizeof(full));
        wipe(ivp, IKE_SK_IV_LEN + pt_len);
        return -1;
    }
    memcpy(icv, full, icv_len);
    wipe(full, sizeof(full));

    *msg_len = total;
    return 0;
}

int ike_sk_open(ike_aes_cbc_fn aes, void *aes_ctx,
                ike_prf_fn integ, void *integ_ctx, size_t integ_out_len, size_t icv_len,
                const uint8_t *sk_e, size_t sk_e_len, const uint8_t *sk_a, size_t sk_a_len,
                const uint8_t *msg, size_t msg_len, size_t sk_body_off,
                uint8_t *inner_out, size_t inner_cap, size_t *inner_len) {
    if (!aes || !integ || !sk_e || !sk_a || !msg || !inner_out || !inner_len) return -1;
    *inner_len = 0;
    if (icv_len == 0 || icv_len > IKE_SK_ICV_MAX || integ_out_len < icv_len || integ_out_len > 64) return -1;

    if (msg_len > IKE_SK_MAX_MSG) return -1;
    if (sk_body_off > msg_len) return -1;
    const size_t overhead = IKE_SK_IV_LEN + 16 + icv_len;   /* iv + >=1 block + icv */
    if (msg_len - sk_body_off < overhead) return -1;
    size_t ct_len = msg_len - sk_body_off - IKE_SK_IV_LEN - icv_len;
    if (ct_len == 0 || (ct_len % 16) != 0) return -1;

    const uint8_t *ivp = msg + sk_body_off;
    const uint8_t *ct  = ivp + IKE_SK_IV_LEN;
    const uint8_t *icv = msg + msg_len - icv_len;

    /* Authenticate FIRST, over everything except the trailing ICV, constant-time. */
    uint8_t full[64];
    if (integ(integ_ctx, sk_a, sk_a_len, msg, msg_len - icv_len, full) != 0) {
        wipe(full, sizeof(full));
        return -1;
    }
    int ok = ct_equal(full, icv, icv_len);
    wipe(full, sizeof(full));
    if (!ok) return -1;                                 /* NEVER decrypt on ICV mismatch */

    /* Decrypt DIRECTLY into the caller's buffer (no stack copy of the message): it must hold the
     * whole ciphertext, padding included -- every core caller passes a workspace region of
     * IKE_SK_MAX_MSG. On any failure the buffer is wiped: no plaintext leaks out of an error. */
    if (ct_len > inner_cap) return -1;
    if (sk_e_len != 16 && sk_e_len != 24 && sk_e_len != 32) return -1;
    if (aes(aes_ctx, 0, sk_e, sk_e_len, ivp, ct, ct_len, inner_out) != 0) { wipe(inner_out, ct_len); return -1; }

    size_t pad_len = inner_out[ct_len - 1];
    if (pad_len + 1 > ct_len) { wipe(inner_out, ct_len); return -1; }
    size_t in_len = ct_len - pad_len - 1;
    wipe(inner_out + in_len, ct_len - in_len);   /* padding + PadLength never reach a parser */
    *inner_len = in_len;
    return 0;
}
