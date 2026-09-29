/*
 * WeirdIKE -- src/core/ike_auth.c : IKEv2 PSK AUTH primitives (RFC 7296 2.15). Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ike_auth.h"
#include <string.h>

#define IKE_AUTH_MAX_ID 256

/* Exactly 17 bytes, NO terminating NUL in the MAC input. */
static const char KEY_PAD[] = "Key Pad for IKEv2";

static void wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

int ike_maced_id(ike_prf_fn prf, void *ctx, size_t prf_len,
                 const uint8_t *sk_p, size_t sk_p_len,
                 uint8_t id_type, const uint8_t *id_data, size_t id_len,
                 uint8_t *out) {
    if (!prf || !sk_p || !out) return -1;
    if (prf_len == 0 || prf_len > IKE_AUTH_MAC_MAX) return -1;
    if (id_len > IKE_AUTH_MAX_ID) return -1;
    if (id_len && !id_data) return -1;

    uint8_t idp[4 + IKE_AUTH_MAX_ID];   /* ID' = type | 000 | data */
    idp[0] = id_type; idp[1] = 0; idp[2] = 0; idp[3] = 0;
    if (id_len) memcpy(idp + 4, id_data, id_len);

    int rc = prf(ctx, sk_p, sk_p_len, idp, 4 + id_len, out);
    wipe(idp, sizeof(idp));
    if (rc != 0) { wipe(out, prf_len); return -1; }   /* never leak half-computed MAC state */
    return 0;
}

int ike_psk_auth(ike_prf_fn prf, void *ctx, size_t prf_len,
                 const uint8_t *psk, size_t psk_len,
                 const uint8_t *signed_octets, size_t signed_len,
                 uint8_t *out) {
    if (!prf || !psk || (!signed_octets && signed_len) || !out) return -1;
    if (prf_len == 0 || prf_len > IKE_AUTH_MAC_MAX) return -1;

    uint8_t keypad_key[IKE_AUTH_MAC_MAX];
    int rc = prf(ctx, psk, psk_len, (const uint8_t *)KEY_PAD, sizeof(KEY_PAD) - 1, keypad_key);
    if (rc == 0) rc = prf(ctx, keypad_key, prf_len, signed_octets, signed_len, out);
    wipe(keypad_key, sizeof(keypad_key));
    if (rc != 0) { wipe(out, prf_len); return -1; }   /* never leak half-computed MAC state */
    return 0;
}
