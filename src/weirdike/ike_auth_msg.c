/*
 * WeirdIKE -- src/core/ike_auth_msg.c : complete IKE_AUTH request builder (M2b-4a). RFC 7296.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ike_auth_msg.h"
#include "ike_auth.h"
#include "ike_auth_wire.h"
#include "ike_sk.h"
#include "ike_wire.h"
#include <string.h>

#define SK_HDR_LEN 4                                   /* generic payload header of the SK payload */
#define PREFIX_LEN (IKE_HDR_LEN + SK_HDR_LEN)          /* 28 + 4 = 32 (feeds the ICV) */

static void wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

int ike_build_auth_request(const weirdike_crypto_t *cr, const ike_auth_req_t *in,
                           uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!cr || !cr->aes_cbc || !in || !out || !out_len) return -1;
    *out_len = 0;
    if (!in->prf || !in->integ || in->prf_len == 0 || in->prf_len > IKE_AUTH_MAC_MAX ||
        in->sk_a_len == 0 || in->integ_out_len == 0 || in->icv_len == 0) return -1;
    if (!in->spi_i || !in->spi_r || !in->sk_ei || !in->sk_ai || !in->sk_pi ||
        !in->psk || !in->real_msg1 || !in->nr || !in->iv) return -1;
    if (in->real_msg1_len == 0 || in->real_msg1_len > WEIRDIKE_MAX_IKE_MSG) return -1;
    if (in->nr_len == 0 || in->nr_len > 256) return -1;
    /* caller-supplied scratch (workspace): the message-sized areas never live on the stack */
    if (!in->scratch_inner || in->scratch_inner_cap < WEIRDIKE_MAX_IKE_MSG ||
        !in->scratch_so || in->scratch_so_cap < in->real_msg1_len + in->nr_len + in->prf_len) return -1;

    int rc = -1;

    /* --- AUTH_i --- MACedIDForI = prf(SK_pi, IDi'); SignedOctets = RealMessage1 | Nr | MACedIDForI. */
    uint8_t maced[IKE_AUTH_MAC_MAX];
    if (ike_maced_id(in->prf, cr->ctx, in->prf_len, in->sk_pi, in->prf_len,
                     in->id_type, in->id_data, in->id_len, maced) != 0) return -1;

    uint8_t *so = in->scratch_so;   /* RealMessage1 | Nr | MACedID */
    size_t   so_len = 0;
    memcpy(so + so_len, in->real_msg1, in->real_msg1_len); so_len += in->real_msg1_len;
    memcpy(so + so_len, in->nr, in->nr_len);               so_len += in->nr_len;
    memcpy(so + so_len, maced, in->prf_len);               so_len += in->prf_len;

    uint8_t auth[IKE_AUTH_MAC_MAX];
    if (ike_psk_auth(in->prf, cr->ctx, in->prf_len, in->psk, in->psk_len, so, so_len, auth) != 0) {
        wipe(so, so_len); wipe(maced, sizeof(maced));
        return -1;
    }
    wipe(so, so_len); wipe(maced, sizeof(maced));

    /* --- inner payload chain --- */
    ike_auth_inner_t inner_in;
    memset(&inner_in, 0, sizeof(inner_in));
    inner_in.id_type = in->id_type; inner_in.id_data = in->id_data; inner_in.id_len = in->id_len;
    inner_in.have_idr = in->have_idr;
    inner_in.idr_type = in->idr_type; inner_in.idr_data = in->idr_data; inner_in.idr_len = in->idr_len;
    inner_in.auth = auth; inner_in.auth_len = in->prf_len;
    inner_in.child_spi_i = in->child_spi_i;
    inner_in.child_policy = in->child_policy;
    inner_in.ts_i = in->ts_i; inner_in.ts_r = in->ts_r;
    inner_in.ts_r_extra = in->ts_r_extra; inner_in.n_ts_r_extra = in->n_ts_r_extra;   /* E2 */
    inner_in.cp = in->cp; inner_in.cp_len = in->cp_len;   /* IKE Config Mode request (PSK path too) */

    uint8_t *inner = in->scratch_inner;
    size_t   inner_len = 0;
    if (ike_build_auth_inner(&inner_in, inner, in->scratch_inner_cap, &inner_len) != 0) goto done;

    /* --- final message length (header must carry it BEFORE seal, it feeds the ICV) --- */
    size_t ct_len = 0, msg_len = 0;
    if (ike_sk_calc_size(PREFIX_LEN, inner_len, in->icv_len, &ct_len, &msg_len) != 0) goto done;
    if (msg_len > out_cap) goto done;

    /* --- IKE header (28) : Next = SK, Exchange = IKE_AUTH, Initiator, Message ID 1 --- */
    size_t n = 0;
    memcpy(out + n, in->spi_i, 8); n += 8;
    memcpy(out + n, in->spi_r, 8); n += 8;
    out[n++] = IKE_PL_SK;
    out[n++] = IKE_VERSION;
    out[n++] = IKE_EXCHANGE_AUTH;
    out[n++] = IKE_FLAG_INITIATOR;
    out[n++] = 0; out[n++] = 0; out[n++] = 0; out[n++] = 1;                 /* Message ID = 1 */
    out[n++] = (uint8_t)(msg_len >> 24); out[n++] = (uint8_t)(msg_len >> 16);
    out[n++] = (uint8_t)(msg_len >> 8);  out[n++] = (uint8_t)msg_len;        /* Length */

    /* --- SK generic payload header (4) : Next = IDi, Length = whole SK payload --- */
    size_t sk_pl_len = msg_len - IKE_HDR_LEN;
    out[n++] = IKE_PL_IDI;
    out[n++] = 0;
    out[n++] = (uint8_t)(sk_pl_len >> 8); out[n++] = (uint8_t)sk_pl_len;

    /* --- encrypt-then-MAC the inner chain (SK_ei / SK_ai) --- */
    size_t sealed = 0;
    if (ike_sk_seal(cr->aes_cbc, cr->ctx, in->integ, cr->ctx, in->integ_out_len, in->icv_len,
                    in->sk_ei, in->sk_e_len ? in->sk_e_len : 32, in->sk_ai, in->sk_a_len, in->iv,
                    out, PREFIX_LEN, out_cap, inner, inner_len, &sealed) != 0) goto done;
    if (sealed != msg_len) goto done;

    *out_len = msg_len;
    rc = 0;

done:
    wipe(auth, sizeof(auth));
    wipe(inner, inner_len);   /* the plaintext chain is now sealed in out; nothing stays in scratch */
    return rc;
}
