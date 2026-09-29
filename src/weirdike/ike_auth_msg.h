/*
 * WeirdIKE -- src/core/ike_auth_msg.h : complete IKE_AUTH request builder (M2b-4a). RFC 7296.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Assembles a full initiator IKE_AUTH request:  IKE header (msgid 1) | SK{ IDi | [IDr] | AUTH |
 * SAi2 | TSi | TSr }.  Computes AUTH_i internally from the retained IKE_SA_INIT transcript and the
 * derived SK keys:
 *     MACedIDForI = prf(SK_pi, IDi')
 *     AUTH_i      = prf( prf(PSK, "Key Pad for IKEv2"), RealMessage1 | Nr | MACedIDForI )
 * then serializes the inner chain (ike_auth_wire) and encrypts it (ike_sk_seal, SK_ei/SK_ai).
 *
 * DETERMINISTIC given `iv` and `child_spi_i`: the RNG lives in the FSM, not here, so the request is
 * byte-exactly testable and a retransmit can re-send the SAME bytes (never re-seal with a new IV).
 */
#ifndef WEIRDIKE_IKE_AUTH_MSG_H
#define WEIRDIKE_IKE_AUTH_MSG_H

#include <stdint.h>
#include <stddef.h>
#include "weirdike.h"        /* weirdike_crypto_t, weirdike_ts_t */
#include "ike_keymat.h"      /* ike_prf_fn */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const uint8_t *spi_i;         /* 8 -- Initiator SPI (from IKE_SA_INIT) */
    const uint8_t *spi_r;         /* 8 -- Responder SPI */

    const uint8_t *sk_ei;         /* SK_ei (encrypt request); sk_e_len bytes (16/24/32; 0 = legacy 32) */
    size_t         sk_e_len;
    const uint8_t *sk_ai;         /* sk_a_len -- SK_ai (integ request) */
    const uint8_t *sk_pi;         /* prf_len  -- SK_pi (MACedIDForI)   */

    /* Negotiated IKE suite primitives (resolved by the caller from weirdike_ike_suite_t). */
    ike_prf_fn     prf;           /* PRF: MACedID + AUTH + SK_p length */
    size_t         prf_len;       /* 32 (SHA256) / 64 (SHA512) */
    ike_prf_fn     integ;         /* INTEG HMAC for the SK{} ICV */
    size_t         integ_out_len; /* INTEG HMAC full output (== sk_a_len) */
    size_t         icv_len;       /* transmitted ICV (16 SHA256-128 / 32 SHA512-256) */
    size_t         sk_a_len;      /* SK_ai length (INTEG key length) */

    const uint8_t *psk;   size_t psk_len;
    const uint8_t *real_msg1;  size_t real_msg1_len;   /* RealMessage1 = verbatim SA_INIT request */
    const uint8_t *nr;         size_t nr_len;          /* responder nonce */

    uint8_t        id_type;   const uint8_t *id_data;  size_t id_len;   /* IDi */
    int            have_idr;
    uint8_t        idr_type;  const uint8_t *idr_data; size_t idr_len;  /* optional IDr */

    const uint8_t *child_spi_i;   /* 4 -- our inbound ESP SPI for SAi2 */
    const weirdike_child_policy_t *child_policy;   /* NORMALIZED allow-lists -> SAi2 transforms */
    const weirdike_ts_t *ts_i;    /* TSi */
    const weirdike_ts_t *ts_r;    /* TSr */
    const weirdike_ts_t *ts_r_extra; size_t n_ts_r_extra;   /* E2: further TSr selectors (NULL/0 = single) */

    /* IKE Config Mode (RFC 7296 2.19): optional CP(CFG_REQUEST) built by ike_cp_build_ipv4_request
     * (generic header included), placed before SAi2. NULL = no CP. Independent of the auth method. */
    const uint8_t *cp;            size_t cp_len;

    const uint8_t *iv;            /* 16 -- caller-supplied SK IV */
    /* Scratch supplied by the caller (workspace, never the stack), wiped by the builder:
     *   inner >= WEIRDIKE_MAX_IKE_MSG                 inner payload chain before sealing
     *   so    >= real_msg1 + Nr + IKE_AUTH_MAC_MAX    InitiatorSignedOctets */
    uint8_t *scratch_inner; size_t scratch_inner_cap;
    uint8_t *scratch_so;    size_t scratch_so_cap;
} ike_auth_req_t;

/* Build the complete request into out (sets *out_len). `cr` supplies hmac_sha256 + aes_cbc.
 * Returns 0 on success; -1 on bad args / crypto failure / buffer too small. */
int ike_build_auth_request(const weirdike_crypto_t *cr, const ike_auth_req_t *in,
                           uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_IKE_AUTH_MSG_H */
