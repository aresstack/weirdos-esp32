/*
 * WeirdIKE -- src/core/ike_auth_resp.h : IKE_AUTH response verifier (M2b-4b). RFC 7296. Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Decrypts + verifies a responder IKE_AUTH message. IKE authentication and the piggybacked Child-SA
 * negotiation are reported as TWO INDEPENDENT results: RFC 7296 permits a successful mutual AUTH
 * together with a FAILED Child-SA negotiation (the IKE SA is still established). So a protected
 * error-class notify does NOT, by itself, mean "authentication failed" -- unlike the IKE_SA_INIT
 * parser, we never collapse every error notify into a whole-exchange failure here.
 *
 * AUTH_r is checked with IDr' taken VERBATIM from the received IDr body (ID Type | 3 reserved | data)
 * -- not reconstructed -- because the reserved bytes are part of the signed octets on the wire.
 *
 *   MACedIDForR          = prf(SK_pr, IDr' verbatim)
 *   ResponderSignedOctets= RealMessage2 | Ni | MACedIDForR
 *   AUTH_r               = prf( prf(PSK, "Key Pad for IKEv2"), ResponderSignedOctets )   [const-time]
 */
#ifndef WEIRDIKE_IKE_AUTH_RESP_H
#define WEIRDIKE_IKE_AUTH_RESP_H

#include <stdint.h>
#include <stddef.h>
#include "weirdike.h"      /* weirdike_crypto_t, weirdike_ts_t, WEIRDIKE_MAX_ID */
#include "ike_keymat.h"    /* ike_prf_fn */
#include "ike_auth.h"      /* IKE_AUTH_MAC_MAX */

#ifdef __cplusplus
extern "C" {
#endif

/* A VIEW into the decrypted inner payloads (the caller's scratch buffer). Valid only until that
 * buffer is reused, i.e. for the rest of the call that received the message. Rule: a view is never
 * promoted into state that outlives the buffer -- copy the bytes (or the derived value) instead. */
typedef struct { const uint8_t *ptr; size_t len; } ike_span_t;

/* Scratch the verifier needs, supplied by the caller (workspace, never the stack):
 *   inner  >= IKE_SK_MAX_MSG          decrypted inner payload chain; every ike_span_t below points here
 *   so     >= real_msg2 + Ni + MAC    ResponderSignedOctets assembly (wiped after use) */
typedef struct { uint8_t *inner; size_t inner_cap; uint8_t *so; size_t so_cap; } ike_auth_scratch_t;

typedef struct {
    int      ike_auth_ok;                 /* IDr + AUTH present and AUTH_r verified */

    uint8_t  idr_type;                    /* authenticated peer identity (valid iff ike_auth_ok) */
    ike_span_t idr;                       /* IDr data -- view */

    int      child_sa_ok;                 /* SAr2 + TSi + TSr present and structurally acceptable */
    uint8_t  child_spi_r[4];              /* responder inbound ESP SPI -> our OUTBOUND SPI */
    /* What the responder SELECTED for the Child SA (valid iff child_sa_ok). Structure is enforced
     * here (one ENCR, one INTEG, NO_ESN); whether the IDs are inside the child policy and
     * implemented by this build is decided by the FSM (ike_policy.c). */
    uint16_t child_encr, child_encr_key_bits, child_integ;
    weirdike_ts_t ts_i;                   /* narrowed selectors as returned by the responder */
    weirdike_ts_t ts_r;
    /* E2: every selector of the TSr payload (narrowed set), ts_r == ts_r_list[0] */
    weirdike_ts_t ts_r_list[WEIRDIKE_TS_MAX]; size_t n_ts_r;

    uint16_t error_notify;                /* first error-class notify type seen, else 0 */

    /* Payload PRESENCE (structure only, no judgement) -- for the secrets-free wire summary and to
     * tell "the peer rejected our AUTH" (error notify, NO AUTH payload) from "the peer's AUTH is
     * there but OUR verification failed" (PSK / signed-octets mismatch). */
    int      have_auth;                   /* an AUTH payload was present (any method) */
    int      have_sa;                     /* SAr2 present */
    int      have_tsi;                    /* TSi present */
    int      have_tsr;                    /* TSr present */

    /* --- AP7 (EAP / certificate server authentication) --- captured, NOT judged here. */
    int      have_idr;                    /* an IDr payload was present (needed for the signed octets) */
    uint8_t  maced_idr[IKE_AUTH_MAC_MAX]; /* prf(SK_pr, IDr' verbatim), valid iff have_idr */
    size_t   maced_idr_len;
    uint8_t  auth_method;                 /* AUTH payload method (2 PSK, 1 RSA-SHA1, 14 RFC 7427), 0 = none */
    ike_span_t auth_data;                 /* raw AUTH data (signature for methods 1/14) -- view */
    uint8_t  cert_encoding;               /* first CERT payload: 4 = X.509 DER */
    ike_span_t cert;                      /* its DER (leaf) -- view */
    ike_span_t cert2;                     /* second CERT payload (intermediate), if any -- view */
    ike_span_t eap;                       /* EAP payload body (one EAP packet) -- view */
    ike_span_t cp;                        /* CP payload (generic header included, for ike_cp) -- view */
} ike_auth_response_t;

typedef struct {
    const uint8_t *spi_i;                 /* 8 */
    const uint8_t *spi_r;                 /* 8 */
    const uint8_t *sk_er;                 /* SK_er (decrypt response); sk_e_len bytes (16/24/32; 0 = legacy 32) */
    size_t         sk_e_len;
    const uint8_t *sk_ar;                 /* sk_a_len -- integ response */
    const uint8_t *sk_pr;                 /* prf_len  -- MACedIDForR    */

    /* Negotiated IKE suite primitives (resolved by the caller from weirdike_ike_suite_t). */
    ike_prf_fn     prf;           /* PRF: MACedID + AUTH + AUTH-payload length */
    size_t         prf_len;       /* 32 (SHA256) / 64 (SHA512) */
    ike_prf_fn     integ;         /* INTEG HMAC for the SK{} ICV */
    size_t         integ_out_len; /* INTEG HMAC full output (== sk_a_len) */
    size_t         icv_len;       /* transmitted ICV (16 / 32) */
    size_t         sk_a_len;      /* SK_ar length (INTEG key length) */

    const uint8_t *psk;        size_t psk_len;         /* PSK, or the EAP MSK for the final round; may be
                                                        * NULL in EAP rounds (then method-2 AUTH is not
                                                        * verified, only captured) */
    const uint8_t *real_msg2;  size_t real_msg2_len;   /* verbatim SA_INIT response */
    const uint8_t *ni;         size_t ni_len;          /* our nonce */
    uint32_t       msg_id;                             /* expected Message ID (0 -> 1, the classic IKE_AUTH) */
} ike_auth_verify_in_t;

/* Returns 0 if the message was well-formed and decrypted (consult *out for the two results; its
 * views point into ws->inner), or -1 if it could not be interpreted safely (outer header mismatch,
 * ICV/decrypt failure, malformed inner chain, unknown critical payload, duplicate required
 * payload). On -1, *out is zeroed and ws->inner wiped. */
int ike_verify_auth_response(const weirdike_crypto_t *cr, const ike_auth_verify_in_t *in,
                             const uint8_t *msg, size_t msg_len,
                             ike_auth_scratch_t *ws, ike_auth_response_t *out);

/* TS payload body -> one IPv4 selector. 1 = filled, 0 = unsupported shape, -1 = malformed. Shared
 * with the CREATE_CHILD_SA parser (ike_rekey.c). */
int ike_ts_parse(const uint8_t *b, size_t n, weirdike_ts_t *ts);
/* E2: all IPv4 selectors of a TS payload (up to cap; further ones ignored). 1 = at least one, 0 = none
 * usable, -1 = malformed. Selector types other than IPv4 address range are skipped. */
int ike_ts_parse_list(const uint8_t *b, size_t n, weirdike_ts_t *list, size_t cap, size_t *count);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_IKE_AUTH_RESP_H */
