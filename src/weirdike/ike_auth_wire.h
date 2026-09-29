/*
 * WeirdIKE -- src/core/ike_auth_wire.h : IKE_AUTH inner-payload encoder (M2b-3). RFC 7296. Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Serializes ONLY the inner payload chain that later goes inside the encrypted SK{} of an IKE_AUTH
 * request:  IDi | [IDr] | AUTH | SAi2 | TSi | TSr.  No IKE header, no Message ID, no SK{} wrap, no
 * crypto (the 32 AUTH bytes are injected precomputed by ike_auth). SK.Next is deterministically IDi.
 *
 * SAi2 is ONE Child proposal generated from the child policy: Proposal #1, ESP, SPI size 4 (the
 * inbound ESP SPI of the caller), every allowed ENCR transform, every allowed INTEG transform, then
 * an explicit NO_ESN. No PRF, no D-H (RFC 7296 forbids a real KE transform in the SA of IKE_AUTH).
 * TSi/TSr are one IPv4 selector each (TS_IPV4_ADDR_RANGE).
 */
#ifndef WEIRDIKE_IKE_AUTH_WIRE_H
#define WEIRDIKE_IKE_AUTH_WIRE_H

#include <stdint.h>
#include <stddef.h>
#include "weirdike.h"   /* weirdike_ts_t */

#ifdef __cplusplus
extern "C" {
#endif

/* Inner-chain payload types (RFC 7296) not already in ike_wire.h. */
#define IKE_PL_IDI    35
#define IKE_PL_IDR    36
#define IKE_PL_CERT   37
#define IKE_PL_CERTREQ 38
#define IKE_PL_AUTH   39
#define IKE_PL_TSI    44
#define IKE_PL_TSR    45
#define IKE_PL_CP     47
#define IKE_PL_EAP    48
#define IKE_CERT_X509_DER 4

#define IKE_PROTO_ESP           3
#define IKE_TRANSFORM_ESN       5    /* ESP Extended Sequence Numbers transform type */
#define IKE_ESN_NONE            0    /* No Extended Sequence Numbers */
#define IKE_TS_IPV4_ADDR_RANGE  7
#define IKE_AUTH_DATA_LEN       32   /* SHA256-128 AUTH size (default); SHA512 AUTH is 64 (auth_len) */
#define IKE_AUTH_DATA_MAX       64   /* HMAC-SHA512 full output */
#define IKE_CHILD_SPI_LEN        4

typedef struct {
    uint8_t        id_type;       /* IDi type (IANA), e.g. 1 = ID_IPV4_ADDR */
    const uint8_t *id_data;
    size_t         id_len;

    int            have_idr;      /* include an explicit IDr payload? */
    uint8_t        idr_type;
    const uint8_t *idr_data;
    size_t         idr_len;

    const uint8_t *auth;          /* precomputed AUTH bytes (from ike_psk_auth) */
    size_t         auth_len;      /* AUTH size = negotiated prf_len (32 SHA256 / 64 SHA512) */

    const uint8_t *child_spi_i;   /* IKE_CHILD_SPI_LEN inbound ESP SPI (caller-supplied) */
    const weirdike_child_policy_t *child_policy;   /* NORMALIZED allow-lists for SAi2 (required) */

    const weirdike_ts_t *ts_i;    /* TSi -- initiator side of the Child traffic */
    const weirdike_ts_t *ts_r;    /* TSr -- responder side */
    const weirdike_ts_t *ts_r_extra; size_t n_ts_r_extra;   /* E2: further TSr selectors (NULL/0 = single) */

    /* --- AP7 EAP first round (RFC 7296 2.16): omit AUTH (auth may be NULL), optionally add a
     * CERTREQ (X.509 DER, empty authority list = any CA) and a CP payload (built by ike_cp,
     * generic header included; its Next byte is rewritten here). Chain becomes
     * IDi | [IDr] | [CERTREQ] | [CP] | SAi2 | TSi | TSr. --- */
    int            omit_auth;
    int            add_certreq;
    const uint8_t *cp;            /* complete CP payload from ike_cp_build_ipv4_request, or NULL */
    size_t         cp_len;
} ike_auth_inner_t;

/* AP7: single-payload inner chains for the EAP rounds. */
int ike_build_eap_inner(const uint8_t *eap, size_t eap_len, uint8_t *out, size_t cap, size_t *len);
int ike_build_auth_only_inner(uint8_t method, const uint8_t *auth, size_t auth_len, uint8_t *out, size_t cap, size_t *len);

/* Serialize the inner payload chain into out (sets *len). IPv4-only TS in this slice; IPv6 TS is
 * rejected. Returns 0 on success, -1 on bad args / invalid TS / SPI / buffer too small. */
int ike_build_auth_inner(const ike_auth_inner_t *in, uint8_t *out, size_t cap, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_IKE_AUTH_WIRE_H */
