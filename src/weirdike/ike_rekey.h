/*
 * WeirdIKE -- src/core/ike_rekey.h : CREATE_CHILD_SA wire (RFC 7296 1.3 / 2.8 / 2.18). Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Crypto-free build/parse of the payloads INSIDE the SK{} of a CREATE_CHILD_SA exchange. The FSM
 * (weirdike.c) owns the envelope (ike_sk), the timers, the DH handles and the key derivation.
 *
 *   Child rekey request  : N(REKEY_SA: ESP, old inbound SPI) | SA(ESP offer, new SPI) | Ni | [KEi] | TSi | TSr
 *   Child rekey response : SA(ESP selection, new SPI)        | Nr | [KEr] | TSi | TSr
 *   IKE-SA rekey request : SA(IKE offer, new SPIi)           | Ni | KEi
 *   IKE-SA rekey response: SA(IKE selection, new SPIr)       | Nr | KEr
 *   error response       : N(NO_ADDITIONAL_SAS) / N(CHILD_SA_NOT_FOUND) / N(INVALID_KE_PAYLOAD, group)
 *
 * Offers come from the NORMALIZED policies (every allowed transform); a selection has exactly one
 * transform per type. PFS = a D-H transform in the ESP proposal + a KE payload (RFC 7296 2.8).
 */
#ifndef WEIRDIKE_IKE_REKEY_H
#define WEIRDIKE_IKE_REKEY_H

#include <stdint.h>
#include <stddef.h>
#include "weirdike.h"     /* policies, weirdike_ts_t */
#include "ike_suite.h"    /* weirdike_ike_suite_t */

#ifdef __cplusplus
extern "C" {
#endif

#define IKE_EXCHANGE_CREATE_CHILD_SA   36
#define IKE_NOTIFY_INVALID_KE_PAYLOAD  17
#define IKE_NOTIFY_NO_ADDITIONAL_SAS   35
#define IKE_NOTIFY_CHILD_SA_NOT_FOUND  44
#define IKE_NOTIFY_TEMPORARY_FAILURE   43   /* RFC 7296 2.25: cannot serve this rekey/close right now, retry later */
#define IKE_NOTIFY_INVALID_SYNTAX      7
#define IKE_NOTIFY_REKEY_SA            16393

#define IKE_REKEY_MAX_TRANSFORMS 16    /* per type, bounded parse of a peer OFFER */

/* ---- builders (inner chain only; return length >= 0 or -1) ------------------------------------ */

/* Child-SA rekey/create REQUEST. old_inbound_spi != NULL adds N(REKEY_SA) first. pfs_group != 0 adds
 * a D-H transform to the proposal and the KE payload (ke_pub 256 B, MODP2048 only today). */
int ike_build_child_rekey_request(uint8_t *out, size_t cap,
                                  const uint8_t *old_inbound_spi,           /* 4 or NULL */
                                  const uint8_t new_spi[4],
                                  const weirdike_child_policy_t *policy,
                                  const uint8_t *nonce, size_t nonce_len,
                                  uint16_t pfs_group, const uint8_t *ke_pub, size_t ke_pub_len,
                                  const weirdike_ts_t *ts_i, const weirdike_ts_t *ts_r,
                                  uint8_t *first_payload);

/* E2 variants with additional TSr selectors (ts_r_extra/n_ts_r_extra; NULL/0 = single). */
int ike_build_child_rekey_request_ex(uint8_t *out, size_t cap, const uint8_t *old_inbound_spi, const uint8_t new_spi[4],
                                  const weirdike_child_policy_t *policy, const uint8_t *nonce, size_t nonce_len,
                                  uint16_t pfs_group, const uint8_t *ke_pub, size_t ke_pub_len,
                                  const weirdike_ts_t *ts_i, const weirdike_ts_t *ts_r,
                                  const weirdike_ts_t *ts_r_extra, size_t n_ts_r_extra, uint8_t *first_payload);
int ike_build_child_rekey_response_ex(uint8_t *out, size_t cap, const uint8_t new_spi[4],
                                   uint16_t encr, uint16_t encr_bits, uint16_t integ,
                                   const uint8_t *nonce, size_t nonce_len,
                                   uint16_t pfs_group, const uint8_t *ke_pub, size_t ke_pub_len,
                                   const weirdike_ts_t *ts_i, const weirdike_ts_t *ts_r,
                                   const weirdike_ts_t *ts_r_extra, size_t n_ts_r_extra, uint8_t *first_payload);

/* Child-SA rekey/create RESPONSE with a single selection (we answer a peer-initiated exchange). */
int ike_build_child_rekey_response(uint8_t *out, size_t cap,
                                   const uint8_t new_spi[4],
                                   uint16_t encr, uint16_t encr_bits, uint16_t integ,
                                   const uint8_t *nonce, size_t nonce_len,
                                   uint16_t pfs_group, const uint8_t *ke_pub, size_t ke_pub_len,
                                   const weirdike_ts_t *ts_i, const weirdike_ts_t *ts_r,
                                   uint8_t *first_payload);

/* IKE-SA rekey REQUEST/RESPONSE: SA(IKE proposal with 8-byte SPI) | Nonce | KE. For the request
 * `policy` (offer) is used; for the response `selected` (one transform per type). */
int ike_build_ike_rekey_request(uint8_t *out, size_t cap, const uint8_t new_spi_i[8],
                                const weirdike_ike_policy_t *policy,
                                const uint8_t *nonce, size_t nonce_len,
                                const uint8_t *ke_pub, size_t ke_pub_len, uint8_t *first_payload);
int ike_build_ike_rekey_response(uint8_t *out, size_t cap, const uint8_t new_spi_r[8],
                                 const weirdike_ike_suite_t *selected,
                                 const uint8_t *nonce, size_t nonce_len,
                                 const uint8_t *ke_pub, size_t ke_pub_len, uint8_t *first_payload);

/* A lone notify (error response). spi may be NULL (SPI size 0). data optional (e.g. 2-byte group). */
int ike_build_notify_only(uint8_t *out, size_t cap, uint8_t proto, const uint8_t *spi, size_t spi_len,
                          uint16_t type, const uint8_t *data, size_t data_len, uint8_t *first_payload);

/* ---- parser (request OR response, ESP or IKE proposal) ------------------------------------------ */
typedef struct {
    int      rekey_sa;                 /* N(REKEY_SA) present */
    uint8_t  rekey_spi[4];             /* ...its ESP SPI (the sender's inbound SPI being replaced) */
    int      sa_present;               /* an SA payload was parsed */
    int      sa_is_ike;                /* proposal Protocol ID = IKE (8-byte SPI) else ESP (4-byte) */
    uint8_t  spi[4];                   /* ESP SPI of the proposal */
    uint8_t  ike_spi[8];               /* IKE SPI of the proposal */
    /* Every transform in the (single) proposal, per type -- an OFFER may carry several, a SELECTION
     * exactly one of each required type. */
    weirdike_encr_t encr[IKE_REKEY_MAX_TRANSFORMS]; size_t n_encr;
    uint16_t integ[IKE_REKEY_MAX_TRANSFORMS];       size_t n_integ;
    uint16_t prf[IKE_REKEY_MAX_TRANSFORMS];         size_t n_prf;
    uint16_t dh[IKE_REKEY_MAX_TRANSFORMS];          size_t n_dh;
    int      esn_none;                 /* an ESN=NO_ESN transform present (ESP) */
    int      esn_other;                /* an ESN != NO_ESN offered (we never select it) */
    int      have_nonce; uint8_t nonce[256]; size_t nonce_len;
    int      have_ke;    uint16_t ke_group; uint8_t ke[WEIRDIKE_KE_MAX]; size_t ke_len;
    int      tsi_ok, tsr_ok; weirdike_ts_t tsi, tsr;
    weirdike_ts_t tsr_list[WEIRDIKE_TS_MAX]; size_t n_tsr;   /* E2: full TSr set (tsr == tsr_list[0]) */
    uint16_t error_notify;             /* first error-class notify (0 = none) */
    uint16_t invalid_ke_group;         /* group demanded by INVALID_KE_PAYLOAD (0 = none) */
} ike_create_child_msg_t;

/* Walk the inner chain. 0 = well-formed (consult fields), -1 = malformed / unknown critical. */
int ike_parse_create_child_inner(uint8_t first_payload, const uint8_t *inner, size_t len,
                                 ike_create_child_msg_t *out);

/* Pick the first offered ESP ENCR/INTEG (and D-H if the offer has one) that the child policy allows
 * (+ build capability). NO_ESN must be offered. Returns 1 and fills the selection, 0 if nothing
 * acceptable. dh_out = 0 when the offer carries no D-H transform (no PFS). */
int ike_select_child_offer(const ike_create_child_msg_t *m, const weirdike_child_policy_t *policy,
                           int want_pfs_group,
                           uint16_t *encr, uint16_t *encr_bits, uint16_t *integ, uint16_t *dh_out);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_IKE_REKEY_H */
