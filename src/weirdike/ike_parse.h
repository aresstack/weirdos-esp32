/*
 * WeirdIKE -- src/core/ike_parse.h : IKE_SA_INIT response parser (M1d). RFC 7296.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Independent RFC 7296 implementation (see PROVENANCE.md). Follows the Next-Payload chain, checks
 * all bounds, requires SA/KE/Nonce exactly once, evaluates NAT-D notifies, skips unknown
 * NON-critical payloads and rejects unknown CRITICAL ones -- so a real strongSwan response with
 * extra optional notifies still parses.
 */
#ifndef WEIRDIKE_IKE_PARSE_H
#define WEIRDIKE_IKE_PARSE_H

#include <stdint.h>
#include <stddef.h>
#include "ike_suite.h"   /* weirdike_ike_suite_t (the negotiated IKE suite) */

#ifdef __cplusplus
extern "C" {
#endif

/* RFC 7296 allows MULTIPLE NAT_DETECTION_SOURCE_IP notifies (sender may not know its egress iface).
 * A bounded array is MCU-friendly; more than this is rejected as a resource limit. */
#define IKE_MAX_NATD_SOURCES 4

typedef struct {
    uint8_t spi_r[8];
    /* VIEWS into the datagram being parsed (valid for the call that received it; the FSM copies
     * what it keeps -- no 512 B of duplicates on the stack). */
    const uint8_t *peer_ke;  size_t peer_ke_len;
    uint16_t peer_ke_group;   /* D-H group carried in the KE payload (must equal the one we sent) */
    const uint8_t *nr;       size_t nr_len;
    uint8_t natd_src[IKE_MAX_NATD_SOURCES][20];
    size_t  natd_src_count;
    int     natd_dst_present;
    uint8_t natd_dst[20];
    int     proposal_ok;    /* SA carried ONE well-formed IKE selection (structure only, see ike_parse.c) */
    weirdike_ike_suite_t suite;   /* what the responder SELECTED (valid iff proposal_ok); the FSM checks
                                   * it against the configured policy + build capability */
    uint16_t error_notify;  /* set to the type when IKE_PARSE_PEER_ERROR is returned (else 0) */
    uint16_t invalid_ke_group; /* AP5.6: group demanded by INVALID_KE_PAYLOAD (valid iff error_notify == 17) */
    /* I2: N(COOKIE) challenge (RFC 7296 2.6): the responder answered with only a COOKIE notify; the
     * initiator repeats IKE_SA_INIT with that cookie as the first payload. */
    uint8_t  cookie[64]; size_t cookie_len;
} ike_sa_init_response_t;

#define IKE_PARSE_OK           0
#define IKE_PARSE_NOT_FOR_US  -1   /* SPIi mismatch -> ignore (not our SA) */
#define IKE_PARSE_MALFORMED   -2   /* bad header/bounds/unknown-critical/missing required payload */
#define IKE_PARSE_PEER_ERROR  -3   /* responder sent an error-class Notify (e.g. NO_PROPOSAL_CHOSEN) */
#define IKE_PARSE_COOKIE      -4   /* I2: responder demands a COOKIE (out->cookie); repeat IKE_SA_INIT with it */

int ike_parse_sa_init_response(const uint8_t *msg, size_t len,
                               const uint8_t our_spi_i[8],
                               ike_sa_init_response_t *out);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_IKE_PARSE_H */
