/*
 * WeirdIKE -- src/core/ike_wire.h : RFC 7296 wire constants + IKE_SA_INIT encoder (M1a).
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Flat-buffer encoder (no CycloneTCP NetBuffer). This is an INDEPENDENT implementation of the
 * RFC 7296 wire format (written to the RFC, not copied from CycloneIPSEC -- see PROVENANCE.md).
 * The FSM computes KE/Ni/NAT-D via the crypto adapter and calls the builder; parsing is in ike_parse.
 */
#ifndef WEIRDIKE_IKE_WIRE_H
#define WEIRDIKE_IKE_WIRE_H

#include <stdint.h>
#include <stddef.h>
#include "weirdike.h"    /* weirdike_ike_policy_t */
#include "ike_suite.h"   /* weirdike_ike_suite_t  */

#ifdef __cplusplus
extern "C" {
#endif

/* IKE header */
#define IKE_VERSION            0x20   /* major 2, minor 0 */
#define IKE_EXCHANGE_SA_INIT   34
#define IKE_EXCHANGE_AUTH      35
#define IKE_FLAG_INITIATOR     0x08
#define IKE_FLAG_RESPONSE      0x20
#define IKE_HDR_LEN            28

/* Payload types */
#define IKE_PL_NONE   0
#define IKE_PL_SA     33
#define IKE_PL_KE     34
#define IKE_PL_NONCE  40
#define IKE_PL_NOTIFY 41
#define IKE_PL_SK     46   /* Encrypted and Authenticated payload */

/* Transform types + IDs used by the encoders/parsers */
#define IKE_TRANSFORM_ENCR   1
#define IKE_TRANSFORM_PRF    2
#define IKE_TRANSFORM_INTEG  3
#define IKE_TRANSFORM_DH     4
#define IKE_PROTO_IKE        1
#define IKE_DH_MODP2048_ID   14   /* MODP2048 (KE encoders for more groups: weirdike_dh_pub_len) */

/* Notify message types */
#define IKE_NOTIFY_NAT_DETECTION_SOURCE_IP        16388
#define IKE_NOTIFY_NAT_DETECTION_DESTINATION_IP   16389

/* Build an IKE_SA_INIT request (initiator). The SA payload is ONE proposal generated from `policy`
 * (a NORMALIZED weirdike_ike_policy_t: every allowed ENCR/PRF/INTEG/DH transform, grouped by type).
 * spi_i    : our 8-byte Initiator SPI (Responder SPI is 0 in the request).
 * ke_pub   : our DH public value for policy->dh[0]; MUST be exactly 256 bytes (MODP2048 only today).
 * nonce    : Ni.
 * natd_src / natd_dst : 20-byte SHA-1 NAT-D hashes; pass NULL for BOTH to omit NAT-D (no NAT-T).
 * Returns the total message length written to out, or -1 on error (bad args/policy/buffer). */
int ike_build_sa_init_request(uint8_t *out, size_t out_cap,
                              const uint8_t spi_i[8],
                              const weirdike_ike_policy_t *policy,
                              const uint8_t *ke_pub, size_t ke_pub_len,
                              const uint8_t *nonce, size_t nonce_len,
                              const uint8_t *natd_src, const uint8_t *natd_dst);
/* I2: the same request repeated with the responder's COOKIE as the first payload (RFC 7296 2.6). */
int ike_build_sa_init_request_cookie(uint8_t *out, size_t out_cap,
                                     const uint8_t spi_i[8],
                                     const weirdike_ike_policy_t *policy,
                                     const uint8_t *ke_pub, size_t ke_pub_len,
                                     const uint8_t *nonce, size_t nonce_len,
                                     const uint8_t *natd_src, const uint8_t *natd_dst,
                                     const uint8_t *cookie, size_t cookie_len);

/* Same, but an IKE_SA_INIT RESPONSE (Response flag, Responder SPI set) carrying exactly the one
 * `selected` suite. Used by a responder role and by tests (round-trip / policy negatives). */
int ike_build_sa_init_response(uint8_t *out, size_t out_cap,
                               const uint8_t spi_i[8], const uint8_t spi_r[8],
                               const weirdike_ike_suite_t *selected,
                               const uint8_t *ke_pub, size_t ke_pub_len,
                               const uint8_t *nonce, size_t nonce_len,
                               const uint8_t *natd_src, const uint8_t *natd_dst);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_IKE_WIRE_H */
