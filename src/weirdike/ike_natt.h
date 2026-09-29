/*
 * WeirdIKE -- src/core/ike_natt.h : NAT-T (UDP-4500) framing + RX demux (RFC 3948 / RFC 7296 2.23).
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * On UDP/4500 three kinds of datagram share the port:
 *   IKE           : 00 00 00 00 (non-ESP marker) | IKE message
 *   ESP           : SPI | Seq | IV | ciphertext | ICV        (SPI is never 0 -> no marker)
 *   NAT keepalive : a single 0xFF byte
 *
 * The 4-byte non-ESP marker is a TRANSPORT wrapper only: it is NOT part of the IKE message and must
 * never enter IKE Length / ICV / AUTH transcripts. This module is pure framing/classification; it
 * holds no state and does no crypto.
 */
#ifndef WEIRDIKE_IKE_NATT_H
#define WEIRDIKE_IKE_NATT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NATT_NON_ESP_MARKER_LEN 4
#define NATT_KEEPALIVE_BYTE     0xFF

typedef enum {
    NATT_DATAGRAM_MALFORMED = 0,
    NATT_DATAGRAM_IKE,        /* non-ESP marker present; the IKE message follows at payload_off */
    NATT_DATAGRAM_ESP,        /* ESP packet (SPI != 0); payload_off = 0 */
    NATT_DATAGRAM_KEEPALIVE   /* single 0xFF byte */
} natt_datagram_t;

/* Prepend the 4-byte non-ESP marker to an IKE message for UDP/4500. Returns the total datagram
 * length, or -1 on bad args / buffer too small. */
int natt_wrap_ike(uint8_t *out, size_t out_cap, const uint8_t *ike, size_t ike_len);

/* Classify a UDP/4500 datagram. For NATT_DATAGRAM_IKE sets *payload_off = 4 (skip the marker before
 * parsing the IKE message); for ESP sets *payload_off = 0. payload_off may be NULL. */
natt_datagram_t natt_classify(const uint8_t *dg, size_t len, size_t *payload_off);

/* Write the single-byte NAT keepalive (0xFF). Returns 1, or -1 if out_cap < 1. */
int natt_make_keepalive(uint8_t *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_IKE_NATT_H */
