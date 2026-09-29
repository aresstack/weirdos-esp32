/*
 * WeirdIKE -- src/core/ike_natt.c : NAT-T (UDP-4500) framing + RX demux.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ike_natt.h"
#include <string.h>

int natt_wrap_ike(uint8_t *out, size_t out_cap, const uint8_t *ike, size_t ike_len) {
    if (!out || !ike || ike_len == 0) return -1;
    if (ike_len > (size_t)0x7fffffff) return -1;
    if (out_cap < (size_t)NATT_NON_ESP_MARKER_LEN + ike_len) return -1;
    out[0] = 0; out[1] = 0; out[2] = 0; out[3] = 0;   /* non-ESP marker */
    memcpy(out + NATT_NON_ESP_MARKER_LEN, ike, ike_len);
    return (int)(NATT_NON_ESP_MARKER_LEN + ike_len);
}

natt_datagram_t natt_classify(const uint8_t *dg, size_t len, size_t *payload_off) {
    if (payload_off) *payload_off = 0;
    if (!dg) return NATT_DATAGRAM_MALFORMED;

    if (len == 1 && dg[0] == NATT_KEEPALIVE_BYTE) return NATT_DATAGRAM_KEEPALIVE;

    int first4_zero = (len >= NATT_NON_ESP_MARKER_LEN &&
                       dg[0] == 0 && dg[1] == 0 && dg[2] == 0 && dg[3] == 0);
    if (first4_zero) {
        /* Non-ESP marker -> IKE. An IKE header must follow (marker-only is malformed). */
        if (len <= (size_t)NATT_NON_ESP_MARKER_LEN) return NATT_DATAGRAM_MALFORMED;
        if (payload_off) *payload_off = NATT_NON_ESP_MARKER_LEN;
        return NATT_DATAGRAM_IKE;
    }

    /* Otherwise ESP: the first 4 bytes are a non-zero SPI. Require at least SPI+Seq. */
    if (len >= 8) return NATT_DATAGRAM_ESP;

    return NATT_DATAGRAM_MALFORMED;
}

int natt_make_keepalive(uint8_t *out, size_t out_cap) {
    if (!out || out_cap < 1) return -1;
    out[0] = NATT_KEEPALIVE_BYTE;
    return 1;
}
