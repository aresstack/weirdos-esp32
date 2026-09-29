/*
 * WeirdIKE -- src/core/ike_info.c : INFORMATIONAL inner-payload wire (RFC 7296 3.11). Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ike_info.h"
#include "ike_wire.h"   /* IKE_PL_NONE, IKE_PROTO_IKE */
#include <string.h>

/* Generic payload header: NextPayload(1) | Critical+Reserved(1) | PayloadLength(2, incl. header). */
#define GEN_HDR 4

int ike_info_build_empty(uint8_t *first_payload) {
    if (first_payload) *first_payload = IKE_PL_NONE;
    return 0;
}

/* DELETE payload body (RFC 7296 3.11): Protocol ID(1) | SPI Size(1) | Num SPIs(2) | SPIs. */
static int build_delete(uint8_t *inner, size_t cap, uint8_t proto, uint8_t spi_size,
                        const uint8_t *spi, uint8_t *first_payload) {
    size_t body = 4u + (size_t)spi_size * (spi_size ? 1u : 0u);   /* one SPI when spi_size>0 */
    size_t total = GEN_HDR + body;
    if (!inner || cap < total) return -1;
    inner[0] = IKE_PL_NONE;                     /* NextPayload: this is the only/last inner payload */
    inner[1] = 0;                               /* not critical */
    inner[2] = (uint8_t)(total >> 8); inner[3] = (uint8_t)total;
    inner[4] = proto;
    inner[5] = spi_size;
    uint16_t num = spi_size ? 1u : 0u;
    inner[6] = (uint8_t)(num >> 8); inner[7] = (uint8_t)num;
    if (spi_size) { if (!spi) return -1; memcpy(inner + 8, spi, spi_size); }
    if (first_payload) *first_payload = IKE_PL_DELETE;
    return (int)total;
}

int ike_info_build_delete_ike(uint8_t *inner, size_t cap, uint8_t *first_payload) {
    return build_delete(inner, cap, (uint8_t)IKE_PROTO_IKE, 0, NULL, first_payload);
}

int ike_info_build_delete_esp(uint8_t *inner, size_t cap, const uint8_t spi[4], uint8_t *first_payload) {
    return build_delete(inner, cap, (uint8_t)IKE_PROTO_ESP_ID, 4, spi, first_payload);
}

int ike_info_parse_inner(uint8_t first_payload, const uint8_t *inner, size_t len,
                         ike_info_content_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (len == 0) { out->is_empty = (first_payload == IKE_PL_NONE); return first_payload == IKE_PL_NONE ? 0 : -1; }
    if (!inner) return -1;

    uint8_t next = first_payload;
    size_t off = 0;
    while (next != IKE_PL_NONE) {
        if (off + GEN_HDR > len) return -1;                 /* header must fit */
        uint8_t  this_type = next;
        uint8_t  nxt       = inner[off + 0];
        uint16_t plen      = (uint16_t)((inner[off + 2] << 8) | inner[off + 3]);
        if (plen < GEN_HDR || off + plen > len) return -1;  /* length sane + in-bounds */

        if (this_type == IKE_PL_DELETE) {
            if (plen < GEN_HDR + 4) return -1;
            uint8_t  proto    = inner[off + 4];
            uint8_t  spi_size = inner[off + 5];
            uint16_t num      = (uint16_t)((inner[off + 6] << 8) | inner[off + 7]);
            size_t   need     = (size_t)GEN_HDR + 4u + (size_t)spi_size * num;
            if (plen < need) return -1;                     /* declared SPIs must fit the payload */
            if (proto == IKE_PROTO_IKE) {
                if (spi_size != 0) return -1;               /* IKE-SA delete carries no SPI */
                out->delete_ike = 1;
            } else if (proto == IKE_PROTO_ESP_ID) {
                if (spi_size != 4) return -1;               /* ESP SPI is 4 bytes */
                out->delete_esp = 1;
                for (uint16_t i = 0; i < num && out->esp_spi_count < IKE_INFO_MAX_ESP_SPI; i++) {
                    memcpy(out->esp_spi[out->esp_spi_count], inner + off + 8 + (size_t)i * 4, 4);
                    out->esp_spi_count++;
                }
            } else {
                out->other_payloads = 1;                    /* AH or unknown proto -> not acted on */
            }
        } else {
            out->other_payloads = 1;                        /* NOTIFY / CP / etc. -- tolerated, ignored */
        }

        next = nxt;
        off += plen;
    }
    /* A chain that consumed exactly `len` is well-formed; trailing garbage is not. */
    if (off != len) return -1;
    return 0;
}
