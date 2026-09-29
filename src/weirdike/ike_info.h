/*
 * WeirdIKE -- src/core/ike_info.h : INFORMATIONAL inner-payload wire (RFC 7296 1.4 / 3.11).
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Pure, crypto-free build/parse of the payloads that live INSIDE the SK{} of an INFORMATIONAL
 * exchange. The SK{} envelope (IKE header + encrypt-then-MAC) is composed in weirdike.c via
 * ike_sk_seal/open -- this module only knows the cleartext inner chain, so it is bounds-checked and
 * host-testable without any crypto.
 *
 *   empty INFORMATIONAL          -> DPD / liveness probe (no inner payloads)
 *   DELETE (Protocol ID = IKE)   -> tear down the whole IKE SA (SPI Size 0, Num SPIs 0)
 *   DELETE (Protocol ID = ESP)   -> tear down a Child SA (SPI Size 4; the sender lists the SPI(s) it
 *                                    expects in its OWN inbound ESP packets)
 */
#ifndef WEIRDIKE_IKE_INFO_H
#define WEIRDIKE_IKE_INFO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IKE_EXCHANGE_INFORMATIONAL 37
#define IKE_PL_DELETE              42
#define IKE_PROTO_ESP_ID           3   /* Protocol ID in a DELETE payload for a Child (ESP) SA */
/* IKE_PROTO_IKE (1) is defined in ike_wire.h */

#define IKE_INFO_MAX_ESP_SPI 4   /* how many ESP SPIs we retain from a received DELETE */

/* --- Build the inner chain (what gets sealed inside SK{}) ---------------------------------------
 * Each writes into `inner` (capacity cap) and returns the byte length (>=0), or -1 on bad args /
 * overflow. *first_payload receives the value for the SK payload's NextPayload field (the type of
 * the first inner payload, or 0 = NONE for an empty message). */

/* Empty INFORMATIONAL (DPD). inner_len = 0, *first_payload = 0. */
int ike_info_build_empty(uint8_t *first_payload);

/* One DELETE payload for the IKE SA (Protocol IKE, SPI Size 0, Num SPIs 0). 8 bytes. */
int ike_info_build_delete_ike(uint8_t *inner, size_t cap, uint8_t *first_payload);

/* One DELETE payload for a Child SA (Protocol ESP, SPI Size 4, Num SPIs 1, the given 4-byte SPI). */
int ike_info_build_delete_esp(uint8_t *inner, size_t cap, const uint8_t spi[4], uint8_t *first_payload);

/* --- Parse the inner chain of a received INFORMATIONAL ------------------------------------------ */
typedef struct {
    int     is_empty;                              /* no inner payloads at all -> DPD request/ack */
    int     delete_ike;                            /* a DELETE with Protocol ID = IKE present */
    int     delete_esp;                            /* a DELETE with Protocol ID = ESP present */
    int     esp_spi_count;                         /* number of ESP SPIs captured (<= MAX) */
    uint8_t esp_spi[IKE_INFO_MAX_ESP_SPI][4];      /* the peer's inbound ESP SPIs it wants deleted */
    int     other_payloads;                        /* saw a payload type we do not act on (e.g. NOTIFY) */
} ike_info_content_t;

/* Walk the generic-payload chain. first_payload = the SK NextPayload value (type of the first inner
 * payload). Returns 0 on a well-formed chain (even if empty), -1 on a malformed/overflowing chain. */
int ike_info_parse_inner(uint8_t first_payload, const uint8_t *inner, size_t len,
                         ike_info_content_t *out);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_IKE_INFO_H */
