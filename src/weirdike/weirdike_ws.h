/*
 * WeirdIKE -- src/core/weirdike_ws.h : the WORKSPACE block (internal layout). Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * One block per context, placed by the host (caller-owned or via the memory provider), lifetime =
 * the context. Inside it, REGIONS have shorter LOGICAL lifetimes; the core owns those and wipes a
 * region when its lifetime ends. Nothing here is ever addressed from another context.
 *
 *   persistent_large  (lifetime: IKE SA, or until ESTABLISHED for the transcript)
 *     sa_init_req / sa_init_resp   RealMessage1/2, verbatim: IKE_SA_INIT retransmit + the signed
 *                                  octets of EVERY IKE_AUTH round (EAP: several) -> kept until the
 *                                  IKE SA is ESTABLISHED, then wiped.
 *     ca_pem                       configuration copy (the caller need not keep its buffer alive).
 *     sa[slot].req                 the ONE outstanding request of that IKE SA, verbatim, for
 *                                  retransmits (IKE_AUTH rounds, INFORMATIONAL, CREATE_CHILD_SA).
 *     sa[slot].resp                the response to the peer's last request N, verbatim, replayed
 *                                  on a retransmit of N; released once request N+1 was processed
 *                                  (window size 1 -- see weirdike.h).
 *   scratch  (lifetime: ONE call into the core; never valid across weirdike_poll/input calls)
 *     rx_plain                     decrypted SK{} inner payloads of the datagram being handled.
 *                                  Parser VIEWS ({ptr,len}) point here and die with the call.
 *     tx_inner                     inner payload chain being built for a message.
 *     tx_msg                       the sealed datagram being sent (+ NAT-T marker room).
 *     crypto                       key-exchange / signed-octets / EAP scratch (secret -> wiped).
 *
 * Non-reentrancy: the core is single-threaded per context; each region has exactly one owner per
 * nesting level. With WEIRDIKE_WS_GUARD the owners are checked at runtime (selftests/CI).
 */
#ifndef WEIRDIKE_WS_H
#define WEIRDIKE_WS_H

#include <stdint.h>
#include <stddef.h>
#include "weirdike.h"
#include "ike_sk.h"          /* IKE_SK_MAX_MSG */
#include "ike_natt.h"        /* NATT_NON_ESP_MARKER_LEN */
#include "ike_auth.h"        /* IKE_AUTH_MAC_MAX */

#ifdef __cplusplus
extern "C" {
#endif

/* Signed octets: RealMessage | nonce(<=256) | MACedID(<=IKE_AUTH_MAC_MAX). */
#define WEIRDIKE_WS_SIGNED_OCTETS_MAX (WEIRDIKE_MAX_IKE_MSG + 256 + IKE_AUTH_MAC_MAX)

struct weirdike_ws {
    /* ---- persistent_large ---- */
    uint8_t  sa_init_req[WEIRDIKE_MAX_IKE_MSG];   size_t sa_init_req_len;
    uint8_t  sa_init_resp[WEIRDIKE_MAX_IKE_MSG];  size_t sa_init_resp_len;
    char     ca_pem[WEIRDIKE_MAX_CA_PEM];         size_t ca_pem_len;      /* trust anchors */
    char     extra_pem[WEIRDIKE_MAX_EXTRA_PEM];   size_t extra_pem_len;   /* chain material only */
    struct {
        uint8_t req[WEIRDIKE_MAX_IKE_MSG];  size_t req_len;    /* our outstanding request (retransmit) */
        uint8_t resp[WEIRDIKE_MAX_IKE_MSG]; size_t resp_len;   /* cached response to the peer's last request */
    } sa[WEIRDIKE_IKE_SA_SLOTS];

    /* ---- scratch ---- */
    uint8_t  rx_msg[WEIRDIKE_MAX_IKE_MSG + NATT_NON_ESP_MARKER_LEN];    /* datagram from transport->recv */
    uint8_t  rx_plain[IKE_SK_MAX_MSG];                          /* decrypted inner payloads (views) */
    uint8_t  tx_inner[WEIRDIKE_MAX_IKE_MSG];                    /* inner chain under construction */
    uint8_t  tx_msg[WEIRDIKE_MAX_IKE_MSG + NATT_NON_ESP_MARKER_LEN];   /* sealed datagram (+ marker) */
    /* Crypto scratch: separate fields on purpose (no union) -- an EAP round builds eap_pkt while
     * the signed octets of the same message may still be needed; aliasing would be a silent bug. */
    struct {
        uint8_t ke_pub[WEIRDIKE_KE_MAX];                        /* our D-H public value (up to MODP4096) */
        uint8_t gir[WEIRDIKE_KE_MAX];                           /* shared secret (wiped after KDF) */
        uint8_t signed_octets[WEIRDIKE_WS_SIGNED_OCTETS_MAX];   /* AUTH input (wiped after use) */
        uint8_t eap_pkt[768];                                   /* EAP packet under construction */
    } crypto;

    /* ---- guard (debug builds) ---- */
    uint32_t in_use;   /* WEIRDIKE_WS_* bits of the regions currently owned by a call frame */
};

/* Region ids for the runtime guard. */
enum {
    WEIRDIKE_WS_RX_PLAIN = 1u << 0,
    WEIRDIKE_WS_TX_INNER = 1u << 1,
    WEIRDIKE_WS_TX_MSG   = 1u << 2,
    WEIRDIKE_WS_CRYPTO   = 1u << 3
};

/* Runtime ownership guard (selftests/CI build with -DWEIRDIKE_WS_GUARD): taking a region that is
 * already owned by an outer frame aborts -- that is exactly the aliasing bug this design forbids.
 * Production builds compile to nothing. */
#ifdef WEIRDIKE_WS_GUARD
#include <assert.h>
#define WS_TAKE(c, bit) do { assert(((c)->ws->in_use & (uint32_t)(bit)) == 0); (c)->ws->in_use |= (uint32_t)(bit); } while (0)
#define WS_GIVE(c, bit) do { (c)->ws->in_use &= ~(uint32_t)(bit); } while (0)
#else
#define WS_TAKE(c, bit) ((void)0)
#define WS_GIVE(c, bit) ((void)0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_WS_H */
