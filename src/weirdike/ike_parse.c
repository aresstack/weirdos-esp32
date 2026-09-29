/*
 * WeirdIKE -- src/core/ike_parse.c : IKE_SA_INIT response parser (M1d). RFC 7296.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ike_parse.h"
#include "ike_wire.h"

#include <string.h>

static unsigned be16(const uint8_t *p) { return (unsigned)((p[0] << 8) | p[1]); }
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Extract the SELECTED proposal from an SA-response body into *suite. STRUCTURE is enforced here
 * (RFC 7296 3.3): a single proposal spanning the whole SA body, Protocol=IKE, SPI size 0, exactly
 * one transform of each type ENCR/PRF/INTEG/DH consuming the proposal exactly, ENCR carrying at most
 * ONE attribute which must be the TV KEY_LENGTH (recorded as encr_key_bits; 0 when absent), no
 * attributes on PRF/INTEG/DH. ALGORITHM IDs are NOT judged here: whether the selection is inside the
 * configured policy (and implemented by this build) is decided by the FSM (ike_policy.c) -- the
 * parser stays link-independent and reports what the responder actually chose. Returns 1 (*suite
 * set) or 0 (malformed / not a single well-formed IKE selection). */
static int sa_select_suite(const uint8_t *b, size_t n, weirdike_ike_suite_t *suite) {
    if (n < 8) return 0;
    unsigned last    = b[0];         /* 0 = last */
    unsigned plen    = be16(b + 2);
    unsigned pnum    = b[4];
    unsigned proto   = b[5];
    unsigned spisize = b[6];
    unsigned ntrans  = b[7];
    if (last != 0)  return 0;        /* exactly one selected proposal */
    if (plen != n)  return 0;        /* proposal spans the whole SA body */
    if (pnum < 1)   return 0;        /* selected proposal number (we offer #1) */
    if (proto != IKE_PROTO_IKE) return 0;
    if (spisize != 0) return 0;
    if (ntrans != 4)  return 0;      /* exactly ENCR/PRF/INTEG/DH */

    size_t off = 8;
    int encr = 0, prf_n = 0, integ_n = 0, dh = 0;
    unsigned encr_id = 0, encr_bits = 0, prf_id = 0, integ_id = 0, dh_id = 0;
    for (unsigned i = 0; i < ntrans; i++) {
        if (off + 8 > plen) return 0;
        unsigned tlast = b[off];                       /* RFC 7296 3.3.2: 0 (last) or 3 (more) */
        unsigned tlen  = be16(b + off + 2);
        unsigned ttype = b[off + 4];
        unsigned tid   = be16(b + off + 6);
        /* Lenient: iterate by ntrans + tlen and only require the flag to be a legal value. The
         * FRITZ!Box sets this byte to 0 for EVERY transform (not 3 for the non-last ones), so do NOT
         * enforce the exact 3..3,0 chain -- `off == plen` at the end still proves exact consumption. */
        if (tlast != 0 && tlast != 3) return 0;
        if (tlen < 8 || off + tlen > plen) return 0;
        size_t alen = (size_t)tlen - 8;

        if (ttype == IKE_TRANSFORM_ENCR) {             /* optional single TV KEY_LENGTH attribute */
            if (alen != 0 && alen != 4) return 0;
            if (alen == 4) {
                if (b[off+8] != 0x80 || b[off+9] != 0x0E) return 0;   /* AF=1, type 14 */
                encr_bits = be16(b + off + 10);
                if (encr_bits == 0) return 0;
            }
            encr_id = tid;
            if (++encr > 1) return 0;
        } else if (ttype == IKE_TRANSFORM_PRF) {
            if (alen != 0) return 0;
            prf_id = tid;
            if (++prf_n > 1) return 0;
        } else if (ttype == IKE_TRANSFORM_INTEG) {
            if (alen != 0) return 0;
            integ_id = tid;
            if (++integ_n > 1) return 0;
        } else if (ttype == IKE_TRANSFORM_DH) {
            if (alen != 0) return 0;
            dh_id = tid;
            if (++dh > 1) return 0;
        } else {
            return 0;
        }
        off += tlen;
    }
    if (off != plen) return 0;       /* transforms consume the proposal exactly */
    if (!(encr == 1 && prf_n == 1 && integ_n == 1 && dh == 1)) return 0;

    suite->encr          = (weirdike_encr_id_t)encr_id;
    suite->encr_key_bits = (uint16_t)encr_bits;
    suite->prf           = (weirdike_prf_id_t)prf_id;
    suite->integ         = (weirdike_integ_id_t)integ_id;
    suite->dh            = (weirdike_dh_id_t)dh_id;
    return 1;
}

int ike_parse_sa_init_response(const uint8_t *msg, size_t len,
                               const uint8_t our_spi_i[8],
                               ike_sa_init_response_t *out) {
    if (!msg || !our_spi_i || !out) return IKE_PARSE_MALFORMED;
    memset(out, 0, sizeof(*out));

    if (len < (size_t)IKE_HDR_LEN) return IKE_PARSE_MALFORMED;
    if (memcmp(msg, our_spi_i, 8) != 0) return IKE_PARSE_NOT_FOR_US;

    /* Responder SPI is nonzero for a SUCCESS response, but an IKE_SA_INIT ERROR response
     * (NO_PROPOSAL_CHOSEN / INVALID_KE_PAYLOAD / COOKIE / ...) legitimately carries SPIr = 0 -- the
     * responder created no SA. So do NOT reject SPIr = 0 here; surface the error notify first and
     * require a nonzero SPIr only on the success path (below). */
    int spir_nonzero = 0;
    for (int i = 8; i < 16; i++) if (msg[i]) spir_nonzero = 1;

    uint8_t  first  = msg[16];
    uint8_t  ver    = msg[17];
    uint8_t  exch   = msg[18];
    uint8_t  flags  = msg[19];
    uint32_t msgid  = be32(msg + 20);
    uint32_t mlen   = be32(msg + 24);

    if ((ver & 0xF0) != 0x20) return IKE_PARSE_MALFORMED;          /* IKE major version 2 */
    if (exch != IKE_EXCHANGE_SA_INIT) return IKE_PARSE_MALFORMED;
    if (!(flags & IKE_FLAG_RESPONSE) || (flags & IKE_FLAG_INITIATOR)) return IKE_PARSE_MALFORMED;
    if (msgid != 0) return IKE_PARSE_MALFORMED;
    /* The IKE header Length MUST equal the datagram: RealMessage2 has no trailing bytes (transport
     * framing such as a UDP-4500 non-ESP marker is stripped before us). Keeps the transcript exact. */
    if ((size_t)mlen != len) return IKE_PARSE_MALFORMED;

    memcpy(out->spi_r, msg + 8, 8);

    size_t  off  = IKE_HDR_LEN;
    uint8_t type = first;
    int sa = 0, ke = 0, nonce = 0;

    while (type != IKE_PL_NONE) {
        if (off + 4 > mlen) return IKE_PARSE_MALFORMED;
        uint8_t  p_next = msg[off];
        int      p_crit = (msg[off + 1] & 0x80) != 0;
        unsigned p_len  = be16(msg + off + 2);
        if (p_len < 4 || off + p_len > mlen) return IKE_PARSE_MALFORMED;
        const uint8_t *body = msg + off + 4;
        size_t body_len = (size_t)p_len - 4;

        switch (type) {
            case IKE_PL_SA:
                if (++sa > 1) return IKE_PARSE_MALFORMED;
                out->proposal_ok = sa_select_suite(body, body_len, &out->suite);
                break;
            case IKE_PL_KE: {
                if (++ke > 1) return IKE_PARSE_MALFORMED;
                if (body_len < 4) return IKE_PARSE_MALFORMED;
                unsigned group = be16(body);
                size_t   kelen = body_len - 4;
                /* B2/B3: any supported group; the KE length is fixed per group (RFC 3526 / 5903 / 8031) */
                if (weirdike_dh_pub_len((uint16_t)group) == 0 || kelen != weirdike_dh_pub_len((uint16_t)group)) return IKE_PARSE_MALFORMED;
                out->peer_ke = body + 4;   /* view into the datagram */
                out->peer_ke_len = kelen;
                out->peer_ke_group = (uint16_t)group;
                break;
            }
            case IKE_PL_NONCE:
                if (++nonce > 1) return IKE_PARSE_MALFORMED;
                if (body_len < 16 || body_len > 256) return IKE_PARSE_MALFORMED;
                out->nr = body;            /* view into the datagram */
                out->nr_len = body_len;
                break;
            case IKE_PL_NOTIFY: {
                if (body_len < 4) return IKE_PARSE_MALFORMED;
                unsigned spisize = body[1];
                unsigned ntype   = be16(body + 2);
                if ((size_t)4 + spisize > body_len) return IKE_PARSE_MALFORMED;
                const uint8_t *ndata = body + 4 + spisize;
                size_t ndlen = body_len - 4 - spisize;
                if (ntype < 16384) {
                    out->error_notify = (uint16_t)ntype;
                    /* AP5.6: INVALID_KE_PAYLOAD carries the 2-byte D-H group the responder demands. */
                    if (ntype == 17 && ndlen == 2) out->invalid_ke_group = (uint16_t)be16(ndata);
                    return IKE_PARSE_PEER_ERROR;
                }
                if (ntype == IKE_NOTIFY_NAT_DETECTION_SOURCE_IP && ndlen == 20) {
                    if (out->natd_src_count >= IKE_MAX_NATD_SOURCES) return IKE_PARSE_MALFORMED;  /* limit */
                    memcpy(out->natd_src[out->natd_src_count++], ndata, 20);
                } else if (ntype == 16390 && ndlen >= 1 && ndlen <= sizeof(out->cookie)) {   /* I2: COOKIE */
                    memcpy(out->cookie, ndata, ndlen); out->cookie_len = ndlen;
                } else if (ntype == IKE_NOTIFY_NAT_DETECTION_DESTINATION_IP && ndlen == 20) {
                    if (out->natd_dst_present) return IKE_PARSE_MALFORMED;   /* exactly one destination */
                    memcpy(out->natd_dst, ndata, 20); out->natd_dst_present = 1;
                }
                /* other status notifies: ignore */
                break;
            }
            default:
                if (p_crit) return IKE_PARSE_MALFORMED;   /* unknown CRITICAL payload */
                /* unknown non-critical: skip */
                break;
        }

        off += p_len;
        type = p_next;
    }

    if (out->cookie_len && sa == 0 && ke == 0 && nonce == 0) return IKE_PARSE_COOKIE;   /* I2: cookie challenge only */
    if (sa != 1 || ke != 1 || nonce != 1) return IKE_PARSE_MALFORMED;
    if (!spir_nonzero) return IKE_PARSE_MALFORMED;   /* a valid SA response needs a real Responder SPI */
    /* RFC 7296: a NAT-T supporter sends >=1 SOURCE and exactly one DESTINATION together. Source
     * present without destination (or vice-versa) is inconsistent. */
    if ((out->natd_src_count > 0) != (out->natd_dst_present != 0)) return IKE_PARSE_MALFORMED;
    return IKE_PARSE_OK;
}
