/*
 * WeirdIKE -- src/core/ike_wire.c : IKE_SA_INIT request encoder (M1a). RFC 7296.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Proposal-policy slice: the SA payload is generated from a weirdike_ike_policy_t (allow-lists per
 * transform type) -- ONE proposal carrying every allowed transform (RFC 7296 3.3.1: several
 * transforms of the same type inside one proposal are alternatives). Nothing about algorithms is
 * hard-coded here any more; the RESPONSE variant encodes exactly one selected suite.
 */
#include "ike_wire.h"
#include "ike_suite.h"   /* weirdike_dh_pub_len (header-only) */
#include "ike_policy.h"

#define NATD_HASH_LEN 20

/* Bounds-checked big-endian writer. */
typedef struct { uint8_t *p; size_t cap; size_t n; int err; } wbuf;
static void w8 (wbuf *b, uint8_t v)  { if (b->n + 1 > b->cap) { b->err = 1; return; } b->p[b->n++] = v; }
static void w16(wbuf *b, uint16_t v) { w8(b, (uint8_t)(v >> 8)); w8(b, (uint8_t)v); }
static void w32(wbuf *b, uint32_t v) { w8(b, (uint8_t)(v >> 24)); w8(b, (uint8_t)(v >> 16));
                                       w8(b, (uint8_t)(v >> 8));  w8(b, (uint8_t)v); }
static void wbytes(wbuf *b, const uint8_t *s, size_t n) { for (size_t i = 0; i < n; i++) w8(b, s[i]); }

/* One transform substructure. `more` = 3 if another transform follows, 0 for the last one. */
static void write_transform(wbuf *b, uint8_t more, uint8_t type, uint16_t id, uint16_t key_bits) {
    w8(b, more); w8(b, 0);
    w16(b, key_bits ? IKE_TRANSFORM_KEYLEN_LEN : IKE_TRANSFORM_PLAIN_LEN);
    w8(b, type); w8(b, 0); w16(b, id);
    if (key_bits) { w16(b, 0x800E); w16(b, key_bits); }   /* attr: AF=1 | type 14 (KEY_LENGTH) */
}

/* Length of the proposal substructure (8-byte header + transforms) for a policy. */
static size_t ike_proposal_len(const weirdike_ike_policy_t *p) {
    size_t n = 8;
    for (size_t i = 0; i < p->n_encr; i++) n += ike_encr_transform_len(&p->encr[i]);
    n += (p->n_prf + p->n_integ + p->n_dh) * IKE_TRANSFORM_PLAIN_LEN;
    return n;
}

/* One IKE proposal (Proposal #1, Protocol IKE, SPI size 0) with ALL transforms of the policy,
 * grouped by type: ENCR*, PRF*, INTEG*, DH*. `last` byte 0 = the only proposal. */
static void write_ike_proposal(wbuf *b, const weirdike_ike_policy_t *p) {
    size_t total = p->n_encr + p->n_prf + p->n_integ + p->n_dh;
    size_t k = 0;
    w8(b, 0);                                  /* last proposal */
    w8(b, 0);                                  /* reserved */
    w16(b, (uint16_t)ike_proposal_len(p));     /* Proposal Length */
    w8(b, 1);                                  /* Proposal Num */
    w8(b, IKE_PROTO_IKE);                      /* Protocol ID = IKE */
    w8(b, 0);                                  /* SPI Size = 0 */
    w8(b, (uint8_t)total);                     /* Num Transforms */
    for (size_t i = 0; i < p->n_encr;  i++, k++) write_transform(b, (k + 1 < total) ? 3 : 0, IKE_TRANSFORM_ENCR,  p->encr[i].id, p->encr[i].key_bits);
    for (size_t i = 0; i < p->n_prf;   i++, k++) write_transform(b, (k + 1 < total) ? 3 : 0, IKE_TRANSFORM_PRF,   p->prf[i], 0);
    for (size_t i = 0; i < p->n_integ; i++, k++) write_transform(b, (k + 1 < total) ? 3 : 0, IKE_TRANSFORM_INTEG, p->integ[i], 0);
    for (size_t i = 0; i < p->n_dh;    i++, k++) write_transform(b, (k + 1 < total) ? 3 : 0, IKE_TRANSFORM_DH,    p->dh[i], 0);
}

static int policy_lists_ok(const weirdike_ike_policy_t *p) {
    return p && p->n_encr >= 1 && p->n_encr <= WEIRDIKE_POLICY_MAX &&
           p->n_prf   >= 1 && p->n_prf   <= WEIRDIKE_POLICY_MAX &&
           p->n_integ >= 1 && p->n_integ <= WEIRDIKE_POLICY_MAX &&
           p->n_dh    >= 1 && p->n_dh    <= WEIRDIKE_POLICY_MAX;
}

/* Common IKE_SA_INIT assembler: header | SA(one proposal from `p`) | KE | Nonce | [NAT-D x2]. */
static int build_sa_init(uint8_t *out, size_t out_cap,
                         const uint8_t spi_i[8], const uint8_t spi_r[8], uint8_t flags,
                         const weirdike_ike_policy_t *p,
                         const uint8_t *ke_pub, size_t ke_pub_len,
                         const uint8_t *nonce, size_t nonce_len,
                         const uint8_t *natd_src, const uint8_t *natd_dst,
                         const uint8_t *cookie, size_t cookie_len) {
    if (!out || !spi_i || !ke_pub || !nonce) return -1;
    if (cookie_len > 64 || (cookie_len && !cookie)) return -1;   /* I2: N(COOKIE) first (RFC 7296 2.6) */
    if (!policy_lists_ok(p)) return -1;
    /* The KE payload carries the FIRST allowed DH group (RFC 7296 2.7: initiator guesses); its
     * public value has the group's fixed length (B2/B3: MODP2048/3072/4096, ECP, X25519). */
    if (weirdike_dh_pub_len(p->dh[0]) == 0 || ke_pub_len != weirdike_dh_pub_len(p->dh[0])) return -1;
    if (nonce_len < 16 || nonce_len > 256) return -1;   /* RFC 7296: 16..256 bytes */
    int natd = (natd_src != NULL && natd_dst != NULL);
    if ((natd_src != NULL) != (natd_dst != NULL)) return -1;  /* both or neither */

    const uint16_t sa_len       = (uint16_t)(4 + ike_proposal_len(p));
    const uint16_t ke_len       = (uint16_t)(4 + 4 + ke_pub_len);   /* generic header + group + reserved + KE data */
    const uint16_t nonce_pl_len = (uint16_t)(4 + nonce_len);
    const uint16_t natd_pl_len  = 4 + 4 + NATD_HASH_LEN; /* = 28 */
    const uint16_t cookie_pl_len = (uint16_t)(cookie_len ? 8 + cookie_len : 0);   /* I2 */
    const uint32_t total = (uint32_t)(IKE_HDR_LEN + cookie_pl_len + sa_len + ke_len + nonce_pl_len
                                      + (natd ? 2 * natd_pl_len : 0));
    if (out_cap < total) return -1;

    wbuf b = { out, out_cap, 0, 0 };

    /* ---- IKE header (28) ---- */
    wbytes(&b, spi_i, 8);                 /* Initiator SPI */
    if (spi_r) wbytes(&b, spi_r, 8); else for (int i = 0; i < 8; i++) w8(&b, 0);
    w8(&b, (uint8_t)(cookie_len ? IKE_PL_NOTIFY : IKE_PL_SA));   /* Next Payload */
    w8(&b, IKE_VERSION);
    w8(&b, IKE_EXCHANGE_SA_INIT);
    w8(&b, flags);
    w32(&b, 0);                           /* Message ID = 0 */
    w32(&b, total);                       /* Length */

    /* ---- I2: N(COOKIE) as the FIRST payload of a repeated request (RFC 7296 2.6) ---- */
    if (cookie_len) {
        w8(&b, IKE_PL_SA); w8(&b, 0); w16(&b, cookie_pl_len);
        w8(&b, 0); w8(&b, 0);             /* Protocol ID = 0, SPI Size = 0 */
        w16(&b, 16390);                   /* COOKIE */
        wbytes(&b, cookie, cookie_len);
    }

    /* ---- SA payload (type 33): one proposal from the policy ---- */
    w8(&b, IKE_PL_KE);                    /* Next Payload = KE */
    w8(&b, 0);                            /* critical/reserved */
    w16(&b, sa_len);
    write_ike_proposal(&b, p);

    /* ---- KE payload (type 34) ---- */
    w8(&b, IKE_PL_NONCE);                 /* Next Payload = Nonce */
    w8(&b, 0);
    w16(&b, ke_len);
    w16(&b, p->dh[0]);                    /* DH Group Num (first allowed group) */
    w16(&b, 0);                           /* reserved */
    wbytes(&b, ke_pub, ke_pub_len);

    /* ---- Nonce payload (type 40) ---- */
    w8(&b, (uint8_t)(natd ? IKE_PL_NOTIFY : IKE_PL_NONE));
    w8(&b, 0);
    w16(&b, nonce_pl_len);
    wbytes(&b, nonce, nonce_len);

    /* ---- NAT-D notifies (type 41) ---- */
    if (natd) {
        /* SOURCE */
        w8(&b, IKE_PL_NOTIFY); w8(&b, 0); w16(&b, natd_pl_len);
        w8(&b, 0); w8(&b, 0);             /* Protocol ID = 0, SPI Size = 0 */
        w16(&b, IKE_NOTIFY_NAT_DETECTION_SOURCE_IP);
        wbytes(&b, natd_src, NATD_HASH_LEN);
        /* DESTINATION (last payload) */
        w8(&b, IKE_PL_NONE); w8(&b, 0); w16(&b, natd_pl_len);
        w8(&b, 0); w8(&b, 0);
        w16(&b, IKE_NOTIFY_NAT_DETECTION_DESTINATION_IP);
        wbytes(&b, natd_dst, NATD_HASH_LEN);
    }

    if (b.err || b.n != total) return -1;
    return (int)total;
}

int ike_build_sa_init_request(uint8_t *out, size_t out_cap,
                              const uint8_t spi_i[8],
                              const weirdike_ike_policy_t *policy,
                              const uint8_t *ke_pub, size_t ke_pub_len,
                              const uint8_t *nonce, size_t nonce_len,
                              const uint8_t *natd_src, const uint8_t *natd_dst) {
    return build_sa_init(out, out_cap, spi_i, NULL, IKE_FLAG_INITIATOR, policy,
                         ke_pub, ke_pub_len, nonce, nonce_len, natd_src, natd_dst, NULL, 0);
}

int ike_build_sa_init_request_cookie(uint8_t *out, size_t out_cap,
                                     const uint8_t spi_i[8],
                                     const weirdike_ike_policy_t *policy,
                                     const uint8_t *ke_pub, size_t ke_pub_len,
                                     const uint8_t *nonce, size_t nonce_len,
                                     const uint8_t *natd_src, const uint8_t *natd_dst,
                                     const uint8_t *cookie, size_t cookie_len) {
    return build_sa_init(out, out_cap, spi_i, NULL, IKE_FLAG_INITIATOR, policy,
                         ke_pub, ke_pub_len, nonce, nonce_len, natd_src, natd_dst, cookie, cookie_len);
}

int ike_build_sa_init_response(uint8_t *out, size_t out_cap,
                               const uint8_t spi_i[8], const uint8_t spi_r[8],
                               const weirdike_ike_suite_t *selected,
                               const uint8_t *ke_pub, size_t ke_pub_len,
                               const uint8_t *nonce, size_t nonce_len,
                               const uint8_t *natd_src, const uint8_t *natd_dst) {
    if (!selected) return -1;
    /* A selected suite is a policy with exactly one entry per list. */
    weirdike_ike_policy_t one;
    one.encr[0].id = selected->encr; one.encr[0].key_bits = selected->encr_key_bits; one.n_encr = 1;
    one.prf[0]   = selected->prf;   one.n_prf   = 1;
    one.integ[0] = selected->integ; one.n_integ = 1;
    one.dh[0]    = selected->dh;    one.n_dh    = 1;
    return build_sa_init(out, out_cap, spi_i, spi_r, IKE_FLAG_RESPONSE, &one,
                         ke_pub, ke_pub_len, nonce, nonce_len, natd_src, natd_dst, NULL, 0);
}
