/*
 * WeirdIKE -- src/core/ike_auth_resp.c : IKE_AUTH response verifier (M2b-4b). RFC 7296.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ike_auth_resp.h"
#include "ike_auth.h"        /* ike_psk_auth */
#include "ike_auth_wire.h"   /* IKE_PL_IDR/AUTH/TSI/TSR, IKE_PROTO_ESP, IKE_TRANSFORM_ESN, IKE_TS_* */
#include "ike_sk.h"
#include "ike_wire.h"        /* IKE header/payload constants, IKE_TRANSFORM_ENCR/PRF/INTEG/DH */
#include <string.h>

#define SK_HDR_LEN 4
#define NOTIFY_ERROR_MAX 16384      /* types < 16384 are error-class (RFC 7296 3.10.1) */

static unsigned be16(const uint8_t *p) { return (unsigned)((p[0] << 8) | p[1]); }
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void wipe(void *p, size_t n) { volatile uint8_t *v = (volatile uint8_t *)p; while (n--) *v++ = 0; }
static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0; for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]); return d == 0;
}

/* Parse an ESP SAr2 proposal body. Returns 1 (structurally acceptable: single ESP proposal #1,
 * 4-byte non-reserved SPI, exactly one ENCR [with at most one TV KEY_LENGTH attribute], one INTEG,
 * one ESN = NO_ESN, nothing else; *spi and the selected IDs set), 0 (well-formed but not such a
 * selection), or -1 (malformed lengths). Transform ORDER is not assumed: transforms are counted by
 * type. Algorithm IDs are reported, not judged -- the FSM checks them against the child policy. */
static int sar2_parse(const uint8_t *b, size_t n, uint8_t spi_out[4],
                      uint16_t *encr_out, uint16_t *bits_out, uint16_t *integ_out) {
    if (n < 8) return -1;
    unsigned last = b[0], plen = be16(b + 2), pnum = b[4], proto = b[5], spisz = b[6], ntr = b[7];
    if (plen != n) return -1;                 /* single proposal spanning the whole SA body */
    if (last != 0) return 0;                  /* more than one selected proposal -> not ours */
    if (pnum != 1 || proto != IKE_PROTO_ESP || spisz != 4) return 0;
    if (8u + 4u > plen) return -1;
    memcpy(spi_out, b + 8, 4);
    /* Reserved ESP SPI 0..255 must never be selected. */
    if (spi_out[0] == 0 && spi_out[1] == 0 && spi_out[2] == 0) return 0;

    size_t off = 12;
    int encr = 0, integ = 0, esn = 0, other = 0;
    unsigned encr_id = 0, encr_bits = 0, integ_id = 0;
    for (unsigned i = 0; i < ntr; i++) {
        if (off + 8 > plen) return -1;
        unsigned tlast = b[off], tlen = be16(b + off + 2), ttype = b[off + 4], tid = be16(b + off + 6);
        /* Lenient more/last (RFC 7296 3.3.2 says 0 or 3): the FRITZ!Box sends 0 for every transform.
         * Iteration is bounded by ntr + tlen and validated by the final off==plen consumption check. */
        if (tlast != 0 && tlast != 3) return -1;
        if (tlen < 8 || off + tlen > plen) return -1;
        size_t alen = (size_t)tlen - 8;
        if (ttype == IKE_TRANSFORM_ENCR) {
            if (alen != 0 && alen != 4) return 0;             /* at most one TV attribute */
            if (alen == 4) {
                if (b[off+8] != 0x80 || b[off+9] != 0x0E) return 0;   /* must be KEY_LENGTH */
                encr_bits = be16(b + off + 10);
                if (encr_bits == 0) return 0;
            }
            encr_id = tid;
            encr++;
        } else if (ttype == IKE_TRANSFORM_INTEG) {
            if (alen != 0) return 0;
            integ_id = tid;
            integ++;
        } else if (ttype == IKE_TRANSFORM_ESN) {
            if (tid != 0 || alen != 0) return 0;              /* NO_ESN only (data plane has no ESN) */
            esn++;
        } else {
            other++;                                          /* PRF/DH/unknown -> not an ESP selection */
        }
        off += tlen;
    }
    if (off != plen) return -1;
    if (!(encr == 1 && integ == 1 && esn == 1 && other == 0)) return 0;
    *encr_out = (uint16_t)encr_id; *bits_out = (uint16_t)encr_bits; *integ_out = (uint16_t)integ_id;
    return 1;
}

/* Parse a TS payload body carrying exactly one IPv4 selector. Returns 1 (+*ts filled), 0
 * (unsupported: not exactly one IPv4 selector), or -1 (malformed lengths). Exported for the
 * CREATE_CHILD_SA parser (ike_rekey.c). */
/* E2: walk every selector of the payload (RFC 7296 3.13.1: Number of TSs, then selectors of
 * varying types/lengths). IPv4 address ranges are collected (up to cap); other types are skipped
 * (an IPv6 selector from a dual-stack responder must not break the IPv4 Child SA). */
int ike_ts_parse_list(const uint8_t *b, size_t n, weirdike_ts_t *list, size_t cap, size_t *count) {
    if (!b || !list || !count) return -1;
    *count = 0;
    if (n < 4) return -1;
    unsigned num = b[0];
    if (num == 0) return 0;
    size_t off = 4;
    for (unsigned k = 0; k < num; k++) {
        if (off + 4 > n) return -1;
        const uint8_t *s = b + off;
        unsigned slen = be16(s + 2);
        if (slen < 8 || off + slen > n) return -1;                  /* selector header + bounds */
        if (s[0] == IKE_TS_IPV4_ADDR_RANGE) {
            if (slen != 16) return -1;
            if (*count < cap) {
                weirdike_ts_t *ts = &list[*count];
                memset(ts, 0, sizeof(*ts));
                ts->address_family = 4;
                ts->ip_protocol = s[1];
                ts->start_port = (uint16_t)be16(s + 4);
                ts->end_port   = (uint16_t)be16(s + 6);
                memcpy(ts->start_addr, s + 8, 4);
                memcpy(ts->end_addr,   s + 12, 4);
                if (ts->start_port <= ts->end_port && memcmp(ts->start_addr, ts->end_addr, 4) <= 0) (*count)++;
            }
        }
        off += slen;
    }
    if (off != n) return -1;
    return *count ? 1 : 0;
}

int ike_ts_parse(const uint8_t *b, size_t n, weirdike_ts_t *ts) {
    weirdike_ts_t list[WEIRDIKE_TS_MAX]; size_t cnt = 0;
    int r = ike_ts_parse_list(b, n, list, WEIRDIKE_TS_MAX, &cnt);
    if (r == 1 && ts) *ts = list[0];
    return r;
}

int ike_verify_auth_response(const weirdike_crypto_t *cr, const ike_auth_verify_in_t *in,
                             const uint8_t *msg, size_t msg_len,
                             ike_auth_scratch_t *ws, ike_auth_response_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!cr || !cr->aes_cbc || !in || !msg || !ws || !ws->inner || !ws->so) return -1;
    if (!in->prf || !in->integ || in->prf_len == 0 || in->prf_len > IKE_AUTH_MAC_MAX ||
        in->sk_a_len == 0 || in->integ_out_len == 0 || in->icv_len == 0) return -1;
    if (!in->spi_i || !in->spi_r || !in->sk_er || !in->sk_ar || !in->sk_pr ||
        !in->real_msg2 || !in->ni) return -1;          /* psk may be NULL in EAP rounds (AP7) */
    if (in->real_msg2_len == 0 || in->real_msg2_len > WEIRDIKE_MAX_IKE_MSG) return -1;
    if (in->ni_len == 0 || in->ni_len > 256) return -1;
    if (ws->inner_cap < IKE_SK_MAX_MSG || ws->so_cap < in->real_msg2_len + in->ni_len + in->prf_len) return -1;

    /* ---- outer IKE header ---- */
    if (msg_len < (size_t)IKE_HDR_LEN + SK_HDR_LEN) return -1;
    if (memcmp(msg, in->spi_i, 8) != 0 || memcmp(msg + 8, in->spi_r, 8) != 0) return -1;
    if (msg[16] != IKE_PL_SK) return -1;
    if ((msg[17] & 0xF0) != 0x20) return -1;
    if (msg[18] != IKE_EXCHANGE_AUTH) return -1;
    if (!(msg[19] & IKE_FLAG_RESPONSE) || (msg[19] & IKE_FLAG_INITIATOR)) return -1;
    if (be32(msg + 20) != (in->msg_id ? in->msg_id : 1u)) return -1;   /* Message ID (1 classic; N in EAP rounds) */
    if (be32(msg + 24) != msg_len) return -1;                 /* Length == datagram */

    /* ---- SK generic header (its Next is the first inner payload type) ---- */
    uint8_t first_type = msg[IKE_HDR_LEN];
    if (be16(msg + IKE_HDR_LEN + 2) != msg_len - IKE_HDR_LEN) return -1;

    /* ---- decrypt into the caller's scratch (ICV verified before decrypt, inside ike_sk_open) ---- */
    uint8_t *inner = ws->inner;
    size_t   inner_len = 0;
    if (ike_sk_open(cr->aes_cbc, cr->ctx, in->integ, cr->ctx, in->integ_out_len, in->icv_len,
                    in->sk_er, in->sk_e_len ? in->sk_e_len : 32, in->sk_ar, in->sk_a_len,
                    msg, msg_len, IKE_HDR_LEN + SK_HDR_LEN, inner, ws->inner_cap, &inner_len) != 0)
        return -1;

    /* ---- walk the inner payload chain ---- */
    const uint8_t *idr_prime = NULL; size_t idr_prime_len = 0;
    uint8_t idr_type = 0; const uint8_t *idr_data = NULL; size_t idr_data_len = 0;
    const uint8_t *auth_data = NULL; int auth_usable = 0;
    int sa_ok = 0, tsi_ok = 0, tsr_ok = 0;
    uint8_t child_spi[4] = { 0 }; weirdike_ts_t tsi, tsr;
    weirdike_ts_t tsr_list[WEIRDIKE_TS_MAX]; size_t n_tsr_list = 0;                    /* E2 */
    uint16_t child_encr = 0, child_bits = 0, child_integ = 0;
    memset(&tsi, 0, sizeof(tsi)); memset(&tsr, 0, sizeof(tsr));
    int n_idr = 0, n_auth = 0, n_sa = 0, n_tsi = 0, n_tsr = 0;
    int rc = -1;

    size_t off = 0;
    uint8_t type = first_type;
    while (type != IKE_PL_NONE) {
        if (off + 4 > inner_len) goto done;
        uint8_t  p_next = inner[off];
        int      p_crit = (inner[off + 1] & 0x80) != 0;
        unsigned p_len  = be16(inner + off + 2);
        if (p_len < 4 || off + p_len > inner_len) goto done;
        const uint8_t *body = inner + off + 4;
        size_t body_len = (size_t)p_len - 4;

        switch (type) {
            case IKE_PL_IDR:
                if (++n_idr > 1) goto done;
                if (body_len < 4) goto done;
                idr_prime = body; idr_prime_len = body_len;      /* VERBATIM (incl. reserved bytes) */
                idr_type = body[0]; idr_data = body + 4; idr_data_len = body_len - 4;
                break;
            case IKE_PL_AUTH:
                if (++n_auth > 1) goto done;
                if (body_len < 4) goto done;
                if (body[0] == IKE_AUTH_METHOD_SHARED_KEY && body_len == 4 + in->prf_len) {
                    auth_data = body + 4; auth_usable = 1;       /* prf_len-byte Shared-Key AUTH */
                }
                /* AP7: expose any method's raw AUTH data to the FSM (signature methods 1/14) -- a VIEW. */
                out->have_auth = 1;
                out->auth_method = body[0];
                out->auth_data.ptr = body + 4; out->auth_data.len = body_len - 4;
                break;
            case IKE_PL_CERT: {
                if (body_len < 1) goto done;
                /* first CERT = leaf, second = intermediate; further ones ignored (bounded) -- views */
                if (out->cert.len == 0) {
                    out->cert_encoding = body[0];
                    out->cert.ptr = body + 1; out->cert.len = body_len - 1;
                } else if (out->cert2.len == 0 && body[0] == out->cert_encoding) {
                    out->cert2.ptr = body + 1; out->cert2.len = body_len - 1;
                }
                break;
            }
            case IKE_PL_EAP:
                if (out->eap.len) goto done;                     /* exactly one EAP payload */
                if (body_len < 4) goto done;
                out->eap.ptr = body; out->eap.len = body_len;
                break;
            case IKE_PL_CP:
                if (out->cp.len) goto done;
                out->cp.ptr = inner + off; out->cp.len = p_len;  /* generic header included */
                break;
            case IKE_PL_SA: {
                if (++n_sa > 1) goto done;
                int r = sar2_parse(body, body_len, child_spi, &child_encr, &child_bits, &child_integ);
                if (r < 0) goto done;                            /* malformed */
                sa_ok = (r == 1);
                break;
            }
            case IKE_PL_TSI: {
                if (++n_tsi > 1) goto done;
                int r = ike_ts_parse(body, body_len, &tsi);
                if (r < 0) goto done;
                tsi_ok = (r == 1);
                break;
            }
            case IKE_PL_TSR: {
                if (++n_tsr > 1) goto done;
                int r = ike_ts_parse_list(body, body_len, tsr_list, WEIRDIKE_TS_MAX, &n_tsr_list);   /* E2: all selectors */
                if (r < 0) goto done;
                tsr_ok = (r == 1);
                if (tsr_ok) tsr = tsr_list[0];
                break;
            }
            case IKE_PL_NOTIFY: {
                if (body_len < 4) goto done;
                unsigned spisz = body[1];
                unsigned ntype = be16(body + 2);
                if ((size_t)4 + spisz > body_len) goto done;
                if (ntype < NOTIFY_ERROR_MAX && out->error_notify == 0)
                    out->error_notify = (uint16_t)ntype;         /* record, do NOT fail the exchange */
                break;
            }
            default:
                if (p_crit) goto done;                           /* unknown critical -> reject */
                break;                                           /* unknown non-critical -> skip */
        }
        off += p_len;
        type = p_next;
    }
    if (off != inner_len) goto done;

    rc = 0;   /* structurally interpretable from here on; results live in *out */
    out->have_sa = (n_sa == 1); out->have_tsi = (n_tsi == 1); out->have_tsr = (n_tsr == 1);

    /* ---- AP7: IDr' MAC for the FSM (signature methods verify the signed octets themselves) ---- */
    if (n_idr == 1 && idr_data_len <= WEIRDIKE_MAX_ID) {
        out->have_idr = 1;
        out->idr_type = idr_type; out->idr.ptr = idr_data; out->idr.len = idr_data_len;
        if (in->prf(cr->ctx, in->sk_pr, in->prf_len, idr_prime, idr_prime_len, out->maced_idr) == 0)
            out->maced_idr_len = in->prf_len;
    }

    /* ---- IKE authentication result (Shared Key method; key = PSK or the EAP MSK) ---- */
    if (n_idr == 1 && auth_usable && in->psk && idr_data_len <= WEIRDIKE_MAX_ID) {
        uint8_t maced[IKE_AUTH_MAC_MAX];
        /* MACedIDForR = prf(SK_pr, IDr' VERBATIM) -- IDr' taken as received (reserved bytes are signed);
         * NOT via ike_maced_id, which would re-zero the reserved bytes. */
        if (in->prf(cr->ctx, in->sk_pr, in->prf_len, idr_prime, idr_prime_len, maced) == 0) {
            uint8_t *so = ws->so;   /* signed octets assembled in the caller's scratch, wiped after use */
            size_t   so_len = 0;
            memcpy(so + so_len, in->real_msg2, in->real_msg2_len); so_len += in->real_msg2_len;
            memcpy(so + so_len, in->ni, in->ni_len);               so_len += in->ni_len;
            memcpy(so + so_len, maced, in->prf_len);               so_len += in->prf_len;
            uint8_t auth_exp[IKE_AUTH_MAC_MAX];
            if (ike_psk_auth(in->prf, cr->ctx, in->prf_len, in->psk, in->psk_len, so, so_len, auth_exp) == 0
                && ct_equal(auth_exp, auth_data, in->prf_len)) {
                out->ike_auth_ok = 1;
                out->idr_type = idr_type;
                out->idr.ptr = idr_data; out->idr.len = idr_data_len;
            }
            wipe(so, so_len); wipe(auth_exp, sizeof(auth_exp));
        }
        wipe(maced, sizeof(maced));
    }

    /* ---- Child-SA negotiation result (independent of ike_auth_ok) ---- */
    if (n_sa == 1 && sa_ok && n_tsi == 1 && tsi_ok && n_tsr == 1 && tsr_ok) {
        out->child_sa_ok = 1;
        memcpy(out->child_spi_r, child_spi, 4);
        out->child_encr = child_encr; out->child_encr_key_bits = child_bits; out->child_integ = child_integ;
        out->ts_i = tsi;
        out->ts_r = tsr;
        for (size_t i = 0; i < n_tsr_list; i++) out->ts_r_list[i] = tsr_list[i];   /* E2 */
        out->n_ts_r = n_tsr_list;
    }

done:
    /* Success: the views in *out point into ws->inner -- the caller owns that lifetime.
     * Failure: nothing of the message may survive. */
    if (rc != 0) { wipe(inner, inner_len); memset(out, 0, sizeof(*out)); }
    return rc;
}
