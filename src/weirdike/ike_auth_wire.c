/*
 * WeirdIKE -- src/core/ike_auth_wire.c : IKE_AUTH inner-payload encoder (M2b-3). RFC 7296.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ike_auth_wire.h"
#include "ike_wire.h"     /* IKE_PL_SA, IKE_PL_NONE, IKE_TRANSFORM_ENCR/INTEG, transform IDs */
#include "ike_auth.h"     /* IKE_AUTH_METHOD_SHARED_KEY */
#include "ike_policy.h"   /* IKE_TRANSFORM_*_LEN, ike_encr_transform_len (header-only use) */
#include <string.h>

/* Bounds-checked big-endian writer (same idiom as ike_wire.c; kept module-local). */
typedef struct { uint8_t *p; size_t cap; size_t n; int err; } wbuf;
static void w8 (wbuf *b, uint8_t v)  { if (b->n + 1 > b->cap) { b->err = 1; return; } b->p[b->n++] = v; }
static void w16(wbuf *b, uint16_t v) { w8(b, (uint8_t)(v >> 8)); w8(b, (uint8_t)v); }
static void wbytes(wbuf *b, const uint8_t *s, size_t n) { for (size_t i = 0; i < n; i++) w8(b, s[i]); }

/* An ID payload body is IDType(1) | 3 reserved | ID data. Only the ID types WeirdIKE supports
 * (matching weirdike_id_type_t) are accepted; length is bounded by the config-side WEIRDIKE_MAX_ID
 * so the encoder never rejects a value weirdike_init() already copied in. */
static int id_ok(uint8_t type, const uint8_t *data, size_t len) {
    if (!data || len == 0 || len > WEIRDIKE_MAX_ID) return 0;
    switch (type) {
        case 1:  return len == 4;   /* ID_IPV4_ADDR carries exactly 4 raw bytes */
        case 2:                     /* ID_FQDN        */
        case 3:                     /* ID_RFC822_ADDR */
        case 11: return 1;          /* ID_KEY_ID      */
        default: return 0;          /* unsupported ID type */
    }
}

/* ESP SPI values 0..255 are reserved (RFC 4303 / IANA) and must never appear on the wire. */
static int spi_ok(const uint8_t *spi) {
    return spi && !(spi[0] == 0 && spi[1] == 0 && spi[2] == 0);
}

/* One IPv4 traffic selector must be self-consistent (RFC 7296 3.13.1). IPv6 rejected in this slice. */
static int ts_ok(const weirdike_ts_t *ts) {
    if (!ts || ts->address_family != 4) return 0;
    if (ts->start_port > ts->end_port) return 0;
    if (ts->ip_protocol == 0 && (ts->start_port != 0 || ts->end_port != 65535)) return 0;
    if (memcmp(ts->start_addr, ts->end_addr, 4) > 0) return 0;   /* start <= end */
    return 1;
}

/* One 16-byte IPv4 selector. */
static void write_ts_sel(wbuf *b, const weirdike_ts_t *ts) {
    w8(b, IKE_TS_IPV4_ADDR_RANGE);               /* TS Type = 7 */
    w8(b, ts->ip_protocol);
    w16(b, 16);                                  /* Selector Length */
    w16(b, ts->start_port);
    w16(b, ts->end_port);
    wbytes(b, ts->start_addr, 4);
    wbytes(b, ts->end_addr, 4);
}
/* Write a TS payload (generic hdr | Number(1)+3 reserved | 1+n 16-byte IPv4 selectors). E2: the
 * extra selectors follow the first one (RFC 7296 3.13: several selectors per payload). */
static void write_ts(wbuf *b, uint8_t next, const weirdike_ts_t *ts, const weirdike_ts_t *extra, size_t n_extra) {
    w8(b, next); w8(b, 0); w16(b, (uint16_t)(8 + 16 * (1 + n_extra)));
    w8(b, (uint8_t)(1 + n_extra)); w8(b, 0); w8(b, 0); w8(b, 0);   /* Number of TSs, 3 reserved */
    write_ts_sel(b, ts);
    for (size_t i = 0; i < n_extra; i++) write_ts_sel(b, &extra[i]);
}

int ike_build_auth_inner(const ike_auth_inner_t *in, uint8_t *out, size_t cap, size_t *len) {
    if (!out || !len) return -1;
    *len = 0;
    if (!in) return -1;
    if (!in->omit_auth) {                                      /* AP7: EAP first round carries no AUTH */
        if (!in->auth) return -1;
        if (in->auth_len == 0 || in->auth_len > IKE_AUTH_DATA_MAX) return -1;
    }
    if (in->cp && (in->cp_len < 4 || in->cp_len > 512)) return -1;
    if (!spi_ok(in->child_spi_i)) return -1;                   /* rejects NULL and 0..255 */
    if (!id_ok(in->id_type, in->id_data, in->id_len)) return -1;
    if (in->have_idr && !id_ok(in->idr_type, in->idr_data, in->idr_len)) return -1;
    if (!ts_ok(in->ts_i) || !ts_ok(in->ts_r)) return -1;
    size_t n_extra = in->ts_r_extra ? in->n_ts_r_extra : 0;                       /* E2 */
    if (n_extra > WEIRDIKE_TS_MAX - 1) return -1;
    for (size_t i = 0; i < n_extra; i++) if (!ts_ok(&in->ts_r_extra[i])) return -1;
    const weirdike_child_policy_t *cp = in->child_policy;
    if (!cp || cp->n_encr < 1 || cp->n_encr > WEIRDIKE_POLICY_MAX ||
        cp->n_integ < 1 || cp->n_integ > WEIRDIKE_POLICY_MAX) return -1;

    /* Derived payload sizes. SAi2 proposal = 8 hdr + 4 SPI + ENCR* + INTEG* + ESN. */
    size_t prop_len = 8 + IKE_CHILD_SPI_LEN;
    for (size_t i = 0; i < cp->n_encr; i++) prop_len += ike_encr_transform_len(&cp->encr[i]);
    prop_len += cp->n_integ * IKE_TRANSFORM_PLAIN_LEN + IKE_TRANSFORM_PLAIN_LEN;
    const uint16_t idi_len  = (uint16_t)(4 + 4 + in->id_len);
    const uint16_t idr_len  = in->have_idr ? (uint16_t)(4 + 4 + in->idr_len) : 0;
    const uint16_t auth_len = in->omit_auth ? 0 : (uint16_t)(4 + 4 + in->auth_len);   /* 40 (SHA256) / 72 (SHA512) */
    const uint16_t creq_len = in->add_certreq ? 5 : 0;                /* generic hdr + Cert Encoding, no authorities */
    const uint16_t cp_len   = in->cp ? (uint16_t)in->cp_len : 0;
    const uint16_t sa_len   = (uint16_t)(4 + prop_len);            /* 44 for the default policy */
    const uint16_t ts_len   = 24;                                       /* TSi: one selector */
    const uint16_t tsr_len  = (uint16_t)(8 + 16 * (1 + n_extra));       /* TSr: 1 + extra selectors */
    const size_t   total    = (size_t)idi_len + idr_len + auth_len + creq_len + cp_len + sa_len + ts_len + tsr_len;
    if (cap < total) return -1;

    wbuf b = { out, cap, 0, 0 };

    /* Payload order: IDi | [IDr] | [AUTH] | [CERTREQ] | [CP] | SAi2 | TSi | TSr. Each Next byte
     * points at whatever comes next in this instance. */
    uint8_t after_idi = in->have_idr ? IKE_PL_IDR : (!in->omit_auth ? IKE_PL_AUTH : (in->add_certreq ? IKE_PL_CERTREQ : (in->cp ? IKE_PL_CP : IKE_PL_SA)));
    uint8_t after_idr = !in->omit_auth ? IKE_PL_AUTH : (in->add_certreq ? IKE_PL_CERTREQ : (in->cp ? IKE_PL_CP : IKE_PL_SA));
    uint8_t after_auth = in->add_certreq ? IKE_PL_CERTREQ : (in->cp ? IKE_PL_CP : IKE_PL_SA);
    uint8_t after_creq = in->cp ? IKE_PL_CP : IKE_PL_SA;

    /* ---- IDi (35) ---- */
    w8(&b, after_idi);   /* Next */
    w8(&b, 0); w16(&b, idi_len);
    w8(&b, in->id_type); w8(&b, 0); w8(&b, 0); w8(&b, 0);
    wbytes(&b, in->id_data, in->id_len);

    /* ---- IDr (36), optional ---- */
    if (in->have_idr) {
        w8(&b, after_idr); w8(&b, 0); w16(&b, idr_len);
        w8(&b, in->idr_type); w8(&b, 0); w8(&b, 0); w8(&b, 0);
        wbytes(&b, in->idr_data, in->idr_len);
    }

    /* ---- AUTH (39): Shared Key MIC, auth_len precomputed bytes (absent in the EAP first round) ---- */
    if (!in->omit_auth) {
        w8(&b, after_auth); w8(&b, 0); w16(&b, auth_len);
        w8(&b, IKE_AUTH_METHOD_SHARED_KEY); w8(&b, 0); w8(&b, 0); w8(&b, 0);
        wbytes(&b, in->auth, in->auth_len);
    }

    /* ---- CERTREQ (38): X.509 DER, empty Certification Authority list (= any trusted CA) ---- */
    if (in->add_certreq) {
        w8(&b, after_creq); w8(&b, 0); w16(&b, creq_len);
        w8(&b, IKE_CERT_X509_DER);
    }

    /* ---- CP (47): CFG_REQUEST built by ike_cp (generic header included; rewrite its Next) ---- */
    if (in->cp) {
        wbytes(&b, in->cp, in->cp_len);
        out[b.n - in->cp_len] = IKE_PL_SA;
    }

    /* ---- SAi2 (33): ESP, SPI size 4, ENCR* + INTEG* from the child policy + NO_ESN ---- */
    w8(&b, IKE_PL_TSI); w8(&b, 0); w16(&b, sa_len);
    /* Proposal substructure (last, reserved, length, num 1, ESP, SPI size 4, N transforms). */
    w8(&b, 0); w8(&b, 0); w16(&b, (uint16_t)prop_len);
    w8(&b, 1); w8(&b, IKE_PROTO_ESP); w8(&b, IKE_CHILD_SPI_LEN);
    w8(&b, (uint8_t)(cp->n_encr + cp->n_integ + 1));
    wbytes(&b, in->child_spi_i, IKE_CHILD_SPI_LEN);
    for (size_t i = 0; i < cp->n_encr; i++) {          /* ENCR (+ KEY_LENGTH attr), more */
        uint16_t bits = cp->encr[i].key_bits;
        w8(&b, 3); w8(&b, 0); w16(&b, bits ? IKE_TRANSFORM_KEYLEN_LEN : IKE_TRANSFORM_PLAIN_LEN);
        w8(&b, IKE_TRANSFORM_ENCR); w8(&b, 0); w16(&b, cp->encr[i].id);
        if (bits) { w16(&b, 0x800E); w16(&b, bits); }
    }
    for (size_t i = 0; i < cp->n_integ; i++) {         /* INTEG, more */
        w8(&b, 3); w8(&b, 0); w16(&b, IKE_TRANSFORM_PLAIN_LEN);
        w8(&b, IKE_TRANSFORM_INTEG); w8(&b, 0); w16(&b, cp->integ[i]);
    }
    /* ESN = NO_ESN (len 8, last) */
    w8(&b, 0); w8(&b, 0); w16(&b, 8); w8(&b, IKE_TRANSFORM_ESN); w8(&b, 0); w16(&b, IKE_ESN_NONE);

    /* ---- TSi (44) then TSr (45, last) ---- */
    write_ts(&b, IKE_PL_TSR,  in->ts_i, NULL, 0);
    write_ts(&b, IKE_PL_NONE, in->ts_r, in->ts_r_extra, n_extra);

    if (b.err || b.n != total) return -1;
    *len = total;
    return 0;
}

/* AP7: EAP round -- the inner chain is exactly one EAP payload carrying one EAP packet. */
int ike_build_eap_inner(const uint8_t *eap, size_t eap_len, uint8_t *out, size_t cap, size_t *len) {
    if (!out || !len) return -1;
    *len = 0;
    if (!eap || eap_len < 4 || eap_len > 1024 || cap < 4 + eap_len) return -1;
    wbuf b = { out, cap, 0, 0 };
    w8(&b, IKE_PL_NONE); w8(&b, 0); w16(&b, (uint16_t)(4 + eap_len));
    wbytes(&b, eap, eap_len);
    if (b.err) return -1;
    *len = b.n;
    return 0;
}

/* AP7: final EAP round -- exactly one AUTH payload (method 2 with the MSK-derived key). */
int ike_build_auth_only_inner(uint8_t method, const uint8_t *auth, size_t auth_len, uint8_t *out, size_t cap, size_t *len) {
    if (!out || !len) return -1;
    *len = 0;
    if (!auth || auth_len == 0 || auth_len > IKE_AUTH_DATA_MAX || cap < 8 + auth_len) return -1;
    wbuf b = { out, cap, 0, 0 };
    w8(&b, IKE_PL_NONE); w8(&b, 0); w16(&b, (uint16_t)(8 + auth_len));
    w8(&b, method); w8(&b, 0); w8(&b, 0); w8(&b, 0);
    wbytes(&b, auth, auth_len);
    if (b.err) return -1;
    *len = b.n;
    return 0;
}
