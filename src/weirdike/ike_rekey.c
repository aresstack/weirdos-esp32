/*
 * WeirdIKE -- src/core/ike_rekey.c : CREATE_CHILD_SA wire (RFC 7296 3.3 / 3.4 / 3.9 / 3.10). Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ike_rekey.h"
#include "ike_wire.h"        /* IKE_PL_*, IKE_TRANSFORM_*, IKE_PROTO_IKE */
#include "ike_auth_wire.h"   /* IKE_PL_TSI/TSR, IKE_PROTO_ESP, IKE_TRANSFORM_ESN, IKE_TS_IPV4_ADDR_RANGE */
#include "ike_auth_resp.h"   /* ike_ts_parse */
#include "ike_policy.h"      /* IKE_TRANSFORM_PLAIN_LEN/KEYLEN_LEN, ike_policy_child_allows */
#include <string.h>

/* B2/B3: KE length is fixed per D-H group (weirdike_dh_pub_len), up to WEIRDIKE_KE_MAX. */

/* ---- tiny bounded writer ---------------------------------------------------------------------- */
typedef struct { uint8_t *p; size_t cap, n; int err; } wbuf;
static void w8 (wbuf *b, uint8_t v)  { if (b->n + 1 > b->cap) { b->err = 1; return; } b->p[b->n++] = v; }
static void w16(wbuf *b, uint16_t v) { w8(b, (uint8_t)(v >> 8)); w8(b, (uint8_t)v); }
static void wb (wbuf *b, const uint8_t *s, size_t n) { for (size_t i = 0; i < n; i++) w8(b, s[i]); }
static unsigned be16(const uint8_t *p) { return (unsigned)((p[0] << 8) | p[1]); }

static int ts_ok(const weirdike_ts_t *ts) {
    if (!ts || ts->address_family != 4) return 0;
    if (ts->start_port > ts->end_port) return 0;
    if (memcmp(ts->start_addr, ts->end_addr, 4) > 0) return 0;
    return 1;
}
static void write_ts_sel(wbuf *b, const weirdike_ts_t *ts) {
    w8(b, IKE_TS_IPV4_ADDR_RANGE); w8(b, ts->ip_protocol); w16(b, 16);
    w16(b, ts->start_port); w16(b, ts->end_port);
    wb(b, ts->start_addr, 4); wb(b, ts->end_addr, 4);
}
/* E2: 1 + n_extra selectors per TS payload (RFC 7296 3.13). */
static void write_ts(wbuf *b, uint8_t next, const weirdike_ts_t *ts, const weirdike_ts_t *extra, size_t n_extra) {
    w8(b, next); w8(b, 0); w16(b, (uint16_t)(8 + 16 * (1 + n_extra)));
    w8(b, (uint8_t)(1 + n_extra)); w8(b, 0); w8(b, 0); w8(b, 0);
    write_ts_sel(b, ts);
    for (size_t i = 0; i < n_extra; i++) write_ts_sel(b, &extra[i]);
}
static int ts_extra_ok(const weirdike_ts_t *extra, size_t n) {
    if (n == 0) return 1;
    if (!extra || n > WEIRDIKE_TS_MAX - 1) return 0;
    for (size_t i = 0; i < n; i++) if (!ts_ok(&extra[i])) return 0;
    return 1;
}
static void write_transform(wbuf *b, uint8_t more, uint8_t type, uint16_t id, uint16_t bits) {
    w8(b, more); w8(b, 0); w16(b, bits ? IKE_TRANSFORM_KEYLEN_LEN : IKE_TRANSFORM_PLAIN_LEN);
    w8(b, type); w8(b, 0); w16(b, id);
    if (bits) { w16(b, 0x800E); w16(b, bits); }
}
static void write_nonce(wbuf *b, uint8_t next, const uint8_t *n, size_t nl) {
    w8(b, next); w8(b, 0); w16(b, (uint16_t)(4 + nl)); wb(b, n, nl);
}
static void write_ke(wbuf *b, uint8_t next, uint16_t group, const uint8_t *ke, size_t kl) {
    w8(b, next); w8(b, 0); w16(b, (uint16_t)(8 + kl)); w16(b, group); w16(b, 0); wb(b, ke, kl);
}
static int nonce_ok(const uint8_t *n, size_t nl) { return n && nl >= 16 && nl <= 256; }
static int spi4_ok(const uint8_t *s) { return s && !(s[0] == 0 && s[1] == 0 && s[2] == 0); }

/* ---- ESP proposal (offer from policy, or single selection) ---------------------------------- */
static size_t esp_prop_len(size_t n_encr_keyed, size_t n_encr_plain, size_t n_integ, int with_dh) {
    return 8 + 4 + n_encr_keyed * IKE_TRANSFORM_KEYLEN_LEN + n_encr_plain * IKE_TRANSFORM_PLAIN_LEN
           + n_integ * IKE_TRANSFORM_PLAIN_LEN + (with_dh ? IKE_TRANSFORM_PLAIN_LEN : 0)
           + IKE_TRANSFORM_PLAIN_LEN /* ESN */;
}
static void write_esp_sa(wbuf *b, uint8_t next, const uint8_t spi[4],
                         const weirdike_encr_t *encr, size_t n_encr,
                         const uint16_t *integ, size_t n_integ, uint16_t dh) {
    size_t keyed = 0, plain = 0;
    for (size_t i = 0; i < n_encr; i++) { if (encr[i].key_bits) keyed++; else plain++; }
    size_t plen = esp_prop_len(keyed, plain, n_integ, dh != 0);
    w8(b, next); w8(b, 0); w16(b, (uint16_t)(4 + plen));
    w8(b, 0); w8(b, 0); w16(b, (uint16_t)plen);
    w8(b, 1); w8(b, IKE_PROTO_ESP); w8(b, 4);
    w8(b, (uint8_t)(n_encr + n_integ + (dh ? 1u : 0u) + 1u));
    wb(b, spi, 4);
    for (size_t i = 0; i < n_encr; i++)  write_transform(b, 3, IKE_TRANSFORM_ENCR,  encr[i].id, encr[i].key_bits);
    for (size_t i = 0; i < n_integ; i++) write_transform(b, 3, IKE_TRANSFORM_INTEG, integ[i], 0);
    if (dh) write_transform(b, 3, IKE_TRANSFORM_DH, dh, 0);
    write_transform(b, 0, IKE_TRANSFORM_ESN, 0, 0);
}

int ike_build_child_rekey_request(uint8_t *out, size_t cap, const uint8_t *old_inbound_spi,
                                  const uint8_t new_spi[4], const weirdike_child_policy_t *policy,
                                  const uint8_t *nonce, size_t nonce_len,
                                  uint16_t pfs_group, const uint8_t *ke_pub, size_t ke_pub_len,
                                  const weirdike_ts_t *ts_i, const weirdike_ts_t *ts_r,
                                  uint8_t *first_payload) {
    return ike_build_child_rekey_request_ex(out, cap, old_inbound_spi, new_spi, policy, nonce, nonce_len, pfs_group, ke_pub, ke_pub_len,
                                            ts_i, ts_r, NULL, 0, first_payload);
}
int ike_build_child_rekey_request_ex(uint8_t *out, size_t cap, const uint8_t *old_inbound_spi,
                                  const uint8_t new_spi[4], const weirdike_child_policy_t *policy,
                                  const uint8_t *nonce, size_t nonce_len,
                                  uint16_t pfs_group, const uint8_t *ke_pub, size_t ke_pub_len,
                                  const weirdike_ts_t *ts_i, const weirdike_ts_t *ts_r,
                                  const weirdike_ts_t *ts_r_extra, size_t n_ts_r_extra,
                                  uint8_t *first_payload) {
    if (!out || !policy || !spi4_ok(new_spi) || !nonce_ok(nonce, nonce_len) || !ts_ok(ts_i) || !ts_ok(ts_r) || !ts_extra_ok(ts_r_extra, n_ts_r_extra)) return -1;
    if (policy->n_encr < 1 || policy->n_encr > WEIRDIKE_POLICY_MAX || policy->n_integ < 1 || policy->n_integ > WEIRDIKE_POLICY_MAX) return -1;
    if (pfs_group && (!ke_pub || ke_pub_len == 0 || ke_pub_len != weirdike_dh_pub_len(pfs_group))) return -1;
    wbuf b = { out, cap, 0, 0 };
    if (old_inbound_spi) {
        if (!spi4_ok(old_inbound_spi)) return -1;
        w8(&b, IKE_PL_SA); w8(&b, 0); w16(&b, 4 + 4 + 4);
        w8(&b, IKE_PROTO_ESP); w8(&b, 4); w16(&b, IKE_NOTIFY_REKEY_SA); wb(&b, old_inbound_spi, 4);
        if (first_payload) *first_payload = IKE_PL_NOTIFY;
    } else if (first_payload) *first_payload = IKE_PL_SA;
    write_esp_sa(&b, IKE_PL_NONCE, new_spi, policy->encr, policy->n_encr, policy->integ, policy->n_integ, pfs_group);
    write_nonce(&b, pfs_group ? IKE_PL_KE : IKE_PL_TSI, nonce, nonce_len);
    if (pfs_group) write_ke(&b, IKE_PL_TSI, pfs_group, ke_pub, ke_pub_len);
    write_ts(&b, IKE_PL_TSR, ts_i, NULL, 0);
    write_ts(&b, IKE_PL_NONE, ts_r, ts_r_extra, n_ts_r_extra);
    return b.err ? -1 : (int)b.n;
}

int ike_build_child_rekey_response(uint8_t *out, size_t cap, const uint8_t new_spi[4],
                                   uint16_t encr, uint16_t encr_bits, uint16_t integ,
                                   const uint8_t *nonce, size_t nonce_len,
                                   uint16_t pfs_group, const uint8_t *ke_pub, size_t ke_pub_len,
                                   const weirdike_ts_t *ts_i, const weirdike_ts_t *ts_r,
                                   uint8_t *first_payload) {
    return ike_build_child_rekey_response_ex(out, cap, new_spi, encr, encr_bits, integ, nonce, nonce_len, pfs_group, ke_pub, ke_pub_len,
                                             ts_i, ts_r, NULL, 0, first_payload);
}
int ike_build_child_rekey_response_ex(uint8_t *out, size_t cap, const uint8_t new_spi[4],
                                   uint16_t encr, uint16_t encr_bits, uint16_t integ,
                                   const uint8_t *nonce, size_t nonce_len,
                                   uint16_t pfs_group, const uint8_t *ke_pub, size_t ke_pub_len,
                                   const weirdike_ts_t *ts_i, const weirdike_ts_t *ts_r,
                                   const weirdike_ts_t *ts_r_extra, size_t n_ts_r_extra,
                                   uint8_t *first_payload) {
    if (!out || !spi4_ok(new_spi) || !nonce_ok(nonce, nonce_len) || !ts_ok(ts_i) || !ts_ok(ts_r) || !ts_extra_ok(ts_r_extra, n_ts_r_extra)) return -1;
    if (pfs_group && (!ke_pub || ke_pub_len == 0 || ke_pub_len != weirdike_dh_pub_len(pfs_group))) return -1;
    wbuf b = { out, cap, 0, 0 };
    weirdike_encr_t e; e.id = encr; e.key_bits = encr_bits;
    write_esp_sa(&b, IKE_PL_NONCE, new_spi, &e, 1, &integ, 1, pfs_group);
    write_nonce(&b, pfs_group ? IKE_PL_KE : IKE_PL_TSI, nonce, nonce_len);
    if (pfs_group) write_ke(&b, IKE_PL_TSI, pfs_group, ke_pub, ke_pub_len);
    write_ts(&b, IKE_PL_TSR, ts_i, NULL, 0);
    write_ts(&b, IKE_PL_NONE, ts_r, ts_r_extra, n_ts_r_extra);
    if (first_payload) *first_payload = IKE_PL_SA;
    return b.err ? -1 : (int)b.n;
}

/* ---- IKE proposal with an 8-byte SPI (IKE-SA rekey) ------------------------------------------ */
static void write_ike_sa(wbuf *b, uint8_t next, const uint8_t spi[8],
                         const weirdike_encr_t *encr, size_t n_encr, const uint16_t *prf, size_t n_prf,
                         const uint16_t *integ, size_t n_integ, const uint16_t *dh, size_t n_dh) {
    size_t plen = 8 + 8;
    for (size_t i = 0; i < n_encr; i++) plen += encr[i].key_bits ? IKE_TRANSFORM_KEYLEN_LEN : IKE_TRANSFORM_PLAIN_LEN;
    plen += (n_prf + n_integ + n_dh) * IKE_TRANSFORM_PLAIN_LEN;
    w8(b, next); w8(b, 0); w16(b, (uint16_t)(4 + plen));
    w8(b, 0); w8(b, 0); w16(b, (uint16_t)plen);
    w8(b, 1); w8(b, IKE_PROTO_IKE); w8(b, 8);
    w8(b, (uint8_t)(n_encr + n_prf + n_integ + n_dh));
    wb(b, spi, 8);
    size_t total = n_encr + n_prf + n_integ + n_dh, k = 0;
    for (size_t i = 0; i < n_encr;  i++, k++) write_transform(b, (uint8_t)(k + 1 < total ? 3 : 0), IKE_TRANSFORM_ENCR,  encr[i].id, encr[i].key_bits);
    for (size_t i = 0; i < n_prf;   i++, k++) write_transform(b, (uint8_t)(k + 1 < total ? 3 : 0), IKE_TRANSFORM_PRF,   prf[i], 0);
    for (size_t i = 0; i < n_integ; i++, k++) write_transform(b, (uint8_t)(k + 1 < total ? 3 : 0), IKE_TRANSFORM_INTEG, integ[i], 0);
    for (size_t i = 0; i < n_dh;    i++, k++) write_transform(b, (uint8_t)(k + 1 < total ? 3 : 0), IKE_TRANSFORM_DH,    dh[i], 0);
}

int ike_build_ike_rekey_request(uint8_t *out, size_t cap, const uint8_t new_spi_i[8],
                                const weirdike_ike_policy_t *policy,
                                const uint8_t *nonce, size_t nonce_len,
                                const uint8_t *ke_pub, size_t ke_pub_len, uint8_t *first_payload) {
    if (!out || !new_spi_i || !policy || !nonce_ok(nonce, nonce_len) || !ke_pub || ke_pub_len == 0) return -1;
    if (policy->n_encr < 1 || policy->n_prf < 1 || policy->n_integ < 1 || policy->n_dh < 1 ||
        policy->n_encr > WEIRDIKE_POLICY_MAX || policy->n_prf > WEIRDIKE_POLICY_MAX ||
        policy->n_integ > WEIRDIKE_POLICY_MAX || policy->n_dh > WEIRDIKE_POLICY_MAX) return -1;
    wbuf b = { out, cap, 0, 0 };
    write_ike_sa(&b, IKE_PL_NONCE, new_spi_i, policy->encr, policy->n_encr, policy->prf, policy->n_prf,
                 policy->integ, policy->n_integ, policy->dh, policy->n_dh);
    write_nonce(&b, IKE_PL_KE, nonce, nonce_len);
    write_ke(&b, IKE_PL_NONE, policy->dh[0], ke_pub, ke_pub_len);
    if (first_payload) *first_payload = IKE_PL_SA;
    return b.err ? -1 : (int)b.n;
}

int ike_build_ike_rekey_response(uint8_t *out, size_t cap, const uint8_t new_spi_r[8],
                                 const weirdike_ike_suite_t *selected,
                                 const uint8_t *nonce, size_t nonce_len,
                                 const uint8_t *ke_pub, size_t ke_pub_len, uint8_t *first_payload) {
    if (!out || !new_spi_r || !selected || !nonce_ok(nonce, nonce_len) || !ke_pub || ke_pub_len == 0) return -1;
    wbuf b = { out, cap, 0, 0 };
    weirdike_encr_t e; e.id = selected->encr; e.key_bits = selected->encr_key_bits;
    uint16_t prf = selected->prf, integ = selected->integ, dh = selected->dh;
    write_ike_sa(&b, IKE_PL_NONCE, new_spi_r, &e, 1, &prf, 1, &integ, 1, &dh, 1);
    write_nonce(&b, IKE_PL_KE, nonce, nonce_len);
    write_ke(&b, IKE_PL_NONE, selected->dh, ke_pub, ke_pub_len);
    if (first_payload) *first_payload = IKE_PL_SA;
    return b.err ? -1 : (int)b.n;
}

int ike_build_notify_only(uint8_t *out, size_t cap, uint8_t proto, const uint8_t *spi, size_t spi_len,
                          uint16_t type, const uint8_t *data, size_t data_len, uint8_t *first_payload) {
    if (!out || (spi_len && !spi) || (data_len && !data) || spi_len > 8 || data_len > 64) return -1;
    wbuf b = { out, cap, 0, 0 };
    w8(&b, IKE_PL_NONE); w8(&b, 0); w16(&b, (uint16_t)(4 + 4 + spi_len + data_len));
    w8(&b, proto); w8(&b, (uint8_t)spi_len); w16(&b, type);
    if (spi_len) wb(&b, spi, spi_len);
    if (data_len) wb(&b, data, data_len);
    if (first_payload) *first_payload = IKE_PL_NOTIFY;
    return b.err ? -1 : (int)b.n;
}

/* ---- parser ------------------------------------------------------------------------------------ */
static int parse_sa(const uint8_t *b, size_t n, ike_create_child_msg_t *o) {
    if (n < 8) return -1;
    unsigned last = b[0], plen = be16(b + 2), pnum = b[4], proto = b[5], spisz = b[6], ntr = b[7];
    if (plen != n) return -1;                     /* exactly ONE proposal (we offer/accept one) */
    if (last != 0 || pnum != 1) return -1;
    if (proto == IKE_PROTO_ESP) { if (spisz != 4) return -1; o->sa_is_ike = 0; memcpy(o->spi, b + 8, 4); if (!spi4_ok(o->spi)) return -1; }
    else if (proto == IKE_PROTO_IKE) { if (spisz != 8) return -1; o->sa_is_ike = 1; memcpy(o->ike_spi, b + 8, 8); }
    else return -1;
    size_t off = 8 + spisz;
    for (unsigned i = 0; i < ntr; i++) {
        if (off + 8 > plen) return -1;
        unsigned tlast = b[off], tlen = be16(b + off + 2), ttype = b[off + 4], tid = be16(b + off + 6);
        if (tlast != 0 && tlast != 3) return -1;
        if (tlen < 8 || off + tlen > plen) return -1;
        size_t alen = (size_t)tlen - 8;
        uint16_t bits = 0;
        if (alen) {
            if (alen != 4 || b[off + 8] != 0x80 || b[off + 9] != 0x0E) return -1;   /* only TV KEY_LENGTH */
            bits = (uint16_t)be16(b + off + 10);
        }
        switch (ttype) {
            case IKE_TRANSFORM_ENCR:  if (o->n_encr  < IKE_REKEY_MAX_TRANSFORMS) { o->encr[o->n_encr].id = (uint16_t)tid; o->encr[o->n_encr].key_bits = bits; o->n_encr++; } break;
            case IKE_TRANSFORM_PRF:   if (alen) return -1; if (o->n_prf   < IKE_REKEY_MAX_TRANSFORMS) o->prf[o->n_prf++]     = (uint16_t)tid; break;
            case IKE_TRANSFORM_INTEG: if (alen) return -1; if (o->n_integ < IKE_REKEY_MAX_TRANSFORMS) o->integ[o->n_integ++] = (uint16_t)tid; break;
            case IKE_TRANSFORM_DH:    if (alen) return -1; if (o->n_dh    < IKE_REKEY_MAX_TRANSFORMS) o->dh[o->n_dh++]       = (uint16_t)tid; break;
            case IKE_TRANSFORM_ESN:   if (alen) return -1; if (tid == 0) o->esn_none = 1; else o->esn_other = 1; break;
            default: return -1;
        }
        off += tlen;
    }
    if (off != plen) return -1;
    o->sa_present = 1;
    return 0;
}

int ike_parse_create_child_inner(uint8_t first_payload, const uint8_t *inner, size_t len,
                                 ike_create_child_msg_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (len && !inner) return -1;
    uint8_t type = first_payload; size_t off = 0;
    int n_sa = 0, n_nonce = 0, n_ke = 0, n_tsi = 0, n_tsr = 0;
    while (type != IKE_PL_NONE) {
        if (off + 4 > len) return -1;
        uint8_t next = inner[off]; int crit = (inner[off + 1] & 0x80) != 0;
        unsigned plen = be16(inner + off + 2);
        if (plen < 4 || off + plen > len) return -1;
        const uint8_t *body = inner + off + 4; size_t bl = plen - 4;
        switch (type) {
            case IKE_PL_SA:
                if (++n_sa > 1) return -1;
                if (parse_sa(body, bl, out) != 0) return -1;
                break;
            case IKE_PL_NONCE:
                if (++n_nonce > 1 || bl < 16 || bl > 256) return -1;
                memcpy(out->nonce, body, bl); out->nonce_len = bl; out->have_nonce = 1;
                break;
            case IKE_PL_KE:
                if (++n_ke > 1 || bl < 4 || bl - 4 > WEIRDIKE_KE_MAX) return -1;
                out->ke_group = (uint16_t)be16(body); out->ke_len = bl - 4;
                memcpy(out->ke, body + 4, out->ke_len); out->have_ke = 1;
                break;
            case IKE_PL_TSI: { if (++n_tsi > 1) return -1; int r = ike_ts_parse(body, bl, &out->tsi); if (r < 0) return -1; out->tsi_ok = (r == 1); break; }
            case IKE_PL_TSR: { if (++n_tsr > 1) return -1; int r = ike_ts_parse_list(body, bl, out->tsr_list, WEIRDIKE_TS_MAX, &out->n_tsr); if (r < 0) return -1; out->tsr_ok = (r == 1); if (out->tsr_ok) out->tsr = out->tsr_list[0]; break; }   /* E2 */
            case IKE_PL_NOTIFY: {
                if (bl < 4) return -1;
                unsigned proto = body[0], spisz = body[1], ntype = be16(body + 2);
                if (4u + spisz > bl) return -1;
                const uint8_t *nd = body + 4 + spisz; size_t ndl = bl - 4 - spisz;
                if (ntype == IKE_NOTIFY_REKEY_SA) {
                    if (proto != IKE_PROTO_ESP || spisz != 4) return -1;
                    out->rekey_sa = 1; memcpy(out->rekey_spi, body + 4, 4);
                } else if (ntype == IKE_NOTIFY_INVALID_KE_PAYLOAD) {
                    if (ndl != 2) return -1;
                    out->invalid_ke_group = (uint16_t)be16(nd);
                    if (!out->error_notify) out->error_notify = (uint16_t)ntype;
                } else if (ntype < 16384) {
                    if (!out->error_notify) out->error_notify = (uint16_t)ntype;
                }
                break;
            }
            default:
                if (crit) return -1;
                break;
        }
        off += plen; type = next;
    }
    return off == len ? 0 : -1;
}

int ike_select_child_offer(const ike_create_child_msg_t *m, const weirdike_child_policy_t *policy,
                           int want_pfs_group,
                           uint16_t *encr, uint16_t *encr_bits, uint16_t *integ, uint16_t *dh_out) {
    if (!m || !policy || !m->sa_present || m->sa_is_ike || !m->esn_none) return 0;
    int found = 0;
    for (size_t i = 0; i < m->n_encr && !found; i++)
        for (size_t j = 0; j < m->n_integ && !found; j++)
            if (ike_policy_child_allows(policy, m->encr[i].id, m->encr[i].key_bits, m->integ[j]) &&
                weirdike_child_encr_supported(m->encr[i].id, m->encr[i].key_bits) &&
                weirdike_child_integ_supported(m->integ[j])) {
                *encr = m->encr[i].id; *encr_bits = m->encr[i].key_bits; *integ = m->integ[j]; found = 1;
            }
    if (!found) return 0;
    *dh_out = 0;
    if (m->n_dh) {
        /* The offer carries D-H (PFS): we must select one we can run; prefer the group the FSM
         * wants, else the first supported. No supported group -> not acceptable. */
        for (size_t i = 0; i < m->n_dh; i++) if ((int)m->dh[i] == want_pfs_group && weirdike_ike_dh_supported(m->dh[i])) { *dh_out = m->dh[i]; break; }
        if (!*dh_out) for (size_t i = 0; i < m->n_dh; i++) if (weirdike_ike_dh_supported(m->dh[i])) { *dh_out = m->dh[i]; break; }
        if (!*dh_out) return 0;
    }
    return 1;
}
