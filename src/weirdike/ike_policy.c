/*
 * WeirdIKE -- src/core/ike_policy.c : proposal policy semantics (see ike_policy.h).
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ike_policy.h"
#include <string.h>

/* ---- normalization: deterministic ascending order, duplicates removed ---- */
static int sort_u16(uint16_t *v, size_t *n) {
    if (*n == 0 || *n > WEIRDIKE_POLICY_MAX) return -1;
    for (size_t i = 1; i < *n; i++) {                 /* insertion sort: n <= 4 */
        uint16_t x = v[i]; size_t j = i;
        while (j > 0 && v[j - 1] > x) { v[j] = v[j - 1]; j--; }
        v[j] = x;
    }
    size_t w = 1;
    for (size_t i = 1; i < *n; i++) if (v[i] != v[w - 1]) v[w++] = v[i];
    for (size_t i = w; i < *n; i++) v[i] = 0;         /* zero the tail: canonical representation */
    *n = w;
    return 0;
}
static int encr_less(const weirdike_encr_t *a, const weirdike_encr_t *b) {
    return a->id < b->id || (a->id == b->id && a->key_bits < b->key_bits);
}
static int sort_encr(weirdike_encr_t *v, size_t *n) {
    if (*n == 0 || *n > WEIRDIKE_POLICY_MAX) return -1;
    for (size_t i = 1; i < *n; i++) {
        weirdike_encr_t x = v[i]; size_t j = i;
        while (j > 0 && encr_less(&x, &v[j - 1])) { v[j] = v[j - 1]; j--; }
        v[j] = x;
    }
    size_t w = 1;
    for (size_t i = 1; i < *n; i++)
        if (v[i].id != v[w - 1].id || v[i].key_bits != v[w - 1].key_bits) v[w++] = v[i];
    for (size_t i = w; i < *n; i++) { v[i].id = 0; v[i].key_bits = 0; }   /* canonical tail */
    *n = w;
    return 0;
}

int ike_policy_normalize_ike(weirdike_ike_policy_t *p) {
    if (!p) return -1;
    if (sort_encr(p->encr, &p->n_encr) != 0) return -1;
    if (sort_u16(p->prf,   &p->n_prf)   != 0) return -1;
    if (sort_u16(p->integ, &p->n_integ) != 0) return -1;
    if (sort_u16(p->dh,    &p->n_dh)    != 0) return -1;
    return 0;
}
int ike_policy_normalize_child(weirdike_child_policy_t *p) {
    if (!p) return -1;
    if (sort_encr(p->encr, &p->n_encr) != 0) return -1;
    if (sort_u16(p->integ, &p->n_integ) != 0) return -1;
    return 0;
}

/* ---- accept side ---- */
static int has_u16(const uint16_t *v, size_t n, uint16_t x) {
    if (n > WEIRDIKE_POLICY_MAX) return 0;
    for (size_t i = 0; i < n; i++) if (v[i] == x) return 1;
    return 0;
}
static int has_encr(const weirdike_encr_t *v, size_t n, uint16_t id, uint16_t bits) {
    if (n > WEIRDIKE_POLICY_MAX) return 0;
    for (size_t i = 0; i < n; i++) if (v[i].id == id && v[i].key_bits == bits) return 1;
    return 0;
}

int ike_policy_ike_allows(const weirdike_ike_policy_t *p, const weirdike_ike_suite_t *s) {
    if (!p || !s) return 0;
    return has_encr(p->encr, p->n_encr, s->encr, s->encr_key_bits) &&
           has_u16(p->prf,   p->n_prf,   s->prf)   &&
           has_u16(p->integ, p->n_integ, s->integ) &&
           has_u16(p->dh,    p->n_dh,    s->dh);
}
int ike_policy_child_allows(const weirdike_child_policy_t *p,
                            uint16_t encr, uint16_t encr_key_bits, uint16_t integ) {
    if (!p) return 0;
    return has_encr(p->encr, p->n_encr, encr, encr_key_bits) && has_u16(p->integ, p->n_integ, integ);
}

/* ---- build capability ---- */
#define LIST_OK(n) ((n) >= 1 && (n) <= WEIRDIKE_POLICY_MAX)
int ike_policy_ike_encr_ok(const weirdike_ike_policy_t *p) {
    if (!p || !LIST_OK(p->n_encr)) return 0;
    for (size_t i = 0; i < p->n_encr; i++) if (!weirdike_ike_encr_supported(p->encr[i].id, p->encr[i].key_bits)) return 0;
    return 1;
}
int ike_policy_ike_prf_ok(const weirdike_ike_policy_t *p) {
    if (!p || !LIST_OK(p->n_prf)) return 0;
    for (size_t i = 0; i < p->n_prf; i++) if (!weirdike_ike_prf_supported(p->prf[i])) return 0;
    return 1;
}
int ike_policy_ike_integ_ok(const weirdike_ike_policy_t *p) {
    if (!p || !LIST_OK(p->n_integ)) return 0;
    for (size_t i = 0; i < p->n_integ; i++) if (!weirdike_ike_integ_supported(p->integ[i])) return 0;
    return 1;
}
int ike_policy_ike_dh_ok(const weirdike_ike_policy_t *p) {
    if (!p || !LIST_OK(p->n_dh)) return 0;
    for (size_t i = 0; i < p->n_dh; i++) if (!weirdike_ike_dh_supported(p->dh[i])) return 0;
    return 1;
}
int ike_policy_child_encr_ok(const weirdike_child_policy_t *p) {
    if (!p || !LIST_OK(p->n_encr)) return 0;
    for (size_t i = 0; i < p->n_encr; i++) if (!weirdike_child_encr_supported(p->encr[i].id, p->encr[i].key_bits)) return 0;
    return 1;
}
int ike_policy_child_integ_ok(const weirdike_child_policy_t *p) {
    if (!p || !LIST_OK(p->n_integ)) return 0;
    for (size_t i = 0; i < p->n_integ; i++) if (!weirdike_child_integ_supported(p->integ[i])) return 0;
    return 1;
}

/* ---- public (weirdike.h) ---- */
void weirdike_ike_policy_default(weirdike_ike_policy_t *p) {
    if (!p) return;
    memset(p, 0, sizeof(*p));
    p->encr[0].id = WEIRDIKE_ENCR_AES_CBC; p->encr[0].key_bits = 256; p->n_encr = 1;
    p->prf[0]   = WEIRDIKE_PRF_HMAC_SHA2_256;      p->prf[1]   = WEIRDIKE_PRF_HMAC_SHA2_512;      p->n_prf   = 2;
    p->integ[0] = WEIRDIKE_AUTH_HMAC_SHA2_256_128; p->integ[1] = WEIRDIKE_AUTH_HMAC_SHA2_512_256; p->n_integ = 2;
    p->dh[0]    = WEIRDIKE_DH_MODP2048;            p->n_dh    = 1;
}
void weirdike_child_policy_default(weirdike_child_policy_t *p) {
    if (!p) return;
    memset(p, 0, sizeof(*p));
    p->encr[0].id = WEIRDIKE_ENCR_AES_CBC; p->encr[0].key_bits = 256; p->n_encr = 1;
    p->integ[0] = WEIRDIKE_AUTH_HMAC_SHA2_256_128; p->n_integ = 1;
}
int weirdike_policy_check(const weirdike_ike_policy_t *ike, const weirdike_child_policy_t *child) {
    if (ike) {
        if (!ike_policy_ike_encr_ok(ike))  return -1;
        if (!ike_policy_ike_prf_ok(ike))   return -2;
        if (!ike_policy_ike_integ_ok(ike)) return -3;
        if (!ike_policy_ike_dh_ok(ike))    return -4;
    }
    if (child) {
        if (!ike_policy_child_encr_ok(child))  return -5;
        if (!ike_policy_child_integ_ok(child)) return -6;
    }
    return 0;
}
