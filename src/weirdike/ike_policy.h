/*
 * WeirdIKE -- src/core/ike_policy.h : proposal policy (allow-lists per transform type). RFC 7296 3.3.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The host-facing types live in weirdike.h (weirdike_ike_policy_t / weirdike_child_policy_t). This
 * module owns their semantics: normalization (deterministic order, no duplicates), the "does this
 * build implement it" check, and the accept-side test "is the selection of the responder inside the
 * policy". The wire encoders (ike_wire / ike_auth_wire) only iterate the lists. No crypto here.
 */
#ifndef WEIRDIKE_IKE_POLICY_H
#define WEIRDIKE_IKE_POLICY_H

#include <stdint.h>
#include <stddef.h>
#include "weirdike.h"
#include "ike_suite.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Sort every list ascending (ENCR by id, then key_bits) and drop duplicates. Returns 0, or -1 if a
 * list is empty or longer than WEIRDIKE_POLICY_MAX (the struct is then unusable for the encoders). */
int ike_policy_normalize_ike(weirdike_ike_policy_t *p);
int ike_policy_normalize_child(weirdike_child_policy_t *p);

/* Accept-side checks: is EVERY transform of the selection listed? Any combination of listed
 * transforms is fine -- the lists are independent. 1 = allowed, 0 = outside the policy. */
int ike_policy_ike_allows(const weirdike_ike_policy_t *p, const weirdike_ike_suite_t *selected);
int ike_policy_child_allows(const weirdike_child_policy_t *p,
                            uint16_t encr, uint16_t encr_key_bits, uint16_t integ);

/* Build-capability checks (per list). 1 = every entry implemented AND 1 <= n <= WEIRDIKE_POLICY_MAX. */
int ike_policy_ike_encr_ok (const weirdike_ike_policy_t *p);
int ike_policy_ike_prf_ok  (const weirdike_ike_policy_t *p);
int ike_policy_ike_integ_ok(const weirdike_ike_policy_t *p);
int ike_policy_ike_dh_ok   (const weirdike_ike_policy_t *p);
int ike_policy_child_encr_ok (const weirdike_child_policy_t *p);
int ike_policy_child_integ_ok(const weirdike_child_policy_t *p);

/* Wire size of one transform substructure: 8, plus 4 for an ENCR that carries KEY_LENGTH. */
#define IKE_TRANSFORM_PLAIN_LEN   8
#define IKE_TRANSFORM_KEYLEN_LEN 12
static inline size_t ike_encr_transform_len(const weirdike_encr_t *e) {
    return e->key_bits ? (size_t)IKE_TRANSFORM_KEYLEN_LEN : (size_t)IKE_TRANSFORM_PLAIN_LEN;
}

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_IKE_POLICY_H */
