/*
 * WeirdIKE -- src/core/ike_suite.h : negotiated IKE-SA crypto suite as a first-class domain object.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The IKE-SA suite (ENCR/PRF/INTEG/DH) is negotiated, not hard-coded. This header turns it into a
 * value with centrally-derived sizes (PRF output, INTEG key/ICV, ENCR key) so keymat / SK{} / AUTH
 * don't each re-hardcode 32/16. CHILD/ESP suites are SEPARATE (weirdike_child_sa_t) -- do not reuse
 * this type for them.
 */
#ifndef WEIRDIKE_IKE_SUITE_H
#define WEIRDIKE_IKE_SUITE_H

#include <stdint.h>
#include <stddef.h>
#include "ike_crypto.h"
#include "ike_keymat.h"   /* ike_prf_fn */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    weirdike_encr_id_t  encr;           /* WEIRDIKE_ENCR_AES_CBC */
    uint16_t            encr_key_bits;  /* 256 */
    weirdike_prf_id_t   prf;            /* WEIRDIKE_PRF_HMAC_SHA2_256 / _512 */
    weirdike_integ_id_t integ;         /* WEIRDIKE_AUTH_HMAC_SHA2_256_128 / _512_256 */
    weirdike_dh_id_t    dh;            /* WEIRDIKE_DH_MODP2048 */
} weirdike_ike_suite_t;

/* Derived sizes in bytes (0 = unknown/unsupported). RFC 4868: HMAC-SHA-512 PRF = 64 B full;
 * AUTH_HMAC_SHA2_512_256 = 64 B key, 32 B ICV. SK_d/SK_p use the PRF (key) length. */
size_t weirdike_prf_len(weirdike_prf_id_t prf);           /* 20/32/48/64 */
size_t weirdike_integ_key_len(weirdike_integ_id_t integ); /* 32/48/64/0(NONE) */
size_t weirdike_integ_icv_len(weirdike_integ_id_t integ); /* 16/24/32/0(NONE) */
size_t weirdike_encr_key_len(weirdike_encr_id_t encr, uint16_t bits); /* bits/8 */

/* The two IKE suites WeirdIKE offers/accepts today (both proven; SHA-512 for FRITZ!Box). */
extern const weirdike_ike_suite_t WEIRDIKE_IKE_SUITE_SHA256;  /* AES-CBC-256/SHA256/SHA256-128/DH14 */
extern const weirdike_ike_suite_t WEIRDIKE_IKE_SUITE_SHA512;  /* AES-CBC-256/SHA512/SHA512-256/DH14 */

/* Pick the vtable HMAC callback for a suite's PRF / INTEG (NULL if unsupported). The vtable's
 * hmac_shaX out[N] parameter is identical to uint8_t* -> assignable to ike_prf_fn without a cast. */
ike_prf_fn weirdike_prf_cb(const weirdike_crypto_t *cr, weirdike_prf_id_t prf);
ike_prf_fn weirdike_integ_cb(const weirdike_crypto_t *cr, weirdike_integ_id_t integ);

/* Build capability per primitive (what THIS build can run on the wire). The proposal policy
 * (ike_policy.c) is validated against these; the negotiated suite may be ANY combination of them. */
int weirdike_ike_encr_supported (uint16_t encr, uint16_t key_bits);   /* AES-CBC-256 */
int weirdike_ike_prf_supported  (uint16_t prf);                        /* HMAC-SHA2-256 / -512 */
int weirdike_ike_integ_supported(uint16_t integ);                      /* HMAC-SHA2-256-128 / -512-256 */
int weirdike_ike_dh_supported   (uint16_t dh);                         /* MODP2048/3072/4096, ECP256/384/521, BP256/384/512, X25519 */

/* D-H group geometry (B2/B3). Header-only so the wire encoder/parser can use it without linking
 * ike_suite.c. KE public value length on the wire (RFC 3526 modulus length; RFC 5903 x||y; RFC 8031
 * 32 B for Curve25519) and the shared-secret length fed to prf+ (MODP: modulus; ECP: x only; X25519: 32).
 * 0 = unknown/unsupported group. */
static inline size_t weirdike_dh_pub_len(uint16_t dh) {
    switch (dh) {
        case 14: return 256;  case 15: return 384;  case 16: return 512;
        case 19: return 64;   case 20: return 96;   case 21: return 132;
        case 28: return 64;   case 29: return 96;   case 30: return 128;
        case 31: return 32;
        default: return 0;
    }
}
static inline size_t weirdike_dh_shared_len(uint16_t dh) {
    switch (dh) {
        case 14: return 256;  case 15: return 384;  case 16: return 512;
        case 19: return 32;   case 20: return 48;   case 21: return 66;
        case 28: return 32;   case 29: return 48;   case 30: return 64;
        case 31: return 32;
        default: return 0;
    }
}
int weirdike_child_encr_supported (uint16_t encr, uint16_t key_bits);  /* ESP AES-CBC-256 */
int weirdike_child_integ_supported(uint16_t integ);                    /* ESP HMAC-SHA2-256-128 */

/* Every primitive of the suite is implemented by this build (any combination). */
int weirdike_ike_suite_supported(const weirdike_ike_suite_t *s);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_IKE_SUITE_H */
