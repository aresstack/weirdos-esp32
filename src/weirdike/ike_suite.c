/*
 * WeirdIKE -- src/core/ike_suite.c : negotiated IKE-SA suite sizes + callbacks.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ike_suite.h"

size_t weirdike_prf_len(weirdike_prf_id_t prf) {
    switch (prf) {
        case WEIRDIKE_PRF_HMAC_SHA1:     return 20;
        case WEIRDIKE_PRF_HMAC_SHA2_256: return 32;
        case WEIRDIKE_PRF_HMAC_SHA2_384: return 48;
        case WEIRDIKE_PRF_HMAC_SHA2_512: return 64;
        default: return 0;
    }
}

size_t weirdike_integ_key_len(weirdike_integ_id_t integ) {
    switch (integ) {
        case WEIRDIKE_AUTH_NONE:              return 0;
        case WEIRDIKE_AUTH_HMAC_SHA1_96:      return 20;
        case WEIRDIKE_AUTH_HMAC_SHA2_256_128: return 32;
        case WEIRDIKE_AUTH_HMAC_SHA2_384_192: return 48;
        case WEIRDIKE_AUTH_HMAC_SHA2_512_256: return 64;
        default: return 0;
    }
}

size_t weirdike_integ_icv_len(weirdike_integ_id_t integ) {
    switch (integ) {
        case WEIRDIKE_AUTH_NONE:              return 0;
        case WEIRDIKE_AUTH_HMAC_SHA1_96:      return 12;
        case WEIRDIKE_AUTH_HMAC_SHA2_256_128: return 16;
        case WEIRDIKE_AUTH_HMAC_SHA2_384_192: return 24;
        case WEIRDIKE_AUTH_HMAC_SHA2_512_256: return 32;
        default: return 0;
    }
}

size_t weirdike_encr_key_len(weirdike_encr_id_t encr, uint16_t bits) {
    (void)encr;
    return (size_t)bits / 8;
}

const weirdike_ike_suite_t WEIRDIKE_IKE_SUITE_SHA256 = {
    WEIRDIKE_ENCR_AES_CBC, 256, WEIRDIKE_PRF_HMAC_SHA2_256,
    WEIRDIKE_AUTH_HMAC_SHA2_256_128, WEIRDIKE_DH_MODP2048
};
const weirdike_ike_suite_t WEIRDIKE_IKE_SUITE_SHA512 = {
    WEIRDIKE_ENCR_AES_CBC, 256, WEIRDIKE_PRF_HMAC_SHA2_512,
    WEIRDIKE_AUTH_HMAC_SHA2_512_256, WEIRDIKE_DH_MODP2048
};

ike_prf_fn weirdike_prf_cb(const weirdike_crypto_t *cr, weirdike_prf_id_t prf) {
    if (!cr) return NULL;
    switch (prf) {
        case WEIRDIKE_PRF_HMAC_SHA1:     return cr->hmac_sha1;     /* AP9: LANCOM DEFAULT lists SHA-1 */
        case WEIRDIKE_PRF_HMAC_SHA2_256: return cr->hmac_sha256;
        case WEIRDIKE_PRF_HMAC_SHA2_384: return cr->hmac_sha384;
        case WEIRDIKE_PRF_HMAC_SHA2_512: return cr->hmac_sha512;
        default: return NULL;
    }
}

ike_prf_fn weirdike_integ_cb(const weirdike_crypto_t *cr, weirdike_integ_id_t integ) {
    if (!cr) return NULL;
    switch (integ) {
        case WEIRDIKE_AUTH_HMAC_SHA1_96:      return cr->hmac_sha1;   /* 20-B HMAC -> 12-B ICV */
        case WEIRDIKE_AUTH_HMAC_SHA2_256_128: return cr->hmac_sha256;
        case WEIRDIKE_AUTH_HMAC_SHA2_384_192: return cr->hmac_sha384;
        case WEIRDIKE_AUTH_HMAC_SHA2_512_256: return cr->hmac_sha512;
        default: return NULL;
    }
}

/* Build capability. Keep these in sync with the callbacks/sizes above and with the ESP data plane
 * (src/esp: AES-CBC-256 + HMAC-SHA2-256-128 or HMAC-SHA1-96). Adding an algorithm = implement it,
 * prove it against a foreign stack, THEN widen the predicate. SHA-1 (AP9) is a POLICY ALTERNATIVE
 * for LANCOM-style gateways, never a replacement: it is only offered when the host's policy lists
 * it, and the default policy does not. */
/* AES-CBC key sizes (A1): 128/192/256 share cipher and wire ID; only KEY_LENGTH and the derived
 * key sizes differ (SK_e via ike_keymat, ESP keys via ike_child_keymat, both size-driven). */
static int aes_cbc_bits_ok(uint16_t encr, uint16_t key_bits) {
    return encr == WEIRDIKE_ENCR_AES_CBC && (key_bits == 128 || key_bits == 192 || key_bits == 256);
}
int weirdike_ike_encr_supported(uint16_t encr, uint16_t key_bits) {
    return aes_cbc_bits_ok(encr, key_bits);
}
/* Full HMAC-SHA2 matrix (A2): PRF SHA1/256/384/512, INTEG SHA1-96/256-128/384-192/512-256. */
int weirdike_ike_prf_supported(uint16_t prf) {
    return prf == WEIRDIKE_PRF_HMAC_SHA1 || prf == WEIRDIKE_PRF_HMAC_SHA2_256 ||
           prf == WEIRDIKE_PRF_HMAC_SHA2_384 || prf == WEIRDIKE_PRF_HMAC_SHA2_512;
}
int weirdike_ike_integ_supported(uint16_t integ) {
    return integ == WEIRDIKE_AUTH_HMAC_SHA1_96 || integ == WEIRDIKE_AUTH_HMAC_SHA2_256_128 ||
           integ == WEIRDIKE_AUTH_HMAC_SHA2_384_192 || integ == WEIRDIKE_AUTH_HMAC_SHA2_512_256;
}
/* B2/B3: every group with a KE encoder in the crypto adapter AND a strongSwan interop gate (SA_INIT,
 * Child PFS, IKE-SA rekey). MODP6144/8192 (17/18): no RFC 3526 constants in mbedTLS and too slow for
 * the MCU -> not offered. Curve448 (32): not enabled in the ESP-IDF mbedTLS build -> not offered. */
int weirdike_ike_dh_supported(uint16_t dh) {
    return dh == WEIRDIKE_DH_MODP2048 || dh == WEIRDIKE_DH_MODP3072 || dh == WEIRDIKE_DH_MODP4096 ||
           dh == WEIRDIKE_DH_ECP256 || dh == WEIRDIKE_DH_ECP384 || dh == WEIRDIKE_DH_ECP521 ||
           dh == WEIRDIKE_DH_BP256 || dh == WEIRDIKE_DH_BP384 || dh == WEIRDIKE_DH_BP512 ||
           dh == WEIRDIKE_DH_CURVE25519;
}
int weirdike_child_encr_supported(uint16_t encr, uint16_t key_bits) {
    return aes_cbc_bits_ok(encr, key_bits);
}
int weirdike_child_integ_supported(uint16_t integ) {
    return integ == WEIRDIKE_AUTH_HMAC_SHA1_96 || integ == WEIRDIKE_AUTH_HMAC_SHA2_256_128 ||
           integ == WEIRDIKE_AUTH_HMAC_SHA2_384_192 || integ == WEIRDIKE_AUTH_HMAC_SHA2_512_256;
}

int weirdike_ike_suite_supported(const weirdike_ike_suite_t *s) {
    if (!s) return 0;
    /* Any combination of implemented primitives: PRF and INTEG are independent transform types
     * (RFC 7296 3.3.1); every consumer derives its sizes per primitive (prf_len / integ_key_len /
     * icv_len), so e.g. PRF-SHA512 with INTEG-SHA256-128 is a valid negotiated suite. */
    return weirdike_ike_encr_supported(s->encr, s->encr_key_bits) &&
           weirdike_ike_prf_supported(s->prf) &&
           weirdike_ike_integ_supported(s->integ) &&
           weirdike_ike_dh_supported(s->dh);
}
