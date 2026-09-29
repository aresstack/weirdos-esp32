/*
 * WeirdIKE -- src/crypto/crypto_mbedtls.c : mbedTLS implementation of weirdike_crypto_t.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "crypto_mbedtls.h"

#include <stdlib.h>
#include <string.h>

#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/dhm.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"    /* B3: ECP groups (secp, brainpool, curve25519) */
#include "mbedtls/ecdh.h"
#ifndef MBEDTLS_PRIVATE
#define MBEDTLS_PRIVATE(m) m   /* mbedTLS 2.x: struct members are public */
#endif
#include "mbedtls/x509_crt.h"   /* AP7: server certificate chain + signature verification (EAP) */
#include "mbedtls/pk.h"
#include "mbedtls/oid.h"
#include "mbedtls/asn1.h"

/* ---- RNG ---- */
static int cb_random(void *ctx, uint8_t *out, size_t len) {
    weirdike_mbedtls_ctx *mc = (weirdike_mbedtls_ctx *)ctx;
    return mbedtls_ctr_drbg_random(&mc->drbg, out, len) == 0 ? 0 : -1;
}

/* ---- hashes (via the message-digest API -> portable across mbedTLS 2.28 and 3.x, unlike the
 *      mbedtls_sha1/sha256/sha512 one-shots whose return type/name changed between versions) ---- */
static int md_oneshot(mbedtls_md_type_t t, const uint8_t *in, size_t len, uint8_t *out) {
    const mbedtls_md_info_t *mi = mbedtls_md_info_from_type(t);
    if (!mi) return -1;
    return mbedtls_md(mi, in, len, out) == 0 ? 0 : -1;
}
static int cb_sha1(void *ctx, const uint8_t *in, size_t len, uint8_t out[20]) {
    (void)ctx; return md_oneshot(MBEDTLS_MD_SHA1, in, len, out);
}
static int cb_sha256(void *ctx, const uint8_t *in, size_t len, uint8_t out[32]) {
    (void)ctx; return md_oneshot(MBEDTLS_MD_SHA256, in, len, out);
}
static int cb_sha384(void *ctx, const uint8_t *in, size_t len, uint8_t out[48]) {
    (void)ctx; return md_oneshot(MBEDTLS_MD_SHA384, in, len, out);
}
static int cb_sha512(void *ctx, const uint8_t *in, size_t len, uint8_t out[64]) {
    (void)ctx; return md_oneshot(MBEDTLS_MD_SHA512, in, len, out);
}

/* ---- HMAC ---- */
static int hmac(mbedtls_md_type_t t, const uint8_t *key, size_t klen,
                const uint8_t *in, size_t len, uint8_t *out) {
    const mbedtls_md_info_t *mi = mbedtls_md_info_from_type(t);
    if (!mi) return -1;
    return mbedtls_md_hmac(mi, key, klen, in, len, out) == 0 ? 0 : -1;
}
static int cb_hmac_sha1(void *ctx, const uint8_t *k, size_t kl, const uint8_t *in, size_t n, uint8_t out[20]) {
    (void)ctx; return hmac(MBEDTLS_MD_SHA1, k, kl, in, n, out);
}
static int cb_hmac_sha256(void *ctx, const uint8_t *k, size_t kl, const uint8_t *in, size_t n, uint8_t out[32]) {
    (void)ctx; return hmac(MBEDTLS_MD_SHA256, k, kl, in, n, out);
}
static int cb_hmac_sha384(void *ctx, const uint8_t *k, size_t kl, const uint8_t *in, size_t n, uint8_t out[48]) {
    (void)ctx; return hmac(MBEDTLS_MD_SHA384, k, kl, in, n, out);
}
static int cb_hmac_sha512(void *ctx, const uint8_t *k, size_t kl, const uint8_t *in, size_t n, uint8_t out[64]) {
    (void)ctx; return hmac(MBEDTLS_MD_SHA512, k, kl, in, n, out);
}

/* ---- AES-CBC ---- */
static int cb_aes_cbc(void *ctx, int enc, const uint8_t *key, size_t klen, const uint8_t iv[16],
                      const uint8_t *in, size_t len, uint8_t *out) {
    (void)ctx;
    if (len % 16 != 0) return -1;
    mbedtls_aes_context a; mbedtls_aes_init(&a);
    uint8_t iv2[16]; memcpy(iv2, iv, 16);   /* crypt_cbc mutates the IV */
    int rc = enc ? mbedtls_aes_setkey_enc(&a, key, (unsigned)klen * 8)
                 : mbedtls_aes_setkey_dec(&a, key, (unsigned)klen * 8);
    if (rc == 0)
        rc = mbedtls_aes_crypt_cbc(&a, enc ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
                                   len, iv2, in, out);
    mbedtls_aes_free(&a);
    return rc == 0 ? 0 : -1;
}

/* ---- AES-GCM ---- */
static int cb_aes_gcm(void *ctx, int enc, const uint8_t *key, size_t klen,
                      const uint8_t *iv, size_t ivlen, const uint8_t *aad, size_t aadlen,
                      const uint8_t *in, size_t len, uint8_t *out, uint8_t *tag, size_t taglen) {
    (void)ctx;
    mbedtls_gcm_context g; mbedtls_gcm_init(&g);
    int rc = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, (unsigned)klen * 8);
    if (rc == 0) {
        if (enc)
            rc = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, len, iv, ivlen,
                                           aad, aadlen, in, out, taglen, tag);
        else
            rc = mbedtls_gcm_auth_decrypt(&g, len, iv, ivlen, aad, aadlen,
                                          tag, taglen, in, out);
    }
    mbedtls_gcm_free(&g);
    return rc == 0 ? 0 : -1;
}

/* ---- Key exchange (B2/B3): MODP2048/3072/4096 via mbedtls_mpi ONLY (bignum) -- ESP-IDF / Arduino-ESP32
 *      ship mbedTLS with MBEDTLS_DHM_C disabled, MBEDTLS_BIGNUM_C is always there; the RFC 3526 primes
 *      come from dhm.h as constants. ECP groups via mbedtls_ecdh on mbedtls_ecp: secp256r1/384r1/521r1
 *      (IKE 19/20/21), brainpoolP256r1/384r1/512r1 (28/29/30) and Curve25519 (31). Wire formats: MODP =
 *      big-endian, zero-left-padded to the modulus length; ECP = x || y fixed size (RFC 5903), shared
 *      secret = x only; Curve25519 = 32-byte little-endian u (RFC 8031). MODP6144/8192 (17/18): no RFC
 *      3526 constants in mbedTLS (only RFC 7919 FFDHE) and too slow for the MCU -> not implemented.
 *      Curve448 (32): not enabled in the ESP-IDF mbedTLS build -> not implemented. ---- */
static const unsigned char MODP2048_P_BIN[] = MBEDTLS_DHM_RFC3526_MODP_2048_P_BIN;
static const unsigned char MODP3072_P_BIN[] = MBEDTLS_DHM_RFC3526_MODP_3072_P_BIN;
static const unsigned char MODP4096_P_BIN[] = MBEDTLS_DHM_RFC3526_MODP_4096_P_BIN;
static const unsigned char MODP_G_BIN[]     = MBEDTLS_DHM_RFC3526_MODP_2048_G_BIN;   /* g = 2 for all */

typedef struct { const unsigned char *p; size_t plen; size_t xlen; } modp_t;
static int modp_params(weirdike_dh_id_t group, modp_t *m) {
    switch (group) {
        case WEIRDIKE_DH_MODP2048: m->p = MODP2048_P_BIN; m->plen = sizeof(MODP2048_P_BIN); m->xlen = 32; return 0;
        case WEIRDIKE_DH_MODP3072: m->p = MODP3072_P_BIN; m->plen = sizeof(MODP3072_P_BIN); m->xlen = 40; return 0;
        case WEIRDIKE_DH_MODP4096: m->p = MODP4096_P_BIN; m->plen = sizeof(MODP4096_P_BIN); m->xlen = 48; return 0;
        default: return -1;
    }
}
typedef struct { size_t coord; mbedtls_ecp_group_id id; int montgomery; } ecp_t;
static int ecp_params(weirdike_dh_id_t group, ecp_t *e) {
    switch (group) {
        case WEIRDIKE_DH_ECP256:     e->coord = 32; e->id = MBEDTLS_ECP_DP_SECP256R1;  e->montgomery = 0; return 0;
        case WEIRDIKE_DH_ECP384:     e->coord = 48; e->id = MBEDTLS_ECP_DP_SECP384R1;  e->montgomery = 0; return 0;
        case WEIRDIKE_DH_ECP521:     e->coord = 66; e->id = MBEDTLS_ECP_DP_SECP521R1;  e->montgomery = 0; return 0;
        case WEIRDIKE_DH_BP256:      e->coord = 32; e->id = MBEDTLS_ECP_DP_BP256R1;    e->montgomery = 0; return 0;
        case WEIRDIKE_DH_BP384:      e->coord = 48; e->id = MBEDTLS_ECP_DP_BP384R1;    e->montgomery = 0; return 0;
        case WEIRDIKE_DH_BP512:      e->coord = 64; e->id = MBEDTLS_ECP_DP_BP512R1;    e->montgomery = 0; return 0;
        case WEIRDIKE_DH_CURVE25519: e->coord = 32; e->id = MBEDTLS_ECP_DP_CURVE25519; e->montgomery = 1; return 0;
        default: return -1;
    }
}

/* MODP peer value checks (RFC 2631 2.1.5 / NIST SP 800-56A 5.6.2.3.1): 2 <= Y <= P-2, and the shared
 * secret must not be trivial (0, 1, P-1). A peer sending such values would force a known secret. */
static int modp_peer_in_range(const mbedtls_mpi *Y, const mbedtls_mpi *P) {
    mbedtls_mpi lim; mbedtls_mpi_init(&lim);
    int ok = mbedtls_mpi_sub_int(&lim, P, 2) == 0 && mbedtls_mpi_cmp_mpi(Y, &lim) <= 0;
    mbedtls_mpi_free(&lim);
    return ok;
}
static int modp_secret_nontrivial(const mbedtls_mpi *S, const mbedtls_mpi *P) {
    mbedtls_mpi lim; mbedtls_mpi_init(&lim);
    int ok = mbedtls_mpi_cmp_int(S, 1) > 0 && mbedtls_mpi_sub_int(&lim, P, 1) == 0 && mbedtls_mpi_cmp_mpi(S, &lim) < 0;
    mbedtls_mpi_free(&lim);
    return ok;
}

/* Private handles: MODP keeps the exponent; ECP keeps the loaded group + scalar. */
typedef struct { int is_ecp; mbedtls_mpi x; mbedtls_ecp_group grp; mbedtls_mpi d; } ke_priv_t;

static int cb_ke_keygen(void *ctx, weirdike_dh_id_t group, void **priv_out, uint8_t *pub_out, size_t *pub_len) {
    weirdike_mbedtls_ctx *mc = (weirdike_mbedtls_ctx *)ctx;
    *priv_out = NULL;
    modp_t m; ecp_t e;
    ke_priv_t *h = (ke_priv_t *)malloc(sizeof(*h));
    if (!h) return -1;
    memset(h, 0, sizeof(*h));
    int rc = -1;
    if (modp_params(group, &m) == 0) {
        if (*pub_len < m.plen) { free(h); return -1; }
        mbedtls_mpi P, G, GX; mbedtls_mpi_init(&P); mbedtls_mpi_init(&G); mbedtls_mpi_init(&GX); mbedtls_mpi_init(&h->x);
        if (mbedtls_mpi_read_binary(&P, m.p, m.plen) == 0 &&
            mbedtls_mpi_read_binary(&G, MODP_G_BIN, sizeof(MODP_G_BIN)) == 0 &&
            /* private exponent: twice the security strength of the group (RFC 3526 guidance) */
            mbedtls_mpi_fill_random(&h->x, m.xlen, mbedtls_ctr_drbg_random, &mc->drbg) == 0 &&
            mbedtls_mpi_exp_mod(&GX, &G, &h->x, &P, NULL) == 0 &&
            mbedtls_mpi_write_binary(&GX, pub_out, m.plen) == 0) {      /* left-padded to the modulus length */
            *pub_len = m.plen; rc = 0;
        }
        mbedtls_mpi_free(&P); mbedtls_mpi_free(&G); mbedtls_mpi_free(&GX);
        if (rc != 0) mbedtls_mpi_free(&h->x);
    } else if (ecp_params(group, &e) == 0) {
        size_t need = e.montgomery ? e.coord : 2 * e.coord;
        if (*pub_len < need) { free(h); return -1; }
        h->is_ecp = 1;
        mbedtls_ecp_group_init(&h->grp); mbedtls_mpi_init(&h->d);
        mbedtls_ecp_point Q; mbedtls_ecp_point_init(&Q);
        if (mbedtls_ecp_group_load(&h->grp, e.id) == 0 &&
            mbedtls_ecdh_gen_public(&h->grp, &h->d, &Q, mbedtls_ctr_drbg_random, &mc->drbg) == 0) {
            if (e.montgomery) {
                if (mbedtls_mpi_write_binary_le(&Q.MBEDTLS_PRIVATE(X), pub_out, e.coord) == 0) { *pub_len = e.coord; rc = 0; }
            } else {
                if (mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), pub_out, e.coord) == 0 &&
                    mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(Y), pub_out + e.coord, e.coord) == 0) { *pub_len = 2 * e.coord; rc = 0; }
            }
        }
        mbedtls_ecp_point_free(&Q);
        if (rc != 0) { mbedtls_ecp_group_free(&h->grp); mbedtls_mpi_free(&h->d); }
    } else {
        free(h); return -1;
    }
    if (rc != 0) { free(h); return -1; }
    *priv_out = h;
    return 0;
}

static int cb_ke_shared(void *ctx, weirdike_dh_id_t group, void *priv,
                        const uint8_t *peer_pub, size_t peer_len, uint8_t *shared_out, size_t *shared_len) {
    weirdike_mbedtls_ctx *mc = (weirdike_mbedtls_ctx *)ctx;
    ke_priv_t *h = (ke_priv_t *)priv;
    if (!h) return -1;
    modp_t m; ecp_t e;
    int rc = -1;
    if (!h->is_ecp && modp_params(group, &m) == 0) {
        if (*shared_len < m.plen || peer_len != m.plen) return -1;
        mbedtls_mpi P, Y, S; mbedtls_mpi_init(&P); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&S);
        if (mbedtls_mpi_read_binary(&P, m.p, m.plen) == 0 &&
            mbedtls_mpi_read_binary(&Y, peer_pub, peer_len) == 0 &&
            mbedtls_mpi_cmp_int(&Y, 2) >= 0 &&                            /* 2 <= Y <= P-2: reject 0, 1, P-1 and >= P (small-subgroup / trivial values) */
            modp_peer_in_range(&Y, &P) &&
            mbedtls_mpi_exp_mod(&S, &Y, &h->x, &P, NULL) == 0 &&
            modp_secret_nontrivial(&S, &P) &&                           /* S must not be 0, 1 or P-1 */
            mbedtls_mpi_write_binary(&S, shared_out, m.plen) == 0) {      /* zero-left-padded (RFC 7296) */
            *shared_len = m.plen; rc = 0;
        }
        mbedtls_mpi_free(&P); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&S);
    } else if (h->is_ecp && ecp_params(group, &e) == 0) {
        size_t need = e.montgomery ? e.coord : 2 * e.coord;
        if (peer_len != need || *shared_len < e.coord) return -1;
        mbedtls_ecp_point Qp; mbedtls_mpi z; mbedtls_ecp_point_init(&Qp); mbedtls_mpi_init(&z);
        int ok;
        if (e.montgomery) {
            ok = mbedtls_mpi_read_binary_le(&Qp.MBEDTLS_PRIVATE(X), peer_pub, e.coord) == 0 &&
                 mbedtls_mpi_lset(&Qp.MBEDTLS_PRIVATE(Z), 1) == 0;
        } else {
            ok = mbedtls_mpi_read_binary(&Qp.MBEDTLS_PRIVATE(X), peer_pub, e.coord) == 0 &&
                 mbedtls_mpi_read_binary(&Qp.MBEDTLS_PRIVATE(Y), peer_pub + e.coord, e.coord) == 0 &&
                 mbedtls_mpi_lset(&Qp.MBEDTLS_PRIVATE(Z), 1) == 0 &&
                 mbedtls_ecp_check_pubkey(&h->grp, &Qp) == 0;               /* point must be on the curve */
        }
        if (ok && mbedtls_ecdh_compute_shared(&h->grp, &z, &Qp, &h->d, mbedtls_ctr_drbg_random, &mc->drbg) == 0) {
            if (e.montgomery) { if (mbedtls_mpi_write_binary_le(&z, shared_out, e.coord) == 0) { *shared_len = e.coord; rc = 0; } }
            else              { if (mbedtls_mpi_write_binary(&z, shared_out, e.coord) == 0)    { *shared_len = e.coord; rc = 0; } }
        }
        mbedtls_ecp_point_free(&Qp); mbedtls_mpi_free(&z);
    }
    return rc;
}

static void cb_ke_free(void *ctx, weirdike_dh_id_t group, void *priv) {
    (void)ctx; (void)group;
    if (!priv) return;
    ke_priv_t *h = (ke_priv_t *)priv;
    if (h->is_ecp) { mbedtls_ecp_group_free(&h->grp); mbedtls_mpi_free(&h->d); }
    else mbedtls_mpi_free(&h->x);
    memset(h, 0, sizeof(*h));
    free(h);
}

/* ---- Trust model: X.509 (server authentication before EAP) ----
 * Chain: leaf (+ intermediates from the CERT payloads, + extra_pem chain MATERIAL) must end at a
 * trust anchor according to trust_mode. No CRL/OCSP (MCU client). expect_id, when given, must match
 * the leaf's SubjectAltName (DNS/IP/email) or CN -- mbedTLS does that inside mbedtls_x509_crt_verify.
 * Anchors need not be self-signed: mbedTLS accepts any certificate of the trusted list as chain end.
 * A leaf byte-identical to an anchor ("exact server certificate") is trusted directly: mbedTLS does
 * that only for SELF-SIGNED leaves ("locally trusted EE"), so pin_vrfy clears the trust flags at
 * depth 0 for a pinned leaf -- the identity check (CN_MISMATCH) is deliberately kept. */
typedef struct { const uint8_t *leaf; size_t leaf_len; int pinned; } pin_ctx_t;

static int pin_vrfy(void *p, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
    pin_ctx_t *pc = (pin_ctx_t *)p;
    if (depth == 0 && pc->pinned && crt->raw.len == pc->leaf_len && memcmp(crt->raw.p, pc->leaf, pc->leaf_len) == 0)
        *flags &= MBEDTLS_X509_BADCERT_CN_MISMATCH;
    return 0;
}

/* PEM parse needs the terminating NUL included in the length -> private copy, wiped afterwards.
 * Strict: every certificate of the block must parse (a half-usable anchor list is a config error). */
static int parse_pem_into(mbedtls_x509_crt *dst, const char *pem, size_t len) {
    if (!pem || !len) return 0;
    uint8_t *buf = (uint8_t *)malloc(len + 1);
    if (!buf) return -1;
    memcpy(buf, pem, len); buf[len] = 0;
    int rc = mbedtls_x509_crt_parse(dst, buf, len + 1);
    memset(buf, 0, len + 1); free(buf);
    return rc != 0 ? -1 : 0;
}

static int rc_from_verify(int vrc, uint32_t flags) {
    if (vrc == 0) return 0;
    return (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) && !(flags & ~(uint32_t)MBEDTLS_X509_BADCERT_CN_MISMATCH) ? -2 : -1;
}

static int cb_x509_verify(void *ctx, int trust_mode, const uint8_t *leaf_der, size_t leaf_len,
                          const uint8_t *inter_der, size_t inter_len,
                          const char *ca_pem, size_t ca_pem_len,
                          const char *extra_pem, size_t extra_pem_len, const char *expect_id) {
    weirdike_mbedtls_ctx *mc = (weirdike_mbedtls_ctx *)ctx;
    if (!leaf_der || !leaf_len) return -1;
    mbedtls_x509_crt chain, ca; mbedtls_x509_crt_init(&chain); mbedtls_x509_crt_init(&ca);
    int rc = -1;
    uint32_t flags = 0;
    if (mbedtls_x509_crt_parse_der(&chain, leaf_der, leaf_len) != 0) goto done;
    if (inter_der && inter_len) {
        /* one or more DER certificates back to back */
        size_t off = 0;
        while (off + 4 <= inter_len) {
            if (inter_der[off] != 0x30) break;
            size_t l = 0, hdr = 0;
            uint8_t b1 = inter_der[off + 1];
            if (b1 < 0x80) { l = b1; hdr = 2; }
            else if (b1 == 0x81 && off + 3 <= inter_len) { l = inter_der[off + 2]; hdr = 3; }
            else if (b1 == 0x82 && off + 4 <= inter_len) { l = ((size_t)inter_der[off + 2] << 8) | inter_der[off + 3]; hdr = 4; }
            else break;
            if (off + hdr + l > inter_len) break;
            if (mbedtls_x509_crt_parse_der(&chain, inter_der + off, hdr + l) != 0) break;
            off += hdr + l;
        }
    }
    /* extra_pem is chain MATERIAL: it joins the chain, never the trusted list */
    if (parse_pem_into(&chain, extra_pem, extra_pem_len) != 0) goto done;

    if (trust_mode == (int)WEIRDIKE_TRUST_NONE) { rc = 0; goto done; }   /* parsable leaf is all; the signature check is separate */

    /* explicit anchors (ANCHOR_PEM, or the optional extra anchors of HOST_STORE_PLUS_PEM) */
    if (trust_mode != (int)WEIRDIKE_TRUST_HOST_STORE && ca_pem && ca_pem_len) {
        if (parse_pem_into(&ca, ca_pem, ca_pem_len) != 0) goto done;
        pin_ctx_t pc; pc.leaf = leaf_der; pc.leaf_len = leaf_len; pc.pinned = 0;
        for (const mbedtls_x509_crt *a = &ca; a; a = a->next)
            if (a->raw.len == leaf_len && memcmp(a->raw.p, leaf_der, leaf_len) == 0) { pc.pinned = 1; break; }
        int vrc = mbedtls_x509_crt_verify(&chain, &ca, NULL, expect_id, &flags, pin_vrfy, &pc);   /* flags AFTER the call (argument order is unspecified) */
        rc = rc_from_verify(vrc, flags);
        if (rc != -1 || trust_mode == (int)WEIRDIKE_TRUST_ANCHOR_PEM) goto done;   /* decided (0/-2); -1 is final for ANCHOR_PEM */
    } else if (trust_mode == (int)WEIRDIKE_TRUST_ANCHOR_PEM) {
        goto done;   /* no anchors = nothing to trust (the core refuses this configuration already) */
    }

    /* host trust store: HOST_STORE, or HOST_STORE_PLUS_PEM after the extra anchors did not match */
    if (!mc || !mc->has_host) goto done;
    flags = 0;
    int hrc = mbedtls_x509_crt_verify(&chain, mc->host.ca_chain, NULL, expect_id, &flags, mc->host.f_vrfy, mc->host.p_vrfy);
    rc = rc_from_verify(hrc, flags);
done:
    mbedtls_x509_crt_free(&chain); mbedtls_x509_crt_free(&ca);
    return rc;
}

static int cb_x509_host_store(void *ctx) {
    weirdike_mbedtls_ctx *mc = (weirdike_mbedtls_ctx *)ctx;
    return mc && mc->has_host;
}

/* Signature over `data` with the leaf's public key.
 *  method 1  = RSA Digital Signature: RSASSA-PKCS1-v1_5 over SHA-1(data) (RFC 7296 3.8).
 *  method 14 = Digital Signature (RFC 7427): sig = [len(1)] AlgorithmIdentifier(DER) | signature.
 *              Supported: sha256/384/512WithRSAEncryption, RSASSA-PSS (sha256), ecdsa-with-SHA256/384/512. */
static int cb_x509_verify_sig(void *ctx, const uint8_t *leaf_der, size_t leaf_len, int method,
                              const uint8_t *data, size_t data_len, const uint8_t *sig, size_t sig_len) {
    (void)ctx;
    if (!leaf_der || !leaf_len || !data || !sig || sig_len == 0) return -1;
    mbedtls_x509_crt crt; mbedtls_x509_crt_init(&crt);
    int rc = -1;
    if (mbedtls_x509_crt_parse_der(&crt, leaf_der, leaf_len) != 0) goto done;
    mbedtls_md_type_t md = MBEDTLS_MD_NONE;
    mbedtls_pk_type_t want = MBEDTLS_PK_NONE;
    const uint8_t *s = sig; size_t sl = sig_len;
    if (method == 1) {
        md = MBEDTLS_MD_SHA1; want = MBEDTLS_PK_RSA;
    } else if (method == 14) {
        /* ASN.1 Length (1 byte) | AlgorithmIdentifier | signature */
        size_t al = sig[0];
        if (al < 2 || 1 + al > sig_len) goto done;
        unsigned char *p = (unsigned char *)sig + 1; const unsigned char *end = p + al;
        size_t seq_len = 0;
        if (mbedtls_asn1_get_tag(&p, end, &seq_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) goto done;
        mbedtls_asn1_buf oid; oid.tag = 0; oid.len = 0; oid.p = NULL;
        size_t oid_len = 0;
        if (mbedtls_asn1_get_tag(&p, end, &oid_len, MBEDTLS_ASN1_OID) != 0) goto done;
        oid.tag = MBEDTLS_ASN1_OID; oid.len = oid_len; oid.p = p;
        mbedtls_pk_type_t pk_alg;
        if (mbedtls_oid_get_sig_alg(&oid, &md, &pk_alg) != 0) goto done;
        want = pk_alg;   /* RSA, RSASSA_PSS or ECDSA */
        s = sig + 1 + al; sl = sig_len - 1 - al;
    } else goto done;
    const mbedtls_md_info_t *mi = mbedtls_md_info_from_type(md);
    if (!mi) goto done;
    unsigned char hash[64]; size_t hl = mbedtls_md_get_size(mi);
    if (mbedtls_md(mi, data, data_len, hash) != 0) goto done;
    if (want == MBEDTLS_PK_RSASSA_PSS) {
        if (!mbedtls_pk_can_do(&crt.pk, MBEDTLS_PK_RSA)) goto done;
        mbedtls_pk_rsassa_pss_options o; o.mgf1_hash_id = md; o.expected_salt_len = MBEDTLS_RSA_SALT_LEN_ANY;
        if (mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS, &o, &crt.pk, md, hash, hl, s, sl) == 0) rc = 0;
    } else {
        if (!mbedtls_pk_can_do(&crt.pk, want)) goto done;
        if (mbedtls_pk_verify(&crt.pk, md, hash, hl, s, sl) == 0) rc = 0;
    }
done:
    mbedtls_x509_crt_free(&crt);
    return rc;
}

/* ---- public ---- */
int weirdike_crypto_mbedtls_init(weirdike_mbedtls_ctx *mc) {
    const char *pers = "weirdike-ike";
    mbedtls_entropy_init(&mc->entropy);
    mbedtls_ctr_drbg_init(&mc->drbg);
    int rc = mbedtls_ctr_drbg_seed(&mc->drbg, mbedtls_entropy_func, &mc->entropy,
                                   (const unsigned char *)pers, strlen(pers));
    mc->inited = (rc == 0);
    memset(&mc->host, 0, sizeof(mc->host)); mc->has_host = 0;
    return rc;
}

void weirdike_crypto_mbedtls_bind(weirdike_mbedtls_ctx *mc, weirdike_crypto_t *out) {
    memset(out, 0, sizeof(*out));
    out->ctx         = mc;
    out->random      = cb_random;
    out->sha1        = cb_sha1;
    out->sha256      = cb_sha256;
    out->sha384      = cb_sha384;
    out->sha512      = cb_sha512;
    out->hmac_sha1   = cb_hmac_sha1;
    out->hmac_sha256 = cb_hmac_sha256;
    out->hmac_sha384 = cb_hmac_sha384;
    out->hmac_sha512 = cb_hmac_sha512;
    out->aes_cbc     = cb_aes_cbc;
    out->aes_gcm     = cb_aes_gcm;
    out->ke_keygen   = cb_ke_keygen;
    out->ke_shared   = cb_ke_shared;
    out->ke_free     = cb_ke_free;
    out->x509_verify     = cb_x509_verify;       /* AP7 + trust model */
    out->x509_host_store = cb_x509_host_store;
    out->x509_verify_sig = cb_x509_verify_sig;   /* AP7 */
}

void weirdike_crypto_mbedtls_set_host_store(weirdike_mbedtls_ctx *mc, const weirdike_mbedtls_host_store_t *hs) {
    if (hs && (hs->ca_chain || hs->f_vrfy)) { mc->host = *hs; mc->has_host = 1; }
    else { memset(&mc->host, 0, sizeof(mc->host)); mc->has_host = 0; }
}

void weirdike_crypto_mbedtls_free(weirdike_mbedtls_ctx *mc) {
    mbedtls_ctr_drbg_free(&mc->drbg);
    mbedtls_entropy_free(&mc->entropy);
    mc->inited = 0;
}
