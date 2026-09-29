/*
 * WeirdIKE -- ike_crypto.h : crypto provider adapter.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The IKEv2 core is crypto-agnostic. A backend (crypto_mbedtls.c first) implements this vtable.
 * Every callback takes the backend ctx first -> multiple instances / HW backends / tests / several
 * concurrent tunnels stay clean (no global crypto state).
 *
 * IANA IKEv2 transform IDs are modelled as DISTINCT types on purpose: PRF (type 2) and INTEG
 * (type 3) are different transform classes with different IDs (e.g. PRF_HMAC_SHA2_256 == 5 is NOT
 * AUTH_HMAC_SHA2_256_128 == 12). ENCR (type 1) and DH (type 4) likewise.
 *
 * Milestone-1 acceptance uses only: ENCR_AES_CBC(256) + PRF_HMAC_SHA2_256 + AUTH_HMAC_SHA2_256_128
 * + DH MODP2048 + PSK. The rest may be present in the vtable but is not required to interop first.
 */
#ifndef WEIRDIKE_CRYPTO_H
#define WEIRDIKE_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint16_t weirdike_encr_id_t;   /* IKEv2 transform type 1 (ENCR) */
typedef uint16_t weirdike_prf_id_t;    /* IKEv2 transform type 2 (PRF)  */
typedef uint16_t weirdike_integ_id_t;  /* IKEv2 transform type 3 (INTEG/AUTH) */
typedef uint16_t weirdike_dh_id_t;     /* IKEv2 transform type 4 (D-H)  */

/* ENCR (type 1) */
#define WEIRDIKE_ENCR_AES_CBC             12
#define WEIRDIKE_ENCR_AES_GCM_16          20   /* AEAD, 16-byte ICV */
/* PRF (type 2) -- IKE SA key derivation */
#define WEIRDIKE_PRF_HMAC_SHA1             2
#define WEIRDIKE_PRF_HMAC_SHA2_256         5
#define WEIRDIKE_PRF_HMAC_SHA2_384         6
#define WEIRDIKE_PRF_HMAC_SHA2_512         7
/* INTEG / AUTH (type 3) -- ESP + IKE integrity */
#define WEIRDIKE_AUTH_NONE                 0    /* AEAD ciphers carry their own ICV */
#define WEIRDIKE_AUTH_HMAC_SHA1_96         2
#define WEIRDIKE_AUTH_HMAC_SHA2_256_128   12
#define WEIRDIKE_AUTH_HMAC_SHA2_384_192   13
#define WEIRDIKE_AUTH_HMAC_SHA2_512_256   14
/* D-H (type 4) */
#define WEIRDIKE_DH_MODP2048              14
#define WEIRDIKE_DH_MODP3072              15
#define WEIRDIKE_DH_MODP4096              16
#define WEIRDIKE_DH_ECP256                19
#define WEIRDIKE_DH_ECP384                20
#define WEIRDIKE_DH_ECP521                21
#define WEIRDIKE_DH_BP256                 28
#define WEIRDIKE_DH_BP384                 29
#define WEIRDIKE_DH_BP512                 30
#define WEIRDIKE_DH_CURVE25519            31
/* Largest KE public value / shared secret any supported group produces (MODP4096 = 512 B). */
#define WEIRDIKE_KE_MAX                  512

typedef struct {
    void *ctx;                                          /* opaque backend state (passed to all) */

    /* Cryptographically secure RNG. Returns 0 on success. */
    int (*random)(void *ctx, uint8_t *out, size_t len);

    /* One-shot hashes. */
    int (*sha1)  (void *ctx, const uint8_t *in, size_t len, uint8_t out[20]);
    int (*sha256)(void *ctx, const uint8_t *in, size_t len, uint8_t out[32]);
    int (*sha384)(void *ctx, const uint8_t *in, size_t len, uint8_t out[48]);
    int (*sha512)(void *ctx, const uint8_t *in, size_t len, uint8_t out[64]);

    /* One-shot HMAC (used both as PRF and as ESP/IKE integrity). */
    int (*hmac_sha1)  (void *ctx, const uint8_t *key, size_t klen, const uint8_t *in, size_t len, uint8_t out[20]);
    int (*hmac_sha256)(void *ctx, const uint8_t *key, size_t klen, const uint8_t *in, size_t len, uint8_t out[32]);
    int (*hmac_sha384)(void *ctx, const uint8_t *key, size_t klen, const uint8_t *in, size_t len, uint8_t out[48]);
    int (*hmac_sha512)(void *ctx, const uint8_t *key, size_t klen, const uint8_t *in, size_t len, uint8_t out[64]);

    /* AES-CBC. enc != 0 to encrypt. iv is 16 bytes; len must be a multiple of 16. The callback MUST
     * NOT mutate the caller's iv (backends copy it) and MUST support in-place operation (in == out);
     * ike_sk seal/open rely on both. Returns 0 on success. */
    int (*aes_cbc)(void *ctx, int enc, const uint8_t *key, size_t klen, const uint8_t iv[16],
                   const uint8_t *in, size_t len, uint8_t *out);

    /* AES-GCM AEAD. On encrypt, writes tag; on decrypt, verifies tag (returns <0 on mismatch). */
    int (*aes_gcm)(void *ctx, int enc, const uint8_t *key, size_t klen,
                   const uint8_t *iv, size_t ivlen,
                   const uint8_t *aad, size_t aadlen,
                   const uint8_t *in, size_t len, uint8_t *out,
                   uint8_t *tag, size_t taglen);

    /* Key exchange. keygen -> our public value (pub_out/pub_len) + opaque private handle.
     * shared -> shared secret from the peer's public value. group is a WEIRDIKE_DH_* id. */
    int  (*ke_keygen)(void *ctx, weirdike_dh_id_t group, void **priv_out, uint8_t *pub_out, size_t *pub_len);
    int  (*ke_shared)(void *ctx, weirdike_dh_id_t group, void *priv,
                      const uint8_t *peer_pub, size_t peer_len,
                      uint8_t *shared_out, size_t *shared_len);
    void (*ke_free)(void *ctx, weirdike_dh_id_t group, void *priv);

    /* --- AP7: server authentication for EAP (RFC 7296 2.16: the responder MUST authenticate with a
     * certificate/signature before the peer runs EAP). Optional in the vtable; a core configured for
     * EAP refuses to start without them. ---
     * x509_verify: TRUST decision for the peer's leaf certificate (DER, CERT payload encoding 4) plus
     *   optional intermediates (DER) according to `trust_mode` (weirdike_trust_mode_t):
     *     ANCHOR_PEM           chain must end at an anchor in ca_pem (anchors need not be self-signed;
     *                          a leaf that is byte-identical to an anchor is trusted directly)
     *     HOST_STORE           chain must end in the HOST trust store (public CAs); ca_pem ignored
     *     HOST_STORE_PLUS_PEM  anchors in ca_pem OR the host store
     *     NONE                 no chain / identity check at all (the signature check below still runs)
     *   extra_pem = additional chain MATERIAL (intermediates) that never ends a chain by itself.
     *   expect_id (non-NULL in modes != NONE) = leaf SubjectAltName/CN must match (DNS/IP/email text).
     *   0 = trusted (+ identity ok), -2 = chain ok but identity mismatch, -1 = not trusted / error.
     * x509_host_store: 1 = the adapter CAN verify against a host trust store (public CAs). A core in a
     *   HOST_STORE mode refuses to start when this is missing or returns 0 -- never a silent fallback.
     * x509_verify_sig: verify `sig` over `data` with the LEAF's public key. method selects the IKEv2
     *   AUTH method: 1 = RSA Digital Signature (RSASSA-PKCS1-v1_5 with SHA-1, RFC 7296 3.8),
     *   14 = Digital Signature (RFC 7427; `sig` = ASN.1 AlgorithmIdentifier length-prefixed +
     *   signature; RSA PKCS#1 v1.5 / RSA-PSS / ECDSA with SHA-256/384/512). 0 = valid.
     *   This runs in EVERY trust mode: "no trust check" never means "no signature check". */
    int (*x509_verify)(void *ctx, int trust_mode,
                       const uint8_t *leaf_der, size_t leaf_len,
                       const uint8_t *inter_der, size_t inter_len,   /* concatenated DER or NULL */
                       const char *ca_pem, size_t ca_pem_len,        /* trust ANCHORS (PEM) or NULL */
                       const char *extra_pem, size_t extra_pem_len,  /* chain MATERIAL (PEM) or NULL */
                       const char *expect_id);
    int (*x509_host_store)(void *ctx);
    int (*x509_verify_sig)(void *ctx, const uint8_t *leaf_der, size_t leaf_len, int method,
                           const uint8_t *data, size_t data_len, const uint8_t *sig, size_t sig_len);
} weirdike_crypto_t;

/* Trust decision for the EAP server certificate (see x509_verify). The value 0 keeps today's
 * semantics for existing configurations (explicit anchors in ca_pem). */
typedef enum {
    WEIRDIKE_TRUST_ANCHOR_PEM          = 0,   /* own trust anchor(s): ca_pem mandatory */
    WEIRDIKE_TRUST_HOST_STORE          = 1,   /* public CAs of the host trust store */
    WEIRDIKE_TRUST_HOST_STORE_PLUS_PEM = 2,   /* host store + extra material and/or extra anchors */
    WEIRDIKE_TRUST_NONE                = 3    /* NOT RECOMMENDED: no chain/identity check (signature only) */
} weirdike_trust_mode_t;

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_CRYPTO_H */
