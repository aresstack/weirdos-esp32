/*
 * WeirdIKE -- src/crypto/crypto_mbedtls.h : mbedTLS backend for weirdike_crypto_t.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Default crypto backend. On ESP32 this rides the ESP-mbedTLS (partly HW-accelerated) and our
 * global mbedTLS->PSRAM memory policy; on host/NuttX it uses libmbedcrypto. The IKE core never
 * sees mbedTLS -- only the weirdike_crypto_t vtable this fills.
 *
 * M1 (IKE_SA_INIT) needs only random + sha1 + DH14; the rest (sha256/hmac/aes-cbc/gcm) is here for
 * the IKE_AUTH / ESP slices. ECP-256 / Curve25519 return an error until implemented.
 */
#ifndef WEIRDIKE_CRYPTO_MBEDTLS_H
#define WEIRDIKE_CRYPTO_MBEDTLS_H

#include "ike_crypto.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#ifdef __cplusplus
extern "C" {
#endif

/* HOST trust store (public CAs) for the trust modes HOST_STORE / HOST_STORE_PLUS_PEM. The host
 * supplies a parsed CA chain (Linux: mbedtls_x509_crt_parse_path("/etc/ssl/certs")) and/or a verify
 * callback pair exactly as mbedTLS uses it (ESP-IDF: the certificate bundle's callback). The
 * adapter knows no platform. Not set = host store unavailable -> the core refuses the host-store
 * trust modes at start() instead of falling back to the PEM anchors or to "no check". */
typedef struct {
    struct mbedtls_x509_crt *ca_chain;      /* may be NULL when f_vrfy alone decides */
    int (*f_vrfy)(void *p_vrfy, struct mbedtls_x509_crt *crt, int depth, uint32_t *flags);
    void *p_vrfy;
} weirdike_mbedtls_host_store_t;

typedef struct {
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context drbg;
    int                      inited;
    weirdike_mbedtls_host_store_t host;     /* see weirdike_crypto_mbedtls_set_host_store */
    int                      has_host;
} weirdike_mbedtls_ctx;

/* Seed the DRBG. Returns 0 on success (an mbedTLS error code otherwise). */
int  weirdike_crypto_mbedtls_init(weirdike_mbedtls_ctx *mc);

/* Fill `out` with the vtable; out->ctx is set to `mc`. Call after init. */
void weirdike_crypto_mbedtls_bind(weirdike_mbedtls_ctx *mc, weirdike_crypto_t *out);

void weirdike_crypto_mbedtls_free(weirdike_mbedtls_ctx *mc);

/* Attach (hs != NULL with a chain and/or callback) or remove (NULL) the host trust store. The chain
 * and callback context must outlive the adapter context. */
void weirdike_crypto_mbedtls_set_host_store(weirdike_mbedtls_ctx *mc, const weirdike_mbedtls_host_store_t *hs);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_CRYPTO_MBEDTLS_H */
