/*
 * WeirdIKE -- src/core/ike_auth.h : IKEv2 PSK AUTH primitives (RFC 7296 2.15). Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * MACedID = prf(SK_p, ID')                                (ID' = IDType | 000 | ID data)
 * AUTH    = prf( prf(PSK, "Key Pad for IKEv2"), SignedOctets )
 * SignedOctets = RealMessage | Nonce | MACedID   (assembled by the caller)
 *
 * The PRF is injected as a generic callback (ike_prf_fn) with its output length (prf_len), so the
 * same primitives serve HMAC-SHA256 (32-B MAC/AUTH) and HMAC-SHA512 (64-B) -- byte-exactly testable
 * against fixed vectors. The MACedID and AUTH values are the FULL prf output (prf_len bytes); the
 * INTEG algorithm's truncation applies only to the SK{} ICV, never here.
 */
#ifndef WEIRDIKE_IKE_AUTH_H
#define WEIRDIKE_IKE_AUTH_H

#include <stdint.h>
#include <stddef.h>
#include "ike_keymat.h"   /* ike_prf_fn */

#ifdef __cplusplus
extern "C" {
#endif

#define IKE_AUTH_METHOD_SHARED_KEY  2   /* RFC 7296: Shared Key Message Integrity Code */
#define IKE_AUTH_MAC_MAX           64   /* HMAC-SHA512 full output */

/* MACedID = prf(sk_p, ID')  with ID' = id_type(1) | 3 reserved zero bytes | id_data. Writes exactly
 * prf_len bytes to out (caller sizes out >= prf_len, <= IKE_AUTH_MAC_MAX).
 * Returns 0 on success, -1 on bad args / id too long / prf_len out of range. */
int ike_maced_id(ike_prf_fn prf, void *ctx, size_t prf_len,
                 const uint8_t *sk_p, size_t sk_p_len,
                 uint8_t id_type, const uint8_t *id_data, size_t id_len,
                 uint8_t *out);

/* PSK AUTH = prf( prf(PSK, "Key Pad for IKEv2"), signed_octets ). The caller assembles
 * signed_octets = RealMessage | Nonce | MACedID. Writes prf_len bytes to out. Returns 0 on success. */
int ike_psk_auth(ike_prf_fn prf, void *ctx, size_t prf_len,
                 const uint8_t *psk, size_t psk_len,
                 const uint8_t *signed_octets, size_t signed_len,
                 uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_IKE_AUTH_H */
