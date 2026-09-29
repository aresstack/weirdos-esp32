/*
 * WeirdIKE -- eap_mschapv2_crypto.h : EAP-MSCHAPv2 credential mathematics.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Keep the legacy MD4/DES primitives PRIVATE to this module. They are required by MS-CHAPv2
 * (RFC 2759) but are not IKE transforms and must never become generic WeirdIKE cipher choices.
 */
#ifndef WEIRDIKE_EAP_MSCHAPV2_CRYPTO_H
#define WEIRDIKE_EAP_MSCHAPV2_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include "ike_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MSCHAPV2_CHALLENGE_LEN 16
#define MSCHAPV2_NT_RESPONSE_LEN 24
#define MSCHAPV2_AUTH_RESPONSE_LEN 20
#define MSCHAPV2_MSK_LEN 64

/* Convert UTF-8 password to UTF-16LE and compute the NT hash (MD4). */
int mschapv2_nt_password_hash(const uint8_t *password_utf8, size_t password_len,
                              uint8_t out[16]);

/* Hash a 16-byte NT hash again with MD4 (PasswordHashHash). */
int mschapv2_hash_nt_password_hash(const uint8_t nt_hash[16], uint8_t out[16]);

/* RFC 2759 ChallengeHash(). username is the account name only (without DOMAIN\\ prefix). */
int mschapv2_challenge_hash(const weirdike_crypto_t *crypto,
                            const uint8_t peer_challenge[16],
                            const uint8_t authenticator_challenge[16],
                            const uint8_t *username, size_t username_len,
                            uint8_t out[8]);

/* RFC 2759 GenerateNTResponse(). */
int mschapv2_generate_nt_response(const weirdike_crypto_t *crypto,
                                  const uint8_t authenticator_challenge[16],
                                  const uint8_t peer_challenge[16],
                                  const uint8_t *username, size_t username_len,
                                  const uint8_t *password_utf8, size_t password_len,
                                  uint8_t out[24]);

/* RFC 2759 GenerateAuthenticatorResponse(). Returns the raw 20-byte value after "S=". */
int mschapv2_generate_authenticator_response(const weirdike_crypto_t *crypto,
                                             const uint8_t *password_utf8, size_t password_len,
                                             const uint8_t nt_response[24],
                                             const uint8_t peer_challenge[16],
                                             const uint8_t authenticator_challenge[16],
                                             const uint8_t *username, size_t username_len,
                                             uint8_t out[20]);

/* RFC 3079 key derivation as used by EAP-MSCHAPv2. Produce the 64-byte EAP MSK:
 * receive-key[16] | send-key[16] | zero[32] (peer/client perspective). */
int mschapv2_generate_msk(const weirdike_crypto_t *crypto,
                          const uint8_t *password_utf8, size_t password_len,
                          const uint8_t nt_response[24],
                          uint8_t out[64]);

/* Expand one 56-bit DES key to 64 bits with odd parity (RFC 2759 8.6 / 9.3). Public only for
 * deterministic RFC-vector tests; the DES block primitive itself stays private. */
void mschapv2_expand_des_key(const uint8_t raw[7], uint8_t key[8]);

#ifdef __cplusplus
}
#endif

#endif /* WEIRDIKE_EAP_MSCHAPV2_CRYPTO_H */
