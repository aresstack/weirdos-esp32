/*
 * WeirdIKE -- eap_mschapv2_crypto.c : RFC 2759 / RFC 3079 primitives for EAP-MSCHAPv2.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * SECURITY BOUNDARY: MD4 and DES exist ONLY here because MS-CHAPv2 requires them. Do not expose
 * them through ike_crypto.h and do not reuse them as IKE/ESP transforms.
 */
#include "eap_mschapv2_crypto.h"
#include <string.h>

static void wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* -------------------------------- MD4 (RFC 1320) -------------------------------- */
typedef struct {
    uint32_t h[4];
    uint64_t bytes;
    uint8_t block[64];
    size_t used;
} md4_ctx_t;

static uint32_t rol32(uint32_t x, unsigned n) { return (x << n) | (x >> (32u - n)); }
static uint32_t rdle32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void wrle32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
#define F(x,y,z) (((x) & (y)) | (~(x) & (z)))
#define G(x,y,z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x,y,z) ((x) ^ (y) ^ (z))
#define R1(a,b,c,d,k,s) ((a) = rol32((a) + F((b),(c),(d)) + x[(k)], (s)))
#define R2(a,b,c,d,k,s) ((a) = rol32((a) + G((b),(c),(d)) + x[(k)] + 0x5a827999u, (s)))
#define R3(a,b,c,d,k,s) ((a) = rol32((a) + H((b),(c),(d)) + x[(k)] + 0x6ed9eba1u, (s)))

static void md4_transform(md4_ctx_t *c, const uint8_t block[64]) {
    uint32_t x[16];
    for (int i = 0; i < 16; i++) x[i] = rdle32(block + 4 * i);
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];

    R1(a,b,cc,d, 0,3); R1(d,a,b,cc, 1,7); R1(cc,d,a,b, 2,11); R1(b,cc,d,a, 3,19);
    R1(a,b,cc,d, 4,3); R1(d,a,b,cc, 5,7); R1(cc,d,a,b, 6,11); R1(b,cc,d,a, 7,19);
    R1(a,b,cc,d, 8,3); R1(d,a,b,cc, 9,7); R1(cc,d,a,b,10,11); R1(b,cc,d,a,11,19);
    R1(a,b,cc,d,12,3); R1(d,a,b,cc,13,7); R1(cc,d,a,b,14,11); R1(b,cc,d,a,15,19);

    R2(a,b,cc,d, 0,3); R2(d,a,b,cc, 4,5); R2(cc,d,a,b, 8,9); R2(b,cc,d,a,12,13);
    R2(a,b,cc,d, 1,3); R2(d,a,b,cc, 5,5); R2(cc,d,a,b, 9,9); R2(b,cc,d,a,13,13);
    R2(a,b,cc,d, 2,3); R2(d,a,b,cc, 6,5); R2(cc,d,a,b,10,9); R2(b,cc,d,a,14,13);
    R2(a,b,cc,d, 3,3); R2(d,a,b,cc, 7,5); R2(cc,d,a,b,11,9); R2(b,cc,d,a,15,13);

    R3(a,b,cc,d, 0,3); R3(d,a,b,cc, 8,9); R3(cc,d,a,b, 4,11); R3(b,cc,d,a,12,15);
    R3(a,b,cc,d, 2,3); R3(d,a,b,cc,10,9); R3(cc,d,a,b, 6,11); R3(b,cc,d,a,14,15);
    R3(a,b,cc,d, 1,3); R3(d,a,b,cc, 9,9); R3(cc,d,a,b, 5,11); R3(b,cc,d,a,13,15);
    R3(a,b,cc,d, 3,3); R3(d,a,b,cc,11,9); R3(cc,d,a,b, 7,11); R3(b,cc,d,a,15,15);

    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    wipe(x, sizeof(x));
}

static void md4_init(md4_ctx_t *c) {
    memset(c, 0, sizeof(*c));
    c->h[0] = 0x67452301u; c->h[1] = 0xefcdab89u;
    c->h[2] = 0x98badcfeu; c->h[3] = 0x10325476u;
}
static void md4_update(md4_ctx_t *c, const uint8_t *p, size_t n) {
    c->bytes += n;
    while (n) {
        size_t take = 64 - c->used;
        if (take > n) take = n;
        memcpy(c->block + c->used, p, take);
        c->used += take; p += take; n -= take;
        if (c->used == 64) { md4_transform(c, c->block); c->used = 0; }
    }
}
static void md4_final(md4_ctx_t *c, uint8_t out[16]) {
    uint64_t bits = c->bytes * 8u;
    uint8_t one = 0x80, zero = 0;
    md4_update(c, &one, 1);
    while (c->used != 56) md4_update(c, &zero, 1);
    uint8_t le[8];
    for (int i = 0; i < 8; i++) le[i] = (uint8_t)(bits >> (8 * i));
    md4_update(c, le, sizeof(le));
    for (int i = 0; i < 4; i++) wrle32(out + 4 * i, c->h[i]);
    wipe(c, sizeof(*c));
}
static void md4_one(const uint8_t *p, size_t n, uint8_t out[16]) {
    md4_ctx_t c; md4_init(&c); if (n) md4_update(&c, p, n); md4_final(&c, out);
}

/* ------------------------------ UTF-8 -> UTF-16LE ------------------------------ */
static int utf8_next(const uint8_t *p, size_t n, size_t *used, uint32_t *cp) {
    if (!n) return -1;
    uint8_t b0 = p[0];
    if (b0 < 0x80) { *cp = b0; *used = 1; return 0; }
    unsigned need; uint32_t v;
    if ((b0 & 0xe0) == 0xc0) { need = 2; v = b0 & 0x1f; if (v < 2) return -1; }
    else if ((b0 & 0xf0) == 0xe0) { need = 3; v = b0 & 0x0f; }
    else if ((b0 & 0xf8) == 0xf0) { need = 4; v = b0 & 0x07; }
    else return -1;
    if (n < need) return -1;
    for (unsigned i = 1; i < need; i++) {
        if ((p[i] & 0xc0) != 0x80) return -1;
        v = (v << 6) | (p[i] & 0x3f);
    }
    if ((need == 3 && v < 0x800) || (need == 4 && v < 0x10000)) return -1;
    if (v > 0x10ffff || (v >= 0xd800 && v <= 0xdfff)) return -1;
    *cp = v; *used = need; return 0;
}

int mschapv2_nt_password_hash(const uint8_t *password_utf8, size_t password_len, uint8_t out[16]) {
    if (!out || (password_len && !password_utf8)) return -1;
    /* NT hash = MD4(UTF-16LE(password)). MD4 is streamed code point by code point -- no 1 KB
     * UTF-16 copy of the password on the stack (and nothing to wipe but the MD4 state). */
    md4_ctx_t md; md4_init(&md);
    size_t pos = 0, chars = 0;
    while (pos < password_len) {
        uint32_t cp; size_t used; uint8_t u[4]; size_t n;
        if (utf8_next(password_utf8 + pos, password_len - pos, &used, &cp) != 0) { wipe(&md, sizeof(md)); return -1; }
        if (++chars > 256) { wipe(&md, sizeof(md)); return -1; }
        if (cp < 0x10000) {
            u[0] = (uint8_t)cp; u[1] = (uint8_t)(cp >> 8); n = 2;
        } else {
            cp -= 0x10000;
            uint16_t hi = (uint16_t)(0xd800u | (cp >> 10));
            uint16_t lo = (uint16_t)(0xdc00u | (cp & 0x3ff));
            u[0] = (uint8_t)hi; u[1] = (uint8_t)(hi >> 8); u[2] = (uint8_t)lo; u[3] = (uint8_t)(lo >> 8); n = 4;
        }
        md4_update(&md, u, n);
        wipe(u, sizeof(u));
        pos += used;
    }
    md4_final(&md, out);
    wipe(&md, sizeof(md));
    return 0;
}

int mschapv2_hash_nt_password_hash(const uint8_t nt_hash[16], uint8_t out[16]) {
    if (!nt_hash || !out) return -1;
    md4_one(nt_hash, 16, out);
    return 0;
}

/* -------------------------------- DES (FIPS 46-3, private) -------------------------------- */
static const uint8_t IP[64] = {
58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4, 62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
57,49,41,33,25,17,9,1, 59,51,43,35,27,19,11,3, 61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7};
static const uint8_t FP[64] = {
40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31, 38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27, 34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25};
static const uint8_t E[48] = {32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13, 12,13,14,15,16,17,
16,17,18,19,20,21, 20,21,22,23,24,25, 24,25,26,27,28,29, 28,29,30,31,32,1};
static const uint8_t P[32] = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
static const uint8_t PC1[56] = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
static const uint8_t PC2[48] = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
static const uint8_t SH[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
static const uint8_t SBOX[8][64] = {
{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8, 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5, 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1, 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9, 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6, 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8, 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6, 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2, 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
};

static uint64_t permute(uint64_t in, const uint8_t *table, int n, int in_bits) {
    uint64_t out = 0;
    for (int i = 0; i < n; i++) { out <<= 1; out |= (in >> (in_bits - table[i])) & 1u; }
    return out;
}
static uint64_t load_be64(const uint8_t b[8]) { uint64_t v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | b[i]; return v; }
static void store_be64(uint8_t b[8], uint64_t v) { for (int i = 7; i >= 0; i--) { b[i] = (uint8_t)v; v >>= 8; } }
static uint32_t des_f(uint32_t r, uint64_t k48) {
    uint64_t e = permute(r, E, 48, 32) ^ k48; uint32_t s = 0;
    for (int box = 0; box < 8; box++) {
        uint8_t six = (uint8_t)((e >> (42 - 6 * box)) & 0x3f);
        uint8_t row = (uint8_t)(((six & 0x20) >> 4) | (six & 1));
        uint8_t col = (uint8_t)((six >> 1) & 0x0f);
        s = (s << 4) | SBOX[box][row * 16 + col];
    }
    return (uint32_t)permute(s, P, 32, 32);
}
static void des_encrypt_block(const uint8_t key[8], const uint8_t in[8], uint8_t out[8]) {
    uint64_t k56 = permute(load_be64(key), PC1, 56, 64);
    uint32_t c = (uint32_t)(k56 >> 28), d = (uint32_t)(k56 & 0x0fffffffu); uint64_t sub[16];
    for (int round = 0; round < 16; round++) {
        c = ((c << SH[round]) | (c >> (28 - SH[round]))) & 0x0fffffffu;
        d = ((d << SH[round]) | (d >> (28 - SH[round]))) & 0x0fffffffu;
        sub[round] = permute(((uint64_t)c << 28) | d, PC2, 48, 56);
    }
    uint64_t ip = permute(load_be64(in), IP, 64, 64); uint32_t l = (uint32_t)(ip >> 32), r = (uint32_t)ip;
    for (int round = 0; round < 16; round++) { uint32_t nr = l ^ des_f(r, sub[round]); l = r; r = nr; }
    store_be64(out, permute(((uint64_t)r << 32) | l, FP, 64, 64)); wipe(sub, sizeof(sub));
}
static uint8_t odd_parity(uint8_t x) {
    x &= 0xfeu; uint8_t p = x; p ^= p >> 4; p ^= p >> 2; p ^= p >> 1;
    return (uint8_t)(x | ((p & 1u) ^ 1u));
}
void mschapv2_expand_des_key(const uint8_t raw[7], uint8_t key[8]) {
    key[0] = raw[0] & 0xfeu;
    key[1] = (uint8_t)(((raw[0] << 7) | (raw[1] >> 1)) & 0xfeu);
    key[2] = (uint8_t)(((raw[1] << 6) | (raw[2] >> 2)) & 0xfeu);
    key[3] = (uint8_t)(((raw[2] << 5) | (raw[3] >> 3)) & 0xfeu);
    key[4] = (uint8_t)(((raw[3] << 4) | (raw[4] >> 4)) & 0xfeu);
    key[5] = (uint8_t)(((raw[4] << 3) | (raw[5] >> 5)) & 0xfeu);
    key[6] = (uint8_t)(((raw[5] << 2) | (raw[6] >> 6)) & 0xfeu);
    key[7] = (uint8_t)((raw[6] << 1) & 0xfeu);
    for (int i = 0; i < 8; i++) key[i] = odd_parity(key[i]);
}
static void challenge_response(const uint8_t challenge[8], const uint8_t hash[16], uint8_t out[24]) {
    uint8_t z[21] = {0}; memcpy(z, hash, 16);
    for (int i = 0; i < 3; i++) { uint8_t k[8]; mschapv2_expand_des_key(z + 7 * i, k); des_encrypt_block(k, challenge, out + 8 * i); wipe(k, sizeof(k)); }
    wipe(z, sizeof(z));
}

/* -------------------------------- RFC 2759 / 3079 composition -------------------------------- */
static int sha1_concat(const weirdike_crypto_t *cr,
                       const uint8_t *a, size_t an, const uint8_t *b, size_t bn,
                       const uint8_t *c, size_t cn, const uint8_t *d, size_t dn,
                       uint8_t out[20]) {
    if (!cr || !cr->sha1 || !out) return -1;
    /* ChallengeHash = SHA1(PeerChallenge16 | AuthenticatorChallenge16 | UserName<=256) -> up to 288 B;
     * the MSK/authenticator inputs are smaller. A 256-B scratch silently refused long user names. */
    if (an + bn + cn + dn > 512) return -1;
    uint8_t tmp[512]; size_t n = 0;
    if (an) { memcpy(tmp + n, a, an); n += an; }
    if (bn) { memcpy(tmp + n, b, bn); n += bn; }
    if (cn) { memcpy(tmp + n, c, cn); n += cn; }
    if (dn) { memcpy(tmp + n, d, dn); n += dn; }
    int rc = cr->sha1(cr->ctx, tmp, n, out); wipe(tmp, sizeof(tmp)); return rc;
}

int mschapv2_challenge_hash(const weirdike_crypto_t *crypto,
                            const uint8_t peer_challenge[16], const uint8_t authenticator_challenge[16],
                            const uint8_t *username, size_t username_len, uint8_t out[8]) {
    if (!peer_challenge || !authenticator_challenge || !out || (username_len && !username)) return -1;
    if (username_len > 256) return -1;
    uint8_t digest[20];
    if (sha1_concat(crypto, peer_challenge, 16, authenticator_challenge, 16, username, username_len, NULL, 0, digest) != 0) return -1;
    memcpy(out, digest, 8); wipe(digest, sizeof(digest)); return 0;
}

int mschapv2_generate_nt_response(const weirdike_crypto_t *crypto,
                                  const uint8_t authenticator_challenge[16], const uint8_t peer_challenge[16],
                                  const uint8_t *username, size_t username_len,
                                  const uint8_t *password_utf8, size_t password_len, uint8_t out[24]) {
    if (!out) return -1;
    uint8_t challenge[8], hash[16];
    if (mschapv2_challenge_hash(crypto, peer_challenge, authenticator_challenge, username, username_len, challenge) != 0) return -1;
    if (mschapv2_nt_password_hash(password_utf8, password_len, hash) != 0) { wipe(challenge, sizeof(challenge)); return -1; }
    challenge_response(challenge, hash, out); wipe(challenge, sizeof(challenge)); wipe(hash, sizeof(hash)); return 0;
}

int mschapv2_generate_authenticator_response(const weirdike_crypto_t *crypto,
                                             const uint8_t *password_utf8, size_t password_len,
                                             const uint8_t nt_response[24], const uint8_t peer_challenge[16],
                                             const uint8_t authenticator_challenge[16],
                                             const uint8_t *username, size_t username_len, uint8_t out[20]) {
    static const uint8_t magic1[] = "Magic server to client signing constant";
    static const uint8_t magic2[] = "Pad to make it do more than one iteration";
    if (!nt_response || !peer_challenge || !authenticator_challenge || !out) return -1;
    uint8_t ph[16], phh[16], challenge[8], digest[20];
    if (mschapv2_nt_password_hash(password_utf8, password_len, ph) != 0) return -1;
    mschapv2_hash_nt_password_hash(ph, phh);
    if (mschapv2_challenge_hash(crypto, peer_challenge, authenticator_challenge, username, username_len, challenge) != 0) goto fail;
    if (sha1_concat(crypto, phh, 16, nt_response, 24, magic1, sizeof(magic1) - 1, NULL, 0, digest) != 0) goto fail;
    if (sha1_concat(crypto, digest, 20, challenge, 8, magic2, sizeof(magic2) - 1, NULL, 0, out) != 0) goto fail;
    wipe(ph, sizeof(ph)); wipe(phh, sizeof(phh)); wipe(challenge, sizeof(challenge)); wipe(digest, sizeof(digest)); return 0;
fail:
    wipe(ph, sizeof(ph)); wipe(phh, sizeof(phh)); wipe(challenge, sizeof(challenge)); wipe(digest, sizeof(digest)); return -1;
}

int mschapv2_generate_msk(const weirdike_crypto_t *crypto,
                          const uint8_t *password_utf8, size_t password_len,
                          const uint8_t nt_response[24], uint8_t out[64]) {
    static const uint8_t magic_master[] = "This is the MPPE Master Key";
    static const uint8_t magic_recv[] = "On the client side, this is the receive key; on the server side, it is the send key.";
    static const uint8_t magic_send[] = "On the client side, this is the send key; on the server side, it is the receive key.";
    static const uint8_t pad1[40] = {0};
    static const uint8_t pad2[40] = {
        0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2, 0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,
        0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2, 0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2,0xf2};
    if (!crypto || !crypto->sha1 || !nt_response || !out) return -1;
    uint8_t ph[16], phh[16], master_digest[20], recv_digest[20], send_digest[20];
    if (mschapv2_nt_password_hash(password_utf8, password_len, ph) != 0) return -1;
    mschapv2_hash_nt_password_hash(ph, phh);
    if (sha1_concat(crypto, phh, 16, nt_response, 24, magic_master, sizeof(magic_master) - 1, NULL, 0, master_digest) != 0) goto fail;
    if (sha1_concat(crypto, master_digest, 16, pad1, sizeof(pad1), magic_recv, sizeof(magic_recv) - 1, pad2, sizeof(pad2), recv_digest) != 0) goto fail;
    if (sha1_concat(crypto, master_digest, 16, pad1, sizeof(pad1), magic_send, sizeof(magic_send) - 1, pad2, sizeof(pad2), send_digest) != 0) goto fail;
    /* EAP MSK (draft-kamath-pppext-eap-mschapv2 / RFC 3079 as implemented by strongSwan, wpa_supplicant,
     * FreeRADIUS): MasterReceiveKey-of-the-AUTHENTICATOR first = the key derived with the "client
     * SEND key" magic, then the one with the "client RECEIVE key" magic, then 32 zero bytes. The
     * previous order (receive|send from the client's view) made the IKEv2 final AUTH fail against
     * strongSwan ("verification of AUTH payload with EAP MSK failed"). */
    memcpy(out, send_digest, 16); memcpy(out + 16, recv_digest, 16); memset(out + 32, 0, 32);
    wipe(ph, sizeof(ph)); wipe(phh, sizeof(phh)); wipe(master_digest, sizeof(master_digest)); wipe(recv_digest, sizeof(recv_digest)); wipe(send_digest, sizeof(send_digest)); return 0;
fail:
    wipe(ph, sizeof(ph)); wipe(phh, sizeof(phh)); wipe(master_digest, sizeof(master_digest)); wipe(recv_digest, sizeof(recv_digest)); wipe(send_digest, sizeof(send_digest)); memset(out, 0, 64); return -1;
}
