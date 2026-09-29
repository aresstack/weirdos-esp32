/*
 * WeirdIKE -- src/core/ike_keymat.c : IKEv2 SKEYSEED + prf+ key schedule (RFC 7296). Pure C99.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ike_keymat.h"
#include <string.h>

#define KDF_MAX_SEED  600          /* Ni|Nr|SPIi|SPIr; Ni/Nr <= 256 each per RFC 7296 */
#define KDF_MAX_NINR  512          /* Ni|Nr */
#define KDF_KEYMAT    512          /* >= 3*prf + 2*integ + 2*encr (SHA-512 suite = 384) */
#define GIR_MAX_LEN   512   /* g^ir up to MODP4096 (B2/B3); ECP secrets are shorter */

static void wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

int ike_prf_plus(ike_prf_fn prf, void *ctx, size_t prf_len,
                 const uint8_t *key, size_t key_len,
                 const uint8_t *seed, size_t seed_len,
                 uint8_t *out, size_t out_len) {
    if (!prf || !key || (!seed && seed_len) || (!out && out_len)) return -1;
    if (prf_len == 0 || prf_len > IKE_PRF_MAX) return -1;
    if (seed_len > KDF_MAX_SEED) return -1;
    if (out_len > 255u * prf_len) return -1;   /* prf+ counter is one octet -> <= 255 blocks */

    uint8_t t[IKE_PRF_MAX];
    uint8_t in[IKE_PRF_MAX + KDF_MAX_SEED + 1];
    size_t  t_len = 0;
    unsigned counter = 1;
    size_t done = 0;
    int rc = 0;

    while (done < out_len) {
        size_t p = 0;
        if (t_len) { memcpy(in, t, t_len); p += t_len; }          /* T(n-1) for n > 1 */
        if (seed_len) { memcpy(in + p, seed, seed_len); p += seed_len; }
        in[p++] = (uint8_t)counter;
        if (prf(ctx, key, key_len, in, p, t) != 0) { rc = -1; break; }
        t_len = prf_len;
        size_t n = out_len - done;
        if (n > prf_len) n = prf_len;
        memcpy(out + done, t, n);
        done += n;
        counter++;
    }

    wipe(t, sizeof(t));
    wipe(in, sizeof(in));
    if (rc != 0 && out) wipe(out, out_len);   /* never leave partial secret output on failure */
    return rc;
}

/* {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr} = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr),
 * streamed block by block straight into the seven SK_* slots (no contiguous KEYMAT buffer). ONE
 * working buffer holds the prf+ input  T(n-1) | seed | n. Shared by the initial and the rekey KDF. */
static int sk_from_skeyseed(ike_prf_fn prf, void *ctx, size_t prf_len,
                            const uint8_t *skeyseed, size_t skeyseed_len,
                            size_t integ_key_len, size_t encr_key_len,
                            const uint8_t *ni, size_t ni_len, const uint8_t *nr, size_t nr_len,
                            const uint8_t spi_i[8], const uint8_t spi_r[8], ike_keys_t *out) {
    uint8_t in[IKE_PRF_MAX + KDF_MAX_NINR + 16 + 1];
    uint8_t t[IKE_PRF_MAX];          /* T(n) */
    int rc = -1;
    size_t seed_len = ni_len + nr_len + 16;
    uint8_t *seed = in + prf_len;
    memcpy(seed, ni, ni_len);
    memcpy(seed + ni_len, nr, nr_len);
    memcpy(seed + ni_len + nr_len, spi_i, 8);
    memcpy(seed + ni_len + nr_len + 8, spi_r, 8);
    {
        struct { uint8_t *dst; size_t len; } part[7];
        part[0].dst = out->sk_d;  part[0].len = prf_len;
        part[1].dst = out->sk_ai; part[1].len = integ_key_len;
        part[2].dst = out->sk_ar; part[2].len = integ_key_len;
        part[3].dst = out->sk_ei; part[3].len = encr_key_len;
        part[4].dst = out->sk_er; part[4].len = encr_key_len;
        part[5].dst = out->sk_pi; part[5].len = prf_len;
        part[6].dst = out->sk_pr; part[6].len = prf_len;
        size_t pi = 0, po = 0, t_len = 0;
        unsigned counter = 1;
        while (pi < 7) {
            /* the prf+ input starts with T(n-1) (absent for n == 1): shift the seed accordingly */
            const uint8_t *msg = in + prf_len - t_len;
            if (t_len) memcpy(in + prf_len - t_len, t, t_len);
            in[prf_len + seed_len] = (uint8_t)counter;
            if (counter > 255 || prf(ctx, skeyseed, skeyseed_len, msg, t_len + seed_len + 1, t) != 0) goto done;
            t_len = prf_len;
            for (size_t i = 0; i < prf_len && pi < 7; i++) {
                part[pi].dst[po++] = t[i];
                if (po == part[pi].len) { pi++; po = 0; }
            }
            counter++;
        }
    }
    out->sk_d_len = prf_len; out->sk_a_len = integ_key_len; out->sk_e_len = encr_key_len; out->sk_p_len = prf_len;
    rc = 0;
done:
    wipe(in, sizeof(in));
    wipe(t, sizeof(t));
    return rc;
}

int ike_derive_keys(ike_prf_fn prf, void *ctx, size_t prf_len,
                    size_t integ_key_len, size_t encr_key_len,
                    const uint8_t *ni, size_t ni_len,
                    const uint8_t *nr, size_t nr_len,
                    const uint8_t *gir, size_t gir_len,
                    const uint8_t spi_i[8], const uint8_t spi_r[8],
                    ike_keys_t *out) {
    if (!prf || !ni || !nr || !gir || !spi_i || !spi_r || !out) return -1;
    if (gir_len == 0 || gir_len > GIR_MAX_LEN) return -1;
    if (prf_len == 0 || prf_len > IKE_PRF_MAX) return -1;
    if (integ_key_len == 0 || integ_key_len > IKE_PRF_MAX) return -1;
    if (encr_key_len == 0 || encr_key_len > IKE_ENCR_MAX) return -1;
    if (ni_len + nr_len > KDF_MAX_NINR) return -1;
    if (ni_len + nr_len + 16 > KDF_MAX_SEED) return -1;

    /* SK_d(prf) | SK_ai(integ) | SK_ar(integ) | SK_ei(encr) | SK_er(encr) | SK_pi(prf) | SK_pr(prf) */
    size_t total = 3 * prf_len + 2 * integ_key_len + 2 * encr_key_len;
    if (total > KDF_KEYMAT) return -1;

    /* ONE working buffer, laid out as the prf+ input  T(n-1) | Ni | Nr | SPIi | SPIr | n :
     *   - Ni|Nr at offset prf_len doubles as the SKEYSEED key (contiguous, no separate copy),
     *   - the seed never needs its own array,
     *   - prf+ output is streamed block by block straight into the seven SK_* slots, so no
     *     contiguous KEYMAT buffer exists either.  ~0.7 KB of stack instead of ~2.3 KB. */
    uint8_t in[IKE_PRF_MAX + KDF_MAX_NINR + 16 + 1];
    uint8_t skeyseed[IKE_PRF_MAX];
    int rc = -1;

    size_t ninr_len = ni_len + nr_len;
    uint8_t *ninr = in + prf_len;
    memcpy(ninr, ni, ni_len);
    memcpy(ninr + ni_len, nr, nr_len);

    /* SKEYSEED = prf(Ni | Nr, g^ir) -> prf_len bytes */
    if (prf(ctx, ninr, ninr_len, gir, gir_len, skeyseed) != 0) goto done;
    rc = sk_from_skeyseed(prf, ctx, prf_len, skeyseed, prf_len, integ_key_len, encr_key_len,
                          ni, ni_len, nr, nr_len, spi_i, spi_r, out);
done:
    wipe(in, sizeof(in));
    wipe(skeyseed, sizeof(skeyseed));
    if (rc != 0) wipe(out, sizeof(*out));
    return rc;
}

int ike_derive_keys_rekey(ike_prf_fn prf_old, size_t prf_old_len,
                          const uint8_t *sk_d_old, size_t sk_d_old_len,
                          ike_prf_fn prf_new, void *ctx, size_t prf_new_len,
                          size_t integ_key_len, size_t encr_key_len,
                          const uint8_t *ni, size_t ni_len,
                          const uint8_t *nr, size_t nr_len,
                          const uint8_t *gir, size_t gir_len,
                          const uint8_t spi_i[8], const uint8_t spi_r[8],
                          ike_keys_t *out) {
    if (!prf_old || !prf_new || !sk_d_old || !ni || !nr || !gir || !spi_i || !spi_r || !out) return -1;
    if (gir_len == 0 || gir_len > GIR_MAX_LEN) return -1;
    if (prf_old_len == 0 || prf_old_len > IKE_PRF_MAX || sk_d_old_len == 0 || sk_d_old_len > IKE_PRF_MAX) return -1;
    if (prf_new_len == 0 || prf_new_len > IKE_PRF_MAX) return -1;
    if (integ_key_len == 0 || integ_key_len > IKE_PRF_MAX) return -1;
    if (encr_key_len == 0 || encr_key_len > IKE_ENCR_MAX) return -1;
    if (ni_len + nr_len > KDF_MAX_NINR) return -1;
    if (3 * prf_new_len + 2 * integ_key_len + 2 * encr_key_len > KDF_KEYMAT) return -1;

    /* SKEYSEED = prf_old(SK_d(old), g^ir | Ni | Nr) -- the OLD SA's PRF, keyed with its SK_d. */
    uint8_t gnn[GIR_MAX_LEN + KDF_MAX_NINR];
    uint8_t skeyseed[IKE_PRF_MAX];
    int rc = -1;
    memcpy(gnn, gir, gir_len);
    memcpy(gnn + gir_len, ni, ni_len);
    memcpy(gnn + gir_len + ni_len, nr, nr_len);
    if (prf_old(ctx, sk_d_old, sk_d_old_len, gnn, gir_len + ni_len + nr_len, skeyseed) != 0) goto done;
    /* keys = prf+_new(SKEYSEED, Ni | Nr | SPIi | SPIr) -- the NEW SA's PRF and key lengths. */
    rc = sk_from_skeyseed(prf_new, ctx, prf_new_len, skeyseed, prf_old_len, integ_key_len, encr_key_len,
                          ni, ni_len, nr, nr_len, spi_i, spi_r, out);
done:
    wipe(gnn, sizeof(gnn));
    wipe(skeyseed, sizeof(skeyseed));
    if (rc != 0) wipe(out, sizeof(*out));
    return rc;
}
