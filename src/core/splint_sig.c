/* SPDX-License-Identifier: Apache-2.0 */
#include "splint/splint_sig.h"

#include <stdlib.h>
#include <string.h>

/* SUPERCOP ed25519 reference API (third_party/ed25519-ref). */
#include "crypto_sign.h"

int splint_sig_verify(const unsigned char *msg, size_t len,
                      const unsigned char sig[SPLINT_SIG_BYTES],
                      const unsigned char pubkey[SPLINT_PUBKEY_BYTES])
{
    /*
     * The reference verifies an *attached* signed message sm = sig || msg and
     * writes the recovered message out. Rebuild that layout, verify, and check
     * the recovered length matches. crypto_sign_open returns 0 only when the
     * signature checks out.
     */
    if (sig == NULL || pubkey == NULL || (msg == NULL && len != 0))
        return -1;

    unsigned long long smlen = (unsigned long long)len + SPLINT_SIG_BYTES;
    unsigned char *sm  = malloc((size_t)smlen);
    unsigned char *out = malloc((size_t)smlen);  /* ref may write up to smlen */
    if (sm == NULL || out == NULL) {
        free(sm);
        free(out);
        return -1;
    }

    memcpy(sm, sig, SPLINT_SIG_BYTES);
    if (len != 0)
        memcpy(sm + SPLINT_SIG_BYTES, msg, len);

    unsigned long long olen = 0;
    int r = crypto_sign_open(out, &olen, sm, smlen, pubkey);
    int ok = (r == 0 && olen == (unsigned long long)len);

    free(sm);
    free(out);
    return ok ? 0 : -1;
}

int splint_sig_keypair_from_seed(unsigned char pubkey[SPLINT_PUBKEY_BYTES],
                                 unsigned char seckey[SPLINT_SECKEY_BYTES],
                                 const unsigned char seed[SPLINT_SEED_BYTES])
{
    unsigned char seedcopy[SPLINT_SEED_BYTES];
    memcpy(seedcopy, seed, SPLINT_SEED_BYTES);  /* ref writes sk from seed */
    return crypto_sign_publickey(pubkey, seckey, seedcopy);
}

int splint_sig_sign(unsigned char sig[SPLINT_SIG_BYTES],
                    const unsigned char *msg, size_t len,
                    const unsigned char seckey[SPLINT_SECKEY_BYTES])
{
    unsigned long long smlen = (unsigned long long)len + SPLINT_SIG_BYTES;
    unsigned char *sm = malloc((size_t)smlen);
    if (sm == NULL)
        return -1;

    unsigned long long out_smlen = 0;
    int r = crypto_sign(sm, &out_smlen, msg, (unsigned long long)len, seckey);
    if (r == 0)
        memcpy(sig, sm, SPLINT_SIG_BYTES);  /* sm = sig || msg */

    free(sm);
    return r == 0 ? 0 : -1;
}
