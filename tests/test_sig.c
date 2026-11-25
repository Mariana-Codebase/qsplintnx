/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Tests for Ed25519 ruleset-signature verification.
 *
 * The interop vector below was produced independently by Python's
 * `cryptography` library (RFC 8032 Ed25519) from the deterministic seed
 * 00,01,...,1f, so a passing KAT proves the vendored reference verifies real
 * RFC 8032 signatures, not merely its own output.
 */
#include "splint/splint_sig.h"
#include "test_util.h"

/* seed = 00..1f ; pk / msg / sig from python-cryptography */
static const unsigned char IV_PUB[32] = {
    0x03,0xa1,0x07,0xbf,0xf3,0xce,0x10,0xbe,0x1d,0x70,0xdd,0x18,0xe7,0x4b,0xc0,0x99,
    0x67,0xe4,0xd6,0x30,0x9b,0xa5,0x0d,0x5f,0x1d,0xdc,0x86,0x64,0x12,0x55,0x31,0xb8
};
static const unsigned char IV_MSG[] = "QSplintNX ruleset provenance test vector";
static const unsigned char IV_SIG[64] = {
    0xf6,0xac,0xf7,0xde,0x9d,0x06,0x0d,0xd5,0x02,0x10,0xda,0xd6,0x13,0x02,0xf2,0x10,
    0x3a,0x53,0xd5,0x40,0xac,0xe5,0x82,0xbf,0xfe,0x04,0xb2,0x54,0xab,0x86,0xe3,0x27,
    0xe1,0xd1,0xa3,0x25,0xdf,0x6c,0xaa,0xea,0xe3,0x30,0xb7,0xbf,0x9e,0xe7,0x13,0x85,
    0xe7,0xe7,0xdb,0x30,0xd4,0x9d,0x79,0x2f,0x26,0xbd,0x4b,0x04,0x2d,0xf6,0x62,0x01
};

static void test_known_answer(void)
{
    size_t mlen = sizeof IV_MSG - 1;   /* drop the NUL */
    CHECK(splint_sig_verify(IV_MSG, mlen, IV_SIG, IV_PUB) == 0);

    /* flip one bit of the signature -> reject */
    unsigned char bad_sig[64];
    memcpy(bad_sig, IV_SIG, 64);
    bad_sig[10] ^= 0x01;
    CHECK(splint_sig_verify(IV_MSG, mlen, bad_sig, IV_PUB) != 0);

    /* flip one bit of the message -> reject */
    unsigned char bad_msg[sizeof IV_MSG];
    memcpy(bad_msg, IV_MSG, sizeof IV_MSG);
    bad_msg[0] ^= 0x01;
    CHECK(splint_sig_verify(bad_msg, mlen, IV_SIG, IV_PUB) != 0);

    /* wrong public key -> reject */
    unsigned char bad_pub[32];
    memcpy(bad_pub, IV_PUB, 32);
    bad_pub[0] ^= 0x01;
    CHECK(splint_sig_verify(IV_MSG, mlen, IV_SIG, bad_pub) != 0);
}

static void test_roundtrip(void)
{
    unsigned char seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (unsigned char)(0x40 + i);
    unsigned char pub[32], sk[64];
    CHECK(splint_sig_keypair_from_seed(pub, sk, seed) == 0);

    const unsigned char msg[] = "match devctl 0x0505 when len > 64 action block";
    size_t mlen = sizeof msg - 1;
    unsigned char sig[64];
    CHECK(splint_sig_sign(sig, msg, mlen, sk) == 0);
    CHECK(splint_sig_verify(msg, mlen, sig, pub) == 0);

    /* a signature from this key must not verify under a different key */
    unsigned char seed2[32], pub2[32], sk2[64];
    memcpy(seed2, seed, 32); seed2[0] ^= 0xFF;
    CHECK(splint_sig_keypair_from_seed(pub2, sk2, seed2) == 0);
    CHECK(splint_sig_verify(msg, mlen, sig, pub2) != 0);

    /* tamper the signed bytes -> reject */
    unsigned char tampered[sizeof msg];
    memcpy(tampered, msg, sizeof msg);
    tampered[5] ^= 0x20;
    CHECK(splint_sig_verify(tampered, mlen, sig, pub) != 0);
}

static void test_empty(void)
{
    unsigned char seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (unsigned char)i;
    unsigned char pub[32], sk[64], sig[64];
    CHECK(splint_sig_keypair_from_seed(pub, sk, seed) == 0);
    CHECK(splint_sig_sign(sig, NULL, 0, sk) == 0);
    CHECK(splint_sig_verify(NULL, 0, sig, pub) == 0);
}

int main(void)
{
    test_known_answer();
    test_roundtrip();
    test_empty();
    TEST_MAIN_END();
}
