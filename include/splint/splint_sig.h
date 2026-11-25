/*
 * QSplintNX - Ed25519 detached-signature verification for rulesets.
 *
 * splintd will not activate a ruleset whose detached signature does not verify
 * against a trusted public key. The signed artifact is the exact bytes of the
 * rules file; the signature travels beside it as <rulesfile>.sig (64 raw
 * bytes). The trusted public key is compiled into splintd (splint_pubkey.h),
 * so a reload cannot swap it. Signing is an offline step (tools/splint-sign);
 * splintd only ever verifies.
 *
 * The implementation is the SUPERCOP ed25519 reference (third_party/ed25519-ref,
 * public domain); this wrapper adapts its attached-signature API to detached
 * verification.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPLINT_SIG_H
#define SPLINT_SIG_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SPLINT_SIG_BYTES    64u   /* Ed25519 signature length */
#define SPLINT_PUBKEY_BYTES 32u   /* Ed25519 public key length */
#define SPLINT_SEED_BYTES   32u   /* private seed length */
#define SPLINT_SECKEY_BYTES 64u   /* reference secret key (seed + pubkey) */

/*
 * Verify a detached signature over msg[0..len) with pubkey. Returns 0 when the
 * signature is valid, -1 otherwise (bad signature, wrong key, allocation
 * failure). Safe to call with len == 0. Does not modify msg.
 */
int splint_sig_verify(const unsigned char *msg, size_t len,
                      const unsigned char sig[SPLINT_SIG_BYTES],
                      const unsigned char pubkey[SPLINT_PUBKEY_BYTES]);

/*
 * Derive a public key and 64-byte secret key from a 32-byte seed. Offline use
 * by the signing tool; splintd does not call this.
 */
int splint_sig_keypair_from_seed(unsigned char pubkey[SPLINT_PUBKEY_BYTES],
                                 unsigned char seckey[SPLINT_SECKEY_BYTES],
                                 const unsigned char seed[SPLINT_SEED_BYTES]);

/*
 * Produce a detached signature of msg[0..len) with a 64-byte secret key.
 * Offline use by the signing tool. Returns 0 on success.
 */
int splint_sig_sign(unsigned char sig[SPLINT_SIG_BYTES],
                    const unsigned char *msg, size_t len,
                    const unsigned char seckey[SPLINT_SECKEY_BYTES]);

#ifdef __cplusplus
}
#endif
#endif /* SPLINT_SIG_H */
