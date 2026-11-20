/* SPDX-License-Identifier: Apache-2.0 */
/*
 * QSplintNX - internal token-bucket table used by the engine for
 * `rate <n> per s` lines (docs/RULES.md, profile blocks).
 *
 * One bucket per (ruleset generation, profile index, client pid). The
 * table has a fixed number of slots, no allocation after init, and every
 * operation touches at most SPLINT_RL_PROBE slots, so its cost is bounded.
 * Buckets whose generation differs from the caller's are treated as free,
 * which is how a ruleset swap resets the table without walking it.
 */
#ifndef SPLINT_RATELIMIT_H
#define SPLINT_RATELIMIT_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#define SPLINT_RL_SLOTS 256u   /* power of two */
#define SPLINT_RL_PROBE 16u    /* slots examined per lookup */

typedef struct splint_rl_bucket {
    uint64_t gen;        /* 0 = never used */
    uint32_t profile;
    int32_t  pid;
    uint64_t tokens;     /* scaled by SPLINT_RL_SCALE */
    uint64_t last_ns;
} splint_rl_bucket_t;

typedef struct splint_rl {
    atomic_flag        lock;
    splint_rl_bucket_t b[SPLINT_RL_SLOTS];
} splint_rl_t;

void splint_rl_init(splint_rl_t *rl);

/*
 * Consume one token from the bucket of (gen, profile, pid), creating it
 * full (burst = per_sec) if absent. Returns true if the message is within
 * the rate, false if it must be rate limited. now_ns comes from the
 * message; a clock that goes backwards simply refills nothing.
 * gen must be non-zero.
 */
bool splint_rl_take(splint_rl_t *rl, uint64_t gen, uint32_t profile,
                    int32_t pid, uint32_t per_sec, uint64_t now_ns);

#endif /* SPLINT_RATELIMIT_H */
