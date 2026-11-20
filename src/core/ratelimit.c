/* SPDX-License-Identifier: Apache-2.0 */
/*
 * QSplintNX - bounded token-bucket table for profile rate lines.
 *
 * Tokens are kept in fixed point, one token = SPLINT_RL_SCALE units, so a
 * refill of per_sec tokens per second is elapsed_ns * per_sec units. The
 * elapsed time is clamped to one second before multiplying: a full second
 * already refills the whole burst (burst == per_sec), and the clamp keeps
 * the product below 1e9 * 2^32 < 2^63.
 *
 * Concurrency: one test-and-set spinlock around a lookup of at most
 * SPLINT_RL_PROBE slots plus a few integer operations. The critical
 * section has no calls, no allocation and no loops beyond the probe
 * window, so the hold time is a few tens of nanoseconds. Lookup scans
 * the whole probe window for the key, remembers the first stale or
 * unused slot and the slot with the oldest last_ns; a miss takes the
 * free slot if there is one, otherwise evicts the oldest (LRU-ish).
 */
#include "ratelimit.h"

#include <string.h>

#define SPLINT_RL_SCALE 1000000000ull
#define SPLINT_RL_SEC   1000000000ull

void splint_rl_init(splint_rl_t *rl)
{
    memset(rl->b, 0, sizeof(rl->b));
    atomic_flag_clear_explicit(&rl->lock, memory_order_release);
}

static uint32_t rl_hash(uint32_t profile, int32_t pid)
{
    uint32_t h = (uint32_t)pid * 0x9E3779B1u;
    h ^= profile * 0x85EBCA77u;
    h ^= h >> 15;
    return h & (SPLINT_RL_SLOTS - 1u);
}

static void rl_lock(splint_rl_t *rl)
{
    while (atomic_flag_test_and_set_explicit(&rl->lock, memory_order_acquire))
        ; /* critical section is a handful of instructions */
}

static void rl_unlock(splint_rl_t *rl)
{
    atomic_flag_clear_explicit(&rl->lock, memory_order_release);
}

bool splint_rl_take(splint_rl_t *rl, uint64_t gen, uint32_t profile,
                    int32_t pid, uint32_t per_sec, uint64_t now_ns)
{
    const uint64_t cap = (uint64_t)per_sec * SPLINT_RL_SCALE;
    uint32_t start = rl_hash(profile, pid);
    splint_rl_bucket_t *hit = NULL, *freeb = NULL, *oldest = NULL;
    bool ok;

    if (per_sec == 0)
        return false;

    rl_lock(rl);
    for (uint32_t i = 0; i < SPLINT_RL_PROBE; i++) {
        splint_rl_bucket_t *b = &rl->b[(start + i) & (SPLINT_RL_SLOTS - 1u)];
        if (b->gen != gen) {
            if (!freeb)
                freeb = b;
            continue;
        }
        if (b->profile == profile && b->pid == pid) {
            hit = b;
            break;
        }
        if (!oldest || b->last_ns < oldest->last_ns)
            oldest = b;
    }

    if (!hit) {
        hit = freeb ? freeb : oldest;
        hit->gen = gen;
        hit->profile = profile;
        hit->pid = pid;
        hit->tokens = cap;
        hit->last_ns = now_ns;
    } else if (now_ns > hit->last_ns) {
        uint64_t el = now_ns - hit->last_ns;
        if (el > SPLINT_RL_SEC)
            el = SPLINT_RL_SEC;
        uint64_t add = el * (uint64_t)per_sec;
        hit->tokens = (cap - hit->tokens < add) ? cap : hit->tokens + add;
        hit->last_ns = now_ns;
    }
    if (hit->tokens > cap)        /* rate line changed under same key */
        hit->tokens = cap;

    ok = hit->tokens >= SPLINT_RL_SCALE;
    if (ok)
        hit->tokens -= SPLINT_RL_SCALE;
    rl_unlock(rl);
    return ok;
}
