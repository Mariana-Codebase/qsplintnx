/* SPDX-License-Identifier: Apache-2.0 */
/*
 * QSplintNX - event ring written by decision threads and drained by
 * splintctl. No allocation after splint_log_new(), no locks, no syscalls
 * on the push path.
 *
 * Scheme. A global counter `head` hands out sequence numbers (fetch_add,
 * first event gets 1). Event s lives in slot (s - 1) & mask. Each slot
 * has a stamp: 2*s means "holds event s, complete", 2*s + 1 means "event
 * s being written", 0 means never written. Event bytes are stored as
 * relaxed atomic 64-bit words so concurrent copies are not data races in
 * the C11 model (and TSan agrees); consistency comes from the stamp.
 *
 * Writer for seq s:
 *   claim:   CAS stamp from an even value v < 2s to 2s+1. If the stamp is
 *            odd (another writer, necessarily for an older or newer lap,
 *            is mid-copy) or already >= 2s (a newer lap overtook us), drop
 *            this event: overwriting it would interleave two writers'
 *            bytes. Each CAS failure means the stamp grew, so retries are
 *            bounded by the number of concurrent writers. A drop shows up
 *            to readers as a seq gap, which the API already allows.
 *   fence(release); store words (relaxed); store stamp = 2s (release).
 *
 * Reader for seq s (classic seqlock read):
 *   v1 = load stamp (acquire); require v1 == 2s; copy words (relaxed);
 *   fence(acquire); v2 = load stamp (relaxed); require v2 == v1.
 * A slot being written or rewritten fails one of the checks and is
 * skipped, so read() never returns a torn event.
 *
 * splintctl links log.c with msg.c only (see Makefile `qnx`), so this
 * file must not call into engine.c (hence its own reason-name table).
 */
#include "splint/log.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EV_WORDS ((sizeof(splint_event_t) + 7u) / 8u)

typedef struct slot {
    _Atomic uint64_t stamp;
    _Atomic uint64_t w[EV_WORDS];
} slot_t;

struct splint_log {
    _Atomic uint64_t head;   /* last sequence handed out */
    uint64_t      mask;
    uint32_t      cap;
    slot_t       *slots;
};

splint_log_t *splint_log_new(uint32_t capacity)
{
    uint32_t cap = 64;
    splint_log_t *l;

    if (capacity > (1u << 31))
        return NULL;
    while (cap < capacity)
        cap <<= 1;
    l = calloc(1, sizeof(*l));
    if (!l)
        return NULL;
    l->slots = calloc(cap, sizeof(slot_t));
    if (!l->slots) {
        free(l);
        return NULL;
    }
    for (uint32_t i = 0; i < cap; i++) {
        atomic_init(&l->slots[i].stamp, (uint64_t)0);
        for (size_t j = 0; j < EV_WORDS; j++)
            atomic_init(&l->slots[i].w[j], (uint64_t)0);
    }
    atomic_init(&l->head, (uint64_t)0);
    l->cap = cap;
    l->mask = cap - 1u;
    return l;
}

void splint_log_free(splint_log_t *l)
{
    if (!l)
        return;
    free(l->slots);
    free(l);
}

static void scopy(char *dst, size_t cap, const char *src)
{
    size_t n = 0;
    if (src)
        while (n + 1 < cap && src[n])
            n++;
    if (n)
        memcpy(dst, src, n);
    dst[n] = '\0';
}

void splint_log_push(splint_log_t *l, const splint_msg_t *m,
                     const splint_verdict_t *v, uint32_t latency_ns)
{
    union { splint_event_t ev; uint64_t w[EV_WORDS]; } u;
    uint64_t s, want, cur;
    slot_t *sl;

    if (!l || !m || !v)
        return;

    memset(&u, 0, sizeof(u));
    u.ev.ts_ns = m->now_ns;
    u.ev.pid = m->client ? m->client->pid : -1;
    u.ev.dcmd = m->dcmd;
    u.ev.len = m->len;
    u.ev.declared = m->declared;
    u.ev.op = (uint8_t)m->op;
    u.ev.action = (uint8_t)v->action;
    u.ev.reason = (uint8_t)v->reason;
    u.ev.would_block = v->would_block ? 1u : 0u;
    u.ev.rule_line = v->rule_line;
    u.ev.latency_ns = latency_ns;
    scopy(u.ev.client, sizeof(u.ev.client), m->client ? m->client->name : NULL);
    scopy(u.ev.rule_id, sizeof(u.ev.rule_id), v->rule_id);
    scopy(u.ev.path, sizeof(u.ev.path), m->path);

    s = atomic_fetch_add_explicit(&l->head, (uint64_t)1, memory_order_relaxed) + 1u;
    u.ev.seq = s;
    sl = &l->slots[(s - 1u) & l->mask];
    want = 2u * s + 1u;

    cur = atomic_load_explicit(&sl->stamp, memory_order_relaxed);
    for (;;) {
        if ((cur & 1u) || cur >= 2u * s)
            return;                             /* drop, see header */
        if (atomic_compare_exchange_weak_explicit(&sl->stamp, &cur, want,
                memory_order_acquire, memory_order_relaxed))
            break;
    }
    atomic_thread_fence(memory_order_release);
    for (size_t j = 0; j < EV_WORDS; j++)
        atomic_store_explicit(&sl->w[j], u.w[j], memory_order_relaxed);
    atomic_store_explicit(&sl->stamp, 2u * s, memory_order_release);
}

uint32_t splint_log_read(const splint_log_t *l, uint64_t after_seq,
                         splint_event_t *out, uint32_t max)
{
    union { splint_event_t ev; uint64_t w[EV_WORDS]; } u;
    splint_log_t *ml = (splint_log_t *)(uintptr_t)l;   /* atomic loads only */
    uint64_t head, s;
    uint32_t n = 0;

    if (!l || !out || max == 0)
        return 0;
    head = atomic_load_explicit(&ml->head, memory_order_acquire);
    s = after_seq + 1u;
    if (head >= l->cap && s < head - l->cap + 1u)
        s = head - l->cap + 1u;
    for (; s <= head && n < max; s++) {
        slot_t *sl = &ml->slots[(s - 1u) & l->mask];
        uint64_t v1 = atomic_load_explicit(&sl->stamp, memory_order_acquire);
        if (v1 != 2u * s)
            continue;           /* not yet written, being written, or lost */
        for (size_t j = 0; j < EV_WORDS; j++)
            u.w[j] = atomic_load_explicit(&sl->w[j], memory_order_relaxed);
        atomic_thread_fence(memory_order_acquire);
        if (atomic_load_explicit(&sl->stamp, memory_order_relaxed) != v1)
            continue;           /* overwritten while copying */
        out[n++] = u.ev;
    }
    return n;
}

static const char *reason_str(uint8_t r)
{
    static const char *const names[] = { "none", "patch", "allow", "default", "rate" };
    return r < sizeof(names) / sizeof(names[0]) ? names[r] : "?";
}

/* Length of a fixed char field that may lack a NUL. */
static int flen(const char *s, size_t cap)
{
    const char *z = memchr(s, '\0', cap);
    return (int)(z ? (size_t)(z - s) : cap);
}

size_t splint_event_format(const splint_event_t *ev, char *buf, size_t cap)
{
    int n;
    if (!ev) {
        if (buf && cap)
            buf[0] = '\0';
        return 0;
    }
    int rl = flen(ev->rule_id, sizeof(ev->rule_id));
    n = snprintf(buf, buf ? cap : 0,
        "#%llu %llu pid=%ld client=%.*s op=%s dcmd=0x%08x len=%llu declared=%llu "
        "%s%s reason=%s rule=%.*s line=%u lat=%uns path=%.*s",
        (unsigned long long)ev->seq, (unsigned long long)ev->ts_ns,
        (long)ev->pid,
        flen(ev->client, sizeof(ev->client)), ev->client,
        splint_op_name((splint_op_t)ev->op), (unsigned)ev->dcmd,
        (unsigned long long)ev->len, (unsigned long long)ev->declared,
        ev->action == 1 ? "BLOCK" : "ALLOW",
        ev->would_block ? " would_block" : "",
        reason_str(ev->reason),
        rl ? rl : 1, rl ? ev->rule_id : "-",
        (unsigned)ev->rule_line, (unsigned)ev->latency_ns,
        flen(ev->path, sizeof(ev->path)), ev->path);
    return n < 0 ? 0 : (size_t)n;
}
