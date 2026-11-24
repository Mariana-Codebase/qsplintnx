/* SPDX-License-Identifier: Apache-2.0 */
/*
 * QSplintNX - decision engine: patches, profiles, rate limits, learn-mode
 * downgrade, and ruleset hot swap. Semantics follow docs/RULES.md,
 * section "Evaluation order", which is normative.
 *
 * ------------------------------------------------------------------------
 * Hot swap scheme (two-parity epoch counters)
 * ------------------------------------------------------------------------
 *
 * State, all seq_cst atomics:
 *   cur        pointer to the active slot {ruleset, generation}, may be NULL
 *   epoch      32-bit counter, bumped once per set_rules
 *   active[2]  number of decisions in flight that entered under an epoch
 *              of parity 0 or 1
 *   wlock      mutex serialising writers (set_rules); readers never take it
 *
 * Reader (decide):
 *   R1 ep = load(epoch)
 *   R2 fetch_add(active[ep & 1], 1)
 *   R3 if load(epoch) != ep: fetch_sub(active[ep & 1], 1), goto R1
 *   R4 s = load(cur); decide using s
 *   R5 fetch_sub(active[ep & 1], 1)
 *
 * Writer (set_rules), under wlock:
 *   W1 old = exchange(cur, new)
 *   W2 ep = load(epoch); store(epoch, ep + 1)
 *   W3 spin (sched_yield) until load(active[ep & 1]) == 0
 *   W4 free(old)
 *
 * Safety argument (no reader dereferences old after W4). All operations
 * are seq_cst, so they sit in one total order S. Take a reader that loads
 * old at R4 and passed R3 with epoch value e, and the writer W that
 * replaced old, which flipped epoch from ep to ep+1.
 *  (a) e == ep. The R3 load returned ep, so it precedes W2's store in S,
 *      so R2 (before R3) precedes W2, so the increment of active[ep & 1]
 *      is visible to W3. W3 cannot observe zero until R5 runs. Safe.
 *  (b) e == ep + 1 or later. Then R3 follows W2 in S, so R4 follows W1,
 *      and R4 cannot return old (it returns new or something newer).
 *      Contradiction with the assumption: this case never loads old.
 *  (c) e < ep. Then R3 precedes the store that moved epoch from e to
 *      e+1, made by an earlier writer W' (writers are serialised by
 *      wlock, so W' finished W3 before W started W1). W' waited for
 *      active[e & 1] to drain after its flip, and R2 precedes that flip,
 *      so this reader finished R5 before W' returned, hence before W1.
 *      It therefore cannot have loaded old, which W1 is the one to
 *      retire; and any pointer it did load was retired by a writer that
 *      waited for it. Safe.
 * A reader that loaded a stale epoch and incremented the wrong parity
 * fails R3 and decrements before it touches cur; it can delay W3 by a
 * few instructions but never holds a pointer. Epoch values are full
 * 32-bit, so an ABA on R3 would need 2^32 swaps inside one R1..R3 window.
 *
 * Progress: readers never wait. R1..R3 retries only when a set_rules
 * flipped the epoch inside that three-instruction window, so retries are
 * bounded by the number of concurrent reloads (in practice zero or one).
 * set_rules may wait for in-flight decisions; it is not on the hot path.
 *
 * rule_id lifetime: splint_verdict_t.rule_id is read by callers after
 * decide() returns, i.e. after R5, when the ruleset may already be freed
 * by a concurrent set_rules. So rule_id never points into the ruleset:
 * the patch id is copied (at most SPLINT_ID_MAX bytes, only when a patch
 * matched) into a _Thread_local buffer and rule_id points there. It stays
 * valid until the same thread calls decide() again.
 *
 * The slot carries a generation number so rate-limit buckets created
 * under an older ruleset are ignored by the new one (the table is reset
 * lazily, see ratelimit.c), even while old in-flight decisions still
 * update them.
 *
 * Verdict fields when a log-only patch matched: rule_id names that patch
 * (it is what the log line is about); reason and rule_line come from the
 * deciding profile step if a profile exists, otherwise reason is PATCH
 * and rule_line is the patch line.
 */
#include "splint/engine.h"
#include "ratelimit.h"

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

static _Thread_local char tl_rule_id[SPLINT_ID_MAX];

typedef struct engine_slot {
    splint_ruleset_t *rs;
    uint64_t          gen;
} engine_slot_t;

struct splint_engine {
    _Atomic(engine_slot_t *) cur;
    atomic_uint              epoch;
    atomic_ulong             active[2];
    pthread_mutex_t          wlock;
    uint64_t                 next_gen;   /* under wlock */

    atomic_ullong st_decided, st_allowed, st_blocked, st_logged,
                  st_rate_limited, st_would_block;

    splint_rl_t rl;
};

splint_engine_t *splint_engine_new(void)
{
    splint_engine_t *e = calloc(1, sizeof(*e));
    if (!e)
        return NULL;
    if (pthread_mutex_init(&e->wlock, NULL) != 0) {
        free(e);
        return NULL;
    }
    atomic_init(&e->cur, NULL);
    atomic_init(&e->epoch, 0u);
    atomic_init(&e->active[0], 0ul);
    atomic_init(&e->active[1], 0ul);
    atomic_init(&e->st_decided, 0ull);
    atomic_init(&e->st_allowed, 0ull);
    atomic_init(&e->st_blocked, 0ull);
    atomic_init(&e->st_logged, 0ull);
    atomic_init(&e->st_rate_limited, 0ull);
    atomic_init(&e->st_would_block, 0ull);
    e->next_gen = 1;
    splint_rl_init(&e->rl);
    return e;
}

static void slot_free(engine_slot_t *s)
{
    if (!s)
        return;
    free(s->rs);        /* same allocator as splint_rules_free() */
    free(s);
}

void splint_engine_free(splint_engine_t *e)
{
    if (!e)
        return;
    /* Caller guarantees no decide() is running. */
    slot_free(atomic_load(&e->cur));
    pthread_mutex_destroy(&e->wlock);
    free(e);
}

void splint_engine_set_rules(splint_engine_t *e, splint_ruleset_t *rs)
{
    engine_slot_t *ns = NULL, *old;
    unsigned ep;

    if (!e) {
        free(rs);
        return;
    }
    pthread_mutex_lock(&e->wlock);
    if (rs) {
        ns = malloc(sizeof(*ns));
        if (!ns) {
            /* Cannot install: keep the running ruleset (all-or-nothing). */
            pthread_mutex_unlock(&e->wlock);
            free(rs);
            return;
        }
        ns->rs = rs;
        ns->gen = e->next_gen++;
    }
    old = atomic_exchange(&e->cur, ns);                     /* W1 */
    ep = atomic_load(&e->epoch);                            /* W2 */
    atomic_store(&e->epoch, ep + 1u);
    while (atomic_load(&e->active[ep & 1u]) != 0)           /* W3 */
        sched_yield();
    slot_free(old);                                         /* W4 */
    pthread_mutex_unlock(&e->wlock);
}

/* ---------------------------------------------------------------- eval */

static bool load_le(const splint_msg_t *m, uint64_t off, unsigned width,
                    uint64_t *out)
{
    if (!m->data || off > m->data_len || width > m->data_len - off)
        return false;
    const uint8_t *p = m->data + off;
    uint64_t v = 0;
    for (unsigned i = 0; i < width; i++)
        v |= (uint64_t)p[i] << (8u * i);
    *out = v;
    return true;
}

static bool operand(const splint_msg_t *m, const splint_operand_t *o,
                    uint64_t *out)
{
    switch (o->kind) {
    case SPLINT_OPD_CONST:    *out = o->value;     return true;
    case SPLINT_OPD_LEN:      *out = m->len;       return true;
    case SPLINT_OPD_DECLARED: *out = m->declared;  return true;
    case SPLINT_OPD_BYTE:     return load_le(m, o->value, 1, out);
    case SPLINT_OPD_U16:      return load_le(m, o->value, 2, out);
    case SPLINT_OPD_U32:      return load_le(m, o->value, 4, out);
    }
    return false;
}

static bool cond_true(const splint_msg_t *m, const splint_cond_t *c)
{
    uint64_t a, b;
    if (!operand(m, &c->lhs, &a) || !operand(m, &c->rhs, &b))
        return false;
    switch (c->cmp) {
    case SPLINT_CMP_EQ: return a == b;
    case SPLINT_CMP_NE: return a != b;
    case SPLINT_CMP_LT: return a <  b;
    case SPLINT_CMP_LE: return a <= b;
    case SPLINT_CMP_GT: return a >  b;
    case SPLINT_CMP_GE: return a >= b;
    }
    return false;
}

static bool op_match(splint_op_t rule_op, splint_op_t msg_op)
{
    return rule_op == SPLINT_OP_ANY || rule_op == msg_op;
}

static bool patch_match(const splint_patch_t *p, const splint_msg_t *m)
{
    if (!op_match(p->op, m->op))
        return false;
    if (p->has_code) {
        if (m->op != SPLINT_OP_DEVCTL)
            return false;
        if (p->code != m->dcmd && p->code != (m->dcmd & 0xFFFFu))
            return false;
    }
    uint32_t n = p->ncond < SPLINT_MAX_CONDS ? p->ncond : SPLINT_MAX_CONDS;
    for (uint32_t i = 0; i < n; i++)
        if (!cond_true(m, &p->cond[i]))
            return false;
    return true;
}

/* The length that `maxlen` bounds depends on the operation. A read carries no
 * inbound payload (m->len is 0); the size that matters is how many bytes the
 * client asked to receive, which the QNX handler records in m->declared. A
 * write or devctl is bounded by the inbound payload actually delivered
 * (m->len); a devctl's declared nbytes also sizes the reply buffer, so it is
 * not the inbound length and must not be bounded here. Returning m->len for a
 * read would let `allow read maxlen N` pass any request size, since m->len is
 * always 0 for reads. */
static uint64_t splint_effective_len(const splint_msg_t *m)
{
    return (m->op == SPLINT_OP_READ) ? m->declared : m->len;
}

static bool allow_match(const splint_allow_t *a, const splint_msg_t *m,
                        const char *cname)
{
    if (!op_match(a->op, m->op))
        return false;
    if (a->has_code) {
        uint32_t s = m->dcmd & 0xFFFFu;
        if (m->op != SPLINT_OP_DEVCTL)
            return false;
        if (!((m->dcmd >= a->code_lo && m->dcmd <= a->code_hi) ||
              (s >= a->code_lo && s <= a->code_hi)))
            return false;
    }
    if (a->has_client && (!cname || strcmp(a->client, cname) != 0))
        return false;
    if (a->has_maxlen && splint_effective_len(m) > a->maxlen)
        return false;
    return true;
}

static const splint_rate_t *pick_rate(const splint_profile_t *pf,
                                      const char *cname)
{
    const splint_rate_t *dflt = NULL;
    uint32_t n = pf->nrate < SPLINT_MAX_RATES ? pf->nrate : SPLINT_MAX_RATES;
    for (uint32_t i = 0; i < n; i++) {
        const splint_rate_t *r = &pf->rate[i];
        if (r->has_client) {
            if (cname && strcmp(r->client, cname) == 0)
                return r;
        } else if (!dflt) {
            dflt = r;
        }
    }
    return dflt;
}

static void eval(splint_engine_t *e, const engine_slot_t *s,
                 const splint_msg_t *m, splint_verdict_t *v)
{
    const splint_ruleset_t *rs = s->rs;
    const char *path = m->path ? m->path : "";
    const char *cname = m->client ? m->client->name : NULL;
    int32_t pid = m->client ? m->client->pid : -1;

    /* 1. patches, first match wins */
    uint32_t np = rs->npatch < SPLINT_MAX_RULES ? rs->npatch : SPLINT_MAX_RULES;
    for (uint32_t i = 0; i < np; i++) {
        const splint_patch_t *p = &rs->patch[i];
        if (strcmp(p->path, path) != 0 || !patch_match(p, m))
            continue;
        memcpy(tl_rule_id, p->id, SPLINT_ID_MAX - 1);
        tl_rule_id[SPLINT_ID_MAX - 1] = '\0';
        v->rule_id = tl_rule_id;
        v->rule_line = p->line;
        v->reason = SPLINT_R_PATCH;
        if (p->actions & SPLINT_ACT_LOG)
            v->log = true;
        if (p->actions & SPLINT_ACT_BLOCK) {
            v->action = SPLINT_BLOCK;
            v->err = p->err ? p->err : EPERM;
            return;
        }
        break;
    }

    /* 2. profile */
    uint32_t nf = rs->nprofile < SPLINT_MAX_PROFILES ? rs->nprofile
                                                     : SPLINT_MAX_PROFILES;
    for (uint32_t pi = 0; pi < nf; pi++) {
        const splint_profile_t *pf = &rs->profile[pi];
        if (strcmp(pf->path, path) != 0)
            continue;

        const splint_rate_t *r = pick_rate(pf, cname);
        if (r && !splint_rl_take(&e->rl, s->gen, pi, pid, r->per_sec,
                                 m->now_ns)) {
            v->action = SPLINT_BLOCK;
            v->reason = SPLINT_R_RATE;
            v->err = EPERM;
            v->rule_line = r->line;
            return;
        }
        uint32_t na = pf->nallow < SPLINT_MAX_ALLOW ? pf->nallow
                                                    : SPLINT_MAX_ALLOW;
        for (uint32_t ai = 0; ai < na; ai++) {
            if (allow_match(&pf->allow[ai], m, cname)) {
                v->action = SPLINT_ALLOW;
                v->reason = SPLINT_R_ALLOW;
                v->rule_line = pf->allow[ai].line;
                return;
            }
        }
        v->reason = SPLINT_R_DEFAULT;
        v->rule_line = pf->line;
        if (pf->default_block) {
            v->action = SPLINT_BLOCK;
            v->err = EPERM;
        }
        return;
    }

    /* 3. no profile: allow (reason stays PATCH if a log patch matched) */
}

void splint_engine_decide(splint_engine_t *e, const splint_msg_t *m,
                          splint_verdict_t *v)
{
    unsigned ep;
    engine_slot_t *s;

    v->action = SPLINT_ALLOW;
    v->reason = SPLINT_R_NONE;
    v->log = false;
    v->would_block = false;
    v->err = 0;
    v->rule_id = NULL;
    v->rule_line = 0;
    if (!e || !m)
        return;

    for (;;) {                                              /* R1..R3 */
        ep = atomic_load(&e->epoch);
        atomic_fetch_add(&e->active[ep & 1u], 1ul);
        if (atomic_load(&e->epoch) == ep)
            break;
        atomic_fetch_sub(&e->active[ep & 1u], 1ul);
    }
    s = atomic_load(&e->cur);                               /* R4 */

    if (s && s->rs) {
        eval(e, s, m, v);
        /* 4. learn mode downgrade */
        if (s->rs->mode == SPLINT_MODE_LEARN && v->action == SPLINT_BLOCK &&
            v->reason != SPLINT_R_PATCH) {
            v->action = SPLINT_ALLOW;
            v->would_block = true;
            v->log = true;
            v->err = 0;
        }
    }
    atomic_fetch_sub(&e->active[ep & 1u], 1ul);             /* R5 */

    atomic_fetch_add_explicit(&e->st_decided, 1, memory_order_relaxed);
    if (v->action == SPLINT_BLOCK)
        atomic_fetch_add_explicit(&e->st_blocked, 1, memory_order_relaxed);
    else
        atomic_fetch_add_explicit(&e->st_allowed, 1, memory_order_relaxed);
    if (v->log)
        atomic_fetch_add_explicit(&e->st_logged, 1, memory_order_relaxed);
    if (v->reason == SPLINT_R_RATE)
        atomic_fetch_add_explicit(&e->st_rate_limited, 1, memory_order_relaxed);
    if (v->would_block)
        atomic_fetch_add_explicit(&e->st_would_block, 1, memory_order_relaxed);
}

void splint_engine_stats(const splint_engine_t *e, splint_engine_stats_t *out)
{
    splint_engine_t *me = (splint_engine_t *)(uintptr_t)e; /* atomics loads only */
    memset(out, 0, sizeof(*out));
    if (!e)
        return;
    out->decided      = atomic_load_explicit(&me->st_decided, memory_order_relaxed);
    out->allowed      = atomic_load_explicit(&me->st_allowed, memory_order_relaxed);
    out->blocked      = atomic_load_explicit(&me->st_blocked, memory_order_relaxed);
    out->logged       = atomic_load_explicit(&me->st_logged, memory_order_relaxed);
    out->rate_limited = atomic_load_explicit(&me->st_rate_limited, memory_order_relaxed);
    out->would_block  = atomic_load_explicit(&me->st_would_block, memory_order_relaxed);
}

const char *splint_reason_name(splint_reason_t r)
{
    switch (r) {
    case SPLINT_R_NONE:    return "none";
    case SPLINT_R_PATCH:   return "patch";
    case SPLINT_R_ALLOW:   return "allow";
    case SPLINT_R_DEFAULT: return "default";
    case SPLINT_R_RATE:    return "rate";
    }
    return "?";
}
