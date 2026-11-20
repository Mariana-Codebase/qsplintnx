/* SPDX-License-Identifier: Apache-2.0 */
/*
 * QSplintNX - learn mode: aggregate observed traffic and propose
 * profiles in docs/RULES.md syntax.
 *
 * Two fixed tables, no allocation after splint_learn_new():
 *   keys   (path, client, op, short code) -> count, max len
 *   pcs    (path, client) -> messages in current aligned 1 s window, peak
 * Both are open-addressed hash tables of 2 * SPLINT_LEARN_MAX_KEYS slots
 * holding indices into dense arrays of SPLINT_LEARN_MAX_KEYS entries.
 * Every (path, client) pair has at least one key, so the pc array can
 * never fill before the key array does.
 *
 * Learn is not on the latency-critical path; one mutex protects all of it.
 */
#include "splint/learn.h"
#include "splint/rules.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HSLOTS (2u * SPLINT_LEARN_MAX_KEYS)   /* power of two */
#define NONE   0xFFFFu
#define SEC_NS 1000000000ull

typedef struct lkey {
    char        path[SPLINT_PATH_MAX];
    char        client[SPLINT_NAME_MAX];
    splint_op_t op;
    uint32_t    code;
    uint64_t    count;
    uint64_t    max_len;
} lkey_t;

typedef struct lpc {
    char     path[SPLINT_PATH_MAX];
    char     client[SPLINT_NAME_MAX];
    uint64_t window;      /* now_ns / 1e9 of current window */
    uint64_t in_window;
    uint64_t peak;
} lpc_t;

struct splint_learn {
    pthread_mutex_t     mu;
    splint_learn_opts_t opts;
    uint32_t            nkeys, npcs;
    uint64_t            dropped;
    uint16_t            khash[HSLOTS];
    uint16_t            phash[HSLOTS];
    lkey_t              keys[SPLINT_LEARN_MAX_KEYS];
    lpc_t               pcs[SPLINT_LEARN_MAX_KEYS];
};

static void lock(const splint_learn_t *l)
{
    pthread_mutex_lock((pthread_mutex_t *)(uintptr_t)&l->mu);
}

static void unlock(const splint_learn_t *l)
{
    pthread_mutex_unlock((pthread_mutex_t *)(uintptr_t)&l->mu);
}

static void clear(splint_learn_t *l)
{
    l->nkeys = l->npcs = 0;
    l->dropped = 0;
    memset(l->khash, 0xFF, sizeof(l->khash));
    memset(l->phash, 0xFF, sizeof(l->phash));
}

splint_learn_t *splint_learn_new(const splint_learn_opts_t *opts)
{
    splint_learn_t *l = calloc(1, sizeof(*l));
    if (!l)
        return NULL;
    if (pthread_mutex_init(&l->mu, NULL) != 0) {
        free(l);
        return NULL;
    }
    if (opts) {
        l->opts = *opts;
    } else {
        l->opts.len_headroom_pct = 25;
        l->opts.rate_headroom_pct = 100;
        l->opts.default_block = 1;
    }
    clear(l);
    return l;
}

void splint_learn_free(splint_learn_t *l)
{
    if (!l)
        return;
    pthread_mutex_destroy(&l->mu);
    free(l);
}

void splint_learn_reset(splint_learn_t *l)
{
    if (!l)
        return;
    lock(l);
    clear(l);
    unlock(l);
}

uint64_t splint_learn_dropped(const splint_learn_t *l)
{
    uint64_t d;
    if (!l)
        return 0;
    lock(l);
    d = l->dropped;
    unlock(l);
    return d;
}

static uint32_t fnv(uint32_t h, const char *s)
{
    for (; *s; s++) {
        h ^= (uint8_t)*s;
        h *= 16777619u;
    }
    return h;
}

static uint32_t fnv_u32(uint32_t h, uint32_t v)
{
    for (int i = 0; i < 4; i++) {
        h ^= (v >> (8 * i)) & 0xFFu;
        h *= 16777619u;
    }
    return h;
}

/* Copy with truncation to a fixed field, always NUL-terminated. */
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

int splint_learn_observe(splint_learn_t *l, const splint_msg_t *m)
{
    char path[SPLINT_PATH_MAX], client[SPLINT_NAME_MAX];
    uint32_t code, hk, hp, i;
    lkey_t *k = NULL;
    lpc_t *pc = NULL;

    if (!l || !m)
        return -1;
    scopy(path, sizeof(path), m->path);
    scopy(client, sizeof(client), m->client ? m->client->name : NULL);
    code = m->op == SPLINT_OP_DEVCTL ? (m->dcmd & 0xFFFFu) : 0u;

    hp = fnv(fnv(2166136261u, path), "\x01");
    hp = fnv(hp, client);
    hk = fnv_u32(fnv_u32(hp, (uint32_t)m->op), code);

    lock(l);
    for (i = hk & (HSLOTS - 1u);; i = (i + 1u) & (HSLOTS - 1u)) {
        uint16_t ix = l->khash[i];
        if (ix == NONE)
            break;
        lkey_t *c = &l->keys[ix];
        if (c->op == m->op && c->code == code && strcmp(c->path, path) == 0 &&
            strcmp(c->client, client) == 0) {
            k = c;
            break;
        }
    }
    if (!k) {
        if (l->nkeys >= SPLINT_LEARN_MAX_KEYS) {
            l->dropped++;
            unlock(l);
            return -1;
        }
        l->khash[i] = (uint16_t)l->nkeys;    /* i is the empty slot */
        k = &l->keys[l->nkeys++];
        memcpy(k->path, path, sizeof(path));
        memcpy(k->client, client, sizeof(client));
        k->op = m->op;
        k->code = code;
        k->count = 0;
        k->max_len = 0;
    }
    k->count++;
    if (m->len > k->max_len)
        k->max_len = m->len;

    for (i = hp & (HSLOTS - 1u);; i = (i + 1u) & (HSLOTS - 1u)) {
        uint16_t ix = l->phash[i];
        if (ix == NONE)
            break;
        lpc_t *c = &l->pcs[ix];
        if (strcmp(c->path, path) == 0 && strcmp(c->client, client) == 0) {
            pc = c;
            break;
        }
    }
    if (!pc) {   /* npcs <= nkeys <= MAX: always room */
        l->phash[i] = (uint16_t)l->npcs;
        pc = &l->pcs[l->npcs++];
        memcpy(pc->path, path, sizeof(path));
        memcpy(pc->client, client, sizeof(client));
        pc->window = m->now_ns / SEC_NS;
        pc->in_window = 0;
        pc->peak = 0;
    }
    uint64_t w = m->now_ns / SEC_NS;
    if (w > pc->window) {
        pc->window = w;
        pc->in_window = 0;
    }
    /* w < window: late arrival from another thread; count it in the
     * current window, which can only overestimate the peak. */
    pc->in_window++;
    if (pc->in_window > pc->peak)
        pc->peak = pc->in_window;
    unlock(l);
    return 0;
}

/* ---------------------------------------------------------------- emit */

typedef struct out {
    char  *buf;
    size_t cap, len;
} out_t;

#if defined(__GNUC__)
static void put(out_t *o, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
#endif

static void put(out_t *o, const char *fmt, ...)
{
    va_list ap;
    char *dst = NULL;
    size_t room = 0;
    if (o->buf && o->len < o->cap) {
        dst = o->buf + o->len;
        room = o->cap - o->len;
    }
    va_start(ap, fmt);
    int n = vsnprintf(dst, room, fmt, ap);
    va_end(ap);
    if (n > 0)
        o->len += (size_t)n;
}

/* ceil(v * (100 + pct) / 100), saturating at UINT64_MAX */
static uint64_t headroom(uint64_t v, uint32_t pct)
{
    uint64_t f = 100u + (uint64_t)pct;
    uint64_t q = v / 100u, r = v % 100u;
    uint64_t hi, lo;
    if (q != 0 && q > UINT64_MAX / f)
        return UINT64_MAX;
    hi = q * f;
    lo = (r * f + 99u) / 100u;
    if (hi > UINT64_MAX - lo)
        return UINT64_MAX;
    return hi + lo;
}

/* Emit a string literal: quotes, escapes for `"` and `\`, and any byte
 * outside printable ASCII replaced by '?' so the output always lexes. */
static void put_str(out_t *o, const char *s)
{
    char tmp[2 * SPLINT_NAME_MAX + 3];
    size_t n = 0;
    tmp[n++] = '"';
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\')
            tmp[n++] = '\\';
        tmp[n++] = (c < 0x20 || c >= 0x7F) ? '?' : (char)c;
    }
    tmp[n++] = '"';
    tmp[n] = '\0';
    put(o, "%s", tmp);
}

static bool path_token_ok(const char *p)
{
    if (p[0] != '/')
        return false;
    for (; *p; p++) {
        char c = *p;
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '/' ||
              c == '-'))
            return false;
    }
    return true;
}

static bool len_meaningful(splint_op_t op)
{
    return op != SPLINT_OP_OPEN && op != SPLINT_OP_CLOSE &&
           op != SPLINT_OP_LSEEK;
}

static int cmp_key(const void *a, const void *b)
{
    const lkey_t *x = *(const lkey_t *const *)a;
    const lkey_t *y = *(const lkey_t *const *)b;
    int c = strcmp(x->path, y->path);
    if (c)
        return c;
    if (x->op != y->op)
        return x->op < y->op ? -1 : 1;
    if (x->code != y->code)
        return x->code < y->code ? -1 : 1;
    return strcmp(x->client, y->client);
}

static int cmp_pc(const void *a, const void *b)
{
    const lpc_t *x = *(const lpc_t *const *)a;
    const lpc_t *y = *(const lpc_t *const *)b;
    int c = strcmp(x->path, y->path);
    return c ? c : strcmp(x->client, y->client);
}

size_t splint_learn_emit(const splint_learn_t *l, char *buf, size_t cap)
{
    const lkey_t *ks[SPLINT_LEARN_MAX_KEYS];
    const lpc_t *ps[SPLINT_LEARN_MAX_KEYS];
    out_t o = { buf, cap, 0 };
    uint32_t nk, np, ki = 0, pi = 0, nprof = 0;

    if (buf && cap)
        buf[0] = '\0';
    if (!l)
        return 0;

    lock(l);
    nk = l->nkeys;
    np = l->npcs;
    for (uint32_t i = 0; i < nk; i++)
        ks[i] = &l->keys[i];
    for (uint32_t i = 0; i < np; i++)
        ps[i] = &l->pcs[i];
    qsort(ks, nk, sizeof(ks[0]), cmp_key);
    qsort(ps, np, sizeof(ps[0]), cmp_pc);

    put(&o, "# proposed by splintd learn mode: %u keys, %llu dropped\n",
        (unsigned)nk, (unsigned long long)l->dropped);

    while (ki < nk) {
        const char *path = ks[ki]->path;
        uint32_t kend = ki, pend = pi, nallow = 0, nrate = 0;
        while (kend < nk && strcmp(ks[kend]->path, path) == 0)
            kend++;
        while (pi < np && strcmp(ps[pi]->path, path) < 0)
            pi++;
        pend = pi;
        while (pend < np && strcmp(ps[pend]->path, path) == 0)
            pend++;

        if (!path_token_ok(path)) {
            put(&o, "\n# skipped path with characters not allowed in rules: ");
            put_str(&o, path);
            put(&o, "\n");
        } else if (nprof >= SPLINT_MAX_PROFILES) {
            put(&o, "\n# skipped %s: more than %u profiles\n", path,
                (unsigned)SPLINT_MAX_PROFILES);
        } else {
            nprof++;
            put(&o, "\nprofile %s {\n", path);
            put(&o, "  default %s\n", l->opts.default_block ? "block" : "allow");
            for (uint32_t i = ki; i < kend; i++) {
                const lkey_t *k = ks[i];
                if (nallow >= SPLINT_MAX_ALLOW)
                    break;
                nallow++;
                put(&o, "  allow %s", splint_op_name(k->op));
                if (k->op == SPLINT_OP_DEVCTL)
                    put(&o, " 0x%04x", (unsigned)k->code);
                put(&o, " client ");
                put_str(&o, k->client);
                if (len_meaningful(k->op)) {
                    uint64_t ml = headroom(k->max_len, l->opts.len_headroom_pct);
                    if (k->max_len > 0 && ml == 0)
                        ml = 1;
                    put(&o, " maxlen %llu", (unsigned long long)ml);
                }
                put(&o, "\n");
            }
            if (kend - ki > nallow)
                put(&o, "  # %u allow lines omitted (limit %u per profile)\n",
                    (unsigned)(kend - ki - nallow), (unsigned)SPLINT_MAX_ALLOW);
            for (uint32_t i = pi; i < pend; i++) {
                const lpc_t *p = ps[i];
                if (nrate >= SPLINT_MAX_RATES)
                    break;
                nrate++;
                uint64_t r = headroom(p->peak, l->opts.rate_headroom_pct);
                if (r < 1)
                    r = 1;
                if (r > UINT32_MAX)
                    r = UINT32_MAX;
                put(&o, "  rate %llu per s client ", (unsigned long long)r);
                put_str(&o, p->client);
                put(&o, "\n");
            }
            if (pend - pi > nrate)
                put(&o, "  # %u rate lines omitted (limit %u per profile)\n",
                    (unsigned)(pend - pi - nrate), (unsigned)SPLINT_MAX_RATES);
            put(&o, "}\n");
        }
        ki = kend;
        pi = pend;
    }
    unlock(l);
    return o.len;
}
