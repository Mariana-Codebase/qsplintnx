/* SPDX-License-Identifier: Apache-2.0 */
/*
 * bench_engine - host micro-benchmark of splint_engine_decide().
 *
 * Built and run by `make bench`. Prints a markdown table to stdout.
 *
 * Scenarios (rulesets built by hand, no parser involved):
 *   patches-0     empty ruleset
 *   patches-16    16 / 64 / 256 patches, all on the message's path, op and
 *   patches-64    devctl code, each with SPLINT_MAX_CONDS `when` conditions
 *   patches-256   of which all but the LAST hold. No patch matches, so the
 *                 engine evaluates every condition of every patch: the
 *                 worst case of the O(npatch * SPLINT_MAX_CONDS) bound.
 *   profile-64    one profile on the path with 64 allow lines, none of
 *                 which matches (code outside every range), default allow;
 *                 every allow line is evaluated. No rate lines.
 *
 * Before timing, each scenario is checked: the bench message must be
 * ALLOWed, and for the patch scenarios a variant of the message that also
 * satisfies the last condition must be BLOCKed by the first patch. That
 * proves the conditions are really evaluated and not skipped early.
 *
 * Timing method: clock_gettime(CLOCK_MONOTONIC) is read once per batch
 * of BATCH (64) consecutive calls, not per call, so the ~20-50 ns cost
 * of reading the clock does not dominate a decision that itself takes
 * tens of ns. Each sample is (batch time / BATCH). The reported
 * percentiles are therefore percentiles of 64-call averages: tails
 * (p99.9, max) are smoothed by a factor of up to 64 compared with true
 * per-call tails, while min and p50 are close to per-call values. The
 * clock read cost per batch is measured with an empty batch and printed
 * separately; it is NOT subtracted. 1e6 calls (15625 batches) are timed
 * per scenario after 1e5 warm-up calls.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "splint/engine.h"
#include "splint/msg.h"
#include "splint/rules.h"

#define BATCH        64u
#define ITERATIONS   1000000u
#define WARMUP       100000u
#define NBATCH       (ITERATIONS / BATCH)

#define BENCH_PATH   "/dev/vendor_can"
#define BENCH_SHORT  0x0505u        /* VCAN_SHORT_SET_FILTER */
#define BENCH_DCMD   (0x80000000u | (64u << 16) | BENCH_SHORT)  /* __DIOT(.., 64 bytes) */
#define PAYLOAD_LEN  32u
#define LAST_OFF     31u            /* byte checked by the failing condition */
#define LAST_VAL     0xEEu

static volatile unsigned g_sink;

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

/* ------------------------------------------------------------ rulesets -- */

static splint_cond_t mkcond(splint_operand_kind_t lk, uint64_t lv, splint_cmp_t cmp,
                            splint_operand_kind_t rk, uint64_t rv)
{
    splint_cond_t c;
    memset(&c, 0, sizeof c);
    c.lhs.kind = lk;
    c.lhs.value = lv;
    c.cmp = cmp;
    c.rhs.kind = rk;
    c.rhs.value = rv;
    return c;
}

/* Conditions that HOLD for the bench message; mixed operand kinds so the
 * engine exercises every load path. */
static splint_cond_t true_cond(uint32_t k)
{
    switch (k % 7u) {
    case 0:  return mkcond(SPLINT_OPD_LEN, 0, SPLINT_CMP_GE, SPLINT_OPD_CONST, 16);
    case 1:  return mkcond(SPLINT_OPD_LEN, 0, SPLINT_CMP_LE, SPLINT_OPD_CONST, 64);
    case 2:  return mkcond(SPLINT_OPD_DECLARED, 0, SPLINT_CMP_EQ, SPLINT_OPD_CONST, 64);
    case 3:  return mkcond(SPLINT_OPD_DECLARED, 0, SPLINT_CMP_NE, SPLINT_OPD_LEN, 0);
    case 4:  return mkcond(SPLINT_OPD_BYTE, 0, SPLINT_CMP_EQ, SPLINT_OPD_CONST, 0x11);
    case 5:  return mkcond(SPLINT_OPD_U16, 2, SPLINT_CMP_EQ, SPLINT_OPD_CONST, 0x2233);
    default: return mkcond(SPLINT_OPD_U32, 4, SPLINT_CMP_EQ, SPLINT_OPD_CONST, 0x44556677u);
    }
}

static splint_ruleset_t *new_ruleset(void)
{
    splint_ruleset_t *rs = calloc(1, sizeof *rs);
    if (rs == NULL) {
        fprintf(stderr, "bench_engine: out of memory\n");
        exit(1);
    }
    rs->mode = SPLINT_MODE_ENFORCE;
    return rs;
}

static splint_ruleset_t *build_patches(uint32_t npatch)
{
    splint_ruleset_t *rs = new_ruleset();
    for (uint32_t i = 0; i < npatch; i++) {
        splint_patch_t *p = &rs->patch[i];
        snprintf(p->id, sizeof p->id, "BENCH-%03u", (unsigned)i);
        snprintf(p->path, sizeof p->path, "%s", BENCH_PATH);
        p->op = SPLINT_OP_DEVCTL;
        p->has_code = true;
        p->code = BENCH_SHORT;
        p->ncond = SPLINT_MAX_CONDS;
        for (uint32_t k = 0; k + 1 < SPLINT_MAX_CONDS; k++)
            p->cond[k] = true_cond(k);
        /* last condition is false for the bench message */
        p->cond[SPLINT_MAX_CONDS - 1] = mkcond(SPLINT_OPD_BYTE, LAST_OFF, SPLINT_CMP_EQ,
                                               SPLINT_OPD_CONST, LAST_VAL);
        p->actions = SPLINT_ACT_BLOCK | SPLINT_ACT_LOG;
        p->err = EPERM;
        p->line = i + 1;
    }
    rs->npatch = npatch;
    return rs;
}

static splint_ruleset_t *build_profile(uint32_t nallow)
{
    splint_ruleset_t *rs = new_ruleset();
    splint_profile_t *pr = &rs->profile[0];
    snprintf(pr->path, sizeof pr->path, "%s", BENCH_PATH);
    pr->default_block = false;
    pr->line = 1;
    for (uint32_t i = 0; i < nallow; i++) {
        splint_allow_t *a = &pr->allow[i];
        a->op = SPLINT_OP_DEVCTL;
        a->has_code = true;
        a->code_lo = 0x0600u + 2u * i;   /* never contains 0x0505 */
        a->code_hi = a->code_lo + 1u;
        a->has_client = true;
        snprintf(a->client, sizeof a->client, "can_client");
        a->has_maxlen = true;
        a->maxlen = 64;
        a->line = i + 2;
    }
    pr->nallow = nallow;
    rs->nprofile = 1;
    return rs;
}

/* -------------------------------------------------------------- timing -- */

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* nearest-rank percentile on sorted samples */
static uint64_t pct(const uint64_t *s, size_t n, double p)
{
    size_t r = (size_t)(p / 100.0 * (double)n + 0.999999);
    if (r < 1)
        r = 1;
    if (r > n)
        r = n;
    return s[r - 1];
}

static void run_batches(splint_engine_t *e, const splint_msg_t *m, uint64_t *samples)
{
    splint_verdict_t v;
    unsigned acc = 0;

    for (uint32_t i = 0; i < WARMUP; i++) {
        splint_engine_decide(e, m, &v);
        acc += (unsigned)v.action;
    }
    for (uint32_t b = 0; b < NBATCH; b++) {
        uint64_t t0 = now_ns();
        for (uint32_t i = 0; i < BATCH; i++) {
            splint_engine_decide(e, m, &v);
            acc += (unsigned)v.action;
        }
        samples[b] = now_ns() - t0;
    }
    g_sink = acc;
}

static uint64_t clock_overhead_ns(uint64_t *samples)
{
    for (uint32_t b = 0; b < NBATCH; b++) {
        uint64_t t0 = now_ns();
        samples[b] = now_ns() - t0;
    }
    qsort(samples, NBATCH, sizeof *samples, cmp_u64);
    return pct(samples, NBATCH, 50.0);
}

static void print_row(const char *name, uint32_t npatch, uint32_t ncond, uint32_t nallow,
                      uint64_t *samples)
{
    qsort(samples, NBATCH, sizeof *samples, cmp_u64);
    printf("| %-11s | %7u | %5u | %5u | %9u | %8.1f | %8.1f | %8.1f | %8.1f | %9.1f |\n",
           name, (unsigned)npatch, (unsigned)ncond, (unsigned)nallow, ITERATIONS,
           (double)samples[0] / BATCH,
           (double)pct(samples, NBATCH, 50.0) / BATCH,
           (double)pct(samples, NBATCH, 99.0) / BATCH,
           (double)pct(samples, NBATCH, 99.9) / BATCH,
           (double)samples[NBATCH - 1] / BATCH);
}

static void expect(splint_engine_t *e, const splint_msg_t *m, splint_action_t want,
                   const char *scenario, const char *what)
{
    splint_verdict_t v;
    memset(&v, 0, sizeof v);
    splint_engine_decide(e, m, &v);
    if (v.action != want) {
        fprintf(stderr, "bench_engine: %s: sanity check failed (%s): got %s, reason %s\n",
                scenario, what, v.action == SPLINT_BLOCK ? "BLOCK" : "ALLOW",
                splint_reason_name(v.reason));
        exit(1);
    }
}

/* ---------------------------------------------------------------- main -- */

int main(void)
{
    static const uint32_t patch_counts[] = { 0, 16, 64, 256 };
    uint8_t payload[PAYLOAD_LEN], payload_hit[PAYLOAD_LEN];
    splint_client_t client;
    splint_msg_t msg, msg_hit;
    splint_engine_t *e;
    uint64_t *samples, overhead;

    memset(payload, 0, sizeof payload);
    payload[0] = 0x11;
    payload[2] = 0x33; payload[3] = 0x22;                        /* u16 LE 0x2233 */
    payload[4] = 0x77; payload[5] = 0x66; payload[6] = 0x55; payload[7] = 0x44;
    memcpy(payload_hit, payload, sizeof payload);
    payload_hit[LAST_OFF] = LAST_VAL;

    memset(&client, 0, sizeof client);
    client.pid = 4242;
    snprintf(client.name, sizeof client.name, "can_client");

    memset(&msg, 0, sizeof msg);
    msg.op = SPLINT_OP_DEVCTL;
    msg.dcmd = BENCH_DCMD;
    msg.declared = 64;
    msg.len = PAYLOAD_LEN;
    msg.data = payload;
    msg.data_len = PAYLOAD_LEN;
    msg.path = BENCH_PATH;
    msg.client = &client;
    msg.now_ns = 1000000000u;
    msg_hit = msg;
    msg_hit.data = payload_hit;

    samples = calloc(NBATCH, sizeof *samples);
    e = splint_engine_new();
    if (samples == NULL || e == NULL) {
        fprintf(stderr, "bench_engine: setup failed\n");
        return 1;
    }

    printf("## splint_engine_decide() latency (host)\n\n");
#ifdef __VERSION__
    printf("compiler: %s; ", __VERSION__);
#endif
    printf("SPLINT_MAX_CONDS=%u; %u calls per scenario after %u warm-up calls; "
           "ns per call = batch time / %u (see bench/README.md).\n",
           (unsigned)SPLINT_MAX_CONDS, ITERATIONS, WARMUP, BATCH);
    overhead = clock_overhead_ns(samples);
    printf("clock_gettime pair overhead per batch (p50, not subtracted): %llu ns "
           "(= %.2f ns per call)\n\n",
           (unsigned long long)overhead, (double)overhead / BATCH);

    printf("| scenario    | patches | conds | allow |     calls |  min ns  |  p50 ns  |  p99 ns  | p99.9 ns |   max ns  |\n");
    printf("|-------------|--------:|------:|------:|----------:|---------:|---------:|---------:|---------:|----------:|\n");

    for (size_t i = 0; i < sizeof patch_counts / sizeof patch_counts[0]; i++) {
        uint32_t n = patch_counts[i];
        char name[32];
        snprintf(name, sizeof name, "patches-%u", (unsigned)n);
        splint_engine_set_rules(e, build_patches(n));
        expect(e, &msg, SPLINT_ALLOW, name, "no patch may match");
        if (n > 0)
            expect(e, &msg_hit, SPLINT_BLOCK, name, "all conditions true must block");
        run_batches(e, &msg, samples);
        print_row(name, n, n ? SPLINT_MAX_CONDS : 0, 0, samples);
    }

    splint_engine_set_rules(e, build_profile(SPLINT_MAX_ALLOW));
    expect(e, &msg, SPLINT_ALLOW, "profile-64", "default allow");
    run_batches(e, &msg, samples);
    print_row("profile-64", 0, 0, SPLINT_MAX_ALLOW, samples);

    splint_engine_free(e);
    free(samples);
    return 0;
}
