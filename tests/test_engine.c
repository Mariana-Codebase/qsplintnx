/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Unit tests for the decision engine (src/core/engine.c) and the rate
 * limiter. Rulesets are built by hand so these tests do not depend on
 * the parser. Includes a multithreaded hot-swap test meant to be run
 * under ASan and, separately, TSan.
 */
#include "splint/engine.h"
#include "test_util.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

#define PATH "/dev/vendor_can"
#define NS   1000000000ull

static splint_ruleset_t *rs_new(void)
{
    splint_ruleset_t *rs = calloc(1, sizeof(*rs));
    if (!rs) {
        perror("calloc");
        exit(2);
    }
    return rs;
}

static splint_patch_t *add_patch(splint_ruleset_t *rs, const char *id,
                                 const char *path, splint_op_t op,
                                 uint32_t actions)
{
    splint_patch_t *p = &rs->patch[rs->npatch++];
    snprintf(p->id, sizeof(p->id), "%s", id);
    snprintf(p->path, sizeof(p->path), "%s", path);
    p->op = op;
    p->actions = actions;
    p->line = rs->npatch * 10u;
    return p;
}

static void add_cond(splint_patch_t *p, splint_operand_kind_t lk, uint64_t lv,
                     splint_cmp_t cmp, splint_operand_kind_t rk, uint64_t rv)
{
    splint_cond_t *c = &p->cond[p->ncond++];
    c->lhs.kind = lk;
    c->lhs.value = lv;
    c->cmp = cmp;
    c->rhs.kind = rk;
    c->rhs.value = rv;
}

static splint_profile_t *add_profile(splint_ruleset_t *rs, const char *path,
                                     bool default_block)
{
    splint_profile_t *pf = &rs->profile[rs->nprofile++];
    snprintf(pf->path, sizeof(pf->path), "%s", path);
    pf->default_block = default_block;
    pf->line = 100u + rs->nprofile;
    return pf;
}

static splint_allow_t *add_allow(splint_profile_t *pf, splint_op_t op)
{
    splint_allow_t *a = &pf->allow[pf->nallow++];
    a->op = op;
    a->line = 200u + pf->nallow;
    return a;
}

static splint_rate_t *add_rate(splint_profile_t *pf, uint32_t per_sec,
                               const char *client)
{
    splint_rate_t *r = &pf->rate[pf->nrate++];
    r->per_sec = per_sec;
    if (client) {
        r->has_client = true;
        snprintf(r->client, sizeof(r->client), "%s", client);
    }
    r->line = 300u + pf->nrate;
    return r;
}

static splint_client_t cl_good = { 100, 0, 0, "can_client" };
static splint_client_t cl_evil = { 200, 0, 0, "exploit" };
static splint_client_t cl_other = { 300, 0, 0, "other" };

static splint_msg_t mk(splint_op_t op, uint32_t dcmd, uint64_t len,
                       const uint8_t *data, size_t dlen,
                       const splint_client_t *cl)
{
    splint_msg_t m;
    memset(&m, 0, sizeof(m));
    m.op = op;
    m.dcmd = dcmd;
    m.len = len;
    m.declared = len;
    m.data = data;
    m.data_len = dlen;
    m.path = PATH;
    m.client = cl;
    m.now_ns = 1 * NS;
    return m;
}

static splint_verdict_t run(splint_engine_t *e, const splint_msg_t *m)
{
    splint_verdict_t v;
    memset(&v, 0xAB, sizeof(v));   /* decide must fill everything */
    splint_engine_decide(e, m, &v);
    return v;
}

/* --------------------------------------------------------------- tests */

static void test_null_ruleset(void)
{
    splint_engine_t *e = splint_engine_new();
    splint_msg_t m = mk(SPLINT_OP_WRITE, 0, 10, NULL, 0, &cl_good);
    splint_verdict_t v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW);
    CHECK(v.reason == SPLINT_R_NONE);
    CHECK(!v.log && !v.would_block);
    CHECK(v.rule_id == NULL);
    CHECK_EQ_U(v.rule_line, 0);
    CHECK_EQ_U(v.err, 0);

    /* setting and then clearing the ruleset */
    splint_engine_set_rules(e, rs_new());
    splint_engine_set_rules(e, NULL);
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW && v.reason == SPLINT_R_NONE);
    splint_engine_free(e);
}

/* one patch with a single condition; returns block?  */
static bool cond_blocks(splint_operand_kind_t lk, uint64_t lv, splint_cmp_t cmp,
                        splint_operand_kind_t rk, uint64_t rv,
                        const splint_msg_t *m)
{
    splint_engine_t *e = splint_engine_new();
    splint_ruleset_t *rs = rs_new();
    splint_patch_t *p = add_patch(rs, "P", PATH, SPLINT_OP_ANY, SPLINT_ACT_BLOCK);
    add_cond(p, lk, lv, cmp, rk, rv);
    splint_engine_set_rules(e, rs);
    splint_verdict_t v = run(e, m);
    splint_engine_free(e);
    return v.action == SPLINT_BLOCK;
}

static void test_operands_and_cmps(void)
{
    /* payload: 01 02 03 04 05 06 07 08 */
    static const uint8_t d[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    splint_msg_t m = mk(SPLINT_OP_WRITE, 0, 100, d, sizeof(d), &cl_good);
    m.declared = 64;

    /* len / declared vs const */
    CHECK(cond_blocks(SPLINT_OPD_LEN, 0, SPLINT_CMP_EQ, SPLINT_OPD_CONST, 100, &m));
    CHECK(!cond_blocks(SPLINT_OPD_LEN, 0, SPLINT_CMP_EQ, SPLINT_OPD_CONST, 99, &m));
    CHECK(cond_blocks(SPLINT_OPD_DECLARED, 0, SPLINT_CMP_EQ, SPLINT_OPD_CONST, 64, &m));
    /* declared != len (length confusion) */
    CHECK(cond_blocks(SPLINT_OPD_DECLARED, 0, SPLINT_CMP_NE, SPLINT_OPD_LEN, 0, &m));
    CHECK(cond_blocks(SPLINT_OPD_LEN, 0, SPLINT_CMP_GT, SPLINT_OPD_DECLARED, 0, &m));
    CHECK(cond_blocks(SPLINT_OPD_LEN, 0, SPLINT_CMP_EQ, SPLINT_OPD_LEN, 0, &m));

    /* every comparator, both outcomes, on len=100 */
    CHECK(cond_blocks(SPLINT_OPD_LEN, 0, SPLINT_CMP_NE, SPLINT_OPD_CONST, 7, &m));
    CHECK(!cond_blocks(SPLINT_OPD_LEN, 0, SPLINT_CMP_NE, SPLINT_OPD_CONST, 100, &m));
    CHECK(cond_blocks(SPLINT_OPD_LEN, 0, SPLINT_CMP_LT, SPLINT_OPD_CONST, 101, &m));
    CHECK(!cond_blocks(SPLINT_OPD_LEN, 0, SPLINT_CMP_LT, SPLINT_OPD_CONST, 100, &m));
    CHECK(cond_blocks(SPLINT_OPD_LEN, 0, SPLINT_CMP_LE, SPLINT_OPD_CONST, 100, &m));
    CHECK(!cond_blocks(SPLINT_OPD_LEN, 0, SPLINT_CMP_LE, SPLINT_OPD_CONST, 99, &m));
    CHECK(cond_blocks(SPLINT_OPD_LEN, 0, SPLINT_CMP_GT, SPLINT_OPD_CONST, 99, &m));
    CHECK(!cond_blocks(SPLINT_OPD_LEN, 0, SPLINT_CMP_GT, SPLINT_OPD_CONST, 100, &m));
    CHECK(cond_blocks(SPLINT_OPD_LEN, 0, SPLINT_CMP_GE, SPLINT_OPD_CONST, 100, &m));
    CHECK(!cond_blocks(SPLINT_OPD_LEN, 0, SPLINT_CMP_GE, SPLINT_OPD_CONST, 101, &m));

    /* byte / u16 / u32 little endian loads */
    CHECK(cond_blocks(SPLINT_OPD_BYTE, 0, SPLINT_CMP_EQ, SPLINT_OPD_CONST, 1, &m));
    CHECK(cond_blocks(SPLINT_OPD_BYTE, 7, SPLINT_CMP_EQ, SPLINT_OPD_CONST, 8, &m));
    CHECK(cond_blocks(SPLINT_OPD_U16, 1, SPLINT_CMP_EQ, SPLINT_OPD_CONST, 0x0302, &m));
    CHECK(cond_blocks(SPLINT_OPD_U16, 6, SPLINT_CMP_EQ, SPLINT_OPD_CONST, 0x0807, &m));
    CHECK(cond_blocks(SPLINT_OPD_U32, 0, SPLINT_CMP_EQ, SPLINT_OPD_CONST, 0x04030201, &m));
    CHECK(cond_blocks(SPLINT_OPD_U32, 4, SPLINT_CMP_EQ, SPLINT_OPD_CONST, 0x08070605, &m));
    /* payload field vs len */
    CHECK(cond_blocks(SPLINT_OPD_BYTE, 3, SPLINT_CMP_LT, SPLINT_OPD_LEN, 0, &m));

    /* out of bounds: condition FALSE regardless of comparator */
    CHECK(!cond_blocks(SPLINT_OPD_BYTE, 8, SPLINT_CMP_NE, SPLINT_OPD_CONST, 12345, &m));
    CHECK(!cond_blocks(SPLINT_OPD_BYTE, 8, SPLINT_CMP_EQ, SPLINT_OPD_CONST, 0, &m));
    CHECK(!cond_blocks(SPLINT_OPD_U16, 7, SPLINT_CMP_GE, SPLINT_OPD_CONST, 0, &m));
    CHECK(!cond_blocks(SPLINT_OPD_U32, 5, SPLINT_CMP_GE, SPLINT_OPD_CONST, 0, &m));
    CHECK(!cond_blocks(SPLINT_OPD_U32, 255, SPLINT_CMP_GE, SPLINT_OPD_CONST, 0, &m));
    CHECK(!cond_blocks(SPLINT_OPD_U32, UINT64_MAX - 1, SPLINT_CMP_GE, SPLINT_OPD_CONST, 0, &m));
    /* NULL data */
    splint_msg_t m0 = mk(SPLINT_OP_WRITE, 0, 100, NULL, 0, &cl_good);
    CHECK(!cond_blocks(SPLINT_OPD_BYTE, 0, SPLINT_CMP_GE, SPLINT_OPD_CONST, 0, &m0));
    /* uint64 comparison, no sign issues */
    m.len = UINT64_MAX;
    CHECK(cond_blocks(SPLINT_OPD_LEN, 0, SPLINT_CMP_GT, SPLINT_OPD_CONST, 0x7FFFFFFFFFFFFFFFull, &m));
}

static void test_patch_matching(void)
{
    splint_engine_t *e = splint_engine_new();
    splint_ruleset_t *rs = rs_new();
    splint_patch_t *p;

    /* short code 0x0505, conditions len > 64 */
    p = add_patch(rs, "CVE-SHORT", PATH, SPLINT_OP_DEVCTL,
                  SPLINT_ACT_BLOCK | SPLINT_ACT_LOG);
    p->has_code = true;
    p->code = 0x0505;
    add_cond(p, SPLINT_OPD_LEN, 0, SPLINT_CMP_GT, SPLINT_OPD_CONST, 64);
    /* full code, custom errno */
    p = add_patch(rs, "CVE-FULL", PATH, SPLINT_OP_DEVCTL, SPLINT_ACT_BLOCK);
    p->has_code = true;
    p->code = 0xC0100606u;
    p->err = EINVAL;
    /* same path different file -> must not match */
    p = add_patch(rs, "OTHERPATH", "/dev/other", SPLINT_OP_ANY, SPLINT_ACT_BLOCK);
    /* op any on write with byte[0]==0xFF */
    p = add_patch(rs, "ANY-FF", PATH, SPLINT_OP_ANY, SPLINT_ACT_BLOCK);
    add_cond(p, SPLINT_OPD_BYTE, 0, SPLINT_CMP_EQ, SPLINT_OPD_CONST, 0xFF);
    /* second patch on same short code, never reported (first wins) */
    p = add_patch(rs, "CVE-SHORT-2", PATH, SPLINT_OP_DEVCTL, SPLINT_ACT_BLOCK);
    p->has_code = true;
    p->code = 0x0505;
    splint_engine_set_rules(e, rs);

    splint_msg_t m = mk(SPLINT_OP_DEVCTL, 0x80400505u, 200, NULL, 0, &cl_evil);
    splint_verdict_t v = run(e, &m);
    CHECK(v.action == SPLINT_BLOCK);
    CHECK(v.reason == SPLINT_R_PATCH);
    CHECK_STR(v.rule_id, "CVE-SHORT");
    CHECK_EQ_U(v.rule_line, 10);
    CHECK_EQ_U(v.err, EPERM);
    CHECK(v.log);

    /* len 64 -> CVE-SHORT does not match; CVE-SHORT-2 (first remaining) */
    m.len = 64;
    v = run(e, &m);
    CHECK(v.action == SPLINT_BLOCK);
    CHECK_STR(v.rule_id, "CVE-SHORT-2");
    CHECK(!v.log);

    /* full code match */
    m = mk(SPLINT_OP_DEVCTL, 0xC0100606u, 16, NULL, 0, &cl_evil);
    v = run(e, &m);
    CHECK(v.action == SPLINT_BLOCK);
    CHECK_STR(v.rule_id, "CVE-FULL");
    CHECK_EQ_U(v.err, EINVAL);
    /* full code with other direction bits does not match */
    m.dcmd = 0x80100606u;
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW);
    /* devctl code on a non-devctl op never matches */
    m = mk(SPLINT_OP_WRITE, 0x0505, 200, NULL, 0, &cl_evil);
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW);

    /* op any */
    static const uint8_t ff[1] = { 0xFF };
    splint_op_t ops[] = { SPLINT_OP_OPEN, SPLINT_OP_READ, SPLINT_OP_WRITE,
                          SPLINT_OP_LSEEK, SPLINT_OP_CLOSE, SPLINT_OP_OTHER };
    for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
        m = mk(ops[i], 0, 1, ff, 1, &cl_good);
        v = run(e, &m);
        CHECK(v.action == SPLINT_BLOCK);
        CHECK_STR(v.rule_id, "ANY-FF");
    }
    /* path is exact */
    m = mk(SPLINT_OP_WRITE, 0, 1, ff, 1, &cl_good);
    m.path = "/dev/vendor_can0";
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW && v.reason == SPLINT_R_NONE);
    m.path = NULL;
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW);

    splint_engine_free(e);
}

static void test_log_only_patch(void)
{
    splint_engine_t *e = splint_engine_new();
    splint_ruleset_t *rs = rs_new();
    splint_patch_t *p = add_patch(rs, "WATCH", PATH, SPLINT_OP_WRITE, SPLINT_ACT_LOG);
    add_cond(p, SPLINT_OPD_LEN, 0, SPLINT_CMP_GT, SPLINT_OPD_CONST, 10);
    splint_engine_set_rules(e, rs);

    /* no profile: allow, log, reason patch */
    splint_msg_t m = mk(SPLINT_OP_WRITE, 0, 20, NULL, 0, &cl_good);
    splint_verdict_t v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW);
    CHECK(v.log);
    CHECK(v.reason == SPLINT_R_PATCH);
    CHECK_STR(v.rule_id, "WATCH");

    /* with a profile: evaluation continues to the profile */
    rs = rs_new();
    p = add_patch(rs, "WATCH", PATH, SPLINT_OP_WRITE, SPLINT_ACT_LOG);
    splint_profile_t *pf = add_profile(rs, PATH, true);
    splint_allow_t *a = add_allow(pf, SPLINT_OP_WRITE);
    a->has_maxlen = true;
    a->maxlen = 15;
    splint_engine_set_rules(e, rs);

    m.len = 20;
    v = run(e, &m);
    CHECK(v.action == SPLINT_BLOCK);
    CHECK(v.reason == SPLINT_R_DEFAULT);
    CHECK(v.log);
    CHECK_STR(v.rule_id, "WATCH");
    CHECK_EQ_U(v.rule_line, pf->line);
    CHECK_EQ_U(v.err, EPERM);

    m.len = 15;
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW);
    CHECK(v.reason == SPLINT_R_ALLOW);
    CHECK(v.log);
    CHECK_EQ_U(v.rule_line, a->line);
    splint_engine_free(e);
}

static void test_profile(void)
{
    splint_engine_t *e = splint_engine_new();
    splint_ruleset_t *rs = rs_new();
    splint_profile_t *pf = add_profile(rs, PATH, true);
    splint_allow_t *a;

    a = add_allow(pf, SPLINT_OP_OPEN);                       /* 201 */
    a = add_allow(pf, SPLINT_OP_DEVCTL);                     /* 202 */
    a->has_code = true; a->code_lo = a->code_hi = 0x0101;
    a->has_maxlen = true; a->maxlen = 16;
    a = add_allow(pf, SPLINT_OP_DEVCTL);                     /* 203 */
    a->has_code = true; a->code_lo = 0x0102; a->code_hi = 0x0104;
    a->has_client = true; snprintf(a->client, sizeof(a->client), "can_client");
    a->has_maxlen = true; a->maxlen = 64;
    a = add_allow(pf, SPLINT_OP_DEVCTL);                     /* 204: full-code range */
    a->has_code = true; a->code_lo = 0x80000700u; a->code_hi = 0x80000701u;
    a = add_allow(pf, SPLINT_OP_ANY);                        /* 205: any op for "other" */
    a->has_client = true; snprintf(a->client, sizeof(a->client), "other");

    /* default allow profile on another path */
    splint_profile_t *pf2 = add_profile(rs, "/dev/open", false);
    splint_engine_set_rules(e, rs);

    splint_msg_t m;
    splint_verdict_t v;

    m = mk(SPLINT_OP_OPEN, 0, 0, NULL, 0, &cl_evil);
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW && v.reason == SPLINT_R_ALLOW);
    CHECK_EQ_U(v.rule_line, 201);
    CHECK(v.rule_id == NULL);

    /* single code by short form with maxlen */
    m = mk(SPLINT_OP_DEVCTL, 0x40100101u, 16, NULL, 0, &cl_evil);
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW);
    CHECK_EQ_U(v.rule_line, 202);
    m.len = 17;
    v = run(e, &m);
    CHECK(v.action == SPLINT_BLOCK && v.reason == SPLINT_R_DEFAULT);
    CHECK_EQ_U(v.rule_line, pf->line);
    CHECK_EQ_U(v.err, EPERM);

    /* range + client */
    for (uint32_t c = 0x0102; c <= 0x0104; c++) {
        m = mk(SPLINT_OP_DEVCTL, 0x80400000u | c, 64, NULL, 0, &cl_good);
        v = run(e, &m);
        CHECK(v.action == SPLINT_ALLOW);
        CHECK_EQ_U(v.rule_line, 203);
    }
    m = mk(SPLINT_OP_DEVCTL, 0x0105, 1, NULL, 0, &cl_good);
    v = run(e, &m);
    CHECK(v.action == SPLINT_BLOCK);
    m = mk(SPLINT_OP_DEVCTL, 0x0103, 1, NULL, 0, &cl_evil);   /* wrong client */
    v = run(e, &m);
    CHECK(v.action == SPLINT_BLOCK);
    m = mk(SPLINT_OP_DEVCTL, 0x0103, 1, NULL, 0, NULL);       /* no client */
    v = run(e, &m);
    CHECK(v.action == SPLINT_BLOCK);

    /* range on full code */
    m = mk(SPLINT_OP_DEVCTL, 0x80000701u, 1, NULL, 0, &cl_evil);
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW);
    CHECK_EQ_U(v.rule_line, 204);
    m.dcmd = 0x80000702u;
    v = run(e, &m);
    CHECK(v.action == SPLINT_BLOCK);

    /* any op with client */
    m = mk(SPLINT_OP_READ, 0, 1000, NULL, 0, &cl_other);
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW);
    CHECK_EQ_U(v.rule_line, 205);

    /* coded allow lines never match non-devctl ops */
    m = mk(SPLINT_OP_WRITE, 0x0101, 1, NULL, 0, &cl_good);
    v = run(e, &m);
    CHECK(v.action == SPLINT_BLOCK);

    /* default allow */
    m = mk(SPLINT_OP_WRITE, 0, 1, NULL, 0, &cl_good);
    m.path = "/dev/open";
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW && v.reason == SPLINT_R_DEFAULT);
    CHECK_EQ_U(v.rule_line, pf2->line);
    CHECK_EQ_U(v.err, 0);

    /* path with no profile */
    m.path = "/dev/none";
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW && v.reason == SPLINT_R_NONE);
    splint_engine_free(e);
}

static void test_rate(void)
{
    splint_engine_t *e = splint_engine_new();
    splint_ruleset_t *rs = rs_new();
    splint_profile_t *pf = add_profile(rs, PATH, false);
    add_rate(pf, 3, NULL);                 /* line 301: default */
    add_rate(pf, 5, "can_client");         /* line 302: specific */
    splint_engine_set_rules(e, rs);

    splint_msg_t m = mk(SPLINT_OP_WRITE, 0, 1, NULL, 0, &cl_good);
    splint_verdict_t v;
    uint64_t t0 = 10 * NS;

    /* can_client: burst of 5 then blocked */
    m.now_ns = t0;
    for (int i = 0; i < 5; i++) {
        v = run(e, &m);
        CHECK(v.action == SPLINT_ALLOW);
    }
    v = run(e, &m);
    CHECK(v.action == SPLINT_BLOCK && v.reason == SPLINT_R_RATE);
    CHECK_EQ_U(v.rule_line, 302);
    CHECK_EQ_U(v.err, EPERM);

    /* exploit uses the default (3) and its own bucket */
    splint_msg_t me = m;
    me.client = &cl_evil;
    for (int i = 0; i < 3; i++)
        CHECK(run(e, &me).action == SPLINT_ALLOW);
    v = run(e, &me);
    CHECK(v.action == SPLINT_BLOCK && v.reason == SPLINT_R_RATE);
    CHECK_EQ_U(v.rule_line, 301);

    /* refill: 5/s -> one token per 200 ms */
    m.now_ns = t0 + 199000000ull;
    CHECK(run(e, &m).action == SPLINT_BLOCK);
    m.now_ns = t0 + 200000000ull;
    CHECK(run(e, &m).action == SPLINT_ALLOW);
    CHECK(run(e, &m).action == SPLINT_BLOCK);
    /* clock going backwards refills nothing */
    m.now_ns = t0;
    CHECK(run(e, &m).action == SPLINT_BLOCK);
    /* long idle -> refill to burst only */
    m.now_ns = t0 + 100 * NS;
    for (int i = 0; i < 5; i++)
        CHECK(run(e, &m).action == SPLINT_ALLOW);
    CHECK(run(e, &m).action == SPLINT_BLOCK);

    /* pid identifies the bucket: same name, other pid -> fresh bucket */
    splint_client_t twin = cl_good;
    twin.pid = 101;
    splint_msg_t mt = m;
    mt.client = &twin;
    CHECK(run(e, &mt).action == SPLINT_ALLOW);

    /* swap resets the table: same rules, fresh burst */
    splint_ruleset_t *rs2 = rs_new();
    *rs2 = *rs;            /* rs still owned by engine until swap */
    splint_engine_set_rules(e, rs2);
    for (int i = 0; i < 5; i++)
        CHECK(run(e, &m).action == SPLINT_ALLOW);
    CHECK(run(e, &m).action == SPLINT_BLOCK);

    splint_engine_stats_t st;
    splint_engine_stats(e, &st);
    CHECK(st.rate_limited >= 6);

    /* many distinct pids: table eviction stays bounded and correct */
    for (int32_t pid = 1000; pid < 3000; pid++) {
        splint_client_t c = { pid, 0, 0, "x" };
        splint_msg_t mx = m;
        mx.client = &c;
        mx.now_ns = t0 + 200 * NS + (uint64_t)pid;
        CHECK(run(e, &mx).action == SPLINT_ALLOW);   /* fresh bucket */
    }
    splint_engine_free(e);
}

static void test_learn_mode(void)
{
    splint_engine_t *e = splint_engine_new();
    splint_ruleset_t *rs = rs_new();
    rs->mode = SPLINT_MODE_LEARN;
    splint_patch_t *p = add_patch(rs, "CVE-X", PATH, SPLINT_OP_DEVCTL, SPLINT_ACT_BLOCK);
    p->has_code = true;
    p->code = 0x0505;
    splint_profile_t *pf = add_profile(rs, PATH, true);
    add_allow(pf, SPLINT_OP_OPEN);
    add_rate(pf, 1, NULL);
    splint_engine_set_rules(e, rs);

    /* patch still enforced */
    splint_msg_t m = mk(SPLINT_OP_DEVCTL, 0x0505, 1, NULL, 0, &cl_evil);
    splint_verdict_t v = run(e, &m);
    CHECK(v.action == SPLINT_BLOCK && v.reason == SPLINT_R_PATCH);
    CHECK(!v.would_block);
    CHECK_EQ_U(v.err, EPERM);

    /* default block downgraded (consumes the 1 token) */
    m = mk(SPLINT_OP_WRITE, 0, 1, NULL, 0, &cl_good);
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW);
    CHECK(v.reason == SPLINT_R_DEFAULT);
    CHECK(v.would_block && v.log);
    CHECK_EQ_U(v.err, 0);
    /* rate limit downgraded */
    m = mk(SPLINT_OP_OPEN, 0, 0, NULL, 0, &cl_good);
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW && v.reason == SPLINT_R_RATE);
    CHECK(v.would_block && v.log);
    /* real allow stays a plain allow */
    m.now_ns += 2 * NS;
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW && v.reason == SPLINT_R_ALLOW);
    CHECK(!v.would_block && !v.log);

    splint_engine_stats_t st;
    splint_engine_stats(e, &st);
    CHECK_EQ_U(st.decided, 4);
    CHECK_EQ_U(st.blocked, 1);
    CHECK_EQ_U(st.allowed, 3);
    CHECK_EQ_U(st.would_block, 2);
    CHECK_EQ_U(st.rate_limited, 1);
    CHECK_EQ_U(st.logged, 2);
    splint_engine_free(e);
}

static void test_stats(void)
{
    splint_engine_t *e = splint_engine_new();
    splint_ruleset_t *rs = rs_new();
    add_patch(rs, "B", PATH, SPLINT_OP_WRITE, SPLINT_ACT_BLOCK | SPLINT_ACT_LOG);
    add_patch(rs, "L", PATH, SPLINT_OP_READ, SPLINT_ACT_LOG);
    splint_engine_set_rules(e, rs);
    splint_msg_t m;
    for (int i = 0; i < 3; i++) {
        m = mk(SPLINT_OP_WRITE, 0, 1, NULL, 0, &cl_good);
        run(e, &m);
    }
    for (int i = 0; i < 2; i++) {
        m = mk(SPLINT_OP_READ, 0, 1, NULL, 0, &cl_good);
        run(e, &m);
    }
    m = mk(SPLINT_OP_OPEN, 0, 1, NULL, 0, &cl_good);
    run(e, &m);
    splint_engine_stats_t st;
    splint_engine_stats(e, &st);
    CHECK_EQ_U(st.decided, 6);
    CHECK_EQ_U(st.blocked, 3);
    CHECK_EQ_U(st.allowed, 3);
    CHECK_EQ_U(st.logged, 5);
    CHECK_EQ_U(st.rate_limited, 0);
    CHECK_EQ_U(st.would_block, 0);
    CHECK_STR(splint_reason_name(SPLINT_R_NONE), "none");
    CHECK_STR(splint_reason_name(SPLINT_R_PATCH), "patch");
    CHECK_STR(splint_reason_name(SPLINT_R_ALLOW), "allow");
    CHECK_STR(splint_reason_name(SPLINT_R_DEFAULT), "default");
    CHECK_STR(splint_reason_name(SPLINT_R_RATE), "rate");
    CHECK_STR(splint_reason_name((splint_reason_t)99), "?");
    splint_engine_free(e);
}

/* ------------------------------------------------------- concurrency */

#define MT_THREADS 4
#define MT_SWAPS   1000

static atomic_int mt_stop;
static atomic_ullong mt_bad;

/* Ruleset k: one block patch whose id is "R<k&1>" and a profile whose
 * default depends on k. Verdicts must always be self-consistent. */
static splint_ruleset_t *mt_rules(unsigned k)
{
    splint_ruleset_t *rs = rs_new();
    for (int i = 0; i < 8; i++) {
        splint_patch_t *p = add_patch(rs, (k & 1) ? "ODD" : "EVEN", PATH,
                                      SPLINT_OP_DEVCTL, SPLINT_ACT_BLOCK);
        p->has_code = true;
        p->code = 0x0500u + (uint32_t)i;
        add_cond(p, SPLINT_OPD_U32, 0, SPLINT_CMP_EQ, SPLINT_OPD_CONST, 0xDEADBEEF);
    }
    splint_profile_t *pf = add_profile(rs, PATH, (k & 1) != 0);
    add_rate(pf, 1000000, NULL);
    add_allow(pf, SPLINT_OP_OPEN);
    return rs;
}

static void *mt_worker(void *arg)
{
    static const uint8_t evil[4] = { 0xEF, 0xBE, 0xAD, 0xDE };
    splint_engine_t *e = arg;
    splint_client_t cl = { 7, 0, 0, "w" };
    uint64_t t = 0;
    while (!atomic_load_explicit(&mt_stop, memory_order_relaxed)) {
        splint_msg_t m = mk(SPLINT_OP_DEVCTL, 0x0507, 4, evil, 4, &cl);
        m.now_ns = t += 1000;
        splint_verdict_t v;
        splint_engine_decide(e, &m, &v);
        /* with a ruleset installed the exploit is always blocked */
        if (v.action == SPLINT_BLOCK) {
            if (v.reason != SPLINT_R_PATCH || !v.rule_id ||
                (strcmp(v.rule_id, "ODD") != 0 && strcmp(v.rule_id, "EVEN") != 0))
                atomic_fetch_add(&mt_bad, 1);
        } else if (v.reason != SPLINT_R_NONE) {
            atomic_fetch_add(&mt_bad, 1);
        }
        m = mk(SPLINT_OP_WRITE, 0, 1, NULL, 0, &cl);
        m.now_ns = t;
        splint_engine_decide(e, &m, &v);
        if (v.reason != SPLINT_R_DEFAULT && v.reason != SPLINT_R_NONE &&
            v.reason != SPLINT_R_RATE)
            atomic_fetch_add(&mt_bad, 1);
    }
    return NULL;
}

static void test_hot_swap_mt(void)
{
    splint_engine_t *e = splint_engine_new();
    pthread_t th[MT_THREADS];
    splint_engine_set_rules(e, mt_rules(0));
    atomic_store(&mt_stop, 0);
    atomic_store(&mt_bad, 0);
    for (int i = 0; i < MT_THREADS; i++)
        CHECK(pthread_create(&th[i], NULL, mt_worker, e) == 0);
    for (unsigned k = 1; k <= MT_SWAPS; k++)
        splint_engine_set_rules(e, (k % 97 == 0) ? NULL : mt_rules(k));
    atomic_store(&mt_stop, 1);
    for (int i = 0; i < MT_THREADS; i++)
        pthread_join(th[i], NULL);
    CHECK_EQ_U(atomic_load(&mt_bad), 0);
    splint_engine_stats_t st;
    splint_engine_stats(e, &st);
    CHECK(st.decided > 0);
    CHECK_EQ_U(st.decided, st.allowed + st.blocked);
    printf("hot swap: %d swaps, %llu decisions\n", MT_SWAPS,
           (unsigned long long)st.decided);
    splint_engine_free(e);
}

/* maxlen on an allow line must bound the operation's data size. A read has no
 * inbound payload (len == 0) and its size lives in declared; a write/devctl is
 * bounded by the inbound payload (len). Regression for the report that
 * `allow read maxlen 512` passed a 64 KiB request because it checked len. */
static void test_read_maxlen(void)
{
    splint_engine_t *e = splint_engine_new();
    splint_ruleset_t *rs = rs_new();
    splint_profile_t *pf = add_profile(rs, PATH, true);  /* default block */
    splint_allow_t *a;

    a = add_allow(pf, SPLINT_OP_READ);
    a->has_maxlen = true; a->maxlen = 512;
    a = add_allow(pf, SPLINT_OP_WRITE);
    a->has_maxlen = true; a->maxlen = 512;
    splint_engine_set_rules(e, rs);

    splint_msg_t m;
    splint_verdict_t v;

    /* read shape from io_read: declared = requested bytes, len = 0 */
    memset(&m, 0, sizeof m);
    m.op = SPLINT_OP_READ; m.path = PATH; m.client = &cl_good; m.now_ns = NS;
    m.declared = 512; m.len = 0;
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW);           /* exactly at the limit */

    m.declared = 513; m.len = 0;
    v = run(e, &m);
    CHECK(v.action == SPLINT_BLOCK);           /* one over */

    m.declared = 65536; m.len = 0;             /* the reported case */
    v = run(e, &m);
    CHECK(v.action == SPLINT_BLOCK && v.reason == SPLINT_R_DEFAULT);

    /* write shape: maxlen bounds the real inbound payload (len) */
    memset(&m, 0, sizeof m);
    m.op = SPLINT_OP_WRITE; m.path = PATH; m.client = &cl_good; m.now_ns = NS;
    m.declared = 0; m.len = 1000;
    v = run(e, &m);
    CHECK(v.action == SPLINT_BLOCK);

    m.declared = 999999; m.len = 10;           /* lying claim, small payload */
    v = run(e, &m);
    CHECK(v.action == SPLINT_ALLOW);           /* bounded by the real 10 bytes */

    splint_engine_free(e);
}

int main(void)
{
    test_null_ruleset();
    test_operands_and_cmps();
    test_patch_matching();
    test_log_only_patch();
    test_profile();
    test_read_maxlen();
    test_rate();
    test_learn_mode();
    test_stats();
    test_hot_swap_mt();
    TEST_MAIN_END();
}
