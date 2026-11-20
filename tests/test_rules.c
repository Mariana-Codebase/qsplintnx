/* SPDX-License-Identifier: Apache-2.0 */
/* Unit tests for the rule parser/compiler and the canonical formatter
 * (src/core/rules_parser.c, src/core/rules_format.c). */
#include "splint/rules.h"
#include "test_util.h"

#include <errno.h>
#include <stdarg.h>

/* ---------------------------------------------------------- helpers --- */

/* Parse from an exact-size heap copy (no NUL) so ASan catches over-reads. */
static int parse_n(const char *src, size_t len, splint_ruleset_t **rs,
                   splint_parse_error_t *err)
{
    char *copy = malloc(len ? len : 1);
    int r;
    if (!copy)
        return -2;
    if (len)
        memcpy(copy, src, len);
    r = splint_rules_parse(copy, len, rs, err);
    free(copy);
    return r;
}

static splint_ruleset_t *parse_ok(const char *src, int lineno)
{
    splint_ruleset_t *rs = (splint_ruleset_t *)1;
    splint_parse_error_t err;
    int r = parse_n(src, strlen(src), &rs, &err);
    t_checks++;
    if (r != 0 || !rs) {
        t_failures++;
        fprintf(stderr, "%s:%d: parse failed at %u:%u: %s\n", __FILE__, lineno,
                (unsigned)err.line, (unsigned)err.col, err.msg);
        return NULL;
    }
    return rs;
}
#define PARSE_OK(src) parse_ok((src), __LINE__)

static void expect_err(const char *src, size_t len, uint32_t line, uint32_t col,
                       const char *substr, int lineno)
{
    splint_ruleset_t *rs = (splint_ruleset_t *)1;
    splint_parse_error_t err;
    int r = parse_n(src, len, &rs, &err);
    t_checks++;
    if (r != -1 || rs != NULL || err.line != line || err.col != col ||
        (substr && !strstr(err.msg, substr))) {
        t_failures++;
        fprintf(stderr, "%s:%d: expected error %u:%u '%s', got r=%d %u:%u '%s'\n",
                __FILE__, lineno, (unsigned)line, (unsigned)col, substr ? substr : "",
                r, (unsigned)err.line, (unsigned)err.col, err.msg);
        if (r == 0)
            splint_rules_free(rs);
    }
}
#define EXPECT_ERR(src, line, col, sub) expect_err((src), strlen(src), (line), (col), (sub), __LINE__)

/* Growable text builder for limit tests. */
typedef struct sb {
    char  *p;
    size_t n, cap;
} sb_t;

static void sb_add(sb_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sb_add(sb_t *b, const char *fmt, ...)
{
    va_list ap;
    int need;
    va_start(ap, fmt);
    need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0)
        return;
    if (b->n + (size_t)need + 1 > b->cap) {
        size_t nc = (b->cap ? b->cap * 2 : 4096) + (size_t)need;
        char *np = realloc(b->p, nc);
        if (!np)
            abort();
        b->p = np;
        b->cap = nc;
    }
    va_start(ap, fmt);
    vsnprintf(b->p + b->n, b->cap - b->n, fmt, ap);
    va_end(ap);
    b->n += (size_t)need;
}

/* Field-by-field comparison, ignoring `line`. */
static int operand_eq(const splint_operand_t *a, const splint_operand_t *b)
{
    return a->kind == b->kind && a->value == b->value;
}

static int ruleset_eq(const splint_ruleset_t *a, const splint_ruleset_t *b)
{
    uint32_t i, j;
    if (a->mode != b->mode || a->npatch != b->npatch || a->nprofile != b->nprofile)
        return 0;
    for (i = 0; i < a->npatch; i++) {
        const splint_patch_t *x = &a->patch[i], *y = &b->patch[i];
        if (strcmp(x->id, y->id) || strcmp(x->path, y->path) || x->op != y->op ||
            x->has_code != y->has_code || x->code != y->code || x->ncond != y->ncond ||
            x->actions != y->actions || x->err != y->err)
            return 0;
        for (j = 0; j < x->ncond; j++) {
            if (!operand_eq(&x->cond[j].lhs, &y->cond[j].lhs) ||
                x->cond[j].cmp != y->cond[j].cmp ||
                !operand_eq(&x->cond[j].rhs, &y->cond[j].rhs))
                return 0;
        }
    }
    for (i = 0; i < a->nprofile; i++) {
        const splint_profile_t *x = &a->profile[i], *y = &b->profile[i];
        if (strcmp(x->path, y->path) || x->default_block != y->default_block ||
            x->nallow != y->nallow || x->nrate != y->nrate)
            return 0;
        for (j = 0; j < x->nallow; j++) {
            const splint_allow_t *p = &x->allow[j], *q = &y->allow[j];
            if (p->op != q->op || p->has_code != q->has_code || p->code_lo != q->code_lo ||
                p->code_hi != q->code_hi || p->has_client != q->has_client ||
                strcmp(p->client, q->client) || p->has_maxlen != q->has_maxlen ||
                p->maxlen != q->maxlen)
                return 0;
        }
        for (j = 0; j < x->nrate; j++) {
            const splint_rate_t *p = &x->rate[j], *q = &y->rate[j];
            if (p->per_sec != q->per_sec || p->has_client != q->has_client ||
                strcmp(p->client, q->client))
                return 0;
        }
    }
    return 1;
}

/* parse -> format -> parse, compare; also checks format is a fixed point. */
static void roundtrip(const char *src, int lineno)
{
    splint_ruleset_t *a = parse_ok(src, lineno), *b = NULL;
    splint_parse_error_t err;
    size_t n, n2;
    char *buf, *buf2;
    if (!a)
        return;
    n = splint_rules_format(a, NULL, 0);
    buf = malloc(n + 1);
    buf2 = malloc(n + 1);
    if (!buf || !buf2)
        abort();
    CHECK_EQ_U(splint_rules_format(a, buf, n + 1), n);
    CHECK_EQ_U(strlen(buf), n);
    t_checks++;
    if (splint_rules_parse(buf, n, &b, &err) != 0) {
        t_failures++;
        fprintf(stderr, "%s:%d: reparse failed %u:%u %s\n---\n%s---\n", __FILE__, lineno,
                (unsigned)err.line, (unsigned)err.col, err.msg, buf);
    } else {
        t_checks++;
        if (!ruleset_eq(a, b)) {
            t_failures++;
            fprintf(stderr, "%s:%d: round-trip mismatch\n%s", __FILE__, lineno, buf);
        }
        n2 = splint_rules_format(b, buf2, n + 1);
        CHECK_EQ_U(n2, n);
        CHECK(memcmp(buf, buf2, n) == 0);
        splint_rules_free(b);
    }
    free(buf);
    free(buf2);
    splint_rules_free(a);
}
#define ROUNDTRIP(src) roundtrip((src), __LINE__)

/* -------------------------------------------------- valid documents --- */

/* Verbatim from docs/RULES.md "patch blocks". */
static const char RULES_MD_PATCH[] =
"patch CVE-2026-0042 {\n"
"  path    /dev/vendor_can            # required, exact match\n"
"  match   devctl 0x0105              # required: <op> [<code>]\n"
"  when    len > 64                   # optional, may repeat; ANDed\n"
"  when    declared != len\n"
"  action  block, log                 # required\n"
"  errno   EPERM                      # optional, default EPERM\n"
"}\n";

/* Verbatim from docs/RULES.md "profile blocks". */
static const char RULES_MD_PROFILE[] =
"profile /dev/vendor_can {\n"
"  default block                       # or: default allow (default: allow)\n"
"  allow open\n"
"  allow devctl 0x0101 maxlen 16\n"
"  allow devctl 0x0102..0x0104 client \"can_client\" maxlen 64\n"
"  allow read  maxlen 512\n"
"  rate 200 per s client \"can_client\"  # token bucket, burst = rate\n"
"  rate 50 per s                       # applies to clients without a\n"
"                                      # more specific rate line\n"
"}\n";

/* Demo patch from demo/include/vendor_can_api.h. */
static const char DEMO_PATCH[] =
"patch CVE-DEMO-0042 {\n"
"  path   /dev/vendor_can\n"
"  match  devctl 0x0505\n"
"  when   len > 64\n"
"  action block, log\n"
"}\n";

static void test_rules_md_patch(void)
{
    splint_ruleset_t *rs = PARSE_OK(RULES_MD_PATCH);
    const splint_patch_t *p;
    if (!rs)
        return;
    CHECK_EQ_U(rs->mode, SPLINT_MODE_ENFORCE);
    CHECK_EQ_U(rs->npatch, 1);
    CHECK_EQ_U(rs->nprofile, 0);
    p = &rs->patch[0];
    CHECK_STR(p->id, "CVE-2026-0042");
    CHECK_STR(p->path, "/dev/vendor_can");
    CHECK_EQ_U(p->op, SPLINT_OP_DEVCTL);
    CHECK(p->has_code);
    CHECK_EQ_U(p->code, 0x0105);
    CHECK_EQ_U(p->ncond, 2);
    CHECK_EQ_U(p->cond[0].lhs.kind, SPLINT_OPD_LEN);
    CHECK_EQ_U(p->cond[0].cmp, SPLINT_CMP_GT);
    CHECK_EQ_U(p->cond[0].rhs.kind, SPLINT_OPD_CONST);
    CHECK_EQ_U(p->cond[0].rhs.value, 64);
    CHECK_EQ_U(p->cond[1].lhs.kind, SPLINT_OPD_DECLARED);
    CHECK_EQ_U(p->cond[1].cmp, SPLINT_CMP_NE);
    CHECK_EQ_U(p->cond[1].rhs.kind, SPLINT_OPD_LEN);
    CHECK_EQ_U(p->actions, SPLINT_ACT_BLOCK | SPLINT_ACT_LOG);
    CHECK_EQ_U(p->err, EPERM);
    CHECK_EQ_U(p->line, 1);
    splint_rules_free(rs);
}

static void test_rules_md_profile(void)
{
    splint_ruleset_t *rs = PARSE_OK(RULES_MD_PROFILE);
    const splint_profile_t *f;
    if (!rs)
        return;
    CHECK_EQ_U(rs->npatch, 0);
    CHECK_EQ_U(rs->nprofile, 1);
    f = &rs->profile[0];
    CHECK_STR(f->path, "/dev/vendor_can");
    CHECK(f->default_block);
    CHECK_EQ_U(f->nallow, 4);
    CHECK_EQ_U(f->allow[0].op, SPLINT_OP_OPEN);
    CHECK(!f->allow[0].has_code);
    CHECK(!f->allow[0].has_client);
    CHECK(!f->allow[0].has_maxlen);
    CHECK_EQ_U(f->allow[0].line, 3);
    CHECK_EQ_U(f->allow[1].op, SPLINT_OP_DEVCTL);
    CHECK(f->allow[1].has_code);
    CHECK_EQ_U(f->allow[1].code_lo, 0x0101);
    CHECK_EQ_U(f->allow[1].code_hi, 0x0101);
    CHECK(f->allow[1].has_maxlen);
    CHECK_EQ_U(f->allow[1].maxlen, 16);
    CHECK_EQ_U(f->allow[2].code_lo, 0x0102);
    CHECK_EQ_U(f->allow[2].code_hi, 0x0104);
    CHECK(f->allow[2].has_client);
    CHECK_STR(f->allow[2].client, "can_client");
    CHECK_EQ_U(f->allow[2].maxlen, 64);
    CHECK_EQ_U(f->allow[3].op, SPLINT_OP_READ);
    CHECK_EQ_U(f->allow[3].maxlen, 512);
    CHECK_EQ_U(f->nrate, 2);
    CHECK_EQ_U(f->rate[0].per_sec, 200);
    CHECK(f->rate[0].has_client);
    CHECK_STR(f->rate[0].client, "can_client");
    CHECK_EQ_U(f->rate[1].per_sec, 50);
    CHECK(!f->rate[1].has_client);
    CHECK_EQ_U(f->rate[1].line, 8);
    splint_rules_free(rs);
}

static void test_demo_patch(void)
{
    splint_ruleset_t *rs = PARSE_OK(DEMO_PATCH);
    if (!rs)
        return;
    CHECK_EQ_U(rs->npatch, 1);
    CHECK_STR(rs->patch[0].id, "CVE-DEMO-0042");
    CHECK_STR(rs->patch[0].path, "/dev/vendor_can");
    CHECK_EQ_U(rs->patch[0].op, SPLINT_OP_DEVCTL);
    CHECK_EQ_U(rs->patch[0].code, 0x0505);
    CHECK_EQ_U(rs->patch[0].ncond, 1);
    CHECK_EQ_U(rs->patch[0].cond[0].rhs.value, 64);
    CHECK_EQ_U(rs->patch[0].actions, SPLINT_ACT_BLOCK | SPLINT_ACT_LOG);
    CHECK_EQ_U(rs->patch[0].err, EPERM);
    splint_rules_free(rs);
}

static void test_misc_valid(void)
{
    splint_ruleset_t *rs;

    /* empty file / comments only: empty enforce ruleset */
    rs = PARSE_OK("");
    if (rs) {
        CHECK_EQ_U(rs->mode, SPLINT_MODE_ENFORCE);
        CHECK_EQ_U(rs->npatch + rs->nprofile, 0);
        splint_rules_free(rs);
    }
    rs = PARSE_OK("# nothing\n\n;;\n");
    if (rs)
        splint_rules_free(rs);

    /* mode anywhere, ';' separators, '}' right after a statement, one-liners */
    rs = PARSE_OK("patch A { path /a; match open; action log }\n"
                  "mode learn\n"
                  "profile /a { allow any }"
                  "patch B { path /b; match any; action block; errno EIO }");
    if (rs) {
        CHECK_EQ_U(rs->mode, SPLINT_MODE_LEARN);
        CHECK_EQ_U(rs->npatch, 2);
        CHECK_EQ_U(rs->patch[0].actions, SPLINT_ACT_LOG);
        CHECK(!rs->patch[0].has_code);
        CHECK_EQ_U(rs->patch[1].op, SPLINT_OP_ANY);
        CHECK_EQ_U(rs->patch[1].err, EIO);
        CHECK_EQ_U(rs->patch[1].line, 3);
        CHECK_EQ_U(rs->nprofile, 1);
        CHECK(!rs->profile[0].default_block);   /* default allow */
        CHECK_EQ_U(rs->profile[0].allow[0].op, SPLINT_OP_ANY);
        splint_rules_free(rs);
    }

    /* all ops, all errnos, all operand forms, all comparators */
    rs = PARSE_OK(
        "mode enforce\n"
        "patch P1 { path /x\n match read\n action block\n errno EACCES\n }\n"
        "patch P2 { path /x\n match write\n action block\n errno EINVAL\n }\n"
        "patch P3 { path /x\n match lseek\n action block\n errno ENOTSUP\n }\n"
        "patch P4 { path /x\n match close\n action block\n errno EPERM\n }\n"
        "patch P5 { path /x\n match other\n action log, block\n }\n"
        "patch P6 {\n path /x\n match devctl\n"
        "  when byte[0] == 1\n when u16[254] != 0xffff\n when u32[252] < declared\n"
        "  when len <= 0\n when declared >= len\n when byte[255] > 18446744073709551615\n"
        "  action block\n}\n");
    if (rs) {
        const splint_patch_t *p = &rs->patch[5];
        CHECK_EQ_U(rs->npatch, 6);
        CHECK_EQ_U(rs->patch[0].op, SPLINT_OP_READ);
        CHECK_EQ_U(rs->patch[0].err, EACCES);
        CHECK_EQ_U(rs->patch[1].op, SPLINT_OP_WRITE);
        CHECK_EQ_U(rs->patch[1].err, EINVAL);
        CHECK_EQ_U(rs->patch[2].op, SPLINT_OP_LSEEK);
        CHECK_EQ_U(rs->patch[2].err, ENOTSUP);
        CHECK_EQ_U(rs->patch[3].op, SPLINT_OP_CLOSE);
        CHECK_EQ_U(rs->patch[4].op, SPLINT_OP_OTHER);
        CHECK_EQ_U(rs->patch[4].actions, SPLINT_ACT_BLOCK | SPLINT_ACT_LOG);
        CHECK(!p->has_code);
        CHECK_EQ_U(p->ncond, 6);
        CHECK_EQ_U(p->cond[0].lhs.kind, SPLINT_OPD_BYTE);
        CHECK_EQ_U(p->cond[0].cmp, SPLINT_CMP_EQ);
        CHECK_EQ_U(p->cond[1].lhs.kind, SPLINT_OPD_U16);
        CHECK_EQ_U(p->cond[1].lhs.value, 254);
        CHECK_EQ_U(p->cond[1].rhs.value, 0xffff);
        CHECK_EQ_U(p->cond[2].lhs.kind, SPLINT_OPD_U32);
        CHECK_EQ_U(p->cond[2].lhs.value, 252);
        CHECK_EQ_U(p->cond[2].cmp, SPLINT_CMP_LT);
        CHECK_EQ_U(p->cond[2].rhs.kind, SPLINT_OPD_DECLARED);
        CHECK_EQ_U(p->cond[3].cmp, SPLINT_CMP_LE);
        CHECK_EQ_U(p->cond[4].cmp, SPLINT_CMP_GE);
        CHECK_EQ_U(p->cond[5].cmp, SPLINT_CMP_GT);
        CHECK(p->cond[5].rhs.value == UINT64_MAX);
        splint_rules_free(rs);
    }

    /* 32-bit full dcmd codes and range equal bounds */
    rs = PARSE_OK("patch F { path /f; match devctl 0xC0100505; action block }\n"
                  "profile /f { allow devctl 0xffffffff..0xffffffff; allow devctl 5..5 }\n");
    if (rs) {
        CHECK_EQ_U(rs->patch[0].code, 0xC0100505u);
        CHECK_EQ_U(rs->profile[0].allow[0].code_lo, 0xffffffffu);
        CHECK_EQ_U(rs->profile[0].allow[1].code_hi, 5);
        splint_rules_free(rs);
    }

    /* CRLF line endings */
    rs = PARSE_OK("patch W {\r\n  path /w\r\n  match open\r\n  action block\r\n}\r\n");
    if (rs)
        splint_rules_free(rs);

    /* not NUL-terminated: parse only a prefix of a buffer */
    {
        const char *s = "patch N { path /n; match open; action block }GARBAGE@@@";
        splint_ruleset_t *r2 = NULL;
        splint_parse_error_t e;
        CHECK_EQ_U(parse_n(s, strlen("patch N { path /n; match open; action block }"), &r2, &e), 0);
        splint_rules_free(r2);
    }

    /* splint_rules_free(NULL) is a no-op; NULL err is accepted */
    splint_rules_free(NULL);
    {
        splint_ruleset_t *r3 = (splint_ruleset_t *)1;
        CHECK((splint_rules_parse("bogus", 5, &r3, NULL)) == -1);
        CHECK(r3 == NULL);
        CHECK_EQ_U(splint_rules_parse(NULL, 0, &r3, NULL), 0);
        splint_rules_free(r3);
    }
}

/* ------------------------------------------------------------ errors --- */

static void test_errors(void)
{
    /* lexer errors propagate with their own message and position */
    EXPECT_ERR("patch X {\n  path /a\n  match devctl 0x\n", 3, 16, "hex");
    EXPECT_ERR("patch \xc3\xa9", 1, 7, "non-ASCII");
    EXPECT_ERR("profile /p { allow open client \"abc\n", 1, 32, "unterminated");

    /* top level */
    EXPECT_ERR("bogus", 1, 1, "expected 'patch'");
    EXPECT_ERR("\n\n  42", 3, 3, "expected 'patch'");
    EXPECT_ERR("mode fast", 1, 6, "enforce");
    EXPECT_ERR("mode learn extra", 1, 12, "end of statement");
    EXPECT_ERR("mode learn\nmode enforce\n", 2, 1, "duplicate 'mode'");
    EXPECT_ERR("patch { }", 1, 7, "identifier");
    EXPECT_ERR("patch \"X\" { }", 1, 7, "identifier");
    EXPECT_ERR("patch X path /a", 1, 9, "'{'");
    EXPECT_ERR("patch X {\n path /a\n match open\n action block\n", 5, 1, "end of file");
    EXPECT_ERR("profile dev { }", 1, 9, "path");
    EXPECT_ERR("profile /a path", 1, 12, "'{'");
    EXPECT_ERR("profile /a {\n allow open\n", 3, 1, "end of file");
    EXPECT_ERR("}", 1, 1, "expected 'patch'");

    /* required / exactly-one in patches (reported at 'patch') */
    EXPECT_ERR("\npatch X {\n match open\n action block\n}\n", 2, 1, "missing 'path'");
    EXPECT_ERR("patch X {\n path /a\n action block\n}\n", 1, 1, "missing 'match'");
    EXPECT_ERR("patch X {\n path /a\n match open\n}\n", 1, 1, "missing 'action'");
    EXPECT_ERR("patch X {\n path /a\n path /b\n match open\n action block\n}", 3, 2, "duplicate 'path'");
    EXPECT_ERR("patch X {\n path /a\n match open\n match read\n action block\n}", 4, 2, "duplicate 'match'");
    EXPECT_ERR("patch X {\n path /a\n match open\n action block\n action log\n}", 5, 2, "duplicate 'action'");
    EXPECT_ERR("patch X {\n path /a\n match open\n action block\n errno EIO\n errno EIO\n}", 6, 2, "duplicate 'errno'");

    /* bad statement contents */
    EXPECT_ERR("patch X {\n path a\n}", 2, 7, "path");
    EXPECT_ERR("patch X {\n path \"/a\"\n}", 2, 7, "path");
    EXPECT_ERR("patch X {\n frobnicate\n}", 2, 2, "unknown statement");
    EXPECT_ERR("patch X {\n path /a /b\n}", 2, 10, "end of statement");
    EXPECT_ERR("patch X {\n match ioctl\n}", 2, 8, "expected operation");
    EXPECT_ERR("patch X {\n match open 0x0105\n}", 2, 13, "only allowed with devctl");
    EXPECT_ERR("patch X {\n match any 1\n}", 2, 12, "only allowed with devctl");
    EXPECT_ERR("patch X {\n match devctl 0x100000000\n}", 2, 15, "32 bits");
    EXPECT_ERR("patch X {\n match devctl 1 2\n}", 2, 17, "end of statement");
    EXPECT_ERR("patch X {\n action\n}", 2, 8, "'block' or 'log'");
    EXPECT_ERR("patch X {\n action drop\n}", 2, 9, "'block' or 'log'");
    EXPECT_ERR("patch X {\n action block, block\n}", 2, 16, "duplicate action");
    EXPECT_ERR("patch X {\n action block,\n}", 2, 15, "'block' or 'log'");
    EXPECT_ERR("patch X {\n action block log\n}", 2, 15, "end of statement");
    EXPECT_ERR("patch X {\n action block, log, block\n}", 2, 19, "end of statement");
    EXPECT_ERR("patch X {\n errno ENOENT\n}", 2, 8, "EPERM");
    EXPECT_ERR("patch X {\n errno eperm\n}", 2, 8, "EPERM");

    /* conditions */
    EXPECT_ERR("patch X {\n when 64 < len\n}", 2, 7, "constant");
    EXPECT_ERR("patch X {\n when foo > 1\n}", 2, 7, "expected len");
    EXPECT_ERR("patch X {\n when len 64\n}", 2, 11, "comparison");
    EXPECT_ERR("patch X {\n when len = 64\n}", 2, 11, "unexpected character");
    EXPECT_ERR("patch X {\n when len > byte[0]\n}", 2, 13, "right side");
    EXPECT_ERR("patch X {\n when len > u32[0]\n}", 2, 13, "right side");
    EXPECT_ERR("patch X {\n when len > \"x\"\n}", 2, 13, "right side");
    EXPECT_ERR("patch X {\n when len >\n}", 2, 12, "right side");
    EXPECT_ERR("patch X {\n when byte 0 > 1\n}", 2, 12, "'['");
    EXPECT_ERR("patch X {\n when byte[] > 1\n}", 2, 12, "offset");
    EXPECT_ERR("patch X {\n when byte[1 > 1\n}", 2, 14, "']'");
    EXPECT_ERR("patch X {\n when byte[256] > 1\n}", 2, 12, "out of range");
    EXPECT_ERR("patch X {\n when u16[255] > 1\n}", 2, 11, "out of range");
    EXPECT_ERR("patch X {\n when u32[253] > 1\n}", 2, 11, "out of range");
    EXPECT_ERR("patch X {\n when u32[18446744073709551615] > 1\n}", 2, 11, "out of range");
    EXPECT_ERR("patch X {\n when len > 1 extra\n}", 2, 15, "end of statement");

    /* profiles */
    EXPECT_ERR("profile /a { }\nprofile /a { }\n", 2, 9, "duplicate profile");
    EXPECT_ERR("profile /a {\n default deny\n}", 2, 10, "'allow' or 'block'");
    EXPECT_ERR("profile /a {\n default block\n default allow\n}", 3, 2, "duplicate 'default'");
    EXPECT_ERR("profile /a {\n path /a\n}", 2, 2, "unknown statement");
    EXPECT_ERR("profile /a {\n allow\n}", 2, 7, "expected operation");
    EXPECT_ERR("profile /a {\n allow read 0x0101\n}", 2, 13, "only allowed with devctl");
    EXPECT_ERR("profile /a {\n allow devctl 0x0104..0x0102\n}", 2, 15, "lower bound");
    EXPECT_ERR("profile /a {\n allow devctl 1..\n}", 2, 18, "devctl code");
    EXPECT_ERR("profile /a {\n allow devctl 1..0x100000000\n}", 2, 18, "32 bits");
    EXPECT_ERR("profile /a {\n allow devctl client can\n}", 2, 22, "quoted");
    EXPECT_ERR("profile /a {\n allow devctl client \"\"\n}", 2, 22, "empty");
    EXPECT_ERR("profile /a {\n allow devctl maxlen\n}", 2, 21, "maxlen");
    EXPECT_ERR("profile /a {\n allow devctl maxlen 1 client \"x\"\n}", 2, 24, "end of statement");
    EXPECT_ERR("profile /a {\n allow open junk\n}", 2, 13, "end of statement");
    EXPECT_ERR("profile /a {\n rate 0 per s\n}", 2, 7, "greater than 0");
    EXPECT_ERR("profile /a {\n rate 4294967296 per s\n}", 2, 7, "32 bits");
    EXPECT_ERR("profile /a {\n rate per s\n}", 2, 7, "per second");
    EXPECT_ERR("profile /a {\n rate 5 s\n}", 2, 9, "'per'");
    EXPECT_ERR("profile /a {\n rate 5 per ms\n}", 2, 13, "'s'");
    EXPECT_ERR("profile /a {\n rate 5 per s client\n}", 2, 21, "quoted");
    EXPECT_ERR("profile /a {\n rate 5 per s\n rate 6 per s\n}", 3, 2, "duplicate default");
    EXPECT_ERR("profile /a {\n rate 5 per s client \"c\"\n rate 6 per s client \"c\"\n}", 3, 2, "duplicate 'rate'");

    /* empty/missing arguments */
    {
        splint_ruleset_t *rs = (splint_ruleset_t *)1;
        splint_parse_error_t e;
        CHECK((splint_rules_parse(NULL, 3, &rs, &e)) == -1);
        CHECK(rs == NULL);
        CHECK((splint_rules_parse("", 0, NULL, &e)) == -1);
    }
}

/* ------------------------------------------------------------ limits --- */

static void test_limits(void)
{
    sb_t b = { 0 };
    splint_ruleset_t *rs;
    uint32_t i;

    /* patches: 256 ok, 257 error at line of the 257th 'patch' */
    for (i = 0; i < SPLINT_MAX_RULES; i++)
        sb_add(&b, "patch P%u { path /p; match open; action block }\n", (unsigned)i);
    rs = PARSE_OK(b.p);
    if (rs) {
        CHECK_EQ_U(rs->npatch, SPLINT_MAX_RULES);
        splint_rules_free(rs);
    }
    sb_add(&b, "patch Pmax { path /p; match open; action block }\n");
    EXPECT_ERR(b.p, SPLINT_MAX_RULES + 1, 1, "too many patches");

    /* conditions: 8 ok, 9 error */
    b.n = 0;
    sb_add(&b, "patch C {\n path /c\n match any\n action block\n");
    for (i = 0; i < SPLINT_MAX_CONDS; i++)
        sb_add(&b, " when byte[%u] == %u\n", (unsigned)i, (unsigned)i);
    sb_add(&b, "}\n");
    rs = PARSE_OK(b.p);
    if (rs) {
        CHECK_EQ_U(rs->patch[0].ncond, SPLINT_MAX_CONDS);
        CHECK_EQ_U(rs->patch[0].cond[7].lhs.value, 7);
        splint_rules_free(rs);
    }
    b.n -= 2; /* drop "}\n" */
    sb_add(&b, " when len > 0\n}\n");
    EXPECT_ERR(b.p, 4 + SPLINT_MAX_CONDS + 1, 2, "too many 'when'");

    /* profiles: 32 ok, 33 error */
    b.n = 0;
    for (i = 0; i < SPLINT_MAX_PROFILES; i++)
        sb_add(&b, "profile /p%u { default block }\n", (unsigned)i);
    rs = PARSE_OK(b.p);
    if (rs) {
        CHECK_EQ_U(rs->nprofile, SPLINT_MAX_PROFILES);
        CHECK(rs->profile[31].default_block);
        splint_rules_free(rs);
    }
    sb_add(&b, "profile /extra { }\n");
    EXPECT_ERR(b.p, SPLINT_MAX_PROFILES + 1, 1, "too many profiles");

    /* allow lines: 64 ok, 65 error */
    b.n = 0;
    sb_add(&b, "profile /a {\n");
    for (i = 0; i < SPLINT_MAX_ALLOW; i++)
        sb_add(&b, " allow devctl %u\n", (unsigned)i);
    sb_add(&b, "}\n");
    rs = PARSE_OK(b.p);
    if (rs) {
        CHECK_EQ_U(rs->profile[0].nallow, SPLINT_MAX_ALLOW);
        splint_rules_free(rs);
    }
    b.n -= 2;
    sb_add(&b, " allow open\n}\n");
    EXPECT_ERR(b.p, 1 + SPLINT_MAX_ALLOW + 1, 2, "too many 'allow'");

    /* rate lines: 16 ok, 17 error */
    b.n = 0;
    sb_add(&b, "profile /r {\n");
    for (i = 0; i < SPLINT_MAX_RATES; i++)
        sb_add(&b, " rate %u per s client \"c%u\"\n", (unsigned)i + 1, (unsigned)i);
    sb_add(&b, "}\n");
    rs = PARSE_OK(b.p);
    if (rs) {
        CHECK_EQ_U(rs->profile[0].nrate, SPLINT_MAX_RATES);
        splint_rules_free(rs);
    }
    b.n -= 2;
    sb_add(&b, " rate 1 per s\n}\n");
    EXPECT_ERR(b.p, 1 + SPLINT_MAX_RATES + 1, 2, "too many 'rate'");

    /* identifier / path / client name at max and max+1 */
    b.n = 0;
    sb_add(&b, "patch %.*s { path /%.*s; match open; action block }\n"
               "profile /q { allow open client \"%.*s\" }\n",
           63, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
           126, "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp"
                "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp",
           63, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    rs = PARSE_OK(b.p);
    if (rs) {
        CHECK_EQ_U(strlen(rs->patch[0].id), SPLINT_ID_MAX - 1);
        CHECK_EQ_U(strlen(rs->patch[0].path), SPLINT_PATH_MAX - 1);
        CHECK_EQ_U(strlen(rs->profile[0].allow[0].client), SPLINT_NAME_MAX - 1);
        splint_rules_free(rs);
    }
    b.n = 0;
    sb_add(&b, "patch %.*s { }", 64,
           "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
    EXPECT_ERR(b.p, 1, 7, "too long");
    b.n = 0;
    sb_add(&b, "profile /%.*s { }", 127,
           "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp"
           "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp");
    EXPECT_ERR(b.p, 1, 9, "too long");

    /* file size: exactly 256 KiB of comments/blank ok; +1 byte error */
    free(b.p);
    b.p = malloc(SPLINT_RULES_FILE_MAX + 1);
    if (!b.p)
        abort();
    memset(b.p, '\n', SPLINT_RULES_FILE_MAX + 1);
    memcpy(b.p, "# big\n", 6);
    {
        splint_parse_error_t e;
        rs = NULL;
        CHECK_EQ_U(parse_n(b.p, SPLINT_RULES_FILE_MAX, &rs, &e), 0);
        splint_rules_free(rs);
        rs = (splint_ruleset_t *)1;
        CHECK((parse_n(b.p, SPLINT_RULES_FILE_MAX + 1, &rs, &e)) == -1);
        CHECK(rs == NULL);
        CHECK(strstr(e.msg, "too large") != NULL);
        CHECK_EQ_U(e.line, 0);
        CHECK_EQ_U(e.col, 0);
    }
    free(b.p);
}

/* -------------------------------------------------------- round trip --- */

static void test_roundtrip(void)
{
    sb_t b = { 0 };
    uint32_t i;

    ROUNDTRIP(RULES_MD_PATCH);
    ROUNDTRIP(RULES_MD_PROFILE);
    ROUNDTRIP(DEMO_PATCH);
    ROUNDTRIP("");
    ROUNDTRIP("mode learn\n");
    ROUNDTRIP("mode enforce\n" "patch A { path /a; match open; action log; errno EIO }\n");
    ROUNDTRIP("mode learn\n"
              "patch Z { path /z; match devctl 0xC0100505; action block; errno ENOTSUP\n"
              " when u32[252] >= 4294967296; when byte[0] != declared; when declared < len }\n"
              "patch Y { path /y; match any; action log, block; errno EACCES }\n"
              "profile /z { default block; allow devctl 0x10000..0x2ffff client \"we\\\"ird\\\\\" maxlen 0\n"
              " allow write maxlen 18446744073709551615; rate 1 per s; rate 4294967295 per s client \"x\" }\n"
              "profile /w { allow other client \"caf\xc3\xa9\" }\n");

    /* a maximal ruleset */
    for (i = 0; i < SPLINT_MAX_RULES; i++)
        sb_add(&b, "patch P%u { path /dev/p%u; match devctl %u; when u16[%u] > %u; action block }\n",
               (unsigned)i, (unsigned)(i % 7), (unsigned)i * 977u, (unsigned)(i % 254),
               (unsigned)i);
    for (i = 0; i < SPLINT_MAX_PROFILES; i++) {
        uint32_t j;
        sb_add(&b, "profile /dev/p%u {\n default %s\n", (unsigned)i, (i & 1) ? "block" : "allow");
        for (j = 0; j < SPLINT_MAX_ALLOW; j++)
            sb_add(&b, " allow devctl %u..%u client \"c%u\" maxlen %u\n",
                   (unsigned)j, (unsigned)j * 3u, (unsigned)j, (unsigned)j * 8u);
        for (j = 0; j < SPLINT_MAX_RATES; j++)
            sb_add(&b, " rate %u per s client \"r%u\"\n", (unsigned)j + 1u, (unsigned)j);
        sb_add(&b, "}\n");
    }
    t_checks++;
    if (b.n > SPLINT_RULES_FILE_MAX) {
        t_failures++;
        fprintf(stderr, "maximal ruleset text too large (%zu)\n", b.n);
    } else {
        ROUNDTRIP(b.p);
    }
    free(b.p);
}

static void test_format(void)
{
    splint_ruleset_t *rs = PARSE_OK(DEMO_PATCH);
    char small[16];
    size_t n;
    if (!rs)
        return;
    n = splint_rules_format(rs, NULL, 0);
    CHECK(n > 0);
    CHECK_EQ_U(splint_rules_format(rs, small, 0), n);
    CHECK_EQ_U(splint_rules_format(rs, NULL, 100), n);
    memset(small, 'Z', sizeof small);
    CHECK_EQ_U(splint_rules_format(rs, small, sizeof small), n);
    CHECK_EQ_U(strlen(small), sizeof small - 1);       /* truncated, NUL-terminated */
    CHECK(strncmp(small, "patch CVE-DEMO-", 15) == 0);
    {
        char *full = malloc(n + 1);
        if (!full)
            abort();
        CHECK_EQ_U(splint_rules_format(rs, full, n + 1), n);
        CHECK_STR(full,
                  "patch CVE-DEMO-0042 {\n"
                  "  path   /dev/vendor_can\n"
                  "  match  devctl 0x0505\n"
                  "  when   len > 64\n"
                  "  action block, log\n"
                  "}\n");
        free(full);
    }
    splint_rules_free(rs);

    /* mode learn only when learn; enforce produces no mode line */
    rs = PARSE_OK("mode learn\nprofile /a { allow devctl 0x12345 }\n");
    if (rs) {
        char buf[256];
        splint_rules_format(rs, buf, sizeof buf);
        CHECK_STR(buf, "mode learn\n\nprofile /a {\n  default allow\n  allow devctl 0x12345\n}\n");
        splint_rules_free(rs);
    }
    rs = PARSE_OK("mode enforce\n");
    if (rs) {
        char buf[8];
        CHECK_EQ_U(splint_rules_format(rs, buf, sizeof buf), 0);
        CHECK_STR(buf, "");
        splint_rules_free(rs);
    }
    CHECK_EQ_U(splint_rules_format(NULL, NULL, 0), 0);
}

int main(void)
{
    test_rules_md_patch();
    test_rules_md_profile();
    test_demo_patch();
    test_misc_valid();
    test_errors();
    test_limits();
    test_roundtrip();
    test_format();
    TEST_MAIN_END();
}
