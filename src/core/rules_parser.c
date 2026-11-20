/* SPDX-License-Identifier: Apache-2.0 */
/*
 * QSplintNX - recursive-descent parser and compiler for the rule language.
 * Grammar and semantics: docs/RULES.md (normative). Output: splint_ruleset_t.
 *
 * All-or-nothing: the first error stops parsing, is reported with 1-based
 * line/column, and no ruleset is returned. Every limit in RULES.md is a
 * parse error, never a silent truncation.
 */
#include "splint/rules.h"
#include "rules_lexer.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct parser {
    splint_lexer_t        lx;
    splint_tok_t          tok;      /* current (lookahead) token */
    splint_ruleset_t     *rs;
    splint_parse_error_t *err;
    int                   failed;
} parser_t;

static void advance(parser_t *p)
{
    splint_lexer_next(&p->lx, &p->tok);
}

static void fail_at(parser_t *p, uint32_t line, uint32_t col, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static void fail_at(parser_t *p, uint32_t line, uint32_t col, const char *fmt, ...)
{
    va_list ap;
    if (p->failed)
        return;
    p->failed = 1;
    if (!p->err)
        return;
    p->err->line = line;
    p->err->col = col;
    va_start(ap, fmt);
    vsnprintf(p->err->msg, sizeof p->err->msg, fmt, ap);
    va_end(ap);
}

/* Error at the current token. A lexer error token reports its own message. */
static int fail_tok(parser_t *p, const char *what)
{
    if (p->tok.kind == SPLINT_TOK_ERROR)
        fail_at(p, p->tok.line, p->tok.col, "%s", p->tok.text);
    else
        fail_at(p, p->tok.line, p->tok.col, "%s", what);
    return -1;
}

static int is_kw(const parser_t *p, const char *kw)
{
    return p->tok.kind == SPLINT_TOK_IDENT && strcmp(p->tok.text, kw) == 0;
}

static int at_stmt_end(const parser_t *p)
{
    return p->tok.kind == SPLINT_TOK_NEWLINE || p->tok.kind == SPLINT_TOK_RBRACE ||
           p->tok.kind == SPLINT_TOK_EOF;
}

/* A statement inside a block ends at NEWLINE/';' or right before '}'. */
static int end_stmt(parser_t *p)
{
    if (p->tok.kind == SPLINT_TOK_NEWLINE) {
        advance(p);
        return 0;
    }
    if (p->tok.kind == SPLINT_TOK_RBRACE)
        return 0;
    return fail_tok(p, "expected end of statement");
}

static void skip_newlines(parser_t *p)
{
    /* Bounded: each iteration consumes one byte of input. */
    while (p->tok.kind == SPLINT_TOK_NEWLINE)
        advance(p);
}

static int parse_op(parser_t *p, splint_op_t *op)
{
    static const char *const names[] = {
        "open", "read", "write", "devctl", "lseek", "close", "other"
    };
    size_t i;
    if (p->tok.kind == SPLINT_TOK_IDENT) {
        for (i = 0; i < sizeof names / sizeof names[0]; i++) {
            if (strcmp(p->tok.text, names[i]) == 0) {
                *op = (splint_op_t)i;
                advance(p);
                return 0;
            }
        }
        if (strcmp(p->tok.text, "any") == 0) {
            *op = SPLINT_OP_ANY;
            advance(p);
            return 0;
        }
    }
    return fail_tok(p, "expected operation (open read write devctl lseek close other any)");
}

static int parse_code32(parser_t *p, uint32_t *out)
{
    if (p->tok.kind != SPLINT_TOK_INT)
        return fail_tok(p, "expected devctl code");
    if (p->tok.ival > UINT32_MAX)
        return fail_tok(p, "devctl code does not fit in 32 bits");
    *out = (uint32_t)p->tok.ival;
    advance(p);
    return 0;
}

/* ------------------------------------------------------------ patch --- */

static int parse_operand(parser_t *p, splint_operand_t *o, int is_lhs)
{
    if (p->tok.kind == SPLINT_TOK_INT) {
        if (is_lhs)
            return fail_tok(p, "left side of condition cannot be a constant");
        o->kind = SPLINT_OPD_CONST;
        o->value = p->tok.ival;
        advance(p);
        return 0;
    }
    if (is_kw(p, "len") || is_kw(p, "declared")) {
        o->kind = is_kw(p, "len") ? SPLINT_OPD_LEN : SPLINT_OPD_DECLARED;
        o->value = 0;
        advance(p);
        return 0;
    }
    if (is_kw(p, "byte") || is_kw(p, "u16") || is_kw(p, "u32")) {
        uint64_t width;
        if (!is_lhs)
            return fail_tok(p, "right side of condition must be an integer, len or declared");
        if (is_kw(p, "byte")) {
            o->kind = SPLINT_OPD_BYTE;
            width = 1;
        } else if (is_kw(p, "u16")) {
            o->kind = SPLINT_OPD_U16;
            width = 2;
        } else {
            o->kind = SPLINT_OPD_U32;
            width = 4;
        }
        advance(p);
        if (p->tok.kind != SPLINT_TOK_LBRACKET)
            return fail_tok(p, "expected '['");
        advance(p);
        if (p->tok.kind != SPLINT_TOK_INT)
            return fail_tok(p, "expected payload offset");
        if (p->tok.ival >= SPLINT_INSPECT_MAX ||
            p->tok.ival + width > SPLINT_INSPECT_MAX) {
            fail_at(p, p->tok.line, p->tok.col,
                    "payload offset out of range (offset + width must be <= %u)",
                    (unsigned)SPLINT_INSPECT_MAX);
            return -1;
        }
        o->value = p->tok.ival;
        advance(p);
        if (p->tok.kind != SPLINT_TOK_RBRACKET)
            return fail_tok(p, "expected ']'");
        advance(p);
        return 0;
    }
    if (is_lhs)
        return fail_tok(p, "expected len, declared, byte[n], u16[n] or u32[n]");
    return fail_tok(p, "right side of condition must be an integer, len or declared");
}

static int parse_cmp(parser_t *p, splint_cmp_t *c)
{
    switch (p->tok.kind) {
    case SPLINT_TOK_EQ: *c = SPLINT_CMP_EQ; break;
    case SPLINT_TOK_NE: *c = SPLINT_CMP_NE; break;
    case SPLINT_TOK_LT: *c = SPLINT_CMP_LT; break;
    case SPLINT_TOK_LE: *c = SPLINT_CMP_LE; break;
    case SPLINT_TOK_GT: *c = SPLINT_CMP_GT; break;
    case SPLINT_TOK_GE: *c = SPLINT_CMP_GE; break;
    default:
        return fail_tok(p, "expected comparison operator (== != < <= > >=)");
    }
    advance(p);
    return 0;
}

static int parse_errno_name(parser_t *p, int *e)
{
    static const struct { const char *name; int val; } tab[] = {
        { "EPERM", EPERM }, { "EACCES", EACCES }, { "EINVAL", EINVAL },
        { "ENOTSUP", ENOTSUP }, { "EIO", EIO }
    };
    size_t i;
    if (p->tok.kind == SPLINT_TOK_IDENT) {
        for (i = 0; i < sizeof tab / sizeof tab[0]; i++) {
            if (strcmp(p->tok.text, tab[i].name) == 0) {
                *e = tab[i].val;
                advance(p);
                return 0;
            }
        }
    }
    return fail_tok(p, "expected errno (EPERM EACCES EINVAL ENOTSUP EIO)");
}

static int parse_patch(parser_t *p)
{
    splint_patch_t *pt;
    uint32_t pline = p->tok.line, pcol = p->tok.col;
    int have_path = 0, have_match = 0, have_action = 0, have_errno = 0;

    if (p->rs->npatch >= SPLINT_MAX_RULES) {
        fail_at(p, pline, pcol, "too many patches (max %u)", (unsigned)SPLINT_MAX_RULES);
        return -1;
    }
    pt = &p->rs->patch[p->rs->npatch];
    memset(pt, 0, sizeof *pt);
    pt->line = pline;
    pt->err = EPERM;

    advance(p); /* 'patch' */
    if (p->tok.kind != SPLINT_TOK_IDENT)
        return fail_tok(p, "expected patch identifier");
    memcpy(pt->id, p->tok.text, strlen(p->tok.text) + 1); /* lexer caps at 63 */
    advance(p);
    if (p->tok.kind != SPLINT_TOK_LBRACE)
        return fail_tok(p, "expected '{'");
    advance(p);

    for (;;) {
        uint32_t sline, scol;
        skip_newlines(p);
        if (p->tok.kind == SPLINT_TOK_RBRACE)
            break;
        if (p->tok.kind == SPLINT_TOK_EOF)
            return fail_tok(p, "unexpected end of file, expected '}'");
        sline = p->tok.line;
        scol = p->tok.col;

        if (is_kw(p, "path")) {
            if (have_path) {
                fail_at(p, sline, scol, "duplicate 'path' in patch");
                return -1;
            }
            advance(p);
            if (p->tok.kind != SPLINT_TOK_PATH)
                return fail_tok(p, "expected path starting with '/'");
            memcpy(pt->path, p->tok.text, strlen(p->tok.text) + 1); /* <= 127 */
            advance(p);
            have_path = 1;
        } else if (is_kw(p, "match")) {
            if (have_match) {
                fail_at(p, sline, scol, "duplicate 'match' in patch");
                return -1;
            }
            advance(p);
            if (parse_op(p, &pt->op))
                return -1;
            if (p->tok.kind == SPLINT_TOK_INT) {
                if (pt->op != SPLINT_OP_DEVCTL)
                    return fail_tok(p, "code is only allowed with devctl");
                if (parse_code32(p, &pt->code))
                    return -1;
                pt->has_code = true;
            }
            have_match = 1;
        } else if (is_kw(p, "when")) {
            splint_cond_t *c;
            if (pt->ncond >= SPLINT_MAX_CONDS) {
                fail_at(p, sline, scol, "too many 'when' conditions (max %u)",
                        (unsigned)SPLINT_MAX_CONDS);
                return -1;
            }
            c = &pt->cond[pt->ncond];
            advance(p);
            if (parse_operand(p, &c->lhs, 1) || parse_cmp(p, &c->cmp) ||
                parse_operand(p, &c->rhs, 0))
                return -1;
            pt->ncond++;
        } else if (is_kw(p, "action")) {
            unsigned n = 0;
            if (have_action) {
                fail_at(p, sline, scol, "duplicate 'action' in patch");
                return -1;
            }
            advance(p);
            /* At most two items (block, log); bounded by the check below. */
            for (;;) {
                uint32_t bit;
                if (is_kw(p, "block"))
                    bit = SPLINT_ACT_BLOCK;
                else if (is_kw(p, "log"))
                    bit = SPLINT_ACT_LOG;
                else
                    return fail_tok(p, "expected action 'block' or 'log'");
                if (pt->actions & bit)
                    return fail_tok(p, "duplicate action");
                pt->actions |= bit;
                advance(p);
                n++;
                if (p->tok.kind != SPLINT_TOK_COMMA || n >= 2)
                    break;
                advance(p);
            }
            have_action = 1;
        } else if (is_kw(p, "errno")) {
            if (have_errno) {
                fail_at(p, sline, scol, "duplicate 'errno' in patch");
                return -1;
            }
            advance(p);
            if (parse_errno_name(p, &pt->err))
                return -1;
            have_errno = 1;
        } else {
            return fail_tok(p, "unknown statement in patch (expected path, match, when, action, errno)");
        }
        if (end_stmt(p))
            return -1;
    }

    if (!have_path) {
        fail_at(p, pline, pcol, "patch '%s' is missing 'path'", pt->id);
        return -1;
    }
    if (!have_match) {
        fail_at(p, pline, pcol, "patch '%s' is missing 'match'", pt->id);
        return -1;
    }
    if (!have_action) {
        fail_at(p, pline, pcol, "patch '%s' is missing 'action'", pt->id);
        return -1;
    }
    advance(p); /* '}' */
    p->rs->npatch++;
    return 0;
}

/* ---------------------------------------------------------- profile --- */

static int parse_client(parser_t *p, bool *has, char *dst)
{
    advance(p); /* 'client' */
    if (p->tok.kind != SPLINT_TOK_STRING)
        return fail_tok(p, "expected quoted client name");
    if (p->tok.text[0] == '\0')
        return fail_tok(p, "client name must not be empty");
    memcpy(dst, p->tok.text, strlen(p->tok.text) + 1); /* lexer caps at 63 */
    *has = true;
    advance(p);
    return 0;
}

static int parse_allow(parser_t *p, splint_profile_t *pf, uint32_t sline, uint32_t scol)
{
    splint_allow_t *a;
    if (pf->nallow >= SPLINT_MAX_ALLOW) {
        fail_at(p, sline, scol, "too many 'allow' lines in profile (max %u)",
                (unsigned)SPLINT_MAX_ALLOW);
        return -1;
    }
    a = &pf->allow[pf->nallow];
    memset(a, 0, sizeof *a);
    a->line = sline;
    advance(p); /* 'allow' */
    if (parse_op(p, &a->op))
        return -1;
    if (p->tok.kind == SPLINT_TOK_INT) {
        uint32_t lo_line = p->tok.line, lo_col = p->tok.col;
        if (a->op != SPLINT_OP_DEVCTL)
            return fail_tok(p, "code is only allowed with devctl");
        if (parse_code32(p, &a->code_lo))
            return -1;
        a->code_hi = a->code_lo;
        if (p->tok.kind == SPLINT_TOK_RANGE) {
            advance(p);
            if (parse_code32(p, &a->code_hi))
                return -1;
            if (a->code_lo > a->code_hi) {
                fail_at(p, lo_line, lo_col, "code range lower bound exceeds upper bound");
                return -1;
            }
        }
        a->has_code = true;
    }
    if (is_kw(p, "client")) {
        if (parse_client(p, &a->has_client, a->client))
            return -1;
    }
    if (is_kw(p, "maxlen")) {
        advance(p);
        if (p->tok.kind != SPLINT_TOK_INT)
            return fail_tok(p, "expected integer after maxlen");
        a->maxlen = p->tok.ival;
        a->has_maxlen = true;
        advance(p);
    }
    if (!at_stmt_end(p))
        return fail_tok(p, "expected code, client \"name\", maxlen n or end of statement");
    pf->nallow++;
    return 0;
}

static int parse_rate(parser_t *p, splint_profile_t *pf, uint32_t sline, uint32_t scol)
{
    splint_rate_t *r;
    uint32_t i;
    if (pf->nrate >= SPLINT_MAX_RATES) {
        fail_at(p, sline, scol, "too many 'rate' lines in profile (max %u)",
                (unsigned)SPLINT_MAX_RATES);
        return -1;
    }
    r = &pf->rate[pf->nrate];
    memset(r, 0, sizeof *r);
    r->line = sline;
    advance(p); /* 'rate' */
    if (p->tok.kind != SPLINT_TOK_INT)
        return fail_tok(p, "expected messages per second");
    if (p->tok.ival == 0)
        return fail_tok(p, "rate must be greater than 0");
    if (p->tok.ival > UINT32_MAX)
        return fail_tok(p, "rate does not fit in 32 bits");
    r->per_sec = (uint32_t)p->tok.ival;
    advance(p);
    if (!is_kw(p, "per"))
        return fail_tok(p, "expected 'per'");
    advance(p);
    if (!is_kw(p, "s"))
        return fail_tok(p, "expected 's'");
    advance(p);
    if (is_kw(p, "client")) {
        if (parse_client(p, &r->has_client, r->client))
            return -1;
    }
    for (i = 0; i < pf->nrate; i++) {
        const splint_rate_t *o = &pf->rate[i];
        if (o->has_client == r->has_client &&
            (!r->has_client || strcmp(o->client, r->client) == 0)) {
            fail_at(p, sline, scol, r->has_client ?
                    "duplicate 'rate' for this client" : "duplicate default 'rate'");
            return -1;
        }
    }
    pf->nrate++;
    return 0;
}

static int parse_profile(parser_t *p)
{
    splint_profile_t *pf;
    uint32_t pline = p->tok.line, pcol = p->tok.col;
    int have_default = 0;
    uint32_t i;

    if (p->rs->nprofile >= SPLINT_MAX_PROFILES) {
        fail_at(p, pline, pcol, "too many profiles (max %u)", (unsigned)SPLINT_MAX_PROFILES);
        return -1;
    }
    pf = &p->rs->profile[p->rs->nprofile];
    memset(pf, 0, sizeof *pf);
    pf->line = pline;

    advance(p); /* 'profile' */
    if (p->tok.kind != SPLINT_TOK_PATH)
        return fail_tok(p, "expected profile path starting with '/'");
    for (i = 0; i < p->rs->nprofile; i++) {
        if (strcmp(p->rs->profile[i].path, p->tok.text) == 0)
            return fail_tok(p, "duplicate profile for this path");
    }
    memcpy(pf->path, p->tok.text, strlen(p->tok.text) + 1);
    advance(p);
    if (p->tok.kind != SPLINT_TOK_LBRACE)
        return fail_tok(p, "expected '{'");
    advance(p);

    for (;;) {
        uint32_t sline, scol;
        skip_newlines(p);
        if (p->tok.kind == SPLINT_TOK_RBRACE)
            break;
        if (p->tok.kind == SPLINT_TOK_EOF)
            return fail_tok(p, "unexpected end of file, expected '}'");
        sline = p->tok.line;
        scol = p->tok.col;

        if (is_kw(p, "default")) {
            if (have_default) {
                fail_at(p, sline, scol, "duplicate 'default' in profile");
                return -1;
            }
            advance(p);
            if (is_kw(p, "allow"))
                pf->default_block = false;
            else if (is_kw(p, "block"))
                pf->default_block = true;
            else
                return fail_tok(p, "expected 'allow' or 'block'");
            advance(p);
            have_default = 1;
        } else if (is_kw(p, "allow")) {
            if (parse_allow(p, pf, sline, scol))
                return -1;
        } else if (is_kw(p, "rate")) {
            if (parse_rate(p, pf, sline, scol))
                return -1;
        } else {
            return fail_tok(p, "unknown statement in profile (expected default, allow, rate)");
        }
        if (end_stmt(p))
            return -1;
    }
    advance(p); /* '}' */
    p->rs->nprofile++;
    return 0;
}

/* ------------------------------------------------------------- file --- */

static int parse_file(parser_t *p)
{
    int have_mode = 0;
    advance(p);
    for (;;) {
        skip_newlines(p);
        if (p->tok.kind == SPLINT_TOK_EOF)
            return 0;
        if (is_kw(p, "patch")) {
            if (parse_patch(p))
                return -1;
        } else if (is_kw(p, "profile")) {
            if (parse_profile(p))
                return -1;
        } else if (is_kw(p, "mode")) {
            if (have_mode)
                return fail_tok(p, "duplicate 'mode' statement");
            advance(p);
            if (is_kw(p, "enforce"))
                p->rs->mode = SPLINT_MODE_ENFORCE;
            else if (is_kw(p, "learn"))
                p->rs->mode = SPLINT_MODE_LEARN;
            else
                return fail_tok(p, "expected 'enforce' or 'learn'");
            advance(p);
            if (p->tok.kind != SPLINT_TOK_NEWLINE && p->tok.kind != SPLINT_TOK_EOF)
                return fail_tok(p, "expected end of statement");
            have_mode = 1;
        } else {
            return fail_tok(p, "expected 'patch', 'profile' or 'mode'");
        }
    }
}

int splint_rules_parse(const char *text, size_t len,
                       splint_ruleset_t **out, splint_parse_error_t *err)
{
    parser_t p;

    if (out)
        *out = NULL;
    if (err)
        memset(err, 0, sizeof *err);
    if (!out || (!text && len > 0)) {
        if (err)
            snprintf(err->msg, sizeof err->msg, "invalid arguments");
        return -1;
    }
    if (len > SPLINT_RULES_FILE_MAX) {
        if (err)
            snprintf(err->msg, sizeof err->msg, "rules file too large (max %u bytes)",
                     (unsigned)SPLINT_RULES_FILE_MAX);
        return -1;
    }

    memset(&p, 0, sizeof p);
    p.err = err;
    p.rs = calloc(1, sizeof *p.rs);
    if (!p.rs) {
        if (err)
            snprintf(err->msg, sizeof err->msg, "out of memory");
        return -1;
    }
    p.rs->mode = SPLINT_MODE_ENFORCE;
    splint_lexer_init(&p.lx, text, len);

    if (parse_file(&p) != 0 || p.failed) {
        if (!p.failed && err)
            snprintf(err->msg, sizeof err->msg, "parse error");
        free(p.rs);
        return -1;
    }
    *out = p.rs;
    return 0;
}

void splint_rules_free(splint_ruleset_t *rs)
{
    free(rs);
}
