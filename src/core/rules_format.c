/* SPDX-License-Identifier: Apache-2.0 */
/*
 * QSplintNX - canonical text form of a compiled ruleset.
 *
 * splint_rules_parse(splint_rules_format(rs)) yields a ruleset with the
 * same fields as rs (only the `line` fields may differ). Output layout:
 * optional `mode learn`, then patches in order, then profiles in order.
 * Return value follows snprintf: the full length, excluding NUL, even
 * when buf is NULL or cap is too small.
 */
#include "splint/rules.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct out {
    char  *buf;
    size_t cap;
    size_t n;      /* bytes that would have been written */
} out_t;

static void put(out_t *o, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void put(out_t *o, const char *fmt, ...)
{
    va_list ap;
    char *dst = NULL;
    size_t room = 0;
    int r;

    if (o->buf && o->n < o->cap) {
        dst = o->buf + o->n;
        room = o->cap - o->n;
    }
    va_start(ap, fmt);
    r = vsnprintf(dst, room, fmt, ap);
    va_end(ap);
    if (r > 0)
        o->n += (size_t)r;
}

static void put_quoted(out_t *o, const char *s, size_t max)
{
    size_t i;
    put(o, "\"");
    for (i = 0; i < max && s[i] != '\0'; i++) {
        if (s[i] == '"' || s[i] == '\\')
            put(o, "\\%c", s[i]);
        else
            put(o, "%c", s[i]);
    }
    put(o, "\"");
}

static void put_code(out_t *o, uint32_t code)
{
    if (code > 0xFFFFu)
        put(o, "0x%x", (unsigned)code);
    else
        put(o, "0x%04x", (unsigned)code);
}

static void put_operand(out_t *o, const splint_operand_t *v)
{
    switch (v->kind) {
    case SPLINT_OPD_CONST:    put(o, "%llu", (unsigned long long)v->value); break;
    case SPLINT_OPD_LEN:      put(o, "len"); break;
    case SPLINT_OPD_DECLARED: put(o, "declared"); break;
    case SPLINT_OPD_BYTE:     put(o, "byte[%llu]", (unsigned long long)v->value); break;
    case SPLINT_OPD_U16:      put(o, "u16[%llu]", (unsigned long long)v->value); break;
    case SPLINT_OPD_U32:      put(o, "u32[%llu]", (unsigned long long)v->value); break;
    default:                  put(o, "?"); break;
    }
}

static const char *cmp_str(splint_cmp_t c)
{
    switch (c) {
    case SPLINT_CMP_EQ: return "==";
    case SPLINT_CMP_NE: return "!=";
    case SPLINT_CMP_LT: return "<";
    case SPLINT_CMP_LE: return "<=";
    case SPLINT_CMP_GT: return ">";
    case SPLINT_CMP_GE: return ">=";
    default:            return "?";
    }
}

static const char *errno_name(int e)
{
    if (e == EPERM)   return "EPERM";
    if (e == EACCES)  return "EACCES";
    if (e == EINVAL)  return "EINVAL";
    if (e == ENOTSUP) return "ENOTSUP";
    if (e == EIO)     return "EIO";
    return NULL;
}

static void put_patch(out_t *o, const splint_patch_t *pt)
{
    uint32_t i, ncond = pt->ncond < SPLINT_MAX_CONDS ? pt->ncond : SPLINT_MAX_CONDS;
    const char *en;

    put(o, "patch %.*s {\n", (int)(SPLINT_ID_MAX - 1), pt->id);
    put(o, "  path   %.*s\n", (int)(SPLINT_PATH_MAX - 1), pt->path);
    put(o, "  match  %s", splint_op_name(pt->op));
    if (pt->has_code) {
        put(o, " ");
        put_code(o, pt->code);
    }
    put(o, "\n");
    for (i = 0; i < ncond; i++) {
        const splint_cond_t *c = &pt->cond[i];
        put(o, "  when   ");
        put_operand(o, &c->lhs);
        put(o, " %s ", cmp_str(c->cmp));
        put_operand(o, &c->rhs);
        put(o, "\n");
    }
    put(o, "  action ");
    if ((pt->actions & SPLINT_ACT_BLOCK) && (pt->actions & SPLINT_ACT_LOG))
        put(o, "block, log\n");
    else if (pt->actions & SPLINT_ACT_LOG)
        put(o, "log\n");
    else
        put(o, "block\n");
    en = errno_name(pt->err);
    if (en && pt->err != EPERM)
        put(o, "  errno  %s\n", en);
    put(o, "}\n");
}

static void put_profile(out_t *o, const splint_profile_t *pf)
{
    uint32_t i;
    uint32_t nallow = pf->nallow < SPLINT_MAX_ALLOW ? pf->nallow : SPLINT_MAX_ALLOW;
    uint32_t nrate = pf->nrate < SPLINT_MAX_RATES ? pf->nrate : SPLINT_MAX_RATES;

    put(o, "profile %.*s {\n", (int)(SPLINT_PATH_MAX - 1), pf->path);
    put(o, "  default %s\n", pf->default_block ? "block" : "allow");
    for (i = 0; i < nallow; i++) {
        const splint_allow_t *a = &pf->allow[i];
        put(o, "  allow %s", splint_op_name(a->op));
        if (a->has_code) {
            put(o, " ");
            put_code(o, a->code_lo);
            if (a->code_hi != a->code_lo) {
                put(o, "..");
                put_code(o, a->code_hi);
            }
        }
        if (a->has_client) {
            put(o, " client ");
            put_quoted(o, a->client, SPLINT_NAME_MAX - 1);
        }
        if (a->has_maxlen)
            put(o, " maxlen %llu", (unsigned long long)a->maxlen);
        put(o, "\n");
    }
    for (i = 0; i < nrate; i++) {
        const splint_rate_t *r = &pf->rate[i];
        put(o, "  rate %u per s", (unsigned)r->per_sec);
        if (r->has_client) {
            put(o, " client ");
            put_quoted(o, r->client, SPLINT_NAME_MAX - 1);
        }
        put(o, "\n");
    }
    put(o, "}\n");
}

size_t splint_rules_format(const splint_ruleset_t *rs, char *buf, size_t cap)
{
    out_t o;
    uint32_t i, npatch, nprofile;

    o.buf = buf;
    o.cap = buf ? cap : 0;
    o.n = 0;
    if (o.cap > 0)
        o.buf[0] = '\0';
    if (!rs)
        return 0;

    npatch = rs->npatch < SPLINT_MAX_RULES ? rs->npatch : SPLINT_MAX_RULES;
    nprofile = rs->nprofile < SPLINT_MAX_PROFILES ? rs->nprofile : SPLINT_MAX_PROFILES;

    if (rs->version != 0)
        put(&o, "version %llu\n", (unsigned long long)rs->version);
    if (rs->mode == SPLINT_MODE_LEARN)
        put(&o, "mode learn\n");
    for (i = 0; i < npatch; i++) {
        if (o.n > 0)
            put(&o, "\n");
        put_patch(&o, &rs->patch[i]);
    }
    for (i = 0; i < nprofile; i++) {
        if (o.n > 0)
            put(&o, "\n");
        put_profile(&o, &rs->profile[i]);
    }
    return o.n;
}
