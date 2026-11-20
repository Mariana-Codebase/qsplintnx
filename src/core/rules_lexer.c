/* SPDX-License-Identifier: Apache-2.0 */
/*
 * QSplintNX - tokenizer for the rule language.
 * Contract: src/core/rules_lexer.h. Lexical structure: docs/RULES.md.
 *
 * Error tokens are sticky: on error the lexer does not advance past the
 * offending token, so every following call reproduces the same ERROR
 * token (same position, same message). Every loop is bounded by the
 * input length and nothing reads past src[len-1].
 */
#include "rules_lexer.h"

#include <stdio.h>
#include <string.h>

#define LEX_IDENT_MAX   63u    /* SPLINT_ID_MAX - 1        */
#define LEX_STRING_MAX  63u    /* SPLINT_NAME_MAX - 1      */
#define LEX_PATH_MAX    127u   /* SPLINT_PATH_MAX - 1      */

static int is_alpha(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static int is_digit(unsigned char c)
{
    return c >= '0' && c <= '9';
}

static int is_ident_start(unsigned char c)
{
    return is_alpha(c) || c == '_';
}

static int is_ident_cont(unsigned char c)
{
    return is_alpha(c) || is_digit(c) || c == '_' || c == '.' || c == ':' || c == '-';
}

static int is_path_char(unsigned char c)
{
    return is_alpha(c) || is_digit(c) || c == '_' || c == '.' || c == '/' || c == '-';
}

static int hex_val(unsigned char c)
{
    if (is_digit(c))
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

void splint_lexer_init(splint_lexer_t *lx, const char *src, size_t len)
{
    lx->src = src;
    lx->len = src ? len : 0;
    lx->pos = 0;
    lx->line = 1;
    lx->col = 1;
}

static unsigned char peek_at(const splint_lexer_t *lx, size_t off)
{
    /* Caller guarantees pos + off < len. */
    return (unsigned char)lx->src[lx->pos + off];
}

static int has(const splint_lexer_t *lx, size_t off)
{
    return lx->pos < lx->len && lx->len - lx->pos > off;
}

/* Advance one byte, maintaining line/col. */
static void bump(splint_lexer_t *lx)
{
    if (lx->src[lx->pos] == '\n') {
        lx->line++;
        lx->col = 1;
    } else {
        lx->col++;
    }
    lx->pos++;
}

static void set_simple(splint_tok_t *t, splint_tok_kind_t k)
{
    t->kind = k;
}

/* Error: rewind the lexer to the token start so the error is sticky. */
static void lex_error(splint_lexer_t *lx, splint_tok_t *t, size_t pos,
                      uint32_t line, uint32_t col, const char *msg)
{
    lx->pos = pos;
    lx->line = line;
    lx->col = col;
    t->kind = SPLINT_TOK_ERROR;
    t->line = line;
    t->col = col;
    t->ival = 0;
    snprintf(t->text, sizeof t->text, "%s", msg);
}

static void skip_blank(splint_lexer_t *lx)
{
    while (lx->pos < lx->len) {
        unsigned char c = peek_at(lx, 0);
        if (c == ' ' || c == '\t' || c == '\r') {
            bump(lx);
        } else if (c == '#') {
            while (lx->pos < lx->len && peek_at(lx, 0) != '\n')
                bump(lx);
        } else {
            break;
        }
    }
}

static void lex_ident(splint_lexer_t *lx, splint_tok_t *t,
                      size_t start, uint32_t line, uint32_t col)
{
    size_t n = 0;
    while (lx->pos < lx->len && is_ident_cont(peek_at(lx, 0))) {
        if (n < LEX_IDENT_MAX)
            t->text[n] = (char)peek_at(lx, 0);
        n++;
        bump(lx);
    }
    if (n > LEX_IDENT_MAX) {
        lex_error(lx, t, start, line, col, "identifier too long (max 63 chars)");
        return;
    }
    t->text[n] = '\0';
    t->kind = SPLINT_TOK_IDENT;
}

static void lex_int(splint_lexer_t *lx, splint_tok_t *t,
                    size_t start, uint32_t line, uint32_t col)
{
    uint64_t v = 0;
    int overflow = 0;
    size_t ndig = 0;

    if (peek_at(lx, 0) == '0' && has(lx, 1) &&
        (peek_at(lx, 1) == 'x' || peek_at(lx, 1) == 'X')) {
        bump(lx);
        bump(lx);
        while (lx->pos < lx->len && hex_val(peek_at(lx, 0)) >= 0) {
            unsigned d = (unsigned)hex_val(peek_at(lx, 0));
            if (v > (UINT64_MAX >> 4))
                overflow = 1;
            v = (v << 4) | d;
            ndig++;
            bump(lx);
        }
        if (ndig == 0) {
            lex_error(lx, t, start, line, col, "hex integer without digits");
            return;
        }
    } else {
        while (lx->pos < lx->len && is_digit(peek_at(lx, 0))) {
            unsigned d = (unsigned)(peek_at(lx, 0) - '0');
            if (v > (UINT64_MAX - d) / 10u)
                overflow = 1;
            v = v * 10u + d;
            ndig++;
            bump(lx);
        }
    }
    /* A number glued to identifier characters (e.g. 64k, 0x1g) is invalid. */
    if (lx->pos < lx->len) {
        unsigned char c = peek_at(lx, 0);
        if (is_alpha(c) || is_digit(c) || c == '_') {
            lex_error(lx, t, start, line, col, "invalid character in integer");
            return;
        }
    }
    if (overflow) {
        lex_error(lx, t, start, line, col, "integer does not fit in 64 bits");
        return;
    }
    t->kind = SPLINT_TOK_INT;
    t->ival = v;
    snprintf(t->text, sizeof t->text, "%llu", (unsigned long long)v);
}

static void lex_string(splint_lexer_t *lx, splint_tok_t *t,
                       size_t start, uint32_t line, uint32_t col)
{
    size_t n = 0;
    bump(lx); /* opening quote */
    for (;;) {
        unsigned char c;
        if (lx->pos >= lx->len) {
            lex_error(lx, t, start, line, col, "unterminated string");
            return;
        }
        c = peek_at(lx, 0);
        if (c == '"') {
            bump(lx);
            break;
        }
        if (c == '\n') {
            lex_error(lx, t, start, line, col, "unterminated string");
            return;
        }
        if (c == '\\') {
            if (!has(lx, 1) || (peek_at(lx, 1) != '"' && peek_at(lx, 1) != '\\')) {
                lex_error(lx, t, start, line, col,
                          "invalid escape in string (only \\\" and \\\\)");
                return;
            }
            bump(lx);
            c = peek_at(lx, 0);
        } else if (c < 0x20 || c == 0x7f) {
            lex_error(lx, t, start, line, col, "control character in string");
            return;
        }
        if (n < LEX_STRING_MAX)
            t->text[n] = (char)c;
        n++;
        bump(lx);
    }
    if (n > LEX_STRING_MAX) {
        lex_error(lx, t, start, line, col, "string too long (max 63 chars)");
        return;
    }
    t->text[n] = '\0';
    t->kind = SPLINT_TOK_STRING;
}

static void lex_path(splint_lexer_t *lx, splint_tok_t *t,
                     size_t start, uint32_t line, uint32_t col)
{
    size_t n = 0;
    while (lx->pos < lx->len && is_path_char(peek_at(lx, 0))) {
        if (n < LEX_PATH_MAX)
            t->text[n] = (char)peek_at(lx, 0);
        n++;
        bump(lx);
    }
    if (n > LEX_PATH_MAX) {
        lex_error(lx, t, start, line, col, "path too long (max 127 chars)");
        return;
    }
    t->text[n] = '\0';
    t->kind = SPLINT_TOK_PATH;
}

void splint_lexer_next(splint_lexer_t *lx, splint_tok_t *out)
{
    size_t start;
    uint32_t line, col;
    unsigned char c;

    memset(out, 0, sizeof *out);
    skip_blank(lx);

    out->line = lx->line;
    out->col = lx->col;
    if (lx->pos >= lx->len) {
        out->kind = SPLINT_TOK_EOF;
        return;
    }

    start = lx->pos;
    line = lx->line;
    col = lx->col;
    c = peek_at(lx, 0);

    if (c >= 0x80) {
        lex_error(lx, out, start, line, col, "non-ASCII byte outside string");
        return;
    }
    if (is_ident_start(c)) {
        lex_ident(lx, out, start, line, col);
        return;
    }
    if (is_digit(c)) {
        lex_int(lx, out, start, line, col);
        return;
    }
    if (c == '"') {
        lex_string(lx, out, start, line, col);
        return;
    }
    if (c == '/') {
        lex_path(lx, out, start, line, col);
        return;
    }

    switch (c) {
    case '\n': case ';': set_simple(out, SPLINT_TOK_NEWLINE); bump(lx); return;
    case '{': set_simple(out, SPLINT_TOK_LBRACE);   bump(lx); return;
    case '}': set_simple(out, SPLINT_TOK_RBRACE);   bump(lx); return;
    case '[': set_simple(out, SPLINT_TOK_LBRACKET); bump(lx); return;
    case ']': set_simple(out, SPLINT_TOK_RBRACKET); bump(lx); return;
    case ',': set_simple(out, SPLINT_TOK_COMMA);    bump(lx); return;
    case '.':
        if (has(lx, 1) && peek_at(lx, 1) == '.') {
            set_simple(out, SPLINT_TOK_RANGE);
            bump(lx);
            bump(lx);
            return;
        }
        break;
    case '=':
        if (has(lx, 1) && peek_at(lx, 1) == '=') {
            set_simple(out, SPLINT_TOK_EQ);
            bump(lx);
            bump(lx);
            return;
        }
        break;
    case '!':
        if (has(lx, 1) && peek_at(lx, 1) == '=') {
            set_simple(out, SPLINT_TOK_NE);
            bump(lx);
            bump(lx);
            return;
        }
        break;
    case '<':
        bump(lx);
        if (lx->pos < lx->len && peek_at(lx, 0) == '=') {
            bump(lx);
            set_simple(out, SPLINT_TOK_LE);
        } else {
            set_simple(out, SPLINT_TOK_LT);
        }
        return;
    case '>':
        bump(lx);
        if (lx->pos < lx->len && peek_at(lx, 0) == '=') {
            bump(lx);
            set_simple(out, SPLINT_TOK_GE);
        } else {
            set_simple(out, SPLINT_TOK_GT);
        }
        return;
    default:
        break;
    }
    lex_error(lx, out, start, line, col, "unexpected character");
}
