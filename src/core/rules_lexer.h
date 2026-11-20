/*
 * QSplintNX - internal lexer interface used by rules_parser.c.
 * Not part of the public API. Token rules: docs/RULES.md "Lexical structure".
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPLINT_RULES_LEXER_H
#define SPLINT_RULES_LEXER_H

#include <stddef.h>
#include <stdint.h>

typedef enum splint_tok_kind {
    SPLINT_TOK_EOF = 0,
    SPLINT_TOK_ERROR,      /* lexer error; text holds message            */
    SPLINT_TOK_NEWLINE,    /* statement terminator: '\n' or ';'          */
    SPLINT_TOK_IDENT,      /* identifiers AND keywords (parser compares) */
    SPLINT_TOK_INT,        /* ival valid                                 */
    SPLINT_TOK_STRING,     /* text holds unescaped contents              */
    SPLINT_TOK_PATH,       /* text holds path, starts with '/'           */
    SPLINT_TOK_LBRACE, SPLINT_TOK_RBRACE,
    SPLINT_TOK_LBRACKET, SPLINT_TOK_RBRACKET,
    SPLINT_TOK_COMMA,
    SPLINT_TOK_RANGE,      /* ".."                                       */
    SPLINT_TOK_EQ, SPLINT_TOK_NE, SPLINT_TOK_LT,
    SPLINT_TOK_LE, SPLINT_TOK_GT, SPLINT_TOK_GE
} splint_tok_kind_t;

#define SPLINT_TOK_TEXT_MAX 160u

typedef struct splint_tok {
    splint_tok_kind_t kind;
    uint32_t          line, col;     /* 1-based position of first char */
    uint64_t          ival;
    char              text[SPLINT_TOK_TEXT_MAX];  /* NUL-terminated */
} splint_tok_t;

typedef struct splint_lexer {
    const char *src;
    size_t      len;
    size_t      pos;
    uint32_t    line, col;
} splint_lexer_t;

void splint_lexer_init(splint_lexer_t *lx, const char *src, size_t len);

/* Produce the next token. Comments and non-newline whitespace are
 * skipped. Consecutive newlines/';' produce one NEWLINE token each
 * (parser skips blanks). After EOF or ERROR, keeps returning the same. */
void splint_lexer_next(splint_lexer_t *lx, splint_tok_t *out);

#endif /* SPLINT_RULES_LEXER_H */
