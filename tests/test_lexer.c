/* SPDX-License-Identifier: Apache-2.0 */
/* Unit tests for the rule-language lexer (src/core/rules_lexer.c). */
#include "rules_lexer.h"
#include "test_util.h"

#include <stdint.h>

#define MAXTOK 64

typedef struct lexed {
    int          n;
    splint_tok_t t[MAXTOK];
} lexed_t;

/* Lex `len` bytes (not NUL-terminated: copied into an exact-size heap
 * buffer so ASan catches any over-read) until EOF/ERROR. */
static void lex_n(const char *src, size_t len, lexed_t *out)
{
    char *copy = malloc(len ? len : 1);
    splint_lexer_t lx;
    if (!copy) {
        out->n = 0;
        return;
    }
    if (len)
        memcpy(copy, src, len);
    splint_lexer_init(&lx, copy, len);
    out->n = 0;
    while (out->n < MAXTOK) {
        splint_tok_t *t = &out->t[out->n++];
        splint_lexer_next(&lx, t);
        if (t->kind == SPLINT_TOK_EOF || t->kind == SPLINT_TOK_ERROR)
            break;
    }
    free(copy);
}

static void lex(const char *src, lexed_t *out)
{
    lex_n(src, strlen(src), out);
}

static const splint_tok_t *last(const lexed_t *l)
{
    return &l->t[l->n - 1];
}

static void test_empty(void)
{
    lexed_t l;
    lex("", &l);
    CHECK_EQ_U(l.n, 1);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_EOF);
    CHECK_EQ_U(l.t[0].line, 1);
    CHECK_EQ_U(l.t[0].col, 1);

    lex("   \t  # only a comment", &l);
    CHECK_EQ_U(l.n, 1);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_EOF);

    /* NULL source with zero length is valid */
    {
        splint_lexer_t lx;
        splint_tok_t t;
        splint_lexer_init(&lx, NULL, 0);
        splint_lexer_next(&lx, &t);
        CHECK_EQ_U(t.kind, SPLINT_TOK_EOF);
    }
}

static void test_punct(void)
{
    static const splint_tok_kind_t want[] = {
        SPLINT_TOK_LBRACE, SPLINT_TOK_RBRACE, SPLINT_TOK_LBRACKET, SPLINT_TOK_RBRACKET,
        SPLINT_TOK_COMMA, SPLINT_TOK_RANGE, SPLINT_TOK_EQ, SPLINT_TOK_NE,
        SPLINT_TOK_LT, SPLINT_TOK_LE, SPLINT_TOK_GT, SPLINT_TOK_GE,
        SPLINT_TOK_NEWLINE, SPLINT_TOK_NEWLINE, SPLINT_TOK_EOF
    };
    lexed_t l;
    size_t i;
    lex("{ } [ ] , .. == != < <= > >= ;\n", &l);
    CHECK_EQ_U(l.n, sizeof want / sizeof want[0]);
    for (i = 0; i < sizeof want / sizeof want[0] && i < (size_t)l.n; i++)
        CHECK_EQ_U(l.t[i].kind, want[i]);

    /* no spaces needed */
    lex("<<=>>=", &l);
    CHECK_EQ_U(l.n, 5);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_LT);
    CHECK_EQ_U(l.t[1].kind, SPLINT_TOK_LE);
    CHECK_EQ_U(l.t[2].kind, SPLINT_TOK_GT);
    CHECK_EQ_U(l.t[3].kind, SPLINT_TOK_GE);

    /* operators at end of input (no lookahead byte) */
    lex(">", &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_GT);
    CHECK_EQ_U(l.t[1].kind, SPLINT_TOK_EOF);
    lex("<", &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_LT);
}

static void test_bad_punct(void)
{
    static const char *const bad[] = { ".", "=", "!", "@", "$", "x . y", "a = b", "!x",
                                       "'", "(", ")", "*", "+", "\\", "`", "\x01", "\x7f" };
    lexed_t l;
    size_t i;
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        lex(bad[i], &l);
        CHECK_EQ_U(last(&l)->kind, SPLINT_TOK_ERROR);
        CHECK(last(&l)->text[0] != '\0');
    }
    lex("a = b", &l);
    CHECK_EQ_U(last(&l)->col, 3);
}

static void test_idents(void)
{
    lexed_t l;
    lex("patch CVE-2026-0042 _x a.b:c-d EPERM s", &l);
    CHECK_EQ_U(l.n, 7);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_IDENT);
    CHECK_STR(l.t[0].text, "patch");
    CHECK_STR(l.t[1].text, "CVE-2026-0042");
    CHECK_STR(l.t[2].text, "_x");
    CHECK_STR(l.t[3].text, "a.b:c-d");
    CHECK_STR(l.t[4].text, "EPERM");
    CHECK_STR(l.t[5].text, "s");
    CHECK_EQ_U(l.t[1].col, 7);

    /* keywords are case sensitive: lexer returns them verbatim */
    lex("Patch", &l);
    CHECK_STR(l.t[0].text, "Patch");

    /* identifier followed directly by punctuation */
    lex("byte[4]", &l);
    CHECK_EQ_U(l.n, 5);
    CHECK_STR(l.t[0].text, "byte");
    CHECK_EQ_U(l.t[1].kind, SPLINT_TOK_LBRACKET);
    CHECK_EQ_U(l.t[2].kind, SPLINT_TOK_INT);
    CHECK_EQ_U(l.t[2].ival, 4);
    CHECK_EQ_U(l.t[3].kind, SPLINT_TOK_RBRACKET);
}

static void test_ident_limit(void)
{
    char buf[80];
    lexed_t l;
    memset(buf, 'a', 63);
    buf[63] = '\0';
    lex(buf, &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_IDENT);
    CHECK_EQ_U(strlen(l.t[0].text), 63);

    memset(buf, 'a', 64);
    buf[64] = '\0';
    lex(buf, &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_ERROR);
    CHECK_EQ_U(l.t[0].line, 1);
    CHECK_EQ_U(l.t[0].col, 1);
    CHECK(strstr(l.t[0].text, "too long") != NULL);
}

static void test_ints(void)
{
    lexed_t l;
    lex("0 64 0x0105 0XfF 18446744073709551615 0xFFFFFFFFFFFFFFFF 007", &l);
    CHECK_EQ_U(l.n, 8);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_INT);
    CHECK_EQ_U(l.t[0].ival, 0);
    CHECK_EQ_U(l.t[1].ival, 64);
    CHECK_EQ_U(l.t[2].ival, 0x105);
    CHECK_EQ_U(l.t[3].ival, 0xff);
    CHECK(l.t[4].ival == UINT64_MAX);
    CHECK(l.t[5].ival == UINT64_MAX);
    CHECK_EQ_U(l.t[6].ival, 7);

    /* ranges: digits stop before '..' */
    lex("0x0102..0x0104 1..2", &l);
    CHECK_EQ_U(l.n, 7);
    CHECK_EQ_U(l.t[0].ival, 0x102);
    CHECK_EQ_U(l.t[1].kind, SPLINT_TOK_RANGE);
    CHECK_EQ_U(l.t[2].ival, 0x104);
    CHECK_EQ_U(l.t[3].ival, 1);
    CHECK_EQ_U(l.t[4].kind, SPLINT_TOK_RANGE);
    CHECK_EQ_U(l.t[5].ival, 2);
}

static void test_int_errors(void)
{
    static const char *const bad[] = {
        "18446744073709551616",          /* 2^64 */
        "99999999999999999999999",
        "0x10000000000000000",           /* 17 hex digits, value 2^64 */
        "0x", "0x;", "64k", "0x1g", "12_3", "0x12z"
    };
    lexed_t l;
    size_t i;
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        lex(bad[i], &l);
        CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_ERROR);
        CHECK_EQ_U(l.t[0].col, 1);
    }
    lex("18446744073709551616", &l);
    CHECK(strstr(l.t[0].text, "64 bits") != NULL);
    /* leading zeros in hex are not an overflow */
    lex("0x0000000000000000000001", &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_INT);
    CHECK_EQ_U(l.t[0].ival, 1);
}

static void test_strings(void)
{
    lexed_t l;
    lex("\"can_client\" \"a\\\"b\" \"x\\\\y\" \"\" \"caf\xc3\xa9\"", &l);
    CHECK_EQ_U(l.n, 6);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_STRING);
    CHECK_STR(l.t[0].text, "can_client");
    CHECK_STR(l.t[1].text, "a\"b");
    CHECK_STR(l.t[2].text, "x\\y");
    CHECK_STR(l.t[3].text, "");
    CHECK_STR(l.t[4].text, "caf\xc3\xa9");   /* bytes >= 0x80 allowed in strings */
    CHECK_EQ_U(l.t[1].col, 14);
}

static void test_string_errors(void)
{
    static const char *const bad[] = {
        "\"abc", "\"abc\nx\"", "\"a\\n\"", "\"a\\", "\"\\x41\"", "\"tab\there\"", "\""
    };
    char buf[100];
    lexed_t l;
    size_t i;
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        lex(bad[i], &l);
        CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_ERROR);
        CHECK_EQ_U(l.t[0].line, 1);
        CHECK_EQ_U(l.t[0].col, 1);
    }
    /* length limit counts unescaped characters: 63 ok, 64 error */
    buf[0] = '"';
    memset(buf + 1, 'x', 63);
    buf[64] = '"';
    buf[65] = '\0';
    lex(buf, &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_STRING);
    CHECK_EQ_U(strlen(l.t[0].text), 63);
    memset(buf + 1, 'x', 64);
    buf[65] = '"';
    buf[66] = '\0';
    lex(buf, &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_ERROR);
    CHECK(strstr(l.t[0].text, "too long") != NULL);
    /* 62 chars + one escape = 63 unescaped chars, 65 raw: still OK */
    buf[0] = '"';
    memset(buf + 1, 'y', 62);
    buf[63] = '\\';
    buf[64] = '\\';
    buf[65] = '"';
    buf[66] = '\0';
    lex(buf, &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_STRING);
    CHECK_EQ_U(strlen(l.t[0].text), 63);
}

static void test_paths(void)
{
    char buf[140];
    lexed_t l;
    lex("/dev/vendor_can /dev/ser1{ / /a.b-c_d/e", &l);
    CHECK_EQ_U(l.n, 6);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_PATH);
    CHECK_STR(l.t[0].text, "/dev/vendor_can");
    CHECK_STR(l.t[1].text, "/dev/ser1");
    CHECK_EQ_U(l.t[2].kind, SPLINT_TOK_LBRACE);
    CHECK_STR(l.t[3].text, "/");
    CHECK_STR(l.t[4].text, "/a.b-c_d/e");

    buf[0] = '/';
    memset(buf + 1, 'p', 126);
    buf[127] = '\0';
    lex(buf, &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_PATH);
    CHECK_EQ_U(strlen(l.t[0].text), 127);
    buf[127] = 'p';
    buf[128] = '\0';
    lex(buf, &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_ERROR);
    CHECK(strstr(l.t[0].text, "too long") != NULL);
}

static void test_newlines_comments_positions(void)
{
    lexed_t l;
    const char *src =
        "# header comment\n"
        "patch X {   # trailing\n"
        "\tpath /p;match open\r\n"
        "}\n";
    lex(src, &l);
    /* NL patch X { NL path /p NL match open NL } NL EOF */
    CHECK_EQ_U(l.n, 14);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_NEWLINE);
    CHECK_EQ_U(l.t[0].line, 1);
    CHECK_EQ_U(l.t[0].col, 17);
    CHECK_STR(l.t[1].text, "patch");
    CHECK_EQ_U(l.t[1].line, 2);
    CHECK_EQ_U(l.t[1].col, 1);
    CHECK_EQ_U(l.t[3].kind, SPLINT_TOK_LBRACE);
    CHECK_EQ_U(l.t[3].col, 9);
    CHECK_EQ_U(l.t[4].kind, SPLINT_TOK_NEWLINE);
    CHECK_EQ_U(l.t[4].line, 2);
    CHECK_STR(l.t[5].text, "path");
    CHECK_EQ_U(l.t[5].line, 3);
    CHECK_EQ_U(l.t[5].col, 2);      /* tab counts as one column */
    CHECK_EQ_U(l.t[6].kind, SPLINT_TOK_PATH);
    CHECK_EQ_U(l.t[6].col, 7);
    CHECK_EQ_U(l.t[7].kind, SPLINT_TOK_NEWLINE);  /* ';' */
    CHECK_EQ_U(l.t[7].col, 9);
    CHECK_STR(l.t[8].text, "match");
    CHECK_EQ_U(l.t[8].col, 10);
    CHECK_STR(l.t[9].text, "open");
    CHECK_EQ_U(l.t[10].kind, SPLINT_TOK_NEWLINE);  /* CRLF -> one NEWLINE */
    CHECK_EQ_U(l.t[10].line, 3);
    CHECK_EQ_U(l.t[10].col, 21);
    CHECK_EQ_U(l.t[11].kind, SPLINT_TOK_RBRACE);
    CHECK_EQ_U(l.t[11].line, 4);
    CHECK_EQ_U(l.t[12].kind, SPLINT_TOK_NEWLINE);
    CHECK_EQ_U(l.t[13].kind, SPLINT_TOK_EOF);
    CHECK_EQ_U(l.t[13].line, 5);
    CHECK_EQ_U(l.t[13].col, 1);

    /* consecutive terminators: one token each */
    lex("\n\n;;", &l);
    CHECK_EQ_U(l.n, 5);
    CHECK_EQ_U(l.t[3].kind, SPLINT_TOK_NEWLINE);
    CHECK_EQ_U(l.t[1].line, 2);

    /* comment directly after a token, and '#' inside a string is not a comment */
    lex("open#c\n\"a#b\"", &l);
    CHECK_EQ_U(l.n, 4);
    CHECK_STR(l.t[0].text, "open");
    CHECK_EQ_U(l.t[1].kind, SPLINT_TOK_NEWLINE);
    CHECK_STR(l.t[2].text, "a#b");
}

static void test_non_ascii(void)
{
    lexed_t l;
    lex("patch \x80", &l);
    CHECK_EQ_U(last(&l)->kind, SPLINT_TOK_ERROR);
    CHECK_EQ_U(last(&l)->col, 7);
    lex("ab\xff", &l);   /* stops identifier, then error */
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_IDENT);
    CHECK_EQ_U(l.t[1].kind, SPLINT_TOK_ERROR);
    CHECK_EQ_U(l.t[1].col, 3);
    /* non-ASCII inside a comment is skipped with the comment */
    lex("# caf\xc3\xa9\nx", &l);
    CHECK_EQ_U(l.n, 3);
    CHECK_STR(l.t[1].text, "x");
}

static void test_sticky(void)
{
    splint_lexer_t lx;
    splint_tok_t t1, t2, t3;
    const char *src = "open @ close";

    splint_lexer_init(&lx, src, strlen(src));
    splint_lexer_next(&lx, &t1);
    CHECK_EQ_U(t1.kind, SPLINT_TOK_IDENT);
    splint_lexer_next(&lx, &t1);
    splint_lexer_next(&lx, &t2);
    splint_lexer_next(&lx, &t3);
    CHECK_EQ_U(t1.kind, SPLINT_TOK_ERROR);
    CHECK_EQ_U(t2.kind, SPLINT_TOK_ERROR);
    CHECK_EQ_U(t3.kind, SPLINT_TOK_ERROR);
    CHECK_EQ_U(t1.col, 6);
    CHECK_EQ_U(t3.col, 6);
    CHECK_STR(t1.text, t3.text);

    splint_lexer_init(&lx, "x", 1);
    splint_lexer_next(&lx, &t1);
    splint_lexer_next(&lx, &t1);
    splint_lexer_next(&lx, &t2);
    CHECK_EQ_U(t1.kind, SPLINT_TOK_EOF);
    CHECK_EQ_U(t2.kind, SPLINT_TOK_EOF);
    CHECK_EQ_U(t1.col, t2.col);
}

static void test_unterminated_input(void)
{
    /* Lexer must respect len and never read beyond src[len-1]. lex_n
     * copies into an exact-size buffer, so ASan flags any over-read. */
    lexed_t l;
    lex_n("open devctl 0x0105 extra", 11, &l);   /* "open devctl" */
    CHECK_EQ_U(l.n, 3);
    CHECK_STR(l.t[1].text, "devctl");
    lex_n("0x", 2, &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_ERROR);
    lex_n("0x1", 3, &l);
    CHECK_EQ_U(l.t[0].ival, 1);
    lex_n("\"ab", 3, &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_ERROR);
    lex_n("\"ab\\", 4, &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_ERROR);
    lex_n(".", 1, &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_ERROR);
    lex_n("=", 1, &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_ERROR);
    lex_n("!", 1, &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_ERROR);
    lex_n("# comment", 9, &l);
    CHECK_EQ_U(l.t[0].kind, SPLINT_TOK_EOF);
    lex_n("/dev", 4, &l);
    CHECK_STR(l.t[0].text, "/dev");
    /* embedded NUL byte is not a valid character */
    lex_n("a\0b", 3, &l);
    CHECK_EQ_U(l.t[1].kind, SPLINT_TOK_ERROR);
}

static void test_demo_patch(void)
{
    lexed_t l;
    lex("patch CVE-DEMO-0042 {\n"
        "  path   /dev/vendor_can\n"
        "  match  devctl 0x0505\n"
        "  when   len > 64\n"
        "  action block, log\n"
        "}\n", &l);
    CHECK_EQ_U(last(&l)->kind, SPLINT_TOK_EOF);
    CHECK_EQ_U(l.n, 24);
    CHECK_STR(l.t[1].text, "CVE-DEMO-0042");
    CHECK_EQ_U(l.t[9].ival, 0x0505);
    CHECK_EQ_U(l.t[13].kind, SPLINT_TOK_GT);
    CHECK_EQ_U(l.t[18].kind, SPLINT_TOK_COMMA);
}

int main(void)
{
    test_empty();
    test_punct();
    test_bad_punct();
    test_idents();
    test_ident_limit();
    test_ints();
    test_int_errors();
    test_strings();
    test_string_errors();
    test_paths();
    test_newlines_comments_positions();
    test_non_ascii();
    test_sticky();
    test_unterminated_input();
    test_demo_patch();
    TEST_MAIN_END();
}
