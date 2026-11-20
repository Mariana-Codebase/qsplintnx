/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Unit tests for learn mode (src/core/learn.c): golden profile emission
 * for a small synthetic trace, aligned 1 s peak windows, headroom maths,
 * table overflow accounting, escaping, snprintf semantics, and a
 * concurrent observe test (run under TSan as well).
 */
#include "splint/learn.h"
#include "test_util.h"

#include <pthread.h>
#include <stdint.h>

#define MS 1000000ull
#define S  1000000000ull

static int obs(splint_learn_t *l, const char *path, const char *client,
               splint_op_t op, uint32_t dcmd, uint64_t len, uint64_t now)
{
    splint_client_t c;
    splint_msg_t m;
    memset(&c, 0, sizeof(c));
    c.pid = 1;
    snprintf(c.name, sizeof(c.name), "%s", client);
    memset(&m, 0, sizeof(m));
    m.op = op;
    m.dcmd = dcmd;
    m.len = len;
    m.declared = len;
    m.path = path;
    m.client = &c;
    m.now_ns = now;
    return splint_learn_observe(l, &m);
}

static char out[1 << 16];

static void test_golden(void)
{
    splint_learn_t *l = splint_learn_new(NULL);
    const char *V = "/dev/vendor_can";
    CHECK(l != NULL);

    /* window 1: 3 messages */
    obs(l, V, "can_client", SPLINT_OP_OPEN, 0, 0, 1000 * MS);
    obs(l, V, "can_client", SPLINT_OP_DEVCTL, 0x40100101u, 16, 1100 * MS);
    obs(l, V, "can_client", SPLINT_OP_DEVCTL, 0x80100101u, 12, 1200 * MS);
    /* window 2: 5 messages */
    for (int i = 0; i < 5; i++)
        obs(l, V, "can_client", SPLINT_OP_DEVCTL, 0x0102, 40, (2000 + 100 * (uint64_t)i) * MS);
    /* window 3: 2 messages */
    obs(l, V, "can_client", SPLINT_OP_READ, 0, 100, 3000 * MS);
    obs(l, V, "can_client", SPLINT_OP_CLOSE, 0, 0, 3100 * MS);
    /* another client on the same path */
    obs(l, V, "diag", SPLINT_OP_DEVCTL, 0xC0040101u, 3, 5000 * MS);
    /* another path, sorts first */
    obs(l, "/dev/aaa", "can_client", SPLINT_OP_WRITE, 0, 1, 1000 * MS);

    size_t n = splint_learn_emit(l, out, sizeof(out));
    const char *want =
        "# proposed by splintd learn mode: 7 keys, 0 dropped\n"
        "\n"
        "profile /dev/aaa {\n"
        "  default block\n"
        "  allow write client \"can_client\" maxlen 2\n"
        "  rate 2 per s client \"can_client\"\n"
        "}\n"
        "\n"
        "profile /dev/vendor_can {\n"
        "  default block\n"
        "  allow open client \"can_client\"\n"
        "  allow read client \"can_client\" maxlen 125\n"
        "  allow devctl 0x0101 client \"can_client\" maxlen 20\n"
        "  allow devctl 0x0101 client \"diag\" maxlen 4\n"
        "  allow devctl 0x0102 client \"can_client\" maxlen 50\n"
        "  allow close client \"can_client\"\n"
        "  rate 10 per s client \"can_client\"\n"
        "  rate 2 per s client \"diag\"\n"
        "}\n";
    CHECK_STR(out, want);
    CHECK_EQ_U(n, strlen(want));

    /* snprintf semantics */
    CHECK_EQ_U(splint_learn_emit(l, NULL, 0), n);
    char small[16];
    CHECK_EQ_U(splint_learn_emit(l, small, sizeof(small)), n);
    CHECK_EQ_U(strlen(small), sizeof(small) - 1);
    CHECK(memcmp(small, want, sizeof(small) - 1) == 0);

    /* deterministic: same output regardless of key insertion order
     * (events permuted inside each 1 s window, windows kept in order) */
    splint_learn_t *l2 = splint_learn_new(NULL);
    obs(l2, "/dev/aaa", "can_client", SPLINT_OP_WRITE, 0, 1, 1000 * MS);
    obs(l2, V, "diag", SPLINT_OP_DEVCTL, 0xC0040101u, 3, 5000 * MS);
    obs(l2, V, "can_client", SPLINT_OP_DEVCTL, 0x80100101u, 12, 1200 * MS);
    obs(l2, V, "can_client", SPLINT_OP_DEVCTL, 0x40100101u, 16, 1100 * MS);
    obs(l2, V, "can_client", SPLINT_OP_OPEN, 0, 0, 1000 * MS);
    for (int i = 0; i < 5; i++)
        obs(l2, V, "can_client", SPLINT_OP_DEVCTL, 0x0102, 40, (2000 + 100 * (uint64_t)i) * MS);
    obs(l2, V, "can_client", SPLINT_OP_CLOSE, 0, 0, 3100 * MS);
    obs(l2, V, "can_client", SPLINT_OP_READ, 0, 100, 3000 * MS);
    static char out2[1 << 16];
    splint_learn_emit(l2, out2, sizeof(out2));
    CHECK_STR(out2, want);
    splint_learn_free(l2);

    /* reset */
    splint_learn_reset(l);
    n = splint_learn_emit(l, out, sizeof(out));
    CHECK_STR(out, "# proposed by splintd learn mode: 0 keys, 0 dropped\n");
    splint_learn_free(l);
}

static void test_opts_and_headroom(void)
{
    splint_learn_opts_t o = { 0, 0, 0 };
    splint_learn_t *l = splint_learn_new(&o);
    obs(l, "/dev/x", "c", SPLINT_OP_WRITE, 0, 1, 0);
    obs(l, "/dev/x", "c", SPLINT_OP_READ, 0, 0, 0);
    obs(l, "/dev/x", "c", SPLINT_OP_LSEEK, 0, 999, 0);
    obs(l, "/dev/x", "c", SPLINT_OP_OTHER, 0, UINT64_MAX, 0);
    splint_learn_emit(l, out, sizeof(out));
    CHECK_STR(out,
        "# proposed by splintd learn mode: 4 keys, 0 dropped\n"
        "\n"
        "profile /dev/x {\n"
        "  default allow\n"
        "  allow read client \"c\" maxlen 0\n"
        "  allow write client \"c\" maxlen 1\n"
        "  allow lseek client \"c\"\n"
        "  allow other client \"c\" maxlen 18446744073709551615\n"
        "  rate 4 per s client \"c\"\n"
        "}\n");
    splint_learn_free(l);

    /* 1 byte with 25 %: ceil(1.25) = 2; 4 -> 5; 100 -> 125; 101 -> 127 */
    l = splint_learn_new(NULL);
    obs(l, "/dev/y", "a", SPLINT_OP_WRITE, 0, 101, 0);
    obs(l, "/dev/y", "b", SPLINT_OP_WRITE, 0, 4, 0);
    splint_learn_emit(l, out, sizeof(out));
    CHECK(strstr(out, "allow write client \"a\" maxlen 127\n") != NULL);
    CHECK(strstr(out, "allow write client \"b\" maxlen 5\n") != NULL);
    splint_learn_free(l);
}

static void test_peak_window(void)
{
    splint_learn_t *l = splint_learn_new(NULL);
    /* 3 at 0.9 s and 3 at 1.1 s: aligned windows -> peak 3, not 6 */
    for (int i = 0; i < 3; i++)
        obs(l, "/dev/p", "c", SPLINT_OP_WRITE, 0, 1, 900 * MS + (uint64_t)i);
    for (int i = 0; i < 3; i++)
        obs(l, "/dev/p", "c", SPLINT_OP_WRITE, 0, 1, 1100 * MS + (uint64_t)i);
    splint_learn_emit(l, out, sizeof(out));
    CHECK(strstr(out, "rate 6 per s client \"c\"\n") != NULL);   /* 3 * 2 */

    /* 4 inside window 7 -> peak 4 -> rate 8 */
    for (int i = 0; i < 4; i++)
        obs(l, "/dev/p", "c", SPLINT_OP_WRITE, 0, 1, 7 * S + (uint64_t)i * 200 * MS);
    /* late arrival with older timestamp counts in the current window */
    obs(l, "/dev/p", "c", SPLINT_OP_WRITE, 0, 1, 6 * S);
    splint_learn_emit(l, out, sizeof(out));
    CHECK(strstr(out, "rate 10 per s client \"c\"\n") != NULL);   /* 5 * 2 */

    /* custom rate headroom 50 %: peak 3 -> ceil(4.5) = 5 */
    splint_learn_opts_t o = { 25, 50, 1 };
    splint_learn_t *l2 = splint_learn_new(&o);
    for (int i = 0; i < 3; i++)
        obs(l2, "/dev/p", "c", SPLINT_OP_WRITE, 0, 1, 5 * S);
    splint_learn_emit(l2, out, sizeof(out));
    CHECK(strstr(out, "rate 5 per s client \"c\"\n") != NULL);
    splint_learn_free(l2);
    splint_learn_free(l);
}

static void test_dropped(void)
{
    splint_learn_t *l = splint_learn_new(NULL);
    for (uint32_t i = 0; i < SPLINT_LEARN_MAX_KEYS; i++)
        CHECK(obs(l, "/dev/d", "c", SPLINT_OP_DEVCTL, i, 1, 0) == 0);
    CHECK_EQ_U(splint_learn_dropped(l), 0);
    CHECK(obs(l, "/dev/d", "c", SPLINT_OP_DEVCTL, 0xFFFF, 1, 0) == -1);
    CHECK(obs(l, "/dev/e", "c", SPLINT_OP_OPEN, 0, 1, 0) == -1);
    CHECK_EQ_U(splint_learn_dropped(l), 2);
    /* existing keys keep being counted */
    CHECK(obs(l, "/dev/d", "c", SPLINT_OP_DEVCTL, 5, 1, 0) == 0);
    CHECK_EQ_U(splint_learn_dropped(l), 2);
    size_t n = splint_learn_emit(l, NULL, 0);
    char *big = malloc(n + 1);
    CHECK(big != NULL);
    splint_learn_emit(l, big, n + 1);
    CHECK(strstr(big, "1024 keys, 2 dropped") != NULL);
    /* 1024 devctl keys in one profile: capped at SPLINT_MAX_ALLOW */
    CHECK(strstr(big, "  # 960 allow lines omitted (limit 64 per profile)\n") != NULL);
    CHECK(strstr(big, "allow devctl 0x003f client") != NULL);
    CHECK(strstr(big, "allow devctl 0x0040 client") == NULL);
    free(big);
    splint_learn_reset(l);
    CHECK_EQ_U(splint_learn_dropped(l), 0);
    CHECK(obs(l, "/dev/e", "c", SPLINT_OP_OPEN, 0, 1, 0) == 0);
    splint_learn_free(l);
}

static void test_escaping(void)
{
    splint_learn_t *l = splint_learn_new(NULL);
    obs(l, "/dev/q", "we\"ird\\n\x01", SPLINT_OP_OPEN, 0, 0, 0);
    obs(l, "/dev/bad path", "c", SPLINT_OP_OPEN, 0, 0, 0);
    splint_learn_emit(l, out, sizeof(out));
    CHECK(strstr(out, "allow open client \"we\\\"ird\\\\n?\"\n") != NULL);
    CHECK(strstr(out, "# skipped path with characters not allowed in rules: \"/dev/bad path\"\n") != NULL);
    CHECK(strstr(out, "profile /dev/bad") == NULL);
    /* NULL client / NULL path do not crash */
    splint_msg_t m;
    memset(&m, 0, sizeof(m));
    m.op = SPLINT_OP_OPEN;
    CHECK(splint_learn_observe(l, &m) == 0);
    CHECK(splint_learn_observe(l, NULL) == -1);
    CHECK(splint_learn_observe(NULL, &m) == -1);
    splint_learn_free(l);
}

#define LT_THREADS 4
#define LT_ITERS   20000

static void *lt_worker(void *arg)
{
    splint_learn_t *l = arg;
    for (int i = 0; i < LT_ITERS; i++)
        obs(l, "/dev/mt", "c", SPLINT_OP_DEVCTL, (uint32_t)(i % 16), (uint64_t)i, (uint64_t)i * MS);
    return NULL;
}

static void test_concurrent(void)
{
    splint_learn_t *l = splint_learn_new(NULL);
    pthread_t th[LT_THREADS];
    for (int i = 0; i < LT_THREADS; i++)
        CHECK(pthread_create(&th[i], NULL, lt_worker, l) == 0);
    for (int k = 0; k < 50; k++)
        splint_learn_emit(l, out, sizeof(out));
    for (int i = 0; i < LT_THREADS; i++)
        pthread_join(th[i], NULL);
    splint_learn_emit(l, out, sizeof(out));
    CHECK(strstr(out, "16 keys, 0 dropped") != NULL);
    CHECK(strstr(out, "allow devctl 0x000f client \"c\" maxlen 24999\n") != NULL); /* 19999*1.25 */
    splint_learn_free(l);
}

int main(void)
{
    test_golden();
    test_opts_and_headroom();
    test_peak_window();
    test_dropped();
    test_escaping();
    test_concurrent();
    TEST_MAIN_END();
}
