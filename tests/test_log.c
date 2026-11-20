/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Unit tests for the event ring (src/core/log.c): capacity rounding,
 * wraparound, ordering, after_seq filtering, truncation, formatting, and
 * a concurrent writers + reader test checking that no torn event is ever
 * returned (run under TSan as well).
 */
#include "splint/log.h"
#include "test_util.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

static void push(splint_log_t *l, int32_t pid, uint64_t len, const char *name,
                 const char *path, splint_action_t act)
{
    splint_client_t c;
    splint_msg_t m;
    splint_verdict_t v;
    memset(&c, 0, sizeof(c));
    c.pid = pid;
    snprintf(c.name, sizeof(c.name), "%s", name);
    memset(&m, 0, sizeof(m));
    m.op = SPLINT_OP_WRITE;
    m.len = len;
    m.declared = len * 7u + (uint64_t)pid;
    m.path = path;
    m.client = &c;
    m.now_ns = len;
    memset(&v, 0, sizeof(v));
    v.action = act;
    v.reason = act == SPLINT_BLOCK ? SPLINT_R_DEFAULT : SPLINT_R_ALLOW;
    v.rule_line = (uint32_t)len;
    splint_log_push(l, &m, &v, 0);
}

static void test_basic_and_wrap(void)
{
    splint_event_t ev[256];
    splint_log_t *l = splint_log_new(1);         /* -> 64 */
    CHECK(l != NULL);
    CHECK_EQ_U(splint_log_read(l, 0, ev, 256), 0);

    for (uint64_t i = 1; i <= 10; i++)
        push(l, 1, i, "a", "/dev/x", SPLINT_ALLOW);
    uint32_t n = splint_log_read(l, 0, ev, 256);
    CHECK_EQ_U(n, 10);
    for (uint32_t i = 0; i < n; i++) {
        CHECK_EQ_U(ev[i].seq, i + 1);
        CHECK_EQ_U(ev[i].len, i + 1);
    }
    /* after_seq filtering and max */
    n = splint_log_read(l, 7, ev, 256);
    CHECK_EQ_U(n, 3);
    CHECK_EQ_U(ev[0].seq, 8);
    n = splint_log_read(l, 2, ev, 4);
    CHECK_EQ_U(n, 4);
    CHECK_EQ_U(ev[0].seq, 3);
    CHECK_EQ_U(ev[3].seq, 6);
    CHECK_EQ_U(splint_log_read(l, 10, ev, 256), 0);
    CHECK_EQ_U(splint_log_read(l, 1000, ev, 256), 0);
    CHECK_EQ_U(splint_log_read(l, 0, ev, 0), 0);

    /* wraparound: 100 events in a 64 ring keep the newest 64 */
    for (uint64_t i = 11; i <= 100; i++)
        push(l, 1, i, "a", "/dev/x", SPLINT_ALLOW);
    n = splint_log_read(l, 0, ev, 256);
    CHECK_EQ_U(n, 64);
    CHECK_EQ_U(ev[0].seq, 37);
    CHECK_EQ_U(ev[63].seq, 100);
    for (uint32_t i = 1; i < n; i++)
        CHECK_EQ_U(ev[i].seq, ev[i - 1].seq + 1);
    n = splint_log_read(l, 90, ev, 256);
    CHECK_EQ_U(n, 10);
    CHECK_EQ_U(ev[0].seq, 91);
    splint_log_free(l);

    /* rounding: 100 -> 128 */
    l = splint_log_new(100);
    for (uint64_t i = 1; i <= 200; i++)
        push(l, 1, i, "a", "/dev/x", SPLINT_ALLOW);
    n = splint_log_read(l, 0, ev, 256);
    CHECK_EQ_U(n, 128);
    CHECK_EQ_U(ev[0].seq, 73);
    splint_log_free(l);

    /* exact power of two kept */
    l = splint_log_new(256);
    for (uint64_t i = 1; i <= 300; i++)
        push(l, 1, i, "a", "/dev/x", SPLINT_ALLOW);
    CHECK_EQ_U(splint_log_read(l, 0, ev, 256), 256);
    CHECK_EQ_U(ev[0].seq, 45);
    splint_log_free(l);
    splint_log_free(NULL);
}

static void test_fields_and_format(void)
{
    static const splint_client_t cl = { 42, 0, 0, "exploit" };
    splint_log_t *l = splint_log_new(64);
    splint_msg_t m;
    splint_verdict_t v;
    splint_event_t ev[4];
    char buf[512];

    memset(&m, 0, sizeof(m));
    m.op = SPLINT_OP_DEVCTL;
    m.dcmd = 0x80400505u;
    m.len = 200;
    m.declared = 64;
    m.path = "/dev/vendor_can";
    m.client = &cl;
    m.now_ns = 1234567890ull;
    memset(&v, 0, sizeof(v));
    v.action = SPLINT_BLOCK;
    v.reason = SPLINT_R_PATCH;
    v.rule_id = "CVE-DEMO-0042";
    v.rule_line = 1;
    v.log = true;
    v.err = 1;
    for (int i = 0; i < 12; i++)
        splint_log_push(l, &m, &v, 3100);
    CHECK_EQ_U(splint_log_read(l, 11, ev, 4), 1);
    CHECK_EQ_U(ev[0].seq, 12);
    CHECK_EQ_U(ev[0].pid, 42);
    CHECK_EQ_U(ev[0].op, SPLINT_OP_DEVCTL);
    CHECK_EQ_U(ev[0].action, SPLINT_BLOCK);
    CHECK_EQ_U(ev[0].reason, SPLINT_R_PATCH);
    CHECK_EQ_U(ev[0].latency_ns, 3100);
    CHECK_STR(ev[0].rule_id, "CVE-DEMO-0042");

    const char *want =
        "#12 1234567890 pid=42 client=exploit op=devctl dcmd=0x80400505 len=200 "
        "declared=64 BLOCK reason=patch rule=CVE-DEMO-0042 line=1 lat=3100ns "
        "path=/dev/vendor_can";
    size_t n = splint_event_format(&ev[0], buf, sizeof(buf));
    CHECK_STR(buf, want);
    CHECK_EQ_U(n, strlen(want));
    /* snprintf semantics */
    CHECK_EQ_U(splint_event_format(&ev[0], NULL, 0), n);
    char small[10];
    CHECK_EQ_U(splint_event_format(&ev[0], small, sizeof(small)), n);
    CHECK_STR(small, "#12 12345");

    /* learn mode allow with would_block, no rule id */
    v.action = SPLINT_ALLOW;
    v.reason = SPLINT_R_RATE;
    v.would_block = true;
    v.rule_id = NULL;
    v.rule_line = 7;
    m.op = SPLINT_OP_WRITE;
    m.dcmd = 0;
    splint_log_push(l, &m, &v, 0);
    CHECK_EQ_U(splint_log_read(l, 12, ev, 4), 1);
    splint_event_format(&ev[0], buf, sizeof(buf));
    CHECK_STR(buf,
        "#13 1234567890 pid=42 client=exploit op=write dcmd=0x00000000 len=200 "
        "declared=64 ALLOW would_block reason=rate rule=- line=7 lat=0ns "
        "path=/dev/vendor_can");

    /* truncation of long strings, NULL client */
    char longname[SPLINT_NAME_MAX];
    memset(longname, 'n', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    char longpath[SPLINT_PATH_MAX];
    memset(longpath, 'p', sizeof(longpath) - 1);
    longpath[0] = '/';
    longpath[sizeof(longpath) - 1] = '\0';
    char longid[SPLINT_ID_MAX];
    memset(longid, 'i', sizeof(longid) - 1);
    longid[sizeof(longid) - 1] = '\0';
    splint_client_t lc = cl;
    memcpy(lc.name, longname, sizeof(longname));
    m.client = &lc;
    m.path = longpath;
    v.rule_id = longid;
    splint_log_push(l, &m, &v, 0);
    CHECK_EQ_U(splint_log_read(l, 13, ev, 4), 1);
    CHECK_EQ_U(strlen(ev[0].client), sizeof(ev[0].client) - 1);
    CHECK_EQ_U(strlen(ev[0].rule_id), sizeof(ev[0].rule_id) - 1);
    CHECK_EQ_U(strlen(ev[0].path), sizeof(ev[0].path) - 1);
    m.client = NULL;
    m.path = NULL;
    splint_log_push(l, &m, &v, 0);
    CHECK_EQ_U(splint_log_read(l, 14, ev, 4), 1);
    CHECK_EQ_U((uint32_t)ev[0].pid, (uint32_t)-1);
    CHECK_STR(ev[0].client, "");

    /* format never overreads unterminated fields (event from the wire) */
    splint_event_t raw;
    memset(&raw, 'Z', sizeof(raw));
    raw.op = 200;
    raw.reason = 99;
    n = splint_event_format(&raw, buf, sizeof(buf));
    CHECK(n > 0 && n < sizeof(buf));
    CHECK(strstr(buf, "op=? ") != NULL);
    CHECK(strstr(buf, "reason=? ") != NULL);
    CHECK_EQ_U(splint_event_format(NULL, buf, sizeof(buf)), 0);

    /* NULL arguments are ignored */
    splint_log_push(l, NULL, &v, 0);
    splint_log_push(l, &m, NULL, 0);
    splint_log_push(NULL, &m, &v, 0);
    CHECK_EQ_U(splint_log_read(l, 15, ev, 4), 0);
    splint_log_free(l);
}

/* -------------------------------------------------- concurrency */

#define W_THREADS 4
#define W_ITERS   50000

static splint_log_t *g_log;
static atomic_int g_writers_done;

static void *writer(void *arg)
{
    int32_t id = (int32_t)(intptr_t)arg;
    char name[16], path[32];
    snprintf(name, sizeof(name), "w%d", (int)id);
    snprintf(path, sizeof(path), "/dev/t%d", (int)id);
    for (uint64_t i = 1; i <= W_ITERS; i++)
        push(g_log, id, i, name, path, (i & 1) ? SPLINT_BLOCK : SPLINT_ALLOW);
    atomic_fetch_add(&g_writers_done, 1);
    return NULL;
}

static void test_concurrent(void)
{
    static splint_event_t ev[64];
    pthread_t th[W_THREADS];
    uint64_t after = 0, got = 0, bad = 0, gaps = 0;
    char name[16], path[32];

    g_log = splint_log_new(64);
    atomic_store(&g_writers_done, 0);
    for (int i = 0; i < W_THREADS; i++)
        CHECK(pthread_create(&th[i], NULL, writer, (void *)(intptr_t)i) == 0);

    for (;;) {
        int done = atomic_load(&g_writers_done) == W_THREADS;
        uint32_t n = splint_log_read(g_log, after, ev, 64);
        for (uint32_t k = 0; k < n; k++) {
            const splint_event_t *e = &ev[k];
            int32_t id = e->pid;
            if (e->seq <= after) bad++;
            if (e->seq != after + 1) gaps++;
            after = e->seq;
            if (id < 0 || id >= W_THREADS) { bad++; continue; }
            snprintf(name, sizeof(name), "w%d", (int)id);
            snprintf(path, sizeof(path), "/dev/t%d", (int)id);
            if (e->declared != e->len * 7u + (uint64_t)id) bad++;
            if (e->ts_ns != e->len || e->rule_line != (uint32_t)e->len) bad++;
            if (e->action != ((e->len & 1) ? SPLINT_BLOCK : SPLINT_ALLOW)) bad++;
            if (strcmp(e->client, name) != 0 || strcmp(e->path, path) != 0) bad++;
            got++;
        }
        if (done && n == 0)
            break;
    }
    for (int i = 0; i < W_THREADS; i++)
        pthread_join(th[i], NULL);
    CHECK_EQ_U(bad, 0);
    CHECK(got > 0);
    /* the final events are published (a drop needs a slot still busy
     * with the previous lap, impossible once every writer returned,
     * except for that last lap itself) */
    CHECK(after <= (uint64_t)W_THREADS * W_ITERS);
    CHECK(after > (uint64_t)W_THREADS * W_ITERS - 64u);
    printf("concurrent log: %llu events read, %llu gaps, 0 torn\n",
           (unsigned long long)got, (unsigned long long)gaps);
    splint_log_free(g_log);
}

int main(void)
{
    test_basic_and_wrap();
    test_fields_and_format();
    test_concurrent();
    TEST_MAIN_END();
}
