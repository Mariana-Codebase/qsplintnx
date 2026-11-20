/* SPDX-License-Identifier: Apache-2.0 */
/*
 * libFuzzer target for the rule parser. Parses arbitrary bytes; on
 * success the ruleset is formatted, the text re-parsed (must succeed and
 * must format to identical text) and both rulesets freed.
 * Build: make fuzz   Run: build/fuzz/fuzz_rules -max_total_time=60 tests/corpus
 */
#include "splint/rules.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    splint_ruleset_t *a = NULL, *b = NULL;
    splint_parse_error_t err;
    size_t n, n2;
    char *t1, *t2;

    if (splint_rules_parse((const char *)data, size, &a, &err) != 0) {
        if (a != NULL)
            abort();            /* failure must not return a ruleset */
        return 0;
    }
    n = splint_rules_format(a, NULL, 0);
    t1 = malloc(n + 1);
    t2 = malloc(n + 1);
    if (!t1 || !t2)
        abort();
    if (splint_rules_format(a, t1, n + 1) != n)
        abort();
    if (splint_rules_parse(t1, n, &b, &err) != 0)
        abort();                /* canonical text must always re-parse */
    n2 = splint_rules_format(b, t2, n + 1);
    if (n2 != n || memcmp(t1, t2, n) != 0)
        abort();                /* format must be a fixed point */
    if (a->mode != b->mode || a->npatch != b->npatch || a->nprofile != b->nprofile)
        abort();
    free(t1);
    free(t2);
    splint_rules_free(b);
    splint_rules_free(a);
    return 0;
}
