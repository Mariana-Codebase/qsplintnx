/* Minimal test helpers. Each test file is its own executable with main().
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef SPLINT_TEST_UTIL_H
#define SPLINT_TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int t_failures;
static int t_checks;

#define CHECK(cond) do { t_checks++; if (!(cond)) { t_failures++; \
    fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); } } while (0)

#define CHECK_EQ_U(a, b) do { unsigned long long _a = (unsigned long long)(a), \
    _b = (unsigned long long)(b); t_checks++; if (_a != _b) { t_failures++; \
    fprintf(stderr, "%s:%d: %s == %s failed (%llu vs %llu)\n", __FILE__, __LINE__, \
    #a, #b, _a, _b); } } while (0)

#define CHECK_STR(a, b) do { const char *_a = (a), *_b = (b); t_checks++; \
    if (!_a || !_b || strcmp(_a, _b) != 0) { t_failures++; \
    fprintf(stderr, "%s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, \
    _a ? _a : "(null)", _b ? _b : "(null)"); } } while (0)

#define TEST_MAIN_END() do { printf("%d checks, %d failures\n", t_checks, t_failures); \
    return t_failures ? 1 : 0; } while (0)

#endif
