/*
 * QSplintNX
 * Copyright (c) 2026 MarianaCodebase
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "splint/identity.h"

/*
 * Authorship as part of the binary, not just a source comment. The string is
 * placed in its own ELF section and marked `used` so the compiler keeps it even
 * though nothing references it. It survives into every linked binary and can be
 * read back without running anything:
 *
 *   readelf -p .qsplintnx.identity splintd
 *
 * A build that strips unknown sections would drop it; the KEEP in a linker
 * script, or simply not stripping, preserves it.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((used, section(".qsplintnx.identity")))
#endif
static const char qsplintnx_identity[] = QSPLINTNX_SIGNATURE;

const char *splint_identity(void)
{
    return qsplintnx_identity;
}

void splint_print_version(FILE *out, const char *prog)
{
    /* ASCII bar so the banner renders on a plain serial console too. */
    static const char *bar = "==============================================";
    fprintf(out, "%s\n", bar);
    fprintf(out, "  %s %s (%s)\n", QSPLINTNX_NAME, QSPLINTNX_VERSION, prog ? prog : "");
    fprintf(out, "  Designed by %s\n", QSPLINTNX_AUTHOR);
    fprintf(out, "  Native QNX runtime protection\n");
    fprintf(out, "  Cryptographic ruleset verification (Ed25519)\n");
    fprintf(out, "%s\n", bar);
}
