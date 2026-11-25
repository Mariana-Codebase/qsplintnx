/*
 * QSplintNX - project identity and version banner.
 *
 * QSplintNX
 * Copyright (c) 2026 MarianaCodebase
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPLINT_IDENTITY_H
#define SPLINT_IDENTITY_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QSPLINTNX_NAME      "QSplintNX"
#define QSPLINTNX_AUTHOR    "MarianaCodebase"
#define QSPLINTNX_VERSION   "0.1"
#define QSPLINTNX_SIGNATURE "QSplintNX by MarianaCodebase"

/* The identity string is also stored verbatim in the ELF section
 * .qsplintnx.identity of every binary; read it with:
 *   readelf -p .qsplintnx.identity splintd
 */
const char *splint_identity(void);

/* Print the multi-line version banner for `prog` to `out`. */
void splint_print_version(FILE *out, const char *prog);

#ifdef __cplusplus
}
#endif
#endif /* SPLINT_IDENTITY_H */
