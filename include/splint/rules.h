/*
 * QSplintNX - compiled ruleset (output of the parser, input of the engine).
 * Grammar and semantics: docs/RULES.md (normative).
 *
 * A ruleset is immutable after splint_rules_parse() returns it, so the
 * engine can swap rulesets with a single pointer store.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SPLINT_RULES_H
#define SPLINT_RULES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "splint/msg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SPLINT_MAX_RULES      256u   /* patches per file              */
#define SPLINT_MAX_CONDS      8u     /* `when` lines per patch        */
#define SPLINT_MAX_PROFILES   32u
#define SPLINT_MAX_ALLOW      64u    /* allow lines per profile       */
#define SPLINT_MAX_RATES      16u    /* rate lines per profile        */
#define SPLINT_ID_MAX         64u    /* identifier incl. NUL          */
#define SPLINT_RULES_FILE_MAX (256u * 1024u)

typedef enum splint_mode { SPLINT_MODE_ENFORCE = 0, SPLINT_MODE_LEARN } splint_mode_t;

/* op value meaning "any op" in a match / allow line */
#define SPLINT_OP_ANY  SPLINT_OP_COUNT_

typedef enum splint_operand_kind {
    SPLINT_OPD_CONST = 0,   /* value                                  */
    SPLINT_OPD_LEN,         /* msg->len                               */
    SPLINT_OPD_DECLARED,    /* msg->declared                          */
    SPLINT_OPD_BYTE,        /* payload u8  at offset                  */
    SPLINT_OPD_U16,         /* payload u16 LE at offset               */
    SPLINT_OPD_U32          /* payload u32 LE at offset               */
} splint_operand_kind_t;

typedef struct splint_operand {
    splint_operand_kind_t kind;
    uint64_t              value;    /* CONST: the value; BYTE/U16/U32: offset */
} splint_operand_t;

typedef enum splint_cmp {
    SPLINT_CMP_EQ = 0, SPLINT_CMP_NE, SPLINT_CMP_LT,
    SPLINT_CMP_LE, SPLINT_CMP_GT, SPLINT_CMP_GE
} splint_cmp_t;

typedef struct splint_cond {
    splint_operand_t lhs;    /* never CONST                    */
    splint_cmp_t     cmp;
    splint_operand_t rhs;    /* CONST, LEN or DECLARED only    */
} splint_cond_t;

#define SPLINT_ACT_BLOCK  0x1u
#define SPLINT_ACT_LOG    0x2u

typedef struct splint_patch {
    char          id[SPLINT_ID_MAX];
    char          path[SPLINT_PATH_MAX];
    splint_op_t   op;           /* SPLINT_OP_ANY allowed            */
    bool          has_code;
    uint32_t      code;         /* devctl code (see RULES.md)       */
    uint32_t      ncond;
    splint_cond_t cond[SPLINT_MAX_CONDS];
    uint32_t      actions;      /* SPLINT_ACT_* bitmask, non-zero   */
    int           err;          /* errno value to reply, default EPERM */
    uint32_t      line;         /* source line of `patch`, for logs */
} splint_patch_t;

typedef struct splint_allow {
    splint_op_t op;             /* SPLINT_OP_ANY allowed            */
    bool        has_code;
    uint32_t    code_lo, code_hi;   /* inclusive; lo == hi for single */
    bool        has_client;
    char        client[SPLINT_NAME_MAX];
    bool        has_maxlen;
    uint64_t    maxlen;
    uint32_t    line;
} splint_allow_t;

typedef struct splint_rate {
    uint32_t per_sec;           /* > 0                               */
    bool     has_client;        /* false = default for other clients */
    char     client[SPLINT_NAME_MAX];
    uint32_t line;
} splint_rate_t;

typedef struct splint_profile {
    char           path[SPLINT_PATH_MAX];
    bool           default_block;
    uint32_t       nallow;
    splint_allow_t allow[SPLINT_MAX_ALLOW];
    uint32_t       nrate;
    splint_rate_t  rate[SPLINT_MAX_RATES];
    uint32_t       line;
} splint_profile_t;

typedef struct splint_ruleset {
    splint_mode_t    mode;
    uint32_t         npatch;
    splint_patch_t   patch[SPLINT_MAX_RULES];
    uint32_t         nprofile;
    splint_profile_t profile[SPLINT_MAX_PROFILES];
} splint_ruleset_t;

typedef struct splint_parse_error {
    uint32_t line;     /* 1-based; 0 if not applicable */
    uint32_t col;      /* 1-based; 0 if not applicable */
    char     msg[160];
} splint_parse_error_t;

/*
 * Parse and compile `len` bytes of rule text. On success returns 0 and
 * stores a heap-allocated ruleset in *out (free with splint_rules_free).
 * On failure returns -1, sets *out = NULL and fills *err (if non-NULL).
 * Never reads beyond text[len-1]; text need not be NUL-terminated.
 */
int  splint_rules_parse(const char *text, size_t len,
                        splint_ruleset_t **out, splint_parse_error_t *err);
void splint_rules_free(splint_ruleset_t *rs);

/* Write a ruleset back as canonical rule text (used by learn mode and
 * tests for round-trips). Returns bytes that would be written excluding
 * NUL, like snprintf. */
size_t splint_rules_format(const splint_ruleset_t *rs, char *buf, size_t cap);

#ifdef __cplusplus
}
#endif
#endif /* SPLINT_RULES_H */
