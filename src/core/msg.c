/* SPDX-License-Identifier: Apache-2.0 */
#include "splint/msg.h"

const char *splint_op_name(splint_op_t op)
{
    static const char *const names[SPLINT_OP_COUNT_ + 1] = {
        "open", "read", "write", "devctl", "lseek", "close", "other", "any"
    };
    if ((unsigned)op > (unsigned)SPLINT_OP_COUNT_)
        return "?";
    return names[op];
}
