#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Minimal supervisor for splintd: respawn it whenever it exits, so a crash of
# the protection layer is a short gap rather than a permanent one. splintd runs
# its resource-manager loop in the foreground, so this command returns only when
# splintd exits or dies; the loop then restarts it.
#
# This is the portable demo mechanism. On a real QNX system the High
# Availability Manager (ham) is the production answer: register splintd with
# ham_attach() and a death condition that re-launches it, so the microkernel's
# own supervision restarts it with no shell in the loop. The behaviour this
# script shows (automatic respawn, device node restored) is what ham provides
# with proper logging, restart limits and escalation.
#
# Environment:
#   BIN     directory with the binaries (default: the script's dir)
#   TYPE    secpol type to start splintd under via `on -T` (default: none)
#   RULES   initial ruleset file (default: empty.rules)
#   MAP     splintd -m mapping (default: /dev/vendor_can=/dev/.splint/vendor_can)
#   CTL     control node (default: /dev/splint/ctl)
#   BACKOFF seconds to wait between respawns (default: 1)
#
BIN=${BIN:-$(dirname "$0")}
RULES=${RULES:-$BIN/empty.rules}
MAP=${MAP:-/dev/vendor_can=/dev/.splint/vendor_can}
CTL=${CTL:-/dev/splint/ctl}
BACKOFF=${BACKOFF:-1}

run() {
    if [ -n "$TYPE" ]; then
        on -T "$TYPE" "$BIN/splintd" -r "$RULES" -m "$MAP" -c "$CTL"
    else
        "$BIN/splintd" -r "$RULES" -m "$MAP" -c "$CTL"
    fi
}

n=0
while true; do
    n=$((n + 1))
    echo "[splint-super] start #$n $(date 2>/dev/null)"
    run
    rc=$?
    echo "[splint-super] splintd exited rc=$rc; respawning in ${BACKOFF}s"
    sleep "$BACKOFF"
done
