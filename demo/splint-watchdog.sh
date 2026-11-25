#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Liveness watchdog for splintd. The supervisor (splint-super.sh) handles a
# splintd that exits; this handles a splintd that is still alive but wedged
# (stuck in a deadlock, a runaway handler, or SIGSTOP'd). It pings the control
# channel on a timeout; after enough consecutive misses it forces splintd down
# (SIGCONT in case it was stopped, then SIGKILL) so the supervisor respawns it.
#
# Environment:
#   BIN       directory with splintctl (default: the script's dir)
#   CTL       control node (default: /dev/splint/ctl)
#   TYPE      secpol type to ping under via `on -T` (default: none)
#   INTERVAL  seconds between pings (default: 2)
#   TIMEOUT   seconds to wait for a ping reply (default: 3)
#   MISSES    consecutive missed pings before acting (default: 2)
#
BIN=${BIN:-$(dirname "$0")}
CTL=${CTL:-/dev/splint/ctl}
INTERVAL=${INTERVAL:-2}
TIMEOUT=${TIMEOUT:-3}
MISSES=${MISSES:-2}

ping_once() {   # returns 0 if splintd replied within TIMEOUT, 1 otherwise
    if [ -n "$TYPE" ]; then
        on -T "$TYPE" "$BIN/splintctl" -c "$CTL" stats >/dev/null 2>&1 &
    else
        "$BIN/splintctl" -c "$CTL" stats >/dev/null 2>&1 &
    fi
    _p=$!
    _w=0
    while kill -0 "$_p" 2>/dev/null; do
        if [ "$_w" -ge "$TIMEOUT" ]; then
            kill -9 "$_p" 2>/dev/null       # ping is stuck: splintd not replying
            return 1
        fi
        sleep 1
        _w=$((_w + 1))
    done
    wait "$_p" 2>/dev/null
    return $?
}

miss=0
while true; do
    if ping_once; then
        miss=0
    else
        miss=$((miss + 1))
        echo "[watchdog] missed ping $miss/$MISSES"
        if [ "$miss" -ge "$MISSES" ]; then
            SPID=$(pidin -p splintd -F "%a" 2>/dev/null | tail -1 | tr -d ' ')
            echo "[watchdog] splintd ($SPID) unresponsive; forcing respawn"
            [ -n "$SPID" ] && kill -CONT "$SPID" 2>/dev/null   # unwedge if stopped
            [ -n "$SPID" ] && kill -9 "$SPID" 2>/dev/null      # supervisor respawns it
            miss=0
        fi
    fi
    sleep "$INTERVAL"
done
