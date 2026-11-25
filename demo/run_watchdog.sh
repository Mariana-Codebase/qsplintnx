#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Liveness demo, run ON a QNX 8.0 target. splint-super.sh respawns a splintd
# that exits; splint-watchdog.sh catches a splintd that is alive but wedged.
# Here we wedge it with SIGSTOP (a stand-in for a deadlock or runaway handler),
# show the control channel stops answering, and watch the watchdog force a
# respawn so the device recovers.
#
# Environment:
#   BIN     directory with binaries and rules (default: the script's dir)
#   SECPOL  if 1, start processes with their secpol type via `on -T`.
#
PUBLIC=/dev/vendor_can
BACKEND=/dev/.splint/vendor_can
CTL=/dev/splint/ctl
BIN=${BIN:-$(dirname "$0")}
cd "$BIN" || exit 1

TY=$([ "$SECPOL" = 1 ] && echo splintd_t)
CY=$([ "$SECPOL" = 1 ] && echo splintctl_t)
run_as() { _t=$1; shift; if [ "$SECPOL" = 1 ]; then on -T "$_t" "$@"; else "$@"; fi; }
# Numeric pid of splintd, or empty. grep drops pidin's "pid" header line so an
# absent process yields "" rather than the word "pid".
splintd_pid() { pidin -p splintd -F "%a" 2>/dev/null | grep -E '^ *[0-9]+ *$' | tail -1 | tr -d ' '; }
banner() { echo; echo "=== $* ==="; }

cleanup() { slay splintd vendor_can splint-super.sh splint-watchdog.sh 2>/dev/null; }
trap cleanup EXIT INT TERM

banner "1. driver + supervised splintd + liveness watchdog"
run_as vendor_can_t ./vendor_can -p "$BACKEND" >/tmp/drv.log 2>&1 &
sleep 1
TYPE="$TY" BIN="$BIN" ./splint-super.sh >/tmp/super.log 2>&1 &
sleep 2
TYPE="$CY" BIN="$BIN" CTL="$CTL" INTERVAL=1 TIMEOUT=2 MISSES=2 \
    ./splint-watchdog.sh >/tmp/wd.log 2>&1 &
sleep 1
P1=$(splintd_pid); echo "splintd pid=$P1; control channel answers:"
run_as "$CY" ./splintctl -c "$CTL" stats >/dev/null 2>&1 && echo "  ping OK"

banner "2. wedge splintd (SIGSTOP): alive but not answering"
kill -STOP "$P1"
echo "sent SIGSTOP to $P1; a ping now hangs (watchdog will time it out)"

banner "3. watchdog detects the stall and forces a respawn"
n=0
while [ "$n" -lt 15 ]; do
    P2=$(splintd_pid)
    if [ -n "$P2" ] && [ "$P2" != "$P1" ]; then break; fi
    sleep 1; n=$((n + 1))
done
echo "--- watchdog log ---"; cat /tmp/wd.log
echo "new splintd pid=$(splintd_pid) (was $P1)"

banner "4. recovered: control channel answers again"
run_as "$CY" ./splintctl -c "$CTL" stats >/dev/null 2>&1 && echo "  ping OK"
ls -l "$PUBLIC" 2>&1

banner "done"
