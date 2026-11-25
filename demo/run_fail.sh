#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# What happens to the protected device when splintd itself dies. Run ON a QNX
# 8.0 target. Three parts:
#   A. relocated mode  -> fail-closed: the public node disappears, the driver is
#      never exposed (secpol still denies the backend), recovery on restart.
#   B. shadow mode     -> fail-open: the driver keeps its own node, so a crash
#      re-exposes it. This part crashes the demo driver on purpose, last.
#   C. supervised      -> a respawn loop turns the crash into a short gap.
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

run_as() { _t=$1; shift; if [ "$SECPOL" = 1 ]; then on -T "$_t" "$@"; else "$@"; fi; }
splintd_pid() { pidin -p splintd -F "%a" 2>/dev/null | tail -1 | tr -d ' '; }
banner() { echo; echo "=== $* ==="; }

cleanup() { slay splintd vendor_can splint-super.sh 2>/dev/null; }
trap cleanup EXIT INT TERM

# ---- A. relocated: fail-closed --------------------------------------------
banner "A. relocated mode: crash fails CLOSED"
run_as vendor_can_t ./vendor_can -p "$BACKEND" >/tmp/drv.log 2>&1 &
sleep 1
run_as splintd_t ./splintd -r empty.rules -m "$PUBLIC=$BACKEND" -c "$CTL" >/tmp/spl.log 2>&1 &
sleep 1
echo "# client works through splintd:"
run_as can_client_t ./can_client -p "$PUBLIC" -n 10 -r 0 2>&1 | tail -1
P=$(splintd_pid); echo "# killing splintd (pid $P)"; kill -9 "$P"; sleep 1
echo "# public node after crash:"; ls -l "$PUBLIC" 2>&1
echo "# client on the public node:"; run_as can_client_t ./can_client -p "$PUBLIC" -n 3 -r 0 2>&1 | tail -1
echo "# client reaching the driver directly (secpol, in the kernel, still denies it):"
run_as can_client_t ./can_client -p "$BACKEND" -n 3 -r 0 2>&1 | tail -1
echo "# driver process still alive, just unreachable:"; pidin -p vendor_can -F "%N" 2>/dev/null | tail -1
echo "# restart splintd -> availability restored, driver state intact:"
run_as splintd_t ./splintd -r empty.rules -m "$PUBLIC=$BACKEND" -c "$CTL" >/tmp/spl.log 2>&1 &
sleep 1
run_as can_client_t ./can_client -p "$PUBLIC" -n 10 -r 0 2>&1 | tail -1
slay splintd vendor_can 2>/dev/null; sleep 1

# ---- C. supervised respawn ------------------------------------------------
banner "C. supervised: the crash becomes a short gap"
run_as vendor_can_t ./vendor_can -p "$BACKEND" >/tmp/drv.log 2>&1 &
sleep 1
TYPE=$([ "$SECPOL" = 1 ] && echo splintd_t) BIN="$BIN" ./splint-super.sh >/tmp/super.log 2>&1 &
sleep 2
P=$(splintd_pid); echo "# supervised splintd pid=$P; node up:"; ls "$PUBLIC"
kill -9 "$P"; echo "# killed; waiting for respawn..."; sleep 3
echo "# node back, new pid=$(splintd_pid):"; ls -l "$PUBLIC" 2>&1
run_as can_client_t ./can_client -p "$PUBLIC" -n 10 -r 0 2>&1 | tail -1
slay splintd vendor_can splint-super.sh 2>/dev/null; sleep 1

# ---- B. shadow: fail-open (destructive, last) -----------------------------
banner "B. shadow mode: crash fails OPEN (re-exposes the driver)"
./vendor_can -p "$PUBLIC" >/tmp/drv.log 2>&1 &
sleep 1
./splintd -s "$PUBLIC" -r cve-demo-0042.rules -c "$CTL" >/tmp/spl.log 2>&1 &
sleep 1
echo "# patch loaded; attack blocked while splintd is up:"
./exploit -p "$PUBLIC" 2>&1 | tail -1
P=$(splintd_pid); echo "# killing splintd (pid $P)"; kill -9 "$P"; sleep 1
echo "# public node still present (the driver's own attach):"; ls -l "$PUBLIC" 2>&1
echo "# the same attack now reaches the driver directly:"
./exploit -p "$PUBLIC" 2>&1 | tail -1

banner "done"
