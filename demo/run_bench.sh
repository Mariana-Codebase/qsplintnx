#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# QSplintNX latency benchmark, run ON a QNX 8.0 target. It measures the per
# message cost splintd adds: min / p50 / p99 / max for devctl calls that go
# through splintd on the public path, and (unless secpol forbids the direct
# open) the same calls straight to the driver, so the difference is splintd's
# overhead. Optionally runs a background traffic flood first, to read p99 and
# worst case under contention rather than on an idle box.
#
# Environment:
#   BIN     directory with the binaries and rules (default: the script's dir)
#   SECPOL  if 1, start processes with their secpol type and skip the direct
#           backend series (the bench process may not connect to the driver);
#           reported numbers are then the absolute through-splintd latency.
#   LOAD    if 1, run a background can_client flood during the measurement.
#   N       timed calls per series (default 200000).
#   PRIO    SCHED_FIFO priority for the bench thread (default 20).
#
PUBLIC=/dev/vendor_can
BACKEND=/dev/.splint/vendor_can
CTL=/dev/splint/ctl
N=${N:-200000}
PRIO=${PRIO:-20}

BIN=${BIN:-$(dirname "$0")}
cd "$BIN" || exit 1

run_as() {
    _t=$1; shift
    if [ "$SECPOL" = 1 ]; then on -T "$_t" "$@"; else "$@"; fi
}

cleanup() {
    [ -n "$LOAD_PID" ] && kill "$LOAD_PID" 2>/dev/null
    [ -n "$SPLINTD_PID" ] && kill "$SPLINTD_PID" 2>/dev/null
    [ -n "$DRIVER_PID" ] && kill "$DRIVER_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

banner() { echo; echo "=== $* ==="; }

banner "start driver (relocated) and splintd, empty ruleset"
run_as vendor_can_t ./vendor_can -p "$BACKEND" >/tmp/vendor_can.log 2>&1 &
DRIVER_PID=$!
sleep 1
run_as splintd_t ./splintd -r empty.rules -m "$PUBLIC=$BACKEND" -c "$CTL" \
    >/tmp/splintd.log 2>&1 &
SPLINTD_PID=$!
sleep 1
ls -l "$PUBLIC"

if [ "$LOAD" = 1 ]; then
    banner "background load: a client flooding splintd during the measurement"
    ( while true; do run_as can_client_t ./can_client -p "$PUBLIC" -n 2000 -r 0 \
        >/dev/null 2>&1; done ) &
    LOAD_PID=$!
    sleep 1
fi

banner "measure per-message latency (n=$N, SCHED_FIFO prio=$PRIO)"
if [ "$SECPOL" = 1 ]; then
    run_as can_client_t ./bench_ipc -n "$N" -w 2000 -P "$PUBLIC" -b none -p "$PRIO"
else
    ./bench_ipc -n "$N" -w 2000 -P "$PUBLIC" -b "$BACKEND" -p "$PRIO"
fi

banner "done"
