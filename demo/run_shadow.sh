#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# QSplintNX shadow-mode demo (spike S1), run ON a QNX 8.0 target.
#
# Shadow mode leaves the driver on its ORIGINAL public path and puts splintd
# on the SAME path with _RESMGR_FLAG_BEFORE, so splintd resolves first. No
# relocation, no change to how the driver is started: the path clients already
# use is now inspected. splintd forwards by opening the same path; it returns
# ENOENT for its own pid so that open falls through to the driver behind it.
#
# Environment:
#   BIN     directory with the binaries and rules (default: the script's dir)
#   SECPOL  if 1, start each process with its secpol type via `on -T`.
#
PUBLIC=/dev/vendor_can
CTL=/dev/splint/ctl

BIN=${BIN:-$(dirname "$0")}
cd "$BIN" || exit 1

run_as() {   # run_as TYPE cmd...   (TYPE used only when SECPOL=1)
    _t=$1; shift
    if [ "$SECPOL" = 1 ]; then on -T "$_t" "$@"; else "$@"; fi
}

cleanup() {
    [ -n "$SPLINTD_PID" ] && kill "$SPLINTD_PID" 2>/dev/null
    [ -n "$DRIVER_PID" ] && kill "$DRIVER_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

banner() { echo; echo "=== $* ==="; }

banner "1. driver on its ORIGINAL public path (no relocation)"
run_as vendor_can_t ./vendor_can -p "$PUBLIC" >/tmp/vendor_can.log 2>&1 &
DRIVER_PID=$!
sleep 1
cat /tmp/vendor_can.log
ls -l "$PUBLIC"

banner "2. splintd shadows the SAME path (attached BEFORE the driver)"
run_as splintd_t ./splintd -s "$PUBLIC" -r empty.rules -c "$CTL" \
    >/tmp/splintd.log 2>&1 &
SPLINTD_PID=$!
sleep 1
# With _RESMGR_FLAG_BEFORE splintd now owns the name: opening /dev/vendor_can
# reaches splintd first, which falls through to the driver for its own opens.
cat /tmp/splintd.log
ls -l "$PUBLIC" "$CTL"

banner "3. a normal client reaches the driver through the shadow"
run_as can_client_t ./can_client -p "$PUBLIC" -n 100 -r 50

banner "4. load the virtual patch live, then replay the attack"
run_as splintctl_t ./splintctl -c "$CTL" reload "$BIN/cve-demo-0042.rules"
run_as exploit_t ./exploit -p "$PUBLIC"
echo "(exploit exit: $? -- 0 means blocked)"

banner "5. traffic keeps flowing and the driver is still up"
run_as can_client_t ./can_client -p "$PUBLIC" -n 50 -r 50
run_as splintctl_t ./splintctl -c "$CTL" stats

banner "done"
