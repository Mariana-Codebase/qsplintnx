#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# QSplintNX demo, run ON a QNX 8.0 target (QEMU or hardware). It reproduces the
# run recorded in docs/qemu-validation.md: a vendor driver with an unpatched
# bug crashes on a malformed message, then survives the same message once a
# one-line virtual patch is loaded live, while normal traffic keeps flowing.
#
# Environment:
#   BIN     directory holding the binaries and rules (default: the script's dir)
#   SECPOL  if 1, start each process with its secpol type via `on -T` and run
#           the bypass check at the end (needs an image built with secpol and
#           the policy from demo/secpol/qsplint.secpol loaded).
#
# Paths come from demo/include/vendor_can_api.h:
PUBLIC=/dev/vendor_can
BACKEND=/dev/.splint/vendor_can
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

start_driver() {
    run_as vendor_can_t ./vendor_can -p "$BACKEND" >/tmp/vendor_can.log 2>&1 &
    DRIVER_PID=$!
    sleep 1
}

banner "1. start the vendor driver on its private backend path"
start_driver
cat /tmp/vendor_can.log

banner "2. put splintd in front, empty ruleset"
run_as splintd_t ./splintd -r empty.rules -m "$PUBLIC=$BACKEND" -c "$CTL" \
    >/tmp/splintd.log 2>&1 &
SPLINTD_PID=$!
sleep 1
ls -l "$PUBLIC" "$CTL"

banner "3. a normal client works through splintd"
run_as can_client_t ./can_client -p "$PUBLIC" -n 100 -r 50

banner "4. unpatched: the malformed message crashes the driver"
run_as exploit_t ./exploit -p "$PUBLIC"
echo "(exploit exit: $?)"

banner "5. restart the driver and load the virtual patch, live"
start_driver
run_as splintctl_t ./splintctl -c "$CTL" reload "$BIN/cve-demo-0042.rules"

banner "6. patched: the same attack is blocked, traffic keeps flowing"
run_as exploit_t ./exploit -p "$PUBLIC"
echo "(exploit exit: $?)"
run_as can_client_t ./can_client -p "$PUBLIC" -n 50 -r 50

banner "7. what splintd saw"
run_as splintctl_t ./splintctl -c "$CTL" stats
run_as splintctl_t ./splintctl -c "$CTL" events -n 8

if [ "$SECPOL" = 1 ]; then
    banner "8. secpol closes the bypass: the driver channel is unreachable directly"
    echo "# via splintd (allowed):"
    run_as exploit_t ./exploit -p "$PUBLIC";  echo "(exit $?)"
    echo "# straight at the driver (denied by secpol):"
    run_as exploit_t ./exploit -p "$BACKEND"; echo "(exit $?)"
fi

banner "done"
