#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Boot / manage the QSplintNX QEMU image built by tools/qemu/build_image.sh.
#
# STATUS: written against QNX SDP 8.0 docs, not yet run on a host with the SDP.
#
# usage: tools/qemu/run.sh [--vm DIR] [--sdp DIR] [ACTION]
#   (no action)       boot in the foreground (mkqnximage --run)
#   --headless        boot headless in the background (mkqnximage --run=-h)
#   --stop            stop the running image (mkqnximage --stop)
#   --ip              print the image's IP address (mkqnximage --getip)
#   --ssh             ssh root@<ip>
#   --push            copy the staged files to /data/qsplintnx over scp
#                     (fallback if the data_files snippet did not work)
#   --fetch-policy    sftp /dev/secpolgenerate/policy from an image built with
#                     --secpol open into <vm>/secpolgenerate.policy, ready for
#                     build_image.sh --secpol secure --policy-base
#
# mkqnximage reference (8.0):
#   https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mkqnximage.html
#   https://qnx.com/developers/docs/8.0/com.qnx.doc.security.system/topic/manual/mkqnximage_secpol.html
set -euo pipefail

SDP="${QNX_SDP:-$HOME/qnx800}"
VM="$HOME/qsplintnx-vm"
ACTION="run"

die() { echo "run: $*" >&2; exit 1; }
usage() { sed -n '/^# usage:/,/^# mkqnximage reference/p' "$0" | sed '$d; s/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
    --vm)           VM="${2:?--vm needs a value}"; shift 2 ;;
    --sdp)          SDP="${2:?--sdp needs a value}"; shift 2 ;;
    --headless)     ACTION="headless"; shift ;;
    --stop)         ACTION="stop"; shift ;;
    --ip)           ACTION="ip"; shift ;;
    --ssh)          ACTION="ssh"; shift ;;
    --push)         ACTION="push"; shift ;;
    --fetch-policy) ACTION="fetch-policy"; shift ;;
    -h|--help)      usage; exit 0 ;;
    *)              usage >&2; die "unknown option: $1" ;;
    esac
done

[ -d "$VM/output" ] || die "$VM/output not found: run tools/qemu/build_image.sh first"
[ -r "$SDP/qnxsdp-env.sh" ] || die "$SDP/qnxsdp-env.sh not found"
set +u
# shellcheck disable=SC1091
. "$SDP/qnxsdp-env.sh" >/dev/null
set -u
command -v mkqnximage >/dev/null || die "mkqnximage not in PATH"
cd "$VM"

kvm_check() {
    if [ -e /dev/kvm ] && [ -w /dev/kvm ]; then
        echo "run: /dev/kvm is usable"
    else
        echo "run: warning: /dev/kvm not usable, QEMU falls back to TCG (slow;" >&2
        echo "     latency numbers from such a run are not representative)." >&2
        echo "     fix: sudo usermod -aG kvm \"${USER:-$(id -un)}\", then wsl --shutdown" >&2
    fi
    # VERIFY-ON-TARGET: whether mkqnximage's QEMU launcher enables KVM by
    # itself. Look for it in the generated build files.
    if grep -rqsE -- '-enable-kvm|accel=kvm' output/ local/ 2>/dev/null; then
        echo "run: generated QEMU command enables KVM"
    else
        echo "run: note: could not confirm KVM in mkqnximage's QEMU command line;" >&2
        echo "     check 'ps -ef | grep qemu' after boot" >&2
    fi
}

target_ip() {
    local ip
    ip="$(mkqnximage --getip | tail -n1 | tr -d '[:space:]')"
    [ -n "$ip" ] || die "could not get the image's IP (is it running?)"
    printf '%s\n' "$ip"
}

case "$ACTION" in
run)
    kvm_check
    exec mkqnximage --run
    ;;
headless)
    kvm_check
    mkqnximage --run=-h
    echo "run: started headless; IP: $(target_ip)"
    ;;
stop)
    mkqnximage --stop
    ;;
ip)
    target_ip
    ;;
ssh)
    exec ssh "root@$(target_ip)"
    ;;
push)
    [ -d "$VM/local/qsplintnx" ] || die "nothing staged: run build_image.sh first"
    ip="$(target_ip)"
    # VERIFY-ON-TARGET: root ssh login (see mkqnximage --ssh-ident) and that
    # /data is writable by root.
    ssh "root@$ip" 'mkdir -p /data/qsplintnx'
    scp -r "$VM/local/qsplintnx/." "root@$ip:/data/qsplintnx/"
    ssh "root@$ip" 'chmod 0755 /data/qsplintnx/bin/* /data/qsplintnx/*.sh /data/qsplintnx/secpol/*.sh 2>/dev/null; ls -lR /data/qsplintnx'
    ;;
fetch-policy)
    ip="$(target_ip)"
    out="$VM/secpolgenerate.policy"
    # Same steps as the mkqnximage "Secpol and policy options" page.
    printf 'get /dev/secpolgenerate/policy %s\nquit\n' "$out" | sftp -b - "root@$ip"
    echo "run: wrote $out"
    echo "run: next: tools/qemu/build_image.sh --secpol secure --policy-base $out"
    ;;
esac
