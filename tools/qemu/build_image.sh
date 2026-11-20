#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build the QNX binaries and a QEMU x86_64 image that carries them.
# Target host: WSL2 Ubuntu 24.04 with QNX SDP 8.0 installed in ~/qnx800.
#
# STATUS: written against QNX SDP 8.0 docs, not yet run on a host with the SDP.
#
# usage: tools/qemu/build_image.sh [options]
#   --sdp DIR           SDP install dir (default: $QNX_SDP or ~/qnx800)
#   --vm DIR            mkqnximage working dir (default: ~/qsplintnx-vm)
#   --secpol MODE       no | open | secure (default: no)
#                         open:   all processes unconstrained, policy generation
#                                 on; run the demo, then fetch the generated base
#                                 policy with: tools/qemu/run.sh --fetch-policy
#                         secure: needs --policy-base; boots with
#                                 base policy + secpolgen fragment
#   --policy-base FILE  base policy (e.g. /dev/secpolgenerate/policy from an
#                       open-mode run); merged with secpolgen's output
#   --secpol-config F   secpolgen JSON (default: tools/secpolgen/example.json)
#   --no-make           skip `make qnx`
#   --clean             pass --clean to mkqnximage (full rebuild)
#   --run               boot the image when done (tools/qemu/run.sh)
#
# mkqnximage reference (8.0):
#   https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mkqnximage.html
#   https://qnx.com/developers/docs/8.0/com.qnx.doc.security.system/topic/manual/mkqnximage_secpol.html
# Files are added through a local/snippets/data_files.custom snippet
# (mkqnx6fsimg buildfile format, "[attributes] target=host"); the data
# partition is mounted read-write at /data on the target.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SDP="${QNX_SDP:-$HOME/qnx800}"
VM="$HOME/qsplintnx-vm"
SECPOL="no"
POLICY_BASE=""
SECPOL_CONFIG="$REPO/tools/secpolgen/example.json"
DO_MAKE=1
CLEAN=""
RUN=0
QARCH="${QARCH:-gcc_ntox86_64}"
# Target directory, relative to the data partition root -> /data/qsplintnx.
# VERIFY-ON-TARGET: that data_files targets are relative to /data.
TARGET_REL="qsplintnx"

die() { echo "build_image: $*" >&2; exit 1; }
log() { echo "build_image: $*"; }

usage() { sed -n '/^# usage:/,/^# mkqnximage reference/p' "$0" | sed '$d; s/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
    --sdp)            SDP="${2:?--sdp needs a value}"; shift 2 ;;
    --vm)             VM="${2:?--vm needs a value}"; shift 2 ;;
    --secpol)         SECPOL="${2:?--secpol needs a value}"; shift 2 ;;
    --policy-base)    POLICY_BASE="${2:?--policy-base needs a value}"; shift 2 ;;
    --secpol-config)  SECPOL_CONFIG="${2:?--secpol-config needs a value}"; shift 2 ;;
    --no-make)        DO_MAKE=0; shift ;;
    --clean)          CLEAN="--clean"; shift ;;
    --run)            RUN=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    *)                usage >&2; die "unknown option: $1" ;;
    esac
done

case "$SECPOL" in
no|open|secure) ;;
*) die "--secpol must be no, open or secure" ;;
esac
if [ "$SECPOL" = secure ] && [ -z "$POLICY_BASE" ]; then
    die "--secpol secure needs --policy-base: the secpolgen output is a fragment and
  a secure image without types for every system service does not boot.
  Build with --secpol open first, run the demo, fetch the generated policy
  (tools/qemu/run.sh --fetch-policy), then pass it here."
fi
[ -z "$POLICY_BASE" ] || [ -r "$POLICY_BASE" ] || die "cannot read $POLICY_BASE"

# ---- SDP environment ------------------------------------------------------
[ -r "$SDP/qnxsdp-env.sh" ] || die "$SDP/qnxsdp-env.sh not found (install SDP 8.0 or use --sdp)"
set +u   # the SDP env script may reference unset variables
# shellcheck disable=SC1091
. "$SDP/qnxsdp-env.sh" >/dev/null
set -u
[ -n "${QNX_TARGET:-}" ] || die "QNX_TARGET not set after sourcing qnxsdp-env.sh"
command -v mkqnximage >/dev/null || die "mkqnximage not in PATH after sourcing qnxsdp-env.sh"
command -v qemu-system-x86_64 >/dev/null || die "qemu-system-x86_64 missing: sudo apt install qemu-system-x86"
if [ ! -w /dev/kvm ]; then
    echo "build_image: warning: /dev/kvm not writable; QEMU will be slow." >&2
    echo "  fix: sudo usermod -aG kvm \"${USER:-$(id -un)}\" and restart WSL (wsl --shutdown)" >&2
fi

# ---- QNX binaries ---------------------------------------------------------
BIN="$REPO/build/qnx-$QARCH"
if [ "$DO_MAKE" -eq 1 ]; then
    log "make qnx"
    make -C "$REPO" qnx QARCH="$QARCH"
fi
for b in splintd splintctl vendor_can can_client exploit bench_ipc; do
    [ -x "$BIN/$b" ] || die "missing $BIN/$b (did make qnx succeed?)"
done

# ---- staging --------------------------------------------------------------
mkdir -p "$VM/local/snippets"
STAGE="$VM/local/qsplintnx"
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/rules" "$STAGE/secpol"
cp "$BIN"/splintd "$BIN"/splintctl "$BIN"/vendor_can "$BIN"/can_client \
   "$BIN"/exploit "$BIN"/bench_ipc "$STAGE/bin/"
if compgen -G "$REPO/demo/rules/*" >/dev/null; then
    cp "$REPO"/demo/rules/* "$STAGE/rules/"
else
    echo "build_image: warning: no demo/rules/* yet" >&2
fi
if [ -f "$REPO/demo/run_demo.sh" ]; then
    cp "$REPO/demo/run_demo.sh" "$STAGE/"
else
    echo "build_image: warning: demo/run_demo.sh not found" >&2
fi

# secpol artefacts are always shipped so the S2 test can run on any image.
python3 "$REPO/tools/secpolgen/secpolgen.py" "$SECPOL_CONFIG" --check-bypass \
    -o "$STAGE/secpol/check_bypass.sh"
POLICY_OUT="$VM/qsplintnx.secpol"
if [ -n "$POLICY_BASE" ]; then
    python3 "$REPO/tools/secpolgen/secpolgen.py" "$SECPOL_CONFIG" \
        --base "$POLICY_BASE" -o "$POLICY_OUT"
else
    python3 "$REPO/tools/secpolgen/secpolgen.py" "$SECPOL_CONFIG" -o "$POLICY_OUT"
fi
cp "$POLICY_OUT" "$STAGE/secpol/"

# ---- data_files snippet -----------------------------------------------------
# mkqnx6fsimg buildfile lines: "[perms=0755] target=host". The snippet is
# regenerated on every run; edit this script, not the snippet.
# VERIFY-ON-TARGET: intermediate directories are created by mkqnx6fsimg,
# and a pre-created local/snippets is honoured on the first build.
SNIP="$VM/local/snippets/data_files.custom"
{
    echo "# generated by qsplintnx tools/qemu/build_image.sh - do not edit"
    find "$STAGE" -type f | sort | while read -r f; do
        rel="${f#"$STAGE"/}"
        case "$rel" in
        bin/*|*.sh) perms=0755 ;;
        *)          perms=0644 ;;
        esac
        echo "[uid=0 gid=0 perms=$perms] $TARGET_REL/$rel=$f"
    done
} > "$SNIP"
log "wrote $SNIP ($(grep -vc '^#' "$SNIP") files -> /data/$TARGET_REL)"

# ---- image ----------------------------------------------------------------
MK=(mkqnximage --type=qemu --arch=x86_64 --build)
[ -z "$CLEAN" ] || MK+=("$CLEAN")
case "$SECPOL" in
no)     MK+=(--secpol=no --policy=none) ;;
open)   MK+=(--secpol=open --policy=none) ;;
secure) MK+=(--secpol=secure "--policy=$POLICY_OUT") ;;
esac
log "cd $VM && ${MK[*]}"
(cd "$VM" && "${MK[@]}")
log "image ready in $VM/output (secpol=$SECPOL)"
log "on target: cd /data/$TARGET_REL && sh ./run_demo.sh"

if [ "$RUN" -eq 1 ]; then
    exec "$REPO/tools/qemu/run.sh" --vm "$VM" --sdp "$SDP"
fi
