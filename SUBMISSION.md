# QSplintNX — QNX Global Hackathon 2026 submission

**Category:** Automotive & Mobility · **Platform:** QNX 8.0 / C · **Author:** MarianaCodebase

## The problem

A vehicle runs supplier drivers it did not write and often cannot rebuild. When a
vulnerability is found in one of those binaries, the fix depends on the supplier's
schedule, and until it ships the device is exposed. On a safety-critical system
you cannot simply take the function offline while you wait.

## What QSplintNX is

QSplintNX is live, protocol-aware virtual patching for QNX resource managers,
with kernel-enforced mediation. A daemon, `splintd`, sits in front of a driver in
the QNX pathname space and inspects every message by its protocol semantics
(operation, devctl code, declared-versus-real length, payload fields). A message
that matches a known exploit is blocked before it reaches the driver. Nothing in
the driver changes and it is never restarted. A QNX security policy (secpol)
makes `splintd` the only process that can reach the driver's channel, so the
mediation cannot be bypassed.

It is not a generic proxy dropped onto QNX. It is built out of the microkernel's
own mechanisms: resource managers and pathname interposition, typed channels,
`secpol`, and message passing. That is what lets a one-line rule neutralize a
driver bug in production without a supplier release.

## What it does, with evidence

Every claim below is reproduced on a QNX 8.0 target under QEMU/KVM. The full
transcripts are in `docs/qemu-validation.md`; the reproduction steps are in
`docs/CODELAB.md` and the README.

- **Interposition and live patching.** The driver crashes on a malformed message
  when unpatched; with a one-line rule loaded live it survives the same attack
  while legitimate traffic keeps flowing. Works in relocated mode (hidden
  backend) and shadow mode (`_RESMGR_FLAG_BEFORE` on the original path).
- **Bypass prevention.** secpol types the driver channel so only `splintd` may
  connect; a client that tries the driver path directly is refused by the kernel.
  The control channel is a separate type, reachable only by `splintctl`.
- **Forwarding integrity.** `splintd` forwards exactly the inspected bytes. A
  regression test (`demo/clients/fwdtest.c`) shows uninspected bytes reaching the
  driver with the fix removed, and none with it in place.
- **Ruleset integrity and provenance.** `splintd` refuses to activate a ruleset
  whose detached Ed25519 signature does not verify against a compiled-in key.
  Verification uses the SUPERCOP reference, checked against an RFC 8032 interop
  vector generated independently by Python's `cryptography`.
- **Anti-rollback.** A monotonic `version` inside the signed ruleset stops an
  older, still-correctly-signed policy from being replayed; `--version-store`
  persists the floor across a daemon restart.
- **Kernel-verified identity.** Authorization rules can bind to the effective
  uid/gid the kernel reports (`_client_info`), not just the spoofable executable
  name.
- **Coherent activation.** Ruleset activation returns a verifiable status, and
  the ruleset, metrics and learn state move together under a lock, with a seqlock
  giving readers a torn-free stats snapshot.
- **Availability.** In relocated mode a crash of `splintd` fails closed (the
  device goes away, the driver is never re-exposed). A supervisor respawns a
  daemon that exits; a liveness watchdog catches one that is alive but wedged.

## Performance

On QNX 8.0 under QEMU/KVM, deciding one message takes about 1 microsecond, and
the per-message overhead `splintd` adds is about 37 microseconds at the median on
an idle box (about 47 under a saturating second client), nearly all of it the
extra IPC hop rather than the decision. The documentation states plainly that
these are emulated figures and not a hard real-time guarantee; `docs/qemu-validation.md`
has the min/p50/p99 numbers and the caveats.

## Engineering process

The repository records real defects found during on-target validation, their
fixes, and regression tests, rather than a demo tuned to pass. The portable core
has five C test suites plus the policy-generator tests, run under ASan/UBSan, and
a parser fuzz target; CI runs them on every push.

## How to reproduce

`README.md` has the build and run steps; `docs/CODELAB.md` is a guided
walkthrough from an empty QNX SDP to the running demo. In short: generate the
secpol policy with `tools/secpolgen`, build an image with `mkqnximage`, boot it,
and run `demo/run_demo.sh` (and `run_shadow.sh`, `run_bench.sh`, `run_fail.sh`,
`run_watchdog.sh`).

## Honest limits and future work

- `--secpol=secure` across the whole image is base-OS policy work beyond the
  application; develop mode already enforces the project's own channel rules.
- Anti-rollback persistence uses an ordinary file; full replay resistance needs a
  hardware monotonic counter (RPMB, eFuses, a TPM NV counter).
- Timing is characterized under emulation only; a WCET analysis and a physical
  ARM64 board are the next step for a hard real-time claim.
- Inspection is per message; stateful multi-message protocols and shared-memory
  interactions are not yet covered.

These are stated so the scope is clear. The security properties that are claimed
are the ones demonstrated on target.
