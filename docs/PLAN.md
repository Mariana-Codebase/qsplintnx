# QSplintNX development plan

Deadline: QNX Global Hackathon, 15 Dec 2026 14:00 ET. Category:
Automotive & Mobility. Bonus targets: Best use of QNX-specific
Technologies, Best Codelab / Tutorial.

## What QSplintNX is

Virtual patching for QNX 8 resource managers. A daemon (`splintd`) sits in
front of a driver in the QNX pathname space, inspects every message by
protocol semantics (operation, devctl code, declared vs real length,
payload fields) and blocks the ones that match a known exploit, with no
change to the driver and no restart. secpol closes the bypass. Rules are a
tiny bounded language (docs/RULES.md) so the worst-case decision time is
known, and the overhead is measured in microseconds on target.

## Environment (Mariana's PC)

Windows 11, WSL2 Ubuntu 24.04 with /dev/kvm, 16 cores, 15 GB RAM.
To install by hand (needs sudo / myQNX account):
`qemu-system-x86 qemu-utils cmake`, user in group `kvm`, QNX Software
Center + SDP 8.0 in `~/qnx800`, empty public repo
`Mariana-Codebase/qsplintnx`.

## Spikes (do first on target, they can kill the design)

* S1 shadow backend: two resmgrs on the same path, the BEFORE one
  returns ENOENT to its own pid. Does splintd's open reach the driver?
  If not, ship relocated mode only and say so in the README.
* S2 secpol bypass closure: with `mkqnximage --secpol`, can a client of
  type other than splintd_t open the hidden backend path or ConnectAttach
  to the driver channel? Expected: EACCES / EPERM.
* S3 devctl forwarding: payload > 16 KB, FROM-only, TO+FROM, and
  `srcmsglen` vs header `nbytes` behaviour.

## Schedule

| Days      | Work |
|-----------|------|
| 20-22 Nov | Wave 1 (core + all components written, host tests green). Mariana installs SDP, QEMU. |
| 23-25 Nov | First qnx build, fix compile errors, spikes S1-S3 on QEMU. |
| 26 Nov-2 Dec | Demo loop end to end: vendor_can + exploit crash, patch blocks it, hot reload, learn mode. secpol image. |
| 3-6 Dec   | Benchmarks on target (ClockCycles), resfuzz against protected driver, hardening. |
| 7-10 Dec  | Docs, codelab, README with QNX evidence map, architecture diagram. |
| 11-13 Dec | Video (< 3 min), Devpost text, LinkedIn post with real screenshot. |
| 14-15 Dec | Buffer. Submit by 14 Dec. |

## Wave 1 ownership (agent army)

| Team | Sub-agent | Files |
|------|-----------|-------|
| Grammar | Lexer | src/core/rules_lexer.c, src/core/rules_format.c, tests/test_lexer.c |
| Grammar | Parser | src/core/rules_parser.c, tests/test_rules.c, tests/fuzz_rules.c, tests/corpus/* |
| Engine | Decide | src/core/engine.c, src/core/ratelimit.c, src/core/ratelimit.h, tests/test_engine.c |
| Engine | LearnLog | src/core/learn.c, src/core/log.c, tests/test_learn.c, tests/test_log.c |
| Interposer | Resmgr | src/qnx/splintd_main.c, src/qnx/interpose.c |
| Interposer | BackendCtl | src/qnx/backend.c, src/qnx/ctl.c, src/qnx/clientinfo.c |
| Demo | VendorDriver | demo/vendor_can/vendor_can.c, demo/rules/*.rules |
| Demo | Clients | demo/clients/can_client.c, demo/clients/exploit.c, demo/run_demo.sh |
| Tooling | CtlSecpol | tools/splintctl/splintctl.c, tools/secpolgen/* |
| Tooling | BenchCI | bench/bench_engine.c, bench/bench_ipc.c, .github/workflows/ci.yml, tools/qemu/* |

Foundation (Commander): include/splint/*.h, src/core/msg.c,
src/core/rules_lexer.h, src/qnx/splintd.h, demo/include/vendor_can_api.h,
tests/test_util.h, Makefile, docs/RULES.md, docs/PLAN.md.

QNX code in wave 1 is written against the QNX 8.0 documentation but cannot
be compiled until the SDP is installed. Every QNX file states that at the
top until the first `make qnx` passes.
