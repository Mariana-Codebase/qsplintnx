<!-- SPDX-License-Identifier: Apache-2.0 -->
# QSplintNX

Virtual patching for QNX 8 resource managers.

When a driver on a QNX system has a known vulnerability and ships as a
binary from a supplier, the integrator cannot rebuild it and has to wait
for a fixed binary. On the web this gap is covered by virtual patching: a
rule in a WAF or IPS blocks the exploit while the real fix is prepared.
QSplintNX brings that idea inside the operating system. A daemon,
`splintd`, sits in front of a driver in the QNX pathname space, inspects
every message by its protocol semantics (operation, devctl code, declared
versus real length, payload fields) and blocks the ones that match a known
exploit, with no change to the driver and no restart.

Concretely, `splintd` owns the driver's public path: in relocated mode the
real driver is started on a private path and `splintd` registers the public
one; in shadow mode `splintd` attaches the same path ahead of the driver
with `_RESMGR_FLAG_BEFORE`. Either way a client's `open`/`read`/`write`/
`devctl` messages land on `splintd`, which runs them past the ruleset and
forwards the allowed ones to the real driver over its own connection. A QNX
security policy (secpol) grants `channel connect` to the driver's channel
only to `splintd`'s type, so no other process can reach the driver except
through `splintd`; that is what closes the bypass.

Inspection is stateless and per-message: each message is judged on its own
operation, devctl code, declared-versus-actual length and fixed-offset
payload fields. This catches the classic length-confusion, bad-command and
malformed-argument bugs. It deliberately does not reconstruct deep stateful
protocol sequences across many messages, and it does not see data a client
moves out of band through shared memory; those are out of scope.

The rule language is deliberately small, with no loops and no regular
expressions, so the worst-case cost of checking one message is bounded. On
a real-time system that bound matters as much as the block itself. On the
development host the engine decides a message in tens of nanoseconds (about
23 ns against an empty ruleset, growing roughly 43 ns per patch in the
worst case where every patch is evaluated); the end-to-end IPC overhead
`splintd` adds on a QNX target is measured by `bench/bench_ipc` and the
numbers are reported with the target and build once collected.

## Status

QNX Global Hackathon 2026 entry, Automotive & Mobility. Under active
development. The portable core (rule language, decision engine, learn
mode, event log) builds and is unit-tested on Linux; the QNX daemon and
tools are written against the QNX SDP 8.0 documentation and are validated
on a QEMU target as the SDK is installed.

## Layout

    include/splint/   public headers (portable)
    src/core/         rule language, engine, learn mode, log (portable C11)
    src/qnx/          splintd: the QNX interposing resource manager
    tools/splintctl/  control client (reload, stats, events, learn-dump)
    tools/secpolgen/  generate the secpol policy that closes the bypass
    bench/            host engine benchmark and on-target IPC benchmark
    demo/             vendor driver scenario, clients, rules, run script
    docs/RULES.md     the rule language, normative
    docs/PLAN.md      development plan and on-target spikes

## Build

Host (Linux, gcc):

    make test        # build the core and run all unit tests
    make sanitize    # the same under AddressSanitizer + UBSan
    make bench       # engine latency micro-benchmark

QNX (after installing QNX SDP 8.0 and sourcing its environment):

    source ~/qnx800/qnxsdp-env.sh
    make qnx

## License

Apache-2.0. See LICENSE.
