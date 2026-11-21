<!-- SPDX-License-Identifier: Apache-2.0 -->
# QEMU validation (QNX 8.0, x86_64)

This records the first end-to-end run of QSplintNX on a real QNX 8.0 system.
The image was built with `mkqnximage --type=qemu` and booted under
`qemu-system-x86_64 --enable-kvm`. The six binaries, the rule files and the
clients were cross-compiled with `qcc` (gcc 12.2, target `gcc_ntox86_64`).

Setup inside the guest:

    vendor_can                                   # driver on /dev/.splint/vendor_can
    splintd -r empty.rules -m /dev/vendor_can=/dev/.splint/vendor_can

## Interposition and forwarding (spike S1 / S3)

A normal client speaking to the public path `/dev/vendor_can`, which `splintd`
owns, is forwarded to the real driver and works:

    can_client: connected to /dev/vendor_can (tx=0 rx=0 filters=0)
    can_client: done, sent=100 errors=0      (rc=0)

This exercised `open`, `devctl` GET_STATUS, a 32-byte SET_FILTER and SEND_FRAME
through `splintd` to the driver. (The first on-target bug was here: the QNX
connect `ioflag` had to be translated to POSIX open flags, otherwise the backend
`open()` failed with EACCES.)

The run above uses relocated mode: the driver sits on a hidden backend path and
`splintd` owns the public name. Shadow mode is the other way to interpose, and it
needs no change to where the driver is attached. The driver keeps its original
public path `/dev/vendor_can`; `splintd` attaches the SAME path with
`_RESMGR_FLAG_BEFORE` so it resolves first, and forwards by opening that path
itself, returning ENOENT for its own pid so the open falls through to the driver
behind it (`src/qnx/interpose.c`). On target (`demo/run_shadow.sh`):

    driver:  vendor_can -p /dev/vendor_can          (original path, no move)
    splintd: splintd -s /dev/vendor_can ...         (same path, attached BEFORE)
    -> ls -l /dev/vendor_can now resolves to splintd, /dev/splint/ctl appears
    can_client -p /dev/vendor_can -n 100 -> sent=100 errors=0   (through the shadow)

With the one-line patch loaded live the replayed attack is blocked and the driver
stays up, `forward errors 0`:

    splintctl reload cve-demo-0042.rules -> OK: rules activated
    exploit  -> TRIGGER: blocked (errno=1, Operation not permitted)   (exit 0)
    can_client -n 50 -> sent=50 errors=0   (driver still serving, filters intact)

So the same inspection and live patching work whether `splintd` is dropped in on
a relocated backend or shadowed onto an existing device node.

## The bug, unpatched

With an empty ruleset the oversized SET_FILTER reaches the driver and crashes it:

    TRIGGER: driver crashed        (exit 2)
    Process 692226 (vendor_can) terminated SIGSEGV code=1 fltno=11

That is the guard-page write, a clean denial-of-service crash.

## The virtual patch

Loading the one-line patch live, with no restart:

    splintctl reload cve-demo-0042.rules   ->   OK

The same attack is now blocked, while the normal client keeps working:

    TRIGGER: blocked (errno=1, Operation not permitted)    (exit 0)
    can_client: done, sent=50 errors=0                     (rc=0)

The event log attributes the block precisely:

    #1 client=exploit op=devctl dcmd=0x80400505 len=200 declared=200
       BLOCK reason=patch rule=CVE-DEMO-0042 line=4 lat=1051ns path=/dev/vendor_can

    patches 1 | decided 165 | allowed 164 | blocked 1

## Latency (measured on this QEMU/KVM target)

The deciding step for the blocked message took **1051 ns** (the `lat` field
above): the cost of running one message past the ruleset.

`bench_ipc` measured the end-to-end per-message cost, direct to the driver versus
through `splintd`, 100000 timed calls per series at SCHED_FIFO priority 20
(`cycles_per_sec=3040618666`). It reports the full distribution, not just the
median, because a filter that matters for safety is judged by its tail. Idle box:

| op          | direct p50 | via splintd p50 | overhead p50 | overhead p99 | overhead min |
|-------------|-----------:|----------------:|-------------:|-------------:|-------------:|
| get_status  |    3652 ns |        41013 ns |    +37361 ns |   +145928 ns |     +7656 ns |
| set_filter  |    3705 ns |        40665 ns |    +36960 ns |   +144076 ns |     +7673 ns |

Then the same measurement with a second client flooding `splintd` at full rate
during the run, to read the tail under contention rather than on a quiet box:

| op          | via splintd p50 | overhead p50 | overhead p99 | overhead min |
|-------------|----------------:|-------------:|-------------:|-------------:|
| get_status  |        49995 ns |    +46262 ns |   +206579 ns |     +7709 ns |
| set_filter  |        51463 ns |    +47627 ns |   +208878 ns |     +7563 ns |

So under QEMU/KVM `splintd` adds about 37 us per message at the median on an idle
box and about 47 us under a saturating second client; the 99th percentile of the
overhead sits near 145 us idle and near 207 us under load. The structural floor
is the `min` column, about 7.6 us, which is one extra IPC round trip and does not
move under load; the decision itself is ~1 us (the `lat` field above). Both
series completed with zero failed calls, and the flood did not starve the
measured client. The large `max` values this run produced (single-digit
milliseconds) are host scheduling outliers under emulation, not time spent in
`splintd`. The IPC hop is far cheaper on real silicon, so these are emulated
figures: re-measure on a board before quoting any of them as hardware results.

## secpol closes the bypass (spike S2)

The image was rebuilt with `mkqnximage --secpol=develop --policy=qsplint.secpol`,
where `qsplint.secpol` is the policy `tools/secpolgen` produces: it types the
driver's channel `vendor_can_t` and grants `channel connect` to it only to
`splintd_t`. Processes were started with their type via `on -T`:

    on -T vendor_can_t  vendor_can ...
    on -T splintd_t     splintd ...

A client type trying to reach the driver's backend channel directly is denied
by the kernel, even as root:

    on -T exploit_t  can_client -p /dev/.splint/vendor_can
    -> open(/dev/.splint/vendor_can): Operation not permitted   (rc=1)
    secpolgenerate: can_client (type:exploit_t) failed to use ability
        channel_connect:vendor_can_t as root

The legitimate route through `splintd` still works:

    on -T can_client_t  can_client -p /dev/vendor_can
    -> connected, sent=5 errors=0   (rc=0)

With the virtual patch loaded, both defenses hold at once:

    on -T exploit_t exploit -p /dev/vendor_can        # through splintd
    -> TRIGGER: blocked (errno=1, Operation not permitted)      (patch)
    on -T exploit_t exploit -p /dev/.splint/vendor_can # straight at the driver
    -> TRIGGER: cannot open ...: Operation not permitted         (secpol)
    driver: still up

So a message the patch would block cannot sidestep `splintd` by talking to the
driver directly: secpol makes `splintd` the only path to the driver's channel.

## The control channel is isolated

`splintd` serves two kinds of channel. The public device nodes share one
dispatch channel, relabeled to `splint_data_t`; the control node
`/dev/splint/ctl` sits on a second dispatch channel, relabeled to
`splint_ctl_t`. Neither uses `splintd`'s process type, so a `channel connect`
rule can allow one without allowing the other. Relabeling a channel needs the
`settypeid` ability, which the policy grants `splintd_t` for both types; the
policy then lets device-client types connect only to `splint_data_t` and lets
only `splintctl_t` connect to `splint_ctl_t`.

On the secure image, only `splintctl` reaches the control node:

    on -T splintctl_t  splintctl -c /dev/splint/ctl stats
    -> rc=0 (stats printed)

A device-client type is denied at the connect, even as root:

    on -T exploit_t    splintctl -c /dev/splint/ctl stats
    -> splintctl: cannot open /dev/splint/ctl: Operation not permitted  (rc=1)
    secpolgenerate: splintctl (type:exploit_t) failed to use ability
        channel_connect:splint_ctl_t as root

    on -T can_client_t splintctl -c /dev/splint/ctl reload empty.rules
    -> splintctl: cannot open /dev/splint/ctl: Operation not permitted  (rc=1)

So a client of a protected device cannot reload rules, read the event log, or
otherwise drive the daemon it sits behind: the control interface is reachable
only by the control client's type. A reload that is refused this way leaves the
active ruleset in place; `splintctl` reports the failure and exits non-zero.

## Concurrency: the learn-table reload race is gone

An earlier version freed the learn table on a mode switch while a worker thread
might still hold the pointer (a use-after-free on the security boundary). The
table is now allocated once and never freed while the daemon runs; an atomic
`learn_active` flag gates observation. Stress on target: a client at 200 Hz
while the ruleset was reloaded 80 times, alternating learn and enforce:

    racing reloads... reloads done
    SPLINTD_ALIVE pid=1118230

splintd stayed up. Learn mode still produces a correct profile from observed
traffic:

    splintctl learn-dump ->
    profile /dev/vendor_can {
      default block
      allow open   client "can_client"
      allow devctl 0x0501 client "can_client" maxlen 0
      allow devctl 0x0502 client "can_client" maxlen 20
      allow devctl 0x0505 client "can_client" maxlen 40
      rate 48 per s client "can_client"
    }

## Reproducing

`demo/run_demo.sh` runs the whole sequence on the target (steps 1-7 above, the
S2 bypass check at step 8 and the control-channel isolation check at step 9 when
`SECPOL=1`). `demo/run_shadow.sh` runs the shadow-mode interposition, and
`demo/run_bench.sh` runs the latency benchmark (`LOAD=1` adds a background flood,
`SECPOL=1` reports absolute through-splintd latency on the secure image). The
transcripts in this document are their output on the secure image.

Notes from this develop-mode run, to tighten in a full `--secpol=secure` policy:
`secpolgenerate` logged two uncovered accesses that develop mode allowed and a
secure policy must grant explicitly: `splintctl_t` reading the rules file on the
data filesystem (`channel_connect:devb_t`), and `splintd` reading
`/proc/<pid>/exefile` for client names. Neither affects the bypass result above.
