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
through `splintd` (20000 iterations, `cycles_per_sec=3044152618`):

| op          | direct p50 | via splintd p50 | overhead p50 |
|-------------|-----------:|----------------:|-------------:|
| get_status  |    4405 ns |        36224 ns |   +31819 ns  |
| set_filter  |    3732 ns |        36498 ns |   +32766 ns  |

So under QEMU/KVM `splintd` adds about 32 us per message at the median, of which
the decision is ~1 us and the rest is the extra IPC hop to the backend. On real
hardware the IPC hop is far cheaper; these numbers are the emulated figures and
should be re-measured on a board before being quoted as hardware results.

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

`demo/run_demo.sh` runs the whole sequence on the target (steps 1-7 above, and
step 8, the bypass check, when `SECPOL=1`). The transcript in this document is
its output on the secure image.

Notes from this develop-mode run, to tighten in a full `--secpol=secure` policy:
`secpolgenerate` logged two uncovered accesses that develop mode allowed and a
secure policy must grant explicitly: `splintctl_t` reading the rules file on the
data filesystem (`channel_connect:devb_t`), and `splintd` reading
`/proc/<pid>/exefile` for client names. Neither affects the bypass result above.
