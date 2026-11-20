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

## Still to validate

- Spike S2: build the image with `--secpol=secure` and confirm a non-`splintd`
  client cannot connect to the relocated backend channel (EACCES/EPERM), i.e.
  that the bypass is actually closed, not just unused.
