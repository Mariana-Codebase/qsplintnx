<!-- SPDX-License-Identifier: Apache-2.0 -->
# Benchmarks

Two benchmarks, one per layer. `bench_engine` measures the decision
engine alone on the host. `bench_ipc` measures what an application on
QNX actually pays: a devctl() round trip to the driver with and without
splintd in the path.

## bench_engine (host)

```
make bench
```

It times `splint_engine_decide()` against rulesets built by hand in the
worst shape the rule language allows. In the `patches-N` scenarios every
patch names the message's path, op and devctl code and carries
`SPLINT_MAX_CONDS` conditions, of which all but the last hold, so no
patch matches and the engine evaluates every condition of every patch.
`profile-64` is one profile with 64 allow lines on the path, none of
which matches, so all of them are checked before the default applies.
Before timing, each scenario is checked: the bench message must be
allowed, and a copy of it that also satisfies the last condition must
be blocked, which shows the conditions are evaluated rather than
skipped.

`clock_gettime(CLOCK_MONOTONIC)` is read once per batch of 64 calls
and each sample is the batch time divided by 64, because reading the
clock costs about as much as an empty decision. The consequence is that
the percentiles are percentiles of 64-call averages: min and p50 are
close to per-call values, while p99.9 and max are smoothed by up to a
factor of 64 compared with true per-call tails. The clock overhead per
batch is printed and not subtracted. One million calls are timed per
scenario after 100000 warm-up calls.

First run, 2026-11-20, gcc 13.3 -O2, x86_64 container (2 vCPU, shared,
not isolated), engine.c as of that day:

| scenario    | patches | conds | allow |     calls |  min ns  |  p50 ns  |  p99 ns  | p99.9 ns |   max ns  |
|-------------|--------:|------:|------:|----------:|---------:|---------:|---------:|---------:|----------:|
| patches-0   |       0 |     0 |     0 |   1000000 |     22.6 |     22.6 |     25.1 |    254.2 |     545.3 |
| patches-16  |      16 |     8 |     0 |   1000000 |    655.8 |    692.0 |   1003.5 |   2299.4 |  135833.9 |
| patches-64  |      64 |     8 |     0 |   1000000 |   2583.3 |   2763.8 |   3228.2 |   4102.0 |    5555.9 |
| patches-256 |     256 |     8 |     0 |   1000000 |  10348.7 |  11194.5 |  12216.0 |  15444.6 |   47523.7 |
| profile-64  |       0 |     0 |    64 |   1000000 |     91.7 |     94.2 |    144.7 |    347.3 |    2580.6 |

The cost grows linearly at roughly 43 ns per worst-case patch, which is
what the O(npatch * SPLINT_MAX_CONDS) bound predicts. The isolated max
values come from the host being shared (a 64-call batch that was
preempted), not from the engine. Real rule files have a handful of
patches, and a patch whose path, op or code does not match costs far
less than these. Numbers on QNX in QEMU will differ and are the ones to
quote.

## bench_ipc (QNX target)

Built by `make qnx` into `build/qnx-gcc_ntox86_64/bench_ipc`.

```
bench_ipc [-n 100000] [-w 1000] [-b /dev/.splint/vendor_can|none] [-P /dev/vendor_can]
          [-p priority] [-o raw.csv]
```

For each of the backend path (the driver, directly) and the public path
(through splintd) it runs two series: `devctl(VCAN_DCMD_GET_STATUS)` and
`devctl(VCAN_DCMD_SET_FILTER)` with a 32-byte payload, which the demo
patch must let through. Each call is timed with `ClockCycles()` and
converted with `SYSPAGE_ENTRY(qtime)->cycles_per_sec`. The output is one
CSV summary row per series (`path,op,n,errors,min_ns,p50_ns,p99_ns,max_ns`)
followed by the overhead of splintd as public minus backend for min,
p50, p99 and max. `-o` writes every sample as `path,op,iter,ns`.

Notes for a meaningful run:

* Run with `-p` (SCHED_FIFO) above the load you want to exclude.
  Priorities of 64 and higher need the `PROCMGR_AID_PRIORITY` ability.
  QNX message passing makes the server thread inherit the client's
  priority, so splintd and the driver run at the bench's priority
  while they serve it.
* KVM must be enabled (see tools/qemu/README.md); TCG numbers are
  meaningless.
* On a secpol image the bench process may not connect to the driver,
  which is the point of the policy. Measure the direct series on an
  image built without secpol, or pass `-b none` and compare against an
  earlier run.
* `cycles_per_sec` is calibrated by startup at boot and can differ
  slightly between boots (ClockCycles() reference page), so compare
  series from the same boot.
* A failing devctl is counted in the `errors` column and its time is
  still recorded. A series with errors is not a valid latency figure.

VERIFY-ON-TARGET: that 32-byte SET_FILTER passes the demo rules and
the driver, and that the default paths match how run_demo.sh starts
the driver.
