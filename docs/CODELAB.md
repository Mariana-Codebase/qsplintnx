# QSplintNX codelab: virtual-patch a QNX driver without touching it

This walkthrough takes you from an empty QNX SDP to a running demo where a
deliberately vulnerable driver is protected, live, by a one-line rule. Along the
way it explains the QNX mechanisms that make it work. It should take about 30
minutes. You need QNX SDP 8.0 and, to run on a target, QEMU with KVM.

## 0. The idea in one paragraph

On QNX, a driver is usually a *resource manager*: a process that registers a name
like `/dev/vendor_can` and answers the messages clients send to it (`open`,
`read`, `write`, `devctl`). Because clients talk to a name and not to a process,
you can put a second resource manager on that name that resolves first, inspects
each message, and forwards the good ones to the real driver. That interposer is
`splintd`. A rule can then block a specific malformed message, the one that
triggers a known bug, before it reaches the driver, so you neutralize a
vulnerability without changing or restarting the driver.

## 1. Build the portable core and run the tests

The decision engine, rule parser, learn mode and signature verification are
plain C with no QNX dependency, so you can build and test them on your host:

    make test        # five C suites + policy-generator tests
    make sanitize    # the same under AddressSanitizer / UBSan

You should see `ALL TESTS PASSED`. This is the part of the system that decides,
for a given message, allow or block. Reading `tests/test_engine.c` is a good way
to see exactly what the engine does.

## 2. Build for QNX

Source the SDP environment and cross-compile:

    source ~/qnx800/qnxsdp-env.sh
    make qnx

This produces `splintd`, the control client `splintctl`, the offline signer
`splint-sign`, the benchmark `bench_ipc`, and the demo driver and clients, all
for `gcc_ntox86_64`.

## 3. Meet the vulnerable driver

`demo/vendor_can/vendor_can.c` is a stand-in CAN driver with a planted bug
(`CVE-DEMO-0042`): its `SET_FILTER` devctl copies the client's payload into a
64-byte table *without checking the length*. The table ends against a guard page,
so an oversized `SET_FILTER` runs off the end and the driver takes a clean
SIGSEGV. This is the kind of memory-safety bug a supplier binary might ship.

`demo/clients/exploit.c` sends that oversized `SET_FILTER`.
`demo/clients/can_client.c` is a well-behaved client.

## 4. Write the virtual patch

A patch is a short rule. `demo/rules/cve-demo-0042.rules`:

    patch CVE-DEMO-0042 {
      path   /dev/vendor_can
      match  devctl 0x0505        # SET_FILTER
      when   len > 64             # bigger than the table
      action block, log
    }

Read it as: on the public path, for a `SET_FILTER` devctl whose real payload is
larger than 64 bytes, block and log. The rule language is deliberately small (no
loops, no regex) so the cost of checking a message is bounded. The full grammar
is in `docs/RULES.md`.

## 5. Sign the ruleset

`splintd` refuses to load a ruleset that is not signed by a trusted key, so an
attacker who can write the rules directory cannot slip in their own policy. Sign
with the demo key:

    ./build/host/splint-sign sign demo/keys/demo.key demo/rules/cve-demo-0042.rules

This writes `cve-demo-0042.rules.sig`. The public key is compiled into `splintd`
(`include/splint/splint_pubkey.h`); for a real deployment you generate your own
keypair with `splint-sign keygen` and keep the private key offline. See
`docs/INTEGRITY.md`.

## 6. Generate the security policy and build a QNX image

secpol is what makes the mediation un-bypassable. `tools/secpolgen` turns a small
JSON description into a policy that types the channels so that only `splintd` can
reach the driver, and only `splintctl` can reach the control node:

    python3 tools/secpolgen/secpolgen.py tools/secpolgen/example.json \
        -o demo/secpol/qsplint.secpol
    mkqnximage --secpol=develop --policy=demo/secpol/qsplint.secpol --clean

Boot the resulting image under QEMU (KVM if available). Copy the binaries, the
signed rules and `demo/*.sh` onto the target; the demo uses a small FAT payload
drive, but any transport works.

## 7. Run the demo and watch the patch work

On the target:

    SECPOL=1 ./run_demo.sh

Step by step it: starts the driver on a hidden backend path, puts `splintd` on
the public `/dev/vendor_can`, shows a normal client working, fires the exploit
and watches the *unpatched* driver crash, restarts the driver and loads the
signed patch live with `splintctl reload`, fires the exploit again and watches it
*blocked* while traffic keeps flowing, then shows that the driver channel cannot
be reached directly (secpol) and that the control channel is isolated.

The key moment is step 6: the same attack that crashed the driver in step 4 is
now refused, and nothing in the driver changed.

## 8. Explore the security properties

Each of these is its own short script, and each has a matching section in
`docs/qemu-validation.md`:

- `./run_shadow.sh` — interpose on the driver's *original* path with
  `_RESMGR_FLAG_BEFORE`, no relocation.
- `LOAD=1 ./run_bench.sh` — per-message latency, min/p50/p99, under a flood.
- `SECPOL=1 ./run_fail.sh` — what happens when `splintd` crashes: relocated mode
  fails closed (the driver is never re-exposed), shadow mode fails open.
- `SECPOL=1 ./run_watchdog.sh` — a liveness watchdog catches a `splintd` that is
  alive but wedged and forces a respawn.

Try the integrity properties by hand: sign `patch-v1.rules` and `patch-v2.rules`,
start with v2, and watch `splintctl reload patch-v1.rules` be refused as a
rollback even though its signature is valid. Tamper a signed ruleset by appending
a byte and watch the reload be refused as a signature failure.

## 9. Read the author's identity out of the binary

Authorship is built into the binaries, not just the source:

    readelf -p .qsplintnx.identity splintd
    # -> QSplintNX by MarianaCodebase
    ./splintctl --version

## Where to go next

`SUBMISSION.md` summarizes the project and its evidence. `docs/RULES.md` is the
rule language, `docs/INTEGRITY.md` the signing and anti-rollback design,
`docs/AVAILABILITY.md` the crash and recovery behaviour, and
`docs/qemu-validation.md` the full on-target transcripts.
