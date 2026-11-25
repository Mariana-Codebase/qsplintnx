# Ruleset integrity and provenance

A virtual patch changes how a protected device behaves, so the authority to load
one matters as much as the control channel that carries it. QSplintNX will not
activate a ruleset unless it carries a valid Ed25519 signature from a trusted
key. That gives two things at once: integrity (the bytes were not altered) and
provenance (they came from the holder of the signing key).

## How it works

The signed artifact is the exact bytes of the rules file. A detached signature
lives beside it as `<rules>.sig` (64 raw bytes). The trusted public key is
compiled into `splintd` (`include/splint/splint_pubkey.h`), so a reload cannot
swap the key the daemon trusts. Signing is an offline step; `splintd` only ever
verifies.

Verification sits in the single ruleset-load path (`splintd_load_rules`), which
startup, `SIGHUP` and the control-channel reload all funnel through. The daemon
reads the rules bytes and `<rules>.sig`, checks the signature with the compiled
key, and only then parses and activates. A missing signature, a short signature,
or one that does not verify is refused, and the running ruleset is left in place
(the fail-safe reload behaviour). `--no-verify` disables the check for
development only.

The implementation is the SUPERCOP ed25519 reference (public domain), vendored
under `third_party/ed25519-ref` and wrapped as detached verification in
`src/core/splint_sig.c`. `tests/test_sig.c` checks it against an RFC 8032 interop
vector produced independently by Python's `cryptography` library, so the host
suite proves the verifier accepts real RFC 8032 signatures, not only its own.

## Signing workflow

    splint-sign keygen ops                 # ops.key (secret, keep offline), ops.pub
    splint-sign header ops.pub > include/splint/splint_pubkey.h
    splint-sign sign ops.key my.rules      # -> my.rules.sig
    splint-sign verify ops.pub my.rules    # optional local check

The demo uses a throwaway key under `demo/keys`; see that folder's README.

## On-target behaviour

On the QNX 8.0 QEMU/KVM target, `splintd` loads a signed ruleset and reports its
provenance, refuses a tampered or unsigned one, and keeps the active ruleset:

    splintd -r empty.rules ...
    -> splintd: QSplintNX by MarianaCodebase; ruleset empty.rules signature verified (provenance OK)

    splintctl reload cve-demo-0042.rules   (signed)
    -> OK: rules activated

    splintctl reload tampered.rules        (bytes changed, old .sig)
    -> signature check failed for tampered.rules (wrong key or tampered)
    -> reload not applied; the previous ruleset is still active   (exit 1)

    splintctl reload unsigned.rules        (no .sig)
    -> unsigned ruleset unsigned.rules.sig; sign it with splint-sign
    -> reload not applied; the previous ruleset is still active   (exit 1)

    splintctl stats -> patches 1   (the signed patch is still active)

## Anti-rollback: a signature is not freshness

A valid signature proves a ruleset is authentic, not that it is the current one.
Without more, an attacker who can write the rules directory could replace the
active ruleset with an older, still-correctly-signed one, for example to
reinstate a policy from before a patch was added. QSplintNX closes that with a
monotonic version: a ruleset may carry `version N` (integrity-protected, since
the whole file is signed), and `splintd` refuses to activate a ruleset that does
not advance the highest version it has seen. Once a versioned ruleset is active,
an unversioned one is refused too.

    splintctl reload patch-v2.rules   (version 2, signed)  -> OK
    splintctl reload patch-v1.rules   (version 1, signed)
    -> rollback refused: version 1 is not newer than active 2
    -> reload not applied; the previous ruleset is still active
    splintctl reload empty.rules      (unversioned, signed)
    -> rollback refused: unversioned ruleset while version 2 is active
    splintctl reload patch-v3.rules   (version 3, signed)  -> OK

The counter lives in the daemon for its lifetime. Persisting it across restarts
so a reboot cannot reset it needs rollback-resistant storage (a monotonic
counter in secure hardware, or a replay-protected file); that is the honest next
step, noted rather than claimed.

## Authorship as part of the binary

Beyond provenance of rulesets, the project's own identity is built in. Every
binary carries `QSplintNX by MarianaCodebase` in the ELF section
`.qsplintnx.identity`:

    readelf -p .qsplintnx.identity splintd
    -> QSplintNX by MarianaCodebase

`splintctl --version` (and `splintd --version`) print a banner naming the author
and the cryptographic-verification capability, `splintd` logs the identity and
provenance on load, and `NOTICE` records the Apache-2.0 copyright and the
third-party attribution for the vendored ed25519 reference.

## Limits

The signature authenticates the ruleset, not the operator who triggered the
reload; the control channel's secpol typing is what restricts who may reload at
all (see `docs/AVAILABILITY.md` and the secpol sections of
`docs/qemu-validation.md`). Key provisioning here is the simplest workable form,
one compiled-in key; rotation, multiple signers, or a key stored in secure
hardware are the natural next steps for a production deployment.
