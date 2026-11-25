# ed25519-ref (vendored)

Ed25519 signature verification, the SUPERCOP `ref` implementation as vendored in
the [python-ed25519](https://pypi.org/project/ed25519/) package by Brian Warner.

- **License:** public domain.
- **Use in QSplintNX:** `splintd` verifies the detached Ed25519 signature of a
  ruleset before activating it (`src/core/splint_sig.c` wraps the attached-
  signature API as detached verification). The offline signer is
  `tools/splint-sign`.
- **Files:** `ed25519.c`, `fe25519.c`, `ge25519.c`, `sc25519.c`, `verify.c`,
  `sha512-hash.c`, `sha512-blocks.c`, `ge25519_base.data`, and headers. Built
  verbatim with warnings disabled; QSplintNX code is not mixed into these files.
- **Verification:** `tests/test_sig.c` checks an RFC 8032 interop vector produced
  independently by Python's `cryptography` library, plus round-trip, wrong-key
  and tamper cases.
