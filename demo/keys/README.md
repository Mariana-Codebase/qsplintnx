# Demo signing keys

**These are throwaway demo keys, not secrets.** `demo.key` is committed only so
anyone can reproduce ruleset signing for the demo. It protects nothing real.

- `demo.key` - 64-byte Ed25519 secret key (seed + public key).
- `demo.pub` - 32-byte Ed25519 public key.

`demo.pub` is compiled into `splintd` via `include/splint/splint_pubkey.h`, so
`splintd` trusts rulesets signed with `demo.key`.

For a real deployment:

1. Generate a keypair offline and keep the `.key` off the build host:
   `splint-sign keygen ops`  ->  `ops.key` (secret), `ops.pub`
2. Compile the public key into `splintd`:
   `splint-sign header ops.pub > include/splint/splint_pubkey.h`
3. Sign each ruleset before shipping it:
   `splint-sign sign ops.key my.rules`  ->  `my.rules.sig`

`splintd` verifies the detached signature before activating any ruleset and
refuses one that is unsigned or tampered; `--no-verify` disables the check for
development only.
