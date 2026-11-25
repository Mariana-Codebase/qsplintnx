# QSplintNX rule language (normative)

This file is the contract between the parser (`src/core/rules_*.c`), the
engine (`src/core/engine.c`) and anyone writing rules. If code and this
file disagree, this file wins and the code is a bug.

The language is deliberately small. It has no loops, no regular
expressions, no variables and no user functions, so the cost of checking
one message against a compiled ruleset is bounded by
`SPLINT_MAX_RULES * SPLINT_MAX_CONDS` constant-time comparisons. That
bound is the property QSplintNX sells to a real-time system integrator.

## Lexical structure

* Encoding is ASCII. Any byte >= 0x80 outside a string is an error.
* `#` starts a comment that runs to end of line.
* Whitespace (space, tab, CR, LF) separates tokens. A newline or `;`
  terminates a statement inside a block. Both are accepted; blank
  statements are ignored.
* Identifiers: `[A-Za-z_][A-Za-z0-9_.:-]*`, max 63 chars. Keywords are
  identifiers with reserved meaning (list below) and are case sensitive.
* Integers: decimal (`64`) or hex (`0x0105`). Unsigned, must fit in 64
  bits. No size suffixes.
* Strings: double quoted, no escapes except `\"` and `\\`, max 63 chars.
* Paths: a token starting with `/`, made of `[A-Za-z0-9_./-]`, max 127
  chars.
* Punctuation: `{ } , ; [ ] ..` and comparison operators
  `== != < <= > >=`.

Keywords: `patch profile path match when and action block log allow
default rate per s client errno len declared byte u16 u32 maxlen any
open read write devctl lseek close other mode enforce learn`.

## File structure

A rules file is a sequence of top-level blocks and at most one `mode`
statement:

```
mode enforce            # or: mode learn   (default: enforce)

patch <ID> { <patch-statements> }
profile <PATH> { <profile-statements> }
```

Order of blocks in the file does not matter for semantics except that,
among patches, the first matching patch in file order is the one reported
in the verdict.

### patch blocks (virtual patches)

A patch describes one known exploit pattern. If a message matches a
patch, the patch's action applies regardless of any profile.

```
patch CVE-2026-0042 {
  path    /dev/vendor_can            # required, exact match
  match   devctl 0x0105              # required: <op> [<code>]
  when    len > 64                   # optional, may repeat; ANDed
  when    declared != len
  action  block, log                 # required
  errno   EPERM                      # optional, default EPERM
}
```

* `path` (exactly one): the public path the client opened.
* `match <op> [<code>]` (exactly one): `<op>` is one of `open read write
  devctl lseek close other any`. `<code>` is allowed only for `devctl`.
  It matches if it equals the full 32-bit `dcmd` the client sent, or if
  it equals `dcmd & 0xFFFF` (class + command, without the direction and
  size bits). This lets rule authors write the short code that
  appears in vendor headers.
* `when <cond>` (0..SPLINT_MAX_CONDS): all must hold (logical AND).
* `action` (exactly one): `block`, `log`, or `block, log`. `log` alone
  means "allow but record".
* `errno` (optional): one of `EPERM EACCES EINVAL ENOTSUP EIO`.

### Conditions

```
<lhs> <cmp> <rhs>
<lhs> := len | declared | byte[<n>] | u16[<n>] | u32[<n>]
<rhs> := <integer> | len | declared
<cmp> := == | != | < | <= | > | >=
```

* `len`: number of payload bytes actually present in the message (for
  devctl/write: bytes after the protocol header, computed from the
  received message length, never from a client-supplied field).
* `declared`: the size the client *claims* in the protocol header
  (`nbytes` for devctl/read/write). QNX documents that this field is not
  reliable for determining message length; comparing it with `len` is
  how a rule catches length-confusion exploits.
* `byte[n]`, `u16[n]`, `u32[n]`: unsigned little-endian load from the
  payload at byte offset `n`. If the payload is shorter than `n+width`
  the condition is FALSE (never reads out of bounds). `n` must be
  `< SPLINT_INSPECT_MAX`.

### profile blocks (allow-lists, usually produced by learn mode)

```
profile /dev/vendor_can {
  default block                       # or: default allow (default: allow)
  allow open
  allow devctl 0x0101 maxlen 16
  allow devctl 0x0102..0x0104 client "can_client" maxlen 64
  allow read  maxlen 512
  rate 200 per s client "can_client"  # token bucket, burst = rate
  rate 50 per s                       # applies to clients without a
                                      # more specific rate line
}
```

* `default allow|block`: what happens if no `allow` line matches.
* `allow <op> [<code> | <lo>..<hi>] [client "<name>"] [maxlen <n>]`:
  matches when op matches, code within range (devctl only; same short
  code convenience as patches), client process name equals `<name>` if
  given, and `len <= maxlen` if given.
* `rate <n> per s [client "<name>"]`: limit messages per second per
  client process. Exceeding the rate yields BLOCK with reason RATE.
* At most one profile per path.

### mode

* `enforce`: verdicts are applied.
* `learn`: the engine computes verdicts and logs them, but splintd
  forwards everything EXCEPT messages matching a `patch` with `block`.
  Patches always enforce; learning never disables a known virtual patch.

### version

An optional `version N` statement (at most one, `N` a non-negative integer)
gives the ruleset a monotonic version for rollback protection:

```
version 7
```

Because the whole file is signed, the version is integrity-protected. splintd
tracks the highest version it has activated and refuses to activate a ruleset
that does not advance it; once any versioned ruleset is active, an unversioned
one (`version 0`, the default) is also refused. A valid signature proves a
ruleset is authentic, not that it is current, so the version is what stops an
authentic but superseded ruleset from being replayed. The counter is in-memory
per daemon lifetime; persisting it across restarts needs rollback-resistant
storage and is noted as future work.

## Evaluation order (engine)

1. Patches whose `path` equals the message path, in file order. First
   match wins. If its action has `block` -> BLOCK (reason PATCH). If
   `log` only -> mark log, continue.
2. Profile for the path (if any): rate limit check first (reason RATE),
   then allow lines in file order (first match -> ALLOW), else the
   profile default (reason DEFAULT if block).
3. No profile -> ALLOW.
4. In `learn` mode, a BLOCK whose reason is not PATCH is downgraded to
   ALLOW with `would_block = true` and `log = true`.

## Limits (see include/splint/rules.h)

`SPLINT_MAX_RULES 256`, `SPLINT_MAX_CONDS 8`, `SPLINT_MAX_PROFILES 32`,
`SPLINT_MAX_ALLOW 64` per profile, `SPLINT_MAX_RATES 16` per profile,
`SPLINT_INSPECT_MAX 256` bytes, rules file max 256 KiB. Exceeding any
limit is a parse error, never a silent truncation.

## Errors

The parser reports the first error with 1-based line and column and a
short message, and produces no ruleset. A ruleset is all-or-nothing:
`splintctl reload` with a bad file leaves the running ruleset untouched.
