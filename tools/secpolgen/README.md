<!-- SPDX-License-Identifier: Apache-2.0 -->
# secpolgen

`secpolgen.py` writes the QNX 8.0 security policy (secpol) rules that
close the bypass around splintd. Without them any process could open the
driver's hidden backend path, or `ConnectAttach()` to the driver's
channel, and never pass through splintd at all. Python 3.10+, standard
library only.

```
python3 tools/secpolgen/secpolgen.py tools/secpolgen/example.json -o qsplintnx.secpol
python3 tools/secpolgen/secpolgen.py tools/secpolgen/example.json --check-bypass -o check_bypass.sh
python3 -m unittest discover tools/secpolgen
```

## Config

```json
{
  "splintd_type": "splintd_t",
  "ctl_client_type": "splintctl_t",
  "ctl_path": "/dev/splint/ctl",
  "nonroot": false,
  "driver_abilities": true,
  "mappings": [
    { "public": "/dev/vendor_can", "backend": "/dev/.splint/vendor_can",
      "driver_type": "vendor_can_t", "mode": "relocated",
      "clients": ["can_client_t", "exploit_t"] }
  ]
}
```

`mode` is `relocated` (driver on a hidden backend path, splintd owns the
public path) or `shadow` (both attach the public path; `backend` may be
omitted and must equal `public`). `nonroot` adds the `nonroot` option to
the ability blocks, which the processes need if they drop root.
`driver_abilities` controls whether the driver type also gets
`pathspace` and `public_channel`; turn it off if the base policy already
grants them. Unknown fields, unknown modes, missing fields, wildcard
paths and type names outside `[A-Za-z_][A-Za-z0-9_]*` are rejected.

## What the policy says

The rules rely on two properties that the "Security policy language"
page of the QNX OS System Security Guide 8.0 states: once a policy is
installed a path that no `allow_attach` rule names cannot be attached,
and a process may only connect to channels of type `default` unless a
`channel connect` rule allows it. A channel takes the type of the
process that owns it, so the driver's channel has the driver's type.

| Rule | Purpose |
|------|---------|
| `type ...;` | one type per process role |
| `allow splintd_t self:ability { pathspace public_channel };` | splintd is a resource manager |
| `allow_attach splintd_t <public>;`, `allow_attach splintd_t <ctl>;` | splintd owns the public paths and its control node |
| `allow_attach <driver_t> <backend>;` | only the driver may attach the hidden path |
| `allow splintd_t <driver_t>:channel connect;` | only splintd may talk to the driver |
| `allow <client_t> splintd_t:channel connect;` | listed clients talk to splintd |
| `allow splintctl_t splintd_t:channel connect;` | the control client talks to splintd |

The output is a fragment, not a bootable policy. A `--secpol=secure`
image needs types and rules for every service in it (mkqnximage refuses
to boot without a policy). The intended workflow is the one in the
mkqnximage "Secpol and policy options" page: build with
`--secpol=open`, run the demo, fetch `/dev/secpolgenerate/policy`, and
merge:

```
python3 tools/secpolgen/secpolgen.py example.json --base policy.txt -o merged.secpol
mkqnximage --type=qemu --secpol=secure --policy=merged.secpol --build
```

`--base` prepends the base policy, does not redeclare types it already
declares, and fails if the base contains a rule that reopens the bypass
(another type attaching a backend path, directly or by `*` / `...`
wildcard, or another type connecting to a driver type). A run of the
open-mode system in which something touched the backend directly would
produce exactly such rules, which is why they are errors by default
(`--allow-base-conflicts` turns them into warnings).

## Bypass test (spike S2)

`--check-bypass` writes a `/bin/sh` script for the target. For each
relocated mapping it runs `on -T <client_t> sh -c ': < <backend>'` and
expects a permission error, and opens the public path the same way as
a control. It prints PASS/FAIL per check and exits with the number of
failures. Shadow mappings are skipped because their backend shares the
public path; testing them needs a small program that calls
`ConnectAttach()` on the driver's channel directly.

## Known limitation

The control node and the public paths are attached on splintd's single
channel, so every type allowed to use a protected device can also
connect to `/dev/splint/ctl` at the channel level, and splintd itself
has to refuse control commands from them. Real separation needs a second
channel for the control node, typed with the optional third argument of
`allow_attach` (`allow_attach splintd_t /dev/splint/ctl splint_ctl_t;`)
and opened only to `splintctl_t`. The generator prints this as a
comment; it does not emit the rule because splintd does not create that
channel. The bypass script reports the ctl open as INFO.

## VERIFY-ON-TARGET

* Whether `allow_attach` alone is enough for splintd, or whether
  `pathspace` is also needed (both are emitted).
* Extra abilities splintd needs to read `/proc/<pid>/exefile` of its
  clients.
* That `on -T` works from the shell used for the test (it needs the
  `settypeid` ability), and the exact error text the shell prints.
* That `secpolcompile` accepts the fragment merged with the generated
  base policy.
