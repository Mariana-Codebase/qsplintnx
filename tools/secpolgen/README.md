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
and a process may connect to a channel only when a `channel connect`
rule allows its type to reach that channel's type. A channel takes the
type of the process that owns it unless `allow_attach` relabels it with
its optional third field; relabeling to a type other than the process
type needs the `settypeid` ability. `splintd` relabels its data and
control channels to distinct types so the two can be governed
separately.

| Rule | Purpose |
|------|---------|
| `type ...;` | one type per process role, plus `splint_data_t` and `splint_ctl_t` for splintd's channels |
| `allow splintd_t self:ability { pathspace public_channel settypeid:splint_data_t settypeid:splint_ctl_t };` | splintd is a resource manager and relabels its two channels |
| `allow_attach splintd_t <public> splint_data_t;` | the public device nodes share one channel, typed `splint_data_t` |
| `allow_attach splintd_t <ctl> splint_ctl_t;` | the control node is on a SEPARATE channel, typed `splint_ctl_t` |
| `allow_attach <driver_t> <backend>;` | only the driver may attach the hidden path |
| `allow splintd_t <driver_t>:channel connect;` | only splintd may talk to the driver |
| `allow <client_t> splint_data_t:channel connect;` | listed clients reach only the data channel |
| `allow splintctl_t splint_ctl_t:channel connect;` | only the control client reaches the control channel |

Because the data and control channels carry different types, a client of
a protected device cannot connect to the control node at all: the kernel
refuses the connect, so `splintd` never has to decide whether to trust a
control command from a device client.

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
a control. It also checks the isolated control channel: a device
client's type opening `/dev/splint/ctl` must be denied, and the control
client's type must be allowed. It prints PASS/FAIL per check and exits
with the number of failures. Shadow mappings skip the backend-path check
because their backend shares the public path; testing those needs a
small program that calls `ConnectAttach()` on the driver's channel
directly.

## VERIFY-ON-TARGET

These were open questions during development; the run recorded in
`docs/qemu-validation.md` resolved them on a develop-mode image.

* Relabeling a channel to a non-process type needs the `settypeid`
  ability, and `secpolcompile` rejects a connect to a process type that
  can be relabeled. That is why the data channel carries its own
  `splint_data_t` rather than `splintd_t`; both are confirmed by
  compiling the generated policy with the SDP 8.0 `secpolcompile`.
* `on -T` from the shell needs the `settypeid` ability, and the denial
  surfaces both as `open(...): Operation not permitted` and as a
  `secpolgenerate` log line naming the refused `channel_connect`.
* Extra abilities splintd needs to read `/proc/<pid>/exefile` of its
  clients, and `splintctl_t` reading the rules file off the data
  filesystem, still show up as develop-mode `secpolgenerate` entries to
  grant explicitly in a full `--secpol=secure` policy.
