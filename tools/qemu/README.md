<!-- SPDX-License-Identifier: Apache-2.0 -->
# QEMU image for QSplintNX

Scripts to build the QNX binaries and run them in a QNX SDP 8.0 QEMU
x86_64 image on WSL2 Ubuntu 24.04. Both wrap `mkqnximage`, which comes
with the SDP.

## Host setup (once)

```
sudo apt install qemu-system-x86 qemu-utils
sudo usermod -aG kvm "$USER"     # then: wsl --shutdown, reopen Ubuntu
ls -l /dev/kvm                   # must be rw for your user
```

QNX SDP 8.0 installed with the QNX Software Center in `~/qnx800`
(override with `--sdp` or `QNX_SDP`).

## Build and boot

```
tools/qemu/build_image.sh            # make qnx + image in ~/qsplintnx-vm
tools/qemu/run.sh                    # boot in the foreground
tools/qemu/run.sh --headless         # or in the background, prints the IP
tools/qemu/run.sh --ssh
```

`build_image.sh` sources `qnxsdp-env.sh`, runs `make qnx`, stages the
binaries from `build/qnx-gcc_ntox86_64/`, `demo/rules/*`,
`demo/run_demo.sh` and the secpol artefacts in
`~/qsplintnx-vm/local/qsplintnx`, and writes
`local/snippets/data_files.custom` so that mkqnximage puts them on the
data partition under `/data/qsplintnx`. Then it runs
`mkqnximage --type=qemu --arch=x86_64 --build` in the VM directory.
On the target:

```
cd /data/qsplintnx && sh ./run_demo.sh
```

If the files are not there (see VERIFY-ON-TARGET below), copy them over
ssh with `tools/qemu/run.sh --push`.

## secpol image (spike S2)

A `--secpol=secure` image needs a policy that covers every service in
it, and the mkqnximage docs say it does not boot without one. The
secpolgen output only covers QSplintNX, so the base comes from the
system itself:

```
tools/qemu/build_image.sh --secpol open      # policy generation mode
tools/qemu/run.sh --headless
#   on the target: run the demo once, exercising every path
tools/qemu/run.sh --fetch-policy             # -> ~/qsplintnx-vm/secpolgenerate.policy
tools/qemu/run.sh --stop
tools/qemu/build_image.sh --secpol secure --policy-base ~/qsplintnx-vm/secpolgenerate.policy
tools/qemu/run.sh
#   on the target:
sh /data/qsplintnx/secpol/check_bypass.sh
```

secpolgen refuses a base policy that lets another type attach the
backend path or connect to the driver, which is what the open-mode
run records if anything touched the driver directly. The processes
must be started with `on -T <type>` for the types to apply; that is
up to run_demo.sh.

## Options

`build_image.sh --help` and `run.sh --help` list them. mkqnximage keeps
its options in `local/options`, so the script always passes `--secpol`
and `--policy` explicitly to avoid inheriting the previous build's
settings.

## VERIFY-ON-TARGET

* Whether targets in a `data_files` snippet are relative to `/data` (the
  script assumes `qsplintnx/...` ends up as `/data/qsplintnx/...`), that
  intermediate directories are created, and that a `local/snippets`
  directory created before the first build is honoured.
* Whether mkqnximage's QEMU launcher enables KVM by itself; `run.sh`
  greps the generated files and warns if it cannot confirm it.
* Root ssh/scp/sftp login to the image (`mkqnximage --ssh-ident`).
* That the console shell may use `on -T` in a secure image (needs the
  `settypeid` ability).

References: mkqnximage utility page and "Secpol and policy options" in
the QNX OS System Security Guide 8.0.
