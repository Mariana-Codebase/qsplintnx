#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""secpolgen - generate the QNX 8.0 security policy fragment for QSplintNX.

Reads a JSON description of splintd, its control client and the driver
mappings it protects, and writes a policy in the QNX security policy
language (text form, compiled by secpolcompile / mkqnximage --policy).

The rules close the bypass around splintd:

* only the driver type may attach a relocated backend path;
* only splintd's type may connect to the driver's channel;
* listed client types (and the ctl client type) may connect to splintd.

With --check-bypass the tool writes, instead of the policy, a shell script
for the target that tries to open each relocated backend path as each
client type and expects EACCES/EPERM (spike S2 in docs/PLAN.md).

Syntax follows the QNX OS System Security Guide 8.0:
  https://www.qnx.com/developers/docs/8.0/com.qnx.doc.security.system/topic/manual/secpol_language.html
  https://www.qnx.com/developers/docs/8.0/com.qnx.doc.security.system/topic/manual/using_security_policies.html
  https://qnx.com/developers/docs/8.0/com.qnx.doc.security.system/topic/manual/abilities_reference.html

Python 3.10+, standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from dataclasses import dataclass, field

VERSION = "0.1"

# Identifiers in the policy language: we restrict to a conservative subset
# so that nothing we emit can be misread as syntax.
_TYPE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
# Paths are emitted unquoted in allow_attach rules, so keep them to the
# same charset the rules language allows (docs/RULES.md). No wildcards:
# '*' and '...' have meaning in allow_attach.
_PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]{0,126}$")
_MODES = ("relocated", "shadow")

DEFAULT_SPLINTD_TYPE = "splintd_t"
DEFAULT_CTL_CLIENT_TYPE = "splintctl_t"
DEFAULT_CTL_PATH = "/dev/splint/ctl"


class ConfigError(ValueError):
    """Raised for any invalid configuration; message is user-facing."""


@dataclass
class Mapping:
    public: str
    backend: str
    driver_type: str
    mode: str
    clients: list[str] = field(default_factory=list)


@dataclass
class Config:
    splintd_type: str
    ctl_client_type: str
    ctl_path: str
    nonroot: bool
    driver_abilities: bool
    mappings: list[Mapping]


# ---------------------------------------------------------------- parsing --

def _req(obj: dict, key: str, where: str):
    if key not in obj:
        raise ConfigError(f"{where}: missing required field '{key}'")
    return obj[key]


def _type_name(value, where: str) -> str:
    if not isinstance(value, str) or not _TYPE_RE.match(value):
        raise ConfigError(f"{where}: invalid type name {value!r} "
                          "(expected [A-Za-z_][A-Za-z0-9_]*, max 63 chars)")
    if value == "default":
        raise ConfigError(f"{where}: 'default' is a reserved type and must not be used")
    return value


def _path(value, where: str) -> str:
    if not isinstance(value, str) or not _PATH_RE.match(value):
        raise ConfigError(f"{where}: invalid path {value!r} "
                          "(absolute, [A-Za-z0-9_./-], max 127 chars, no wildcards)")
    if "/../" in value + "/" or "//" in value:
        raise ConfigError(f"{where}: path {value!r} must be normalised")
    return value


def parse_config(data: dict) -> Config:
    """Validate a decoded JSON document and return a Config."""
    if not isinstance(data, dict):
        raise ConfigError("top level must be a JSON object")

    known_top = {"splintd_type", "ctl_client_type", "ctl_path", "nonroot",
                 "driver_abilities", "mappings", "comment"}
    unknown = set(data) - known_top
    if unknown:
        raise ConfigError(f"unknown top-level field(s): {', '.join(sorted(unknown))}")

    splintd_type = _type_name(data.get("splintd_type", DEFAULT_SPLINTD_TYPE), "splintd_type")
    ctl_type = _type_name(data.get("ctl_client_type", DEFAULT_CTL_CLIENT_TYPE), "ctl_client_type")
    ctl_path = _path(data.get("ctl_path", DEFAULT_CTL_PATH), "ctl_path")
    nonroot = data.get("nonroot", False)
    drv_ab = data.get("driver_abilities", True)
    if not isinstance(nonroot, bool) or not isinstance(drv_ab, bool):
        raise ConfigError("nonroot and driver_abilities must be true or false")
    if ctl_type == splintd_type:
        raise ConfigError("ctl_client_type must differ from splintd_type")

    raw_maps = _req(data, "mappings", "config")
    if not isinstance(raw_maps, list) or not raw_maps:
        raise ConfigError("mappings: must be a non-empty list")

    mappings: list[Mapping] = []
    seen_public: set[str] = {ctl_path}
    seen_backend: set[str] = set()
    for i, m in enumerate(raw_maps):
        where = f"mappings[{i}]"
        if not isinstance(m, dict):
            raise ConfigError(f"{where}: must be an object")
        unknown = set(m) - {"public", "backend", "driver_type", "mode", "clients", "comment"}
        if unknown:
            raise ConfigError(f"{where}: unknown field(s): {', '.join(sorted(unknown))}")

        public = _path(_req(m, "public", where), f"{where}.public")
        mode = _req(m, "mode", where)
        if mode not in _MODES:
            raise ConfigError(f"{where}.mode: unknown mode {mode!r} (expected relocated or shadow)")
        driver = _type_name(_req(m, "driver_type", where), f"{where}.driver_type")
        if mode == "relocated":
            backend = _path(_req(m, "backend", where), f"{where}.backend")
            if backend == public:
                raise ConfigError(f"{where}: relocated mapping needs backend != public "
                                  "(use mode shadow for a shared path)")
        else:
            backend = _path(m.get("backend", public), f"{where}.backend")
            if backend != public:
                raise ConfigError(f"{where}: shadow mapping must have backend == public")

        clients_raw = m.get("clients", [])
        if not isinstance(clients_raw, list):
            raise ConfigError(f"{where}.clients: must be a list of type names")
        clients = []
        for j, c in enumerate(clients_raw):
            c = _type_name(c, f"{where}.clients[{j}]")
            if c in (driver, splintd_type):
                raise ConfigError(f"{where}.clients[{j}]: {c} cannot be a client type "
                                  "(it is the driver or splintd type)")
            if c not in clients:
                clients.append(c)

        if driver in (splintd_type, ctl_type):
            raise ConfigError(f"{where}.driver_type: must differ from splintd and ctl types")
        if public in seen_public:
            raise ConfigError(f"{where}.public: path {public} used twice (or equals ctl_path)")
        if mode == "relocated" and backend in seen_backend:
            raise ConfigError(f"{where}.backend: path {backend} used twice")
        seen_public.add(public)
        seen_backend.add(backend)
        mappings.append(Mapping(public, backend, driver, mode, clients))

    all_drivers = {m.driver_type for m in mappings}
    for m in mappings:
        for c in m.clients:
            if c in all_drivers:
                raise ConfigError(f"client type {c} is also a driver type; a driver type "
                                  "may connect only through splintd rules it is not given")
    return Config(splintd_type, ctl_type, ctl_path, nonroot, drv_ab, mappings)


def load_config(path: str) -> Config:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e.strerror}") from e
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: invalid JSON at line {e.lineno} col {e.colno}: {e.msg}") from e
    return parse_config(data)


# ------------------------------------------------------------- generation --

def _all_types(cfg: Config) -> list[str]:
    out: list[str] = []
    for t in [cfg.splintd_type, cfg.ctl_client_type,
              *[m.driver_type for m in cfg.mappings],
              *[c for m in cfg.mappings for c in m.clients]]:
        if t not in out:
            out.append(t)
    return out


def _ability_block(type_name: str, nonroot: bool) -> list[str]:
    # Comments are kept outside the braces on purpose: the docs show '#'
    # comments anywhere, but no example puts one inside an ability block.
    lines = ["# pathspace: resmgr_attach() adds names to the path space.",
             "# public_channel: dispatch_create() makes a non-private channel."]
    if nonroot:
        lines.append("# nonroot: the abilities also apply when running as non-root.")
    lines.append(f"allow {type_name} self:ability {{")
    if nonroot:
        lines.append("    nonroot")
    lines.append("    pathspace")
    lines.append("    public_channel")
    lines.append("};")
    return lines


def generate_policy(cfg: Config, base_types: set[str] | None = None) -> str:
    """Return the policy text. Types already declared in a base policy
    (base_types) are not declared again."""
    base_types = base_types or set()
    L: list[str] = []
    a = L.append
    a("# QSplintNX security policy fragment")
    a(f"# Generated by tools/secpolgen/secpolgen.py {VERSION}. Do not edit by hand;")
    a("# edit the JSON config and regenerate.")
    a("#")
    a("# Policy language: QNX OS System Security Guide 8.0, 'Security policy language'.")
    a("# Once a policy is installed no path can be attached unless an allow_attach")
    a("# rule names it, and a process may connect only to channels of type default")
    a("# unless a 'channel connect' rule allows it. Channels inherit the type of")
    a("# the process that owns them. QSplintNX relies on both properties.")
    a("")
    a("# ---- types ---------------------------------------------------------------")
    for t in _all_types(cfg):
        if t in base_types:
            a(f"# type {t}; (already declared in base policy)")
        else:
            a(f"type {t};")
    a("")

    a("# ---- splintd -------------------------------------------------------------")
    a("# splintd is a resource manager: it attaches the public paths and its")
    a("# control node, so it needs pathspace and public_channel.")
    a("# VERIFY-ON-TARGET: splintd reads /proc/<pid>/exefile of clients")
    a("# (src/qnx/clientinfo.c); check secpolgenerate output for any extra")
    a("# ability that needs.")
    L.extend(_ability_block(cfg.splintd_type, cfg.nonroot))
    a("# Control node used by splintctl.")
    a(f"allow_attach {cfg.splintd_type} {cfg.ctl_path};")
    for m in cfg.mappings:
        a(f"# Public path of {m.driver_type} ({m.mode} mapping): clients resolve here.")
        a(f"allow_attach {cfg.splintd_type} {m.public};")
    a("")

    for m in cfg.mappings:
        a(f"# ---- mapping {m.public} ({m.mode}) " + "-" * max(0, 52 - len(m.public) - len(m.mode)))
        if cfg.driver_abilities:
            a(f"# The driver {m.driver_type} is itself a resource manager.")
            L.extend(_ability_block(m.driver_type, cfg.nonroot))
        if m.mode == "relocated":
            a(f"# ONLY {m.driver_type} may attach the hidden backend path. No other")
            a("# allow_attach rule may name this path, or another process could")
            a("# impersonate the driver behind splintd.")
            a(f"allow_attach {m.driver_type} {m.backend};")
        else:
            a(f"# Shadow mode: {m.driver_type} attaches the SAME path as splintd;")
            a("# splintd attaches with _RESMGR_FLAG_BEFORE so it resolves first")
            a("# (spike S1, VERIFY-ON-TARGET).")
            a(f"allow_attach {m.driver_type} {m.backend};")
        a(f"# ONLY splintd may connect to the driver's channel (type {m.driver_type}).")
        a("# No client type gets this rule: opening the backend path directly, or")
        a("# ConnectAttach() to the driver's channel, fails with a permission error.")
        a(f"allow {cfg.splintd_type} {m.driver_type}:channel connect;")
        if m.clients:
            a(f"# Clients allowed to use {m.public} connect to splintd, never to the driver.")
            for c in m.clients:
                a(f"allow {c} {cfg.splintd_type}:channel connect;")
        else:
            a(f"# No client types listed for {m.public}.")
        a("")

    a("# ---- control client ------------------------------------------------------")
    a(f"allow {cfg.ctl_client_type} {cfg.splintd_type}:channel connect;")
    a("# KNOWN LIMITATION: the control node and the public paths share splintd's")
    a("# single channel, so every client type above can also reach the control")
    a("# node at the channel level. Access to the control node is then decided by")
    a("# splintd itself. Channel-level separation needs a second channel for the")
    a("# control node, typed with the optional channel type of allow_attach, e.g.")
    a(f"#   allow_attach {cfg.splintd_type} {cfg.ctl_path} splint_ctl_t;")
    a(f"#   allow {cfg.ctl_client_type} splint_ctl_t:channel connect;")
    a("# (not emitted: splintd does not create that channel yet).")
    a("")
    return "\n".join(L)


# ---------------------------------------------------------- base policies --

_TYPE_DECL_RE = re.compile(r"^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)\s*[,;]")
_ATTACH_RE = re.compile(r"^\s*allow_attach\s+(\{[^}]*\}|\S+)\s+(\S+?)(?:\s+\S+)?\s*;")
_CONNECT_RE = re.compile(r"^\s*allow\s+(\{[^}]*\}|\S+)\s+(\{[^}]*\}|[A-Za-z0-9_]+)\s*:\s*channel\s+[^;]*\bconnect\b")


def _names(token: str) -> list[str]:
    return token.strip("{}").split()


def scan_base(text: str, cfg: Config) -> tuple[set[str], list[str]]:
    """Return (types declared in text, list of bypass conflicts).

    A conflict is a base rule that would reopen the bypass: another type
    attaching a backend path, or another type connecting to a driver type.
    """
    types: set[str] = set()
    problems: list[str] = []
    drivers = {m.driver_type: m for m in cfg.mappings}
    backends = {m.backend: m for m in cfg.mappings if m.mode == "relocated"}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0]
        mt = _TYPE_DECL_RE.match(line)
        if mt:
            types.add(mt.group(1))
        ma = _ATTACH_RE.match(line)
        if ma:
            path = ma.group(2)
            for who in _names(ma.group(1)):
                m = backends.get(path)
                if m is not None and who != m.driver_type:
                    problems.append(f"line {lineno}: {who} may attach backend path {path}")
                if any(path.endswith(s) for s in ("/*", "/...")):
                    parent = path.rsplit("/", 1)[0]
                    for bp, bm in backends.items():
                        if bp.startswith(parent + "/") and who != bm.driver_type:
                            problems.append(f"line {lineno}: {who} may attach {path}, "
                                            f"which covers backend {bp}")
        mc = _CONNECT_RE.match(line)
        if mc:
            for target in _names(mc.group(2)):
                if target in drivers:
                    for who in _names(mc.group(1)):
                        if who != cfg.splintd_type:
                            problems.append(f"line {lineno}: {who} may connect to "
                                            f"driver channel {target}")
    return types, problems


# ------------------------------------------------------------ bypass test --

def generate_check_script(cfg: Config) -> str:
    """Shell script for the target (QNX sh/ksh) implementing spike S2."""
    q = shlex.quote
    L: list[str] = []
    a = L.append
    a("#!/bin/sh")
    a("# SPDX-License-Identifier: Apache-2.0")
    a(f"# QSplintNX secpol bypass check (spike S2), generated by secpolgen {VERSION}.")
    a("# Run on the target as a user allowed to start processes with 'on -T'")
    a("# (needs the settypeid ability), with the policy loaded, splintd and the")
    a("# drivers running. For each relocated mapping and each client type it")
    a("# opens the hidden backend path and expects EACCES or EPERM; opening the")
    a("# public path is a control and should succeed (splintd allows open).")
    a("# VERIFY-ON-TARGET: exact error strings printed by the QNX shell.")
    a("# Exit status: number of failed checks.")
    a("")
    a("fail=0")
    a("pass=0")
    a("")
    a("# try_open TYPE PATH -> prints shell's error text, returns open() status")
    a("try_open() {")
    a("    on -T \"$1\" sh -c ': < \"$0\"' \"$2\" 2>&1")
    a("}")
    a("")
    a("expect_denied() {")
    a("    out=$(try_open \"$1\" \"$2\"); rc=$?")
    a("    case \"$out\" in")
    a("    *\"ermission denied\"*|*\"not permitted\"*|*EACCES*|*EPERM*)")
    a("        echo \"PASS  $1 cannot open $2\"; pass=$((pass + 1)) ;;")
    a("    *)")
    a("        if [ \"$rc\" -eq 0 ]; then")
    a("            echo \"FAIL  $1 opened $2 directly: BYPASS IS OPEN\"")
    a("        else")
    a("            echo \"FAIL  $1 on $2: unexpected result (rc=$rc): $out\"")
    a("        fi")
    a("        fail=$((fail + 1)) ;;")
    a("    esac")
    a("}")
    a("")
    a("expect_allowed() {")
    a("    out=$(try_open \"$1\" \"$2\"); rc=$?")
    a("    if [ \"$rc\" -eq 0 ]; then")
    a("        echo \"PASS  $1 can open $2 (through splintd)\"; pass=$((pass + 1))")
    a("    else")
    a("        echo \"FAIL  $1 cannot open public path $2 (rc=$rc): $out\"; fail=$((fail + 1))")
    a("    fi")
    a("}")
    a("")
    any_reloc = False
    for m in cfg.mappings:
        if m.mode != "relocated":
            a(f"echo \"SKIP  {m.public}: shadow mapping, backend shares the public path;\"")
            a("echo \"      test direct ConnectAttach to the driver channel separately\"")
            continue
        any_reloc = True
        a(f"# mapping {m.public} -> {m.backend} (driver {m.driver_type})")
        for c in m.clients:
            a(f"expect_denied {q(c)} {q(m.backend)}")
            a(f"expect_allowed {q(c)} {q(m.public)}")
        a(f"expect_denied {q(cfg.ctl_client_type)} {q(m.backend)}")
        a("")
    if not any_reloc:
        a("echo \"no relocated mappings: nothing to test\"")
    a("# Known limitation (reported, not counted): client types share splintd's")
    a("# channel with the control node, so this open is NOT denied by secpol.")
    clients = [c for m in cfg.mappings for c in m.clients]
    if clients:
        a(f"if try_open {q(clients[0])} {q(cfg.ctl_path)} >/dev/null; then")
        a(f"    echo \"INFO  {clients[0]} can open {cfg.ctl_path} (shared channel, known limitation)\"")
        a("fi")
    a("")
    a("echo \"passed=$pass failed=$fail\"")
    a("exit $fail")
    a("")
    return "\n".join(L)


# -------------------------------------------------------------------- CLI --

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="secpolgen",
        description="Generate a QNX 8.0 secpol policy fragment for QSplintNX.")
    ap.add_argument("config", help="JSON config (see tools/secpolgen/example.json)")
    ap.add_argument("-o", "--output", help="write to this file instead of stdout")
    ap.add_argument("--base", metavar="POLICY",
                    help="prepend this policy text (e.g. secpolgenerate output); types it "
                         "declares are not redeclared and rules that reopen the bypass "
                         "are reported as errors")
    ap.add_argument("--allow-base-conflicts", action="store_true",
                    help="with --base: report bypass conflicts as warnings only")
    ap.add_argument("--check-bypass", action="store_true",
                    help="emit the target shell script for spike S2 instead of the policy")
    ap.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = ap.parse_args(argv)

    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        print(f"secpolgen: {e}", file=sys.stderr)
        return 1

    if args.check_bypass:
        text = generate_check_script(cfg)
    else:
        base_text = ""
        base_types: set[str] = set()
        if args.base:
            try:
                with open(args.base, encoding="utf-8") as f:
                    base_text = f.read()
            except OSError as e:
                print(f"secpolgen: cannot read {args.base}: {e.strerror}", file=sys.stderr)
                return 1
            base_types, problems = scan_base(base_text, cfg)
            for p in problems:
                print(f"secpolgen: base policy {args.base}: {p}", file=sys.stderr)
            if problems and not args.allow_base_conflicts:
                print("secpolgen: base policy reopens the splintd bypass; fix it or "
                      "pass --allow-base-conflicts", file=sys.stderr)
                return 1
        text = generate_policy(cfg, base_types)
        if base_text:
            sep = "" if base_text.endswith("\n") else "\n"
            text = (f"# ---- base policy: {args.base} ----\n{base_text}{sep}\n" + text)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text)
        except OSError as e:
            print(f"secpolgen: cannot write {args.output}: {e.strerror}", file=sys.stderr)
            return 1
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
