# SPDX-License-Identifier: Apache-2.0
"""Unit tests for secpolgen. Run: python3 -m unittest discover tools/secpolgen"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import secpolgen  # noqa: E402

EXAMPLE = os.path.join(HERE, "example.json")


def load_example() -> dict:
    with open(EXAMPLE, encoding="utf-8") as f:
        return json.load(f)


def rule_lines(text: str) -> list[str]:
    """Non-comment, non-blank lines with whitespace collapsed."""
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(" ".join(line.split()))
    return out


def run_main(args: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = secpolgen.main(args)
    return rc, out.getvalue(), err.getvalue()


class TestExamplePolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = secpolgen.load_config(EXAMPLE)
        cls.text = secpolgen.generate_policy(cls.cfg)
        cls.rules = rule_lines(cls.text)

    def test_types_declared_once(self):
        for t in ("splintd_t", "splintctl_t", "vendor_can_t", "can_client_t", "exploit_t"):
            self.assertEqual(self.rules.count(f"type {t};"), 1, t)

    def test_splintd_abilities(self):
        i = self.rules.index("allow splintd_t self:ability {")
        self.assertEqual(self.rules[i + 1:i + 4], ["pathspace", "public_channel", "};"])

    def test_splintd_attaches_public_and_ctl(self):
        self.assertIn("allow_attach splintd_t /dev/vendor_can;", self.rules)
        # The control node is attached on its own channel, typed splint_ctl_t.
        self.assertIn("allow_attach splintd_t /dev/splint/ctl splint_ctl_t;", self.rules)

    def test_only_driver_attaches_backend(self):
        attach = [r for r in self.rules if r.startswith("allow_attach") and
                  r.split()[2].rstrip(";") == "/dev/.splint/vendor_can"]
        self.assertEqual(attach, ["allow_attach vendor_can_t /dev/.splint/vendor_can;"])

    def test_only_splintd_connects_to_driver(self):
        conn = [r for r in self.rules if "vendor_can_t:channel connect" in r]
        self.assertEqual(conn, ["allow splintd_t vendor_can_t:channel connect;"])

    def test_clients_connect_to_splintd(self):
        for t in ("can_client_t", "exploit_t"):
            self.assertIn(f"allow {t} splintd_t:channel connect;", self.rules)

    def test_ctl_channel_isolated(self):
        # Only the control client may connect to the isolated control channel,
        # and it does NOT connect to the data channel (splintd_t).
        self.assertIn("allow splintctl_t splint_ctl_t:channel connect;", self.rules)
        self.assertNotIn("allow splintctl_t splintd_t:channel connect;", self.rules)
        self.assertIn("type splint_ctl_t;", self.rules)
        # No device-client type may reach the control channel.
        for t in ("can_client_t", "exploit_t"):
            self.assertNotIn(f"allow {t} splint_ctl_t:channel connect;", self.rules)

    def test_no_client_reaches_driver(self):
        for r in self.rules:
            if r.startswith("allow ") and "vendor_can_t" in r.split(":")[0].split()[-1:]:
                self.assertTrue(r.startswith("allow splintd_t ") or
                                r.startswith("allow vendor_can_t self:"), r)

    def test_control_channel_not_shared(self):
        # The old shared-channel limitation must be gone from the output.
        self.assertNotIn("KNOWN LIMITATION", self.text)
        self.assertNotIn("shared channel", self.text)

    def test_statements_terminated(self):
        for r in self.rules:
            if r.startswith(("type ", "allow_attach ")) or ":channel" in r:
                self.assertTrue(r.endswith(";"), r)

    def test_balanced_braces(self):
        self.assertEqual(self.text.count("{") - self.text.count("}"), 0)

    def test_nonroot(self):
        data = load_example()
        data["nonroot"] = True
        rules = rule_lines(secpolgen.generate_policy(secpolgen.parse_config(data)))
        i = rules.index("allow splintd_t self:ability {")
        self.assertEqual(rules[i + 1], "nonroot")

    def test_driver_abilities_off(self):
        data = load_example()
        data["driver_abilities"] = False
        rules = rule_lines(secpolgen.generate_policy(secpolgen.parse_config(data)))
        self.assertNotIn("allow vendor_can_t self:ability {", rules)

    def test_shadow_mapping(self):
        data = load_example()
        m = data["mappings"][0]
        m["mode"] = "shadow"
        del m["backend"]
        rules = rule_lines(secpolgen.generate_policy(secpolgen.parse_config(data)))
        self.assertIn("allow_attach vendor_can_t /dev/vendor_can;", rules)
        self.assertIn("allow_attach splintd_t /dev/vendor_can;", rules)
        self.assertIn("allow splintd_t vendor_can_t:channel connect;", rules)


class TestValidation(unittest.TestCase):
    def assertConfigError(self, data, fragment):
        with self.assertRaises(secpolgen.ConfigError) as cm:
            secpolgen.parse_config(data)
        self.assertIn(fragment, str(cm.exception))

    def test_unknown_mode(self):
        d = load_example()
        d["mappings"][0]["mode"] = "inline"
        self.assertConfigError(d, "unknown mode")

    def test_missing_fields(self):
        for key in ("public", "driver_type", "mode", "backend"):
            d = load_example()
            del d["mappings"][0][key]
            self.assertConfigError(d, f"missing required field '{key}'")
        d = load_example()
        del d["mappings"]
        self.assertConfigError(d, "missing required field 'mappings'")

    def test_empty_mappings(self):
        d = load_example()
        d["mappings"] = []
        self.assertConfigError(d, "non-empty list")

    def test_bad_type_and_path(self):
        d = load_example()
        d["mappings"][0]["driver_type"] = "bad type;"
        self.assertConfigError(d, "invalid type name")
        d = load_example()
        d["mappings"][0]["backend"] = "/dev/*"
        self.assertConfigError(d, "invalid path")
        d = load_example()
        d["mappings"][0]["public"] = "dev/rel"
        self.assertConfigError(d, "invalid path")
        d = load_example()
        d["splintd_type"] = "default"
        self.assertConfigError(d, "reserved")

    def test_relocated_needs_distinct_backend(self):
        d = load_example()
        d["mappings"][0]["backend"] = d["mappings"][0]["public"]
        self.assertConfigError(d, "backend != public")

    def test_shadow_backend_must_equal_public(self):
        d = load_example()
        d["mappings"][0]["mode"] = "shadow"
        self.assertConfigError(d, "backend == public")

    def test_client_cannot_be_driver_or_splintd(self):
        d = load_example()
        d["mappings"][0]["clients"].append("vendor_can_t")
        self.assertConfigError(d, "cannot be a client type")

    def test_duplicate_public(self):
        d = load_example()
        d["mappings"].append(copy.deepcopy(d["mappings"][0]))
        d["mappings"][1]["backend"] = "/dev/.splint/other"
        self.assertConfigError(d, "used twice")

    def test_unknown_field(self):
        d = load_example()
        d["mappings"][0]["typo"] = 1
        self.assertConfigError(d, "unknown field")

    def test_cli_reports_error(self):
        d = load_example()
        d["mappings"][0]["mode"] = "bogus"
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(d, f)
        try:
            rc, out, err = run_main([f.name])
        finally:
            os.unlink(f.name)
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertIn("unknown mode", err)

    def test_cli_invalid_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{ nope")
        try:
            rc, _, err = run_main([f.name])
        finally:
            os.unlink(f.name)
        self.assertEqual(rc, 1)
        self.assertIn("invalid JSON", err)


class TestCheckBypass(unittest.TestCase):
    def setUp(self):
        rc, self.out, _ = run_main([EXAMPLE, "--check-bypass"])
        self.assertEqual(rc, 0)

    def test_shape(self):
        self.assertTrue(self.out.startswith("#!/bin/sh\n"))
        self.assertIn("SPDX-License-Identifier: Apache-2.0", self.out)
        self.assertIn("on -T", self.out)
        self.assertIn("exit $fail", self.out)

    def test_expectations(self):
        for c in ("can_client_t", "exploit_t", "splintctl_t"):
            self.assertIn(f"expect_denied {c} /dev/.splint/vendor_can", self.out)
        for c in ("can_client_t", "exploit_t"):
            self.assertIn(f"expect_allowed {c} /dev/vendor_can", self.out)
        self.assertIn("EACCES", self.out)
        self.assertIn("EPERM", self.out)

    def test_ctl_channel_checked(self):
        # The isolated control channel: a device client is denied, the control
        # client is allowed.
        self.assertIn("expect_denied can_client_t /dev/splint/ctl", self.out)
        self.assertIn("expect_allowed splintctl_t /dev/splint/ctl", self.out)

    def test_not_a_policy(self):
        self.assertNotIn("allow_attach", self.out)

    def test_shadow_skipped(self):
        d = load_example()
        d["mappings"][0]["mode"] = "shadow"
        del d["mappings"][0]["backend"]
        out = secpolgen.generate_check_script(secpolgen.parse_config(d))
        self.assertIn("SKIP", out)
        # Shadow mapping: the backend shares the public path, so there is no
        # backend-path bypass check. The isolated control channel is still
        # checked (it is independent of mapping mode).
        body = out.split("expect_allowed() {")[1].split("}\n", 1)[1]
        self.assertNotIn("/dev/vendor_can\n", body.replace("/dev/splint/ctl", ""))
        self.assertIn("expect_denied can_client_t /dev/splint/ctl", body)

    @unittest.skipUnless(shutil.which("bash"), "bash not available")
    def test_bash_syntax(self):
        r = subprocess.run(["bash", "-n"], input=self.out, text=True, capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_output_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "check.sh")
            rc, out, _ = run_main([EXAMPLE, "--check-bypass", "-o", p])
            self.assertEqual(rc, 0)
            self.assertEqual(out, "")
            with open(p, encoding="utf-8") as f:
                self.assertEqual(f.read(), self.out)


class TestBase(unittest.TestCase):
    def _run(self, base_text, *extra):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(base_text)
        try:
            return run_main([EXAMPLE, "--base", f.name, *extra])
        finally:
            os.unlink(f.name)

    def test_base_types_not_redeclared(self):
        rc, out, _ = self._run("type splintd_t;\ntype console_t;\n")
        self.assertEqual(rc, 0)
        self.assertEqual(rule_lines(out).count("type splintd_t;"), 1)
        self.assertIn("type console_t;", out)

    def test_base_bypass_rejected(self):
        base = ("type evil_t;\nallow_attach evil_t /dev/.splint/vendor_can;\n"
                "allow can_client_t vendor_can_t:channel connect;\n")
        rc, out, err = self._run(base)
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertIn("evil_t may attach backend", err)
        self.assertIn("can_client_t may connect to driver channel", err)

    def test_base_wildcard_rejected(self):
        rc, _, err = self._run("allow_attach evil_t /dev/.splint/*;\n")
        self.assertEqual(rc, 1)
        self.assertIn("covers backend", err)

    def test_base_conflicts_allowed(self):
        rc, out, err = self._run("allow_attach evil_t /dev/.splint/vendor_can;\n",
                                 "--allow-base-conflicts")
        self.assertEqual(rc, 0)
        self.assertIn("evil_t", err)
        self.assertIn("allow_attach vendor_can_t /dev/.splint/vendor_can;", out)


if __name__ == "__main__":
    unittest.main()
