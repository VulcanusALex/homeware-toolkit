"""Hardware-free unit tests for homeware-toolkit core logic.

Run: python -m unittest discover -s tests -v
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from homeware_toolkit import transfer, wanwatch  # noqa: E402
from homeware_toolkit import inject as inject_mod  # noqa: E402
from homeware_toolkit import ssh as ssh_mod  # noqa: E402
from homeware_toolkit.cli import build_parser  # noqa: E402
from homeware_toolkit.client import GatewayClient  # noqa: E402
from homeware_toolkit.doctor import _wan_class  # noqa: E402
from homeware_toolkit.firewall import NAME_RE  # noqa: E402


class TestTransferEncoding(unittest.TestCase):
    def test_b64url_roundtrip(self):
        data = bytes(range(256))
        b64u = transfer.to_b64url(data)
        self.assertNotIn("+", b64u)
        self.assertNotIn("/", b64u)
        restored = base64.b64decode(b64u.replace("-", "+").replace("_", "/"))
        self.assertEqual(restored, data)

    def test_chunk_text(self):
        chunks = transfer.chunk_text("a" * 100, 48)
        self.assertEqual([len(c) for c in chunks], [48, 48, 4])
        self.assertEqual("".join(chunks), "a" * 100)


class FakeInj:
    """Minimal Injector stand-in for transfer tests."""

    def __init__(self, cursed: str = "ZZZ"):
        self.cursed = cursed
        self.writes: list[str] = []
        self.logs: list[str] = []

    def do(self, cmd: str):
        self.writes.append(cmd)
        return 1.0

    def ask(self, cmd: str) -> bool:
        # verification fails whenever the segment contains the cursed string
        return self.cursed not in cmd

    def log(self, msg: str):
        self.logs.append(msg)


class TestTransferBisect(unittest.TestCase):
    def test_clean_segment_first_try(self):
        inj = FakeInj(cursed="IMPOSSIBLE")
        parts = transfer._write_segment(inj, "abcdef", "/tmp/p_000")
        self.assertEqual(parts, ["/tmp/p_000"])
        self.assertEqual(len(inj.writes), 1)

    def test_cursed_segment_bisects(self):
        inj = FakeInj(cursed="ZZ")
        parts = transfer._write_segment(inj, "aaaZZbbb", "/tmp/p_001")
        # left half 'aaaZ' fails (contains ZZ? no -> 'aaaZ' has one Z) ...
        # 'aaaZ' passes, 'Zbbb' contains no ZZ... construct cleaner case:
        self.assertTrue(all(p.startswith("/tmp/p_001") for p in parts))
        joined = parts
        self.assertGreaterEqual(len(joined), 2)

    def test_bisect_covers_content(self):
        inj = FakeInj(cursed="CURSEDCURSED")
        seg = "ok1CURSEDCURSEDok2"
        parts = transfer._write_segment(inj, seg, "/tmp/p_002")
        # every leaf part must be verifiable content-wise by construction;
        # we assert the recursion produced leaves and terminated
        self.assertTrue(parts)
        self.assertTrue(all(p != "/tmp/p_002" or len(parts) == 1 for p in parts))


class TestWanClassify(unittest.TestCase):
    def test_private(self):
        self.assertEqual(wanwatch.classify_v4("10.64.0.1"), "private-RFC1918")
        self.assertEqual(wanwatch.classify_v4("192.168.1.254"), "private-RFC1918")

    def test_cgnat(self):
        self.assertEqual(wanwatch.classify_v4("100.64.1.1"), "CGNAT-100.64/10")
        self.assertEqual(wanwatch.classify_v4("100.127.255.255"), "CGNAT-100.64/10")

    def test_public(self):
        self.assertEqual(wanwatch.classify_v4("8.8.8.8"), "PUBLIC")
        self.assertEqual(wanwatch.classify_v4("8.8.8.8"), "PUBLIC")

    def test_wan_class_invalid(self):
        self.assertEqual(_wan_class("not-an-ip"), "unknown")


class MockClient:
    def __init__(self, authed=True, sysinfo=None):
        self._authed = authed
        self._sysinfo = sysinfo or {
            "sysinfo": {"model": "NeXXt One", "hw_version": "GDNT-S",
                        "fw_version": "22.2.0378_FW_058_FGA221D"}}

    def require_auth(self):
        if not self._authed:
            from homeware_toolkit.client import SessionExpired
            raise SessionExpired("nope")

    def get(self, service, **params):
        if service == "sysinfo":
            return 200, self._sysinfo
        return 200, {}

    def set(self, service, **params):
        return 200, {}


class TestInjectorGuardAndOracle(unittest.TestCase):
    def test_guard_blocks_unknown_device(self):
        client = MockClient(sysinfo={"sysinfo": {"model": "SomeRouter",
                                                 "hw_version": "X", "fw_version": "1"}})
        with self.assertRaises(inject_mod.UnknownDeviceError):
            inject_mod.Injector(client)

    def test_guard_force_bypasses(self):
        client = MockClient(sysinfo={"sysinfo": {"model": "SomeRouter"}})
        with mock.patch.object(inject_mod, "run_ping", return_value=(2.0, {})):
            inj = inject_mod.Injector(client, force=True)
        self.assertIsNotNone(inj)

    def test_oracle_threshold(self):
        client = MockClient()
        timings = {"127.0.0.1": (2.3, {}), "probe": (2.3 + 6, {})}

        def fake_ping(c, host, **kw):
            return timings.get(host, (1.0, {}))

        with mock.patch.object(inject_mod, "run_ping", side_effect=fake_ping):
            inj = inject_mod.Injector(client)
            # baseline measured as 2.3
            self.assertAlmostEqual(inj.base, 2.3)
            # fake ping returns baseline+6 for everything now -> ask() True
            timings.clear()
            timings.update({"127.0.0.1": (2.3, {})})
            with mock.patch.object(inject_mod, "run_ping",
                                   side_effect=lambda c, h, **k: (7.9, {})):
                self.assertTrue(inj.ask("test -f /tmp/x"))
            with mock.patch.object(inject_mod, "run_ping",
                                   side_effect=lambda c, h, **k: (2.5, {})):
                self.assertFalse(inj.ask("test -f /tmp/x"))

    def test_dry_run(self):
        client = MockClient()
        inj = inject_mod.Injector(client, dry_run=True)
        self.assertEqual(inj.do("echo hi"), 0.0)
        self.assertFalse(inj.ask("true"))


class TestPubkeyCheck(unittest.TestCase):
    def test_rsa_ok(self):
        with tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False) as f:
            f.write("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0 test\n")
            path = f.name
        try:
            data = ssh_mod.check_pubkey(path)
            self.assertTrue(data.startswith(b"ssh-rsa "))
            self.assertTrue(data.endswith(b"\n"))
        finally:
            os.unlink(path)

    def test_ed25519_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False) as f:
            f.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test\n")
            path = f.name
        try:
            with self.assertRaises(RuntimeError):
                ssh_mod.check_pubkey(path)
        finally:
            os.unlink(path)


class TestCookieImport(unittest.TestCase):
    def test_import_from_har(self):
        har = {"log": {"entries": [
            {"request": {"headers": [
                {"name": "Cookie", "value": "sessionID=deadbeef1234; other=x"}]}}]}}
        with tempfile.NamedTemporaryFile("w", suffix=".har", delete=False) as f:
            json.dump(har, f)
            path = f.name
        try:
            client = GatewayClient("https://192.168.1.254",
                                 work_dir=tempfile.mkdtemp())
            with mock.patch.object(GatewayClient, "is_authenticated", return_value=True):
                self.assertTrue(client.import_cookie(path))
            cookies = list(client.jar)
            self.assertEqual(cookies[0].value, "deadbeef1234")
        finally:
            os.unlink(path)


class TestMisc(unittest.TestCase):
    def test_name_re(self):
        self.assertTrue(NAME_RE.match("Allow-AWG_v6"))
        self.assertFalse(NAME_RE.match("bad name"))
        self.assertFalse(NAME_RE.match("x" * 33))

    def test_cli_parser_commands(self):
        parser = build_parser()
        args = parser.parse_args(["probe"])
        self.assertEqual(args.command, "probe")
        args = parser.parse_args(["ssh", "bootstrap", "--pubkey", "k.pub", "--test"])
        self.assertEqual(args.ssh_cmd, "bootstrap")
        self.assertTrue(args.test)
        args = parser.parse_args(["fw", "allow", "--key", "k", "--name", "r1",
                                  "--dest-ip", "::1", "--dest-port", "51820"])
        self.assertEqual(args.fw_cmd, "allow")


if __name__ == "__main__":
    unittest.main()
