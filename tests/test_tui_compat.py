"""Tests for the data-driven compatibility DB and the curses dashboard.

Hardware-free: providers and clients are mocked, the curses main loop is
never entered (rendering is tested through the pure render_lines function).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

from homeware_toolkit import compat, inject as inject_mod, tui


class MockClient:
    def __init__(self, sysinfo=None):
        self._sysinfo = sysinfo or {
            "sysinfo": {"model": "NeXXt One", "hw_version": "GDNT-S",
                        "fw_version": "22.2.0378_FW_058_FGA221D"}}

    def require_auth(self):
        pass

    def get(self, service, **params):
        if service == "sysinfo":
            return 200, self._sysinfo
        return 200, {}

    def set(self, service, **params):
        return 200, {}


class TestLoadCompat(unittest.TestCase):
    def test_bundled_database_loads(self):
        entries = compat.load_compat()
        self.assertIsInstance(entries, list)
        self.assertGreaterEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["board"], "GDNT-S")
        self.assertEqual(entry["model_prefix"], "FGA221")
        self.assertEqual(entry["product_contains"], "NeXXt")
        self.assertIn("22.2.0378_FW_058_FGA221D", entry["known_firmware"])
        self.assertIn("22.2.0378_FW_056_FGA221D", entry["known_firmware"])
        self.assertEqual(entry["status"], "verified")

    def test_missing_database_raises(self):
        with self.assertRaises(RuntimeError):
            compat.load_compat(path="/nonexistent/compat.json")

    def test_malformed_database_raises(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as fh:
            fh.write('{"fingerprints": [{"board": ""}]}')
            path = fh.name
        try:
            with self.assertRaises(RuntimeError):
                compat.load_compat(path=path)
        finally:
            os.unlink(path)


class TestMatchFingerprint(unittest.TestCase):
    def test_verified_exact_firmware(self):
        result = compat.match_fingerprint(
            board="GDNT-S", model="NeXXt One", product="NeXXt One",
            firmware="22.2.0378_FW_058_FGA221D")
        self.assertEqual(result.status, "verified")
        self.assertTrue(result.firmware_known)
        self.assertIsNotNone(result.entry)

    def test_verified_second_known_firmware(self):
        result = compat.match_fingerprint(
            board="GDNT-S", model="NeXXt One", product="",
            firmware="22.2.0378_FW_056_FGA221D")
        self.assertEqual(result.status, "verified")

    def test_untested_known_board_unknown_firmware(self):
        result = compat.match_fingerprint(
            board="GDNT-S", model="NeXXt One", product="NeXXt One",
            firmware="22.2.9999_FW_999_FGA221D")
        self.assertEqual(result.status, "untested")
        self.assertFalse(result.firmware_known)
        self.assertIn("not in known_firmware", result.reason)

    def test_unknown_device(self):
        result = compat.match_fingerprint(
            board="X", model="SomeRouter", product="SomeRouter",
            firmware="1")
        self.assertEqual(result.status, "unknown")
        self.assertIsNone(result.entry)

    def test_custom_entries(self):
        entries = [{"board": "TESTBOARD", "model_prefix": "TST",
                    "product_contains": "TestRouter",
                    "known_firmware": ["1.0"], "status": "verified"}]
        result = compat.match_fingerprint(
            board="TESTBOARD-1", model="TestRouter", product="",
            firmware="1.0", entries=entries)
        self.assertEqual(result.status, "verified")
        result = compat.match_fingerprint(
            board="OTHER", model="TestRouter", product="",
            firmware="1.0", entries=entries)
        self.assertEqual(result.status, "unknown")


class TestInjectorGuardDataDriven(unittest.TestCase):
    """The guard now consults compat.json but keeps the same semantics."""

    def test_guard_allows_known_device_and_firmware(self):
        client = MockClient()
        inj = inject_mod.Injector(client, dry_run=True, log=lambda *_: None)
        self.assertIsNotNone(inj)

    def test_guard_allows_untested_firmware_on_known_board(self):
        client = MockClient(sysinfo={"sysinfo": {
            "model": "NeXXt One", "hw_version": "GDNT-S",
            "fw_version": "22.2.9999_FW_999_FGA221D"}})
        inj = inject_mod.Injector(client, dry_run=True, log=lambda *_: None)
        self.assertIsNotNone(inj)

    def test_guard_blocks_unknown_device(self):
        client = MockClient(sysinfo={"sysinfo": {"model": "SomeRouter",
                                                 "hw_version": "X",
                                                 "fw_version": "1"}})
        with self.assertRaises(inject_mod.UnknownDeviceError):
            inject_mod.Injector(client, dry_run=True, log=lambda *_: None)

    def test_guard_blocks_when_sysinfo_unavailable(self):
        class DownClient(MockClient):
            def get(self, service, **params):
                return 500, {}
        with self.assertRaises(inject_mod.UnknownDeviceError):
            inject_mod.Injector(DownClient(), dry_run=True,
                                log=lambda *_: None)

    def test_guard_force_bypasses(self):
        client = MockClient(sysinfo={"sysinfo": {"model": "SomeRouter"}})
        inj = inject_mod.Injector(client, force=True, dry_run=True,
                                  log=lambda *_: None)
        self.assertIsNotNone(inj)

    def test_known_fingerprints_constant_kept(self):
        # Backwards compatibility for external importers.
        self.assertIn("GDNT-S", inject_mod.KNOWN_FINGERPRINTS)
        self.assertIn("FGA221", inject_mod.KNOWN_FINGERPRINTS)
        self.assertIn("NeXXt", inject_mod.KNOWN_FINGERPRINTS)


class TestCompatReport(unittest.TestCase):
    def _probe_result(self):
        return {
            "target": "http://192.168.1.254",
            "tcp_ports": {"22": "refused", "80": "open", "443": "open"},
            "assets": {"/login": {"status": 200, "last_modified": "Mon, 01 Jan 2024"},
                       "/app/app.js": {"error": "timed out"}},
            "analysis": {
                "asset_version_stamps": ["20240101000000"],
                "uses_status_cgi": True,
                "has_pingstatus_setter": True,
                "has_ping_status_reader": True,
                "ipv6_validator_found": True,
                "compatibility_signal": "strong-front-end-match",
            },
        }

    def test_report_contains_key_fields(self):
        report = compat.generate_compat_report(
            self._probe_result(),
            sysinfo={"sysinfo": {"model": "NeXXt One", "hw_version": "GDNT-S",
                                 "fw_version": "22.2.0378_FW_058_FGA221D"}})
        self.assertIn("compatibility report", report.lower())
        self.assertIn("GDNT-S", report)
        self.assertIn("22.2.0378_FW_058_FGA221D", report)
        self.assertIn("NeXXt One", report)
        self.assertIn("strong-front-end-match", report)
        self.assertIn("20240101000000", report)

    def test_report_markdown_structure(self):
        report = compat.generate_compat_report(self._probe_result())
        self.assertTrue(report.startswith("# "))
        self.assertIn("| Port | State |", report)
        self.assertIn("| 80 | open |", report)
        self.assertIn("| Asset | HTTP | Last-Modified |", report)
        self.assertIn("- [ ]", report)  # checklist template
        self.assertIn("## Checklist", report)

    def test_report_without_sysinfo(self):
        report = compat.generate_compat_report(self._probe_result())
        self.assertIn("http://192.168.1.254", report)


class TestCollectSnapshot(unittest.TestCase):
    def test_snapshot_assembled_from_providers(self):
        providers = tui.Providers(
            device_info=lambda: {"model": "NeXXt One", "hw_version": "GDNT-S",
                                 "fw_version": "22.2.0378_FW_058_FGA221D"},
            wan_state=lambda: {"wan_ipv4": "100.64.1.5",
                               "wan_ipv4_class": "CGNAT-100.64/10",
                               "mode": "6rd",
                               "sixrd_prefixes": ["2001:db8::/56"],
                               "change_summary": "WAN IPv4 a -> b"},
            ssh_status=lambda: {"port": 2222, "listening": True,
                                "uci_instance": True, "authorized_keys": True,
                                "managed_state": True},
            fw_rules=lambda: [{"section": "nx_web", "name": "web",
                               "proto": "tcp", "dest_ip": "2001:db8::2",
                               "dest_port": "443"}],
            last_event=lambda: "wanwatch: WAN IPv4 a -> b",
        )
        snap = tui.collect_snapshot(providers)
        self.assertEqual(snap.device_model, "NeXXt One")
        self.assertEqual(snap.device_board, "GDNT-S")
        self.assertEqual(snap.device_firmware, "22.2.0378_FW_058_FGA221D")
        self.assertEqual(snap.wan_ipv4, "100.64.1.5")
        self.assertEqual(snap.wan_ipv4_class, "CGNAT-100.64/10")
        self.assertEqual(snap.wan_mode, "6rd")
        self.assertEqual(snap.sixrd_prefixes, ["2001:db8::/56"])
        self.assertEqual(snap.wan_last_change, "WAN IPv4 a -> b")
        self.assertTrue(snap.ssh["listening"])
        self.assertEqual(len(snap.fw_rules), 1)
        self.assertEqual(snap.last_event, "wanwatch: WAN IPv4 a -> b")
        self.assertEqual(snap.errors, [])
        self.assertTrue(snap.ts)

    def test_failing_provider_recorded_not_raised(self):
        def boom():
            raise ConnectionError("device unreachable")

        providers = tui.Providers(device_info=boom, wan_state=boom)
        snap = tui.collect_snapshot(providers)
        self.assertEqual(snap.device_model, "")
        self.assertEqual(len(snap.errors), 2)
        self.assertTrue(any("device_info" in e for e in snap.errors))
        self.assertTrue(any("device unreachable" in e for e in snap.errors))

    def test_missing_providers_yield_defaults(self):
        snap = tui.collect_snapshot(tui.Providers())
        self.assertEqual(snap.wan_ipv4, "")
        self.assertEqual(snap.ssh, {})
        self.assertEqual(snap.fw_rules, [])


class TestWanwatchStateProvider(unittest.TestCase):
    def test_reads_persisted_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = os.path.join(tmp, "state.json")
            with open(state_file, "w", encoding="utf-8") as fh:
                json.dump({"snapshot": {"wan_ipv4": "93.33.1.2",
                                        "wan_ipv4_class": "PUBLIC",
                                        "mode": "6rd"}}, fh)
            provider = tui.wanwatch_state_provider(state_file)
            self.assertEqual(provider()["wan_ipv4"], "93.33.1.2")

    def test_missing_state_file_yields_empty(self):
        provider = tui.wanwatch_state_provider("/nonexistent/state.json")
        self.assertEqual(provider(), {})


class TestRenderLines(unittest.TestCase):
    def _snapshot(self):
        return tui.DashboardSnapshot(
            ts="2026-08-28T23:53:26",
            device_model="NeXXt One", device_board="GDNT-S",
            device_firmware="22.2.0378_FW_058_FGA221D",
            wan_ipv4="93.33.1.2", wan_ipv4_class="PUBLIC", wan_mode="6rd",
            sixrd_prefixes=["2001:db8::/56"],
            wan_last_change="WAN IPv4 10.0.0.1 -> 93.33.1.2",
            ssh={"port": 2222, "listening": True, "uci_instance": True,
                 "authorized_keys": True},
            fw_rules=[{"name": "web", "proto": "tcp",
                       "dest_ip": "2001:db8::2", "dest_port": "443"}],
            last_event="wanwatch: prefix changed")

    def test_key_texts_present(self):
        text = "\n".join(tui.render_lines(self._snapshot(), width=100))
        self.assertIn("NeXXt One", text)
        self.assertIn("GDNT-S", text)
        self.assertIn("22.2.0378_FW_058_FGA221D", text)
        self.assertIn("2026-08-28T23:53:26", text)
        self.assertIn("93.33.1.2 (PUBLIC)", text)
        self.assertIn("6rd", text)
        self.assertIn("2001:db8::/56", text)
        self.assertIn("WAN IPv4 10.0.0.1 -> 93.33.1.2", text)
        self.assertIn("dropbear UP port 2222 key-only", text)
        self.assertIn("web", text)
        self.assertIn("443", text)
        self.assertIn("wanwatch: prefix changed", text)
        self.assertIn("[q] quit", text)
        self.assertIn("[r] refresh", text)

    def test_down_ssh_and_empty_state(self):
        snap = tui.DashboardSnapshot(
            ssh={"port": 2222, "listening": False})
        text = "\n".join(tui.render_lines(snap, width=100))
        self.assertIn("dropbear DOWN port 2222", text)
        self.assertIn("0 rule(s)", text)

    def test_errors_rendered(self):
        snap = tui.DashboardSnapshot(errors=["wan_state: boom"])
        text = "\n".join(tui.render_lines(snap, width=100))
        self.assertIn("wan_state: boom", text)

    def test_lines_clipped_to_width(self):
        lines = tui.render_lines(self._snapshot(), width=40)
        self.assertTrue(all(len(line) <= 40 for line in lines))


class TestRunDashboardGuards(unittest.TestCase):
    def test_non_tty_raises_clear_error(self):
        with mock.patch.object(sys.stdout, "isatty", return_value=False):
            with self.assertRaises(RuntimeError) as ctx:
                tui.run_dashboard(tui.Providers())
        self.assertIn("--json", str(ctx.exception))


class FakeCursesError(Exception):
    pass


class FakeCurses:
    """Minimal stand-in for the curses module (what _main_loop touches)."""

    error = FakeCursesError


class FakeStdscr:
    """Scripted curses window: replays keys, records every drawn line."""

    def __init__(self, keys, size=(24, 80), fail_rows=()):
        self._keys = list(keys)
        self._size = size
        self._fail_rows = set(fail_rows)
        self.drawn = []          # (row, text) pairs actually accepted
        self.timeout_ms = None
        self.refresh_count = 0

    def timeout(self, ms):
        self.timeout_ms = ms

    def erase(self):
        pass

    def getmaxyx(self):
        return self._size

    def addnstr(self, row, col, text, n):
        if row in self._fail_rows:
            raise FakeCursesError("simulated curses.error")
        self.drawn.append((row, text[:n]))

    def refresh(self):
        self.refresh_count += 1

    def getch(self):
        return self._keys.pop(0) if self._keys else ord("q")


def _counting_provider(counter):
    def provider():
        counter[0] += 1
        return {"model": "FGA221D", "hw_version": "GDNT-S",
                "fw_version": "FW_058"}
    return provider


class TestMainLoop(unittest.TestCase):
    """The curses event loop, driven through a scripted fake window."""

    def _run(self, keys, size=(24, 80), fail_rows=()):
        counter = [0]
        providers = tui.Providers(device_info=_counting_provider(counter))
        stdscr = FakeStdscr(keys, size=size, fail_rows=fail_rows)
        tui._main_loop(stdscr, providers, 5.0, FakeCurses)
        return stdscr, counter

    def test_quit_exits_after_initial_render(self):
        stdscr, counter = self._run([ord("q")])
        self.assertEqual(counter[0], 1)           # one initial collection
        self.assertTrue(stdscr.drawn)             # something was drawn
        self.assertEqual(stdscr.drawn[0][0], 0)   # starting at row 0
        self.assertEqual(stdscr.timeout_ms, 5000)  # refresh -> timeout ms

    def test_r_key_forces_refresh(self):
        _, counter = self._run([ord("r"), ord("R"), ord("q")])
        self.assertEqual(counter[0], 3)  # initial + two manual refreshes

    def test_timeout_triggers_periodic_refresh(self):
        _, counter = self._run([-1, -1, ord("q")])
        self.assertEqual(counter[0], 3)  # initial + two periodic refreshes

    def test_rows_beyond_height_are_skipped(self):
        stdscr, _ = self._run([ord("q")], size=(3, 80))
        self.assertTrue(all(row < 2 for row, _ in stdscr.drawn))

    def test_curses_error_on_row_is_swallowed(self):
        stdscr, _ = self._run([ord("q")], fail_rows=(1,))
        rows = [row for row, _ in stdscr.drawn]
        self.assertNotIn(1, rows)
        self.assertIn(0, rows)  # other rows still drawn

    def test_run_dashboard_uses_injected_wrapper(self):
        stdscr = FakeStdscr([ord("q")])
        seen = {}

        def fake_wrapper(fn):
            seen["called"] = True
            fn(stdscr)

        with mock.patch.object(sys.stdout, "isatty", return_value=True):
            code = tui.run_dashboard(tui.Providers(), _wrapper=fake_wrapper)
        self.assertEqual(code, 0)
        self.assertTrue(seen.get("called"))
        self.assertTrue(stdscr.drawn)


if __name__ == "__main__":
    unittest.main()
