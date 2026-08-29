"""Hardware-free end-to-end tests against the fake gateway simulator.

Run: python -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import os
import random
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from home_gateway_toolkit import inject as inject_mod  # noqa: E402
from home_gateway_toolkit import probe, transfer, verify as verify_mod  # noqa: E402
from home_gateway_toolkit.client import GatewayClient  # noqa: E402
from home_gateway_toolkit.driver import detect_from_sysinfo  # noqa: E402
from home_gateway_toolkit.inject import Injector, UnknownDeviceError  # noqa: E402
from home_gateway_toolkit.simulator import (  # noqa: E402
    FakeGateway, GENERIC_HOMEWARE_PROFILE, VirtualShell)

SILENT = lambda *args: None  # noqa: E731

# inject.ask() requires elapsed > base + ORACLE_SLEEP - 2, so the smallest
# oracle sleep that still discriminates true/false with fast polling is ~2.5s.
FAST_ORACLE_SLEEP = 2.5


def _fast_poll(module):
    """Patch a module's run_ping reference to poll the simulator faster."""
    real = inject_mod.run_ping

    def wrapper(client, host, settle_timeout=45.0, poll_interval=0.05,
                service=None, reader=None):
        kwargs = {}
        if service is not None:
            kwargs["service"] = service
        if reader is not None:
            kwargs["reader"] = reader
        return real(client, host, settle_timeout, poll_interval, **kwargs)

    return mock.patch.object(module, "run_ping", wrapper)


class GatewayCase(unittest.TestCase):
    gateway_kwargs: dict = {}

    def setUp(self):
        self.gateway = FakeGateway(**self.gateway_kwargs)
        self.gateway.start()
        self.tmp = tempfile.TemporaryDirectory()
        self.client = GatewayClient(self.gateway.base_url, timeout=5.0,
                                  work_dir=self.tmp.name)

    def tearDown(self):
        self.gateway.stop()
        self.tmp.cleanup()

    def quick_login(self):
        """Button-login handshake driven synchronously (no 1s poll waits)."""
        self.client.fresh_session()
        status, _ = self.client.set("login_confirm", cmd=7, loginPath=2)
        self.assertEqual(status, 200)
        self.gateway.press_buttons()
        _, data = self.client.get("login_confirm", cmd=7)
        self.assertEqual(str(data["login_confirm"]["loginPath"]), "1")
        status, _ = self.client.set("login_confirm", cmd=7, loginPath=1)
        self.assertEqual(status, 200)
        self.assertTrue(self.client.is_authenticated())


class VirtualShellUnit(unittest.TestCase):
    """Direct tests for the restricted shell interpreting injections."""

    def setUp(self):
        self.shell = VirtualShell(time_scale=0.01)

    def test_sleep_is_scaled(self):
        start = time.time()
        self.assertEqual(self.shell.run("sleep 5"), 0)
        self.assertLess(time.time() - start, 1.0)

    def test_and_or_short_circuit(self):
        self.assertEqual(self.shell.run("false && touch /tmp/a"), 1)
        self.assertNotIn("/tmp/a", self.shell.fs)
        self.assertEqual(self.shell.run("true || touch /tmp/b"), 0)
        self.assertNotIn("/tmp/b", self.shell.fs)
        self.assertEqual(self.shell.run("false; touch /tmp/c"), 0)
        self.assertIn("/tmp/c", self.shell.fs)

    def test_ifs_and_bracket_test(self):
        self.assertEqual(self.shell.run("touch${IFS}/tmp/m"), 0)
        self.assertEqual(self.shell.run("[${IFS}-f${IFS}/tmp/m${IFS}]"), 0)
        self.assertEqual(self.shell.run("test -f /tmp/nope"), 1)

    def test_echo_append_and_grep(self):
        self.shell.run("printf %s hello > /tmp/f")
        self.shell.run("printf %s world >> /tmp/f")
        self.assertEqual(self.shell.fs["/tmp/f"], b"helloworld")
        self.assertEqual(self.shell.run("grep -qFx helloworld /tmp/f"), 0)
        self.assertEqual(self.shell.run("grep -qFx hellowor /tmp/f"), 1)
        self.assertEqual(self.shell.run("grep -qFx helloworldx /tmp/f"), 1)

    def test_tee_cat_tr_base64_roundtrip(self):
        import base64
        payload = os.urandom(64)
        b64 = base64.b64encode(payload).decode().replace("+", "-").replace("/", "_")
        self.shell.run(f"printf %s {b64} | tee /tmp/part")
        self.shell.run(f"cat /tmp/part | tr '_-' '/+' | base64 -d | tee /tmp/out")
        self.assertEqual(self.shell.fs["/tmp/out"], payload)

    def test_md5sum_and_rm_glob(self):
        self.shell.run("printf %s abc | tee /tmp/x_1")
        self.shell.run("printf %s abc | tee /tmp/x_2")
        expect = hashlib.md5(b"abc").hexdigest()
        self.assertEqual(self.shell.run(f"md5sum /tmp/x_1 | grep -q {expect}"), 0)
        self.assertEqual(self.shell.run(f"md5 /tmp/x_1 | grep -q {expect}"), 0)
        self.assertEqual(self.shell.run("rm -f /tmp/x_*"), 0)
        self.assertEqual(self.shell.fs, {})
        self.assertEqual(self.shell.run("rm /tmp/x_1"), 1)  # no -f: error

    def test_mkdir_touch_unknown(self):
        self.assertEqual(self.shell.run("mkdir -p /etc/nx"), 0)
        self.assertEqual(self.shell.run("test -d /etc/nx"), 0)
        self.assertEqual(self.shell.run("definitely-not-a-command"), 127)


class ProbeAgainstSimulator(GatewayCase):
    def test_fingerprint_strong_match(self):
        result = probe.run_probe(self.gateway.base_url, timeout=1.0)
        analysis = result["analysis"]
        self.assertEqual(analysis["compatibility_signal"], "strong-front-end-match")
        self.assertTrue(analysis["uses_status_cgi"])
        self.assertTrue(analysis["has_pingstatus_setter"])
        self.assertTrue(analysis["has_ping_status_reader"])
        self.assertTrue(analysis["ipv6_validator_found"])
        self.assertFalse(analysis["ipv6_validator_start_anchored"])
        self.assertFalse(analysis["ipv6_validator_end_anchored"])
        self.assertEqual(analysis["asset_version_stamps"], ["20260515082010"])
        for path in probe.ASSETS:
            self.assertEqual(result["assets"][path]["status"], 200, path)


class SessionLifecycle(GatewayCase):
    gateway_kwargs = {"auto_press_delay": 0.3}

    def test_writes_rejected_without_session(self):
        self.assertFalse(self.client.is_authenticated())
        status, _ = self.client.set("pingstatus", host="127.0.0.1",
                                    state="Requested", name="ping")
        self.assertEqual(status, 403)

    def test_button_login_full_flow(self):
        ok = self.client.button_login(wait_seconds=10, log=SILENT)
        self.assertTrue(ok)
        self.assertTrue(self.client.is_authenticated())
        status, data = self.client.get("sysinfo")
        self.assertEqual(status, 200)
        self.assertEqual(data["sysinfo"]["model"], "FGA221D")
        self.assertEqual(data["sysinfo"]["hw_version"], "GDNT-S")
        # writes accepted now
        status, _ = self.client.set("pingstatus", host="127.0.0.1",
                                    state="Requested", name="ping")
        self.assertEqual(status, 200)

    def test_reads_require_authentication(self):
        """Verified on real FW_058 hardware (2026-08-29): every nvget
        readout answers nginx 403 without an authenticated session -- even
        holding a fresh /login session cookie. Only the login_confirm
        handshake service is reachable pre-auth."""
        # fresh session cookie exists but is not authenticated
        self.assertFalse(self.client.is_authenticated())
        for service in ("sysinfo", "wanstatusinfo", "pingstatusinfo",
                        "laninfo"):
            status, _ = self.client.get(service)
            self.assertEqual(status, 403, service)
        # the login handshake itself must stay reachable pre-auth
        status, data = self.client.get("login_confirm", cmd="7")
        self.assertEqual(status, 200)
        self.assertIn("login_confirm", data)
        # after the button login, reads open up
        self.assertTrue(self.client.button_login(wait_seconds=10, log=SILENT))
        for service in ("sysinfo", "pingstatusinfo"):
            status, _ = self.client.get(service)
            self.assertEqual(status, 200, service)


class SessionExpiry(GatewayCase):
    gateway_kwargs = {"session_ttl": 0.4}

    def test_expired_session_is_rejected(self):
        self.quick_login()
        self.assertTrue(self.client.is_authenticated())
        time.sleep(0.6)
        self.assertFalse(self.client.is_authenticated())
        status, _ = self.client.set("pingstatus", host="127.0.0.1",
                                    state="Requested", name="ping")
        self.assertEqual(status, 403)


class TimingOracle(GatewayCase):
    def test_oracle_true_and_false(self):
        self.quick_login()
        with _fast_poll(inject_mod), \
                mock.patch.object(inject_mod, "ORACLE_SLEEP", FAST_ORACLE_SLEEP):
            inj = Injector(self.client, log=SILENT)
            self.assertTrue(inj.ask("true"))
            self.assertFalse(inj.ask("false"))


class VerifyFlow(GatewayCase):
    def test_verify_reports_backend_execution(self):
        self.quick_login()
        with _fast_poll(inject_mod), _fast_poll(verify_mod):
            inj = Injector(self.client, log=SILENT)
            # sleep_seconds must exceed baseline + verify.TIMING_THRESHOLD (3s)
            report = verify_mod.verify(inj, sleep_seconds=4, log=SILENT)
        self.assertTrue(report["timing_injection_observed"], report)
        self.assertTrue(report["marker_existed"], report)
        self.assertTrue(report["marker_deleted_confirmed"], report)
        self.assertTrue(report["backend_command_execution"], report)
        self.assertNotIn(report["marker"], self.gateway.virtual_fs)


class TransferEndToEnd(GatewayCase):
    def _injector(self):
        return Injector(self.client, log=SILENT)

    def test_random_payload_roundtrip(self):
        self.quick_login()
        data = random.Random(20260828).randbytes(60)
        expect_md5 = hashlib.md5(data).hexdigest()
        with _fast_poll(inject_mod), \
                mock.patch.object(inject_mod, "ORACLE_SLEEP", FAST_ORACLE_SLEEP):
            inj = self._injector()
            parts = transfer.push_data(inj, data, "e2e")
            self.assertGreater(len(parts), 1)  # exercised the chunking path
            transfer.assemble(inj, parts, "/tmp/nx_payload.bin",
                              expect_md5=expect_md5)
        self.assertEqual(self.gateway.read_file("/tmp/nx_payload.bin"), data)
        self.assertEqual(hashlib.md5(
            self.gateway.read_file("/tmp/nx_payload.bin")).hexdigest(),
            expect_md5)

    def test_corrupted_segment_is_detected(self):
        self.quick_login()
        data = random.Random(7).randbytes(20)
        with _fast_poll(inject_mod), \
                mock.patch.object(inject_mod, "ORACLE_SLEEP", FAST_ORACLE_SLEEP):
            inj = self._injector()
            parts = transfer.push_data(inj, data, "bad")
            self.gateway.shell.fs[parts[0]] = b"X" * len(
                self.gateway.shell.fs[parts[0]])
            with self.assertRaisesRegex(RuntimeError, "md5 mismatch"):
                transfer.assemble(inj, parts, "/tmp/nx_bad.bin",
                                  expect_md5=hashlib.md5(data).hexdigest())


class FingerprintGuard(GatewayCase):
    gateway_kwargs = {"model": "X9000", "board": "ZZZZ-Z",
                      "product": "OtherGate", "fw_version": "0.0.1"}

    def test_unknown_device_is_refused(self):
        self.quick_login()
        with self.assertRaises(UnknownDeviceError):
            Injector(self.client, log=SILENT)

    def test_force_bypasses_guard(self):
        self.quick_login()
        with _fast_poll(inject_mod):
            inj = Injector(self.client, force=True, log=SILENT)
        self.assertGreaterEqual(inj.base, 0.0)


class MultiProfileSimulator(unittest.TestCase):
    def test_generic_homeware_profile_is_detected(self):
        gateway = FakeGateway(profile=GENERIC_HOMEWARE_PROFILE,
                              auto_press_delay=0.5)
        gateway.start()
        try:
            result = probe.run_probe(gateway.base_url)
            self.assertEqual(
                result["analysis"]["compatibility_signal"], "strong-front-end-match")
            # Board/model/firmware come from the profile.
            client = GatewayClient(gateway.base_url)
            client.button_login(60, log=SILENT)
            status, data = client.get("sysinfo")
            self.assertEqual(status, 200)
            sysinfo = data["sysinfo"]
            self.assertEqual(sysinfo["hw_version"], "VCNT-I")
            self.assertEqual(sysinfo["model"], "VBNT-6")
            self.assertIn("VCNTI", sysinfo["fw_version"])
            # The fingerprint should map to the vcnt_i driver.
            device = detect_from_sysinfo(sysinfo)
            self.assertEqual(device.name, "vcnt_i")
            self.assertEqual(device.cap("wan", "wan4_interface"), "eth4")
        finally:
            gateway.stop()


if __name__ == "__main__":
    unittest.main()
