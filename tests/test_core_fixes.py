"""Regression tests for probe crash, User-Agent versioning, and baseline."""

import unittest
import urllib.error
from unittest import mock

from homeware_toolkit import __version__
from homeware_toolkit import probe
from homeware_toolkit import inject as inject_mod


STRONG = {
    "/login": {"body": "<html>app.js?v=20260515082010</html>"},
    "/app/app.js": {"body": "const ipv6 = /[0-9a-f:]+/gi.test(value)"},
    "/app/services/statusService.js": {
        "body": "api.set('pingstatus', data); api.get('pingstatusinfo')"},
    "/app/services/sharedServices.js": {
        "body": "apiServiceUrl', '/status.cgi'"},
}


class ProbeCrashRegression(unittest.TestCase):
    def test_missing_ipv6_validator_does_not_crash(self):
        # ipv6_pattern is None here -> must NOT raise AttributeError.
        items = {
            "/login": {"body": "nothing"},
            "/app/app.js": {"body": "no validator here"},
            "/app/services/statusService.js": {"body": ""},
            "/app/services/sharedServices.js": {"body": ""},
        }
        result = probe.inspect_assets(items)
        self.assertEqual(result["compatibility_signal"], "incomplete-match")
        self.assertFalse(result["ipv6_validator_found"])

    def test_strong_match(self):
        result = probe.inspect_assets(STRONG)
        self.assertEqual(result["compatibility_signal"], "strong-front-end-match")
        self.assertTrue(result["ipv6_validator_found"])

    def test_empty_items_no_crash(self):
        self.assertEqual(
            probe.inspect_assets({})["compatibility_signal"], "incomplete-match")


class UserAgentVersion(unittest.TestCase):
    def test_constant_uses_version(self):
        self.assertEqual(probe.USER_AGENT, f"homeware-toolkit/{__version__}")
        self.assertNotIn("1.2", probe.USER_AGENT)

    def test_fetch_actually_sends_versioned_ua(self):
        captured = {}

        def fake_urlopen(req, **kw):
            captured["ua"] = req.get_header("User-agent")
            raise urllib.error.URLError("stop")  # fetch catches this -> no net

        with mock.patch.object(probe.urllib.request, "urlopen",
                               side_effect=fake_urlopen):
            probe.fetch("https://192.0.2.1", "/login", 1.0)
        self.assertEqual(captured["ua"], probe.USER_AGENT)
        self.assertIn(__version__, captured["ua"])


class _MockClient:
    def require_auth(self):
        pass

    def get(self, service, **params):
        if service == "sysinfo":
            return 200, {"sysinfo": {"model": "NeXXt One", "hw_version": "GDNT-S",
                                     "fw_version": "22.2.0378_FW_058_FGA221D"}}
        return 200, {}

    def set(self, service, **params):
        return 200, {}


class BaselineTwoSampleMax(unittest.TestCase):
    def test_injector_baseline_takes_max_of_two(self):
        with mock.patch.object(inject_mod, "run_ping",
                               side_effect=[(2.0, {}), (3.5, {})]):
            inj = inject_mod.Injector(_MockClient())
        self.assertAlmostEqual(inj.base, 3.5)


if __name__ == "__main__":
    unittest.main()
