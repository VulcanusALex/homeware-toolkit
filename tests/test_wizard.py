"""Tests for the local setup wizard (home-gateway setup --wizard)."""

from __future__ import annotations

import threading
import unittest
import urllib.error
import urllib.request

from home_gateway_toolkit import wizard
from home_gateway_toolkit.simulator import FakeGateway


class WizardServerTest(unittest.TestCase):
    def setUp(self):
        self.gateway = FakeGateway()
        self.gateway.start()
        self.state = wizard.WizardState(self.gateway.base_url)
        self.server = wizard.HTTPServer(
            ("127.0.0.1", 0), wizard.make_handler(self.state))
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.gateway.stop()

    def _get(self, path: str) -> tuple[int, str]:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{self.port}{path}", timeout=5) as resp:
            return resp.status, resp.read().decode("utf-8")

    def test_serves_html(self):
        status, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("home-gateway setup wizard", body)
        self.assertIn("<button", body)

    def test_probe_endpoint(self):
        status, body = self._get("/api/probe")
        self.assertEqual(status, 200)
        data = __import__("json").loads(body)
        self.assertEqual(data["target"], self.gateway.base_url)
        self.assertIn("analysis", data)

    def test_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._get("/nonexistent")
        self.assertEqual(ctx.exception.code, 404)


class WizardStateTest(unittest.TestCase):
    def test_default_device(self):
        state = wizard.WizardState("http://192.168.1.254")
        self.assertEqual(state.detect_device().name, "nexxt")


if __name__ == "__main__":
    unittest.main()
