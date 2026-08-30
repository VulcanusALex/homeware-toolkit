"""Tests for the SRP-6 implementation and the simulated /authenticate flow."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from homeware_toolkit import srp6  # noqa: E402
from homeware_toolkit.client import GatewayClient  # noqa: E402
from homeware_toolkit.simulator import (  # noqa: E402
    FakeGateway, GENERIC_HOMEWARE_PROFILE)

SILENT = lambda *args: None  # noqa: E731


class SRP6Math(unittest.TestCase):
    def test_client_server_roundtrip(self):
        salt, verifier = srp6.make_verifier(b"vodafone", b"secret123")
        client = srp6.Client(b"vodafone", b"secret123")
        server = srp6.Server(b"vodafone", salt, verifier)
        expected_m1, m2 = server.process(client.public_ephemeral())
        m1 = client.process_challenge(salt, server.public_ephemeral())
        self.assertEqual(m1, expected_m1)
        self.assertTrue(client.verify_server(m2))

    def test_wrong_password_fails(self):
        salt, verifier = srp6.make_verifier(b"vodafone", b"secret123")
        client = srp6.Client(b"vodafone", b"wrong")
        server = srp6.Server(b"vodafone", salt, verifier)
        expected_m1, _ = server.process(client.public_ephemeral())
        m1 = client.process_challenge(salt, server.public_ephemeral())
        self.assertNotEqual(m1, expected_m1)

    def test_unsafe_ephemerals_rejected(self):
        client = srp6.Client(b"u", b"p")
        with self.assertRaises(ValueError):
            client.process_challenge(b"\x00\x01", (0).to_bytes(1, "big"))
        salt, verifier = srp6.make_verifier(b"u", b"p")
        server = srp6.Server(b"u", salt, verifier)
        with self.assertRaises(ValueError):
            server.process((0).to_bytes(1, "big"))


class SRP6AgainstSimulator(unittest.TestCase):
    def setUp(self):
        self.gateway = FakeGateway(profile=GENERIC_HOMEWARE_PROFILE)
        self.gateway.start()
        self.tmp = __import__("tempfile").TemporaryDirectory()
        self.client = GatewayClient(self.gateway.base_url, timeout=5.0,
                                    work_dir=self.tmp.name)

    def tearDown(self):
        self.gateway.stop()
        self.tmp.cleanup()

    def test_srp6_login_success(self):
        self.assertTrue(self.client.srp6_login("vodafone", "vodafone",
                                               log=SILENT))
        self.assertTrue(self.client.is_authenticated())

    def test_srp6_login_wrong_password(self):
        self.assertFalse(self.client.srp6_login("vodafone", "nope",
                                                log=SILENT))
        self.assertFalse(self.client.is_authenticated())

    def test_srp6_login_unknown_user(self):
        self.assertFalse(self.client.srp6_login("nobody", "x", log=SILENT))


if __name__ == "__main__":
    unittest.main()
