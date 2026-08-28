"""Hardware-free tests for the WireGuard bootstrap module (vpn.py)."""

from __future__ import annotations

import base64
import os
import stat
import tempfile
import unittest
from unittest import mock

from nexxt_toolkit import vpn


def _h(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr)


NINE = bytes([9]) + bytes(31)


class X25519Rfc7748(unittest.TestCase):
    """Test vectors from RFC 7748 section 5.2."""

    def test_single_iteration_vector(self):
        out = vpn.x25519(NINE, NINE)
        self.assertEqual(
            out.hex(),
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")

    def test_thousand_iterations_vector(self):
        k = u = NINE
        for _ in range(1000):
            k, u = vpn.x25519(k, u), k
        self.assertEqual(
            k.hex(),
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")

    def test_ecdh_vector(self):
        alice_priv = _h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        alice_pub = _h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        bob_priv = _h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        bob_pub = _h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        shared = _h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        self.assertEqual(vpn.x25519(alice_priv, NINE), alice_pub)
        self.assertEqual(vpn.x25519(bob_priv, NINE), bob_pub)
        self.assertEqual(vpn.x25519(alice_priv, bob_pub), shared)
        self.assertEqual(vpn.x25519(bob_priv, alice_pub), shared)

    def test_ecdh_symmetry_random_keypairs(self):
        alice, bob = vpn.generate_keypair(), vpn.generate_keypair()
        alice_priv = base64.b64decode(alice["private"])
        bob_priv = base64.b64decode(bob["private"])
        alice_pub = base64.b64decode(alice["public"])
        bob_pub = base64.b64decode(bob["public"])
        self.assertEqual(vpn.x25519(alice_priv, bob_pub),
                         vpn.x25519(bob_priv, alice_pub))

    def test_rejects_wrong_input_lengths(self):
        with self.assertRaises(ValueError):
            vpn.x25519(b"\x00" * 31, NINE)
        with self.assertRaises(ValueError):
            vpn.x25519(NINE, b"\x00" * 33)


class WireGuardKeyFormat(unittest.TestCase):
    def test_private_key_is_base64_of_32_bytes(self):
        key = vpn.generate_private_key()
        self.assertEqual(len(key), 44)
        self.assertTrue(key.endswith("="))
        self.assertEqual(len(base64.b64decode(key)), 32)

    def test_private_key_is_clamped(self):
        for _ in range(50):
            raw = base64.b64decode(vpn.generate_private_key())
            self.assertEqual(raw[0] & 0b111, 0)
            self.assertEqual(raw[31] & 0b1000_0000, 0)
            self.assertEqual(raw[31] & 0b0100_0000, 0b0100_0000)

    def test_derive_public_key_roundtrip_and_format(self):
        pair = vpn.generate_keypair()
        self.assertEqual(len(pair["public"]), 44)
        self.assertEqual(len(base64.b64decode(pair["public"])), 32)
        self.assertEqual(vpn.derive_public_key(pair["private"]), pair["public"])

    def test_derive_public_key_matches_rfc_vector(self):
        alice_priv_b64 = base64.b64encode(
            _h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        ).decode()
        self.assertEqual(
            vpn.derive_public_key(alice_priv_b64),
            base64.b64encode(
                _h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
            ).decode())

    def test_psk_is_base64_of_32_bytes(self):
        psk = vpn.generate_psk()
        self.assertEqual(len(psk), 44)
        self.assertEqual(len(base64.b64decode(psk)), 32)
        self.assertNotEqual(psk, vpn.generate_psk())

    def test_derive_public_key_rejects_garbage(self):
        with self.assertRaises(RuntimeError):
            vpn.derive_public_key("not!base64!")
        with self.assertRaises(RuntimeError):
            vpn.derive_public_key(base64.b64encode(b"short").decode())


class ConfigGeneration(unittest.TestCase):
    def setUp(self):
        self.server = vpn.generate_keypair()
        self.client = vpn.generate_keypair()
        self.psk = vpn.generate_psk()

    def _server_config(self, peers=None):
        if peers is None:
            peers = [{"name": "phone", "public_key": self.client["public"],
                      "preshared_key": self.psk,
                      "allowed_ips": ["10.66.66.2/32"]}]
        return vpn.generate_server_config(
            private_key=self.server["private"], address="10.66.66.1/24",
            listen_port=51820, peers=peers)

    def test_server_config_required_fields(self):
        conf = self._server_config()
        self.assertIn("[Interface]", conf)
        self.assertIn(f"PrivateKey = {self.server['private']}", conf)
        self.assertIn("Address = 10.66.66.1/24", conf)
        self.assertIn("ListenPort = 51820", conf)
        self.assertIn("[Peer]", conf)
        self.assertIn(f"PublicKey = {self.client['public']}", conf)
        self.assertIn(f"PresharedKey = {self.psk}", conf)
        self.assertIn("AllowedIPs = 10.66.66.2/32", conf)
        self.assertIn("# client: phone", conf)

    def test_server_config_multiple_peers(self):
        second = vpn.generate_keypair()
        peers = [
            {"name": "phone", "public_key": self.client["public"],
             "preshared_key": self.psk, "allowed_ips": ["10.66.66.2/32"]},
            {"name": "laptop", "public_key": second["public"],
             "preshared_key": vpn.generate_psk(),
             "allowed_ips": ["10.66.66.3/32"]},
        ]
        conf = self._server_config(peers)
        self.assertEqual(conf.count("[Peer]"), 2)
        self.assertIn("# client: phone", conf)
        self.assertIn("# client: laptop", conf)
        self.assertIn("AllowedIPs = 10.66.66.3/32", conf)

    def test_client_config_required_fields(self):
        conf = vpn.generate_client_config(
            private_key=self.client["private"], address="10.66.66.2/32",
            peer_public_key=self.server["public"], preshared_key=self.psk,
            endpoint="2001:b07:abc::5",
            allowed_ips=["10.66.66.0/24", "192.168.1.0/24"],
            dns=["192.168.1.254"], persistent_keepalive=25)
        self.assertIn("[Interface]", conf)
        self.assertIn(f"PrivateKey = {self.client['private']}", conf)
        self.assertIn("Address = 10.66.66.2/32", conf)
        self.assertIn("DNS = 192.168.1.254", conf)
        self.assertIn(f"PublicKey = {self.server['public']}", conf)
        self.assertIn(f"PresharedKey = {self.psk}", conf)
        self.assertIn("AllowedIPs = 10.66.66.0/24, 192.168.1.0/24", conf)
        self.assertIn("Endpoint = [2001:b07:abc::5]:51820", conf)
        self.assertIn("PersistentKeepalive = 25", conf)

    def test_client_config_placeholder_endpoint(self):
        conf = vpn.generate_client_config(
            private_key=self.client["private"], address="10.66.66.2/32",
            peer_public_key=self.server["public"], preshared_key=self.psk,
            endpoint=None)
        self.assertIn(f"Endpoint = {vpn.ENDPOINT_PLACEHOLDER}:51820", conf)
        self.assertIn("# TODO", conf)

    def test_client_config_optional_lines_omitted(self):
        conf = vpn.generate_client_config(
            private_key=self.client["private"], address="10.66.66.2/32",
            peer_public_key=self.server["public"], preshared_key=self.psk,
            endpoint="2001:db8::1", persistent_keepalive=0)
        self.assertNotIn("DNS =", conf)
        self.assertNotIn("PersistentKeepalive", conf)

    def test_invalid_inputs_raise(self):
        with self.assertRaises(RuntimeError):
            self._server_config(
                peers=[{"name": "x", "public_key": "bogus",
                        "preshared_key": self.psk,
                        "allowed_ips": ["10.66.66.2/32"]}])
        with self.assertRaises(RuntimeError):
            vpn.generate_server_config(
                private_key=self.server["private"], address="10.66.66.1/24",
                listen_port=99999, peers=[])
        with self.assertRaises(ValueError):
            vpn.generate_client_config(
                private_key=self.client["private"], address="10.66.66.2/32",
                peer_public_key=self.server["public"], preshared_key=self.psk,
                endpoint="2001:db8::1", allowed_ips=["not-a-cidr"])


class BootstrapWireguard(unittest.TestCase):
    def _run(self, out_dir, **kwargs):
        logs = []
        fw = mock.Mock()
        fw.ensure.return_value = {"name": "Allow-WG-v6", "changed": True,
                                  "section": "@rule[2]"}
        kwargs.setdefault("log", logs.append)
        result = vpn.bootstrap_wireguard(fw, out_dir, **kwargs)
        return result, fw, logs

    def test_pinhole_uses_exact_firewall_args(self):
        out_dir = os.path.join(tempfile.mkdtemp(), "wg")
        result, fw, _logs = self._run(
            out_dir, server_ipv6="2001:b07:abc::5", clients=["phone"])
        fw.ensure.assert_called_once_with(
            name="Allow-WG-v6", proto="udp", dest_ip="2001:b07:abc::5",
            dest_port="51820", family="ipv6")
        self.assertEqual(result["rule"]["section"], "@rule[2]")
        self.assertEqual(result["endpoint"], "[2001:b07:abc::5]:51820")

    def test_custom_port_subnet_and_rule_name(self):
        out_dir = os.path.join(tempfile.mkdtemp(), "wg")
        result, fw, _logs = self._run(
            out_dir, server_ipv6="2001:b07:abc::5", clients=["a", "b"],
            wg_subnet="10.99.0.0/24", listen_port=51822,
            rule_name="WG-Custom")
        fw.ensure.assert_called_once_with(
            name="WG-Custom", proto="udp", dest_ip="2001:b07:abc::5",
            dest_port="51822", family="ipv6")
        self.assertEqual(result["server"]["wg_address"], "10.99.0.1/24")
        self.assertEqual(result["clients"][0]["wg_address"], "10.99.0.2/32")
        self.assertEqual(result["clients"][1]["wg_address"], "10.99.0.3/32")

    def test_files_written_with_strict_permissions(self):
        out_dir = os.path.join(tempfile.mkdtemp(), "wg")
        result, _fw, _logs = self._run(
            out_dir, server_ipv6="2001:b07:abc::5", clients=["phone", "laptop"])
        mode = stat.S_IMODE(os.stat(result["output_dir"]).st_mode)
        self.assertEqual(mode, 0o700)
        paths = [result["server"]["config_path"]]
        paths += [c["config_path"] for c in result["clients"]]
        self.assertEqual(len(paths), 3)
        for path in paths:
            self.assertTrue(os.path.isfile(path), path)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            with open(path) as fh:
                content = fh.read()
            self.assertIn("PrivateKey = ", content)
            self.assertEqual(content,
                             result["server"]["config"]
                             if path == result["server"]["config_path"]
                             else next(c["config"] for c in result["clients"]
                                       if c["config_path"] == path))

    def test_private_keys_never_logged_in_full(self):
        out_dir = os.path.join(tempfile.mkdtemp(), "wg")
        result, _fw, logs = self._run(
            out_dir, server_ipv6="2001:b07:abc::5", clients=["phone"])
        joined = "\n".join(logs)
        with open(result["server"]["config_path"]) as fh:
            server_conf = fh.read()
        secrets_found = [
            line.split(" = ", 1)[1] for line in server_conf.splitlines()
            if line.startswith("PrivateKey = ")]
        client_conf = result["clients"][0]["config"]
        secrets_found += [
            line.split(" = ", 1)[1] for line in client_conf.splitlines()
            if line.startswith(("PrivateKey = ", "PresharedKey = "))]
        self.assertTrue(secrets_found)
        for secret in secrets_found:
            self.assertNotIn(secret, joined)
        self.assertIn("...", joined)  # masked preview instead

    def test_existing_files_require_force(self):
        out_dir = os.path.join(tempfile.mkdtemp(), "wg")
        self._run(out_dir, server_ipv6="2001:b07:abc::5", clients=["phone"])
        with self.assertRaisesRegex(RuntimeError, "force"):
            self._run(out_dir, server_ipv6="2001:b07:abc::5",
                      clients=["phone"])

    def test_force_overwrites_and_regenerates(self):
        out_dir = os.path.join(tempfile.mkdtemp(), "wg")
        first, _fw, _logs = self._run(
            out_dir, server_ipv6="2001:b07:abc::5", clients=["phone"])
        second, _fw, _logs = self._run(
            out_dir, server_ipv6="2001:b07:abc::5", clients=["phone"],
            force=True)
        self.assertNotEqual(first["server"]["public_key"],
                            second["server"]["public_key"])
        with open(second["server"]["config_path"]) as fh:
            self.assertEqual(fh.read(), second["server"]["config"])
        self.assertIn(second["clients"][0]["public_key"],
                      second["server"]["config"])

    def test_fw_none_skips_pinhole_and_suggests_manual_command(self):
        out_dir = os.path.join(tempfile.mkdtemp(), "wg")
        result = vpn.bootstrap_wireguard(
            None, out_dir, server_ipv6="2001:b07:abc::5", clients=["phone"],
            log=lambda _m: None)
        self.assertIsNone(result["rule"])
        self.assertTrue(any("nexxt fw ensure" in step
                            for step in result["next_steps"]))

    def test_placeholder_endpoint_without_server_ipv6(self):
        out_dir = os.path.join(tempfile.mkdtemp(), "wg")
        result = vpn.bootstrap_wireguard(
            None, out_dir, clients=["phone"], log=lambda _m: None)
        self.assertIsNone(result["endpoint"])
        self.assertIn(vpn.ENDPOINT_PLACEHOLDER,
                      result["clients"][0]["config"])
        self.assertTrue(any(vpn.ENDPOINT_PLACEHOLDER in step
                            for step in result["next_steps"]))

    def test_pinhole_requires_server_ipv6(self):
        out_dir = os.path.join(tempfile.mkdtemp(), "wg")
        with self.assertRaisesRegex(RuntimeError, "server_ipv6"):
            self._run(out_dir, clients=["phone"])

    def test_snapshot_prefix_mismatch_warns(self):
        out_dir = os.path.join(tempfile.mkdtemp(), "wg")
        snapshot = {"mode": "6rd", "sixrd_prefixes": ["2001:b07:5a00::/56"]}
        result, _fw, logs = self._run(
            out_dir, server_ipv6="2001:b07:ffff::5", clients=["phone"],
            snapshot=snapshot)
        self.assertTrue(result["warnings"])
        self.assertTrue(any("WARNING" in line for line in logs))

    def test_snapshot_prefix_match_no_warning(self):
        out_dir = os.path.join(tempfile.mkdtemp(), "wg")
        snapshot = {"mode": "6rd", "sixrd_prefixes": ["2001:b07:5a00::/56"]}
        result, _fw, _logs = self._run(
            out_dir, server_ipv6="2001:b07:5a00:1::5", clients=["phone"],
            snapshot=snapshot)
        self.assertEqual(result["warnings"], [])

    def test_invalid_arguments_raise(self):
        out_dir = os.path.join(tempfile.mkdtemp(), "wg")
        base = dict(server_ipv6="2001:b07:abc::5", clients=["phone"],
                    log=lambda _m: None)
        with self.assertRaises(RuntimeError):
            vpn.bootstrap_wireguard(None, out_dir, **{**base, "clients": []})
        with self.assertRaises(RuntimeError):
            vpn.bootstrap_wireguard(
                None, out_dir, **{**base, "clients": ["phone", "phone"]})
        with self.assertRaises(RuntimeError):
            vpn.bootstrap_wireguard(
                None, out_dir, **{**base, "clients": ["bad;name"]})
        with self.assertRaises(RuntimeError):
            vpn.bootstrap_wireguard(
                None, out_dir, **{**base, "wg_subnet": "10.0.0.0/31"})
        with self.assertRaises(RuntimeError):
            vpn.bootstrap_wireguard(
                None, out_dir, **{**base, "listen_port": 0})
        with self.assertRaises(RuntimeError):
            vpn.bootstrap_wireguard(
                None, out_dir, **{**base, "server_ipv6": "fd00::1"})
        with self.assertRaises(RuntimeError):
            vpn.bootstrap_wireguard(
                None, out_dir, **{**base, "server_ipv6": "192.168.1.5"})
        with self.assertRaises(RuntimeError):
            vpn.bootstrap_wireguard(
                None, out_dir, **{**base, "rule_name": "bad name!"})

    def test_ensure_failure_leaves_no_config_files(self):
        out_dir = os.path.join(tempfile.mkdtemp(), "wg")
        fw = mock.Mock()
        fw.ensure.side_effect = RuntimeError("ssh down")
        with self.assertRaisesRegex(RuntimeError, "ssh down"):
            vpn.bootstrap_wireguard(fw, out_dir, server_ipv6="2001:b07:abc::5",
                                    clients=["phone"], log=lambda _m: None)
        self.assertFalse(os.path.exists(out_dir))


if __name__ == "__main__":
    unittest.main()
