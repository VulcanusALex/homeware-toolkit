"""Security tests for firewall command-injection hardening."""

import unittest
from unittest import mock

from home_gateway_toolkit import firewall
from home_gateway_toolkit.firewall import FW, NAME_RE


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fw():
    return FW("192.0.2.1", 22, "/dev/null")


class AllowValidationTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(
            firewall, "ssh_run", return_value=_Proc(0, "", ""))
        self.mock_ssh = patcher.start()
        self.addCleanup(patcher.stop)

    def test_dest_ip_single_quote(self):
        with self.assertRaises(RuntimeError):
            _fw().allow("web", "tcp", "1.2.3.4'", "80")

    def test_dest_ip_semicolon(self):
        with self.assertRaises(RuntimeError):
            _fw().allow("web", "tcp", "1.2.3.4; reboot", "80")

    def test_dest_ip_space(self):
        with self.assertRaises(RuntimeError):
            _fw().allow("web", "tcp", "1.2.3.4 5.6.7.8", "80")

    def test_dest_ip_bogus(self):
        with self.assertRaises(RuntimeError):
            _fw().allow("web", "tcp", "notanip", "80")

    def test_dest_port_injection(self):
        with self.assertRaises(RuntimeError):
            _fw().allow("web", "tcp", "192.168.8.10", "22; reboot")

    def test_dest_port_abc(self):
        with self.assertRaises(RuntimeError):
            _fw().allow("web", "tcp", "192.168.8.10", "abc")

    def test_dest_port_out_of_range(self):
        with self.assertRaises(RuntimeError):
            _fw().allow("web", "tcp", "192.168.8.10", "70000")

    def test_bad_zone(self):
        with self.assertRaises(RuntimeError):
            _fw().allow("web", "tcp", "192.168.8.10", "80", src="wan; x")

    def test_bad_proto(self):
        with self.assertRaises(RuntimeError):
            _fw().allow("web", "tcp; x", "192.168.8.10", "80")

    def test_accept_ipv6_cidr_single_port(self):
        _fw().allow("wg", "udp", "2001:db8::b85/128", "51820")
        self.assertTrue(self.mock_ssh.called)

    def test_accept_port_range(self):
        self.mock_ssh.reset_mock()
        _fw().allow("wg", "udp", "2001:db8::b85/128", "51820-51830")
        self.assertTrue(self.mock_ssh.called)

    def test_accept_port_list(self):
        self.mock_ssh.reset_mock()
        _fw().allow("web", "tcp", "2001:db8::b85/128", "80,443")
        self.assertTrue(self.mock_ssh.called)

    def test_accept_ipv4_plain(self):
        self.mock_ssh.reset_mock()
        _fw().allow("web", "tcp", "192.168.8.10", "443")
        self.assertTrue(self.mock_ssh.called)

    def test_ipv6_prefix_out_of_range(self):
        with self.assertRaises(RuntimeError):
            _fw().allow("web", "tcp", "2001:db8::1/129", "80")

    def test_ipv4_prefix_out_of_range(self):
        with self.assertRaises(RuntimeError):
            _fw().allow("web", "tcp", "192.168.8.10/33", "80")

    def test_dest_ip_ipv6_scope_id_injection(self):
        # ipaddress.ip_address() accepts %<zone>; ensure the scope-id vector
        # (which could smuggle a quote out of the UCI string) is rejected.
        with self.assertRaises(RuntimeError):
            _fw().allow("web", "tcp", "::1%'; reboot; '", "80")

    def test_dest_ip_is_normalized_before_interpolation(self):
        # The command actually sent must contain the canonical address, never
        # the caller's raw bytes.
        self.mock_ssh.reset_mock()
        _fw().allow("web", "tcp", "2001:0db8:0000::0001", "80")
        sent = " ".join(str(c.args) for c in self.mock_ssh.call_args_list)
        self.assertIn("2001:db8::1", sent)
        self.assertNotIn("2001:0db8:0000::0001", sent)


class DeleteValidationTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(
            firewall, "ssh_run", return_value=_Proc(0, "", ""))
        self.mock_ssh = patcher.start()
        self.addCleanup(patcher.stop)

    def test_delete_injection(self):
        with self.assertRaises(RuntimeError):
            _fw().delete("x'; reboot; '")

    def test_delete_valid(self):
        # empty stdout -> no sections -> returns []
        result = _fw().delete("wg-tunnel")
        self.assertEqual(result, [])
        self.assertTrue(self.mock_ssh.called)


class NameReTest(unittest.TestCase):
    def test_name_re_still_meaningful(self):
        self.assertTrue(NAME_RE.match("wg-tunnel_1"))
        self.assertFalse(NAME_RE.match("x'; reboot; '"))
        self.assertFalse(NAME_RE.match(""))


if __name__ == "__main__":
    unittest.main()
