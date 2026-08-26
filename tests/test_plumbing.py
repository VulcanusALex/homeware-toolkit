"""Regression tests for transfer md5 verify, path expansion, UA, dead code."""

import os
import tempfile
import unittest
from unittest import mock

from nexxt_toolkit import __version__
from nexxt_toolkit import transfer, wanwatch, doctor, client


class _FakeInj:
    def __init__(self, ask_result=True):
        self.dry_run = False
        self.ask_result = ask_result
        self.cmds = []

    def do(self, cmd):
        self.cmds.append(cmd)

    def ask(self, cmd):
        return self.ask_result

    def log(self, msg):
        pass


class TransferMd5Verify(unittest.TestCase):
    def test_md5_mismatch_raises(self):
        inj = _FakeInj(ask_result=False)  # md5 oracle says "no match"
        with self.assertRaises(RuntimeError):
            transfer.assemble(inj, ["/tmp/p_000"], "/tmp/t", expect_md5="deadbeef")

    def test_md5_match_ok(self):
        inj = _FakeInj(ask_result=True)
        transfer.assemble(inj, ["/tmp/p_000"], "/tmp/t", expect_md5="deadbeef")

    def test_backward_compatible_no_md5(self):
        # ssh.install_key still calls assemble(inj, parts, target) with no md5.
        inj = _FakeInj(ask_result=False)  # would raise if md5 were consulted
        transfer.assemble(inj, ["/tmp/p_000"], "/tmp/t")

    def test_group_temps_cleaned(self):
        inj = _FakeInj()
        transfer.assemble(inj, ["/tmp/p_000"], "/tmp/t")
        self.assertTrue(any("rm" in c and "/tmp/nxg_" in c for c in inj.cmds))


class PathExpansion(unittest.TestCase):
    def test_leading_tilde_expands(self):
        self.assertEqual(os.path.expanduser("~/.nexxt_wanwatch_state.json"),
                         os.path.join(os.path.expanduser("~"),
                                      ".nexxt_wanwatch_state.json"))

    def test_embedded_tilde_untouched(self):
        self.assertEqual(os.path.expanduser("/tmp/a~b.json"), "/tmp/a~b.json")


class UserAgentVersion(unittest.TestCase):
    def test_client_ua_uses_version(self):
        self.assertIn(__version__, client.USER_AGENT)
        self.assertNotIn("1.2 ", client.USER_AGENT)


class DeadCodeRemoved(unittest.TestCase):
    def test_wan_class_from_dump_gone(self):
        self.assertFalse(hasattr(doctor, "_wan_class_from_dump"))


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class WanwatchStateRoundTrip(unittest.TestCase):
    def test_public_ipv4_exit_zero_and_state_written(self):
        statefile = os.path.join(tempfile.mkdtemp(), "state.json")
        out = "inet 8.8.8.8/24\ninet6 2001:db8::1/64"
        with mock.patch.object(wanwatch, "ssh_run",
                               return_value=_Proc(0, out)):
            report, code = wanwatch.watch("h", 22, "k", statefile)
        self.assertEqual(code, 0)  # public IPv4
        self.assertEqual(report["wan_ipv4_class"], "PUBLIC")
        self.assertTrue(os.path.exists(statefile))
        self.assertFalse(os.path.exists(statefile + ".tmp"))  # atomic


def _rich(sixrd_up, wan6_up, wan4):
    sixrd = ('{"up":true,"dynamic":true,"ipv6-prefix":'
             '[{"address":"2001:db8:a::","mask":64}]}') if sixrd_up else '{"up":false}'
    wan6 = '{"up":true,"ipv6-prefix":[{"address":"2001:db8:b::","mask":64}]}' \
        if wan6_up else '{"up":false}'
    return (f"{sixrd}\n{wanwatch._M_WAN6}\n{wan6}\n{wanwatch._M_IP4}\n"
            f"inet {wan4}/22\n{wanwatch._M_IP6}\n"
            "inet6 2001:db8:a::b85/64 scope global")


class WanwatchRich(unittest.TestCase):
    def test_mode_detection_and_change(self):
        statefile = os.path.join(tempfile.mkdtemp(), "s.json")
        out1 = _rich(sixrd_up=True, wan6_up=False, wan4="100.64.1.1")   # 6rd, CGNAT
        out2 = _rich(sixrd_up=False, wan6_up=True, wan4="203.0.113.5")  # native, public
        with mock.patch.object(wanwatch, "ssh_run",
                               side_effect=[_Proc(0, out1), _Proc(0, out2)]):
            r1, c1 = wanwatch.watch("h", 22, "k", statefile)
            r2, c2 = wanwatch.watch("h", 22, "k", statefile)
        self.assertEqual(r1["mode"], "6rd")
        self.assertEqual(r1["wan_ipv4_class"], "CGNAT-100.64/10")
        self.assertEqual(c1, 1)                       # not yet public, first run
        self.assertEqual(c2, 2)                        # provisioning changed
        self.assertIn("mode 6rd -> native-dhcpv6", r2["change_summary"])
        self.assertEqual(r1["sixrd_prefixes"], ["2001:db8:a::/64"])


if __name__ == "__main__":
    unittest.main()
