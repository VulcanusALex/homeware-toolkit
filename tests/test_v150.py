"""Regression tests for safe lifecycle, inbound observation and support tools."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
import zipfile
from unittest import mock

from home_gateway_toolkit import audit, doctor, egress, firewall, inbound, setup, ssh, support
from home_gateway_toolkit.cli import build_parser


class _Inj:
    def __init__(self, answers=None, dry_run=False):
        self.answers = answers or {}
        self.dry_run = dry_run
        self.commands = []
        self.logs = []

    def ask(self, command):
        for needle, answer in self.answers.items():
            if needle in command:
                return answer
        return False

    def do(self, command):
        self.commands.append(command)

    def log(self, message):
        self.logs.append(message)


def _pubkey():
    with tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False) as handle:
        handle.write("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0 test\n")
        return handle.name


class SafeSshLifecycle(unittest.TestCase):
    def test_privileged_or_invalid_bootstrap_port_is_refused(self):
        key = _pubkey()
        try:
            with self.assertRaisesRegex(RuntimeError, "1024"):
                ssh.bootstrap(_Inj(dry_run=True), key, 22)
        finally:
            os.unlink(key)

    def test_unowned_legacy_install_is_refused(self):
        inj = _Inj({"uci${IFS}-q${IFS}show${IFS}dropbear.nx": True})
        key = _pubkey()
        try:
            with self.assertRaisesRegex(RuntimeError, "--adopt-legacy"):
                ssh.bootstrap(inj, key, 2222)
        finally:
            os.unlink(key)

    def test_safe_teardown_removes_only_recorded_key(self):
        inj = _Inj({
            ssh.OWNER_MARKER: True,
            ssh.KEY_RECORD: True,
            "/etc/dropbear/authorized_keys": True,
            "/root/.ssh/authorized_keys": True,
            ssh.ROOT_RECORD: True,
            "dropbear.nx": True,
        })
        with mock.patch.object(ssh.time, "sleep"):
            ssh.teardown(inj, 2222)
        joined = "\n".join(inj.commands)
        self.assertIn("grep${IFS}-vxF", joined)
        self.assertNotIn("rm${IFS}-f${IFS}/etc/dropbear/authorized_keys", joined)
        self.assertIn(ssh.ROOT_RECORD, joined)

    def test_unowned_teardown_refuses_by_default(self):
        with self.assertRaisesRegex(RuntimeError, "ownership record"):
            ssh.teardown(_Inj(), 2222)

    def test_install_key_appends_instead_of_replacing(self):
        inj = _Inj({"grep${IFS}-qFx": True,
                    ssh.KEY_RECORD: False,
                    "/etc/dropbear/authorized_keys": True,
                    "/root/.ssh/authorized_keys": True})
        with (mock.patch.object(ssh.transfer, "push_data", return_value=["/tmp/p"]),
              mock.patch.object(ssh.transfer, "assemble")):
            ssh.install_key(inj, b"ssh-rsa AAAA test\n")
        joined = "\n".join(inj.commands)
        self.assertIn("tee${IFS}-a", joined)
        self.assertNotIn("cp${IFS}/etc/dropbear/authorized_keys", joined)


class DoctorNatSemantics(unittest.TestCase):
    class Client:
        def __init__(self, *_args, **_kwargs):
            pass

        def is_authenticated(self):
            return False

    class Proc:
        def __init__(self, stdout, returncode=0, stderr=""):
            self.stdout, self.returncode, self.stderr = stdout, returncode, stderr

    def test_private_wan_is_informational_not_blocked(self):
        probe = {"analysis": {"compatibility_signal": "strong-front-end-match"}}
        with (mock.patch.object(doctor.probe_mod, "run_probe", return_value=probe),
              mock.patch.object(doctor, "NexxtClient", self.Client),
              mock.patch.object(doctor, "ssh_run", side_effect=[
                  self.Proc("OK\n"), self.Proc("inet 10.64.23.145/22\n")])):
            stages, code = doctor.run_doctor("https://192.168.1.254", 2222,
                                             key="key", check_injection=False,
                                             log=lambda _m: None)
        wan = next(s for s in stages if s["stage"] == "wan-ipv4-assignment")
        reach = next(s for s in stages if s["stage"] == "inbound-reachability")
        self.assertEqual(wan["status"], "INFO")
        self.assertIn("cannot determine", wan["hint"])
        self.assertEqual(reach["status"], "SKIP")
        self.assertEqual(code, 0)


class OptInEgress(unittest.TestCase):
    def test_dual_stack_query(self):
        with mock.patch.object(egress, "_fetch",
                               side_effect=["198.51.100.8", "2001:db8::8"]):
            result = egress.query()
        self.assertEqual(result, {"ipv4": "198.51.100.8", "ipv6": "2001:db8::8"})


class InboundObserve(unittest.TestCase):
    class FW:
        def __init__(self, snapshots):
            self.snapshots = iter(snapshots)

        def list_rules(self):
            return [{"name": "vpn", "section": "@rule[3]"}]

        def counter_snapshot(self, _name):
            return next(self.snapshots)

    def test_positive_delta_confirms_gateway_arrival(self):
        fw = self.FW([
            {"name": "vpn", "matched_rules": 1, "packets": 4, "bytes": 100},
            {"name": "vpn", "matched_rules": 1, "packets": 6, "bytes": 260},
        ])
        with (mock.patch.object(inbound.time, "monotonic", side_effect=[0, 0.1, 0.2]),
              mock.patch.object(inbound.time, "sleep")):
            result = inbound.observe(fw, "vpn", seconds=1, log=lambda _m: None)
        self.assertEqual(result["state"], "confirmed-at-gateway")
        self.assertEqual(result["packet_delta"], 2)


class FirewallManagement(unittest.TestCase):
    def test_ensure_noop_when_rule_is_exact(self):
        fw = firewall.FW("host", 22, "key")
        existing = {"section": "@rule[3]", "name": "vpn", "src": "wan",
                    "dest": "lan", "proto": "udp", "family": "ipv6",
                    "dest_ip": "2001:db8::1", "dest_port": "51820",
                    "target": "ACCEPT", "enabled": "1"}
        with (mock.patch.object(fw, "list_rules", return_value=[existing]),
              mock.patch.object(fw, "run") as run):
            result = fw.ensure("vpn", "udp", "2001:db8::1", "51820")
        self.assertFalse(result["changed"])
        run.assert_not_called()

    def test_counter_parser_sums_exact_name(self):
        fw = firewall.FW("host", 22, "key")
        data = ("[2:120] -A zone_wan_forward -m comment --comment \"!fw3: vpn\"\n"
                "[8:900] -A x -m comment --comment \"!fw3: other\"\n"
                "[1:60] -A y -m comment --comment \"vpn\"\n")
        with mock.patch.object(fw, "run", return_value=data):
            result = fw.counter_snapshot("vpn")
        self.assertEqual(result["matched_rules"], 2)
        self.assertEqual(result["packets"], 3)

    def test_ensure_rolls_back_when_rule_does_not_persist(self):
        fw = firewall.FW("host", 22, "key")
        commands = []
        with (mock.patch.object(fw, "list_rules", side_effect=[[], []]),
              mock.patch.object(fw, "run", side_effect=lambda cmd: commands.append(cmd) or ""),
              self.assertRaisesRegex(RuntimeError, "did not persist")):
            fw.ensure("vpn", "udp", "2001:db8::1", "51820")
        self.assertTrue(any("uci import firewall" in cmd for cmd in commands))

    def test_audit_flags_broad_wan_accept(self):
        fw = firewall.FW("host", 22, "key")
        broad = {"section": "@rule[1]", "name": "too-wide", "src": "wan",
                 "target": "ACCEPT", "enabled": "1"}
        with (mock.patch.object(fw, "list_rules", return_value=[broad]),
              mock.patch.object(fw, "_runtime_rows", return_value=[])):
            result = fw.audit()
        self.assertFalse(result["ok"])
        self.assertIn("broad-wan-accept", {f["type"] for f in result["findings"]})

    def test_delete_revalidates_remote_section_name(self):
        fw = firewall.FW("host", 22, "key")
        with (mock.patch.object(fw, "run", return_value="safe\n@rule[3]\nbad;reboot\n"),
              self.assertRaisesRegex(RuntimeError, "unsafe UCI section")):
            fw.delete("vpn")


class SanitizedSupportBundle(unittest.TestCase):
    def test_recursive_sanitizer_removes_secrets_and_addresses(self):
        value = {"sessionID": "secret", "nested": {"mac": "aa:bb:cc:dd:ee:ff"},
                 "message": "gateway 192.168.1.254 and [2001:db8::b85]"}
        clean = support._sanitize(value)
        encoded = json.dumps(clean)
        self.assertNotIn("secret", encoded)
        self.assertNotIn("192.168.1.254", encoded)
        self.assertNotIn("aa:bb:cc:dd:ee:ff", encoded)
        self.assertNotIn("2001:db8::b85", encoded)

    def test_zip_contains_report_and_review_notice(self):
        path = os.path.join(tempfile.mkdtemp(), "bundle.zip")
        support.write_bundle({"safe": True}, path)
        with zipfile.ZipFile(path) as archive:
            self.assertEqual(set(archive.namelist()), {"report.json", "README.txt"})


class SetupKeypair(unittest.TestCase):
    def test_existing_pair_is_reused(self):
        directory = tempfile.mkdtemp()
        private = os.path.join(directory, "id_rsa")
        with open(private, "w") as fh:
            fh.write("private-placeholder")
        with open(private + ".pub", "w") as fh:
            fh.write("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0 test\n")
        result = setup.ensure_keypair(private, log=lambda _m: None)
        self.assertEqual(result, (private, private + ".pub", False))


class UpgradeAudit(unittest.TestCase):
    class Proc:
        returncode = 0
        stderr = ""
        stdout = ("__SHELL__\nroot:x:0:0:root:/root:/bin/ash\n__DROPBEAR__\n"
                  "dropbear.nx.Interface='lan'\n"
                  "dropbear.nx.PasswordAuth='off'\n"
                  "dropbear.nx.RootPasswordAuth='off'\n"
                  "__STATE__\nmanaged\n")

    def test_changed_fingerprint_is_not_accepted_implicitly(self):
        state = os.path.join(tempfile.mkdtemp(), "audit.json")
        probes = [
            {"analysis": {"compatibility_signal": "strong-front-end-match",
                          "asset_version_stamps": ["one"]}},
            {"analysis": {"compatibility_signal": "strong-front-end-match",
                          "asset_version_stamps": ["two"]}},
        ]
        fw_report = {"ok": True, "rules": [], "findings": []}
        fake_fw = mock.Mock()
        fake_fw.audit.return_value = fw_report
        with (mock.patch.object(audit, "run_probe", side_effect=probes),
              mock.patch.object(audit, "ssh_run", return_value=self.Proc()),
              mock.patch.object(audit, "FW", return_value=fake_fw)):
            _first, first_code = audit.run_audit("https://192.168.1.254", 2222,
                                                 "key", state)
            second, second_code = audit.run_audit("https://192.168.1.254", 2222,
                                                  "key", state)
        self.assertEqual(first_code, 0)
        self.assertEqual(second_code, 0)  # change is a warning, not a false failure
        self.assertTrue(second["firmware_changed"])
        self.assertFalse(second["baseline_updated"])
        with open(state) as fh:
            self.assertEqual(json.load(fh)["asset_version_stamps"], ["one"])


class CliCoverage(unittest.TestCase):
    def test_new_commands_parse(self):
        parser = build_parser()
        self.assertEqual(parser.parse_args(["setup", "--yes"]).command, "setup")
        self.assertEqual(parser.parse_args(
            ["inbound", "observe", "--rule", "vpn", "--key", "k"]
        ).inbound_cmd, "observe")
        self.assertEqual(parser.parse_args(
            ["fw", "audit", "--key", "k"]).fw_cmd, "audit")
        self.assertEqual(parser.parse_args(
            ["support-bundle"]).command, "support-bundle")


if __name__ == "__main__":
    unittest.main()
