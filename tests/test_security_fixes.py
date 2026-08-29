"""Security tests: transfer input validation, SSH host-key TOFU, TLS pinning.

All hardware-free: subprocess is mocked, TLS is exercised with mocked
sockets, and the known_hosts trust store is redirected to a temp dir.
"""

import hashlib
import http.client
import os
import ssl
import stat
import tempfile
import unittest
import urllib.request
from unittest import mock

from home_gateway_toolkit import client as client_mod
from home_gateway_toolkit import ssh as ssh_mod
from home_gateway_toolkit import transfer


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _Inj:
    """Minimal injector double; dry_run so no verification loops run."""

    dry_run = True

    def __init__(self):
        self.commands = []

    def do(self, cmd):
        self.commands.append(cmd)

    def ask(self, cmd):
        return True

    def log(self, msg):
        pass


# ---- transfer.py: tag/target injection validation ----

class TagValidationTest(unittest.TestCase):
    def test_valid_tags(self):
        for tag in ("backup", "cfg.tar.gz", "a_b-c.1", "x" * 32, "v1.5.0"):
            self.assertEqual(transfer._validate_tag(tag), tag)

    def test_reject_empty_and_too_long(self):
        for tag in ("", "x" * 33):
            with self.assertRaises(ValueError):
                transfer._validate_tag(tag)

    def test_reject_injection_characters(self):
        for tag in ("tag;rm -rf /", "$(id)", "`id`", "a b", "../x", "a/b",
                    "tag|sh", "tag&reboot", "tag'", 'tag"', "tag>out"):
            with self.assertRaises(ValueError):
                transfer._validate_tag(tag)

    def test_push_data_rejects_bad_tag_before_any_command(self):
        inj = _Inj()
        with self.assertRaises(ValueError):
            transfer.push_data(inj, b"data", "bad;tag")
        self.assertEqual(inj.commands, [])

    def test_push_data_valid_tag_interpolated_safely(self):
        inj = _Inj()
        transfer.push_data(inj, b"data", "good-tag.1")
        self.assertTrue(inj.commands)
        self.assertTrue(all(";" not in c for c in inj.commands))
        self.assertIn("nxseg_good-tag.1_", inj.commands[0])


class TargetValidationTest(unittest.TestCase):
    def test_valid_targets(self):
        for target in ("/tmp/x", "/etc/home-gateway-toolkit/authorized_key",
                       "/www/backup-v1.2_bin", "/" + "a" * 199):
            self.assertEqual(transfer._validate_target(target), target)

    def test_reject_relative_and_empty(self):
        for target in ("", "tmp/x", "etc/passwd"):
            with self.assertRaises(ValueError):
                transfer._validate_target(target)

    def test_reject_dotdot(self):
        for target in ("/tmp/../etc/passwd", "/..", "/a/b/..c/.."):
            with self.assertRaises(ValueError):
                transfer._validate_target(target)

    def test_reject_injection_characters(self):
        for target in ("/tmp/a; reboot", "/tmp/$(id)", "/tmp/`id`",
                       "/tmp/a b", "/tmp/a|sh", "/tmp/a>out", "/tmp/paß",
                       "/tmp/a\nb"):
            with self.assertRaises(ValueError):
                transfer._validate_target(target)

    def test_reject_too_long(self):
        with self.assertRaises(ValueError):
            transfer._validate_target("/" + "a" * 200)

    def test_assemble_rejects_bad_target_before_any_command(self):
        inj = _Inj()
        with self.assertRaises(ValueError):
            transfer.assemble(inj, ["/tmp/p_000"], "/tmp/x; reboot")
        self.assertEqual(inj.commands, [])

    def test_assemble_valid_target_still_works(self):
        inj = _Inj()
        transfer.assemble(inj, ["/tmp/p_000"], "/tmp/t", expect_md5="deadbeef")
        self.assertTrue(inj.commands)


# ---- ssh.py: host-key TOFU ----

class KnownHostsPathTest(unittest.TestCase):
    def test_creates_dir_0700_and_file_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            kh_dir = os.path.join(tmp, ".home-gateway-toolkit")
            kh_file = os.path.join(kh_dir, "known_hosts")
            with mock.patch.object(ssh_mod, "KNOWN_HOSTS_DIR", kh_dir), \
                    mock.patch.object(ssh_mod, "KNOWN_HOSTS", kh_file):
                path = ssh_mod.known_hosts_path()
                self.assertEqual(path, kh_file)
                self.assertTrue(os.path.isfile(kh_file))
                self.assertEqual(
                    stat.S_IMODE(os.stat(kh_dir).st_mode), 0o700)
                self.assertEqual(
                    stat.S_IMODE(os.stat(kh_file).st_mode), 0o600)
                # Idempotent: second call keeps the store and its contents.
                with open(kh_file, "w", encoding="ascii") as fh:
                    fh.write("host ssh-rsa AAAA\n")
                self.assertEqual(ssh_mod.known_hosts_path(), kh_file)
                with open(kh_file, encoding="ascii") as fh:
                    self.assertIn("ssh-rsa", fh.read())

    def test_fixes_loose_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            kh_dir = os.path.join(tmp, ".home-gateway-toolkit")
            kh_file = os.path.join(kh_dir, "known_hosts")
            os.makedirs(kh_dir, mode=0o755)
            with open(kh_file, "w", encoding="ascii") as fh:
                fh.write("")
            os.chmod(kh_file, 0o644)
            with mock.patch.object(ssh_mod, "KNOWN_HOSTS_DIR", kh_dir), \
                    mock.patch.object(ssh_mod, "KNOWN_HOSTS", kh_file):
                ssh_mod.known_hosts_path()
            self.assertEqual(stat.S_IMODE(os.stat(kh_dir).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(kh_file).st_mode), 0o600)


class TofuSshRunTest(unittest.TestCase):
    def _run(self, **kwargs):
        with mock.patch.object(
                ssh_mod, "known_hosts_path",
                return_value="/home/u/.home-gateway-toolkit/known_hosts"
                ) as mock_kh, \
                mock.patch.object(ssh_mod.subprocess, "run",
                                  return_value=_Proc(0, "", "")) as mock_run:
            ssh_mod.ssh_run("192.0.2.1", 22, "/k", "id", **kwargs)
        return mock_run.call_args[0][0], mock_kh

    def test_default_is_tofu_accept_new(self):
        cmd, mock_kh = self._run()
        self.assertIn("StrictHostKeyChecking=accept-new", cmd)
        self.assertIn(
            "UserKnownHostsFile=/home/u/.home-gateway-toolkit/known_hosts", cmd)
        self.assertNotIn("StrictHostKeyChecking=no", cmd)
        self.assertNotIn("UserKnownHostsFile=/dev/null", cmd)
        mock_kh.assert_called_once_with()

    def test_verify_host_key_false_restores_legacy_behaviour(self):
        cmd, mock_kh = self._run(verify_host_key=False)
        self.assertIn("StrictHostKeyChecking=no", cmd)
        self.assertIn("UserKnownHostsFile=/dev/null", cmd)
        self.assertNotIn("StrictHostKeyChecking=accept-new", cmd)
        mock_kh.assert_not_called()

    def test_dropbear_rsa_constraints_preserved(self):
        for kwargs in ({}, {"verify_host_key": False}):
            cmd, _ = self._run(**kwargs)
            self.assertIn("HostKeyAlgorithms=+ssh-rsa", cmd)
            self.assertIn("PubkeyAcceptedKeyTypes=+ssh-rsa", cmd)


# ---- client.py: TLS fingerprint pinning ----

DER = b"\x30\x82fake-self-signed-der-bytes"
DER_FP = hashlib.sha256(DER).hexdigest()
DER_FP_COLON = ":".join(DER_FP[i:i + 2] for i in range(0, 64, 2))
OTHER_FP = hashlib.sha256(b"other-cert").hexdigest()


class NormalizeFingerprintTest(unittest.TestCase):
    def test_plain_lowercase(self):
        self.assertEqual(
            client_mod.normalize_tls_fingerprint(DER_FP), DER_FP)

    def test_colon_separated_uppercase(self):
        self.assertEqual(
            client_mod.normalize_tls_fingerprint(DER_FP_COLON.upper()), DER_FP)

    def test_format_round_trip(self):
        self.assertEqual(client_mod.format_tls_fingerprint(DER_FP),
                         DER_FP_COLON)

    def test_reject_garbage(self):
        for bad in ("", "zz" * 32, DER_FP[:-2], DER_FP + "00", None, 1234):
            with self.assertRaises((ValueError, TypeError)):
                client_mod.normalize_tls_fingerprint(bad)


class PinnedConnectionTest(unittest.TestCase):
    def _connect(self, fingerprint, der=DER):
        conn = client_mod._PinnedHTTPSConnection(
            "192.0.2.1", context=ssl._create_unverified_context(),
            fingerprint=fingerprint)
        conn.sock = mock.Mock()
        conn.sock.getpeercert.return_value = der
        with mock.patch.object(
                http.client.HTTPSConnection, "connect", return_value=None):
            conn.connect()
        return conn

    def test_matching_fingerprint_passes(self):
        conn = self._connect(DER_FP)
        conn.sock.getpeercert.assert_called_once_with(binary_form=True)
        conn.sock.close.assert_not_called()

    def test_mismatch_raises_and_closes(self):
        with self.assertRaises(client_mod.FingerprintMismatch) as ctx:
            self._connect(OTHER_FP)
        self.assertIn("fingerprint mismatch", str(ctx.exception))
        self.assertIn(client_mod.format_tls_fingerprint(DER_FP),
                      str(ctx.exception))

    def test_mismatch_is_an_ssl_error(self):
        with self.assertRaises(ssl.SSLError):
            self._connect(OTHER_FP)

    def test_no_pin_configured_skips_check(self):
        conn = self._connect(None)
        conn.sock.getpeercert.assert_not_called()


class ClientPinningWiringTest(unittest.TestCase):
    def _client(self, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(client_mod, "ensure_local_target",
                                   return_value=["192.0.2.1"]):
                client = client_mod.NexxtClient(
                    "https://192.168.1.254", work_dir=tmp, **kwargs)
        return client

    def test_no_fingerprint_keeps_legacy_behaviour(self):
        client = self._client()
        self.assertIsNone(client.tls_fingerprint)
        handlers = client.opener.handlers
        self.assertFalse(any(isinstance(h, client_mod._PinnedHTTPSHandler)
                             for h in handlers))
        self.assertTrue(any(isinstance(h, urllib.request.HTTPSHandler)
                            for h in handlers))

    def test_fingerprint_selects_pinned_handler(self):
        client = self._client(tls_fingerprint=DER_FP_COLON)
        self.assertEqual(client.tls_fingerprint, DER_FP)
        pinned = [h for h in client.opener.handlers
                  if isinstance(h, client_mod._PinnedHTTPSHandler)]
        self.assertEqual(len(pinned), 1)
        self.assertEqual(pinned[0]._pinned_fingerprint, DER_FP)

    def test_invalid_fingerprint_rejected(self):
        with self.assertRaises(ValueError):
            self._client(tls_fingerprint="not-a-fingerprint")


class FetchFingerprintTest(unittest.TestCase):
    def test_fetch_returns_colon_separated_sha256(self):
        tls = mock.MagicMock()
        tls.getpeercert.return_value = DER
        wrapped = mock.MagicMock()
        wrapped.__enter__.return_value = tls
        context = mock.MagicMock()
        context.wrap_socket.return_value = wrapped
        raw = mock.MagicMock()
        with mock.patch.object(client_mod.socket, "create_connection",
                               return_value=raw) as mock_conn, \
                mock.patch.object(client_mod.ssl, "_create_unverified_context",
                                  return_value=context):
            result = client_mod.fetch_tls_fingerprint("https://192.168.1.254")
        self.assertEqual(result, DER_FP_COLON)
        mock_conn.assert_called_once()
        context.wrap_socket.assert_called_once_with(
            raw.__enter__.return_value, server_hostname="192.168.1.254")

    def test_fetch_respects_explicit_port(self):
        tls = mock.MagicMock()
        tls.getpeercert.return_value = DER
        wrapped = mock.MagicMock()
        wrapped.__enter__.return_value = tls
        context = mock.MagicMock()
        context.wrap_socket.return_value = wrapped
        with mock.patch.object(client_mod.socket, "create_connection",
                               return_value=mock.MagicMock()) as mock_conn, \
                mock.patch.object(client_mod.ssl, "_create_unverified_context",
                                  return_value=context):
            client_mod.fetch_tls_fingerprint("https://192.168.1.254:8443")
        self.assertEqual(mock_conn.call_args[0][0], ("192.168.1.254", 8443))

    def test_fetch_rejects_non_https(self):
        with self.assertRaises(RuntimeError):
            client_mod.fetch_tls_fingerprint("http://192.168.1.254")


if __name__ == "__main__":
    unittest.main()
