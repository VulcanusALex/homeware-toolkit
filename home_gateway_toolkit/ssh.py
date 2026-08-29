"""Persistent key-only SSH service management (bootstrap/status/teardown)
and SSH execution helpers."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import time

from . import transfer
from .inject import I

INSTANCE = "nx"
STATE_DIR = "/etc/home-gateway-toolkit"
ROOT_RECORD = f"{STATE_DIR}/root.passwd.before"
KEY_RECORD = f"{STATE_DIR}/authorized_key"
OWNER_MARKER = f"{STATE_DIR}/dropbear.{INSTANCE}.owned"
AUTH_FILES = ("/etc/dropbear/authorized_keys", "/root/.ssh/authorized_keys")
KNOWN_HOSTS_DIR = os.path.expanduser("~/.home-gateway-toolkit")
KNOWN_HOSTS = os.path.join(KNOWN_HOSTS_DIR, "known_hosts")
# Base options only; host-key verification options are added per call by
# _host_key_opts() so the TOFU behaviour can be explicitly opted out of.
SSH_OPTS = [
    "-o", "ConnectTimeout=8",
    "-o", "PreferredAuthentications=publickey",
    "-o", "IdentitiesOnly=yes",
    "-o", "HostKeyAlgorithms=+ssh-rsa",
    "-o", "PubkeyAcceptedKeyTypes=+ssh-rsa",
]


def known_hosts_path() -> str:
    """Return the toolkit's private known_hosts path, creating it if needed.

    The directory is forced to 0700 and the file to 0600 so other local
    users can neither read nor replace the trust store.
    """
    os.makedirs(KNOWN_HOSTS_DIR, mode=0o700, exist_ok=True)
    os.chmod(KNOWN_HOSTS_DIR, 0o700)
    if not os.path.exists(KNOWN_HOSTS):
        with open(KNOWN_HOSTS, "a", encoding="ascii"):
            pass
    os.chmod(KNOWN_HOSTS, 0o600)
    return KNOWN_HOSTS


def _host_key_opts(verify_host_key: bool) -> list[str]:
    """TOFU by default: accept-new keys into the toolkit's own known_hosts.

    verify_host_key=False restores the legacy fully-unverified behaviour
    (StrictHostKeyChecking=no + /dev/null) for tests and special cases.
    """
    if verify_host_key:
        return ["-o", "StrictHostKeyChecking=accept-new",
                "-o", f"UserKnownHostsFile={known_hosts_path()}"]
    return ["-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null"]


def check_pubkey(path: str) -> bytes:
    with open(path) as fh:
        line = fh.read().strip()
    algo = line.split()[0] if line.split() else ""
    if algo != "ssh-rsa":
        raise RuntimeError(
            f"public key must be RSA (found {algo!r}); the stock dropbear is "
            "2019.x and supports neither ed25519 nor ecdsa")
    return (line + "\n").encode()


def host_of(base_url: str) -> str:
    return base_url.split("://", 1)[-1].split(":")[0].split("/")[0]


def ssh_run(host: str, port: int, key: str, remote_cmd: str,
            timeout: int = 30,
            verify_host_key: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ssh", "-i", key, "-p", str(port), *SSH_OPTS,
         *_host_key_opts(verify_host_key), f"root@{host}", remote_cmd],
        capture_output=True, text=True, timeout=timeout, check=False)


def _validate_original_shell(value: str) -> str:
    if not re.fullmatch(r"/[A-Za-z0-9_./-]{1,127}", value):
        raise RuntimeError("original shell must be an absolute path")
    return value


def _validate_service_port(port: int) -> int:
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise RuntimeError("toolkit SSH port must be between 1024 and 65535")
    return port


def _ssh_service(inj) -> str:
    """Return the SSH service name (e.g. dropbear) from device capabilities."""
    device = getattr(inj, "device", None)
    return device.cap("ssh", "service", default="dropbear") if device else "dropbear"


def _ssh_instance(inj) -> str:
    """Return the UCI instance name from device capabilities."""
    device = getattr(inj, "device", None)
    return device.cap("ssh", "instance", default=INSTANCE) if device else INSTANCE


def _ssh_shell(inj) -> str:
    """Return the target root shell path from device capabilities."""
    device = getattr(inj, "device", None)
    return device.cap("ssh", "shell", default="/bin/ash") if device else "/bin/ash"


def _ssh_original_shell(inj, fallback: str = "/bin/restricted_shell") -> str:
    """Return the pre-toolkit root shell path from device capabilities."""
    device = getattr(inj, "device", None)
    return device.cap("ssh", "original_shell", default=fallback) if device else fallback


def _prepare_state(inj, adopt_legacy: bool = False,
                   original_shell: str = "/bin/restricted_shell") -> None:
    """Create persistent ownership records before changing device state.

    v1.4.0 and older did not leave a persistent ownership marker and kept the
    passwd backup in /tmp.  Refuse to guess unless the operator explicitly
    opts into adopting such an installation.
    """
    original_shell = _validate_original_shell(
        _ssh_original_shell(inj, fallback=original_shell))
    ssh_service = _ssh_service(inj)
    ssh_instance = _ssh_instance(inj)
    ssh_shell = _ssh_shell(inj)
    owner_marker = f"{STATE_DIR}/dropbear.{ssh_instance}.owned"
    has_instance = False if inj.dry_run else inj.ask(
        f"uci{I}-q{I}show{I}{ssh_service}.{ssh_instance}")
    owned = False if inj.dry_run else inj.ask(f"test{I}-f{I}{owner_marker}")
    shell_is_ash = False if inj.dry_run else inj.ask(
        f"grep{I}-q{I}'^root:.*:{re.escape(ssh_shell)}'{I}/etc/passwd")

    if (has_instance or shell_is_ash) and not owned and not adopt_legacy:
        raise RuntimeError(
            "existing SSH/root-shell changes have no nexxt-toolkit ownership "
            "record; refusing to overwrite them. If they were created by "
            "home-gateway-toolkit <=1.4.0, re-run with --adopt-legacy")

    inj.do(f"mkdir{I}-p{I}{STATE_DIR}")
    inj.do(f"chmod{I}700{I}{STATE_DIR}")
    if not inj.dry_run and not inj.ask(f"test{I}-s{I}{ROOT_RECORD}"):
        if adopt_legacy and shell_is_ash:
            inj.do(
                f"grep{I}'^root:'{I}/etc/passwd|sed{I}"
                f"'s#{re.escape(ssh_shell)}$#{original_shell}#'|tee{I}{ROOT_RECORD}")
        else:
            inj.do(f"grep{I}'^root:'{I}/etc/passwd|tee{I}{ROOT_RECORD}")
        if not inj.ask(f"test{I}-s{I}{ROOT_RECORD}"):
            raise RuntimeError("failed to persist the original root account record")
    inj.do(f"chmod{I}600{I}{ROOT_RECORD}")
    inj.do(f"printf{I}%s{I}owned|tee{I}{owner_marker}")
    inj.do(f"chmod{I}600{I}{owner_marker}")


def backup_and_patch_shell(inj) -> None:
    ssh_shell = _ssh_shell(inj)
    if not inj.ask(f"grep{I}-q{I}'^root:.*:{re.escape(ssh_shell)}'{I}/etc/passwd"):
        inj.do("sed" + I + "-i" + I +
               f"'s#^\\(root:.*:\\)[^:]*$#\\1{ssh_shell}#'" + I + "/etc/passwd")
        if not inj.dry_run and not inj.ask(
                f"grep{I}-q{I}'^root:.*:{re.escape(ssh_shell)}'{I}/etc/passwd"):
            raise RuntimeError("failed to patch root shell")


def _remove_recorded_key(inj) -> None:
    if inj.dry_run or not inj.ask(f"test{I}-s{I}{KEY_RECORD}"):
        return
    for index, target in enumerate(AUTH_FILES):
        if not inj.ask(f"test{I}-f{I}{target}"):
            continue
        temp = f"/tmp/nx_auth_{index}"
        inj.do(f"grep{I}-vxF{I}-f{I}{KEY_RECORD}{I}{target}|tee{I}{temp}")
        inj.do(f"cp{I}{temp}{I}{target}")
        inj.do(f"chmod{I}600{I}{target}")
        inj.do(f"rm{I}-f{I}{temp}")


def install_key(inj, keydata: bytes) -> None:
    # Rotation is exact: remove only the key recorded by this toolkit, never
    # replace or delete unrelated authorized_keys content.
    _remove_recorded_key(inj)
    parts = transfer.push_data(inj, keydata, "sshkey")
    want = hashlib.md5(keydata).hexdigest()
    transfer.assemble(inj, parts, KEY_RECORD, expect_md5=want)
    inj.do(f"chmod{I}600{I}{KEY_RECORD}")
    inj.do(f"mkdir{I}-p{I}/etc/dropbear{I}/root/.ssh")
    for target in AUTH_FILES:
        inj.do(f"touch{I}{target}")
        inj.do(
            f"grep{I}-qFx{I}-f{I}{KEY_RECORD}{I}{target}"
            f"||cat{I}{KEY_RECORD}|tee{I}-a{I}{target}")
        inj.do(f"chmod{I}600{I}{target}")
    if not inj.dry_run:
        for target in AUTH_FILES:
            if not inj.ask(f"grep{I}-qFx{I}-f{I}{KEY_RECORD}{I}{target}"):
                raise RuntimeError(f"public key missing after install: {target}")
    inj.do(f"chmod{I}700{I}/root/.ssh")
    inj.do(f"rm{I}-f{I}/tmp/nxg_*{I}/tmp/nxseg_sshkey_*")


def create_instance(inj, port: int) -> None:
    port = _validate_service_port(port)
    ssh_service = _ssh_service(inj)
    ssh_instance = _ssh_instance(inj)
    if not inj.dry_run and inj.ask(f"uci{I}-q{I}show{I}{ssh_service}.{ssh_instance}"):
        inj.log(f"[ssh] uci instance {ssh_instance!r} already exists, reusing")
    else:
        inj.do(f"uci{I}add{I}{ssh_service}{I}{ssh_service}")
        inj.do(f"uci{I}rename{I}{ssh_service}.@{ssh_service}[-1]={ssh_instance}")
    inj.do(f"uci{I}set{I}{ssh_service}.{ssh_instance}.enable=1")
    inj.do(f"uci{I}set{I}{ssh_service}.{ssh_instance}.Port={port}")
    inj.do(f"uci{I}set{I}{ssh_service}.{ssh_instance}.Interface=lan")
    inj.do(f"uci{I}set{I}{ssh_service}.{ssh_instance}.PasswordAuth=off")
    inj.do(f"uci{I}set{I}{ssh_service}.{ssh_instance}.RootPasswordAuth=off")
    inj.do(f"uci{I}commit{I}{ssh_service}")
    inj.do(f"/etc/init.d/{ssh_service}{I}restart")
    time.sleep(2)
    if not inj.dry_run and not inj.ask(f"netstat{I}-tln|grep{I}-q{I}:{port}"):
        raise RuntimeError(f"{ssh_service} not listening on port {port}")


def bootstrap(inj, pubkey_path: str, port: int, log=print,
              adopt_legacy: bool = False,
              original_shell: str = "/bin/restricted_shell") -> None:
    """Idempotent: re-running repairs any missing piece."""
    port = _validate_service_port(port)
    keydata = check_pubkey(pubkey_path)
    _prepare_state(inj, adopt_legacy=adopt_legacy,
                   original_shell=original_shell)
    backup_and_patch_shell(inj)
    log("[ssh] root shell ready")
    install_key(inj, keydata)
    log("[ssh] public key installed (md5 verified)")
    create_instance(inj, port)


def status(inj, port: int) -> dict:
    ssh_service = _ssh_service(inj)
    ssh_instance = _ssh_instance(inj)
    owner_marker = f"{STATE_DIR}/dropbear.{ssh_instance}.owned"
    return {
        "port": port,
        "listening": inj.ask(f"netstat{I}-tln|grep{I}-q{I}:{port}"),
        "uci_instance": inj.ask(f"uci{I}-q{I}show{I}{ssh_service}.{ssh_instance}"),
        "authorized_keys": inj.ask(f"test{I}-s{I}/etc/dropbear/authorized_keys"),
        "managed_state": inj.ask(f"test{I}-s{I}{owner_marker}"),
    }


def teardown(inj, port: int, log=print, legacy_force: bool = False) -> None:
    ssh_service = _ssh_service(inj)
    ssh_instance = _ssh_instance(inj)
    owner_marker = f"{STATE_DIR}/dropbear.{ssh_instance}.owned"
    owned = False if inj.dry_run else inj.ask(f"test{I}-s{I}{owner_marker}")
    if not owned and not legacy_force and not inj.dry_run:
        raise RuntimeError(
            "no persistent ownership record found; refusing destructive "
            "legacy teardown. Use --legacy-force only for a confirmed "
            "home-gateway-toolkit <=1.4.0 installation")

    if owned:
        _remove_recorded_key(inj)
        if inj.ask(f"test{I}-s{I}{ROOT_RECORD}"):
            inj.do(
                f"cat{I}{ROOT_RECORD}|tee{I}/tmp/nx_root_restore;"
                f"grep{I}-v{I}'^root:'{I}/etc/passwd|tee{I}-a{I}/tmp/nx_root_restore")
            inj.do(f"cp{I}/tmp/nx_root_restore{I}/etc/passwd")
            inj.do(f"rm{I}-f{I}/tmp/nx_root_restore")
    elif legacy_force:
        if inj.ask(f"test{I}-f{I}/tmp/nx_passwd.bak"):
            inj.do(f"cp{I}/tmp/nx_passwd.bak{I}/etc/passwd")
        inj.do(f"rm{I}-f{I}/etc/dropbear/authorized_keys{I}/root/.ssh/authorized_keys")

    if inj.ask(f"uci{I}-q{I}show{I}{ssh_service}.{ssh_instance}"):
        inj.do(f"uci{I}delete{I}{ssh_service}.{ssh_instance}")
        inj.do(f"uci{I}commit{I}{ssh_service}")
    inj.do(f"/etc/init.d/{ssh_service}{I}restart")
    if owned:
        inj.do(f"rm{I}-rf{I}{STATE_DIR}")
    time.sleep(2)
    still = inj.ask(f"netstat{I}-tln|grep{I}-q{I}:{port}")
    log(f"[teardown] done; port {port} "
        f"{'STILL LISTENING (check manually!)' if still else 'closed'}")
