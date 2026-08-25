"""Persistent key-only SSH service management (bootstrap/status/teardown)
and SSH execution helpers."""

from __future__ import annotations

import hashlib
import subprocess
import time

from .inject import I
from . import transfer

INSTANCE = "nx"
SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=8",
    "-o", "PreferredAuthentications=publickey",
    "-o", "IdentitiesOnly=yes",
    "-o", "HostKeyAlgorithms=+ssh-rsa",
    "-o", "PubkeyAcceptedKeyTypes=+ssh-rsa",
]


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
            timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ssh", "-i", key, "-p", str(port), *SSH_OPTS, f"root@{host}", remote_cmd],
        capture_output=True, text=True, timeout=timeout)


def backup_and_patch_shell(inj) -> None:
    inj.do(f"cp{I}-n{I}/etc/passwd{I}/tmp/nx_passwd.bak")
    if not inj.ask(f"grep{I}-q{I}'^root:.*:/bin/ash'{I}/etc/passwd"):
        inj.do("sed" + I + "-i" + I + "'s#^\\(root:.*:\\)[^:]*$#\\1/bin/ash#'" + I + "/etc/passwd")
        if not inj.dry_run and not inj.ask(f"grep{I}-q{I}'^root:.*:/bin/ash'{I}/etc/passwd"):
            raise RuntimeError("failed to patch root shell")


def install_key(inj, keydata: bytes) -> None:
    parts = transfer.push_data(inj, keydata, "sshkey")
    transfer.assemble(inj, parts, "/etc/dropbear/authorized_keys")
    if not inj.dry_run:
        want = hashlib.md5(keydata).hexdigest()
        if not inj.ask(f"md5sum{I}/etc/dropbear/authorized_keys|grep{I}-q{I}{want}"):
            raise RuntimeError("authorized_keys md5 mismatch after transfer")
    inj.do(f"mkdir{I}-p{I}/root/.ssh")
    inj.do(f"cp{I}/etc/dropbear/authorized_keys{I}/root/.ssh/authorized_keys")
    inj.do(f"chmod{I}600{I}/etc/dropbear/authorized_keys{I}/root/.ssh/authorized_keys")
    inj.do(f"chmod{I}700{I}/root/.ssh")
    inj.do(f"rm{I}-f{I}/tmp/nxg_*{I}/tmp/nxseg_sshkey_*")


def create_instance(inj, port: int) -> None:
    if not inj.dry_run and inj.ask(f"uci{I}-q{I}show{I}dropbear.{INSTANCE}"):
        inj.log(f"[ssh] uci instance {INSTANCE!r} already exists, reusing")
    else:
        inj.do(f"uci{I}add{I}dropbear{I}dropbear")
        inj.do(f"uci{I}rename{I}dropbear.@dropbear[-1]={INSTANCE}")
    inj.do(f"uci{I}set{I}dropbear.{INSTANCE}.enable=1")
    inj.do(f"uci{I}set{I}dropbear.{INSTANCE}.Port={port}")
    inj.do(f"uci{I}set{I}dropbear.{INSTANCE}.Interface=lan")
    inj.do(f"uci{I}set{I}dropbear.{INSTANCE}.PasswordAuth=off")
    inj.do(f"uci{I}set{I}dropbear.{INSTANCE}.RootPasswordAuth=off")
    inj.do(f"uci{I}commit{I}dropbear")
    inj.do(f"/etc/init.d/dropbear{I}restart")
    time.sleep(2)
    if not inj.dry_run and not inj.ask(f"netstat{I}-tln|grep{I}-q{I}:{port}"):
        raise RuntimeError(f"dropbear not listening on port {port}")


def bootstrap(inj, pubkey_path: str, port: int, log=print) -> None:
    """Idempotent: re-running repairs any missing piece."""
    keydata = check_pubkey(pubkey_path)
    backup_and_patch_shell(inj)
    log("[ssh] root shell ready")
    install_key(inj, keydata)
    log("[ssh] public key installed (md5 verified)")
    create_instance(inj, port)


def status(inj, port: int) -> dict:
    return {
        "port": port,
        "listening": inj.ask(f"netstat{I}-tln|grep{I}-q{I}:{port}"),
        "uci_instance": inj.ask(f"uci{I}-q{I}show{I}dropbear.{INSTANCE}"),
        "authorized_keys": inj.ask(f"test{I}-s{I}/etc/dropbear/authorized_keys"),
    }


def teardown(inj, port: int, log=print) -> None:
    if inj.ask(f"uci{I}-q{I}show{I}dropbear.{INSTANCE}"):
        inj.do(f"uci{I}delete{I}dropbear.{INSTANCE}")
        inj.do(f"uci{I}commit{I}dropbear")
    inj.do(f"/etc/init.d/dropbear{I}restart")
    if inj.ask(f"test{I}-f{I}/tmp/nx_passwd.bak"):
        inj.do(f"cp{I}/tmp/nx_passwd.bak{I}/etc/passwd")
    inj.do(f"rm{I}-f{I}/etc/dropbear/authorized_keys{I}/root/.ssh/authorized_keys")
    time.sleep(2)
    still = inj.ask(f"netstat{I}-tln|grep{I}-q{I}:{port}")
    log(f"[teardown] done; port {port} "
        f"{'STILL LISTENING (check manually!)' if still else 'closed'}")
