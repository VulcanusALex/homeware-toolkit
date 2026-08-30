"""Guided, transactional first-time setup."""

from __future__ import annotations

import os
import subprocess

from . import ssh as ssh_mod
from .client import GatewayClient
from .doctor import run_doctor
from .inject import Injector
from .probe import run_probe
from .verify import verify


DEFAULT_KEY = "~/.homeware-toolkit/id_rsa"


def ensure_keypair(private_path: str, log=print) -> tuple[str, str, bool]:
    private_path = os.path.abspath(os.path.expanduser(private_path))
    public_path = private_path + ".pub"
    if os.path.exists(private_path) or os.path.exists(public_path):
        if not (os.path.isfile(private_path) and os.path.isfile(public_path)):
            raise RuntimeError(
                f"incomplete keypair at {private_path}; keep both the private key "
                "and .pub file, or choose a different --key path")
        ssh_mod.check_pubkey(public_path)
        return private_path, public_path, False
    directory = os.path.dirname(private_path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    try:
        proc = subprocess.run(
            ["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-N", "",
             "-C", "homeware-toolkit", "-f", private_path],
            capture_output=True, text=True, check=False)
    except OSError as exc:
        raise RuntimeError(f"cannot run ssh-keygen: {exc}") from exc
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "ssh-keygen failed")
    os.chmod(private_path, 0o600)
    os.chmod(public_path, 0o600)
    log(f"[setup] generated RSA keypair in {directory}")
    return private_path, public_path, True


def _confirm(assume_yes: bool, input_fn=input) -> None:
    if assume_yes:
        return
    try:
        answer = input_fn(
            "Install a LAN-only, key-only SSH instance and patch root's shell? [y/N] ")
    except EOFError as exc:
        raise RuntimeError("confirmation required; use --yes in non-interactive mode") from exc
    if answer.strip().lower() not in {"y", "yes"}:
        raise RuntimeError("setup cancelled")


def run_setup(base_url: str, port: int = 2222, key_path: str = DEFAULT_KEY,
              assume_yes: bool = False, force: bool = False,
              adopt_legacy: bool = False, log=print,
              runner=None) -> tuple[dict, int]:
    report: dict = {"steps": []}
    probe = run_probe(base_url)
    compatibility = probe["analysis"]["compatibility_signal"]
    report["steps"].append({"step": "probe", "result": compatibility})
    if compatibility != "strong-front-end-match" and not force:
        raise RuntimeError(
            "firmware fingerprint is not recognized; inspect 'homeware probe' and "
            "use --force only after verifying compatibility")

    client = GatewayClient(base_url)
    if not client.is_authenticated() and not client.button_login(60, log=log):
        raise RuntimeError("physical-button login did not complete")
    report["steps"].append({"step": "session", "result": "authenticated"})

    verification = verify(Injector(client, force=force, log=log), log=log)
    if not verification["backend_command_execution"]:
        raise RuntimeError("non-persistent command-execution verification failed")
    report["steps"].append({"step": "verify", "result": "confirmed"})

    private_key, public_key, generated = ensure_keypair(key_path, log=log)
    report["key"] = {"private": private_key, "public": public_key,
                     "generated": generated}
    log("[setup] planned persistent changes:")
    log("        - save a root-only rollback record under /etc/homeware-toolkit")
    log("        - change only root's login shell to /bin/ash")
    log("        - append the generated public key without replacing existing keys")
    log(f"        - create key-only dropbear.nx on LAN port {port}")
    _confirm(assume_yes)

    inj = Injector(client, force=force, log=log)
    try:
        ssh_mod.bootstrap(inj, public_key, port, log=log,
                          adopt_legacy=adopt_legacy)
        proc = (runner("echo SSH_OK; id") if runner is not None
                else ssh_mod.ssh_run(ssh_mod.host_of(base_url), port,
                                     private_key, "echo SSH_OK; id"))
        if proc.returncode != 0 or "SSH_OK" not in proc.stdout:
            raise RuntimeError(proc.stderr.strip() or "SSH handshake failed")
    except Exception:
        # Ownership state is created before mutations, so rollback can remove
        # exactly this setup's changes without touching unrelated keys.
        try:
            ssh_mod.teardown(inj, port, log=log)
        except Exception as rollback_error:
            log(f"[setup] automatic rollback needs attention: {rollback_error}")
        raise

    report["steps"].append({"step": "ssh", "result": "handshake-ok"})
    stages, code = run_doctor(base_url, port, key=private_key,
                              check_injection=False, log=log, runner=runner)
    report["doctor"] = stages
    return report, code
