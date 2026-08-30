"""Post-upgrade and security-state audit."""

from __future__ import annotations

import json
import os

from .firewall import FW
from .probe import run_probe
from .ssh import host_of, ssh_run


def _check(items: list[dict], name: str, ok: bool, detail: str,
           hint: str = "", warning: bool = False) -> None:
    items.append({"check": name, "status": "PASS" if ok else ("WARN" if warning else "FAIL"),
                  "detail": detail, "hint": hint})


def run_audit(base_url: str, port: int, key: str,
              state_file: str = "~/.homeware-toolkit/audit-state.json",
              accept_change: bool = False,
              device=None, runner=None) -> tuple[dict, int]:
    checks: list[dict] = []
    probe = run_probe(base_url)
    signal = probe["analysis"]["compatibility_signal"]
    _check(checks, "firmware-fingerprint", signal == "strong-front-end-match", signal,
           "do not run injection commands until compatibility is reviewed")

    from .driver import default_device
    from .ssh import STATE_DIR
    device = device or default_device()
    ssh_service = device.cap("ssh", "service", default="dropbear")
    ssh_instance = device.cap("ssh", "instance", default="nx")

    host = host_of(base_url)
    audit_cmd = (
        "printf '%s\\n' __SHELL__; grep '^root:' /etc/passwd; "
        f"printf '%s\\n' __DROPBEAR__; uci -q show {ssh_service}.{ssh_instance}; "
        f"printf '%s\\n' __STATE__; test -s {STATE_DIR}/{ssh_service}.{ssh_instance}.owned && echo managed")
    proc = (runner(audit_cmd) if runner is not None
            else ssh_run(host, port, key, audit_cmd))
    ssh_ok = proc.returncode == 0
    _check(checks, "ssh-handshake", ssh_ok,
           "reachable with key" if ssh_ok else (proc.stderr.strip() or "failed"),
           "run setup again only after reviewing the firmware change")
    text = proc.stdout if ssh_ok else ""
    ssh_shell = device.cap("ssh", "shell", default="/bin/ash")
    _check(checks, "root-shell", f"{ssh_shell}" in text, f"expected {ssh_shell}")
    hardened = all(token in text for token in (
        f"{ssh_service}.{ssh_instance}.Interface='lan'",
        f"{ssh_service}.{ssh_instance}.PasswordAuth='off'",
        f"{ssh_service}.{ssh_instance}.RootPasswordAuth='off'"))
    _check(checks, "ssh-policy", hardened, "LAN-only and password auth disabled",
           f"repair the {ssh_instance} UCI instance before exposing SSH")
    managed = "__STATE__\nmanaged" in text
    _check(checks, "rollback-state", managed, "persistent ownership record",
           "adopt a legacy install before relying on automatic teardown", warning=True)

    firewall_report = None
    if ssh_ok:
        firewall_report = FW(host, port, key, runner=runner).audit()
        _check(checks, "firewall-audit", firewall_report["ok"],
               f"{len(firewall_report['findings'])} finding(s)",
               "run 'homeware fw audit --json' and narrow broad WAN rules")

    snapshot = {
        "asset_version_stamps": probe["analysis"].get("asset_version_stamps", []),
        "compatibility_signal": signal,
    }
    state_file = os.path.abspath(os.path.expanduser(state_file))
    previous = None
    try:
        with open(state_file, encoding="utf-8") as fh:
            previous = json.load(fh)
    except (OSError, ValueError):
        pass
    changed = previous is not None and previous != snapshot
    _check(checks, "firmware-change", not changed,
           "changed since previous audit" if changed else "no change recorded",
           "review the new probe fingerprint before privileged operations",
           warning=changed)
    baseline_updated = previous is None or not changed or accept_change
    if baseline_updated:
        directory = os.path.dirname(state_file)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        temp = state_file + ".tmp"
        with open(temp, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh, indent=2)
            fh.write("\n")
        os.chmod(temp, 0o600)
        os.replace(temp, state_file)

    report = {"checks": checks, "firmware_changed": changed,
              "baseline_updated": baseline_updated,
              "firewall": firewall_report, "state_file": state_file}
    return report, 0 if not any(c["status"] == "FAIL" for c in checks) else 1
