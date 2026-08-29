"""End-to-end health check ('doctor'): tells you exactly what is missing."""

from __future__ import annotations

from . import probe as probe_mod
from .client import GatewayClient, SessionExpired
from .inject import Injector, run_ping
from .ssh import host_of, ssh_run
from .ssh import status as ssh_status
from .wanwatch import classify_v4

PASS, FAIL, SKIP, INFO = "PASS", "FAIL", "SKIP", "INFO"


def _wan_class(ip: str) -> str:
    try:
        return classify_v4(ip)
    except ValueError:
        return "unknown"


def run_doctor(base_url: str, port: int, key: str | None = None,
               check_injection: bool = True, check_egress: bool = False,
               log=print) -> tuple[list[dict], int]:
    """Returns (stages, exit_code). exit 0 = all critical stages pass."""
    stages: list[dict] = []

    def stage(name: str, status: str, detail: str = "", hint: str = "") -> None:
        stages.append({"stage": name, "status": status, "detail": detail, "hint": hint})
        mark = {"PASS": "✓", "FAIL": "✗", "SKIP": "-", "INFO": "i"}[status]
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
    client = GatewayClient(base_url)
    authed = client.is_authenticated()
    if authed:
        stage("web-session", PASS)
    else:
        stage("web-session", SKIP, "no valid session",
              "homeware session login (or import-cookie) — needed only for bootstrap/verify")

    # 3. injection (only if authed)
    if authed and check_injection:
        try:
            inj = Injector(client)
            base, _ = run_ping(client, "127.0.0.1",
                               service=inj.injection_service,
                               reader=inj.injection_reader)
            e, _ = run_ping(client, f"{inj.payload_prefix}sleep{inj.I}3",
                            service=inj.injection_service,
                            reader=inj.injection_reader)
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
                  "homeware ssh bootstrap --pubkey <rsa.pub>")
    elif authed:
        try:
            inj = Injector(client, force=True)
            st = ssh_status(inj, port)
            ok = st["listening"] and st["uci_instance"] and st["authorized_keys"]
            stage("ssh-service", PASS if ok else FAIL, str(st),
                  "" if ok else "homeware ssh bootstrap --pubkey <rsa.pub>")
        except Exception as exc:
            stage("ssh-service", FAIL, str(exc))
    else:
        stage("ssh-service", SKIP, "needs session or --key")

    # 5. WAN IPv4 assignment. A private address does NOT prove that inbound
    # is blocked: an ISP can still provide 1:1 NAT or another upstream mapping.
    from .driver import default_device
    wan4_iface = default_device().cap("wan", "wan4_interface",
                                      default="veip0_1")
    wan_class = None
    if key:
        proc = ssh_run(host_of(base_url), port, key,
                       f"ip -4 addr show dev {wan4_iface} | grep 'inet '")
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
        stage("wan-ipv4-assignment", INFO, wan_class,
              ("direct public assignment observed" if wan_class == "PUBLIC" else
               "private WAN alone cannot determine inbound reachability"))
    else:
        stage("wan-ipv4-assignment", SKIP, "needs session or --key")
    if check_egress:
        from .egress import query
        egress = query()
        if egress["ipv4"]:
            relationship = (
                "upstream NAT present; inbound policy still unknown"
                if wan_class and wan_class != "PUBLIC" else
                "public egress observed")
            stage("public-egress-ipv4", INFO, egress["ipv4"], relationship)
        else:
            stage("public-egress-ipv4", SKIP, "lookup unavailable")
        stage("public-egress-ipv6", INFO if egress["ipv6"] else SKIP,
              egress["ipv6"] or "lookup unavailable")
    else:
        stage("public-egress", SKIP, "external lookup disabled",
              "re-run doctor with --check-egress to contact api4/api6.ipify.org")
    stage("inbound-reachability", SKIP, "not inferred from WAN addressing",
          "use 'homeware inbound observe --rule NAME --key KEY' during a fresh external connection")

    critical = [s for s in stages if s["stage"] in
                ("web-ui-compatibility", "command-injection", "ssh-service")]
    exit_code = 0 if all(s["status"] in (PASS, SKIP) for s in critical) else 1
    return stages, exit_code
