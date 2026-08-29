"""WAN state watcher (public IPv4 provisioning / 6rd prefix changes).

Read-only: connects over the persistent LAN SSH service, snapshots the WAN
provisioning state, compares it with the previous run, and reports meaningful
changes. When the router exposes ``ifstatus`` (ubus) it additionally reports
the connectivity mode (native DHCPv6 vs 6rd) and delegated prefixes; when it
does not, it falls back to plain ``ip addr`` parsing.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import re
import subprocess

from .ssh import ssh_run

CGNAT_FIRST = ipaddress.ip_address("100.64.0.0")
CGNAT_LAST = ipaddress.ip_address("100.127.255.255")

# Markers delimit the sections of the combined remote command so we can parse
# each independently. ifstatus emits JSON; the ip commands emit plain text.
_M_WAN6 = "__NX_WAN6__"
_M_IP4 = "__NX_IP4__"
_M_IP6 = "__NX_IP6__"

DEFAULT_WAN_INTERFACES = {
    "wan4_interface": "veip0_1",
    "lan6_interface": "br-lan",
}


def _remote_command(interfaces: dict | None = None) -> str:
    """Build the remote probe command for the given interface names.

    ``interfaces`` may contain ``wan4_interface`` and ``lan6_interface`` keys;
    missing keys fall back to the NeXXt One defaults so callers without a
    device still work.
    """
    iface = dict(DEFAULT_WAN_INTERFACES)
    if interfaces:
        iface.update(interfaces)
    return (
        "ifstatus 6rd 2>/dev/null; "
        f"echo {_M_WAN6}; "
        "ifstatus wan6 2>/dev/null; "
        f"echo {_M_IP4}; "
        f"ip -4 addr show dev {iface['wan4_interface']} 2>/dev/null; "
        f"echo {_M_IP6}; "
        f"ip -6 addr show dev {iface['lan6_interface']} 2>/dev/null"
    )


def classify_v4(addr: str) -> str:
    ip = ipaddress.ip_address(addr)
    if ip.is_private:
        return "private-RFC1918"
    if CGNAT_FIRST <= ip <= CGNAT_LAST:
        return "CGNAT-100.64/10"
    return "PUBLIC"


def _read_json(text: str) -> dict:
    text = text.strip()
    if not text:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _prefixes(data: dict) -> list[str]:
    out: list[str] = []
    for key in ("ipv6-prefix", "ipv6-prefix-assignment"):
        for item in data.get(key, []) or []:
            address, mask = item.get("address"), item.get("mask")
            if address and mask is not None:
                out.append(f"{address}/{mask}")
    return sorted(set(out))


def _first_global_v6(ip6_text: str) -> list[str]:
    out = []
    for m in re.finditer(r"\binet6 ([0-9a-fA-F:]+)/\d+ scope global", ip6_text):
        addr = m.group(1).lower()
        try:
            if not ipaddress.ip_address(addr).is_private:
                out.append(addr)
        except ValueError:
            pass
    return sorted(set(out))


def _snapshot(stdout: str) -> dict:
    """Build a provisioning snapshot, tolerant of a device without ifstatus."""
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    sixrd = wan6 = {}
    ip4_text = ip6_text = stdout
    if _M_WAN6 in stdout and _M_IP4 in stdout and _M_IP6 in stdout:
        sixrd_text, rest = stdout.split(_M_WAN6, 1)
        wan6_text, rest = rest.split(_M_IP4, 1)
        ip4_text, ip6_text = rest.split(_M_IP6, 1)
        sixrd, wan6 = _read_json(sixrd_text), _read_json(wan6_text)

    m4 = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)", ip4_text)
    wan4 = m4.group(1) if m4 else None
    lan6 = _first_global_v6(ip6_text)

    if wan6.get("up"):
        mode = "native-dhcpv6"
    elif sixrd.get("up"):
        mode = "6rd"
    elif lan6:
        mode = "unknown-up"
    else:
        mode = "none"

    return {
        "ts": now,
        "mode": mode,
        "wan_ipv4": wan4,
        "wan_ipv4_class": classify_v4(wan4) if wan4 else None,
        "lan_ipv6": lan6[0] if lan6 else None,
        "lan_global_ipv6": lan6,
        "sixrd_up": bool(sixrd.get("up")),
        "sixrd_dynamic": sixrd.get("dynamic"),
        "sixrd_prefixes": _prefixes(sixrd),
        "wan6_up": bool(wan6.get("up")),
        "wan6_prefixes": _prefixes(wan6),
    }


_COMPARE_KEYS = ("mode", "wan_ipv4", "lan_global_ipv6", "sixrd_dynamic",
                 "sixrd_prefixes", "wan6_prefixes")


def _describe_change(old: dict, new: dict) -> str:
    parts = []
    if old.get("mode") != new.get("mode"):
        parts.append(f"mode {old.get('mode')} -> {new.get('mode')}")
    if old.get("wan_ipv4") != new.get("wan_ipv4"):
        parts.append(f"WAN IPv4 {old.get('wan_ipv4')} -> {new.get('wan_ipv4')}")
    if old.get("sixrd_prefixes") != new.get("sixrd_prefixes"):
        parts.append("6rd prefix changed")
    if old.get("wan6_prefixes") != new.get("wan6_prefixes"):
        parts.append("native IPv6 prefix changed")
    if old.get("lan_global_ipv6") != new.get("lan_global_ipv6"):
        parts.append("LAN IPv6 changed")
    return "; ".join(parts) or "provisioning changed"


def _changed(old: dict, new: dict) -> bool:
    return any(old.get(k) != new.get(k) for k in _COMPARE_KEYS)


def _load_state(state_file: str) -> dict:
    try:
        with open(state_file) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, ValueError, OSError):
        return {}


def _save_state(state_file: str, state: dict) -> None:
    tmp = state_file + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, state_file)  # atomic


def _notify(title: str, body: str) -> None:
    """Best-effort desktop notification (macOS only); silent no-op elsewhere."""
    osa = "/usr/bin/osascript"
    if not os.path.exists(osa):
        return

    def esc(v: str) -> str:
        return v.replace("\\", "\\\\").replace('"', '\\"')

    try:
        subprocess.run(
            [osa, "-e",
             f'display notification "{esc(body)}" with title "{esc(title)}"'],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def watch(host: str, port: int, key: str, state_file: str,
          notify: bool = False,
          interfaces: dict | None = None) -> tuple[dict, int]:
    """Snapshot WAN state and compare with the last run.

    Returns (report, exit_code): 0 public IPv4, 1 not-yet-public,
    2 provisioning changed, 3 error.

    ``interfaces`` optionally overrides the default WAN/LAN interface names
    when the toolkit is used with a different device family.
    """
    proc = ssh_run(host, port, key, _remote_command(interfaces))
    if proc.returncode != 0 or not proc.stdout.strip():
        return {"error": proc.stderr.strip() or "no output"}, 3

    snapshot = _snapshot(proc.stdout)
    state = _load_state(state_file)
    previous = state.get("snapshot") if isinstance(state.get("snapshot"), dict) else None
    changed = previous is not None and _changed(previous, snapshot)

    _save_state(state_file, {"snapshot": snapshot})

    report = dict(snapshot)
    report["changed_since_last_run"] = changed
    if changed:
        report["change_summary"] = _describe_change(previous, snapshot)
        if notify:
            _notify("Gateway WAN changed", report["change_summary"])
        return report, 2
    if snapshot["wan_ipv4"] and snapshot["wan_ipv4_class"] == "PUBLIC":
        if notify and previous is not None:
            _notify("Fastweb WAN public", f"WAN IPv4 {snapshot['wan_ipv4']} is public")
        return report, 0
    return report, 1
