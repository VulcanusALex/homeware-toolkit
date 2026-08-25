"""WAN state watcher (public IPv4 provisioning / 6rd prefix changes)."""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import re

from .ssh import ssh_run

CGNAT_FIRST = ipaddress.ip_address("100.64.0.0")
CGNAT_LAST = ipaddress.ip_address("100.127.255.255")


def classify_v4(addr: str) -> str:
    ip = ipaddress.ip_address(addr)
    if ip.is_private:
        return "private-RFC1918"
    if CGNAT_FIRST <= ip <= CGNAT_LAST:
        return "CGNAT-100.64/10"
    return "PUBLIC"


def watch(host: str, port: int, key: str, state_file: str) -> tuple[dict, int]:
    """Returns (report, exit_code): 0 public, 1 private, 2 changed, 3 error."""
    proc = ssh_run(host, port, key,
                   "ip -4 addr show dev veip0_1 | grep 'inet ' ; "
                   "ip -6 addr show dev br-lan | grep 'inet6 2001'")
    if proc.returncode != 0 or not proc.stdout.strip():
        return {"error": proc.stderr.strip() or "no output"}, 3

    m4 = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", proc.stdout)
    m6 = re.search(r"inet6 (2001:[0-9a-f:]+)/", proc.stdout)
    wan4 = m4.group(1) if m4 else None
    lan6 = m6.group(1) if m6 else None
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    state = {}
    if os.path.exists(state_file):
        try:
            state = json.load(open(state_file))
        except ValueError:
            pass
    changed = bool(state) and (state.get("wan4") != wan4 or state.get("lan6") != lan6)
    json.dump({"wan4": wan4, "lan6": lan6, "ts": now}, open(state_file, "w"))

    report = {
        "ts": now,
        "wan_ipv4": wan4,
        "wan_ipv4_class": classify_v4(wan4) if wan4 else None,
        "lan_ipv6": lan6,
        "changed_since_last_run": changed,
    }
    if changed:
        return report, 2
    if wan4 and classify_v4(wan4) == "PUBLIC":
        return report, 0
    return report, 1
