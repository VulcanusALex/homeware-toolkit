#!/usr/bin/env python3
"""Watch the NeXXt WAN state and report whether the ISP has finally
assigned a public IPv4 (and whether the 6rd prefix changed).

Designed for Fastweb users waiting for a static public IPv4 provisioning to
complete. Runs over the persistent SSH service (see nexxt_ssh.py) — no web
session needed.

Exit codes (for cron/monitoring):
  0  WAN IPv4 is PUBLIC (or was already public at first run)
  1  WAN IPv4 is private/CGNAT
  2  state changed since last run (new WAN IP or new 6rd prefix)
  3  error (unreachable, auth failure, ...)

Cron example (every 10 minutes, log to file):
  */10 * * * * /usr/bin/python3 /path/tools/nexxt_wanwatch.py --key ~/.ssh/nexxt_rsa >> ~/wanwatch.log 2>&1
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from nexxt_ssh import ssh_run, host_of  # noqa: E402

STATE_FILE = os.path.join(os.path.expanduser("~"), ".nexxt_wanwatch_state.json")


def classify_v4(addr: str) -> str:
    ip = ipaddress.ip_address(addr)
    if ip.is_private:
        return "private-RFC1918"
    if ipaddress.ip_address("100.64.0.0") <= ip <= ipaddress.ip_address("100.127.255.255"):
        return "CGNAT-100.64/10"
    return "PUBLIC"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="https://192.168.1.254")
    parser.add_argument("--key", default=os.path.expanduser("~/.ssh/nexxt_rsa"))
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--state-file", default=STATE_FILE)
    args = parser.parse_args()

    host = host_of(args.base_url)
    proc = ssh_run(host, args.port, args.key,
                   "ip -4 addr show dev veip0_1 | grep 'inet ' ; "
                   "ip -6 addr show dev br-lan | grep 'inet6 2001' ; "
                   "ip -6 route show default | head -2")
    if proc.returncode != 0 or not proc.stdout.strip():
        print(json.dumps({"error": proc.stderr.strip() or "no output"}))
        return 3

    m4 = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", proc.stdout)
    m6 = re.search(r"inet6 (2001:[0-9a-f:]+)/", proc.stdout)
    wan4 = m4.group(1) if m4 else None
    lan6 = m6.group(1) if m6 else None
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    state = {}
    if os.path.exists(args.state_file):
        try:
            state = json.load(open(args.state_file))
        except ValueError:
            pass
    changed = bool(state) and (state.get("wan4") != wan4 or state.get("lan6") != lan6)
    json.dump({"wan4": wan4, "lan6": lan6, "ts": now}, open(args.state_file, "w"))

    result = {
        "ts": now,
        "wan_ipv4": wan4,
        "wan_ipv4_class": classify_v4(wan4) if wan4 else None,
        "lan_ipv6": lan6,
        "changed_since_last_run": changed,
    }
    print(json.dumps(result, ensure_ascii=False))
    if changed:
        return 2
    if wan4 and classify_v4(wan4) == "PUBLIC":
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
