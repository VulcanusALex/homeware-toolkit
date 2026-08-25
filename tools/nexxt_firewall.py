#!/usr/bin/env python3
"""Manage precise firewall pinhole rules on the NeXXt over the persistent
SSH service (see nexxt_ssh.py). The firewall stays ON; only the exact
destinations you allow are reachable.

Subcommands:

  list    Show pinhole rules (name/src/proto/dest_ip/dest_port/enabled).
  allow   Add a precise rule, e.g. a WireGuard/AmneziaWG server:
            nexxt_firewall.py allow --name Allow-AWG-v6 --proto udp \
              --dest-ip 2001:db8::123 --dest-port 51820 --family ipv6
  delete  Remove a rule by name.

The change is committed to UCI (persistent) and the firewall service is
restarted, which briefly rebuilds all rules.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from nexxt_ssh import ssh_run, host_of  # noqa: E402

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


class FW:
    def __init__(self, host: str, port: int, key: str) -> None:
        self.host, self.port, self.key = host, port, key

    def run(self, cmd: str) -> str:
        proc = ssh_run(self.host, self.port, self.key, cmd, timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or f"exit {proc.returncode}")
        return proc.stdout

    def list_rules(self) -> None:
        out = self.run(
            "uci show firewall | grep -E '^firewall\\..*\\.(name|src|dest|proto|family|dest_ip|dest_port|target|enabled)='"
            " | grep -vE '\\.(zone|redirect|include|defaults|forwarding|rulesgroup)\\.'"
        )
        rules: dict[str, dict[str, str]] = {}
        for line in out.splitlines():
            m = re.match(r"firewall\.([^.=]+)\.([a-z_]+)='?(.*?)'?$", line.strip())
            if m:
                rules.setdefault(m.group(1), {})[m.group(2)] = m.group(3)
        interesting = {k: v for k, v in rules.items()
                       if v.get("dest_port") or v.get("dest_ip")}
        if not interesting:
            print("(no pinhole rules)")
            return
        for section, r in sorted(interesting.items()):
            print(f"{r.get('name', section)}\n"
                  f"    src={r.get('src', '-')} dest={r.get('dest', '-')} "
                  f"proto={r.get('proto', '-')} family={r.get('family', 'any')}\n"
                  f"    dest_ip={r.get('dest_ip', '-')} "
                  f"dest_port={r.get('dest_port', '-')} "
                  f"target={r.get('target', '-')} enabled={r.get('enabled', '1')}")

    def allow(self, name: str, proto: str, dest_ip: str, dest_port: str,
              family: str, src: str, dest: str) -> None:
        if not NAME_RE.match(name):
            raise RuntimeError("rule name must be [A-Za-z0-9_-]{1,32}")
        cmds = [
            "uci add firewall rule",
            f"uci set firewall.@rule[-1].name='{name}'",
            f"uci set firewall.@rule[-1].src='{src}'",
            f"uci set firewall.@rule[-1].dest='{dest}'",
            f"uci set firewall.@rule[-1].proto='{proto}'",
            f"uci set firewall.@rule[-1].dest_ip='{dest_ip}'",
            f"uci set firewall.@rule[-1].dest_port='{dest_port}'",
            f"uci set firewall.@rule[-1].target='ACCEPT'",
            "uci set firewall.@rule[-1].enabled='1'",
        ]
        if family != "any":
            cmds.append(f"uci set firewall.@rule[-1].family='{family}'")
        cmds.append("uci commit firewall")
        self.run(" && ".join(cmds))
        self.run("/etc/init.d/firewall restart >/dev/null 2>&1")
        print(f"[fw] rule {name!r} added and firewall reloaded")

    def delete(self, name: str) -> None:
        out = self.run(
            f"uci show firewall | grep -E \"name='{name}'\" | cut -d. -f2")
        sections = [s.strip() for s in out.splitlines() if s.strip()]
        if not sections:
            print(f"[fw] no rule named {name!r}")
            return
        for s in sections:
            self.run(f"uci delete firewall.{s} && uci commit firewall")
            print(f"[fw] deleted firewall.{s}")
        self.run("/etc/init.d/firewall restart >/dev/null 2>&1")
        print("[fw] firewall reloaded")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="https://192.168.1.254")
    parser.add_argument("--key", default=os.path.expanduser("~/.ssh/nexxt_rsa"),
                        help="SSH private key (default %(default)s)")
    parser.add_argument("--port", type=int, default=2222)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list pinhole rules")
    p_allow = sub.add_parser("allow", help="add a precise allow rule")
    p_allow.add_argument("--name", required=True)
    p_allow.add_argument("--proto", default="udp", choices=["tcp", "udp", "tcpudp", "all"])
    p_allow.add_argument("--dest-ip", required=True)
    p_allow.add_argument("--dest-port", required=True)
    p_allow.add_argument("--family", default="ipv6",
                         choices=["ipv4", "ipv6", "any"])
    p_allow.add_argument("--src", default="wan")
    p_allow.add_argument("--dest", default="lan")
    p_del = sub.add_parser("delete", help="delete a rule by name")
    p_del.add_argument("--name", required=True)
    args = parser.parse_args()

    fw = FW(host_of(args.base_url), args.port, args.key)
    try:
        if args.command == "list":
            fw.list_rules()
        elif args.command == "allow":
            fw.allow(args.name, args.proto, args.dest_ip, args.dest_port,
                     args.family, args.src, args.dest)
        elif args.command == "delete":
            fw.delete(args.name)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
