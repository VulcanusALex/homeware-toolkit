"""Precise firewall pinhole management over SSH (firewall stays ON)."""

from __future__ import annotations

import re

from .ssh import ssh_run

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


class FW:
    def __init__(self, host: str, port: int, key: str) -> None:
        self.host, self.port, self.key = host, port, key

    def run(self, cmd: str) -> str:
        proc = ssh_run(self.host, self.port, self.key, cmd, timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or f"exit {proc.returncode}")
        return proc.stdout

    def list_rules(self) -> list[dict]:
        out = self.run(
            "uci show firewall | grep -E '^firewall\\..*\\.(name|src|dest|proto|family|dest_ip|dest_port|target|enabled)='")
        rules: dict[str, dict] = {}
        for line in out.splitlines():
            m = re.match(r"firewall\.([^.=]+)\.([a-z_]+)='?(.*?)'?$", line.strip())
            if m:
                rules.setdefault(m.group(1), {})[m.group(2)] = m.group(3)
        result = []
        for section, r in sorted(rules.items()):
            if r.get("dest_port") or r.get("dest_ip"):
                entry = {"section": section}
                entry.update(r)
                result.append(entry)
        return result

    def allow(self, name: str, proto: str, dest_ip: str, dest_port: str,
              family: str = "ipv6", src: str = "wan", dest: str = "lan") -> None:
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
            "uci set firewall.@rule[-1].target='ACCEPT'",
            "uci set firewall.@rule[-1].enabled='1'",
        ]
        if family != "any":
            cmds.append(f"uci set firewall.@rule[-1].family='{family}'")
        cmds.append("uci commit firewall")
        self.run(" && ".join(cmds))
        self.run("/etc/init.d/firewall restart >/dev/null 2>&1")

    def delete(self, name: str) -> list[str]:
        out = self.run(f"uci show firewall | grep -E \"name='{name}'\" | cut -d. -f2")
        sections = [s.strip() for s in out.splitlines() if s.strip()]
        for s in sections:
            self.run(f"uci delete firewall.{s} && uci commit firewall")
        if sections:
            self.run("/etc/init.d/firewall restart >/dev/null 2>&1")
        return sections
