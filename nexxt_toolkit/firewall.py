"""Precise firewall pinhole management over SSH (firewall stays ON)."""

from __future__ import annotations

import ipaddress
import re

from .ssh import ssh_run

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
SECTION_RE = re.compile(r"^(?:[A-Za-z0-9_-]{1,64}|@(?:rule|redirect)\[\d+\])$")

# Zone names (src/dest) and proto tokens: strict, no shell metacharacters.
ZONE_RE = re.compile(r"^[A-Za-z0-9_]{1,32}$")
PROTO_RE = re.compile(r"^[A-Za-z0-9_]{1,16}$")

# A single port or an inclusive range "a-b". Numeric ranges verified separately.
_PORT_RE = re.compile(r"^\d{1,5}(-\d{1,5})?$")


def _validate_dest_ip(dest_ip: str) -> str:
    """Validate an IPv4/IPv6 address, optionally with a /prefix. Returns it.

    Rejects anything that is not a bare address or address/prefix, so no
    quotes, semicolons, spaces or other shell metacharacters can survive.
    """
    if not isinstance(dest_ip, str) or dest_ip == "":
        raise RuntimeError("dest_ip must be a non-empty IP address")
    # Reject IPv6 scope-ids (%zone): ipaddress accepts arbitrary characters
    # after '%', which would otherwise smuggle shell metacharacters through.
    if "%" in dest_ip:
        raise RuntimeError(f"scope-id not allowed in dest_ip: {dest_ip!r}")
    addr_part = dest_ip
    if "/" in dest_ip:
        addr_part, _, prefix_part = dest_ip.partition("/")
        # exactly one slash
        if "/" in prefix_part:
            raise RuntimeError(f"invalid dest_ip: {dest_ip!r}")
        if not re.fullmatch(r"\d{1,3}", prefix_part):
            raise RuntimeError(f"invalid dest_ip prefix: {dest_ip!r}")
        prefix = int(prefix_part)
    else:
        prefix = None
    try:
        ip = ipaddress.ip_address(addr_part)
    except ValueError:
        raise RuntimeError(f"invalid dest_ip: {dest_ip!r}")
    if prefix is not None:
        max_prefix = 32 if ip.version == 4 else 128
        if prefix < 0 or prefix > max_prefix:
            raise RuntimeError(
                f"invalid dest_ip prefix for IPv{ip.version}: {dest_ip!r}")
    # Return the NORMALIZED form so the interpolated value contains only
    # characters ipaddress itself emits (hex/digits/colons/dots) — never the
    # caller's raw bytes. This is what makes the interpolation injection-proof.
    return str(ip) if prefix is None else f"{ip}/{prefix}"


def _validate_one_port(token: str, original: str) -> None:
    if not _PORT_RE.match(token):
        raise RuntimeError(f"invalid dest_port: {original!r}")
    if "-" in token:
        lo_s, hi_s = token.split("-", 1)
        lo, hi = int(lo_s), int(hi_s)
        if not (1 <= lo <= 65535 and 1 <= hi <= 65535 and lo <= hi):
            raise RuntimeError(f"invalid dest_port range: {original!r}")
    else:
        n = int(token)
        if not (1 <= n <= 65535):
            raise RuntimeError(f"invalid dest_port: {original!r}")


def _validate_dest_port(dest_port: str) -> str:
    """Validate a single port, a range "a-b", or a comma-separated list."""
    if not isinstance(dest_port, str) or dest_port == "":
        raise RuntimeError("dest_port must be a non-empty port spec")
    parts = dest_port.split(",")
    for part in parts:
        if part == "":
            raise RuntimeError(f"invalid dest_port: {dest_port!r}")
        _validate_one_port(part, dest_port)
    return dest_port


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
            if r.get("dest_port") or r.get("dest_ip") or r.get("name"):
                entry = {"section": section}
                entry.update(r)
                result.append(entry)
        return result

    @staticmethod
    def _validate_section(section: str) -> str:
        if not SECTION_RE.fullmatch(section):
            raise RuntimeError(f"unsafe UCI section returned by device: {section!r}")
        return section

    @staticmethod
    def _desired(name: str, proto: str, dest_ip: str, dest_port: str,
                 family: str, src: str, dest: str) -> dict:
        if not NAME_RE.fullmatch(name):
            raise RuntimeError("rule name must be [A-Za-z0-9_-]{1,32}")
        if not ZONE_RE.fullmatch(src):
            raise RuntimeError("src zone must be [A-Za-z0-9_]{1,32}")
        if not ZONE_RE.fullmatch(dest):
            raise RuntimeError("dest zone must be [A-Za-z0-9_]{1,32}")
        if not PROTO_RE.fullmatch(proto):
            raise RuntimeError("proto must be [A-Za-z0-9_]{1,16}")
        if family not in {"ipv4", "ipv6", "any"}:
            raise RuntimeError("family must be ipv4, ipv6, or any")
        return {
            "name": name, "src": src, "dest": dest, "proto": proto,
            "family": family, "dest_ip": _validate_dest_ip(dest_ip),
            "dest_port": _validate_dest_port(dest_port), "target": "ACCEPT",
            "enabled": "1",
        }

    @staticmethod
    def _set_commands(section: str, desired: dict) -> list[str]:
        commands = []
        for key in ("name", "src", "dest", "proto", "dest_ip", "dest_port",
                    "target", "enabled"):
            commands.append(f"uci set firewall.{section}.{key}='{desired[key]}'")
        if desired["family"] == "any":
            commands.append(f"(uci -q delete firewall.{section}.family || true)")
        else:
            commands.append(
                f"uci set firewall.{section}.family='{desired['family']}'")
        return commands

    def allow(self, name: str, proto: str, dest_ip: str, dest_port: str,
              family: str = "ipv6", src: str = "wan", dest: str = "lan") -> None:
        # Validate every free-form value that gets interpolated into the
        # remote shell command. Strict validation is the primary defense.
        if not NAME_RE.match(name):
            raise RuntimeError("rule name must be [A-Za-z0-9_-]{1,32}")
        if not ZONE_RE.match(src):
            raise RuntimeError("src zone must be [A-Za-z0-9_]{1,32}")
        if not ZONE_RE.match(dest):
            raise RuntimeError("dest zone must be [A-Za-z0-9_]{1,32}")
        if not PROTO_RE.match(proto):
            raise RuntimeError("proto must be [A-Za-z0-9_]{1,16}")
        dest_ip = _validate_dest_ip(dest_ip)
        dest_port = _validate_dest_port(dest_port)
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
            if not ZONE_RE.match(family):
                raise RuntimeError("family must be [A-Za-z0-9_]{1,32}")
            cmds.append(f"uci set firewall.@rule[-1].family='{family}'")
        cmds.append("uci commit firewall")
        self.run(" && ".join(cmds))
        self.run("/etc/init.d/firewall restart >/dev/null 2>&1")

    def ensure(self, name: str, proto: str, dest_ip: str, dest_port: str,
               family: str = "ipv6", src: str = "wan", dest: str = "lan") -> dict:
        """Create or update one exact rule, with rollback on reload failure."""
        desired = self._desired(name, proto, dest_ip, dest_port, family, src, dest)
        matches = [r for r in self.list_rules() if r.get("name") == name]
        if len(matches) > 1:
            raise RuntimeError(
                f"multiple firewall rules are named {name!r}; run 'nexxt fw audit' "
                "and remove duplicates before ensuring it")
        changed = True
        if matches:
            current = matches[0]
            changed = any(current.get(k, "any" if k == "family" else "") != v
                          for k, v in desired.items())
            section = self._validate_section(current["section"])
        else:
            section = "@rule[-1]"

        if not changed:
            return {"name": name, "changed": False,
                    "section": matches[0]["section"]}

        backup = "/tmp/nexxt-toolkit-firewall.backup"
        self.run(f"uci export firewall > {backup}")
        try:
            if not matches:
                self.run("uci add firewall rule")
            commands = self._set_commands(section, desired)
            commands.append("uci commit firewall")
            self.run(" && ".join(commands))
            self.run("/etc/init.d/firewall restart >/dev/null 2>&1")
            refreshed = [r for r in self.list_rules() if r.get("name") == name]
            if len(refreshed) != 1:
                raise RuntimeError(f"firewall rule {name!r} did not persist uniquely")
        except Exception:
            self.run(
                f"uci -q revert firewall; uci import firewall < {backup}; "
                "uci commit firewall; /etc/init.d/firewall restart >/dev/null 2>&1; "
                f"rm -f {backup}")
            raise
        self.run(f"rm -f {backup}")
        return {"name": name, "changed": True,
                "section": refreshed[0]["section"]}

    def _runtime_rows(self) -> list[dict]:
        out = self.run(
            "iptables-save -c 2>/dev/null; ip6tables-save -c 2>/dev/null")
        rows = []
        for line in out.splitlines():
            counter = re.match(r"^\[(\d+):(\d+)\]", line.strip())
            comment = (re.search(r"/\*\s*(?:!fw3:\s*)?(.+?)\s*\*/", line)
                       or re.search(r"--comment\s+\"(?:!fw3:\s*)?(.+?)\"", line))
            if not counter or not comment:
                continue
            rows.append({"name": comment.group(1),
                         "packets": int(counter.group(1)),
                         "bytes": int(counter.group(2)), "raw": line})
        return rows

    def counter_snapshot(self, name: str) -> dict:
        if not NAME_RE.fullmatch(name):
            raise RuntimeError("rule name must be [A-Za-z0-9_-]{1,32}")
        rows = [row for row in self._runtime_rows() if row["name"] == name]
        return {"name": name, "matched_rules": len(rows),
                "packets": sum(row["packets"] for row in rows),
                "bytes": sum(row["bytes"] for row in rows)}

    def audit(self) -> dict:
        rules = self.list_rules()
        runtime_names = {row["name"] for row in self._runtime_rows()}
        findings = []
        by_name: dict[str, list[dict]] = {}
        for rule in rules:
            name = rule.get("name")
            if name:
                by_name.setdefault(name, []).append(rule)
            if (rule.get("src") == "wan" and rule.get("target") == "ACCEPT"
                    and (not rule.get("dest_ip") or not rule.get("dest_port"))):
                findings.append({"severity": "high", "type": "broad-wan-accept",
                                 "rule": name or rule["section"]})
            if rule.get("enabled", "1") != "0" and name and name not in runtime_names:
                findings.append({"severity": "warning", "type": "not-in-runtime",
                                 "rule": name})
        for name, items in by_name.items():
            if len(items) > 1:
                findings.append({"severity": "warning", "type": "duplicate-name",
                                 "rule": name, "count": len(items)})
        return {"ok": not any(f["severity"] == "high" for f in findings),
                "rules": rules, "findings": findings}

    def delete(self, name: str) -> list[str]:
        if not NAME_RE.match(name):
            raise RuntimeError("rule name must be [A-Za-z0-9_-]{1,32}")
        out = self.run(f"uci show firewall | grep -E \"name='{name}'\" | cut -d. -f2")
        sections = [self._validate_section(s.strip()) for s in out.splitlines()
                    if s.strip()]
        for s in sections:
            self.run(f"uci delete firewall.{s} && uci commit firewall")
        if sections:
            self.run("/etc/init.d/firewall restart >/dev/null 2>&1")
        return sections
