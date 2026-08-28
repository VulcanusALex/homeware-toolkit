"""Declarative configuration management ("configuration as code").

A single JSON document describes the desired device state; the CLI (wired up
in cli.py) turns that into ``nexxt diff`` (read-only preview) and
``nexxt apply`` (idempotent convergence).

Layered API, pure logic separated from I/O so the CLI can render text or
``--json`` without touching device code:

- :func:`load_config`  parse + strictly validate a JSON file into a
  :class:`Config`. Rule fields reuse the same validators as
  :mod:`nexxt_toolkit.firewall`, so anything accepted here is also safe for
  ``FW.ensure``.
- :func:`plan`         pure function: (Config, device rules, ssh state) ->
  plan dict with CREATE/UPDATE/DELETE/NOOP/CHECK_PASS/CHECK_FAIL ops.
- :func:`apply_plan`   executes a plan against an :class:`FW`-like object,
  reusing ``FW.ensure``'s idempotency and rollback. Stops at the first
  failure and reports what ran and what did not.
- :func:`read_ssh_state`, :func:`gather_plan`, :func:`run_diff`,
  :func:`run_apply`  thin I/O wrappers the CLI calls directly.

Config schema (version 1)::

    {
      "version": 1,                      # required, must be 1
      "firewall": {
        "prune": false,                  # optional; delete toolkit-managed
                                         # rules absent from this file
        "rules": [
          {"name": "Allow-AWG-v6",       # required, [A-Za-z0-9_-]{1,32}
           "proto": "udp",               # required, [A-Za-z0-9_]{1,16}
           "dest_ip": "2001:db8::123",   # required, IPv4/IPv6 (opt. /prefix)
           "dest_port": 51820,           # required, int or "p"/"a-b"/"a,b"
           "family": "ipv6",             # optional: ipv4|ipv6|any
           "src": "wan",                 # optional zone
           "dest": "lan",                # optional zone
           "enabled": true}              # optional; only true is supported
        ]                                #   (FW.ensure always sets enabled=1)
      },
      "ssh": {
        "require_key_only": true,        # optional assertions only
        "require_lan_only": true         #   (never mutate SSH from a config)
      }
    }

Unknown keys at any level are recorded in ``Config.warnings`` and otherwise
ignored (forward compatibility: older toolkits can read newer files). All
sections are optional; an absent section simply produces no ops.
"""

from __future__ import annotations

import json

from .firewall import FW, NAME_RE, PROTO_RE, ZONE_RE
from .firewall import _validate_dest_ip, _validate_dest_port

SCHEMA_VERSION = 1

#: Rule fields forwarded verbatim to ``FW.ensure``.
_ENSURE_KWARGS = ("name", "proto", "dest_ip", "dest_port", "family", "src",
                  "dest")

_OP_SYMBOLS = {"CREATE": "+", "UPDATE": "~", "DELETE": "-", "NOOP": "=",
               "CHECK_PASS": "ok", "CHECK_FAIL": "FAIL"}


class ConfigError(RuntimeError):
    """Invalid declarative config. The message carries the field path,
    e.g. ``firewall.rules[0].dest_port: out of range``."""


class Config:
    """Validated, normalized declarative configuration."""

    def __init__(self, firewall_rules: list[dict], firewall_prune: bool,
                 ssh: dict, warnings: list[str]) -> None:
        self.firewall_rules = firewall_rules
        self.firewall_prune = firewall_prune
        self.ssh = ssh  # {"require_key_only": bool, "require_lan_only": bool}
        self.warnings = warnings

    def to_dict(self) -> dict:
        return {
            "version": SCHEMA_VERSION,
            "firewall": {"prune": self.firewall_prune,
                         "rules": self.firewall_rules},
            "ssh": dict(self.ssh),
            "warnings": list(self.warnings),
        }


def _fail(path: str, message: str) -> None:
    raise ConfigError(f"{path}: {message}")


def _require_bool(value, path: str) -> bool:
    if not isinstance(value, bool):
        _fail(path, f"expected boolean, got {type(value).__name__}")
    return value


def _validate_rule(rule, index: int) -> tuple[dict, list[str]]:
    path = f"firewall.rules[{index}]"
    if not isinstance(rule, dict):
        _fail(path, f"expected object, got {type(rule).__name__}")

    name = rule.get("name")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        _fail(f"{path}.name", "must match [A-Za-z0-9_-]{1,32}")

    proto = rule.get("proto")
    if not isinstance(proto, str) or not PROTO_RE.fullmatch(proto):
        _fail(f"{path}.proto", "must match [A-Za-z0-9_]{1,16}")

    dest_ip = rule.get("dest_ip")
    if not isinstance(dest_ip, str):
        _fail(f"{path}.dest_ip", "must be an IPv4/IPv6 address string")
    try:
        dest_ip = _validate_dest_ip(dest_ip)  # normalized, injection-proof
    except RuntimeError as exc:
        _fail(f"{path}.dest_ip", str(exc))

    dest_port = rule.get("dest_port")
    if isinstance(dest_port, bool):
        _fail(f"{path}.dest_port", "must be an int or port-spec string")
    if isinstance(dest_port, int):
        dest_port = str(dest_port)
    if not isinstance(dest_port, str):
        _fail(f"{path}.dest_port", "must be an int or port-spec string")
    try:
        dest_port = _validate_dest_port(dest_port)
    except RuntimeError as exc:
        _fail(f"{path}.dest_port", str(exc))

    family = rule.get("family", "ipv6")
    if family not in {"ipv4", "ipv6", "any"}:
        _fail(f"{path}.family", "must be ipv4, ipv6, or any")

    src = rule.get("src", "wan")
    if not isinstance(src, str) or not ZONE_RE.fullmatch(src):
        _fail(f"{path}.src", "must match [A-Za-z0-9_]{1,32}")
    dest = rule.get("dest", "lan")
    if not isinstance(dest, str) or not ZONE_RE.fullmatch(dest):
        _fail(f"{path}.dest", "must match [A-Za-z0-9_]{1,32}")

    enabled = rule.get("enabled", True)
    _require_bool(enabled, f"{path}.enabled")
    if not enabled:
        # FW.ensure hardcodes enabled='1'; applying an enabled=false rule
        # would never converge, so reject it instead of breaking idempotency.
        _fail(f"{path}.enabled",
              "only true is supported in schema v1 (FW.ensure always enables);"
              " remove the rule from the config to stop managing it")

    known = {"name", "proto", "dest_ip", "dest_port", "family", "src",
             "dest", "enabled"}
    warnings = [f"{path}.{k}: unknown key ignored" for k in rule
                if k not in known]
    normalized = {"name": name, "proto": proto, "dest_ip": dest_ip,
                  "dest_port": dest_port, "family": family, "src": src,
                  "dest": dest, "enabled": True}
    return normalized, warnings


def load_config(path: str) -> Config:
    """Parse and strictly validate a JSON config file.

    Raises :class:`ConfigError` (a ``RuntimeError``) with the dotted field
    path on any violation. Unknown keys are tolerated and reported through
    ``Config.warnings``.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: invalid JSON: {exc}") from exc
    except FileNotFoundError as exc:
        raise ConfigError(f"{path}: file not found") from exc

    if not isinstance(raw, dict):
        _fail("$", f"top level must be an object, got {type(raw).__name__}")
    version = raw.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        _fail("version", "required integer schema version")
    if version != SCHEMA_VERSION:
        _fail("version", f"unsupported schema version {version}; "
                         f"this toolkit understands {SCHEMA_VERSION}")

    warnings = []
    for key in raw:
        if key not in {"version", "firewall", "ssh"}:
            warnings.append(f"{key}: unknown top-level key ignored")

    firewall = raw.get("firewall", {})
    if not isinstance(firewall, dict):
        _fail("firewall", f"expected object, got {type(firewall).__name__}")
    for key in firewall:
        if key not in {"rules", "prune"}:
            warnings.append(f"firewall.{key}: unknown key ignored")
    prune = _require_bool(firewall.get("prune", False), "firewall.prune")

    rules_raw = firewall.get("rules", [])
    if not isinstance(rules_raw, list):
        _fail("firewall.rules", f"expected array, "
                                f"got {type(rules_raw).__name__}")
    rules, seen = [], set()
    for index, item in enumerate(rules_raw):
        normalized, rule_warnings = _validate_rule(item, index)
        if normalized["name"] in seen:
            _fail(f"firewall.rules[{index}].name",
                  f"duplicate rule name {normalized['name']!r}")
        seen.add(normalized["name"])
        rules.append(normalized)
        warnings.extend(rule_warnings)

    ssh_raw = raw.get("ssh", {})
    if not isinstance(ssh_raw, dict):
        _fail("ssh", f"expected object, got {type(ssh_raw).__name__}")
    ssh = {}
    for key in ("require_key_only", "require_lan_only"):
        if key in ssh_raw:
            ssh[key] = _require_bool(ssh_raw[key], f"ssh.{key}")
    for key in ssh_raw:
        if key not in {"require_key_only", "require_lan_only"}:
            warnings.append(f"ssh.{key}: unknown key ignored")

    return Config(rules, prune, ssh, warnings)


def _desired(rule: dict) -> dict:
    return FW._desired(rule["name"], rule["proto"], rule["dest_ip"],
                       rule["dest_port"], rule["family"], rule["src"],
                       rule["dest"])


def _rule_changes(current: dict, desired: dict) -> dict:
    """Field-level diff between a device rule and the desired state.

    Mirrors the comparison inside ``FW.ensure`` (missing family means "any")
    so a NOOP here exactly matches ensure's no-change path.
    """
    changes = {}
    for key, value in desired.items():
        old = current.get(key, "any" if key == "family" else "")
        if old != value:
            changes[key] = [old, value]
    return changes


def _is_toolkit_managed(rule: dict) -> bool:
    """Heuristic for ``prune``: the pinhole shape this toolkit creates
    (named wan->lan ACCEPT rule pinned to dest_ip + dest_port). Rules not
    matching this shape are never deleted by apply."""
    return (bool(rule.get("name")) and rule.get("target") == "ACCEPT"
            and rule.get("src") == "wan" and bool(rule.get("dest_ip"))
            and bool(rule.get("dest_port")))


def _op(op: str, kind: str, description: str, details: dict) -> dict:
    return {"op": op, "kind": kind, "description": description,
            "details": details}


def plan(config: Config, rules: list[dict],
         ssh_state: dict | None = None) -> dict:
    """Pure diff: desired state vs observed device state.

    ``rules`` is the output of ``FW.list_rules()``; ``ssh_state`` the output
    of :func:`read_ssh_state` (required iff the config has an ssh section).
    Returns a plan dict with an ordered ``ops`` list and a ``summary`` of op
    counts. ``ok`` is False when any CHECK_FAIL op is present.
    """
    ops: list[dict] = []

    by_name: dict[str, list[dict]] = {}
    for rule in rules:
        name = rule.get("name")
        if name:
            by_name.setdefault(name, []).append(rule)

    for rule in config.firewall_rules:
        desired = _desired(rule)
        ensure_kwargs = {k: rule[k] for k in _ENSURE_KWARGS}
        matches = by_name.get(rule["name"], [])
        if len(matches) > 1:
            ops.append(_op(
                "CHECK_FAIL", "firewall",
                f"rule {rule['name']!r}: {len(matches)} duplicate sections on "
                "device; run 'nexxt fw audit' and remove duplicates",
                {"name": rule["name"], "duplicates": len(matches)}))
        elif matches:
            changes = _rule_changes(matches[0], desired)
            if changes:
                ops.append(_op(
                    "UPDATE", "firewall",
                    f"rule {rule['name']!r}: update "
                    + ", ".join(f"{k} {old!r} -> {new!r}"
                                for k, (old, new) in changes.items()),
                    {"name": rule["name"], "section": matches[0]["section"],
                     "changes": changes, "ensure": ensure_kwargs}))
            else:
                ops.append(_op("NOOP", "firewall",
                               f"rule {rule['name']!r}: already exact",
                               {"name": rule["name"],
                                "section": matches[0]["section"]}))
        else:
            ops.append(_op(
                "CREATE", "firewall",
                f"rule {rule['name']!r}: create {rule['proto']} "
                f"{rule['src']}->{rule['dest']} "
                f"{rule['dest_ip']}:{rule['dest_port']}",
                {"name": rule["name"], "ensure": ensure_kwargs}))

    if config.firewall_prune:
        managed_names = {r["name"] for r in config.firewall_rules}
        for rule in rules:
            name = rule.get("name")
            if name and name not in managed_names and _is_toolkit_managed(rule):
                ops.append(_op(
                    "DELETE", "firewall",
                    f"rule {name!r}: delete (toolkit-managed, not in config)",
                    {"name": name, "section": rule["section"]}))

    if config.ssh:
        if ssh_state is None:
            raise RuntimeError(
                "ssh_state is required when the config has an ssh section")
        checks = (("require_key_only", "key_only",
                   "SSH is key-only (password auth off, key installed)"),
                  ("require_lan_only", "lan_only",
                   "SSH listens on LAN only"))
        for config_key, state_key, label in checks:
            if not config.ssh.get(config_key):
                continue
            ok = bool(ssh_state.get(state_key))
            ops.append(_op(
                "CHECK_PASS" if ok else "CHECK_FAIL", "ssh",
                f"{label}: {'ok' if ok else 'FAILED'}",
                {"check": config_key, "expected": True, "actual": ok}))

    summary = {word: 0 for word in ("create", "update", "delete", "noop",
                                    "check_pass", "check_fail")}
    for item in ops:
        summary[item["op"].lower()] += 1
    return {"version": SCHEMA_VERSION, "ops": ops, "summary": summary,
            "ok": summary["check_fail"] == 0,
            "pending_changes": (summary["create"] + summary["update"]
                                + summary["delete"])}


def apply_plan(plan_dict: dict, fw, log=None) -> dict:
    """Execute a plan against an FW-like object (ensure/delete).

    Refuses to mutate anything while the plan contains CHECK_FAIL ops.
    Otherwise runs CREATE/UPDATE via ``fw.ensure`` and DELETE via
    ``fw.delete`` in plan order, stopping at the first failure. Returns a
    result dict: ``ok``, ``applied``/``unchanged`` ops with device results,
    the ``failed`` op (with error) and the ``aborted`` ops that never ran.
    """
    log = log or (lambda msg: None)
    ops = plan_dict["ops"]
    result = {"ok": True, "applied": [], "unchanged": [],
              "checks_failed": [{"op": item["op"], "description": item["description"],
                                 "details": item["details"]}
                                for item in ops if item["op"] == "CHECK_FAIL"],
              "failed": None, "aborted": []}

    mutating = [item for item in ops if item["op"] in ("CREATE", "UPDATE", "DELETE")]
    if result["checks_failed"]:
        result["ok"] = False
        result["aborted"] = mutating
        log("[apply] refusing to apply: ssh/firewall assertions failed")
        return result

    for index, item in enumerate(ops):
        if item["op"] in ("NOOP", "CHECK_PASS"):
            result["unchanged"].append(item)
            log(f"[apply] {item['description']}")
            continue
        try:
            if item["op"] in ("CREATE", "UPDATE"):
                outcome = fw.ensure(**item["details"]["ensure"])
            else:  # DELETE
                outcome = {"deleted": fw.delete(item["details"]["name"])}
        except Exception as exc:
            record = dict(item)
            record["error"] = str(exc)
            result["ok"] = False
            result["failed"] = record
            remaining = [x for x in ops[index + 1:]
                         if x["op"] in ("CREATE", "UPDATE", "DELETE")]
            result["aborted"] = remaining
            log(f"[apply] FAILED: {item['description']}: {exc}")
            return result
        record = dict(item)
        record["result"] = outcome
        result["applied"].append(record)
        log(f"[apply] {item['description']}")
    return result


def read_ssh_state(run) -> dict:
    """Read SSH service posture via a ``run(cmd) -> stdout`` callable
    (e.g. ``FW.run``). Returns flags consumed by :func:`plan`."""
    uci = run("uci show dropbear.nx 2>/dev/null || true")
    key_answer = run(
        "test -s /etc/dropbear/authorized_keys && echo yes || echo no")
    instance = bool(uci.strip())
    authorized_keys = key_answer.strip().splitlines()[-1:] == ["yes"]
    password_off = ("dropbear.nx.PasswordAuth='off'" in uci
                    and "dropbear.nx.RootPasswordAuth='off'" in uci)
    lan_only = "dropbear.nx.Interface='lan'" in uci
    return {"instance": instance,
            "authorized_keys": authorized_keys,
            "key_only": instance and authorized_keys and password_off,
            "lan_only": instance and lan_only}


def gather_plan(config: Config, fw) -> dict:
    """Fetch live device state through ``fw`` and compute the plan."""
    ssh_state = read_ssh_state(fw.run) if config.ssh else None
    return plan(config, fw.list_rules(), ssh_state)


def render_plan(plan_dict: dict) -> str:
    """Human-readable, read-only rendering of a plan (``nexxt diff``)."""
    lines = []
    for item in plan_dict["ops"]:
        symbol = _OP_SYMBOLS.get(item["op"], "?")
        lines.append(f"[{symbol}] {item['description']}")
    if not lines:
        lines.append("(no ops: config is empty)")
    s = plan_dict["summary"]
    lines.append(
        f"plan: {s['create']} to create, {s['update']} to update, "
        f"{s['delete']} to delete, {s['noop']} unchanged, "
        f"{s['check_pass']} checks ok, {s['check_fail']} checks failed")
    return "\n".join(lines)


def run_diff(fw, config_path: str) -> tuple[dict, int]:
    """CLI entry for ``nexxt diff``. Exit 0 in sync, 2 changes pending,
    1 assertions failed."""
    config = load_config(config_path)
    plan_dict = gather_plan(config, fw)
    if not plan_dict["ok"]:
        return plan_dict, 1
    return plan_dict, 2 if plan_dict["pending_changes"] else 0


def run_apply(fw, config_path: str, log=None) -> tuple[dict, int]:
    """CLI entry for ``nexxt apply``. Exit 0 converged, 1 failure."""
    config = load_config(config_path)
    plan_dict = gather_plan(config, fw)
    result = apply_plan(plan_dict, fw, log=log)
    result["plan_summary"] = plan_dict["summary"]
    result["config_warnings"] = config.warnings
    return result, 0 if result["ok"] else 1
