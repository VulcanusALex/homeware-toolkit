"""Data-driven device compatibility database and report generation.

The fingerprint data lives in ``compat.json`` next to this module so that
adding support for a new board or firmware never requires a code change:
edit the JSON, ship it, done.

As of schema 2 each fingerprint may also declare a ``driver`` name and a
``capabilities`` object.  The driver tells the CLI which device-specific
implementation to load; capabilities supply per-device constants such as
injection payload prefixes, firewall backends, and WAN interface names.
When absent, the historical NeXXt One defaults are used so existing data
and older ``compat.json`` files remain valid.

Match semantics (used by the injection guard in ``inject.py``):
  * ``verified`` — board family matches AND the exact firmware is listed in
    ``known_firmware``;
  * ``untested`` — board family matches but the firmware is unknown (the
    guard still allows it, mirroring the historical substring guard which
    never inspected the firmware version);
  * ``unknown``  — no fingerprint entry matches; privileged operations are
    refused unless the operator passes ``--force``.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from dataclasses import dataclass

COMPAT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "compat.json")


def _load_compat_data(path: str | None) -> dict:
    """Load compat.json from a path or from the package resources.

    When ``path`` is the default COMPAT_PATH (i.e. no custom path was supplied),
    we read via ``importlib.resources`` so the toolkit works when packaged as a
    zipapp (``.pyz``).  Custom paths are read directly from the filesystem for
    tests and compatibility-report tooling.
    """
    if path is None or os.path.abspath(path or COMPAT_PATH) == os.path.abspath(COMPAT_PATH):
        try:
            from importlib.resources import files
        except ImportError:  # pragma: no cover - Python <3.9 fallback
            from importlib_resources import files  # type: ignore
        raw = files(__package__).joinpath("compat.json").read_text(encoding="utf-8")
        return json.loads(raw)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)

STATUS_VERIFIED = "verified"
STATUS_UNTESTED = "untested"
STATUS_UNKNOWN = "unknown"

# Historical NeXXt One defaults.  Used when a fingerprint entry does not
# declare its own driver/capabilities (backward compatibility with schema 1).
DEFAULT_DRIVER = "nexxt"
DEFAULT_CAPABILITIES: dict = {
    "api": {
        "base_path": "/status.cgi",
        "read_param": "nvget",
        "write_action": "nvset",
    },
    "auth": {
        "method": "button_login",
        "service": "login_confirm",
    },
    "injection": {
        "service": "pingstatus",
        "payload_prefix": ":::::::;",
        "space_substitute": "${IFS}",
        "oracle_sleep": 5,
    },
    "firewall": {
        "backend": "uci",
    },
    "ssh": {
        "service": "dropbear",
        "instance": "nx",
        "shell": "/bin/ash",
        "original_shell": "/bin/restricted_shell",
        "key_algorithms": ["ssh-rsa"],
    },
    "wan": {
        "wan4_interface": "veip0_1",
        "lan6_interface": "br-lan",
    },
}


@dataclass
class MatchResult:
    """Outcome of matching a device against the compatibility database."""

    status: str                     # verified | untested | unknown
    entry: dict | None = None       # the matching fingerprint entry, if any
    firmware_known: bool = False    # exact firmware found in known_firmware
    reason: str = ""                # human-readable explanation


def load_compat(path: str | None = None) -> list[dict]:
    """Load the fingerprint list from compat.json (list of entries).

    Raises RuntimeError with a clear message if the database is missing or
    malformed — a broken database must fail closed, never silently match.
    """
    try:
        data = _load_compat_data(path)
    except FileNotFoundError:
        raise RuntimeError(f"compatibility database not found: {path or COMPAT_PATH}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"compatibility database is not valid JSON: {exc}")
    if not isinstance(data, dict) or not isinstance(data.get("fingerprints"), list):
        raise RuntimeError(
            f"compatibility database {path} must be an object with a "
            "'fingerprints' list")
    for entry in data["fingerprints"]:
        for key in ("board", "model_prefix", "product_contains"):
            if not isinstance(entry.get(key), str) or not entry[key]:
                raise RuntimeError(
                    f"fingerprint entry missing non-empty {key!r}: {entry!r}")
        if "driver" in entry and (not isinstance(entry["driver"], str)
                                  or not entry["driver"]):
            raise RuntimeError(
                f"fingerprint entry 'driver' must be a non-empty string: "
                f"{entry!r}")
        if "capabilities" in entry and not isinstance(entry["capabilities"], dict):
            raise RuntimeError(
                f"fingerprint entry 'capabilities' must be an object: "
                f"{entry!r}")
    return data["fingerprints"]


def entry_driver(entry: dict | None) -> str:
    """Return the driver name for a fingerprint entry.

    Falls back to ``DEFAULT_DRIVER`` when the entry is missing or does not
    declare one, preserving backward compatibility with schema 1.
    """
    if entry is None:
        return DEFAULT_DRIVER
    return entry.get("driver") or DEFAULT_DRIVER


def _deep_update(base: dict, overlay: dict) -> dict:
    """Return a new dict: ``base`` recursively merged with ``overlay``."""
    result = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_update(result[key], value)
        else:
            result[key] = value
    return result


def entry_capabilities(entry: dict | None) -> dict:
    """Return the capabilities for a fingerprint entry.

    Missing sections are filled from ``DEFAULT_CAPABILITIES`` so callers can
    safely read nested values even for minimal entries.
    """
    if entry is None:
        return dict(DEFAULT_CAPABILITIES)
    return _deep_update(DEFAULT_CAPABILITIES, entry.get("capabilities", {}))


def _contains(haystack: str, needle: str) -> bool:
    return bool(needle) and needle.lower() in (haystack or "").lower()


def match_fingerprint(board: str, model: str, product: str,
                      firmware: str,
                      entries: list[dict] | None = None) -> MatchResult:
    """Match device identity fields against the compatibility database.

    ``board``/``model``/``firmware`` map to the sysinfo fields
    ``hw_version``/``model``/``fw_version``; ``product`` is an optional
    product-name string (falls back to ``model`` when empty).
    """
    entries = load_compat() if entries is None else entries
    product_text = product or model
    for entry in entries:
        board_hit = _contains(board, entry.get("board", ""))
        product_hit = _contains(product_text, entry.get("product_contains", ""))
        model_hit = _contains(f"{model} {firmware}",
                              entry.get("model_prefix", ""))
        if not (board_hit and (product_hit or model_hit)):
            continue
        known = entry.get("known_firmware", [])
        if firmware and firmware in known:
            return MatchResult(
                status=STATUS_VERIFIED, entry=entry, firmware_known=True,
                reason=f"exact firmware match in {os.path.basename(COMPAT_PATH)}")
        return MatchResult(
            status=STATUS_UNTESTED, entry=entry, firmware_known=False,
            reason=(f"board family {entry.get('board')!r} matches but firmware "
                    f"{firmware!r} is not in known_firmware"))
    return MatchResult(
        status=STATUS_UNKNOWN,
        reason=(f"no fingerprint entry matches board={board!r} model={model!r} "
                f"firmware={firmware!r}"))


def generate_compat_report(probe_result: dict,
                           sysinfo: dict | None = None) -> str:
    """Render a Markdown compatibility report suitable for a GitHub issue.

    ``probe_result`` is the dict returned by ``probe.run_probe``; ``sysinfo``
    is the optional authenticated sysinfo payload (its ``sysinfo`` sub-dict).
    Read-only and safe to share: it contains no credentials, keys, MACs or
    serial numbers.
    """
    info = (sysinfo or {}).get("sysinfo", sysinfo or {})
    analysis = probe_result.get("analysis", {})
    assets = probe_result.get("assets", {})
    ports = probe_result.get("tcp_ports", {})
    today = dt.datetime.now(dt.timezone.utc).date().isoformat()

    stamps = analysis.get("asset_version_stamps", [])
    lines = [
        "# home-gateway-toolkit compatibility report",
        "",
        f"- Date (UTC): {today}",
        f"- Target: {probe_result.get('target', 'n/a')}",
        "",
        "## Device fingerprint",
        "",
        f"- Product / model: {info.get('model', '')}",
        f"- Board (hw_version): {info.get('hw_version', '')}",
        f"- Firmware (fw_version): {info.get('fw_version', '')}",
        "",
        "## Probe result (unauthenticated, public assets only)",
        "",
        f"- Compatibility signal: `{analysis.get('compatibility_signal', 'n/a')}`",
        f"- Uses status.cgi API: {analysis.get('uses_status_cgi', 'n/a')}",
        f"- pingstatus setter present: {analysis.get('has_pingstatus_setter', 'n/a')}",
        f"- pingstatusinfo reader present: {analysis.get('has_ping_status_reader', 'n/a')}",
        f"- IPv6 validator found: {analysis.get('ipv6_validator_found', 'n/a')}",
        f"- Asset version stamps: {', '.join(stamps) if stamps else 'none'}",
        "",
        "## TCP port states",
        "",
        "| Port | State |",
        "| --- | --- |",
    ]
    for port in sorted(ports, key=int):
        lines.append(f"| {port} | {ports[port]} |")
    lines += [
        "",
        "## Fetched assets",
        "",
        "| Asset | HTTP | Last-Modified |",
        "| --- | --- | --- |",
    ]
    for path in sorted(assets):
        item = assets[path]
        lines.append(f"| {path} | {item.get('status', item.get('error', 'n/a'))} "
                     f"| {item.get('last_modified') or '-'} |")
    lines += [
        "",
        "## Checklist for the reporter",
        "",
        "- [ ] `home-gateway probe` output attached above (no credentials included)",
        "- [ ] Firmware version read from the web UI or `sysinfo` double-checked",
        "- [ ] `home-gateway doctor` run and result pasted below (optional)",
        "- [ ] `home-gateway verify` tried: yes / no / not tried",
        "- [ ] I reviewed this report and it contains no tokens, keys, MACs or serials",
        "",
        "## Notes",
        "",
        "(anything else: ISP provisioning changes, hardware revision, ...)",
        "",
    ]
    return "\n".join(lines)
