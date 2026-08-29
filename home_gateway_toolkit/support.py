"""Generate a deliberately minimal, sanitized compatibility support bundle."""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import platform
import re
import zipfile

from . import __version__
from .client import NexxtClient
from .doctor import run_doctor
from .probe import run_probe


SAFE_SYSINFO_FIELDS = ("model", "product_name", "hw_version", "fw_version",
                       "software_version", "hardware_version")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_MAC = re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b")
_IPV6 = re.compile(r"(?i)(?<![0-9a-f:])\[?(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\]?(?![0-9a-f:])")


def _redact_string(value: str) -> str:
    value = _MAC.sub("<redacted-mac>", value)
    value = _IPV4.sub("<redacted-ipv4>", value)

    def replace_v6(match: re.Match) -> str:
        token = match.group(0)
        bare = token.strip("[]")
        try:
            ipaddress.IPv6Address(bare)
        except ValueError:
            return token
        return "<redacted-ipv6>"

    return _IPV6.sub(replace_v6, value)


def _sanitize(value):
    if isinstance(value, dict):
        return {str(k): _sanitize(v) for k, v in value.items()
                if not any(secret in str(k).lower() for secret in
                           ("cookie", "session", "password", "secret", "private",
                            "preshared", "uuid", "short_id", "sip", "serial", "imei"))}
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, str):
        return _redact_string(value)
    return value


def build_report(base_url: str, port: int = 2222, key: str | None = None) -> dict:
    probe = _sanitize(run_probe(base_url))
    report = {
        "schema": 1,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "toolkit_version": __version__,
        "environment": {"python": platform.python_version(),
                        "platform": platform.platform()},
        "probe": probe,
        "privacy": [
            "No cookies, session IDs, keys, passwords, SIP/VoIP credentials, MACs, serials, or raw IP addresses are included.",
            "Review the report before sharing it publicly.",
        ],
    }
    client = NexxtClient(base_url)
    if client.is_authenticated():
        status, data = client.get("sysinfo")
        raw = data.get("sysinfo", {}) if status == 200 else {}
        report["sysinfo"] = _sanitize(
            {field: raw[field] for field in SAFE_SYSINFO_FIELDS if field in raw})
    if key:
        stages, _ = run_doctor(base_url, port, key=key,
                               check_injection=False, log=lambda _msg: None)
        report["doctor"] = _sanitize(stages)
    return report


def write_bundle(report: dict, output: str) -> str:
    output = os.path.abspath(os.path.expanduser(output))
    os.makedirs(os.path.dirname(output), exist_ok=True)
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if output.lower().endswith(".json"):
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(encoded)
    else:
        if not output.lower().endswith(".zip"):
            output += ".zip"
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("report.json", encoded)
            archive.writestr(
                "README.txt",
                "Sanitized home-gateway-toolkit support bundle. Review report.json "
                "before attaching it to a public issue.\n")
    os.chmod(output, 0o600)
    return output


def default_output() -> str:
    stamp = dt.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    return os.path.join(os.getcwd(), f"home-gateway-support-{stamp}.zip")
