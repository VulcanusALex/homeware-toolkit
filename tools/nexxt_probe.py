#!/usr/bin/env python3
"""Read-only compatibility probe for a local Fastweb NeXXt web interface.

The probe fetches only public static web assets and attempts TCP connects. It
does not authenticate, submit diagnostic requests, change settings, or execute
router/community code.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_BASE_URL = "https://192.168.1.254"
ASSETS = (
    "/login",
    "/app/app.js",
    "/app/services/sharedServices.js",
    "/app/services/statusService.js",
)
PORTS = (22, 23, 80, 443, 8080, 8443)


def ensure_local_target(host: str) -> list[str]:
    """Resolve host and refuse to probe addresses outside local/private ranges."""
    try:
        resolved = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
    except socket.gaierror as exc:
        raise RuntimeError(f"cannot resolve {host}: {exc}") from exc

    if not resolved:
        raise RuntimeError(f"no address resolved for {host}")

    for value in resolved:
        address = ipaddress.ip_address(value.split("%", 1)[0])
        if not (address.is_private or address.is_link_local or address.is_loopback):
            raise RuntimeError(f"refusing non-local address: {address}")
    return resolved


def fetch(base_url: str, path: str, timeout: float) -> dict[str, object]:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "nexxt-readonly-probe/1.0"},
        method="GET",
    )
    context = ssl._create_unverified_context()  # Local router uses a self-signed cert.
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(2_000_000).decode("utf-8", errors="replace")
            return {
                "url": url,
                "status": response.status,
                "last_modified": response.headers.get("Last-Modified"),
                "content_type": response.headers.get("Content-Type"),
                "body": body,
            }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"url": url, "error": str(exc), "body": ""}


def tcp_state(host: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "refused"
    except (TimeoutError, socket.timeout):
        return "timeout"
    except OSError as exc:
        return f"error: {exc}"


def inspect_assets(items: dict[str, dict[str, object]]) -> dict[str, object]:
    combined = "\n".join(str(item.get("body", "")) for item in items.values())
    app_js = str(items.get("/app/app.js", {}).get("body", ""))
    status_js = str(items.get("/app/services/statusService.js", {}).get("body", ""))
    login_html = str(items.get("/login", {}).get("body", ""))

    version_stamps = sorted(set(re.findall(r"[?&]v=(\d{14})", login_html)))
    ipv6_match = re.search(
        r"const\s+ipv6\s*=\s*/(.*?)/gi\.test\(value\)", app_js, re.DOTALL
    )
    ipv6_pattern = ipv6_match.group(1).strip() if ipv6_match else None

    return {
        "asset_version_stamps": version_stamps,
        "uses_status_cgi": "apiServiceUrl', '/status.cgi'" in combined,
        "has_pingstatus_setter": "api.set('pingstatus', data)" in status_js,
        "has_ping_status_reader": "api.get('pingstatusinfo')" in status_js,
        "has_client_ping_validator": "valid_pingTrace" in app_js,
        "ipv6_validator_found": ipv6_pattern is not None,
        "ipv6_validator_start_anchored": bool(ipv6_pattern and ipv6_pattern.startswith("^")),
        "ipv6_validator_end_anchored": bool(ipv6_pattern and ipv6_pattern.endswith("$")),
        "compatibility_signal": (
            "strong-front-end-match"
            if all(
                (
                    "apiServiceUrl', '/status.cgi'" in combined,
                    "api.set('pingstatus', data)" in status_js,
                    ipv6_pattern is not None,
                    not ipv6_pattern.startswith("^"),
                    not ipv6_pattern.endswith("$"),
                )
            )
            else "incomplete-match"
        ),
        "important_limit": (
            "Static assets can show that the same request path and weak client-side "
            "validation remain, but cannot prove that the router backend still executes "
            "shell metacharacters. No payload was sent."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()

    parsed = urllib.parse.urlparse(args.base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        parser.error("base URL must be an http(s) URL with a host")

    try:
        addresses = ensure_local_target(parsed.hostname)
    except RuntimeError as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, indent=2))
        return 2

    fetched = {path: fetch(args.base_url, path, args.timeout) for path in ASSETS}
    output = {
        "probe": "nexxt-readonly-probe/1.0",
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "target": {"base_url": args.base_url, "resolved_addresses": addresses},
        "safety": {
            "authenticated": False,
            "submitted_router_forms": False,
            "sent_diagnostic_payload": False,
            "modified_router": False,
            "executed_third_party_code": False,
        },
        "tcp_ports": {
            str(port): tcp_state(parsed.hostname, port, args.timeout) for port in PORTS
        },
        "assets": {
            path: {key: value for key, value in item.items() if key != "body"}
            for path, item in fetched.items()
        },
        "analysis": inspect_assets(fetched),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
