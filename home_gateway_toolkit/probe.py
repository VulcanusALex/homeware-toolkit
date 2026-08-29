"""Unauthenticated read-only compatibility probe (public static assets only)."""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

from . import __version__

USER_AGENT = f"home-gateway-toolkit/{__version__}"

ASSETS = (
    "/login",
    "/app/app.js",
    "/app/services/sharedServices.js",
    "/app/services/statusService.js",
)
PORTS = (22, 23, 80, 443, 8080, 8443)

import socket  # noqa: E402


def fetch(base_url: str, path: str, timeout: float) -> dict:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT},
                                     method="GET")
    context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(2_000_000).decode("utf-8", errors="replace")
            return {"url": url, "status": response.status,
                    "last_modified": response.headers.get("Last-Modified"),
                    "content_type": response.headers.get("Content-Type"), "body": body}
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


def inspect_assets(items: dict) -> dict:
    combined = "\n".join(str(item.get("body", "")) for item in items.values())
    app_js = str(items.get("/app/app.js", {}).get("body", ""))
    status_js = str(items.get("/app/services/statusService.js", {}).get("body", ""))
    login_html = str(items.get("/login", {}).get("body", ""))

    version_stamps = sorted(set(re.findall(r"[?&]v=(\d{14})", login_html)))
    ipv6_match = re.search(r"const\s+ipv6\s*=\s*/(.*?)/gi\.test\(value\)", app_js, re.DOTALL)
    ipv6_pattern = ipv6_match.group(1).strip() if ipv6_match else None

    return {
        "asset_version_stamps": version_stamps,
        "uses_status_cgi": "apiServiceUrl', '/status.cgi'" in combined,
        "has_pingstatus_setter": "api.set('pingstatus', data)" in status_js,
        "has_ping_status_reader": "api.get('pingstatusinfo')" in status_js,
        "ipv6_validator_found": ipv6_pattern is not None,
        "ipv6_validator_start_anchored": bool(ipv6_pattern and ipv6_pattern.startswith("^")),
        "ipv6_validator_end_anchored": bool(ipv6_pattern and ipv6_pattern.endswith("$")),
        # Short-circuit: when ipv6_pattern is None (older/different firmware,
        # or asset fetch failed — exactly the case this probe must REPORT),
        # `and` stops before None.startswith(...) instead of raising.
        "compatibility_signal": (
            "strong-front-end-match"
            if ("apiServiceUrl', '/status.cgi'" in combined
                and "api.set('pingstatus', data)" in status_js
                and ipv6_pattern is not None
                and not ipv6_pattern.startswith("^")
                and not ipv6_pattern.endswith("$"))
            else "incomplete-match"
        ),
    }


def run_probe(base_url: str, timeout: float = 3.0) -> dict:
    host = urllib.parse.urlparse(base_url).hostname
    fetched = {path: fetch(base_url, path, timeout) for path in ASSETS}
    return {
        "target": base_url,
        "tcp_ports": {str(p): tcp_state(host, p, timeout) for p in PORTS},
        "assets": {path: {k: v for k, v in item.items() if k != "body"}
                   for path, item in fetched.items()},
        "analysis": inspect_assets(fetched),
    }
