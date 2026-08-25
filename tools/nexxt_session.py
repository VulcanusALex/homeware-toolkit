#!/usr/bin/env python3
"""Session helper for the local Fastweb NeXXt web API.

Implements, from scratch, the same request flow the stock web UI uses:

* login:    physical-button assisted login (no password exists in this UI);
            the script polls login_confirm while the user presses the button
            on the router.
* check:    report whether the saved session is still authenticated.
* dump:     read-only Phase-A snapshot (sysinfo, WAN, firewall, DMZ,
            port-forwarding and UPnP state) printed as JSON.

Safety properties:

* only talks to local/private addresses (refuses public ones);
* never writes router configuration except the login_confirm handshake
  itself (loginPath 2 -> poll -> 1), which is the normal UI login flow;
* stores only the session cookie locally under .work/, never any password
  (there is no password in this UI).
"""

from __future__ import annotations

import argparse
import datetime as dt
import http.cookiejar
import ipaddress
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE_URL = "https://192.168.1.254"
HERE = os.path.dirname(os.path.abspath(__file__))
WORK_DIR = os.path.normpath(os.path.join(HERE, "..", ".work"))
COOKIE_FILE = os.path.join(WORK_DIR, "nexxt_session_cookies.txt")
USER_AGENT = "nexxt-session-helper/1.0 (own-network diagnostics)"

READ_ONLY_SERVICES = (
    "sysinfo",
    "statusinfo",
    "wanstatusinfo",
    "wwanstatusinfo",
    "lan_status",
    "laninfo",
    "lanipv6details",
    "firewall_conf",
    "dmz_conf",
    "virtual_server_list",
    "upnp_conf",
    "pingstatusinfo",
)


def ensure_local_target(host: str) -> None:
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


class NexxtClient:
    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise RuntimeError("base URL must be an http(s) URL with a host")
        ensure_local_target(parsed.hostname)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        os.makedirs(WORK_DIR, exist_ok=True)
        self.jar = http.cookiejar.MozillaCookieJar(COOKIE_FILE)
        if os.path.exists(COOKIE_FILE):
            try:
                self.jar.load(ignore_discard=True, ignore_expires=True)
            except Exception:
                pass
        context = ssl._create_unverified_context()  # router uses a self-signed cert
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=context),
        )
        self.opener.addheaders = [("User-Agent", USER_AGENT)]

    def save_cookies(self) -> None:
        self.jar.save(ignore_discard=True, ignore_expires=True)

    def _cgi(self, params: dict[str, object]) -> tuple[int, dict]:
        query = dict(params)
        query["_"] = int(time.time() * 1000)
        url = f"{self.base_url}/status.cgi?{urllib.parse.urlencode(query)}"
        try:
            with self.opener.open(url, timeout=self.timeout) as response:
                body = response.read(1_000_000).decode("utf-8", errors="replace")
                status = response.status
        except urllib.error.HTTPError as exc:
            return exc.code, {"http_error": exc.code, "body": exc.read(4096).decode("utf-8", errors="replace")}
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return -1, {"transport_error": str(exc)}
        self.save_cookies()
        try:
            return status, json.loads(body)
        except ValueError:
            return status, {"raw_body": body[:2000]}

    def get(self, service: str, **params: object) -> tuple[int, dict]:
        return self._cgi({"nvget": service, **params})

    def set(self, service: str, **params: object) -> tuple[int, dict]:
        return self._cgi({"act": "nvset", "service": service, **params})

    # ---- auth ----

    def login_status(self) -> tuple[int, dict]:
        return self.get("login_confirm", cmd=4)

    def is_authenticated(self) -> bool:
        status, data = self.login_status()
        return status == 200 and str(data.get("login_confirm", {}).get("login_status")) == "1"

    def button_login(self, wait_seconds: int = 60) -> bool:
        """Reproduce the UI login: load /login, arm button wait, poll, confirm."""
        # The real UI always loads /login first; some firmware binds the
        # session state machine to that visit.
        try:
            with self.opener.open(f"{self.base_url}/login", timeout=self.timeout) as resp:
                resp.read(100_000)
        except Exception as exc:
            print(f"[login] warning: GET /login failed: {exc}", flush=True)
        self.save_cookies()

        status, data = self.set("login_confirm", cmd=7, loginPath=2)
        print(f"[login] armed button wait (http {status}): {json.dumps(data)}", flush=True)
        print(f"[login] *** 请在 {wait_seconds} 秒内按下 NeXXt 机身上的登录按钮 ***", flush=True)
        deadline = time.time() + wait_seconds
        detected = False
        confirmed = False
        while time.time() < deadline:
            time.sleep(1.0)
            if detected:
                status, data = self.login_status()
                state = str(data.get("login_confirm", {}).get("login_status", ""))
                print(f"[login] post-press login_status={state!r}", flush=True)
                if state == "1":
                    return True
                if not confirmed:
                    confirmed = True
                    status, data = self.set("login_confirm", cmd=7, loginPath=1)
                    print(f"[login] confirm: {json.dumps(data)}", flush=True)
                continue
            status, data = self.get("login_confirm", cmd=7)
            path = str(data.get("login_confirm", {}).get("loginPath", ""))
            print(f"[login] poll: http {status} loginPath={path!r}", flush=True)
            if path == "1":
                detected = True
                print("[login] button press detected, watching login_status...", flush=True)
        return False


def cmd_login(client: NexxtClient, wait: int) -> int:
    if client.is_authenticated():
        print("[login] session already authenticated")
        return 0
    ok = client.button_login(wait)
    print(f"[login] authenticated={ok}")
    return 0 if ok else 1


def cmd_check(client: NexxtClient) -> int:
    status, data = client.login_status()
    print(json.dumps({"http": status, "response": data}, indent=2, ensure_ascii=False))
    return 0 if client.is_authenticated() else 1


def cmd_dump(client: NexxtClient) -> int:
    if not client.is_authenticated():
        print(json.dumps({"error": "not authenticated; run 'login' first"}, indent=2))
        return 1
    out: dict[str, object] = {
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "note": "read-only snapshot; only nvget requests were sent",
    }
    for service in READ_ONLY_SERVICES:
        status, data = client.get(service)
        out[service] = {"http": status, "data": data}
        print(f"[dump] {service}: http {status}", file=sys.stderr, flush=True)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


def cmd_import_cookie(client: NexxtClient, source: str) -> int:
    """Import a sessionID from a browser HAR export or a raw cookie string.

    The stock login requires pressing the physical buttons; the reliable
    scripted path is to log in once in a browser and reuse its sessionID.
    """
    sid = None
    if os.path.exists(source):
        try:
            har = json.load(open(source))
            for entry in har.get("log", {}).get("entries", []):
                for header in entry.get("request", {}).get("headers", []):
                    if header.get("name", "").lower() == "cookie":
                        for part in header.get("value", "").split(";"):
                            part = part.strip()
                            if part.startswith("sessionID="):
                                sid = part.split("=", 1)[1]
        except (ValueError, OSError) as exc:
            print(json.dumps({"error": f"cannot parse HAR: {exc}"}, indent=2))
            return 2
    else:
        sid = source.removeprefix("sessionID=").strip()
    if not sid:
        print(json.dumps({"error": "no sessionID found in input"}, indent=2))
        return 2
    host = urllib.parse.urlparse(client.base_url).hostname
    cookie = http.cookiejar.Cookie(
        0, "sessionID", sid, None, False, host, True, False,
        "/", True, False, None, False, None, None, {}, False)
    client.jar.set_cookie(cookie)
    client.save_cookies()
    ok = client.is_authenticated()
    print(json.dumps({"imported": True, "authenticated": ok}, indent=2))
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--timeout", type=float, default=5.0)
    sub = parser.add_subparsers(dest="command", required=True)
    p_login = sub.add_parser("login", help="button-assisted login")
    p_login.add_argument("--wait", type=int, default=60)
    sub.add_parser("check", help="check authentication state")
    sub.add_parser("dump", help="read-only Phase-A snapshot")
    p_imp = sub.add_parser("import-cookie",
                           help="import sessionID from a browser HAR file or raw value")
    p_imp.add_argument("source", help="path to HAR export, or the sessionID value itself")
    args = parser.parse_args()

    client = NexxtClient(args.base_url, args.timeout)
    if args.command == "login":
        return cmd_login(client, args.wait)
    if args.command == "check":
        return cmd_check(client)
    if args.command == "dump":
        return cmd_dump(client)
    if args.command == "import-cookie":
        return cmd_import_cookie(client, args.source)
    return 2


if __name__ == "__main__":
    sys.exit(main())
