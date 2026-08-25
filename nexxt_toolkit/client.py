"""HTTP client for the NeXXt web API and session handling.

Only talks to local/private addresses. Stores the session cookie locally
(never any password — the stock UI has none).
"""

from __future__ import annotations

import http.cookiejar
import ipaddress
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE_URL = "https://192.168.1.254"
USER_AGENT = "nexxt-one-toolkit/1.2 (own-network diagnostics)"

READ_ONLY_SERVICES = (
    "sysinfo", "wanstatusinfo", "wwanstatusinfo", "lan_status", "laninfo",
    "lanipv6details", "firewall_conf", "dmz_conf", "virtual_server_list",
    "upnp_conf", "pingstatusinfo",
)


def ensure_local_target(host: str) -> list[str]:
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


class SessionExpired(RuntimeError):
    pass


class NexxtClient:
    def __init__(self, base_url: str = DEFAULT_BASE_URL, timeout: float = 5.0,
                 work_dir: str = ".work") -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise RuntimeError("base URL must be an http(s) URL with a host")
        self.host = parsed.hostname
        ensure_local_target(self.host)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        os.makedirs(work_dir, exist_ok=True)
        self.cookie_file = os.path.join(work_dir, "nexxt_session_cookies.txt")
        self.jar = http.cookiejar.MozillaCookieJar(self.cookie_file)
        if os.path.exists(self.cookie_file):
            try:
                self.jar.load(ignore_discard=True, ignore_expires=True)
            except Exception:
                pass
        context = ssl._create_unverified_context()  # router self-signed cert
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=context),
        )
        self.opener.addheaders = [("User-Agent", USER_AGENT)]

    def save_cookies(self) -> None:
        self.jar.save(ignore_discard=True, ignore_expires=True)

    def _cgi(self, params: dict) -> tuple[int, dict]:
        query = dict(params)
        query["_"] = int(time.time() * 1000)
        url = f"{self.base_url}/status.cgi?{urllib.parse.urlencode(query)}"
        try:
            with self.opener.open(url, timeout=self.timeout) as response:
                body = response.read(1_000_000).decode("utf-8", errors="replace")
                status = response.status
        except urllib.error.HTTPError as exc:
            return exc.code, {"http_error": exc.code,
                              "body": exc.read(4096).decode("utf-8", errors="replace")}
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return -1, {"transport_error": str(exc)}
        self.save_cookies()
        try:
            return status, json.loads(body)
        except ValueError:
            return status, {"raw_body": body[:2000]}

    def get(self, service: str, **params) -> tuple[int, dict]:
        return self._cgi({"nvget": service, **params})

    def set(self, service: str, **params) -> tuple[int, dict]:
        return self._cgi({"act": "nvset", "service": service, **params})

    # ---- auth ----

    def login_status(self) -> tuple[int, dict]:
        return self.get("login_confirm", cmd=4)

    def is_authenticated(self) -> bool:
        status, data = self.login_status()
        return status == 200 and str(data.get("login_confirm", {}).get("login_status")) == "1"

    def require_auth(self) -> None:
        if not self.is_authenticated():
            raise SessionExpired(
                "not authenticated; run 'nexxt session login' or "
                "'nexxt session import-cookie <har>' first")

    def fresh_session(self) -> None:
        """Drop the cookie jar so the router issues a NEW session.

        The button-login confirm step only authenticates the session that was
        created most recently (see sessionmgr.lua:newSession and login.wat),
        so scripted login must start with a fresh cookie.
        """
        self.jar.clear()
        try:
            with self.opener.open(f"{self.base_url}/login", timeout=self.timeout) as resp:
                resp.read(100_000)
        except Exception:
            pass
        self.save_cookies()

    def button_login(self, wait_seconds: int = 60, log=print) -> bool:
        """Reproduce the UI login: fresh session, arm button wait, poll, confirm."""
        self.fresh_session()
        log("[login] fresh session created (must stay the latest — do not open")
        log("        the router page in a browser during this process)")

        status, data = self.set("login_confirm", cmd=7, loginPath=2)
        log(f"[login] armed button wait (http {status})")
        log(f"[login] press BOTH side buttons for 3s within {wait_seconds}s")
        deadline = time.time() + wait_seconds
        detected = confirmed = False
        while time.time() < deadline:
            time.sleep(1.0)
            if detected:
                _, data = self.login_status()
                state = str(data.get("login_confirm", {}).get("login_status", ""))
                if state == "1":
                    return True
                if not confirmed:
                    confirmed = True
                    self.set("login_confirm", cmd=7, loginPath=1)
                continue
            _, data = self.get("login_confirm", cmd=7)
            if str(data.get("login_confirm", {}).get("loginPath", "")) == "1":
                detected = True
                log("[login] button press detected")
        return False

    def import_cookie(self, source: str) -> bool:
        """Import sessionID from a HAR export path or a raw cookie value."""
        sid = None
        if os.path.exists(source):
            har = json.load(open(source))
            for entry in har.get("log", {}).get("entries", []):
                for header in entry.get("request", {}).get("headers", []):
                    if header.get("name", "").lower() == "cookie":
                        for part in header.get("value", "").split(";"):
                            part = part.strip()
                            if part.startswith("sessionID="):
                                sid = part.split("=", 1)[1]
        else:
            sid = source.removeprefix("sessionID=").strip()
        if not sid:
            raise RuntimeError("no sessionID found in input")
        cookie = http.cookiejar.Cookie(
            0, "sessionID", sid, None, False, self.host, True, False,
            "/", True, False, None, False, None, None, {}, False)
        self.jar.set_cookie(cookie)
        self.save_cookies()
        return self.is_authenticated()

    def dump(self) -> dict:
        self.require_auth()
        out = {}
        for service in READ_ONLY_SERVICES:
            status, data = self.get(service)
            out[service] = {"http": status, "data": data}
        return out
