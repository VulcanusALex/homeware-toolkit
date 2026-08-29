"""HTTP client for the NeXXt web API and session handling.

Only talks to local/private addresses. Stores the session cookie locally
(never any password — the stock UI has none).
"""

from __future__ import annotations

import hashlib
import http.client
import http.cookiejar
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__

# Imported lazily to avoid circular imports; driver.py imports compat only.
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .driver import Device

DEFAULT_BASE_URL = "https://192.168.1.254"
USER_AGENT = f"home-gateway-toolkit/{__version__} (own-network diagnostics)"

READ_ONLY_SERVICES = (
    "sysinfo", "wanstatusinfo", "wwanstatusinfo", "lan_status", "laninfo",
    "lanipv6details", "firewall_conf", "dmz_conf", "virtual_server_list",
    "upnp_conf", "pingstatusinfo",
)


class FingerprintMismatch(ssl.SSLError):
    """The peer certificate does not match the pinned SHA-256 fingerprint."""


def normalize_tls_fingerprint(fingerprint: str) -> str:
    """Normalize a SHA-256 fingerprint to 64 lowercase hex chars (no colons).

    Accepts both colon-separated (any case) and plain hex forms.
    """
    if not isinstance(fingerprint, str):
        raise ValueError("TLS fingerprint must be a string")
    compact = fingerprint.replace(":", "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", compact):
        raise ValueError(
            "TLS fingerprint must be a 64-hex-character SHA-256 digest "
            f"(colons optional): {fingerprint!r}")
    return compact


def format_tls_fingerprint(digest_hex: str) -> str:
    """Render a normalized hex digest in the classic colon-separated form."""
    compact = normalize_tls_fingerprint(digest_hex)
    return ":".join(compact[i:i + 2] for i in range(0, 64, 2))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that pins the peer certificate by SHA-256 fingerprint.

    CA verification stays off (the device uses a self-signed certificate);
    the fingerprint is checked right after the handshake instead.
    """

    def __init__(self, *args, fingerprint: str | None = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._pinned_fingerprint = fingerprint

    def connect(self) -> None:
        super().connect()
        if self._pinned_fingerprint is None:
            return
        der = self.sock.getpeercert(binary_form=True)
        actual = hashlib.sha256(der).hexdigest()
        if actual != self._pinned_fingerprint:
            self.sock.close()
            raise FingerprintMismatch(
                "TLS fingerprint mismatch: device presented "
                f"{format_tls_fingerprint(actual)} but "
                f"{format_tls_fingerprint(self._pinned_fingerprint)} was "
                "pinned; refusing to connect (possible impersonation or "
                "firmware re-flash)")


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPSHandler that builds fingerprint-pinning connections."""

    def __init__(self, context: ssl.SSLContext, fingerprint: str) -> None:
        super().__init__(context=context)
        self._pinned_fingerprint = fingerprint

    def https_open(self, req):
        return self.do_open(
            lambda host, **kwargs: _PinnedHTTPSConnection(
                host, context=self._context,
                fingerprint=self._pinned_fingerprint, **kwargs),
            req)


def fetch_tls_fingerprint(base_url: str = DEFAULT_BASE_URL,
                          timeout: float = 5.0) -> str:
    """Fetch the device's TLS certificate and return its SHA-256 fingerprint.

    CA verification is intentionally skipped (self-signed cert) — the point
    of this helper is to obtain the fingerprint to pin on first contact.
    """
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise RuntimeError("fingerprint fetch requires an https URL with a host")
    host, port = parsed.hostname, parsed.port or 443
    context = ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    return format_tls_fingerprint(hashlib.sha256(der).hexdigest())


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
                 work_dir: str = ".work",
                 tls_fingerprint: str | None = None,
                 device: "Device" | None = None) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise RuntimeError("base URL must be an http(s) URL with a host")
        self.host = parsed.hostname
        ensure_local_target(self.host)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        # Optional certificate pinning: when given, the peer certificate's
        # SHA-256 fingerprint must match even though CA verification stays
        # off (the device uses a self-signed certificate).
        self.tls_fingerprint = (normalize_tls_fingerprint(tls_fingerprint)
                                if tls_fingerprint is not None else None)

        # Device capabilities select the web API shape.  When no device is
        # supplied we default to the historical NeXXt One behaviour.
        if device is None:
            from .driver import default_device
            device = default_device()
        self.device = device
        self._api_base = self.device.cap("api", "base_path", default="/status.cgi")
        self._api_read = self.device.cap("api", "read_param", default="nvget")
        self._api_write = self.device.cap("api", "write_action", default="nvset")

        os.makedirs(work_dir, exist_ok=True)
        self.cookie_file = os.path.join(work_dir, "home_gateway_session_cookies.txt")
        self.jar = http.cookiejar.MozillaCookieJar(self.cookie_file)
        if os.path.exists(self.cookie_file):
            try:
                self.jar.load(ignore_discard=True, ignore_expires=True)
            except Exception:
                pass
        context = ssl._create_unverified_context()  # router self-signed cert
        if self.tls_fingerprint is not None:
            https_handler = _PinnedHTTPSHandler(context, self.tls_fingerprint)
        else:
            https_handler = urllib.request.HTTPSHandler(context=context)
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            https_handler,
        )
        self.opener.addheaders = [("User-Agent", USER_AGENT)]

    def save_cookies(self) -> None:
        self.jar.save(ignore_discard=True, ignore_expires=True)

    def _cgi(self, params: dict) -> tuple[int, dict]:
        query = dict(params)
        query["_"] = int(time.time() * 1000)
        url = f"{self.base_url}{self._api_base}?{urllib.parse.urlencode(query)}"
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
        return self._cgi({self._api_read: service, **params})

    def set(self, service: str, **params) -> tuple[int, dict]:
        return self._cgi({"act": self._api_write, "service": service, **params})

    # ---- auth ----

    def login_status(self) -> tuple[int, dict]:
        auth_service = self.device.cap("auth", "service", default="login_confirm")
        return self.get(auth_service, cmd=4)

    def is_authenticated(self) -> bool:
        auth_service = self.device.cap("auth", "service", default="login_confirm")
        status, data = self.login_status()
        return status == 200 and str(data.get(auth_service, {}).get("login_status")) == "1"

    def require_auth(self) -> None:
        if not self.is_authenticated():
            raise SessionExpired(
                "not authenticated; run 'home-gateway session login' or "
                "'home-gateway session import-cookie <har>' first")

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
        auth_service = self.device.cap("auth", "service", default="login_confirm")
        self.fresh_session()
        log("[login] fresh session created (must stay the latest — do not open")
        log("        the router page in a browser during this process)")

        status, data = self.set(auth_service, cmd=7, loginPath=2)
        log(f"[login] armed button wait (http {status})")
        log(f"[login] press BOTH side buttons for 3s within {wait_seconds}s")
        deadline = time.time() + wait_seconds
        detected = confirmed = False
        while time.time() < deadline:
            time.sleep(1.0)
            if detected:
                _, data = self.login_status()
                state = str(data.get(auth_service, {}).get("login_status", ""))
                if state == "1":
                    return True
                if not confirmed:
                    confirmed = True
                    self.set(auth_service, cmd=7, loginPath=1)
                continue
            _, data = self.get(auth_service, cmd=7)
            if str(data.get(auth_service, {}).get("loginPath", "")) == "1":
                detected = True
                log("[login] button press detected")
        return False

    def import_cookie(self, source: str) -> bool:
        """Import sessionID from a HAR export path or a raw cookie value."""
        sid = None
        if os.path.exists(source):
            with open(source) as fh:
                har = json.load(fh)
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
