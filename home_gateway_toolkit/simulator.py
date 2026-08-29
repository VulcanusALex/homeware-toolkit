"""In-process fake NeXXt One gateway for hardware-free integration tests.

Simulates the stock web stack closely enough for the toolkit clients:
  * the four static front-end assets probed by probe.py;
  * ``status.cgi?nvget=<service>`` JSON readouts;
  * the physical-button login handshake (login_confirm cmd=7) issuing a
    ``sessionID`` cookie, with configurable session TTL;
  * the ping diagnostic endpoint, including the host-field command
    injection channel: injected commands are interpreted by a tiny
    restricted shell operating on an in-memory virtual filesystem, so the
    full transfer pipeline (chunk / verify / assemble / md5) really runs.

Only used by tests; never talks to a real network by itself (binds to
127.0.0.1 on an ephemeral port).

Fidelity record (checked against a real FW_058 device on 2026-08-29):
  * VERIFIED: all ``nvget`` readouts return nginx 403 without an
    authenticated session -- even a fresh ``/login`` session cookie is not
    enough; only the ``login_confirm`` handshake service itself is reachable
    pre-auth (it implements login).
  * VERIFIED: the JSON envelope wraps payloads as ``{"<service>": {...}}``
    (confirmed for ``login_confirm``; ``sysinfo``/``pingstatusinfo`` follow
    the same convention used by the front-end code).
  * PENDING real-device capture: exact ``DiagnosticsState`` terminal values
    and the full ``pingstatusinfo``/``sysinfo`` field sets. The client only
    relies on the envelope and on the state leaving ``Requested``/
    ``InProgress``, so the simulation is safe for the toolkit's usage.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import re
import secrets
import shlex
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

@dataclass
class DeviceProfile:
    """Configuration for a simulated gateway family.

    The simulator is intentionally still generic (it does not model every
    quirk of a real device), but profiles let integration tests exercise the
    toolkit's device-capability dispatch against different board/firmware
    fingerprints and web-asset signatures.
    """

    name: str
    firmware: str
    board: str
    model: str
    product: str
    asset_stamp: str
    login_html: str
    app_js: str
    shared_services_js: str
    status_service_js: str
    default_services: dict = field(default_factory=dict)
    injection_prefix: str = ":::::::;"

    @property
    def static_assets(self) -> dict[str, tuple[str, str]]:
        return {
            "/app/app.js": ("application/javascript", self.app_js),
            "/app/services/sharedServices.js": (
                "application/javascript", self.shared_services_js),
            "/app/services/statusService.js": (
                "application/javascript", self.status_service_js),
        }


DEFAULT_FIRMWARE = "22.2.0378_FW_058_FGA221D"
ASSET_STAMP = "20260515082010"

_NEXXT_LOGIN_HTML = f"""<!doctype html>
<html><head><title>NeXXt One</title>
<script src="/app/app.js?v={ASSET_STAMP}"></script>
<script src="/app/services/sharedServices.js?v={ASSET_STAMP}"></script>
<script src="/app/services/statusService.js?v={ASSET_STAMP}"></script>
</head><body><div ng-app="nexxt"></div></body></html>
"""

_NEXXT_APP_JS = """'use strict';
var app = angular.module('nexxt', []);
app.factory('validators', function () {
    const ipv6 = /([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/gi.test(value);
    return {ipv6: ipv6};
});
"""

_NEXXT_SHARED_SERVICES_JS = """'use strict';
// The odd array-index line below intentionally reproduces the exact
// "apiServiceUrl', '/status.cgi'" substring the compatibility probe looks
// for in real NeXXt One firmware assets.  Do not "fix" it.
app.service('api', function ($http) {
    $http.defaults.headers.post['apiServiceUrl', '/status.cgi'] = true;
    var apiServiceUrl = '/status.cgi'; // apiServiceUrl', '/status.cgi'
    this.set = function (service, data) { return $http.get(apiServiceUrl, data); };
    this.get = function (service) { return $http.get(apiServiceUrl, service); };
});
"""

_NEXXT_STATUS_SERVICE_JS = """'use strict';
app.service('statusService', function (api) {
    this.startPing = function (data) {
        return api.set('pingstatus', data);
    };
    this.pingInfo = function () {
        return api.get('pingstatusinfo');
    };
});
"""

NEXXT_PROFILE = DeviceProfile(
    name="nexxt",
    firmware=DEFAULT_FIRMWARE,
    board="GDNT-S",
    model="FGA221D",
    product="NeXXt",
    asset_stamp=ASSET_STAMP,
    login_html=_NEXXT_LOGIN_HTML,
    app_js=_NEXXT_APP_JS,
    shared_services_js=_NEXXT_SHARED_SERVICES_JS,
    status_service_js=_NEXXT_STATUS_SERVICE_JS,
    default_services={
        "wanstatusinfo": {"WanConnectionStatus": "Connected"},
        "wwanstatusinfo": {},
        "lan_status": {"LanUp": "1"},
        "laninfo": {"IPAddress": "192.168.1.254"},
        "lanipv6details": {},
        "firewall_conf": {"level": "medium"},
        "dmz_conf": {},
        "virtual_server_list": {},
        "upnp_conf": {},
    },
)

# Generic Homeware profile: same web API shape, different board/firmware.
# Used to exercise the driver-dispatch path without a real second device.
_GENERIC_HOMEWARE_ASSET_STAMP = "20260401000000"
_GENERIC_HOMEWARE_LOGIN_HTML = f"""<!doctype html>
<html><head><title>Homeware Gateway</title>
<script src="/app/app.js?v={_GENERIC_HOMEWARE_ASSET_STAMP}"></script>
<script src="/app/services/sharedServices.js?v={_GENERIC_HOMEWARE_ASSET_STAMP}"></script>
<script src="/app/services/statusService.js?v={_GENERIC_HOMEWARE_ASSET_STAMP}"></script>
</head><body><div ng-app="homeware"></div></body></html>
"""

_GENERIC_HOMEWARE_APP_JS = """'use strict';
var app = angular.module('homeware', []);
app.factory('validators', function () {
    const ipv6 = /([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/gi.test(value);
    return {ipv6: ipv6};
});
"""

GENERIC_HOMEWARE_PROFILE = DeviceProfile(
    name="generic_homeware",
    firmware="22.2.0378_FW_058_VCNTI",
    board="VCNT-I",
    model="VBNT-6",
    product="Vodafone",
    asset_stamp=_GENERIC_HOMEWARE_ASSET_STAMP,
    login_html=_GENERIC_HOMEWARE_LOGIN_HTML,
    app_js=_GENERIC_HOMEWARE_APP_JS,
    shared_services_js=_NEXXT_SHARED_SERVICES_JS,
    status_service_js=_NEXXT_STATUS_SERVICE_JS,
    default_services={
        "wanstatusinfo": {"WanConnectionStatus": "Connected"},
        "wwanstatusinfo": {},
        "lan_status": {"LanUp": "1"},
        "laninfo": {"IPAddress": "192.168.1.254"},
        "lanipv6details": {},
        "firewall_conf": {"level": "medium"},
        "dmz_conf": {},
        "virtual_server_list": {},
        "upnp_conf": {},
    },
)

# Backwards-compatible module-level defaults.
STATIC_ASSETS = NEXXT_PROFILE.static_assets
DEFAULT_SERVICES = NEXXT_PROFILE.default_services


class ShellError(Exception):
    pass


class VirtualShell:
    """Restricted shell subset over an in-memory filesystem.

    Supports exactly the commands the toolkit injects: sleep, test/[,
    grep (-q/-F/-x/-v), echo/printf, tee, cat, rm, md5/md5sum, base64 -d,
    mkdir, touch, true/false — plus pipes, && / || / ; chaining and
    > / >> redirection. Files are ``path -> bytes``.
    """

    def __init__(self, time_scale: float = 1.0) -> None:
        self.fs: dict[str, bytes] = {}
        self.dirs: set[str] = {"/", "/tmp", "/etc"}
        self.time_scale = time_scale
        self.lock = threading.RLock()

    # ---- parsing helpers ----

    @staticmethod
    def _split_top(text: str, seps: tuple[str, ...]) -> list[tuple[str, str]]:
        """Split on shell operators outside quotes; returns (op, segment)."""
        out: list[tuple[str, str]] = []
        buf: list[str] = []
        quote = None
        i = 0
        op = ""
        while i < len(text):
            ch = text[i]
            if quote:
                buf.append(ch)
                if ch == quote:
                    quote = None
                i += 1
                continue
            if ch in "'\"":
                quote = ch
                buf.append(ch)
                i += 1
                continue
            hit = next((s for s in seps if text.startswith(s, i)), None)
            if hit:
                out.append((op, "".join(buf)))
                buf = []
                op = hit
                i += len(hit)
            else:
                buf.append(ch)
                i += 1
        out.append((op, "".join(buf)))
        return out

    def _glob(self, pattern: str) -> list[str]:
        with self.lock:
            if not any(c in pattern for c in "*?["):
                return [pattern] if pattern in self.fs else []
            return sorted(p for p in self.fs if fnmatch.fnmatch(p, pattern))

    # ---- entry point ----

    def run(self, command: str) -> int:
        command = command.replace("${IFS}", " ")
        status = 0
        for op, segment in self._split_top(command, ("&&", "||", ";")):
            segment = segment.strip()
            if not segment:
                continue
            if op == "&&" and status != 0:
                continue
            if op == "||" and status == 0:
                continue
            status = self._pipeline(segment)
        return status

    def _pipeline(self, segment: str) -> int:
        # top-level redirection applies to the whole pipeline's stdout
        redirect = None  # (mode, path)
        for redir in (">>", ">"):
            parts = self._split_top(segment, (redir,))
            if len(parts) > 1:
                segment = parts[0][1]
                target = parts[-1][1].strip()
                redirect = (redir, shlex.split(target)[0] if target else "")
                break
        stages = [s for _, s in self._split_top(segment, ("|",))]
        data = b""
        status = 0
        for stage in stages:
            try:
                argv = shlex.split(stage)
            except ValueError:
                return 127
            if not argv:
                continue
            status, data = self._exec(argv, data)
        if redirect:
            mode, path = redirect
            if not path:
                return 1
            with self.lock:
                if mode == ">>":
                    self.fs[path] = self.fs.get(path, b"") + data
                else:
                    self.fs[path] = data
            self._parent_dirs(path)
        return status

    # ---- builtins ----

    def _exec(self, argv: list[str], stdin: bytes) -> tuple[int, bytes]:
        name = argv[0]
        args = argv[1:]
        try:
            handler = getattr(self, "_cmd_" + name.replace("-", "_"))
        except AttributeError:
            if name == "[":
                return self._cmd_test(args[:-1] if args and args[-1] == "]" else args, stdin)
            return 127, b""
        try:
            return handler(args, stdin)
        except ShellError:
            return 1, b""
        except (ValueError, OSError):
            return 1, b""

    def _read(self, path: str) -> bytes:
        with self.lock:
            if path not in self.fs:
                raise ShellError(path)
            return self.fs[path]

    def _parent_dirs(self, path: str) -> None:
        parts = path.strip("/").split("/")[:-1]
        cur = ""
        for part in parts:
            cur += "/" + part
            self.dirs.add(cur)

    def _write(self, path: str, data: bytes, append: bool = False) -> None:
        with self.lock:
            if append:
                self.fs[path] = self.fs.get(path, b"") + data
            else:
                self.fs[path] = data
            self._parent_dirs(path)

    def _cmd_sleep(self, args, stdin):
        seconds = float(args[0]) if args else 0.0
        time.sleep(max(0.0, seconds) * self.time_scale)
        return 0, b""

    def _cmd_true(self, args, stdin):
        return 0, b""

    def _cmd_false(self, args, stdin):
        return 1, b""

    def _cmd_test(self, args, stdin):
        negate = False
        while args and args[0] == "!":
            negate = not negate
            args = args[1:]
        if len(args) == 2:
            flag, path = args
            with self.lock:
                if flag == "-f":
                    ok = path in self.fs
                elif flag == "-e":
                    ok = path in self.fs or path in self.dirs
                elif flag == "-d":
                    ok = path in self.dirs
                elif flag == "-s":
                    ok = bool(self.fs.get(path))
                else:
                    raise ShellError(flag)
            return (1 if ok == negate else 0), b""
        if len(args) == 1:
            ok = bool(args[0])
            return (1 if ok == negate else 0), b""
        raise ShellError("test")

    def _cmd_touch(self, args, stdin):
        for path in args:
            if not path.startswith("-"):
                with self.lock:
                    self.fs.setdefault(path, b"")
                self._parent_dirs(path)
        return 0, b""

    def _cmd_mkdir(self, args, stdin):
        for path in args:
            if not path.startswith("-"):
                with self.lock:
                    self.dirs.add(path.rstrip("/"))
                    self._parent_dirs(path.rstrip("/") + "/x")
        return 0, b""

    def _cmd_rm(self, args, stdin):
        paths = [a for a in args if not a.startswith("-")]
        force = any(a.startswith("-") and "f" in a for a in args)
        status = 0
        with self.lock:
            for pattern in paths:
                matches = [p for p in list(self.fs)
                           if fnmatch.fnmatch(p, pattern)] or \
                          ([pattern] if pattern in self.fs else [])
                if not matches and not force:
                    status = 1
                for path in matches:
                    self.fs.pop(path, None)
        return status, b""

    def _cmd_cat(self, args, stdin):
        paths = [a for a in args if not a.startswith("-")]
        if not paths:
            return 0, stdin
        out = b""
        status = 0
        for pattern in paths:
            matches = self._glob(pattern)
            if not matches:
                status = 1
            for path in matches:
                out += self._read(path)
        return status, out

    def _cmd_tee(self, args, stdin):
        append = False
        paths = []
        for arg in args:
            if arg == "-a":
                append = True
            elif not arg.startswith("-"):
                paths.append(arg)
        for path in paths:
            self._write(path, stdin, append)
        return 0, stdin

    def _cmd_echo(self, args, stdin):
        newline = True
        if args and args[0] == "-n":
            newline = False
            args = args[1:]
        out = " ".join(args).encode() + (b"\n" if newline else b"")
        return 0, out

    def _cmd_printf(self, args, stdin):
        if not args:
            return 0, b""
        fmt, values = args[0], args[1:]
        out = ""
        used = 0
        i = 0
        while i < len(fmt):
            if fmt[i] == "%" and i + 1 < len(fmt) and fmt[i + 1] == "s":
                out += values[used] if used < len(values) else ""
                used += 1
                i += 2
            elif fmt[i] == "%" and i + 1 < len(fmt) and fmt[i + 1] == "%":
                out += "%"
                i += 2
            else:
                out += fmt[i]
                i += 1
        out += "".join(values[used:])
        return 0, out.encode()

    def _cmd_tr(self, args, stdin):
        if len(args) < 2:
            raise ShellError("tr")
        table = bytes.maketrans(args[0].encode(), args[1].encode())
        return 0, stdin.translate(table)

    def _cmd_base64(self, args, stdin):
        if "-d" in args:
            try:
                return 0, base64.b64decode(stdin, validate=False)
            except Exception:
                return 1, b""
        return 0, base64.b64encode(stdin)

    def _cmd_md5sum(self, args, stdin):
        paths = [a for a in args if not a.startswith("-")]
        out = ""
        status = 0
        for path in paths:
            try:
                digest = hashlib.md5(self._read(path)).hexdigest()
            except ShellError:
                status = 1
                continue
            out += f"{digest}  {path}\n"
        return status, out.encode()

    def _cmd_md5(self, args, stdin):
        paths = [a for a in args if not a.startswith("-")]
        out = ""
        status = 0
        for path in paths:
            try:
                digest = hashlib.md5(self._read(path)).hexdigest()
            except ShellError:
                status = 1
                continue
            out += f"MD5 ({path}) = {digest}\n"
        return status, out.encode()

    def _cmd_grep(self, args, stdin):
        quiet = fixed = whole_line = invert = False
        rest = list(args)
        while rest and rest[0].startswith("-") and rest[0] != "-":
            flags = rest.pop(0)[1:]
            quiet = quiet or "q" in flags
            fixed = fixed or "F" in flags
            whole_line = whole_line or "x" in flags
            invert = invert or "v" in flags
        if not rest:
            raise ShellError("grep")
        pattern, paths = rest[0], rest[1:]
        data = b""
        if paths:
            for path in paths:
                data += self._read(path)
        else:
            data = stdin
        text = data.decode("latin-1")

        def matched(line: str) -> bool:
            if fixed:
                hit = line == pattern if whole_line else pattern in line
            else:
                try:
                    rx = re.compile(pattern)
                except re.error:
                    rx = re.compile(re.escape(pattern))
                hit = bool(rx.fullmatch(line) if whole_line else rx.search(line))
            return hit != invert

        hits = [line for line in text.split("\n") if matched(line)]
        if quiet:
            return (0 if hits else 1), b""
        out = ("\n".join(hits) + "\n").encode() if hits else b""
        return (0 if hits else 1), out


class FakeGateway:
    """Threaded in-process fake of the NeXXt One web stack."""

    def __init__(self, board: str | None = None, model: str | None = None,
                 product: str | None = None, fw_version: str | None = None,
                 session_ttl: float = 300.0, time_scale: float = 1.0,
                 auto_press_delay: float | None = None,
                 profile: DeviceProfile | None = None) -> None:
        self.profile = profile or NEXXT_PROFILE
        self.board = board or self.profile.board
        self.model = model or self.profile.model
        self.product = product or self.profile.product
        self.fw_version = fw_version or self.profile.firmware
        self.session_ttl = session_ttl
        self.auto_press_delay = auto_press_delay
        self.shell = VirtualShell(time_scale=time_scale)
        self._lock = threading.RLock()
        self._diag_lock = threading.Lock()
        self._sessions: dict[str, dict] = {}
        self._latest_sid: str | None = None
        self._armed = False
        self._button_pressed = False
        self._diag_state = "None"
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ---- lifecycle ----

    def start(self) -> None:
        gateway = self

        class Handler(_GatewayHandler):
            fake = gateway

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.05},
            daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def base_url(self) -> str:
        if not self._server:
            raise RuntimeError("gateway not started")
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    # ---- test hooks ----

    @property
    def virtual_fs(self) -> dict[str, bytes]:
        with self.shell.lock:
            return dict(self.shell.fs)

    def read_file(self, path: str) -> bytes:
        return self.shell.fs[path]

    def press_buttons(self) -> None:
        """Simulate the physical both-buttons-for-3s press."""
        with self._lock:
            if self._armed:
                self._button_pressed = True

    # ---- session handling ----

    def _new_session(self) -> str:
        sid = secrets.token_hex(16)
        with self._lock:
            self._sessions[sid] = {"authenticated": False, "auth_time": 0.0}
            self._latest_sid = sid
        return sid

    def _session(self, sid: str | None) -> dict | None:
        with self._lock:
            return self._sessions.get(sid or "")

    def _authenticated(self, sid: str | None) -> bool:
        session = self._session(sid)
        if not session or not session["authenticated"]:
            return False
        if time.time() - session["auth_time"] > self.session_ttl:
            with self._lock:
                session["authenticated"] = False
            return False
        return True

    def _arm_button_wait(self) -> None:
        with self._lock:
            self._armed = True
            self._button_pressed = False
        if self.auto_press_delay is not None:
            timer = threading.Timer(self.auto_press_delay, self.press_buttons)
            timer.daemon = True
            timer.start()

    def _confirm_login(self) -> None:
        """Confirm step: authenticates the most recently created session."""
        with self._lock:
            if not self._button_pressed or not self._latest_sid:
                return
            session = self._sessions[self._latest_sid]
            session["authenticated"] = True
            session["auth_time"] = time.time()
            self._armed = False
            self._button_pressed = False

    # ---- ping diagnostic / injection ----

    def _start_diagnostic(self, host: str) -> None:
        with self._lock:
            self._diag_state = "Requested"

        def work() -> None:
            with self._diag_lock:  # one diagnostic at a time, like the UI
                with self._lock:
                    self._diag_state = "InProgress"
                status = 0
                prefix = self.profile.injection_prefix
                if prefix in host:
                    command = host.split(prefix, 1)[1]
                    status = self.shell.run(command)
                elif ";" in host:
                    # Fallback for tests that bypass the configured prefix.
                    command = host.split(";", 1)[1]
                    status = self.shell.run(command)
                else:
                    # a real ping round-trip takes a moment even on loopback
                    time.sleep(0.02)
                with self._lock:
                    self._diag_state = "Complete" if status == 0 else "Error"

        threading.Thread(target=work, daemon=True).start()

    # ---- status.cgi dispatch ----

    def handle_status_cgi(self, params: dict[str, str],
                          sid: str | None) -> tuple[int, dict]:
        if "nvget" in params:
            return self._handle_nvget(params["nvget"], params, sid)
        if params.get("act") == "nvset":
            return self._handle_nvset(params, sid)
        return 400, {"error": "bad request"}

    def _handle_nvget(self, service: str, params: dict[str, str],
                      sid: str | None) -> tuple[int, dict]:
        if service == "login_confirm":
            cmd = params.get("cmd", "")
            if cmd == "4":
                state = "1" if self._authenticated(sid) else "0"
                return 200, {"login_confirm": {"login_status": state}}
            if cmd == "7":
                with self._lock:
                    path = "1" if self._button_pressed else "0"
                return 200, {"login_confirm": {"loginPath": path}}
            return 200, {"login_confirm": {}}
        # Verified on real FW_058 hardware: every other nvget readout is
        # gated behind an authenticated session (nginx 403 otherwise), even
        # when the caller holds a fresh but unauthenticated session cookie.
        if not self._authenticated(sid):
            return 403, {"error": "session required"}
        if service == "pingstatusinfo":
            with self._lock:
                state = self._diag_state
            return 200, {"pingstatusinfo": {
                "DiagnosticsState": state, "Status": "",
                "NumberOfRepetitions": "3"}}
        if service == "sysinfo":
            return 200, {"sysinfo": {
                "model": self.model,
                "product_name": self.product,
                "board": self.board,
                "hw_version": self.board,
                "fw_version": self.fw_version,
                "uptime": "3600"}}
        data = self.profile.default_services.get(service)
        if data is not None:
            return 200, {service: dict(data)}
        return 200, {}

    def _handle_nvset(self, params: dict[str, str],
                      sid: str | None) -> tuple[int, dict]:
        service = params.get("service", "")
        if service == "login_confirm" and params.get("cmd") == "7":
            # the login handshake itself is obviously reachable pre-auth
            if params.get("loginPath") == "2":
                self._arm_button_wait()
            elif params.get("loginPath") == "1":
                self._confirm_login()
            return 200, {"login_confirm": {"result": "success"}}
        if not self._authenticated(sid):
            return 403, {"error": "session required"}
        if service == "pingstatus":
            host = params.get("host", "")
            self._start_diagnostic(host)
            return 200, {"pingstatus": {"result": "success"}}
        return 200, {service: {"result": "success"}}


class _GatewayHandler(BaseHTTPRequestHandler):
    fake: FakeGateway
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:  # keep test output quiet
        pass

    def _session_cookie(self) -> str | None:
        header = self.headers.get("Cookie", "")
        for part in header.split(";"):
            part = part.strip()
            if part.startswith("sessionID="):
                return part.split("=", 1)[1]
        return None

    def _send(self, status: int, body: bytes, content_type: str,
              extra_headers: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = {k: v[0] for k, v in urllib.parse.parse_qs(
            parsed.query, keep_blank_values=True).items()}

        if path == "/login":
            sid = self.fake._new_session()
            self._send(200, self.fake.profile.login_html.encode(), "text/html",
                       {"Set-Cookie": f"sessionID={sid}; Path=/"})
            return
        assets = self.fake.profile.static_assets
        if path in assets:
            content_type, body = assets[path]
            self._send(200, body.encode(), content_type,
                       {"Last-Modified": "Wed, 15 May 2026 08:20:10 GMT"})
            return
        if path == "/status.cgi":
            status, payload = self.fake.handle_status_cgi(
                params, self._session_cookie())
            self._send_json(status, payload)
            return
        if path in ("/", "/index.html"):
            self._send(302, b"", "text/plain", {"Location": "/login"})
            return
        self._send(404, b"not found", "text/plain")
