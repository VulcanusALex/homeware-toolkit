"""In-process fake NeXXt One gateway for hardware-free integration tests.

Simulates the stock web stack closely enough for the toolkit clients:
  * the four static front-end assets probed by probe.py;
  * ``status.cgi?nvget=<service>`` JSON readouts;
  * the physical-button login handshake (login_confirm cmd=7) issuing a
    ``sessionID`` cookie, with configurable session TTL;
  * the ping diagnostic endpoint, including the host-field command
    injection channel: injected commands are interpreted by a tiny
    restricted shell operating on an in-memory virtual filesystem, so the
    full transfer pipeline (chunk / verify / assemble / md5) really runs;
  * a loopback-only ``POST /__sim__/exec`` endpoint that executes commands in
    the virtual shell — this backs the toolkit's simulated-SSH transport
    (see ``ssh.SimRunner``), so the SSH-data-plane features (firewall,
    apply/diff, doctor --key, ...) run hardware-free as well.

Only used by tests and local demos; never talks to a real network by itself
(binds to 127.0.0.1 on an ephemeral port).

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
import copy
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
    # "button" (NeXXt-style physical press) or "srp6" (Vodafone-style
    # password SRP-6 against /authenticate with a CSRF token).
    auth_method: str = "button"
    srp6_username: str = "vodafone"
    srp6_password: str = "vodafone"

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
    auth_method="srp6",
)

# Backwards-compatible module-level defaults.
STATIC_ASSETS = NEXXT_PROFILE.static_assets
DEFAULT_SERVICES = NEXXT_PROFILE.default_services


class ShellError(Exception):
    pass


class NetState:
    """Mutable network/service state the virtual shell observes.

    ``listening`` holds the TCP ports currently bound by virtual services
    (only dropbear instances managed via uci + init.d ever appear here).
    Interface readouts (``ip addr``, ``ifstatus``) come from a fixed profile
    seeded at construction; they intentionally describe a CGNAT/private WAN
    so doctor/wanwatch report the realistic "private-RFC1918" outcome.
    """

    def __init__(self) -> None:
        self.listening: set[int] = set()


class VirtualShell:
    """Restricted shell subset over an in-memory filesystem.

    Supports the commands the toolkit injects or runs over (simulated) SSH:
    sleep, test/[, grep (-q/-F/-x/-v/-E/-f), sed (s///, -i), cut, echo/printf,
    tee, cat, cp, mv, rm, chmod, touch, mkdir, md5/md5sum, base64 -d, id,
    true/false, a uci subset (show/add/set/rename/delete/commit/revert/
    export/import) over a staged+committed config model, netstat -tln,
    /etc/init.d/<svc> restart, iptables-save/ip6tables-save -c (synthesized
    from the committed firewall config), ifstatus and ip addr — plus pipes,
    && / || / ; chaining, > / >> / < redirection and 2>/dev/null, 2>&1.
    Files are ``path -> bytes``.
    """

    def __init__(self, time_scale: float = 1.0, net: NetState | None = None) -> None:
        self.fs: dict[str, bytes] = {
            "/etc/passwd": (b"root:!:0:0:root:/root:/bin/restricted_shell\n"
                            b"daemon:*:1:1:daemon:/var:/bin/false\n"
                            b"nobody:*:99:99:nobody:/var:/bin/false\n"),
        }
        self.dirs: set[str] = {"/", "/tmp", "/etc", "/etc/config",
                               "/etc/dropbear", "/root"}
        self.time_scale = time_scale
        self.lock = threading.RLock()
        self.net = net or NetState()
        # uci config model: cfg -> {"committed": [sections], "staged": [...]}
        # section: {"name": str|None, "type": str, "options": {str: str}}
        stock_dropbear = [{"name": None, "type": "dropbear", "options": {
            "enable": "0", "Port": "22", "PasswordAuth": "on"}}]
        stock_firewall = [
            {"name": None, "type": "defaults",
             "options": {"syn_flood": "1", "input": "ACCEPT",
                         "output": "ACCEPT", "forward": "REJECT"}},
            {"name": None, "type": "zone",
             "options": {"input": "ACCEPT", "output": "ACCEPT",
                         "forward": "ACCEPT"}},
            {"name": None, "type": "zone",
             "options": {"input": "REJECT", "output": "ACCEPT",
                         "forward": "REJECT", "masq": "1"}},
        ]
        self.uci: dict[str, dict] = {
            "dropbear": {"committed": copy.deepcopy(stock_dropbear),
                         "staged": copy.deepcopy(stock_dropbear)},
            "firewall": {"committed": copy.deepcopy(stock_firewall),
                         "staged": copy.deepcopy(stock_firewall)},
        }

    # ---- parsing helpers ----

    @staticmethod
    def _split_top(text: str, seps: tuple[str, ...]) -> list[tuple[str, str]]:
        """Split on shell operators outside quotes/parens; returns (op, segment)."""
        out: list[tuple[str, str]] = []
        buf: list[str] = []
        quote = None
        depth = 0
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
            if ch == "(":
                depth += 1
                buf.append(ch)
                i += 1
                continue
            if ch == ")":
                depth -= 1
                buf.append(ch)
                i += 1
                continue
            hit = depth == 0 and next(
                (s for s in seps if text.startswith(s, i)), None)
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
        return self.run_capture(command)[0]

    def run_capture(self, command: str) -> tuple[int, bytes]:
        command = command.replace("${IFS}", " ")
        status = 0
        output = b""
        for op, segment in self._split_top(command, ("&&", "||", ";")):
            segment = segment.strip()
            if not segment:
                continue
            if op == "&&" and status != 0:
                continue
            if op == "||" and status == 0:
                continue
            status, data = self._pipeline(segment)
            output += data
        return status, output

    def _pipeline(self, segment: str) -> tuple[int, bytes]:
        # strip one pair of balanced outer parentheses: ( a || b )
        if segment.startswith("(") and segment.endswith(")"):
            depth = 0
            balanced = True
            for i, ch in enumerate(segment):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0 and i != len(segment) - 1:
                        balanced = False
                        break
            if balanced and depth == 0:
                segment = segment[1:-1].strip()
        # stderr handling: 2>&1 merges into stdout (we fold it away),
        # 2>target discards stderr (we do not model stderr separately)
        segment = segment.replace("2>&1", " ")
        parts = self._split_top(segment, ("2>",))
        if len(parts) > 1:
            segment = parts[0][1]
        # stdin redirection: cmd < file
        stdin: bytes | None = None
        parts = self._split_top(segment, ("<",))
        if len(parts) > 1:
            segment = parts[0][1]
            src = parts[-1][1].strip()
            src = shlex.split(src)[0] if src else ""
            if src:
                stdin = self._read(src)
        # stdout redirection applies to the whole pipeline
        redirect = None  # (mode, path)
        for redir in (">>", ">"):
            parts = self._split_top(segment, (redir,))
            if len(parts) > 1:
                segment = parts[0][1]
                target = parts[-1][1].strip()
                redirect = (redir, shlex.split(target)[0] if target else "")
                break
        stages = [s for _, s in self._split_top(segment, ("|",))]
        data = b"" if stdin is None else stdin
        status = 0
        for i, stage in enumerate(stages):
            try:
                argv = shlex.split(stage)
            except ValueError:
                return 127, b""
            if not argv:
                continue
            status, data = self._exec(argv, data)
        if redirect:
            mode, path = redirect
            if not path:
                return 1, b""
            if path == "/dev/null":
                return status, b""
            with self.lock:
                if mode == ">>":
                    self.fs[path] = self.fs.get(path, b"") + data
                else:
                    self.fs[path] = data
            self._parent_dirs(path)
            return status, b""
        return status, data

    # ---- builtins ----

    def _exec(self, argv: list[str], stdin: bytes) -> tuple[int, bytes]:
        name = argv[0]
        args = argv[1:]
        if name.startswith("/etc/init.d/"):
            return self._cmd_initd(name.rsplit("/", 1)[-1], args)
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
        # POSIX printf interprets backslash escapes in the format string
        fmt = fmt.replace("\\n", "\n").replace("\\t", "\t").replace("\\\\", "\0")
        fmt = fmt.replace("\0", "\\")
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
        quiet = fixed = whole_line = invert = extended = False
        rest = list(args)
        pattern_file = None
        while rest and rest[0].startswith("-") and rest[0] != "-":
            if rest[0] == "-f":
                rest.pop(0)
                if not rest:
                    raise ShellError("grep -f")
                pattern_file = rest.pop(0)
                continue
            flags = rest.pop(0)[1:]
            if not flags:
                break
            quiet = quiet or "q" in flags
            fixed = fixed or "F" in flags
            whole_line = whole_line or "x" in flags
            invert = invert or "v" in flags
            extended = extended or "E" in flags
        if pattern_file is not None:
            patterns = [p for p in self._read(pattern_file)
                        .decode("latin-1").splitlines() if p != ""]
            if not patterns:
                return 1, b""
        else:
            if not rest:
                raise ShellError("grep")
            patterns = [rest.pop(0)]
        data = b""
        if rest:
            for path in rest:
                data += self._read(path)
        else:
            data = stdin
        text = data.decode("latin-1")
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()  # trailing newline is a terminator, not an empty line

        def matched(line: str) -> bool:
            for pattern in patterns:
                if fixed:
                    hit = line == pattern if whole_line else pattern in line
                else:
                    # translate the BRE \\( \\) groups the toolkit emits
                    pat = pattern if extended else pattern.replace(
                        "\\(", "(").replace("\\)", ")")
                    try:
                        rx = re.compile(pat)
                    except re.error:
                        rx = re.compile(re.escape(pat))
                    hit = bool(rx.fullmatch(line) if whole_line else rx.search(line))
                if hit:
                    return not invert
            return invert

        hits = [line for line in lines if matched(line)]
        if quiet:
            return (0 if hits else 1), b""
        out = ("\n".join(hits) + "\n").encode() if hits else b""
        return (0 if hits else 1), out
    # ---- file utilities added for the SSH-data-plane commands ----

    def _cmd_cp(self, args, stdin):
        paths = [a for a in args if not a.startswith("-")]
        if len(paths) != 2:
            raise ShellError("cp")
        self._write(paths[1], self._read(paths[0]))
        return 0, b""

    def _cmd_mv(self, args, stdin):
        paths = [a for a in args if not a.startswith("-")]
        if len(paths) != 2:
            raise ShellError("mv")
        self._write(paths[1], self._read(paths[0]))
        with self.lock:
            self.fs.pop(paths[0], None)
        return 0, b""

    def _cmd_chmod(self, args, stdin):
        # permissions are not modelled; accept if all target paths exist
        paths = [a for a in args if not a.startswith("-")
                 and not a[0].isdigit()]
        with self.lock:
            for path in paths:
                if path not in self.fs and path not in self.dirs:
                    return 1, b""
        return 0, b""

    def _cmd_cut(self, args, stdin):
        delim = "\t"
        fields = None
        i = 0
        while i < len(args):
            if args[i] == "-d" and i + 1 < len(args):
                delim = args[i + 1]
                i += 2
            elif args[i].startswith("-d"):
                delim = args[i][2:]
                i += 1
            elif args[i] == "-f" and i + 1 < len(args):
                fields = args[i + 1]
                i += 2
            elif args[i].startswith("-f"):
                fields = args[i][2:]
                i += 1
            else:
                i += 1
        if fields is None:
            raise ShellError("cut")
        wanted = {int(f) for f in fields.split(",")}
        out = []
        for line in stdin.decode("latin-1").split("\n"):
            if line == "":
                continue
            parts = line.split(delim)
            out.append(delim.join(p for n, p in enumerate(parts,  1)
                                  if n in wanted))
        return 0, ("\n".join(out) + "\n").encode() if out else b""

    def _cmd_id(self, args, stdin):
        return 0, b"uid=0(root) gid=0(root) groups=0(root)\n"

    def _cmd_sed(self, args, stdin):
        in_place = False
        script = None
        paths = []
        for arg in args:
            if arg == "-i":
                in_place = True
            elif arg == "-e":
                continue
            elif script is None and arg.startswith("s") and len(arg) > 2:
                script = arg
            elif script is not None and not arg.startswith("-"):
                paths.append(arg)
            elif arg.startswith("s") and len(arg) > 2:
                script = arg
            elif not arg.startswith("-"):
                paths.append(arg)
        if script is None:
            raise ShellError("sed")
        delim = script[1]
        parts = script[2:].split(delim)
        if len(parts) < 2:
            raise ShellError("sed script")
        pat, repl = parts[0], parts[1]
        # translate the BRE groups the toolkit emits: \( \) and \1 backrefs
        pat = pat.replace("\\(", "(").replace("\\)", ")")
        repl = re.sub(r"\\([0-9])", r"\\g<\1>", repl)
        try:
            rx = re.compile(pat, re.MULTILINE)
        except re.error:
            raise ShellError("sed pattern")
        data = b""
        if paths:
            for path in paths:
                data += self._read(path)
        else:
            data = stdin
        text = rx.sub(repl, data.decode("latin-1"))
        if in_place and paths:
            for path in paths:
                self._write(path, text.encode())
            return 0, b""
        return 0, text.encode()

    # ---- uci configuration model ----

    def _uci_sections(self, cfg: str, staged: bool = True) -> list[dict]:
        state = self.uci.setdefault(
            cfg, {"committed": [], "staged": []})
        return state["staged" if staged else "committed"]

    def _uci_resolve(self, sections: list[dict], ref: str) -> dict | None:
        m = re.fullmatch(r"@([A-Za-z0-9_-]+)\[(-?\d+)\]", ref)
        if m:
            stype, idx = m.group(1), int(m.group(2))
            matches = [s for s in sections if s["type"] == stype
                       and s["name"] is None]
            try:
                return matches[idx]
            except IndexError:
                return None
        for s in sections:
            if s["name"] == ref:
                return s
        return None

    def _uci_show_lines(self, cfg: str, sections: list[dict]) -> list[str]:
        lines = []
        anon_count: dict[str, int] = {}
        for s in sections:
            if s["name"] is not None:
                ref = s["name"]
            else:
                idx = anon_count.get(s["type"], 0)
                anon_count[s["type"]] = idx + 1
                ref = f"@{s['type']}[{idx}]"
            lines.append(f"{cfg}.{ref}={s['type']}")
            for key, val in s["options"].items():
                lines.append(f"{cfg}.{ref}.{key}='{val}'")
        return lines

    def _cmd_uci(self, args, stdin):
        quiet = False
        rest = list(args)
        while rest and rest[0].startswith("-"):
            flags = rest.pop(0)[1:]
            quiet = quiet or "q" in flags
        if not rest:
            raise ShellError("uci")
        cmd, rest = rest[0], rest[1:]

        if cmd == "show":
            # uci [-q] show cfg[.section[.option]]
            parts = rest[0].split(".")
            cfg = parts[0]
            sections = self._uci_sections(cfg)
            if len(parts) >= 2:
                sec = self._uci_resolve(sections, parts[1])
                if sec is None:
                    return 1, b""
                if len(parts) >= 3:
                    if parts[2] not in sec["options"]:
                        return 1, b""
                    val = sec["options"][parts[2]]
                    return 0, f"{cfg}.{parts[1]}.{parts[2]}='{val}'\n".encode()
                sections = [sec]
            if cfg not in self.uci:
                return 1, b""
            lines = self._uci_show_lines(cfg, sections)
            if not lines:
                return 1, b""
            return 0, ("\n".join(lines) + "\n").encode()

        if cmd == "add":
            cfg, stype = rest[0], rest[1]
            self._uci_sections(cfg).append(
                {"name": None, "type": stype, "options": {}})
            return 0, b""

        if cmd == "rename":
            target, _, new_name = rest[0].partition("=")
            cfg, _, ref = target.partition(".")
            sec = self._uci_resolve(self._uci_sections(cfg), ref)
            if sec is None or not new_name:
                return 1, b""
            sec["name"] = new_name
            return 0, b""

        if cmd == "set":
            target, _, value = rest[0].partition("=")
            parts = target.split(".")
            if len(parts) != 3:
                return 1, b""
            cfg, ref, opt = parts
            sec = self._uci_resolve(self._uci_sections(cfg), ref)
            if sec is None:
                return 1, b""
            sec["options"][opt] = value.strip("'")
            return 0, b""

        if cmd == "delete":
            parts = rest[0].split(".")
            cfg = parts[0]
            sections = self._uci_sections(cfg)
            if len(parts) == 2:
                sec = self._uci_resolve(sections, parts[1])
                if sec is None:
                    return 0 if quiet else 1, b""
                sections.remove(sec)
                return 0, b""
            if len(parts) == 3:
                sec = self._uci_resolve(sections, parts[1])
                if sec is None or parts[2] not in sec["options"]:
                    return 0 if quiet else 1, b""
                del sec["options"][parts[2]]
                return 0, b""
            return 1, b""

        if cmd == "commit":
            state = self.uci.get(rest[0])
            if state is None:
                return 1, b""
            state["committed"] = copy.deepcopy(state["staged"])
            return 0, b""

        if cmd == "revert":
            state = self.uci.get(rest[0])
            if state is None:
                return 0 if quiet else 1, b""
            state["staged"] = copy.deepcopy(state["committed"])
            return 0, b""

        if cmd == "export":
            cfg = rest[0]
            sections = self._uci_sections(cfg, staged=False)
            out = [f"package '{cfg}'", ""]
            for s in sections:
                name = f" '{s['name']}'" if s["name"] else ""
                out.append(f"config {s['type']}{name}")
                for key, val in s["options"].items():
                    out.append(f"\toption {key} '{val}'")
                out.append("")
            return 0, ("\n".join(out) + "\n").encode()

        if cmd == "import":
            cfg = rest[0]
            sections: list[dict] = []
            current = None
            for raw in stdin.decode("latin-1").splitlines():
                line = raw.strip()
                if line.startswith("config "):
                    tokens = shlex.split(line)
                    current = {"name": tokens[2] if len(tokens) > 2 else None,
                               "type": tokens[1], "options": {}}
                    sections.append(current)
                elif line.startswith("option ") and current is not None:
                    tokens = shlex.split(line)
                    current["options"][tokens[1]] = tokens[2]
            self.uci[cfg] = {"committed": copy.deepcopy(sections),
                             "staged": sections}
            return 0, b""

        return 1, b""

    # ---- network/service state commands ----

    def _cmd_initd(self, service: str, args):
        action = args[0] if args else "restart"
        if service == "dropbear" and action in ("start", "restart", "reload"):
            ports = set()
            for s in self._uci_sections("dropbear", staged=False):
                if s["type"] == "dropbear" and \
                        s["options"].get("enable", "1") == "1":
                    try:
                        ports.add(int(s["options"].get("Port", "22")))
                    except ValueError:
                        pass
            with self.lock:
                self.net.listening = ports
        elif service == "dropbear" and action == "stop":
            with self.lock:
                self.net.listening = set()
        return 0, b""

    def _cmd_netstat(self, args, stdin):
        out = []
        with self.lock:
            ports = sorted(self.net.listening)
        for port in ports:
            out.append(f"tcp        0      0 0.0.0.0:{port}"
                       "            0.0.0.0:*               LISTEN")
        return (0 if out else 1), ("\n".join(out) + "\n").encode() if out else b""

    def _iptables_dump(self, family: str) -> bytes:
        lines = ["*filter", ":zone_wan_forward - [0:0]"]
        for s in self._uci_sections("firewall", staged=False):
            if s["type"] != "rule":
                continue
            o = s["options"]
            if o.get("enabled", "1") == "0" or o.get("src") != "wan":
                continue
            fam = o.get("family", "any")
            if fam not in (family, "any"):
                continue
            name = o.get("name", "")
            protos = ("tcp", "udp") if o.get("proto") == "tcpudp" \
                else (o.get("proto", "all"),)
            for proto in protos:
                rule = f"[0:0] -A zone_wan_forward -p {proto}"
                if o.get("dest_ip"):
                    rule += f" -d {o['dest_ip']}"
                if o.get("dest_port"):
                    rule += f" --dport {o['dest_port']}"
                rule += (f" -m comment --comment \"!fw3: {name}\""
                         f" -j {o.get('target', 'ACCEPT')}")
                lines.append(rule)
        lines.append("COMMIT")
        return ("\n".join(lines) + "\n").encode()

    def _cmd_iptables_save(self, args, stdin):
        return 0, self._iptables_dump("ipv4")

    def _cmd_ip6tables_save(self, args, stdin):
        return 0, self._iptables_dump("ipv6")

    def _cmd_ip(self, args, stdin):
        # ip -4|-6 addr show dev IFACE
        family = args[0] if args else "-4"
        dev = args[-1] if args else ""
        if family == "-4":
            if dev == "veip0_1":
                return 0, (b"3: veip0_1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                           b"    inet 10.73.50.23 brd 10.73.255.255 scope global veip0_1\n"
                           b"       valid_lft forever preferred_lft forever\n")
            return 1, b""
        if family == "-6":
            if dev == "br-lan":
                return 0, (b"2: br-lan: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                           b"    inet6 2001:db8:100::1/64 scope global\n"
                           b"       valid_lft forever preferred_lft forever\n")
            return 1, b""
        return 1, b""

    def _cmd_ifstatus(self, args, stdin):
        iface = args[0] if args else ""
        if iface == "wan6":
            return 0, json.dumps({
                "up": True,
                "ipv6-prefix-assignment": [
                    {"address": "2001:db8:100::", "mask": 56}],
            }).encode() + b"\n"
        if iface == "6rd":
            return 0, b'{"up": false}\n'
        return 0, b'{"up": false}\n'


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
        # SRP-6 server state (only used when profile.auth_method == "srp6")
        from . import srp6 as _srp6
        self._srp6_salt, self._srp6_verifier = _srp6.make_verifier(
            self.profile.srp6_username.encode(),
            self.profile.srp6_password.encode())
        self._srp6_pending: dict[str, object] = {}  # csrf token -> Server
        self.session_ttl = session_ttl
        self.auto_press_delay = auto_press_delay
        self.net = NetState()
        self.shell = VirtualShell(time_scale=time_scale, net=self.net)
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

    def exec_local(self, command: str) -> tuple[int, str]:
        """Run a command in the virtual shell; backs the /__sim__/exec endpoint."""
        rc, out = self.shell.run_capture(command)
        return rc, out.decode("latin-1")

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

    # ---- SRP-6 password login (Vodafone-style /authenticate) ----

    def new_csrf_token(self) -> str:
        token = secrets.token_hex(16)
        with self._lock:
            self._srp6_pending[token] = None
        return token

    def handle_authenticate(self, params: dict[str, str],
                            sid: str | None) -> tuple[int, dict]:
        """Two-step SRP-6 handshake: {I, A} -> {s, B}; then {M} -> {M2}."""
        from . import srp6 as _srp6
        token = params.get("CSRFtoken", "")
        with self._lock:
            pending = self._srp6_pending
            if token not in pending:
                return 403, {"error": "bad CSRF token"}
            entry = pending[token]
        username = params.get("I")
        a_hex = params.get("A")
        m_hex = params.get("M")
        if username is not None and a_hex is not None:
            if username != self.profile.srp6_username:
                return 403, {"error": "unknown user"}
            server = _srp6.Server(username.encode(), self._srp6_salt,
                                  self._srp6_verifier)
            try:
                _, m2 = server.process(bytes.fromhex(a_hex))
            except (ValueError, KeyError):
                return 400, {"error": "bad ephemeral"}
            with self._lock:
                self._srp6_pending[token] = (server, m2)
            return 200, {"s": self._srp6_salt.hex(),
                         "B": server.public_ephemeral().hex()}
        if m_hex is not None and entry is not None:
            server, m2 = entry
            try:
                client_m = bytes.fromhex(m_hex)
            except ValueError:
                return 400, {"error": "bad proof"}
            if client_m != server.M1_expected:
                return 403, {"error": "400"}
            session = self._session(sid)
            if session is None:
                return 403, {"error": "no session"}
            with self._lock:
                session["authenticated"] = True
                session["auth_time"] = time.time()
            return 200, {"M": m2.hex()}
        return 400, {"error": "bad request"}

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
        self.send_header("X-Homeware-Simulator", self.fake.profile.name)
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/__sim__/exec":
            # Loopback-only escape hatch used by the toolkit's simulated-SSH
            # transport: execute a command in the virtual shell and return
            # its stdout. A real gateway never serves this path.
            length = int(self.headers.get("Content-Length", "0"))
            command = self.rfile.read(length).decode("utf-8")
            rc, out = self.fake.exec_local(command)
            self._send_json(200, {"rc": rc, "stdout": out})
            return
        if parsed.path == "/authenticate":
            # SRP-6 password login (Vodafone-style profiles)
            length = int(self.headers.get("Content-Length", "0"))
            form = urllib.parse.parse_qs(
                self.rfile.read(length).decode("utf-8"),
                keep_blank_values=True)
            params = {k: v[0] for k, v in form.items()}
            status, payload = self.fake.handle_authenticate(
                params, self._session_cookie())
            self._send_json(status, payload)
            return
        self._send(404, b"not found", "text/plain")

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = {k: v[0] for k, v in urllib.parse.parse_qs(
            parsed.query, keep_blank_values=True).items()}

        if path == "/login":
            sid = self.fake._new_session()
            html = self.fake.profile.login_html
            if self.fake.profile.auth_method == "srp6":
                token = self.fake.new_csrf_token()
                html = html.replace(
                    "</head>",
                    f'<meta name="CSRFtoken" content="{token}"></head>')
            self._send(200, html.encode(), "text/html",
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
