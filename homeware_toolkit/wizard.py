"""Local web setup wizard for homeware-toolkit.

Running ``homeware setup --wizard`` starts a small HTTP server on ``127.0.0.1``
that guides the user through probe → button login → injection verification →
SSH bootstrap with a browser UI.  The wizard never talks to the internet; all
state stays on the user's machine.

This is intentionally a minimal prototype: it reuses the existing CLI modules
and streams results back as JSON.  A future iteration can add real-time
progress events and richer visual feedback.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import __version__
from .client import GatewayClient
from .driver import detect_from_sysinfo

WIZARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>homeware setup wizard</title>
<style>
  :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
  body { max-width: 720px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
  h1 { font-size: 1.5rem; }
  .step { display: none; border: 1px solid #888; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
  .step.active { display: block; }
  button { padding: 0.5rem 1rem; margin: 0.5rem 0.25rem 0 0; cursor: pointer; }
  pre { background: #222; color: #eee; padding: 1rem; border-radius: 6px; overflow-x: auto; }
  .ok { color: #2e7d32; }
  .warn { color: #f57c00; }
  .err { color: #c62828; }
  .muted { color: #888; }
</style>
</head>
<body>
<h1>homeware setup wizard <span class="muted">v{version}</span></h1>

<div id="step-welcome" class="step active">
  <p>This wizard helps you set up persistent, key-only SSH on your own
     Technicolor/Vantiva Homeware gateway.</p>
  <ul>
    <li>Only run this on a gateway you own.</li>
    <li>You will need to press both side buttons on the router when asked.</li>
    <li>All keys are generated on this computer; nothing is sent to the cloud.</li>
  </ul>
  <button onclick="next('probe')">Start</button>
</div>

<div id="step-probe" class="step">
  <h2>1. Compatibility probe</h2>
  <p>Checking whether your gateway looks like a supported device...</p>
  <pre id="probe-out">...</pre>
  <div id="probe-actions"></div>
</div>

<div id="step-login" class="step">
  <h2>2. Button login</h2>
  <p>Press <strong>both side buttons</strong> on the router for about 3 seconds,
     then click <strong>Login</strong>.</p>
  <button id="login-btn" onclick="startLogin()">Login</button>
  <pre id="login-out">...</pre>
  <div id="login-actions"></div>
</div>

<div id="step-verify" class="step">
  <h2>3. Verify injection channel</h2>
  <p>A harmless, non-persistent probe confirms the diagnostic command channel.</p>
  <button onclick="doVerify()">Run verification</button>
  <pre id="verify-out">...</pre>
  <div id="verify-actions"></div>
</div>

<div id="step-setup" class="step">
  <h2>4. Deploy persistent SSH</h2>
  <p>This generates an RSA key locally and installs a LAN-only, key-only SSH
     service on the gateway.  You can remove it later with
     <code>homeware ssh teardown</code>.</p>
  <button onclick="doSetup()">Deploy SSH</button>
  <pre id="setup-out">...</pre>
  <div id="setup-actions"></div>
</div>

<div id="step-done" class="step">
  <h2>Done</h2>
  <p>Your gateway is ready.  Connect with:</p>
  <pre id="done-cmd"></pre>
  <p>Run <code>homeware doctor --key ~/.homeware-toolkit/id_rsa</code> any time
     to check health.</p>
</div>

<script>
const $ = id => document.getElementById(id);
function show(id) { document.querySelectorAll('.step').forEach(s => s.classList.remove('active')); $(id).classList.add('active'); }
function next(id) { show('step-' + id); if (id === 'probe') doProbe(); }
function setOut(id, text) { $(id).textContent = text; }
function btn(id, enabled) { $(id).disabled = !enabled; }

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(r.status + ' ' + await r.text());
  return r.json();
}

async function doProbe() {
  setOut('probe-out', 'running...');
  btn('login-btn', false);
  try {
    const data = await api('/api/probe');
    setOut('probe-out', JSON.stringify(data, null, 2));
    const ok = data.analysis && data.analysis.compatibility_signal === 'strong-front-end-match';
    $('probe-actions').innerHTML = ok
      ? '<p class="ok">Gateway looks compatible.</p><button onclick="next(\'login\')">Continue</button>'
      : '<p class="warn">Compatibility signal is not a strong match. You can still try, but please consider filing a compatibility report.</p><button onclick="next(\'login\')">Continue anyway</button>';
    btn('login-btn', true);
  } catch (e) {
    setOut('probe-out', 'Error: ' + e.message);
  }
}

async function startLogin() {
  btn('login-btn', false);
  setOut('login-out', 'waiting for button press (60s)...');
  try {
    const data = await api('/api/session/login', {method: 'POST'});
    setOut('login-out', JSON.stringify(data, null, 2));
    if (data.authenticated) {
      $('login-actions').innerHTML = '<p class="ok">Authenticated.</p><button onclick="next(\'verify\')">Continue</button>';
    } else {
      $('login-actions').innerHTML = '<p class="err">Timed out. Make sure you pressed both buttons and no browser tab was open on the router page.</p><button onclick="startLogin()">Retry</button>';
      btn('login-btn', true);
    }
  } catch (e) {
    setOut('login-out', 'Error: ' + e.message);
    btn('login-btn', true);
  }
}

async function doVerify() {
  setOut('verify-out', 'running...');
  try {
    const data = await api('/api/verify', {method: 'POST'});
    setOut('verify-out', JSON.stringify(data, null, 2));
    if (data.backend_command_execution) {
      $('verify-actions').innerHTML = '<p class="ok">Injection channel confirmed.</p><button onclick="next(\'setup\')">Continue</button>';
    } else {
      $('verify-actions').innerHTML = '<p class="err">Injection channel not confirmed. SSH deployment will not work on this firmware.</p>';
    }
  } catch (e) {
    setOut('verify-out', 'Error: ' + e.message);
  }
}

async function doSetup() {
  setOut('setup-out', 'running (this takes a few minutes)...');
  try {
    const data = await api('/api/setup', {method: 'POST'});
    setOut('setup-out', JSON.stringify(data, null, 2));
    if (data.code === 0) {
      $('setup-actions').innerHTML = '<p class="ok">SSH deployed.</p><button onclick="finish()">Finish</button>';
    } else {
      $('setup-actions').innerHTML = '<p class="err">Setup failed. See output above.</p>';
    }
  } catch (e) {
    setOut('setup-out', 'Error: ' + e.message);
  }
}

function finish() {
  show('step-done');
  $('done-cmd').textContent = 'ssh -i ~/.homeware-toolkit/id_rsa -p 2222 ' +
    '-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa ' +
    'root@{gateway_host}';
}
</script>
</body>
</html>
"""


class WizardState:
    """Shared state for the local wizard HTTP server."""

    def __init__(self, base_url: str, tls_fingerprint: str | None = None,
                 key_path: str = "~/.homeware-toolkit/id_rsa",
                 port: int = 2222) -> None:
        self.base_url = base_url
        self.tls_fingerprint = tls_fingerprint
        self.key_path = os.path.expanduser(key_path)
        self.port = port
        self.client: GatewayClient | None = None
        self._lock = threading.Lock()

    def get_client(self) -> GatewayClient:
        with self._lock:
            if self.client is None:
                self.client = GatewayClient(
                    self.base_url, tls_fingerprint=self.tls_fingerprint)
            return self.client

    def detect_device(self):
        client = self.get_client()
        status, data = client.get("sysinfo")
        info = data.get("sysinfo", {}) if status == 200 else {}
        return detect_from_sysinfo(info)


def _json_response(handler, data: dict, status: int = 200) -> None:
    body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _text_response(handler, text: str, status: int = 200,
                   content_type: str = "text/plain") -> None:
    body = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json_body(handler) -> dict:
    length = int(handler.headers.get("Content-Length", "0"))
    if length <= 0:
        return {}
    raw = handler.rfile.read(length).decode("utf-8")
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {}


def make_handler(state: WizardState):
    """Return a RequestHandler class bound to ``state``."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            # Suppress default access logging noise.
            pass

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            if path == "/" or path == "/index.html":
                html = (WIZARD_HTML
                        .replace("{version}", __version__)
                        .replace("{gateway_host}",
                                 urllib.parse.urlparse(state.base_url).hostname
                                 or "192.168.1.254"))
                _text_response(self, html, content_type="text/html")
                return

            if path == "/api/probe":
                from . import probe
                result = probe.run_probe(state.base_url)
                _json_response(self, result)
                return

            self.send_error(404)

        def do_POST(self):
            path = urllib.parse.urlparse(self.path).path

            if path == "/api/session/login":
                client = state.get_client()
                ok = client.button_login(60, log=lambda _m: None)
                _json_response(self, {"authenticated": ok})
                return

            if path == "/api/verify":
                from .inject import Injector
                from . import verify as verify_mod
                client = state.get_client()
                inj = Injector(client, log=lambda _m: None)
                report = verify_mod.verify(inj, log=lambda _m: None)
                _json_response(self, report)
                return

            if path == "/api/setup":
                from .setup import run_setup
                from .ssh import make_runner
                # The wizard UI itself is the explicit consent, so run_setup
                # must not block on a terminal prompt.  Failures are reported
                # in the JSON payload (code != 0) so the browser can render
                # them gracefully.
                try:
                    result, code = run_setup(
                        state.base_url, state.port, state.key_path,
                        assume_yes=True, force=False, adopt_legacy=False,
                        log=lambda _m: None,
                        runner=make_runner(state.base_url, state.port,
                                           state.key_path,
                                           log=lambda _m: None))
                    _json_response(self, {"result": result, "code": code})
                except Exception as exc:
                    _json_response(self, {"result": str(exc), "code": 1})
                return

            self.send_error(404)

    return Handler


def run_wizard(base_url: str, port: int = 2222,
               key: str = "~/.homeware-toolkit/id_rsa",
               tls_fingerprint: str | None = None,
               bind: str = "127.0.0.1", listen_port: int = 0) -> int:
    """Start the local setup wizard and block until the user stops it.

    ``listen_port`` 0 means an ephemeral port.  Returns only on KeyboardInterrupt.
    """
    state = WizardState(base_url, tls_fingerprint=tls_fingerprint,
                        key_path=key, port=port)
    server = HTTPServer((bind, listen_port), make_handler(state))
    url = f"http://{bind}:{server.server_address[1]}"
    print(f"[wizard] serving on {url}")
    print(f"[wizard] open {url} in your browser and follow the steps.")
    print("[wizard] press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
