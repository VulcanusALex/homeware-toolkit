"""Non-persistent verification that the ping diagnostic executes commands."""

from __future__ import annotations

import random
import string

from .inject import run_ping

TIMING_THRESHOLD = 3.0


def verify(inj, sleep_seconds: int = 10, log=print) -> dict:
    """Timing probe + /tmp marker lifecycle. Nothing persistent is changed."""
    client = inj.client
    prefix = inj.payload_prefix
    I = inj.I
    base1, _ = run_ping(client, "127.0.0.1",
                        service=inj.injection_service,
                        reader=inj.injection_reader)
    base2, _ = run_ping(client, "127.0.0.1",
                        service=inj.injection_service,
                        reader=inj.injection_reader)
    baseline = max(base1, base2)
    log(f"[verify] baseline {baseline:.1f}s")

    marker = "/tmp/hw_b_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    report = {"marker": marker, "baseline_s": round(baseline, 2)}

    def timed(cmd: str) -> float:
        elapsed, _ = run_ping(client, prefix + cmd,
                              service=inj.injection_service,
                              reader=inj.injection_reader)
        return elapsed

    t_sleep = timed(f"sleep{I}{sleep_seconds}")
    log(f"[verify] timing-sleep {t_sleep:.1f}s")
    report["timing_sleep_s"] = round(t_sleep, 2)
    timing_injection = t_sleep > baseline + TIMING_THRESHOLD

    timed(f"touch{I}{marker}")
    t_check1 = timed(f"test{I}-f{I}{marker}&&sleep{I}{sleep_seconds}")
    log(f"[verify] marker-check {t_check1:.1f}s")
    report["marker_check_s"] = round(t_check1, 2)
    marker_existed = t_check1 > baseline + TIMING_THRESHOLD

    timed(f"rm{I}-f{I}{marker}")
    t_check2 = timed(f"test{I}-f{I}{marker}&&sleep{I}{sleep_seconds}")
    log(f"[verify] marker-after-delete {t_check2:.1f}s")
    report["marker_after_delete_s"] = round(t_check2, 2)
    marker_gone = t_check2 <= baseline + TIMING_THRESHOLD

    report.update({
        "timing_injection_observed": timing_injection,
        "marker_existed": marker_existed,
        "marker_deleted_confirmed": marker_gone,
        "backend_command_execution": bool(timing_injection and marker_existed and marker_gone),
    })
    return report
