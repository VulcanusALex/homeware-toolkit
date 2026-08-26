"""Observe inbound traffic using existing firewall rule counters.

This deliberately does not claim that a zero delta proves blocking: hardware
offload, an already-established flow, or a client that never sent a packet can
all leave counters unchanged.  A positive delta is strong local evidence that
traffic reached the gateway and matched the selected rule.
"""

from __future__ import annotations

import time


def observe(fw, name: str, seconds: int = 30, interval: float = 1.0,
            log=print) -> dict:
    if not 1 <= seconds <= 600:
        raise RuntimeError("observation window must be between 1 and 600 seconds")
    matches = [rule for rule in fw.list_rules() if rule.get("name") == name]
    if not matches:
        raise RuntimeError(f"no firewall rule named {name!r}")
    if len(matches) > 1:
        raise RuntimeError(f"multiple firewall rules are named {name!r}; audit first")

    before = fw.counter_snapshot(name)
    if before["matched_rules"] == 0:
        raise RuntimeError(
            f"rule {name!r} exists in UCI but is absent from the running firewall; "
            "run 'nexxt fw audit' and reload the firewall")

    log(f"[inbound] watching {name!r} for up to {seconds}s")
    log("[inbound] start a NEW connection from the external client now")
    deadline = time.monotonic() + seconds
    after = before
    while time.monotonic() < deadline:
        time.sleep(min(interval, max(0.0, deadline - time.monotonic())))
        after = fw.counter_snapshot(name)
        if after["packets"] > before["packets"]:
            break

    packet_delta = max(0, after["packets"] - before["packets"])
    byte_delta = max(0, after["bytes"] - before["bytes"])
    state = "confirmed-at-gateway" if packet_delta else "not-observed"
    if packet_delta:
        log(f"[inbound] CONFIRMED: +{packet_delta} packets / +{byte_delta} bytes")
    else:
        log("[inbound] no new counter hit; this is inconclusive, not proof of blocking")
    return {
        "rule": matches[0], "state": state, "window_seconds": seconds,
        "before": before, "after": after,
        "packet_delta": packet_delta, "byte_delta": byte_delta,
        "inference": (
            "traffic reached the gateway and matched the selected firewall rule"
            if packet_delta else
            "no new match was observed; client activity, offload, or upstream blocking are all possible"
        ),
    }
