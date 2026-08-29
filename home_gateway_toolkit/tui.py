"""Read-only curses dashboard ('home-gateway dashboard').

Architecture: collection and rendering are separated so the rendering layer
is testable without a terminal.

  * ``collect_snapshot(providers)`` gathers all state through injected
    provider callables (no I/O is hard-wired) and returns an immutable
    ``DashboardSnapshot``.
  * ``render_lines(snapshot, width)`` is a pure function turning a snapshot
    into printable lines — this is what the tests assert on.
  * ``run_dashboard(providers)`` is the thin curses main loop: it collects a
    snapshot, renders it, and refreshes on a timer or on keypress.

Safety model: the dashboard is strictly read-only. Providers are expected to
only *query* state (sysinfo reads, wanwatch state files, SSH status reads);
no write operation of any kind is performed here.
"""

from __future__ import annotations

import datetime as dt
import sys
from dataclasses import dataclass, field
from typing import Callable

DEFAULT_REFRESH = 5.0


@dataclass
class Providers:
    """Injected data sources; every field is an optional zero-arg callable.

    device_info()  -> {"model": ..., "hw_version": ..., "fw_version": ...}
    wan_state()    -> wanwatch-style snapshot dict (see wanwatch._snapshot)
    ssh_status()   -> dict as returned by ssh.status()
    fw_rules()     -> list of dicts as returned by firewall.FW.list_rules()
    last_event()   -> short human-readable string
    """

    device_info: Callable[[], dict] | None = None
    wan_state: Callable[[], dict] | None = None
    ssh_status: Callable[[], dict] | None = None
    fw_rules: Callable[[], list] | None = None
    last_event: Callable[[], str] | None = None


@dataclass
class DashboardSnapshot:
    """Everything the dashboard renders, collected at one point in time."""

    ts: str = ""
    device_model: str = ""
    device_board: str = ""
    device_firmware: str = ""
    wan_ipv4: str = ""
    wan_ipv4_class: str = ""
    wan_mode: str = ""
    sixrd_prefixes: list = field(default_factory=list)
    wan6_prefixes: list = field(default_factory=list)
    wan_last_change: str = ""
    ssh: dict = field(default_factory=dict)
    fw_rules: list = field(default_factory=list)
    last_event: str = ""
    errors: list = field(default_factory=list)


def _safe_call(name: str, fn: Callable | None, errors: list):
    """Call a provider, recording (not raising) any failure."""
    if fn is None:
        return None
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - dashboard must stay up
        errors.append(f"{name}: {exc}")
        return None


def collect_snapshot(providers: Providers) -> DashboardSnapshot:
    """Gather a point-in-time snapshot from the injected providers."""
    snap = DashboardSnapshot(
        ts=dt.datetime.now().isoformat(timespec="seconds"))
    errors = snap.errors

    info = _safe_call("device_info", providers.device_info, errors) or {}
    snap.device_model = str(info.get("model", ""))
    snap.device_board = str(info.get("hw_version", info.get("board", "")))
    snap.device_firmware = str(info.get("fw_version", info.get("firmware", "")))

    wan = _safe_call("wan_state", providers.wan_state, errors) or {}
    snap.wan_ipv4 = str(wan.get("wan_ipv4") or "")
    snap.wan_ipv4_class = str(wan.get("wan_ipv4_class") or "")
    snap.wan_mode = str(wan.get("mode") or "")
    snap.sixrd_prefixes = list(wan.get("sixrd_prefixes") or [])
    snap.wan6_prefixes = list(wan.get("wan6_prefixes") or [])
    snap.wan_last_change = str(wan.get("change_summary") or "")

    snap.ssh = _safe_call("ssh_status", providers.ssh_status, errors) or {}
    snap.fw_rules = _safe_call("fw_rules", providers.fw_rules, errors) or []
    snap.last_event = str(
        _safe_call("last_event", providers.last_event, errors) or "")
    return snap


def wanwatch_state_provider(state_file: str) -> Callable[[], dict]:
    """Provider factory reusing wanwatch's persisted snapshot (read-only).

    Reads the state file written by 'home-gateway wanwatch' so the dashboard can
    show the most recent WAN snapshot and change summary without opening
    its own SSH connection.
    """
    from . import wanwatch

    def read() -> dict:
        state = wanwatch._load_state(state_file)
        snapshot = state.get("snapshot")
        return snapshot if isinstance(snapshot, dict) else {}

    return read


def _clip(text: str, width: int) -> str:
    if width > 0 and len(text) > width:
        return text[: max(0, width - 1)] + "…" if width > 1 else text[:width]
    return text


def render_lines(snapshot: DashboardSnapshot, width: int = 100) -> list[str]:
    """Pure renderer: snapshot -> printable lines (no curses required)."""
    device = " ".join(part for part in
                      (snapshot.device_model, snapshot.device_board,
                       snapshot.device_firmware) if part) or "unknown device"
    lines = [
        f" {device}",
        f" {snapshot.ts}",
        "",
    ]

    # WAN section
    wan_head = " WAN   "
    if snapshot.wan_ipv4:
        cls = f" ({snapshot.wan_ipv4_class})" if snapshot.wan_ipv4_class else ""
        wan_head += f"IPv4 {snapshot.wan_ipv4}{cls}"
    else:
        wan_head += "IPv4 n/a"
    if snapshot.wan_mode:
        wan_head += f" | mode {snapshot.wan_mode}"
    lines.append(wan_head)
    prefixes = snapshot.sixrd_prefixes or snapshot.wan6_prefixes
    if prefixes:
        label = "6rd" if snapshot.sixrd_prefixes else "wan6"
        lines.append(f"       {label} prefixes: {', '.join(prefixes)}")
    if snapshot.wan_last_change:
        lines.append(f"       last change: {snapshot.wan_last_change}")

    # SSH section
    ssh = snapshot.ssh
    if ssh:
        state = "UP" if ssh.get("listening") else "DOWN"
        port = ssh.get("port", "?")
        key_only = "key-only" if (ssh.get("uci_instance")
                                  and ssh.get("authorized_keys")) else "unknown-auth"
        lines.append(f" SSH   dropbear {state} port {port} {key_only}")
    else:
        lines.append(" SSH   status unavailable")

    # Firewall section
    lines.append(f" FW    {len(snapshot.fw_rules)} rule(s)")
    if snapshot.fw_rules:
        lines.append(f"       {'name':<20} {'proto':<6} {'dest':<30} ports")
        for rule in snapshot.fw_rules:
            lines.append(
                f"       {str(rule.get('name', rule.get('section', '-')))[:20]:<20} "
                f"{str(rule.get('proto', '-'))[:6]:<6} "
                f"{str(rule.get('dest_ip', '-'))[:30]:<30} "
                f"{rule.get('dest_port', '-')}")

    if snapshot.errors:
        lines.append("")
        for err in snapshot.errors:
            lines.append(f" ! {err}")

    lines.append("")
    if snapshot.last_event:
        lines.append(f" EVENT {snapshot.last_event}")
    lines.append(" [q] quit   [r] refresh")
    return [_clip(line, width) for line in lines]


def _render_frame(stdscr, snapshot: DashboardSnapshot, curses_mod) -> None:
    """Draw one full frame. ``curses_mod`` is the (possibly fake) curses
    module, injected so the frame logic is testable without a terminal."""
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    for row, line in enumerate(render_lines(snapshot, width - 1)):
        if row >= height - 1:
            break
        try:
            stdscr.addnstr(row, 0, line, width - 1)
        except curses_mod.error:
            pass  # window too small for this line; skip it
    stdscr.refresh()


def _main_loop(stdscr, providers: Providers, refresh: float,
               curses_mod) -> None:
    """Event loop. ``curses_mod`` is injected for testability: any object
    exposing an ``error`` exception class works (real curses or a fake)."""
    stdscr.timeout(max(100, int(refresh * 1000)))
    snapshot = collect_snapshot(providers)
    while True:
        _render_frame(stdscr, snapshot, curses_mod)
        key = stdscr.getch()
        if key in (ord("q"), ord("Q")):
            return
        if key in (ord("r"), ord("R")):
            snapshot = collect_snapshot(providers)
        elif key == -1:  # timeout elapsed -> periodic refresh
            snapshot = collect_snapshot(providers)


def run_dashboard(providers: Providers, refresh: float = DEFAULT_REFRESH,
                  _wrapper=None) -> int:
    """Run the curses dashboard. Returns 0 on clean exit ('q').

    Raises RuntimeError with a clear message when curses is unavailable or
    stdout is not a terminal; in that case use the '--json' output of the
    individual commands in a polling loop instead.

    ``_wrapper`` is a test seam: a callable ``wrapper(fn, *args)`` standing
    in for ``curses.wrapper``.
    """
    if not sys.stdout.isatty():
        raise RuntimeError(
            "dashboard requires an interactive terminal (stdout is not a "
            "tty); use the --json output of 'home-gateway doctor' / 'home-gateway wanwatch' "
            "in a polling loop instead")
    try:
        import curses
    except ImportError as exc:
        raise RuntimeError(
            "the 'curses' module is not available on this Python/platform; "
            "use the --json output of the individual commands in a polling "
            "loop instead") from exc
    wrapper = _wrapper or curses.wrapper
    wrapper(lambda stdscr: _main_loop(stdscr, providers, refresh, curses))
    return 0
