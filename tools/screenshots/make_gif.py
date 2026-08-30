#!/usr/bin/env python3
"""Generate docs/images/demo.gif: animated run of the five setup steps."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from PIL import Image, ImageDraw

import render_shots as rs

# smaller canvas + faster typing to keep the GIF compact
rs.SIZE = 13
rs.LINE_H = 19
rs.PAD_X, rs.PAD_Y = 12, 10
rs.WIDTH = 1000
from PIL import ImageFont
rs._mono = ImageFont.truetype(rs.FONT_MONO, rs.SIZE)
rs._cjk = ImageFont.truetype(rs.FONT_CJK, rs.SIZE)

from render_shots import (BG, COLORS, _font_for, step1, step2, step3, step4,
                          step5)

SCALE = 1
LINE_H, PAD_X, PAD_Y, WIDTH = rs.LINE_H, rs.PAD_X, rs.PAD_Y, rs.WIDTH


def draw_lines(d, lines, upto=None):
    y = PAD_Y * SCALE
    for i, line in enumerate(lines):
        if upto is not None and i > upto[0]:
            break
        x = PAD_X * SCALE
        limit = upto[1] if upto is not None and i == upto[0] else None
        xoff = 0
        stop = False
        for text, style in line:
            for ch in text:
                if limit is not None and xoff >= limit:
                    stop = True
                    break
                f = _font_for(ch)
                d.text((x, y), ch, font=f, fill=COLORS[style])
                x += d.textlength(ch, font=f)
                xoff += 1
            if stop:
                break
        y += LINE_H * SCALE


def norm(lines):
    return [[(s, "text") if isinstance(s, str) else s for s in
             (l if isinstance(l, list) else [l])] for l in lines]


def main(out: str) -> None:
    # Build the full transcript: steps separated by one blank line.
    steps = [norm(s()) for s in (step1, step2, step3, step4, step5)]
    transcript = []
    for si, st in enumerate(steps):
        if si:
            transcript.append([])
        transcript.extend(st)

    total_lines = len(transcript)
    height = 2 * PAD_Y + LINE_H * total_lines
    frames: list[tuple[Image.Image, int]] = []  # (image, duration ms)

    def snapshot(upto, dur):
        img = Image.new("RGB", (WIDTH * SCALE, height * SCALE), BG)
        d = ImageDraw.Draw(img)
        draw_lines(d, transcript, upto)
        frames.append((img, dur))

    cursor_line = 0
    for si, st in enumerate(steps):
        if si:
            cursor_line += 1  # blank separator already revealed
        for li, line in enumerate(st[1:], start=1):  # skip title line
            abs_line = cursor_line + li
            spans = [(t, s) for t, s in line]
            is_cmd = bool(spans) and spans[0][1] == "prompt"
            if is_cmd:
                # typing animation: reveal chars of the command line
                nchars = sum(len(t) for t, _ in spans)
                nsteps = min(6, nchars)
                for k in range(1, nsteps + 1):
                    snapshot((abs_line, nchars * k // nsteps), 55)
                snapshot((abs_line, None), 420)
            elif not spans:
                snapshot((abs_line, None), 100)
            else:
                snapshot((abs_line, None), 280)
        # title of next step appears with a pause after previous block
        cursor_line += len(st)
        snapshot(None if si == len(steps) - 1 else (cursor_line + 1, None),
                 2200 if si == len(steps) - 1 else 800)
    # final hold
    snapshot(None, 2800)

    images = [f for f, _ in frames]
    durations = [d for _, d in frames]
    base = images[len(images) // 2].quantize(colors=128,
                                             method=Image.MEDIANCUT)
    q = [f.quantize(palette=base, dither=Image.FLOYDSTEINBERG)
         for f in images]
    q[0].save(
        out, save_all=True, append_images=q[1:], duration=durations,
        loop=0, optimize=True, disposal=2)
    print(f"wrote {out}: {len(images)} frames")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "docs/images/demo.gif")
