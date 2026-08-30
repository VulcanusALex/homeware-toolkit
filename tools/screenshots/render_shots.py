#!/usr/bin/env python3
"""Render terminal-style screenshots (PNG) and demo GIF for docs/images.

Not part of the toolkit; a maintainer utility. Uses real CLI output captured
from the simulator where possible.

Markup per line: list of (text, style) spans, or a plain string (style "dim").
Styles map to colors approximating the previous screenshots' dark theme.
"""
from __future__ import annotations

import sys

from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------- theme ----
BG = (28, 30, 36)
COLORS = {
    "title": (150, 154, 162),    # gray-ish Chinese title
    "prompt": (226, 230, 236),   # "$"
    "cmd": (86, 182, 255),       # cyan command
    "text": (212, 216, 222),     # normal output
    "dim": (150, 154, 162),
    "ok": (86, 211, 134),        # green
    "warn": (230, 192, 96),      # yellow
    "err": (255, 108, 108),      # red
    "note": (126, 214, 190),     # teal annotation
}

FONT_MONO = "/System/Library/Fonts/Menlo.ttc"
FONT_CJK = "/System/Library/Fonts/Hiragino Sans GB.ttc"

SIZE = 15
PAD_X, PAD_Y = 16, 14
LINE_H = 23

_mono = ImageFont.truetype(FONT_MONO, SIZE)
_mono_b = ImageFont.truetype(FONT_MONO, SIZE, index=2)  # bold face in ttc
_cjk = ImageFont.truetype(FONT_CJK, SIZE)


def _font_for(ch: str) -> ImageFont.FreeTypeFont:
    return _cjk if ord(ch) > 0x2E7F else _mono


def _span_width(text: str) -> int:
    d = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    w = 0
    for ch in text:
        w += d.textlength(ch, font=_font_for(ch))
    return int(round(w))


def render_lines(lines, path: str | None = None, width: int | None = None,
                 scale: int = 2) -> Image.Image:
    """lines: list of list[(text, style)]. Returns PIL image (scaled x2)."""
    norm = [[(s, "text") if isinstance(s, str) else s for s in
             (line if isinstance(line, list) else [line])] for line in lines]
    if width is None:
        width = max(2 * PAD_X + max((_span_width("".join(t for t, _ in line))
                                     for line in norm), default=0), 200)
        width += 8
    height = 2 * PAD_Y + LINE_H * len(norm)
    img = Image.new("RGB", (width * scale, height * scale), BG)
    d = ImageDraw.Draw(img)
    y = PAD_Y * scale
    for line in norm:
        x = PAD_X * scale
        for text, style in line:
            for ch in text:
                f = _font_for(ch)
                d.text((x, y), ch, font=f, fill=COLORS[style])
                x += d.textlength(ch, font=f)
        y += LINE_H * scale
    return img


def save(lines, path: str, width: int | None = None) -> None:
    img = render_lines(lines, width=width)
    img.save(path)
    print(f"wrote {path} {img.size}")


# ------------------------------------------------------------ content ----
# Spans are composed to match the toolkit's actual output strings.

def step1():
    return [
        [("第 1 步：只读兼容性探测（不需要登录）", "title")],
        [],
        [("$ ", "prompt"), ("./homeware probe", "cmd")],
        [("compatibility: ", "text"), ("strong-front-end-match", "ok"),
         ("  stamps=['20260515082010']  ports={'22': 'refused', '80': 'open', "
          "...}", "dim")],
    ]


def step2():
    return [
        [("第 2 步：一条命令 + 按下机身双键", "title")],
        [],
        [("$ ", "prompt"), ("./homeware session login", "cmd")],
        [("[login] fresh session created (must stay the latest — do not open", "text")],
        [("        the router page in a browser during this process)", "text")],
        [("[login] armed button wait (http 200)", "text")],
        [("[login] ", "text"), ("press BOTH side buttons for 3s within 60s", "warn")],
        [("    ← 此时到路由器上，同时按住侧面两个按钮 3 秒", "note")],
        [("[login] button press detected", "text")],
        [("[login] ", "text"), ("authenticated=True", "ok")],
    ]


def step3():
    return [
        [("第 3 步：无持久化注入验证", "title")],
        [],
        [("$ ", "prompt"), ("./homeware verify", "cmd")],
        [("[verify] baseline 1.0s", "text")],
        [("[verify] timing-sleep 10.1s", "text")],
        [("[verify] marker-check 10.1s", "text")],
        [("[verify] marker-after-delete 1.0s", "text")],
        [("backend command execution: ", "text"), ("CONFIRMED", "ok")],
    ]


def step4():
    return [
        [("第 4 步：部署持久 SSH（自动验证握手）", "title")],
        [],
        [("$ ", "prompt"),
         ("ssh-keygen -t rsa -b 2048 -f ~/.homeware-toolkit/id_rsa", "cmd")],
        [("$ ", "prompt"),
         ("./homeware ssh bootstrap --pubkey ~/.homeware-toolkit/id_rsa.pub --test",
          "cmd")],
        [("[ssh] root shell ready", "text")],
        [("[transfer] /tmp/nxseg_sshkey_000 ok (48 chars)", "text")],
        [("[transfer] ...", "dim")],
        [("[ssh] public key installed (md5 verified)", "text")],
        [("[ssh] ", "text"), ("handshake OK", "ok")],
    ]


def step5():
    return [
        [("第 5 步：doctor 一键体检", "title")],
        [],
        [("$ ", "prompt"),
         ("./homeware doctor --key ~/.homeware-toolkit/id_rsa", "cmd")],
        [("[✓] web-ui-compatibility: ", "text"), ("PASS", "ok"),
         (" strong-front-end-match", "dim")],
        [("[✓] web-session: ", "text"), ("PASS", "ok")],
        [("[✓] command-injection: ", "text"), ("PASS", "ok"),
         (" baseline 1.0s, probe 4.2s", "dim")],
        [("[✓] ssh-service: ", "text"), ("PASS", "ok"),
         (" port 2222 reachable with key", "dim")],
        [("[i] wan-ipv4-assignment: ", "text"), ("INFO", "warn"),
         (" private-RFC1918", "dim")],
        [("    → private WAN alone cannot determine inbound reachability", "dim")],
    ]


WIDTH = 1000

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "docs/images"
    for name, fn in [("step1-probe", step1), ("step2-login", step2),
                     ("step3-verify", step3), ("step4-bootstrap", step4),
                     ("step5-doctor", step5)]:
        img = render_lines(fn(), width=WIDTH, scale=2)
        # keep the same 1000px logical width as the old files
        img.save(f"{out}/{name}.png")
        print(f"wrote {out}/{name}.png {img.size}")
