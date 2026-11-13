"""Render the README demo as a terminal-style GIF.

The commands and their output are the real ones (captured from a live run of the
API against httpd 2.4.49/2.4.50/2.4.51); this script only animates them.

Usage: python3 make_demo_gif.py <out.gif> [<last_frame.png>]
"""
import sys

from PIL import Image, ImageDraw, ImageFont

SCALE = 2
FONT_PX = 15 * SCALE
LINE_H = 23 * SCALE
PAD_X = 22 * SCALE
PAD_Y = 16 * SCALE
BAR_H = 34 * SCALE
COLS = 86
ROWS = 20

MENLO = "/System/Library/Fonts/Menlo.ttc"
REG = ImageFont.truetype(MENLO, FONT_PX, index=0)
BOLD = ImageFont.truetype(MENLO, FONT_PX, index=1)
SMALL = ImageFont.truetype(MENLO, int(FONT_PX * 0.82), index=0)
CH_W = REG.getlength("M")

W = int(PAD_X * 2 + CH_W * COLS)
H = int(BAR_H + PAD_Y * 2 + LINE_H * ROWS)

BG = "#0d1117"
BAR = "#161b22"
EDGE = "#30363d"
FG = "#c9d1d9"
DIM = "#8b949e"
GREEN = "#3fb950"
RED = "#ff7b72"
AMBER = "#e3b341"
BLUE = "#79c0ff"
STR = "#a5d6ff"
KEY = "#7ee787"

PROMPT = [("$ ", GREEN, True)]


def seg(text, color=FG, bold=False):
    return (text, color, bold)


def render(lines, cursor=None):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, BAR_H], fill=BAR)
    d.line([0, BAR_H, W, BAR_H], fill=EDGE, width=SCALE)
    r = 6 * SCALE
    for i, c in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        cx = PAD_X + i * 20 * SCALE
        d.ellipse([cx - r, BAR_H // 2 - r, cx + r, BAR_H // 2 + r], fill=c)
    title = "fixproof: triage by execution"
    d.text(((W - SMALL.getlength(title)) / 2, BAR_H / 2 - FONT_PX * 0.5), title, font=SMALL, fill=DIM)

    y = BAR_H + PAD_Y
    for row, line in enumerate(lines):
        x = PAD_X
        for text, color, bold in line:
            d.text((x, y), text, font=BOLD if bold else REG, fill=color)
            x += CH_W * len(text)
        if cursor is not None and row == cursor:
            d.rectangle([x, y + 2 * SCALE, x + CH_W, y + LINE_H - 4 * SCALE], fill=FG)
        y += LINE_H
    return img


frames, durations = [], []


def shot(lines, ms, cursor=None):
    frames.append(render(lines, cursor))
    durations.append(ms)


screen = []


def type_line(prefix, segments, step=2, ms=34):
    """Type `segments` after `prefix` on a new line, a few characters per frame."""
    screen.append(list(prefix))
    row = len(screen) - 1
    total = sum(len(t) for t, _, _ in segments)
    n = 0
    while n < total:
        n = min(total, n + step)
        shown, left = [], n
        for text, color, bold in segments:
            if left <= 0:
                break
            shown.append((text[:left], color, bold))
            left -= len(text)
        screen[row] = list(prefix) + shown
        shot(screen, ms, cursor=row)


def out(*lines):
    screen.extend(lines)


def pause(ms, cursor=True):
    if cursor:
        screen.append([])
        shot(screen, ms, cursor=len(screen) - 1)
        screen.pop()
    else:
        shot(screen, ms)


def comment(text):
    type_line(PROMPT, [seg(text, DIM)], step=3, ms=30)


CONT = [("    ", FG, False)]

# --- scene 1: is B a duplicate of A? --------------------------------------------
pause(500)
comment("# Two reports. Both read /etc/passwd from Apache httpd: same file,")
comment("# same CWE, nearly the same text. A was fixed in 2.4.50.")
comment("# Is B a duplicate of A? Replay B's PoC before and after A's fix.")
pause(500)
type_line(PROMPT, [seg("curl -s localhost:8099/triage --json @examples/triage-bypass.json \\")])
type_line(CONT, [seg("| jq '{verdict, reason, action: .disposition.action}'")])
# curl prints nothing while the two sandboxed replays run.
for _ in range(3):
    pause(430)
    pause(430, cursor=False)
out(
    [seg("{")],
    [seg('  "verdict"', KEY), seg(": "), seg('"BYPASS"', RED, True), seg(",")],
    [seg('  "reason"', KEY), seg(": "), seg('"the new PoC still works with the candidate\'s fix applied"', STR), seg(",")],
    [seg('  "action"', KEY), seg(": "), seg('"KEEP_OPEN"', AMBER, True)],
    [seg("}")],
)
pause(2600)

# --- scene 2: where was it actually fixed? ---------------------------------------
comment("# B survived A's patch. Not a duplicate. Where was it really fixed?")
pause(400)
type_line(PROMPT, [seg("curl -s localhost:8099/scan --json @examples/scan-ladder.json \\")])
type_line(CONT, [seg("| jq -r '.per_version[] | \"\\(.version)  \\(.outcome)\"'")])
for _ in range(3):
    pause(430)
    pause(430, cursor=False)
out([seg("2.4.49  "), seg("pass", RED, True)])
pause(350)
out([seg("2.4.50  "), seg("pass", RED, True)])
pause(350)
out([seg("2.4.51  "), seg("fail", GREEN, True)])
pause(900)
comment("# pass = the exploit worked. Fixed in 2.4.51, decided by execution.")
pause(4200)

assert len(screen) <= ROWS, len(screen)

# One shared palette (taken from the final, fullest frame) keeps colors stable.
pal = frames[-1].quantize(colors=96, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
pframes = [f.quantize(palette=pal, dither=Image.Dither.NONE) for f in frames]
pframes[0].save(
    sys.argv[1], save_all=True, append_images=pframes[1:],
    duration=durations, loop=0, optimize=False, disposal=1,
)
if len(sys.argv) > 2:
    frames[-1].save(sys.argv[2])
print(f"{len(frames)} frames, {sum(durations) / 1000:.1f}s, {W}x{H}")
