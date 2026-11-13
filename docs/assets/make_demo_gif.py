"""Render the README hero animation (docs/assets/demo.gif).

It illustrates the one real case the project is built around: CVE-2021-41773 (A)
was fixed in Apache httpd 2.4.50, and CVE-2021-42013 (B) is a near-identical
report whose PoC survives that fix. Both PoCs reproduce on 2.4.49; on 2.4.50 A is
blocked and B still works, so B is a BYPASS, not a duplicate. The payloads shown
are the ones in fixproof/replays/.

Usage: python3 make_demo_gif.py <out.gif> [<frames_dir>]      (needs Pillow, macOS fonts)
"""
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

LW, LH = 800, 450      # logical canvas
SS = 4                 # shapes are drawn supersampled, then reduced for clean edges
OUT = 2                # output scale: 1600x900
FPS = 20

HN = "/System/Library/Fonts/HelveticaNeue.ttc"
MENLO = "/System/Library/Fonts/Menlo.ttc"
FACES = {"reg": (HN, 0), "bold": (HN, 1), "med": (HN, 10), "black": (HN, 9),
         "mono": (MENLO, 0), "monob": (MENLO, 1)}
_fonts = {}


def font(face, size):
    key = (face, size)
    if key not in _fonts:
        path, index = FACES[face]
        _fonts[key] = ImageFont.truetype(path, int(size * SS), index=index)
    return _fonts[key]


def rgb(h):
    return tuple(int(h[i:i + 2], 16) for i in (1, 3, 5))


BG, PANEL, BORDER = rgb("#0d1117"), rgb("#161b22"), rgb("#30363d")
FG, DIM = rgb("#e6edf3"), rgb("#8b949e")
GREEN, RED = rgb("#3fb950"), rgb("#ff5d5d")
COL_A, COL_B = rgb("#39c5cf"), rgb("#f778ba")


def mix(c, base, a):
    a = max(0.0, min(1.0, a))
    return tuple(int(round(c[i] * a + base[i] * (1 - a))) for i in range(3))


def clamp(x):
    return max(0.0, min(1.0, x))


def ease_out(x):
    x = clamp(x)
    return 1 - (1 - x) ** 3


def ease_in_out(x):
    x = clamp(x)
    return 3 * x * x - 2 * x * x * x


def lerp(p0, p1, a):
    return (p0[0] + (p1[0] - p0[0]) * a, p0[1] + (p1[1] - p0[1]) * a)


class Frame:
    def __init__(self):
        self.img = Image.new("RGB", (LW * SS, LH * SS), BG)
        self.d = ImageDraw.Draw(self.img)

    def rect(self, x0, y0, x1, y1, fill=None, outline=None, r=0, w=1.0):
        self.d.rounded_rectangle([x0 * SS, y0 * SS, x1 * SS, y1 * SS], radius=r * SS,
                                 fill=fill, outline=outline, width=max(1, int(w * SS)))

    def circle(self, cx, cy, r, fill=None, outline=None, w=1.0):
        self.d.ellipse([(cx - r) * SS, (cy - r) * SS, (cx + r) * SS, (cy + r) * SS],
                       fill=fill, outline=outline, width=max(1, int(w * SS)))

    def line(self, p0, p1, fill, w=1.0):
        self.d.line([p0[0] * SS, p0[1] * SS, p1[0] * SS, p1[1] * SS], fill=fill, width=max(1, int(w * SS)))

    def dashed(self, p0, p1, fill, w=1.0, dash=5, gap=5):
        length = ((p1[0] - p0[0]) ** 2 + (p1[1] - p0[1]) ** 2) ** 0.5
        n = int(length // (dash + gap))
        for i in range(n + 1):
            a, b = i * (dash + gap) / length, min(1.0, (i * (dash + gap) + dash) / length)
            self.line(lerp(p0, p1, a), lerp(p0, p1, b), fill, w)

    def text(self, x, y, s, face, size, fill, anchor="lm"):
        self.d.text((x * SS, y * SS), s, font=font(face, size), fill=fill, anchor=anchor)

    def width(self, s, face, size):
        return font(face, size).getlength(s) / SS


# --- layout ----------------------------------------------------------------------
CARD_X0, CARD_X1 = 40, 252
CARD_A_Y, CARD_B_Y = 92, 252
SRV = (598, 148, 762, 312)
LANE_A = ((CARD_X1, CARD_A_Y + 60), (SRV[0], 214))
LANE_B = ((CARD_X1, CARD_B_Y + 60), (SRV[0], 246))
SHIELD_X = 520
SHIELD_FRAC = (SHIELD_X - CARD_X1) / (SRV[0] - CARD_X1)
SHIELD_YA = lerp(*LANE_A, SHIELD_FRAC)[1]
SHIELD_YB = lerp(*LANE_B, SHIELD_FRAC)[1]

# --- timeline (seconds) ----------------------------------------------------------
T_CARDS, T_SIM, T_STAGE = 0.2, 1.3, 2.2
A1, B1 = 2.9, 4.0                 # phase 1 launches
FLY = 0.75                        # card -> server
T_P2 = 5.7                        # the fix goes in
A2, B2 = 6.9, 8.3                 # phase 2 launches
T_VERDICT = B2 + FLY + 0.45
END = T_VERDICT + 4.6


def card(f, y0, t, label, cve, code, color, tag, hot=0.0):
    a = ease_out((t - T_CARDS) / 0.5)
    if a <= 0:
        return
    dx = -18 * (1 - a)
    x0, x1 = CARD_X0 + dx, CARD_X1 + dx
    f.rect(x0, y0, x1, y0 + 120, fill=mix(PANEL, BG, a), outline=mix(mix(RED, BORDER, hot), BG, a), r=10, w=1.2 + hot)
    f.circle(x0 + 20, y0 + 20, 4, fill=mix(color, BG, a))
    f.text(x0 + 30, y0 + 20, label, "bold", 10.5, mix(color, BG, a))
    f.text(x1 - 14, y0 + 20, tag, "reg", 10, mix(DIM, BG, a), anchor="rm")
    f.text(x0 + 16, y0 + 44, cve, "bold", 16, mix(FG, BG, a))
    bar = mix(mix(DIM, PANEL, 0.3), BG, a)
    f.rect(x0 + 16, y0 + 62, x0 + 168, y0 + 67, fill=bar, r=2.5)
    f.rect(x0 + 16, y0 + 73, x0 + 128, y0 + 78, fill=bar, r=2.5)
    f.rect(x0 + 14, y0 + 88, x1 - 14, y0 + 108, fill=mix(BG, PANEL, a), r=5)
    f.text(x0 + 21, y0 + 98, code, "mono", 8.6, mix(color, BG, a))


def server(f, flash, a, v_mix):
    x0, y0, x1, y1 = SRV
    body = mix(mix(mix(RED, PANEL, 0.28), PANEL, flash), BG, a)
    f.rect(x0, y0, x1, y1, fill=body, outline=mix(mix(RED, BORDER, flash), BG, a), r=12, w=1.2 + 1.3 * flash)
    for i in range(3):
        ry = y0 + 22 + i * 34
        f.rect(x0 + 20, ry, x1 - 20, ry + 24, fill=mix(mix(BORDER, PANEL, 0.55), BG, a), r=5)
        f.circle(x0 + 33, ry + 12, 3.4, fill=mix(mix(RED, GREEN, flash), BG, a))
        f.circle(x0 + 45, ry + 12, 3.4, fill=mix(mix(DIM, PANEL, 0.5), BG, a))
        f.rect(x1 - 62, ry + 10, x1 - 32, ry + 14, fill=mix(mix(DIM, PANEL, 0.35), BG, a), r=2)
    cx = (x0 + x1) / 2
    # the version label cross-fades 2.4.49 -> 2.4.50 when the fix goes in
    if v_mix < 1:
        f.text(cx, y1 - 22, "httpd 2.4.49", "monob", 13, mix(FG, body, a * (1 - v_mix)), anchor="mm")
    if v_mix > 0:
        f.text(cx, y1 - 22, "httpd 2.4.50", "monob", 13, mix(FG, body, a * v_mix), anchor="mm")


def projectile(f, t, t0, lane, color, stop=1.0, fade=1.0):
    """Draw a PoC flying along its lane, leaving a faint trace of its path."""
    if t < t0:
        return
    frac = min(stop, ease_in_out((t - t0) / FLY))
    p0, p1 = lane
    p = lerp(p0, p1, frac)
    arrived = frac >= stop
    f.line(p0, p, mix(color, BG, (0.22 if arrived else 0.30) * fade), 1.6)
    if not arrived:
        for i in range(8):
            a0, a1 = max(0.0, frac - 0.16 * (1 - i / 8)), max(0.0, frac - 0.16 * (1 - (i + 1) / 8))
            f.line(lerp(p0, p1, a0), lerp(p0, p1, a1), mix(color, BG, 0.25 + 0.75 * (i + 1) / 8), 2.6)
        f.circle(p[0], p[1], 15, fill=mix(color, BG, 0.10))
        f.circle(p[0], p[1], 10.5, fill=mix(color, BG, 0.24))
        f.circle(p[0], p[1], 6.2, fill=color)
        f.circle(p[0], p[1], 2.6, fill=mix(FG, color, 0.85))


def arrival(t0, frac):
    """When a projectile launched at t0 reaches `frac` of its lane (inverse of the ease)."""
    lo, hi = 0.0, 1.0
    for _ in range(30):
        mid = (lo + hi) / 2
        if ease_in_out(mid) < frac:
            lo = mid
        else:
            hi = mid
    return t0 + FLY * hi


def ring(f, t, t0, center, color, grow=24, life=0.55):
    x = (t - t0) / life
    if 0 <= x <= 1:
        f.circle(center[0], center[1], 6 + grow * ease_out(x), outline=mix(color, BG, 1 - x), w=2.2 * (1 - x) + 0.6)


def chip(f, x, y, t, t0, dot, label, bold=False, fade=1.0):
    a = ease_out((t - t0) / 0.3) * fade
    if a <= 0:
        return
    f.circle(x + 5, y, 4.2, fill=mix(dot, BG, a))
    f.text(x + 16, y, label, "bold" if bold else "reg", 12, mix(dot if bold else FG, BG, a))


def stamp(img, t):
    """The verdict, slammed on at an angle."""
    x = (t - T_VERDICT) / 0.28
    if x <= 0:
        return
    a, scale = clamp(x * 1.6), 1.0 + 0.55 * (1 - ease_out(x))
    w, h = 250, 74
    layer = Image.new("RGBA", (w * SS, h * SS), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    d.rounded_rectangle([3 * SS, 3 * SS, (w - 3) * SS, (h - 3) * SS], radius=9 * SS,
                        fill=mix(RED, BG, 0.10) + (255,), outline=RED + (255,), width=int(2.6 * SS))
    d.text((w * SS / 2, 30 * SS), "BYPASS", font=font("black", 31), fill=RED + (255,), anchor="mm")
    d.text((w * SS / 2, 55 * SS), "not a duplicate  ·  keep open", font=font("bold", 10.5), fill=RED + (255,), anchor="mm")
    layer = layer.rotate(5, resample=Image.Resampling.BICUBIC, expand=True)
    if scale != 1.0:
        layer = layer.resize((int(layer.width * scale), int(layer.height * scale)), Image.Resampling.BICUBIC)
    if a < 1:
        layer.putalpha(layer.getchannel("A").point(lambda v: int(v * a)))
    cx, cy = 428, 372
    img.paste(layer, (int(cx * SS - layer.width / 2), int(cy * SS - layer.height / 2)), layer)


T_A_BLOCKED = arrival(A2, SHIELD_FRAC - 0.025)
T_B_BREACH = arrival(B2, SHIELD_FRAC)


def draw(t):
    f = Frame()
    a0 = ease_out(t / 0.5)

    f.text(40, 36, "Is report B a duplicate of report A?", "bold", 21, mix(FG, BG, a0))
    f.text(40, 62, "Same file, same CWE, nearly the same text. One way to know: run it.", "reg", 12.5, mix(DIM, BG, a0))
    f.text(760, 36, "FIXPROOF", "monob", 11, mix(GREEN, BG, a0), anchor="rm")

    verdict = clamp((t - T_VERDICT) / 0.3)
    card(f, CARD_A_Y, t, "REPORT A", "CVE-2021-41773", "/.%2e/.%2e/…/etc/passwd", COL_A, "fixed in 2.4.50")
    card(f, CARD_B_Y, t, "REPORT B", "CVE-2021-42013", "/.%%32%65/.%%32%65/…/etc/passwd", COL_B, "new report", hot=verdict)
    f.text((CARD_X0 + CARD_X1) / 2, 232, "≈  nearly identical text", "reg", 11, mix(DIM, BG, ease_out((t - T_SIM) / 0.4)), anchor="mm")

    # stage: target server, lanes, phase caption
    sa = ease_out((t - T_STAGE) / 0.5)
    p2 = ease_out((t - T_P2) / 0.6)
    if sa > 0:
        for lane in (LANE_A, LANE_B):
            f.dashed(*lane, mix(BORDER, BG, sa * 0.9), 1.0)
        hits = [A1 + FLY, B1 + FLY, B2 + FLY]
        flash = max([0.0] + [1 - (t - h) / 0.8 for h in hits if 0 <= t - h <= 0.8])
        server(f, flash, sa, p2)
        cx = (SRV[0] + SRV[2]) / 2
        if p2 < 1:
            f.text(cx, 128, "BEFORE THE FIX", "bold", 11, mix(DIM, BG, sa * (1 - p2)), anchor="mm")
        if p2 > 0:
            f.text(cx, 128, "AFTER A'S FIX", "bold", 11, mix(GREEN, BG, p2), anchor="mm")

    # phase 1 leftovers fade out as the fix goes in
    fade1 = 1 - clamp((t - T_P2) / 0.35)
    if fade1 > 0:
        for t0, lane, col in ((A1, LANE_A, COL_A), (B1, LANE_B, COL_B)):
            projectile(f, t, t0, lane, col, fade=fade1)
            ring(f, t, t0 + FLY, lane[1], RED)
        chip(f, SRV[0] + 8, 332, t, A1 + FLY, RED, "PoC A reproduces", fade=fade1)
        chip(f, SRV[0] + 8, 352, t, B1 + FLY, RED, "PoC B reproduces", fade=fade1)

    # the fix: a wall in front of the server
    if p2 > 0:
        top, bot = 150 - 26 * (1 - p2), 310 - 26 * (1 - p2)
        hit_a = max(0.0, 1 - (t - T_A_BLOCKED) / 0.5) if t >= T_A_BLOCKED else 0.0
        f.rect(SHIELD_X - 4.5, top, SHIELD_X + 4.5, bot, fill=mix(mix(FG, GREEN, hit_a * 0.6), BG, p2), r=4.5)
        f.text(SHIELD_X, top - 14, "A's fix", "bold", 11, mix(GREEN, BG, p2), anchor="mm")
        if t >= T_B_BREACH:
            f.rect(SHIELD_X - 7, SHIELD_YB - 10, SHIELD_X + 7, SHIELD_YB + 10, fill=BG)
            f.rect(SHIELD_X - 4.5, SHIELD_YB - 13, SHIELD_X + 4.5, SHIELD_YB - 10, fill=RED, r=1)
            f.rect(SHIELD_X - 4.5, SHIELD_YB + 10, SHIELD_X + 4.5, SHIELD_YB + 13, fill=RED, r=1)

    # phase 2: A is stopped by its own fix, B goes through it
    if t >= T_P2 + 0.35:
        projectile(f, t, A2, LANE_A, COL_A, stop=SHIELD_FRAC - 0.025)
        ring(f, t, T_A_BLOCKED, (SHIELD_X - 6, SHIELD_YA), GREEN)
        projectile(f, t, B2, LANE_B, COL_B)
        ring(f, t, T_B_BREACH, (SHIELD_X, SHIELD_YB), RED, grow=16, life=0.4)
        ring(f, t, B2 + FLY, LANE_B[1], RED)
        chip(f, SRV[0] + 8, 332, t, T_A_BLOCKED, GREEN, "PoC A blocked")
        chip(f, SRV[0] + 8, 352, t, B2 + FLY, RED, "PoC B still works", bold=True)

    stamp(f.img, t)
    if verdict > 0:
        brand, rest = "FixProof", "   decided by execution, not by similarity"
        x = (LW - f.width(brand, "bold", 12.5) - f.width(rest, "reg", 12.5)) / 2
        f.text(x, 430, brand, "bold", 12.5, mix(FG, BG, verdict))
        f.text(x + f.width(brand, "bold", 12.5), 430, rest, "reg", 12.5, mix(DIM, BG, verdict))

    return f.img.reduce(SS // OUT)


def main():
    out = sys.argv[1]
    frames = [draw(i / FPS) for i in range(int(END * FPS) + 1)]

    # One shared palette, sampled from frames that between them show every color.
    keys = [A1 + FLY + 0.05, B1 + FLY * 0.5, T_A_BLOCKED - 0.1, B2 + FLY + 0.05, T_VERDICT + 1.0]
    strip = Image.new("RGB", (frames[0].width, frames[0].height * len(keys)))
    for i, k in enumerate(keys):
        strip.paste(frames[int(k * FPS)], (0, i * frames[0].height))
    pal = strip.quantize(colors=200, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)

    merged, durations = [], []
    for fr in frames:
        q = fr.quantize(palette=pal, dither=Image.Dither.NONE)
        if merged and q.tobytes() == merged[-1].tobytes():
            durations[-1] += 1000 // FPS
        else:
            merged.append(q)
            durations.append(1000 // FPS)
    merged[0].save(out, save_all=True, append_images=merged[1:], duration=durations, loop=0, disposal=1)

    if len(sys.argv) > 2:
        d = Path(sys.argv[2])
        d.mkdir(parents=True, exist_ok=True)
        names = ("1-control", "2-b-flying", "3-a-about-to-hit", "4-b-through", "5-verdict")
        for name, k in zip(names, keys):
            frames[int(k * FPS)].save(d / f"{name}.png")
    print(f"{len(merged)} frames ({len(frames)} drawn), {END:.1f}s, {frames[0].width}x{frames[0].height}")


if __name__ == "__main__":
    main()
