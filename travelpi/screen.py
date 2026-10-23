"""The 3.5" SPI screen (/dev/fb0, 480x320 RGB565) and its resistive touch layer (ADS7846 via evdev)."""
from __future__ import annotations

import json
import select
import time
from pathlib import Path

import numpy as np
from PIL import Image

from .config import ETC

W, H = 480, 320
CAL_FILE = ETC / "touch.json"


def to_rgb565(img: Image.Image) -> bytes:
    a = np.asarray(img.convert("RGB"), dtype=np.uint16)
    v = ((a[:, :, 0] >> 3) << 11) | ((a[:, :, 1] >> 2) << 5) | (a[:, :, 2] >> 3)
    return v.astype("<u2").tobytes()


class Framebuffer:
    def __init__(self, dev: str = "/dev/fb0"):
        self.f = open(dev, "wb", buffering=0)

    def show(self, img: Image.Image) -> None:
        self.f.seek(0)
        self.f.write(to_rgb565(img))


def calibrate_from(raw: list[tuple[int, int]], pts: list[tuple[int, int]]) -> dict:
    """Three taps: pts[0] top-left, pts[1] top-right (same y), pts[2] bottom-left (same x).
    Whichever raw axis moved most between taps 0→1 is the screen's x axis."""
    (r0, r1, r2), (p0, p1, p2) = raw, pts
    swap = abs(r1[1] - r0[1]) > abs(r1[0] - r0[0])
    ix, iy = (1, 0) if swap else (0, 1)
    ax = (p1[0] - p0[0]) / ((r1[ix] - r0[ix]) or 1)
    ay = (p2[1] - p0[1]) / ((r2[iy] - r0[iy]) or 1)
    return {"swap": swap, "ax": ax, "bx": p0[0] - ax * r0[ix], "ay": ay, "by": p0[1] - ay * r0[iy]}


def apply_cal(cal: dict, rx: int, ry: int) -> tuple[int, int]:
    a, b = (ry, rx) if cal["swap"] else (rx, ry)
    x, y = cal["ax"] * a + cal["bx"], cal["ay"] * b + cal["by"]
    return max(0, min(W - 1, round(x))), max(0, min(H - 1, round(y)))


class Touch:
    """Yields taps as screen (x, y). A tap is reported when the finger/stylus lifts."""

    def __init__(self) -> None:
        import evdev
        self.ev = evdev
        dev = next(evdev.InputDevice(p) for p in evdev.list_devices() if "ADS7846" in evdev.InputDevice(p).name)
        self.dev = dev
        self.cal = self.load()
        self.rx = self.ry = None
        self.samples: list[tuple[int, int]] = []

    @staticmethod
    def load() -> dict | None:
        try:
            return json.loads(CAL_FILE.read_text())
        except (OSError, ValueError):
            return None

    def save(self, cal: dict) -> None:
        CAL_FILE.parent.mkdir(parents=True, exist_ok=True)
        CAL_FILE.write_text(json.dumps(cal))
        self.cal = cal

    def poll(self, timeout: float) -> tuple[int, int, tuple[int, int]] | None:
        """Wait up to `timeout` s; return (x, y, raw) for a completed tap, else None."""
        e = self.ev.ecodes
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return None
            r, _, _ = select.select([self.dev.fd], [], [], left)
            if not r:
                return None
            for ev in self.dev.read():
                if ev.type == e.EV_ABS and ev.code == e.ABS_X:
                    self.rx = ev.value
                elif ev.type == e.EV_ABS and ev.code == e.ABS_Y:
                    self.ry = ev.value
                elif ev.type == e.EV_SYN and self.rx is not None and self.ry is not None:
                    self.samples.append((self.rx, self.ry))
                elif ev.type == e.EV_KEY and ev.code == e.BTN_TOUCH and ev.value == 0 and self.samples:
                    s = self.samples[len(self.samples) // 4:] or self.samples   # first readings are noisy
                    raw = (int(np.median([p[0] for p in s])), int(np.median([p[1] for p in s])))
                    self.samples = []
                    x, y = apply_cal(self.cal, *raw) if self.cal else (0, 0)
                    return x, y, raw
                elif ev.type == e.EV_KEY and ev.code == e.BTN_TOUCH and ev.value == 1:
                    self.samples = []

    def drain(self) -> None:
        try:
            while select.select([self.dev.fd], [], [], 0)[0]:
                list(self.dev.read())
        except OSError:
            pass
        self.samples = []


def blank_console() -> None:
    """Stop the text console's cursor blinking over the UI."""
    for p in ("/sys/class/graphics/fbcon/cursor_blink",):
        try:
            Path(p).write_text("0")
        except OSError:
            pass
