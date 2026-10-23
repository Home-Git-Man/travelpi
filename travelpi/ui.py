"""Touch screens for the 480x320 display: Home, Wi-Fi (+ keyboard), VPN, Hotel login, More (travel Wi-Fi name and
password, devices, ad-block, speed test, power), Calibrate.
Each screen draws onto a PIL image and registers tap targets; App redraws when something changes."""
from __future__ import annotations

import subprocess
import threading
import time
from typing import Any, Callable

import qrcode
from PIL import Image, ImageDraw, ImageFont

from .config import NAME
from .screen import H, W, calibrate_from

BG, PANEL, LINE = (4, 7, 13), (11, 18, 32), (22, 40, 60)
CYAN, RED, GREEN, AMBER = (0, 229, 255), (255, 46, 91), (0, 229, 160), (255, 176, 32)
TEXT, BRIGHT, MUTED = (196, 211, 230), (241, 246, 255), (93, 115, 145)
SLEEP_AFTER = 180

_fonts: dict[tuple, ImageFont.FreeTypeFont] = {}


def font(size: int, bold: bool = False, mono: bool = False) -> ImageFont.FreeTypeFont:
    key = (size, bold, mono)
    if key not in _fonts:
        name = "DejaVuSansMono" if mono else "DejaVuSans"
        _fonts[key] = ImageFont.truetype(f"/usr/share/fonts/truetype/dejavu/{name}{'-Bold' if bold else ''}.ttf", size)
    return _fonts[key]


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return ""


STATUS = {  # status → (headline, colour)
    "protected": ("PROTECTED", GREEN), "blocked": ("BLOCKED", AMBER), "connecting": ("CONNECTING", AMBER),
    "portal": ("HOTEL LOGIN", CYAN), "portal_needed": ("LOGIN NEEDED", AMBER), "direct": ("NOT PROTECTED", RED),
    "offline": ("NO INTERNET", RED), "starting": ("STARTING", MUTED),
}


class Canvas:
    def __init__(self) -> None:
        self.img = Image.new("RGB", (W, H), BG)
        self.d = ImageDraw.Draw(self.img)
        self.targets: list[tuple[tuple[int, int, int, int], Callable[[], None]]] = []

    def panel(self, box: tuple[int, int, int, int], edge: tuple = CYAN, fill: tuple = PANEL) -> None:
        x0, y0, x1, y1 = box
        c = 10
        self.d.polygon([(x0, y0), (x1 - c, y0), (x1, y0 + c), (x1, y1), (x0, y1)], fill=fill, outline=LINE)
        self.d.line([(x0, y0), (x0, y1)], fill=edge, width=3)

    def text(self, xy: tuple[int, int], s: str, size: int = 16, colour: tuple = TEXT, bold: bool = False,
             mono: bool = False, anchor: str = "la", maxw: int = 0) -> None:
        f = font(size, bold, mono)
        if maxw:
            while s and self.d.textlength(s, font=f) > maxw:
                s = s[:-2] + "…" if len(s) > 2 else ""
        self.d.text(xy, s, font=f, fill=colour, anchor=anchor)

    def button(self, box: tuple[int, int, int, int], label: str, on: Callable[[], None], colour: tuple = CYAN,
               filled: bool = False, size: int = 17, sub: str = "") -> None:
        x0, y0, x1, y1 = box
        c = 8
        poly = [(x0, y0), (x1 - c, y0), (x1, y0 + c), (x1, y1), (x0 + c, y1), (x0, y1 - c)]
        self.d.polygon(poly, fill=tuple(int(v * .22) for v in colour) if filled else PANEL, outline=colour)
        cy = (y0 + y1) // 2 - (7 if sub else 0)
        self.text(((x0 + x1) // 2, cy), label, size, BRIGHT if filled else colour, bold=True, anchor="mm")
        if sub:
            self.text(((x0 + x1) // 2, cy + 17), sub, 11, MUTED, anchor="mm")
        self.targets.append(((x0, y0, x1, y1), on))

    def header(self, title: str, back: Callable[[], None] | None) -> None:
        self.d.rectangle((0, 0, W, 38), fill=PANEL)
        self.d.line([(0, 38), (W, 38)], fill=LINE)
        if back:
            self.button((4, 3, 70, 35), "‹ Back", back, MUTED, size=14)
        self.text((W // 2, 19), title, 17, CYAN, bold=True, anchor="mm")

    def hit(self, x: int, y: int) -> Callable[[], None] | None:
        for (x0, y0, x1, y1), fn in reversed(self.targets):
            if x0 - 4 <= x <= x1 + 4 and y0 - 4 <= y <= y1 + 4:
                return fn
        return None


def shield(c: Canvas, cx: int, cy: int, s: int, colour: tuple) -> None:
    pts = [(cx, cy - s), (cx + s * .8, cy - s * .65), (cx + s * .75, cy + s * .1), (cx, cy + s), (cx - s * .75, cy + s * .1),
           (cx - s * .8, cy - s * .65)]
    c.d.polygon(pts, outline=colour, width=3)
    c.d.line([(cx - s * .35, cy), (cx - s * .05, cy + s * .3), (cx + s * .4, cy - s * .3)], fill=colour, width=4)


def bars(c: Canvas, x: int, y: int, signal: int, colour: tuple = CYAN) -> None:
    for i in range(4):
        h = 4 + i * 4
        on = signal >= (i + 1) * 22
        c.d.rectangle((x + i * 6, y + 16 - h, x + i * 6 + 4, y + 16), fill=colour if on else LINE)


class App:
    def __init__(self, net: Any, fb: Any, touch: Any):
        self.net, self.fb, self.touch = net, fb, touch
        self.screen = "calibrate" if touch.cal is None else "home"
        self.args: dict[str, Any] = {}
        self.canvas = Canvas()
        self.last_tap = time.time()
        self.asleep = False
        self.toast: tuple[str, float] | None = None
        self.dirty = True
        self.sig = None
        self.cal_raw: list[tuple[int, int]] = []

    # ----- plumbing -----

    def go(self, screen: str, **args: Any) -> None:
        self.screen, self.args, self.dirty = screen, args, True

    def say(self, msg: str) -> None:
        self.toast = (msg, time.time() + 3.5)
        self.dirty = True

    def spawn(self, fn: Callable[[], Any], then: Callable[[Any], None]) -> None:
        def work() -> None:
            try:
                res = fn()
            except Exception as e:      # shown as a toast, never kills the screen
                res = e
            then(res)
            self.dirty = True
        threading.Thread(target=work, daemon=True).start()

    def run(self) -> None:
        while True:
            st = self.net.state
            t = st.get("toast")
            if t:
                st["toast"] = None
                self.say(t)
            sig = (st.get("status"), st.get("detail"), st.get("clients"), st.get("busy"), (st.get("uplink") or {}).get("name"),
                   (st.get("public") or {}).get("ip"), st.get("today", 0) // 10_000_000, time.strftime("%H:%M"))
            if sig != self.sig and self.screen in ("home", "portal", "speed"):
                self.dirty = True
            self.sig = sig
            if self.toast and time.time() > self.toast[1]:
                self.toast, self.dirty = None, True
            if not self.asleep and time.time() - self.last_tap > SLEEP_AFTER and self.screen != "calibrate":
                self.asleep = True
                self.go("home")
                self.fb.show(self.sleep_frame())
            if self.dirty and not self.asleep:
                self.dirty = False
                self.draw()
            tap = self.touch.poll(1.0)
            if not tap:
                continue
            x, y, raw = tap
            self.last_tap = time.time()
            if self.asleep:                     # first tap only wakes the screen
                self.asleep, self.dirty = False, True
                continue
            if self.screen == "calibrate":
                self.cal_tap(raw)
                continue
            fn = self.canvas.hit(x, y)
            if fn:
                fn()
                self.dirty = True

    def draw(self) -> None:
        self.canvas = Canvas()
        getattr(self, f"draw_{self.screen}")(self.canvas)
        if self.toast:
            c = self.canvas
            c.d.rectangle((40, H - 46, W - 40, H - 10), fill=(12, 30, 44), outline=CYAN)
            c.text((W // 2, H - 28), self.toast[0], 15, BRIGHT, anchor="mm", maxw=W - 100)
        self.fb.show(self.canvas.img)

    def sleep_frame(self) -> Image.Image:
        c = Canvas()
        colour = STATUS.get(self.net.state.get("status"), STATUS["starting"])[1]
        c.d.ellipse((W // 2 - 4, H // 2 - 4, W // 2 + 4, H // 2 + 4), fill=colour)
        return c.img

    # ----- Home -----

    def draw_home(self, c: Canvas) -> None:
        st = self.net.state
        head, colour = STATUS.get(st.get("status"), STATUS["starting"])
        c.d.rectangle((0, 0, W, 30), fill=PANEL)
        name = NAME.upper()[:16]
        c.text((12, 15), name, 15, BRIGHT, bold=True, anchor="lm")
        c.text((22 + int(c.d.textlength(name, font=font(15, True))), 15), "// SOC", 13, CYAN, anchor="lm")
        c.text((W - 12, 15), time.strftime("%H:%M"), 15, BRIGHT, mono=True, bold=True, anchor="rm")
        c.text((W - 70, 15), f"{st.get('clients', 0)} dev", 13, MUTED, anchor="rm")

        c.panel((8, 38, W - 8, 168), edge=colour)
        shield(c, 56, 92, 34, colour)
        c.text((104, 66), head, 28, colour, bold=True, anchor="lm")
        c.text((104, 98), st.get("busy") or st.get("detail") or "", 15, TEXT, anchor="lm", maxw=W - 124)
        pub, ex = st.get("public") or {}, st.get("exit")
        if pub:
            where = pub.get("country") or f"{pub.get('loc', '')} {pub.get('colo', '')}".strip()
            c.text((104, 124), f"{pub.get('ip', '')}  ·  {where}", 14, MUTED, mono=True, anchor="lm", maxw=W - 124)
        elif ex and st.get("status") in ("connecting",):
            c.text((104, 124), f"Exit: {ex['where']}", 14, MUTED, anchor="lm")
        up = st.get("uplink") or {}
        if up.get("connected"):
            c.text((104, 150), f"Wi-Fi: {up.get('name', '')}", 14, TEXT, anchor="lm", maxw=W - 170)
            if up.get("signal") is not None:
                bars(c, W - 50, 141, up["signal"])
        else:
            c.text((104, 150), "Wi-Fi: not connected", 14, AMBER, anchor="lm")

        phone = st.get("phone_today", 0)
        c.text((14, 186), f"Phone {human_bytes(phone)}" if phone else f"Today {human_bytes(st.get('today', 0))}", 13,
               AMBER if st.get("phone_warn") else MUTED, anchor="lm")
        c.text((W // 2, 186), self.net.modes.get(st.get("mode", "auto"), "").split(" –")[0].split(" (")[0], 13, MUTED, anchor="mm")
        ads = st.get("ads")
        c.text((W - 14, 186), f"{ads['blocked']:,} ads blocked" if ads else "", 13, GREEN if ads else MUTED, anchor="rm")
        c.targets.append(((0, 172, W * 2 // 3, 200), self.open_stats))         # tap data → Stats screen
        c.targets.append(((W * 2 // 3, 172, W, 200), lambda: self.go("adblock")))  # tap ads → Ad-block screen

        need_login = st.get("status") == "portal_needed"
        bw = (W - 8 * 5) // 4
        for i, (label, fn, col) in enumerate([
                ("Wi-Fi", self.open_wifi, CYAN), ("VPN", lambda: self.go("vpn"), CYAN),
                ("Hotel login", lambda: self.go("portal"), AMBER if need_login else CYAN),
                ("More", lambda: self.go("more"), CYAN)]):
            x0 = 8 + i * (bw + 8)
            c.button((x0, 206, x0 + bw, 310), label, fn, col, filled=(need_login and label == "Hotel login"),
                     size=16 if len(label) < 8 else 14)

    # ----- Wi-Fi -----

    def open_wifi(self) -> None:
        self.go("wifi", nets=None, page=0)
        self.spawn(self.net.scan, lambda nets: self.args.update(nets=nets if isinstance(nets, list) else []))

    def draw_wifi(self, c: Canvas) -> None:
        c.header("Wi-Fi networks", lambda: self.go("home"))
        c.button((W - 82, 3, W - 4, 35), "Scan", self.open_wifi, CYAN, size=14)
        nets = self.args.get("nets")
        if nets is None:
            c.text((W // 2, H // 2), "Scanning…", 18, MUTED, anchor="mm")
            return
        if not nets:
            c.text((W // 2, H // 2), "No networks found – tap Scan", 16, MUTED, anchor="mm")
            return
        per, page = 5, self.args.get("page", 0)
        rows = nets[page * per:(page + 1) * per]
        for i, n in enumerate(rows):
            y0 = 44 + i * 46
            box = (6, y0, W - 66, y0 + 42)
            col = GREEN if n["active"] else CYAN

            def pick(n: dict = n) -> None:
                if n["active"]:
                    self.say(f"Already on {n['ssid']}")
                elif n["known"] or not n["secure"]:
                    self.join(n["ssid"], None)
                else:
                    self.ask_password(n["ssid"])
            c.panel(box, edge=col)
            c.targets.append((box, pick))
            c.text((18, y0 + 21), n["ssid"], 16, BRIGHT if n["active"] else TEXT, bold=n["active"], anchor="lm", maxw=W - 190)
            tag = "connected" if n["active"] else "saved" if n["known"] else ("🔒" if n["secure"] else "open")
            c.text((W - 112, y0 + 21), tag if tag != "🔒" else "locked", 11, MUTED, anchor="rm")
            bars(c, W - 104, y0 + 12, n["signal"], col)
        pages = (len(nets) + per - 1) // per
        if page > 0:
            c.button((W - 58, 44, W - 6, 132), "▲", lambda: self.args.update(page=page - 1), CYAN)
        if page < pages - 1:
            c.button((W - 58, 182, W - 6, 270), "▼", lambda: self.args.update(page=page + 1), CYAN)
        c.text((W - 32, 157), f"{page + 1}/{pages}", 12, MUTED, anchor="mm")
        if self.net.state.get("busy"):
            c.text((W // 2, H - 16), self.net.state["busy"], 14, AMBER, anchor="mm")

    def join(self, ssid: str, password: str | None) -> None:
        self.go("home")
        self.say(f"Joining {ssid}…")

        def done(err: Any) -> None:
            if err:
                self.say(f"{ssid}: {err}")
                if password is not None:
                    self.ask_password(ssid, password)
            else:
                self.say(f"Connected to {ssid}")
        self.spawn(lambda: self.net.connect(ssid, password), done)

    # ----- keyboard -----

    def keyboard(self, title: str, text: str, done: Callable[[str], None], ok: str = "Join",
                 back: Callable[[], None] | None = None, show: bool = False) -> None:
        self.go("keyboard", title=title, text=text, done=done, ok=ok, back=back or self.open_wifi, layer=0, shift=False,
                show=show)

    def ask_password(self, ssid: str, text: str = "") -> None:
        self.keyboard(f"Password: {ssid}", text, lambda pw: self.join(ssid, pw))

    LAYERS = [["qwertyuiop", "asdfghjkl", "zxcvbnm"], ["1234567890", "-_@#$%&*!?", ".,:;'\"/+="]]

    def draw_keyboard(self, c: Canvas) -> None:
        a = self.args
        c.header(a["title"][:34], a["back"])
        txt = a["text"] if a["show"] else "•" * len(a["text"])
        c.panel((6, 44, W - 6, 82))
        c.text((16, 63), txt[-34:] + "_", 18, BRIGHT, mono=True, anchor="lm")
        layer = self.LAYERS[a["layer"]]
        kw, kh, y = 46, 44, 88
        for r, row in enumerate(layer):
            x = (W - len(row) * (kw + 2)) // 2 - (24 if r == 2 else 0)
            for ch in row:
                ch2 = ch.upper() if a["shift"] and a["layer"] == 0 else ch
                c.button((x, y, x + kw, y + kh), ch2, lambda ch2=ch2: self.type(ch2), CYAN, size=18)
                x += kw + 2
            if r == 2:
                c.button((x + 4, y, x + 4 + 70, y + kh), "⌫", lambda: a.update(text=a["text"][:-1]), AMBER, size=18)
            y += kh + 3
        y += 2
        c.button((4, y, 74, y + 40), "123" if a["layer"] == 0 else "abc", lambda: a.update(layer=1 - a["layer"]), MUTED, size=14)
        c.button((78, y, 140, y + 40), "⇧", lambda: a.update(shift=not a["shift"]), CYAN if a["shift"] else MUTED, filled=a["shift"])
        c.button((144, y, 300, y + 40), "space", lambda: self.type(" "), MUTED, size=14)
        c.button((304, y, 370, y + 40), "hide" if a["show"] else "show", lambda: a.update(show=not a["show"]), MUTED, size=13)
        c.button((374, y, W - 4, y + 40), a["ok"], lambda: a["done"](a["text"]), GREEN, filled=True, size=14)

    def type(self, ch: str) -> None:
        self.args["text"] += ch
        if self.args["shift"]:
            self.args["shift"] = False

    # ----- VPN -----

    def draw_vpn(self, c: Canvas) -> None:
        c.header("VPN", lambda: self.go("home"))
        cur = self.net.state.get("mode", "auto")
        colours = {"auto": GREEN, "direct": RED, "block": AMBER}
        modes = list(self.net.modes.items())
        cols = 3
        rows = (len(modes) + cols - 1) // cols
        bw, bh = (W - 8 * (cols + 1)) // cols, min(64, (H - 46 - 6 * rows) // rows)
        for i, (mode, text) in enumerate(modes):
            x0, y0 = 8 + (i % cols) * (bw + 8), 44 + (i // cols) * (bh + 6)
            label, sub = text.split(" – ")[0].split(" (")[0], (text.split(" – ")[1] if " – " in text else "")
            ex = self.net.exit(mode)
            if ex and ex.get("sub"):
                sub = ex["sub"]
            act = (lambda: self.go("confirm", text="Turn the VPN off? Devices will NOT be protected.",
                                   yes=lambda: (self.net.set_mode("direct"), self.go("home")))) if mode == "direct" \
                else (lambda m=mode: (self.net.set_mode(m), self.go("home")))
            c.button((x0, y0, x0 + bw, y0 + bh), f"{label}{' ✓' if cur == mode else ''}", act, colours.get(mode, CYAN),
                     filled=cur == mode, size=14 if len(label) < 12 else 12, sub=sub[:22])

    # ----- hotel login -----

    def draw_portal(self, c: Canvas) -> None:
        c.header("Hotel / airport login", lambda: self.go("home"))
        ap = self.net.ap_info()
        open_now = self.net.state.get("status") == "portal"
        steps = ["1. Tap Start below", f"2. On your phone join {ap['ssid'] or 'the travel Wi-Fi'}",
                 "3. The hotel page pops up –", "    sign in there", "4. The VPN comes back by itself"]
        for i, s in enumerate(steps):
            c.text((14, 58 + i * 24), s, 15, TEXT, maxw=W - 150)
        qr = self.wifi_qr(ap, 118)
        if qr:
            c.img.paste(qr, (W - 128, 46))
        c.text((14, 182), "If the page doesn't open, browse to any http:// site.", 12, MUTED)
        if open_now:
            c.button((8, 206, W // 2 - 4, 310), "I'm signed in", lambda: (self.net.end_portal(), self.go("home")), GREEN, filled=True)
            c.button((W // 2 + 4, 206, W - 8, 310), "Cancel", lambda: (self.net.end_portal(), self.go("home")), MUTED)
        else:
            c.button((8, 206, W - 8, 310), "Start hotel login", lambda: self.net.start_portal(), AMBER, filled=True,
                     sub="Opens the network for 10 minutes – VPN is off meanwhile")

    @staticmethod
    def wifi_qr(ap: dict, size: int) -> Image.Image | None:
        if not ap.get("ssid"):
            return None
        esc = lambda s: "".join("\\" + ch if ch in '\\;,":' else ch for ch in s)
        q = qrcode.QRCode(border=2, box_size=3)
        q.add_data(f"WIFI:T:WPA;S:{esc(ap['ssid'])};P:{esc(ap['password'])};;")
        img = q.make_image(fill_color="black", back_color="white").get_image().convert("RGB")
        return img.resize((size, size), Image.NEAREST)

    # ----- more -----

    def draw_more(self, c: Canvas) -> None:
        c.header("Travel Wi-Fi & device", lambda: self.go("home"))
        ap = self.net.ap_info()
        qr = self.wifi_qr(ap, 112)
        if qr:
            c.img.paste(qr, (8, 44))
        c.text((130, 50), "Join", 12, MUTED)
        c.text((130, 66), ap["ssid"], 17, BRIGHT, bold=True, maxw=200)
        c.text((130, 92), ap["password"], 17, BRIGHT, mono=True, maxw=200)
        c.text((130, 122), "Phone control page", 12, MUTED)
        c.text((130, 138), "http://10.42.0.1", 15, CYAN, mono=True)
        page = self.url_qr("http://10.42.0.1", 92)
        c.img.paste(page, (W - 100, 46))
        bw = (W - 8 * 6) // 5
        acts = [("Devices", self.open_devices, CYAN), ("Ad-block", lambda: self.go("adblock"), GREEN),
                ("Speed", lambda: self.go("speed"), CYAN), ("Wi-Fi name", self.edit_ap, CYAN),
                ("Power", lambda: self.go("power"), AMBER)]
        for i, (label, fn, col) in enumerate(acts):
            x0 = 8 + i * (bw + 8)
            c.button((x0, 170, x0 + bw, 250), label, fn, col, size=14 if len(label) < 8 else 12)
        c.text((W // 2, 280), "Everything here also works from the phone page – even without this screen", 11, MUTED, anchor="mm")

    def edit_ap(self) -> None:
        """Rename the travel Wi-Fi / change its password: name, then password, then confirm."""
        ap = self.net.ap_info()
        more = lambda: self.go("more")

        def got_name(name: str) -> None:
            if not name.strip():
                return self.say("The Wi-Fi name can't be empty")
            self.keyboard("New password (8+)", ap["password"], lambda pw: got_password(name.strip(), pw), ok="Save",
                          back=more, show=True)

        def got_password(name: str, pw: str) -> None:
            if len(pw) < 8:
                return self.say("The password needs 8 or more characters")
            self.go("confirm", text=f"Change the travel Wi-Fi to {name}? Every device drops off and joins again with "
                                    "the new password.", yes=lambda: save(name, pw))

        def save(name: str, pw: str) -> None:
            self.go("more")
            self.say("Restarting the travel Wi-Fi…")
            self.spawn(lambda: self.net.set_ap(name, pw), lambda err: self.say(str(err) if err else f"Travel Wi-Fi is now {name}"))
        self.keyboard("Travel Wi-Fi name", ap["ssid"], got_name, ok="Next", back=more, show=True)

    @staticmethod
    def url_qr(url: str, size: int) -> Image.Image:
        q = qrcode.QRCode(border=2, box_size=3)
        q.add_data(url)
        return q.make_image(fill_color="black", back_color="white").get_image().convert("RGB").resize((size, size), Image.NEAREST)

    def draw_power(self, c: Canvas) -> None:
        c.header("Power", lambda: self.go("more"))
        bw = (W - 8 * 4) // 3
        acts = [("Calibrate", lambda: self.go("calibrate"), CYAN, "touch"),
                ("Reboot", lambda: self.go("confirm", text="Reboot the travel router?", yes=lambda: self.power("reboot")), AMBER, ""),
                ("Shut down", lambda: self.go("confirm", text="Shut down? Unplug once the screen goes still.",
                                              yes=lambda: self.power("poweroff")), RED, "")]
        for i, (label, fn, col, sub) in enumerate(acts):
            x0 = 8 + i * (bw + 8)
            c.button((x0, 120, x0 + bw, 220), label, fn, col, sub=sub)

    # ----- stats: ads blocked + data per device -----

    def open_stats(self) -> None:
        self.go("stats", devs=None)
        self.spawn(self.net.devices, lambda d: self.args.update(devs=d if isinstance(d, list) else []))

    def draw_stats(self, c: Canvas) -> None:
        c.header("Today's stats", lambda: self.go("home"))
        ads = self.net.state.get("ads") or {}
        c.panel((6, 44, 236, 150), edge=GREEN)
        c.text((121, 82), f"{ads.get('blocked', 0):,}" if ads else "–", 30, GREEN, bold=True, mono=True, anchor="mm")
        c.text((121, 112), "ads & trackers blocked", 12, MUTED, anchor="mm")
        c.text((121, 130), f"{ads.get('pct', 0)}% of {ads.get('queries', 0):,} lookups · 24 h" if ads else "AdGuard not reachable",
               11, MUTED, anchor="mm")
        c.panel((244, 44, W - 6, 150), edge=CYAN)
        c.text((254, 58), "Most blocked", 11, MUTED)
        for i, dom in enumerate((ads.get("top") or [])[:4]):
            c.text((254, 78 + i * 18), dom, 12, TEXT, maxw=W - 268)
        st = self.net.state
        c.text((10, 166), f"Data today {human_bytes(st.get('today', 0))}" + (f" · phone {human_bytes(st['phone_today'])}"
               if st.get("phone_today") else ""), 13, BRIGHT, bold=True)
        devs = sorted(self.args.get("devs") or [], key=lambda d: -d.get("today", 0))
        if self.args.get("devs") is None:
            c.text((W // 2, 240), "Loading…", 15, MUTED, anchor="mm")
        for i, d in enumerate(devs[:5]):
            y = 192 + i * 24
            c.text((14, y), d["name"] or d["ip"] or d["mac"], 14, TEXT if d["online"] else MUTED, maxw=280)
            c.text((W - 14, y), human_bytes(d.get("today", 0)), 14, BRIGHT, mono=True, anchor="ra")

    # ----- ad-block: AdGuard Home on the Pi -----

    def adblock(self, minutes: int) -> None:
        """Pause (minutes) or turn back on (0); the numbers refresh when AdGuard answers."""
        self.args["busy"] = True
        def done(r: Any) -> None:
            self.args["busy"] = False
            if isinstance(r, dict):
                self.net.state["ads"] = r
            else:
                self.say(f"AdGuard: {r}")
        self.spawn(lambda: self.net.adblock(minutes), done)

    def draw_adblock(self, c: Canvas) -> None:
        c.header("Ad-block", lambda: self.go("home"))
        ads = self.net.state.get("ads")
        if not ads:
            c.text((W // 2, 150), "AdGuard isn't answering", 17, AMBER, bold=True, anchor="mm")
            c.text((W // 2, 176), "DNS for the travel Wi-Fi runs on this router – try again in a minute", 11, MUTED,
                   anchor="mm", maxw=W - 20)
            return
        on = ads.get("on", True)
        edge = GREEN if on else AMBER
        c.panel((6, 44, 196, 150), edge=edge)
        c.text((101, 80), f"{ads['blocked']:,}", 30, edge, bold=True, mono=True, anchor="mm")
        c.text((101, 108), "blocked · 24 h", 12, MUTED, anchor="mm")
        c.text((101, 128), f"{ads['pct']}% of {ads['queries']:,} lookups", 11, MUTED, anchor="mm")
        c.panel((204, 44, W - 6, 150), edge=CYAN)
        c.text((214, 54), "Most blocked", 11, MUTED)
        for i, dom in enumerate((ads.get("top") or [])[:4]):
            c.text((214, 72 + i * 18), dom, 12, TEXT, maxw=W - 228)
        c.text((10, 158), "Devices · lookups today", 11, MUTED)
        for i, cl in enumerate((ads.get("clients") or [])[:3]):
            y = 174 + i * 20
            c.text((14, y), cl["name"], 13, TEXT, maxw=W - 110)
            c.text((W - 14, y), f"{cl['queries']:,}", 13, BRIGHT, mono=True, anchor="ra")
        state = "Protection on" if on else f"Paused – back on in {ads.get('paused_min') or 0} min"
        c.text((10, 240), f"{state} · {ads.get('ms', 0)} ms per lookup", 12, edge)
        busy = self.args.get("busy")
        label, fn, col = (("Pause 10 min", lambda: self.adblock(10), AMBER) if on
                          else ("Turn back on", lambda: self.adblock(0), GREEN))
        c.button((8, 260, W // 2 - 4, 312), "Working…" if busy else label, fn, col, size=16)
        c.button((W // 2 + 4, 260, W - 8, 312), "Data per device", self.open_stats, CYAN, size=16)

    # ----- devices: kids mode + hotel address -----

    def open_devices(self) -> None:
        self.go("devices", devs=None, page=0, clone="")
        def load() -> tuple:
            return self.net.devices(), self.net.clone_state()
        self.spawn(load, lambda r: self.args.update(devs=r[0], clone=r[1]) if isinstance(r, tuple) else self.args.update(devs=[]))

    def draw_devices(self, c: Canvas) -> None:
        c.header("Devices", lambda: self.go("more"))
        devs = self.args.get("devs")
        if devs is None:
            c.text((W // 2, H // 2), "Loading…", 18, MUTED, anchor="mm")
            return
        if not devs:
            c.text((W // 2, H // 2), "No devices on the travel Wi-Fi yet", 16, MUTED, anchor="mm")
            return
        per, page = 4, self.args.get("page", 0)
        for i, d in enumerate(devs[page * per:(page + 1) * per]):
            y0 = 44 + i * 58
            hotel = self.args.get("clone") == d["mac"]
            c.panel((6, y0, W - 66, y0 + 54), edge=GREEN if d["online"] else MUTED)
            c.text((16, y0 + 16), d["name"] or "Unknown device", 15, BRIGHT, bold=True, maxw=170)
            c.text((16, y0 + 38), f"{d['ip'] or d['mac']} · {human_bytes(d.get('today', 0))}", 12, MUTED, mono=True, maxw=175)
            c.button((196, y0 + 6, 296, y0 + 48), "Kids on" if d["kids"] else "Kids off",
                     lambda d=d: (self.net.set_kids(d["mac"], not d["kids"]), self.open_devices()),
                     GREEN if d["kids"] else MUTED, filled=d["kids"], size=13)
            c.button((300, y0 + 6, W - 72, y0 + 48), "Hotel ✓" if hotel else "Use for hotel",
                     lambda d=d, hotel=hotel: self.go("confirm", text="Reset the hotel Wi-Fi address?" if hotel else
                                                      f"Use {d['name'] or 'this device'}'s address on the hotel Wi-Fi?",
                                                      yes=lambda: self.do_clone(None if hotel else d["mac"])),
                     CYAN, filled=hotel, size=12)
        pages = (len(devs) + per - 1) // per
        if page > 0:
            c.button((W - 58, 44, W - 6, 132), "▲", lambda: self.args.update(page=page - 1), CYAN)
        if page < pages - 1:
            c.button((W - 58, 182, W - 6, 270), "▼", lambda: self.args.update(page=page + 1), CYAN)

    def do_clone(self, mac: str | None) -> None:
        self.go("home")
        self.say("Reconnecting with the new address…")
        self.spawn(lambda: self.net.clone(mac), lambda err: self.say(err or "Hotel address updated"))

    # ----- speed test -----

    def draw_speed(self, c: Canvas) -> None:
        c.header("Speed test", lambda: self.go("more"))
        sp = self.net.state.get("speed") or {}
        busy = self.net.state.get("busy")
        cells = [("VPN", sp.get("vpn"), "Mbps"), ("Hotel line", sp.get("line"), "Mbps"), ("Latency", sp.get("ping"), "ms")]
        for i, (label, v, unit) in enumerate(cells):
            x0 = 8 + i * 156
            c.panel((x0, 50, x0 + 148, 150), edge=CYAN)
            c.text((x0 + 74, 92), "–" if v is None else str(v), 30, BRIGHT, bold=True, mono=True, anchor="mm")
            c.text((x0 + 74, 128), f"{label} · {unit}", 12, MUTED, anchor="mm")
        if sp.get("at"):
            c.text((W // 2, 168), time.strftime("Last run %d %b %H:%M", time.localtime(sp["at"])) + f" · uses {sp.get('mb', 25) * 2} MB",
                   12, MUTED, anchor="mm")
        if busy:
            c.text((W // 2, 250), busy, 18, AMBER, bold=True, anchor="mm")
        else:
            c.button((8, 200, W - 8, 300), "Run speed test", lambda: self.spawn(self.net.speedtest, lambda r: None), CYAN, filled=True,
                     sub="About 20 seconds")

    def power(self, what: str) -> None:
        c = Canvas()
        c.text((W // 2, H // 2), "Rebooting…" if what == "reboot" else "Shutting down…", 22, AMBER, bold=True, anchor="mm")
        self.fb.show(c.img)
        subprocess.Popen(["systemctl", what])

    # ----- confirm -----

    def draw_confirm(self, c: Canvas) -> None:
        c.panel((20, 60, W - 20, 250), edge=AMBER)
        words, line, lines = self.args["text"].split(), "", []
        for w in words:
            if c.d.textlength(f"{line} {w}", font=font(18)) > W - 80:
                lines.append(line)
                line = w
            else:
                line = f"{line} {w}".strip()
        lines.append(line)
        for i, s in enumerate(lines):
            c.text((W // 2, 100 + i * 26), s, 18, BRIGHT, anchor="mm")
        c.button((40, 180, W // 2 - 10, 236), "Yes", self.args["yes"], RED, filled=True)
        c.button((W // 2 + 10, 180, W - 40, 236), "No", lambda: self.go("home"), MUTED)

    # ----- touch calibration -----

    CAL_PTS = [(40, 40), (440, 40), (40, 280)]

    def draw_calibrate(self, c: Canvas) -> None:
        i = len(self.cal_raw)
        x, y = self.CAL_PTS[i]
        c.text((W // 2, H // 2 - 10), "Touch calibration", 20, CYAN, bold=True, anchor="mm")
        c.text((W // 2, H // 2 + 20), f"Press the centre of the cross firmly ({i + 1}/3)", 14, TEXT, anchor="mm")
        c.d.line([(x - 18, y), (x + 18, y)], fill=AMBER, width=3)
        c.d.line([(x, y - 18), (x, y + 18)], fill=AMBER, width=3)
        c.d.ellipse((x - 5, y - 5, x + 5, y + 5), outline=AMBER, width=2)

    def cal_tap(self, raw: tuple[int, int]) -> None:
        self.cal_raw.append(raw)
        if len(self.cal_raw) == 3:
            self.touch.save(calibrate_from(self.cal_raw, self.CAL_PTS))
            self.cal_raw = []
            self.go("home")
            self.say("Touch calibrated")
        self.dirty = True
        time.sleep(0.3)
        self.touch.drain()
