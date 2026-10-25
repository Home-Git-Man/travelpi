"""Control page for phones on the travel Wi-Fi (http://10.42.0.1 or http://travelpi) and a small JSON API (also used
by Sentinel over Tailscale). Devices on our Wi-Fi need no login (they already know the Wi-Fi password) – except that
devices in kids mode can only look, not change anything; anything else needs the token in /etc/travelpi/api.token.
Hotel networks can't reach this port at all (firewall input chain).
The page does everything the touch screen does, so the router can be run without one (or with a broken one).
Loading it from the travel Wi-Fi also confirms a fresh network setup (no rollback)."""
from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import subprocess
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import iptv, kodi, library
from .config import AP_NET, ETC, NAME, WEB_PORT
from .wg import COUNTRY

log = logging.getLogger("travelpi.web")
PAGE = Path(__file__).with_name("page.html")
HLSJS = Path(__file__).with_name("hls.min.js")
LOCAL = ipaddress.ip_network(AP_NET)


def allowed(client_ip: str, token_header: str, token: str) -> bool:
    try:
        if ipaddress.ip_address(client_ip) in LOCAL:
            return True
    except ValueError:
        return False
    return bool(token) and hmac.compare_digest(token_header or "", token)


def public_state(net: Any) -> dict[str, Any]:
    st = {k: v for k, v in net.state.items() if k != "toast"}
    st["modes"] = net.modes
    st["name"] = NAME
    st["vpns"] = [{"id": e["id"], "label": e["label"], "where": e["where"], "kind": e["kind"], "cc": e.get("cc", "")}
                  for e in net.exits]
    st["countries"] = COUNTRY
    return st


KIDS_OK = {"/api/tv/remote", "/api/tv/channel", "/api/tv/play"}


def kids_device(client_ip: str, leases: list[dict[str, str]], kids: set[str]) -> bool:
    """Is this address one of the devices in kids mode? (they may look at the page but not change things)"""
    return any(d["ip"] == client_ip and d["mac"] in kids for d in leases)


class Handler(BaseHTTPRequestHandler):
    net: Any = None
    token = ""

    def log_message(self, fmt: str, *args: Any) -> None:   # quiet
        pass

    def _send(self, code: int, body: Any, ctype: str = "application/json") -> None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _pump(self, resp: Any) -> None:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            try:
                self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError):
                break

    def _relay(self, url: str, ua: str = "", ref: str = "") -> None:
        """Relay an IPTV stream to the device: rewrite HLS playlists back through here, stream segments straight. The
        upstream fetch goes over the VPN (iptv.open_url) and refuses local/private/tailnet addresses (SSRF guard).
        `ua`/`ref` are the channel's required User-Agent/Referer (many streams 403 without them)."""
        if not url:
            return self._send(400, {"error": "no url"})
        fwd = {}
        rng = self.headers.get("Range")              # players use byte ranges for video/seeking – pass them upstream
        if rng:
            fwd["Range"] = rng
        if ua:
            fwd["User-Agent"] = ua
        if ref:
            fwd["Referer"] = ref
            rp = urllib.parse.urlsplit(ref)
            if rp.scheme and rp.netloc:
                fwd["Origin"] = f"{rp.scheme}://{rp.netloc}"
        try:
            resp = iptv.open_url(url, timeout=15, headers=fwd)
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:                       # upstream timeout / DNS / TLS – the channel is just down
            return self._send(502, {"error": str(e)[:120]})
        try:
            ctype = resp.headers.get("Content-Type", "")
            head = b""
            is_pl = url.split("?")[0].lower().endswith((".m3u8", ".m3u")) or "mpegurl" in ctype.lower()
            if not is_pl:                            # peek: a playlist served with a generic type/extension
                head = resp.read(64)
                is_pl = head.lstrip()[:7] == b"#EXTM3U"
            if is_pl:
                text = (head + resp.read(6_000_000)).decode("utf-8", "replace")
                suffix = (("&ua=" + urllib.parse.quote(ua, safe="")) if ua else "") + \
                         (("&ref=" + urllib.parse.quote(ref, safe="")) if ref else "")
                prox = lambda u: "/tv/stream?u=" + urllib.parse.quote(u, safe="") + suffix
                data = iptv.rewrite_playlist(text, resp.geturl(), prox).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.apple.mpegurl")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            self.send_response(resp.status)         # 206 when the player asked for a byte range
            self.send_header("Content-Type", ctype or "video/mp2t")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-store")
            for hdr in ("Content-Length", "Content-Range", "Accept-Ranges"):
                v = resp.headers.get(hdr)
                if v:
                    self.send_header(hdr, v)
            self.end_headers()
            if head:
                self.wfile.write(head)
            self._pump(resp)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            resp.close()

    def _ok(self, change: bool = False) -> bool:
        ip = self.client_address[0]
        if not allowed(ip, self.headers.get("X-Token", ""), self.token):
            self._send(403, {"error": "forbidden"})
            return False
        if change and self.path.split("?")[0] in KIDS_OK:      # the TV remote is fine for everyone
            return True
        if change and self.net.kids and kids_device(ip, self.net._leases(), self.net.kids):
            self._send(403, {"error": "Kids-mode devices can't change the router's settings"})
            return False
        return True

    def do_GET(self) -> None:
        if not self._ok():
            return
        path, _, query = self.path.partition("?")
        qs = {k: v[0] for k, v in urllib.parse.parse_qs(query).items()}
        try:
            if path == "/api/tv/now":
                return self._send(200, {**kodi.now_playing(), "library": library.name()})
            if path == "/api/tv/lists":
                src = kodi.current_sources()
                return self._send(200, {"selected": src["codes"], "custom": src["custom"], "choices": kodi.LIST_CHOICES})
            if path == "/api/tv/channels":
                return self._send(200, {"channels": kodi.channels(qs.get("q", ""), qs.get("group", ""))})
            if path == "/api/tv/groups":
                names = {n.lower() for n in COUNTRY.values()}
                return self._send(200, kodi.groups(names))
            if path == "/api/library":
                return self._send(200, library.browse(qs.get("view", ""), qs.get("key", ""), qs.get("q", "")))
            if path == "/api/library/thumb":
                data, ctype = library.thumb(qs.get("path", ""))
                return self._send(200, data, ctype)
            if path == "/api/tv/webchannels":
                return self._send(200, {"channels": iptv.channels(qs.get("refresh") == "1")})
            if path == "/tv/stream":
                return self._relay(qs.get("u", ""), qs.get("ua", ""), qs.get("ref", ""))
            if path == "/hls.js":
                return self._send(200, HLSJS.read_bytes(), "application/javascript; charset=utf-8")
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        if path == "/":
            confirm_setup(self.client_address[0])
            return self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        if path == "/api/ap":
            return self._send(200, self.net.ap_info())
        if path == "/api/settings":
            return self._send(200, self.net.settings_view())
        if path == "/api/state":
            return self._send(200, public_state(self.net))
        if path == "/api/devices":
            return self._send(200, {"devices": self.net.devices(), "clone": self.net.clone_state()})
        if path == "/api/adblock":
            return self._send(200, self.net.adblock_overview())
        if path == "/api/wifi":
            nets = self.net.scan()
            for n in nets:
                n["backup"] = n["ssid"] in self.net.backup
            return self._send(200, {"networks": nets})
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._ok(change=True):
            return
        # a custom header forces a CORS preflight, so other web pages can't drive this from a browser
        if self.headers.get("X-TravelPi") != "1":
            return self._send(400, {"error": "missing header"})
        try:
            body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 65536)) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        n, path = self.net, self.path.split("?")[0]
        try:
            if path == "/api/mode" and body.get("mode") in n.modes:
                n.set_mode(body["mode"])
                return self._send(200, {"ok": True})
            if path == "/api/portal":
                (n.start_portal if body.get("action") == "start" else n.end_portal)()
                return self._send(200, {"ok": True})
            if path == "/api/wifi/join" and body.get("ssid"):
                err = n.connect(body["ssid"], body.get("password") or None)
                if not err and "backup" in body:
                    n.set_backup(body["ssid"], bool(body["backup"]))
                return self._send(200, {"ok": not err, "error": err})
            if path == "/api/wifi/backup" and body.get("ssid"):
                n.set_backup(body["ssid"], bool(body.get("on")))
                return self._send(200, {"ok": True})
            if path == "/api/wifi/forget" and body.get("ssid"):
                n.forget(body["ssid"])
                return self._send(200, {"ok": True})
            if path == "/api/kids" and body.get("mac"):
                n.set_kids(body["mac"], bool(body.get("on")))
                return self._send(200, {"ok": True})
            if path == "/api/clone":
                err = n.clone(body.get("mac") or None)
                return self._send(200, {"ok": not err, "error": err})
            if path == "/api/precheck":
                return self._send(200, {"ok": True, "report": n.precheck()})
            if path == "/api/adblock":
                return self._send(200, {"ok": True, **n.adblock_action(body)})
            if path == "/api/speedtest":
                return self._send(200, {"ok": True, "result": n.speedtest()})
            if path == "/api/ap":
                n.set_ap(str(body.get("ssid") or ""), str(body.get("password") or ""))
                return self._send(200, {"ok": True})
            if path == "/api/vpn/add":
                name = n.add_vpn(str(body.get("provider") or ""), str(body.get("country") or ""), str(body.get("conf") or ""))
                return self._send(200, {"ok": True, "id": name})
            if path == "/api/vpn/remove":
                n.remove_vpn(str(body.get("id") or ""))
                return self._send(200, {"ok": True})
            if path == "/api/tv":
                n.tv(str(body.get("action") or ""))
                return self._send(200, {"ok": True})
            if path == "/api/tv/remote":
                kodi.press(str(body.get("button") or ""))
                return self._send(200, {"ok": True})
            if path == "/api/tv/lists":
                restarted = kodi.set_sources(body.get("lists"), body.get("custom"))
                return self._send(200, {"ok": True, "restarted": restarted})
            if path == "/api/tv/channel":
                kodi.play_channel(int(body.get("id") or 0))
                return self._send(200, {"ok": True})
            if path == "/api/tv/play":
                url, resume = library.stream(str(body.get("key") or ""))
                kodi.play_file(url, resume if body.get("resume", True) else 0)
                return self._send(200, {"ok": True})
            if path == "/api/settings":
                n.apply_settings(body)
                return self._send(200, {"ok": True, "restarting": True})
            if path == "/api/power" and body.get("action") in ("reboot", "poweroff"):
                n.save_usage()
                threading.Timer(2, subprocess.Popen, args=(["systemctl", body["action"]],)).start()
                return self._send(200, {"ok": True})
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        except RuntimeError as e:                 # a command on the Pi failed (e.g. nmcli)
            return self._send(500, {"error": str(e)[:200]})
        self._send(404, {"error": "not found"})


def confirm_setup(client_ip: str) -> None:
    """A phone on the travel Wi-Fi reached this page, so the new network setup works: stop the 7-minute rollback."""
    f = ETC / "net-confirmed"
    try:
        if not f.exists() and ipaddress.ip_address(client_ip) in LOCAL:
            f.touch()
            log.info("network setup confirmed from %s", client_ip)
    except (OSError, ValueError):
        pass


def serve(net: Any) -> None:
    try:
        Handler.token = (ETC / "api.token").read_text().strip()
    except OSError:
        Handler.token = ""
    Handler.net = net
    srv = ThreadingHTTPServer(("0.0.0.0", WEB_PORT), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True, name="web").start()
    log.info("control page on port %s", WEB_PORT)
