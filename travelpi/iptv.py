"""Watch the Live TV channels in a browser on a device on the travel Wi-Fi – no TV/Kodi needed.

The Pi relays the HLS stream to the device (same-origin, so every browser plays it, and routed through the VPN exactly
like Kodi: the upstream socket is tagged with fwmark 0x33, which net.py's rule sends into the tunnel). The channel list
is parsed from the same iptv-org lists / custom m3u the TV uses, so "watch here" and "watch on the TV" show the same
channels. An SSRF guard keeps the relay from being pointed at the home network, link-local or the tailnet."""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import time
import urllib.parse
import urllib.request
from typing import Any, Iterator

from . import kodi

SO_MARK = 36                       # Linux SO_MARK option number: tags the fetch so the 0x33 rule routes it via the VPN
VPN_MARK = 0x33
UA = "VLC/3.0.20 (TravelPi)"       # a media-player UA – some IPTV hosts reject the default urllib one
TTL = 1800                         # re-read the channel lists at most every 30 minutes
MAX_CH = 3000                      # cap (the iptv-org "index" list is 10,000+; the UI searches)
TAILNET = ipaddress.ip_network("100.64.0.0/10")

_cache: dict[str, Any] = {"at": 0.0, "key": None, "channels": []}


# ---------- marked, SSRF-guarded fetch (upstream rides the VPN) ----------
def _blocked(host: str) -> bool:
    """True if the host resolves to something the relay must never reach (home LAN, loopback, link-local, tailnet)."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return True
    for *_, sa in infos:
        try:
            ip = ipaddress.ip_address(sa[0])
        except ValueError:
            return True
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
                or ip.is_unspecified or (ip.version == 4 and ip in TAILNET)):
            return True
    return False


def _sock(address: tuple, timeout: float | None) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, SO_MARK, VPN_MARK)
    except OSError:
        pass                        # not root / no CAP_NET_ADMIN – falls back to normal routing
    s.settimeout(timeout)
    s.connect(address)
    return s


class _HTTPConn(http.client.HTTPConnection):
    def connect(self) -> None:
        if _blocked(self.host):
            raise ValueError("blocked address")
        self.sock = _sock((self.host, self.port), self.timeout)


class _HTTPSConn(http.client.HTTPSConnection):
    def connect(self) -> None:
        if _blocked(self.host):
            raise ValueError("blocked address")
        self.sock = self._context.wrap_socket(_sock((self.host, self.port), self.timeout), server_hostname=self.host)


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req: Any) -> Any:
        return self.do_open(_HTTPConn, req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req: Any) -> Any:
        return self.do_open(_HTTPSConn, req)


_opener = urllib.request.build_opener(_HTTPHandler, _HTTPSHandler)


def open_url(url: str, timeout: float = 15, headers: dict[str, str] | None = None) -> Any:
    """Open an http(s) URL over the VPN (fwmark 0x33), refusing local/private/tailnet destinations. Follows redirects
    (each hop is re-checked in connect()). `headers` adds request headers (e.g. a Range forwarded from the player)."""
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname or _blocked(p.hostname):
        raise ValueError("blocked url")
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    return _opener.open(urllib.request.Request(url, headers=h), timeout=timeout)


# ---------- channel list (parsed from the configured m3u sources) ----------
_LOGO = re.compile(r'tvg-logo="([^"]*)"')
_GROUP = re.compile(r'group-title="([^"]*)"')


def parse_m3u(text: str) -> Iterator[dict[str, str]]:
    name = logo = group = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#EXTINF"):
            logo = (_LOGO.search(line) or _NONE).group(1) if 'tvg-logo="' in line else ""
            group = (_GROUP.search(line) or _NONE).group(1) if 'group-title="' in line else ""
            name = line.split(",", 1)[1].strip() if "," in line else ""
        elif line and not line.startswith("#"):
            if name:
                yield {"name": name, "logo": logo, "group": group, "url": line}
            name = logo = group = ""


class _NONE:                        # so a missing match still has .group(1) == ""
    @staticmethod
    def group(_: int) -> str:
        return ""


def source_urls() -> list[str]:
    src = kodi.current_sources()
    urls = [f"{kodi.IPTV_BASE}{c}.m3u" for c in src.get("codes", [])]
    custom = src.get("custom") or {}
    if custom.get("m3u"):
        urls.append(custom["m3u"])
    return urls


def channels(force: bool = False) -> list[dict[str, str]]:
    """The playable channels across the configured lists (name, logo, group, url), de-duplicated and cached."""
    urls = source_urls()
    key = tuple(urls)
    now = time.time()
    if not force and _cache["channels"] and _cache["key"] == key and now - _cache["at"] < TTL:
        return _cache["channels"]
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for u in urls:
        try:
            with open_url(u, timeout=20) as r:
                text = r.read(12_000_000).decode("utf-8", "replace")
        except Exception:
            continue
        for ch in parse_m3u(text):
            if ch["url"] in seen:
                continue
            seen.add(ch["url"])
            out.append(ch)
            if len(out) >= MAX_CH:
                break
        if len(out) >= MAX_CH:
            break
    _cache.update(at=now, key=key, channels=out)
    return out


# ---------- HLS playlist rewriting (point every URI back at the relay) ----------
_URI_ATTR = re.compile(r'URI="([^"]+)"')


def rewrite_playlist(text: str, base: str, proxify: Any) -> str:
    """Rewrite an m3u8 so variant playlists, segments and key/map URIs all come back through the relay (absolute)."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            out.append(line)
        elif s.startswith("#"):
            out.append(_URI_ATTR.sub(lambda m: f'URI="{proxify(urllib.parse.urljoin(base, m.group(1)))}"', line))
        else:
            out.append(proxify(urllib.parse.urljoin(base, s)))
    return "\n".join(out)


def is_playlist(url: str, ctype: str, head: bytes) -> bool:
    return (url.split("?")[0].lower().endswith((".m3u8", ".m3u")) or "mpegurl" in ctype.lower()
            or head[:7].lstrip().startswith(b"#EXTM3U"))
