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
import threading
import time
import urllib.parse
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


# ---- keep-alive connection pool: reuse the upstream TLS connection across segments, so each one doesn't pay a fresh
#      handshake over the VPN (the big cause of slow buffering). Per (scheme,host,port), thread-safe. ----
_POOL: dict[tuple, list] = {}
_POOL_LOCK = threading.Lock()
_POOL_MAX = 6


def _conn_for(key: tuple, timeout: float) -> tuple[Any, bool]:
    with _POOL_LOCK:
        pool = _POOL.get(key)
        if pool:
            return pool.pop(), True
    scheme, host, port = key
    cls = _HTTPSConn if scheme == "https" else _HTTPConn
    return cls(host, port, timeout=timeout), False


def _release(key: tuple, conn: Any, resp: Any) -> None:
    try:                                          # only a fully-read, keep-alive connection is safe to reuse
        reusable = resp.isclosed() and not resp.will_close
    except Exception:
        reusable = False
    if reusable:
        with _POOL_LOCK:
            pool = _POOL.setdefault(key, [])
            if len(pool) < _POOL_MAX:
                pool.append(conn)
                return
    try:
        conn.close()
    except OSError:
        pass


class _Resp:
    """Minimal response wrapper: returns its connection to the pool when closed (if the body was fully read)."""
    def __init__(self, conn: Any, resp: Any, key: tuple, url: str) -> None:
        self._conn, self._resp, self._key, self._url = conn, resp, key, url
        self.status = resp.status
        self.headers = resp.headers

    def read(self, n: int = -1) -> bytes:
        return self._resp.read() if n is None or n < 0 else self._resp.read(n)

    def geturl(self) -> str:
        return self._url

    def close(self) -> None:
        _release(self._key, self._conn, self._resp)

    def __enter__(self) -> "_Resp":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def open_url(url: str, timeout: float = 15, headers: dict[str, str] | None = None, _depth: int = 0) -> _Resp:
    """Open an http(s) URL over the VPN (fwmark 0x33), refusing local/private/tailnet destinations. Reuses pooled
    keep-alive connections, follows redirects (each re-checked), and forwards extra `headers` (e.g. a Range)."""
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname or _blocked(p.hostname):
        raise ValueError("blocked url")
    port = p.port or (443 if p.scheme == "https" else 80)
    path = (p.path or "/") + ("?" + p.query if p.query else "")
    h = {"User-Agent": UA, "Accept": "*/*", "Connection": "keep-alive"}
    if headers:
        h.update(headers)
    key = (p.scheme, p.hostname, port)
    conn = resp = None
    for attempt in (0, 1):                        # a pooled socket may be stale – one retry with a fresh connection
        conn, pooled = _conn_for(key, timeout)
        try:
            conn.request("GET", path, headers=h)
            resp = conn.getresponse()
            break
        except Exception:
            try:
                conn.close()
            except OSError:
                pass
            if pooled and attempt == 0:
                continue
            raise
    if resp.status in (301, 302, 303, 307, 308) and _depth < 5:
        loc = resp.headers.get("Location")
        try:
            resp.read()
        except Exception:
            pass
        _release(key, conn, resp)
        if not loc:
            raise ValueError("redirect without location")
        return open_url(urllib.parse.urljoin(url, loc), timeout, headers, _depth + 1)
    return _Resp(conn, resp, key, url)


# ---------- channel list (parsed from the configured m3u sources) ----------
_ATTR = {k: re.compile(k + r'="([^"]*)"') for k in ("tvg-logo", "group-title", "http-user-agent", "http-referrer")}


def _attr(key: str, line: str) -> str:
    m = _ATTR[key].search(line)
    return m.group(1) if m else ""


def parse_m3u(text: str) -> Iterator[dict[str, str]]:
    """Channels with the per-channel headers many streams require (a browser user-agent, a referrer) – from the EXTINF
    attributes and/or the #EXTVLCOPT lines. Without these a lot of (esp. US) channels 403 the request."""
    name = logo = group = ua = ref = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#EXTINF"):
            logo, group = _attr("tvg-logo", line), _attr("group-title", line)
            ua, ref = _attr("http-user-agent", line), _attr("http-referrer", line)
            name = line.split(",", 1)[1].strip() if "," in line else ""
        elif line.startswith("#EXTVLCOPT") and "=" in line:
            low, val = line.lower(), line.split("=", 1)[1].strip()
            if "user-agent" in low:
                ua = val
            elif "referrer" in low or "referer" in low:
                ref = val
        elif line and not line.startswith("#"):
            if name:
                ch = {"name": name, "logo": logo, "group": group, "url": line}
                if ua:
                    ch["ua"] = ua
                if ref:
                    ch["ref"] = ref
                yield ch
            name = logo = group = ua = ref = ""


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
