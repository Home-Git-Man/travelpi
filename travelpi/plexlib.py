"""Browse the Plex server at home (Continue watching, Recently added, libraries, search) for the TV remote, and hand
the chosen film or episode to Kodi as a direct file stream – full quality, nothing converted on the server.
The server address and token live in /etc/travelpi/plex.env (root-only, never sent to a browser); posters are fetched
through the router (/api/plex/thumb), so the token stays on the Pi. Optional: without the file there's no Plex browser."""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .config import ETC

PLAYABLE = ("movie", "episode")
THUMB = re.compile(r"^/library/metadata/\d+/(thumb|art|grandparentThumb|parentThumb)/\d+$")


def conf() -> dict[str, str]:
    try:
        env = dict(l.split("=", 1) for l in (ETC / "plex.env").read_text().splitlines() if "=" in l)
    except OSError:
        return {}
    return {"url": env.get("PLEX_URL", "").rstrip("/"), "token": env.get("PLEX_TOKEN", "")}


def enabled() -> bool:
    c = conf()
    return bool(c.get("url") and c.get("token"))


def _get(path: str, params: dict[str, Any] | None = None, raw: bool = False, timeout: float = 12) -> Any:
    c = conf()
    if not c.get("url"):
        raise ValueError("Plex isn't set up on this router")
    q = urllib.parse.urlencode({**(params or {}), "X-Plex-Token": c["token"]})
    req = urllib.request.Request(f"{c['url']}{path}?{q}", headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
            return (data, r.headers.get("Content-Type", "image/jpeg")) if raw else json.loads(data)
    except OSError:
        raise ValueError("Plex at home isn't reachable – is the VPN on Home, or Tailscale up?") from None


def item(m: dict[str, Any]) -> dict[str, Any]:
    """A Plex metadata entry → what the remote lists."""
    t = m.get("type", "")
    sub = ""
    if t == "episode":
        sub = f"{m.get('grandparentTitle', '')} · S{m.get('parentIndex', 0):02d}E{m.get('index', 0):02d}"
    elif t == "season":
        sub = m.get("parentTitle", "")
    elif t in ("movie", "show"):
        sub = str(m.get("year") or "")
    thumb = m.get("grandparentThumb") if t == "episode" and m.get("grandparentThumb") else m.get("thumb")
    dur, off = m.get("duration") or 0, m.get("viewOffset") or 0
    return {"key": str(m.get("ratingKey", "")), "type": t, "title": m.get("title", ""), "sub": sub,
            "thumb": thumb if thumb and THUMB.match(thumb) else "", "playable": t in PLAYABLE,
            "progress": round(100 * off / dur) if dur and off else 0, "watched": bool(m.get("viewCount"))}


def _items(data: dict) -> list[dict[str, Any]]:
    mc = data.get("MediaContainer") or {}
    return [item(m) for m in mc.get("Metadata") or []]


def browse(view: str, key: str = "", q: str = "") -> dict[str, Any]:
    if view == "continue":
        return {"items": _items(_get("/library/onDeck", {"X-Plex-Container-Size": 40}))}
    if view == "recent":
        return {"items": _items(_get("/library/recentlyAdded", {"X-Plex-Container-Size": 40}))}
    if view == "sections":
        d = _get("/library/sections").get("MediaContainer") or {}
        return {"sections": [{"key": s["key"], "title": s["title"], "type": s["type"]} for s in d.get("Directory") or []
                             if s.get("type") in ("movie", "show")]}
    if view == "section" and key.isdigit():
        return {"items": _items(_get(f"/library/sections/{key}/all", {"sort": "titleSort", "X-Plex-Container-Size": 400}))}
    if view == "children" and key.isdigit():
        return {"items": _items(_get(f"/library/metadata/{key}/children"))}
    if view == "search" and q.strip():
        d = _get("/search", {"query": q.strip()[:80], "limit": 40}).get("MediaContainer") or {}
        return {"items": [item(m) for m in d.get("Metadata") or [] if m.get("type") in ("movie", "show", "episode")]}
    raise ValueError("unknown Plex view")


def thumb(path: str) -> tuple[bytes, str]:
    if not THUMB.match(path or ""):
        raise ValueError("not a poster")
    return _get("/photo/:/transcode", {"url": path, "width": 240, "height": 360, "minSize": 1}, raw=True)


def blocked_reason(status: int, body: str) -> str:
    """Plex's answer to a direct-file request → a plain reason it won't play ('' when it's fine)."""
    if status == 403 and "plex pass" in (body or "").lower():
        return ("Plex won't stream this to the travel router without a Plex Pass (it treats a Tailscale connection as "
                "remote). Options: a Plex Pass, or use Jellyfin, or play it on the home Wi-Fi.")
    if status >= 400:
        return f"Plex refused the file (HTTP {status})."
    return ""


def stream(key: str) -> tuple[str, int]:
    """(direct file URL for Kodi, resume position in ms) for a film or episode. Checks Plex will actually serve it,
    so a block shows a clear message instead of a black screen on the TV."""
    if not key.isdigit():
        raise ValueError("bad item")
    m = ((_get(f"/library/metadata/{key}").get("MediaContainer") or {}).get("Metadata") or [{}])[0]
    if m.get("type") not in PLAYABLE:
        raise ValueError("Pick a film or an episode")
    part = (((m.get("Media") or [{}])[0].get("Part")) or [{}])[0].get("key")
    if not part:
        raise ValueError("Plex has no file for that")
    c = conf()
    url = f"{c['url']}{part}?X-Plex-Token={c['token']}"
    import urllib.request
    req = urllib.request.Request(url, method="GET", headers={"Range": "bytes=0-1"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            status, body = r.status, ""
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read(300).decode(errors="replace")
    except OSError:
        raise ValueError("Plex at home isn't reachable right now.") from None
    why = blocked_reason(status, body)
    if why:
        raise ValueError(why)
    return url, int(m.get("viewOffset") or 0)
