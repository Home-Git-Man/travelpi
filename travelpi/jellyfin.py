"""Browse a Jellyfin server at home for the TV remote (the alternative to plexlib.py) and hand the chosen film or
episode to Kodi as a direct stream. Settings in /etc/travelpi/jellyfin.env (root-only): JELLYFIN_URL, JELLYFIN_KEY
(an API key from Dashboard → API Keys) and JELLYFIN_USER (the user id whose "continue watching" to show); posters go
through the router, so the key never reaches a browser."""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .config import ETC

ID = re.compile(r"^[0-9a-f]{32}$")
THUMB = re.compile(r"^/Items/([0-9a-f]{32})/Images/Primary$")
PLAYABLE = ("Movie", "Episode")
KIND = {"Movie": "movie", "Episode": "episode", "Series": "show", "Season": "season"}
FIELDS = "UserData,ProductionYear,SeriesName,ParentIndexNumber,IndexNumber,RunTimeTicks"


def conf() -> dict[str, str]:
    try:
        env = dict(l.split("=", 1) for l in (ETC / "jellyfin.env").read_text().splitlines() if "=" in l)
    except OSError:
        return {}
    return {"url": env.get("JELLYFIN_URL", "").rstrip("/"), "key": env.get("JELLYFIN_KEY", ""), "user": env.get("JELLYFIN_USER", "")}


def enabled() -> bool:
    c = conf()
    return bool(c.get("url") and c.get("key") and c.get("user"))


def _get(path: str, params: dict[str, Any] | None = None, raw: bool = False, timeout: float = 12) -> Any:
    c = conf()
    if not c.get("url"):
        raise ValueError("Jellyfin isn't set up on this router")
    q = urllib.parse.urlencode(params or {})
    req = urllib.request.Request(f"{c['url']}{path}" + (f"?{q}" if q else ""), headers={
        "Authorization": f'MediaBrowser Token="{c["key"]}"', "X-Emby-Token": c["key"], "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
            return (data, r.headers.get("Content-Type", "image/jpeg")) if raw else json.loads(data)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise ValueError("Jellyfin rejected the router's key – re-run the installer's Jellyfin step.") from None
        raise ValueError(f"Jellyfin error (HTTP {e.code}).") from None
    except OSError:
        raise ValueError("Jellyfin at home isn't reachable – is the VPN on Home, or Tailscale up?") from None


def item(m: dict[str, Any]) -> dict[str, Any]:
    """A Jellyfin item → the same shape plexlib.item gives."""
    t = m.get("Type", "")
    sub = ""
    if t == "Episode":
        sub = f"{m.get('SeriesName', '')} · S{m.get('ParentIndexNumber') or 0:02d}E{m.get('IndexNumber') or 0:02d}"
    elif t == "Season":
        sub = m.get("SeriesName", "")
    elif t in ("Movie", "Series"):
        sub = str(m.get("ProductionYear") or "")
    poster = m.get("SeriesId") if t == "Episode" and m.get("SeriesPrimaryImageTag") else m.get("Id")
    has_image = bool((m.get("ImageTags") or {}).get("Primary")) or (t == "Episode" and m.get("SeriesPrimaryImageTag"))
    ud = m.get("UserData") or {}
    return {"key": str(m.get("Id", "")), "type": KIND.get(t, t.lower()), "title": m.get("Name", ""), "sub": sub,
            "thumb": f"/Items/{poster}/Images/Primary" if has_image and poster and ID.match(str(poster)) else "",
            "playable": t in PLAYABLE, "progress": round(ud.get("PlayedPercentage") or 0), "watched": bool(ud.get("Played"))}


def _items(data: Any) -> list[dict[str, Any]]:
    rows = data if isinstance(data, list) else (data or {}).get("Items") or []
    return [item(m) for m in rows if m.get("Type") in KIND]


def browse(view: str, key: str = "", q: str = "") -> dict[str, Any]:
    u = conf().get("user", "")
    if view == "continue":
        return {"items": _items(_get(f"/Users/{u}/Items/Resume", {"Limit": 40, "MediaTypes": "Video", "Fields": FIELDS}))}
    if view == "recent":
        return {"items": _items(_get(f"/Users/{u}/Items/Latest", {"Limit": 40, "Fields": FIELDS}))}
    if view == "sections":
        d = _get(f"/Users/{u}/Views")
        return {"sections": [{"key": v["Id"], "title": v["Name"], "type": "movie" if v.get("CollectionType") == "movies" else "show"}
                             for v in d.get("Items") or [] if v.get("CollectionType") in ("movies", "tvshows")]}
    if view == "section" and ID.match(key):
        return {"items": _items(_get(f"/Users/{u}/Items", {"ParentId": key, "Recursive": "true", "SortBy": "SortName",
                                                            "IncludeItemTypes": "Movie,Series", "Fields": FIELDS, "Limit": 400}))}
    if view == "children" and ID.match(key):
        return {"items": _items(_get(f"/Users/{u}/Items", {"ParentId": key, "SortBy": "SortName", "Fields": FIELDS}))}
    if view == "search" and q.strip():
        return {"items": _items(_get(f"/Users/{u}/Items", {"searchTerm": q.strip()[:80], "Recursive": "true", "Limit": 40,
                                                            "IncludeItemTypes": "Movie,Series,Episode", "Fields": FIELDS}))}
    raise ValueError("unknown library view")


def thumb(path: str) -> tuple[bytes, str]:
    if not THUMB.match(path or ""):
        raise ValueError("not a poster")
    return _get(path, {"maxHeight": 360, "quality": 85}, raw=True)


def stream(key: str) -> tuple[str, int]:
    """(direct stream URL for Kodi, resume position in ms) for a film or episode."""
    if not ID.match(key or ""):
        raise ValueError("bad item")
    c = conf()
    m = _get(f"/Users/{c['user']}/Items/{key}")
    if m.get("Type") not in PLAYABLE:
        raise ValueError("Pick a film or an episode")
    resume = int(((m.get("UserData") or {}).get("PlaybackPositionTicks") or 0) // 10_000)
    return f"{c['url']}/Videos/{key}/stream?static=true&api_key={c['key']}", resume
