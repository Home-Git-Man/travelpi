"""TV mode remote: drives Kodi (on the HDMI port) through its JSON-RPC API on 127.0.0.1:8080 – the phone page and
Sentinel get a D-pad, playback and volume buttons, what's playing, and the world TV channels. Kodi's web server only
answers on the Pi itself (fw.py drops port 8080 from everywhere else); its login is in /etc/travelpi/kodi.env."""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .config import ETC

URL = "http://127.0.0.1:8080/jsonrpc"
IPTV_DIR = Path("/var/lib/kodi/.kodi/userdata/addon_data/pvr.iptvsimple")
IPTV_BASE = "https://iptv-org.github.io/iptv/"
# channel lists offered on the phone page / Sentinel (any other iptv-org language/country/category code works too)
LIST_CHOICES = {
    "Language": {"languages/eng": "English"},
    "Country": {"countries/au": "Australia", "countries/nz": "New Zealand", "countries/uk": "United Kingdom",
                "countries/us": "United States", "countries/za": "South Africa", "countries/ie": "Ireland",
                "countries/ca": "Canada", "countries/in": "India"},
    "Type": {"categories/news": "News", "categories/kids": "Kids", "categories/sports": "Sport",
             "categories/movies": "Movies", "categories/documentary": "Documentary", "categories/music": "Music"},
    "Everything": {"index": "All channels (10,000+)"},
}
LIST_RE = re.compile(r"^(index|(languages|countries|categories)/[a-z_]{2,20})$")
URL_RE = re.compile(r"^https?://[^\s\"'<>]{6,500}$")


def _xml(v: str) -> str:
    return (v or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def clean_sources(codes: Any, custom: Any) -> tuple[list[str], dict | None]:
    """Validate the TV sources: iptv-org `codes` (the picker) + an optional `custom` {name, m3u, epg} of your own.
    Returns (codes, custom-or-None) or raises ValueError in plain words."""
    codes = codes or []
    if not isinstance(codes, list) or len(codes) > 12 or not all(isinstance(x, str) and LIST_RE.match(x) for x in codes):
        raise ValueError("Pick valid channel lists")
    codes = list(dict.fromkeys(codes))
    c = None
    if isinstance(custom, dict) and str(custom.get("m3u") or "").strip():
        m3u, epg = str(custom["m3u"]).strip(), str(custom.get("epg") or "").strip()
        if not URL_RE.match(m3u):
            raise ValueError("The IPTV playlist must be a http:// or https:// .m3u URL")
        if epg and not URL_RE.match(epg):
            raise ValueError("The EPG (guide) must be a http:// or https:// URL")
        c = {"name": (str(custom.get("name") or "").strip()[:40] or "My IPTV"), "m3u": m3u, "epg": epg}
    if not codes and not c:
        raise ValueError("Add at least one channel list or your own IPTV URL")
    return codes, c
# button → (method, params); "{player}" is filled with the active player's id
REMOTE: dict[str, tuple[str, dict[str, Any]]] = {
    "up": ("Input.Up", {}), "down": ("Input.Down", {}), "left": ("Input.Left", {}), "right": ("Input.Right", {}),
    "select": ("Input.Select", {}), "back": ("Input.Back", {}), "home": ("Input.Home", {}),
    "info": ("Input.Info", {}), "menu": ("Input.ContextMenu", {}),
    "playpause": ("Player.PlayPause", {"playerid": "{player}"}), "stop": ("Player.Stop", {"playerid": "{player}"}),
    "forward": ("Player.Seek", {"playerid": "{player}", "value": {"step": "smallforward"}}),
    "rewind": ("Player.Seek", {"playerid": "{player}", "value": {"step": "smallbackward"}}),
    "skip": ("Player.Seek", {"playerid": "{player}", "value": {"step": "bigforward"}}),
    "subtitles": ("Player.SetSubtitle", {"playerid": "{player}", "subtitle": "next", "enable": True}),
    "audio": ("Player.SetAudioStream", {"playerid": "{player}", "stream": "next"}),
    "volup": ("Application.SetVolume", {"volume": "increment"}),
    "voldown": ("Application.SetVolume", {"volume": "decrement"}),
    "mute": ("Application.SetMute", {"mute": "toggle"}),
}


def clean_lists(lists: Any) -> list[str]:
    if not isinstance(lists, list) or not 1 <= len(lists) <= 12 or not all(isinstance(x, str) and LIST_RE.match(x) for x in lists):
        raise ValueError("Pick 1–12 channel lists")
    return list(dict.fromkeys(lists))


def list_name(code: str) -> str:
    for group in LIST_CHOICES.values():
        if code in group:
            return group[code]
    return code.split("/")[-1].upper()


def instance_source(n: int, name: str, m3u: str, epg: str = "") -> str:
    epg_xml = (f'    <setting id="epgPathType">1</setting>\n    <setting id="epgUrl">{_xml(epg)}</setting>\n'
               if epg else '    <setting id="epgPathType">1</setting>\n    <setting id="logoFromEpg">1</setting>\n')
    return (f'<settings version="2">\n    <setting id="kodi_addon_instance_name">{_xml(name)}</setting>\n'
            f'    <setting id="kodi_addon_instance_enabled">true</setting>\n    <setting id="m3uPathType">1</setting>\n'
            f'    <setting id="m3uUrl">{_xml(m3u)}</setting>\n    <setting id="m3uCache">true</setting>\n'
            f'{epg_xml}</settings>\n')


def instance_xml(n: int, code: str) -> str:
    return instance_source(n, f"{list_name(code)} (iptv-org)", f"{IPTV_BASE}{code}.m3u")


def current_lists(d: Path = IPTV_DIR) -> list[str]:
    out = []
    for f in sorted(d.glob("instance-settings-*.xml"), key=lambda f: int(re.sub(r"\D", "", f.stem) or 0)):
        m = re.search(re.escape(IPTV_BASE) + r"([a-z_/]+)\.m3u", f.read_text(errors="replace"))
        if m and LIST_RE.match(m.group(1)):
            out.append(m.group(1))
    return out


def current_sources(d: Path = IPTV_DIR) -> dict:
    """What the TV is set to now: {codes: [iptv-org codes], custom: {name, m3u, epg} or None}."""
    codes, custom = [], None
    for f in sorted(d.glob("instance-settings-*.xml"), key=lambda f: int(re.sub(r"\D", "", f.stem) or 0)) if d.exists() else []:
        t = f.read_text(errors="replace")
        m = re.search(r'id="m3uUrl">([^<]+)<', t)
        if not m:
            continue
        url = m.group(1).replace("&amp;", "&")
        if url.startswith(IPTV_BASE) and url.endswith(".m3u") and LIST_RE.match(url[len(IPTV_BASE):-4]):
            codes.append(url[len(IPTV_BASE):-4])
        else:
            name = re.search(r'id="kodi_addon_instance_name">([^<]*)<', t)
            epg = re.search(r'id="epgUrl">([^<]*)<', t)
            custom = {"name": (name.group(1) if name else "My IPTV"), "m3u": url,
                      "epg": (epg.group(1).replace("&amp;", "&") if epg else "")}
    return {"codes": codes, "custom": custom}


def set_sources(codes: Any, custom: Any, d: Path = IPTV_DIR) -> bool:
    """Set the TV's channel sources (iptv-org picker codes + an optional custom m3u). Restarts Kodi to reload."""
    codes, custom = clean_sources(codes, custom)
    rows = [(f"{list_name(c)} (iptv-org)", f"{IPTV_BASE}{c}.m3u", "") for c in codes]
    if custom:
        rows.append((custom["name"], custom["m3u"], custom["epg"]))
    d.mkdir(parents=True, exist_ok=True)
    for f in d.glob("instance-settings-*.xml"):
        f.unlink()
    for n, (name, m3u, epg) in enumerate(rows, 1):
        f = d / f"instance-settings-{n}.xml"
        f.write_text(instance_source(n, name, m3u, epg))
        if os.geteuid() == 0:
            shutil.chown(f, "kodi", "kodi")
    running = subprocess.run(["systemctl", "is-active", "--quiet", "kodi"]).returncode == 0
    if running:
        subprocess.run(["systemctl", "restart", "kodi"], timeout=30)
    return running


def set_lists(lists: list[str], d: Path = IPTV_DIR) -> bool:
    """Write one IPTV Simple instance per list (replacing the old ones); restarts Kodi if it's running so it reloads.
    Returns True when Kodi was restarted."""
    lists = clean_lists(lists)
    d.mkdir(parents=True, exist_ok=True)
    for f in d.glob("instance-settings-*.xml"):
        f.unlink()
    for n, code in enumerate(lists, 1):
        f = d / f"instance-settings-{n}.xml"
        f.write_text(instance_xml(n, code))
        if os.geteuid() == 0:
            shutil.chown(f, "kodi", "kodi")
    running = subprocess.run(["systemctl", "is-active", "--quiet", "kodi"]).returncode == 0
    if running:
        subprocess.run(["systemctl", "restart", "kodi"], timeout=30)
    return running


def _auth() -> str:
    env = dict(l.split("=", 1) for l in (ETC / "kodi.env").read_text().splitlines() if "=" in l)
    return "Basic " + base64.b64encode(f"{env['KODI_USER']}:{env['KODI_PASS']}".encode()).decode()


def rpc(method: str, params: dict | None = None, timeout: float = 8) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"})
    try:
        req.add_header("Authorization", _auth())
        with urllib.request.urlopen(req, timeout=timeout) as r:
            out = json.loads(r.read())
    except (OSError, KeyError, ValueError):
        raise ValueError("TV mode is off – turn it on first") from None
    if "error" in out:
        raise ValueError(f"Kodi: {out['error'].get('message', 'error')}")
    return out.get("result")


def fill(params: dict[str, Any], player: int | None) -> dict[str, Any]:
    """Put the active player's id into a REMOTE entry (no player → ValueError: nothing is playing)."""
    out = {}
    for k, v in params.items():
        if v == "{player}":
            if player is None:
                raise ValueError("Nothing is playing")
            v = player
        out[k] = v
    return out


def _player() -> int | None:
    players = rpc("Player.GetActivePlayers") or []
    video = [p for p in players if p.get("type") == "video"] or players
    return video[0]["playerid"] if video else None


def press(button: str) -> None:
    if button not in REMOTE:
        raise ValueError("unknown button")
    method, params = REMOTE[button]
    rpc(method, fill(params, _player() if "{player}" in params.values() else None))


def summarise_playing(item: dict[str, Any], props: dict[str, Any]) -> dict[str, Any]:
    """Player.GetItem + Player.GetProperties → what the pages show."""
    secs = lambda t: (t or {}).get("hours", 0) * 3600 + (t or {}).get("minutes", 0) * 60 + (t or {}).get("seconds", 0)
    show, title = item.get("showtitle") or "", item.get("title") or item.get("label") or ""
    if show and item.get("season", -1) >= 0 and item.get("episode", -1) >= 0:
        title = f"{show} · S{item['season']:02d}E{item['episode']:02d} · {title}"
    elif item.get("type") == "channel":
        title = item.get("label") or title
    return {"playing": True, "title": title, "kind": item.get("type") or "", "paused": props.get("speed") == 0,
            "time": secs(props.get("time")), "total": secs(props.get("totaltime")),
            "percent": round(props.get("percentage") or 0, 1)}


def now_playing() -> dict[str, Any]:
    p = _player()
    if p is None:
        return {"playing": False}
    item = (rpc("Player.GetItem", {"playerid": p, "properties": ["title", "showtitle", "season", "episode"]}) or {}).get("item") or {}
    props = rpc("Player.GetProperties", {"playerid": p, "properties": ["time", "totaltime", "percentage", "speed"]}) or {}
    return summarise_playing(item, props)


def ensure_pvr() -> None:
    """Make sure the IPTV Simple PVR add-on is enabled (Kodi ships it disabled); harmless if already on."""
    try:
        rpc("Addons.SetAddonEnabled", {"addonid": "pvr.iptvsimple", "enabled": True})
    except ValueError:
        pass


# genre words that may appear in an iptv-org group name (so the guide can offer a "genre" filter)
TV_GENRES = {"news", "sport", "sports", "movies", "movie", "kids", "music", "documentary", "documentaries",
             "entertainment", "general", "comedy", "lifestyle", "culture", "education", "educational", "business",
             "science", "religious", "weather", "cooking", "travel", "outdoor", "family", "animation", "classic",
             "legislative", "auto", "shop", "relax", "series", "undefined"}


def _broadcast(b: Any) -> dict[str, Any] | None:
    """A PVR 'broadcastnow'/'broadcastnext' object → the guide's now/next (empty → None)."""
    if not isinstance(b, dict) or not b.get("title"):
        return None
    return {"title": b.get("title", ""), "start": b.get("starttime", ""), "end": b.get("endtime", ""),
            "progress": round(b.get("progresspercentage") or 0)}


def channels(q: str = "", group: str = "", limit: int = 200) -> list[dict[str, Any]]:
    """Live TV channels (optionally only those in one channel group), each with what's on now and next."""
    gid: Any = group.strip() or "alltv"
    if isinstance(gid, str) and gid.isdigit():
        gid = int(gid)
    try:
        res = rpc("PVR.GetChannels", {"channelgroupid": gid,
                                      "properties": ["channelnumber", "hidden", "broadcastnow", "broadcastnext"]}, timeout=15) or {}
    except ValueError:                               # PVR not up yet – enable it and let Kodi load the list
        ensure_pvr()
        raise ValueError("Live TV is starting up – try again in a few seconds") from None
    out = [{"id": c["channelid"], "name": c.get("label", ""), "number": c.get("channelnumber"),
            "now": _broadcast(c.get("broadcastnow")), "next": _broadcast(c.get("broadcastnext"))}
           for c in res.get("channels") or [] if not c.get("hidden")]
    q = q.strip().lower()
    return [c for c in out if not q or q in c["name"].lower()][:limit]


def groups(country_names: set[str] | None = None) -> dict[str, list[dict[str, Any]]]:
    """Kodi's TV channel groups (from the iptv-org lists in use), split into genre / country / other so the guide can
    offer both filters. iptv-org names groups by category (News…) or by country depending on the list loaded."""
    countries = country_names or set()
    try:
        res = rpc("PVR.GetChannelGroups", {"channeltype": "tv"}, timeout=10) or {}
    except ValueError:
        return {"genre": [], "country": [], "other": []}
    out: dict[str, list[dict[str, Any]]] = {"genre": [], "country": [], "other": []}
    seen: set[str] = set()                           # one entry per name (iptv-org repeats group names per list)
    for g in res.get("channelgroups") or []:
        gid, name = g.get("channelgroupid"), (g.get("label") or "").strip()
        low = name.lower()
        if gid is None or not name or low in seen or low in ("all channels", "all tv channels", "alltv"):
            continue
        seen.add(low)
        item = {"id": gid, "name": name}
        if low in TV_GENRES or any(w in TV_GENRES for w in re.split(r"[^a-z]+", low)):
            out["genre"].append(item)
        elif low in countries:
            out["country"].append(item)
        else:
            out["other"].append(item)
    for k in out:
        out[k].sort(key=lambda x: x["name"].lower())
    return out


def play_channel(channel_id: int) -> None:
    rpc("Player.Open", {"item": {"channelid": int(channel_id)}})


def play_file(url: str, resume_ms: int = 0) -> None:
    opts: dict[str, Any] = {}
    if resume_ms > 60_000:                      # pick up where it was left (Plex's "continue watching")
        s = resume_ms // 1000
        opts["resume"] = {"hours": s // 3600, "minutes": s % 3600 // 60, "seconds": s % 60, "milliseconds": 0}
    rpc("Player.Open", {"item": {"file": url}, **({"options": opts} if opts else {})}, timeout=15)
