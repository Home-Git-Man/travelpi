"""AdGuard Home on the Pi: DNS + ad-blocking for the travel Wi-Fi (10.42.0.1:53; dnsmasq only does DHCP).
Its admin API listens on 127.0.0.1:3080 only, login in /etc/travelpi/adguard-local.env (deploy/adguard-install.sh).

Upstreams follow the router's mode (set by the controller with the rest of DNS):
  VPN modes        → encrypted DNS (Quad9, Cloudflare over HTTPS) through the tunnel; settings' dns_fallback (or Quad9)
                     as fallback
  direct / login   → the hotel's own DNS (login pages need it), encrypted DNS as fallback
Kids' devices still go to AdGuard Family (fw.py), Tor mode's DNS comes here too."""
from __future__ import annotations

import base64
import json
import re
import time
import urllib.error
import urllib.request
from typing import Any

from .config import DNS_FALLBACK, ETC

API = "http://127.0.0.1:3080"
DOH = ["https://dns.quad9.net/dns-query", "https://cloudflare-dns.com/dns-query"]
BOOTSTRAP = ["9.9.9.9", "1.1.1.1"]
FALLBACK = [DNS_FALLBACK] if DNS_FALLBACK else ["9.9.9.9"]     # plain DNS if DNS-over-HTTPS fails


def upstreams_for(dns: list[str], tunnel: bool) -> tuple[list[str], list[str]]:
    """(upstream, fallback) for AdGuard Home, given the DNS servers the controller picked for this mode."""
    if tunnel:
        return DOH, list(FALLBACK)
    return list(dns) or ["1.1.1.1"], DOH


def _auth() -> str:
    env = dict(l.split("=", 1) for l in (ETC / "adguard-local.env").read_text().splitlines() if "=" in l)
    return "Basic " + base64.b64encode(f"{env['ADGUARD_USER']}:{env['ADGUARD_PASS']}".encode()).decode()


def call(path: str, body: dict | None = None, timeout: float = 6) -> Any:
    req = urllib.request.Request(API + path, data=json.dumps(body).encode() if body is not None else None,
                                 method="POST" if body is not None else "GET")
    req.add_header("Authorization", _auth())
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:         # AdGuard said no (e.g. a list address that isn't a list): pass it on
        raise ValueError(f"AdGuard: {e.read().decode(errors='replace').strip()[:200] or e.reason}") from None
    try:
        return json.loads(raw) if raw.strip() else None
    except ValueError:                       # some calls answer plain text ("OK: added …")
        return raw.decode(errors="replace")


def set_upstreams(upstream: list[str], fallback: list[str]) -> None:
    call("/control/dns_config", {"upstream_dns": upstream, "fallback_dns": fallback, "bootstrap_dns": BOOTSTRAP})


def set_rewrite(domain: str, answer: str) -> None:
    """Make `domain` answer `answer` on the travel Wi-Fi ("" removes it) – e.g. "sentinel" → its Tailscale address."""
    have = [r for r in call("/control/rewrite/list") or [] if r.get("domain") == domain]
    for r in have:
        if r.get("answer") != answer:
            call("/control/rewrite/delete", {"domain": domain, "answer": r.get("answer")})
    if answer and not any(r.get("answer") == answer for r in have):
        call("/control/rewrite/add", {"domain": domain, "answer": answer})


def pause(minutes: int) -> None:
    call("/control/protection", {"enabled": False, "duration": minutes * 60_000})


def resume() -> None:
    call("/control/protection", {"enabled": True})


def summarise(st: dict, status: dict, names: dict[str, str], now: float | None = None) -> dict[str, Any]:
    """AdGuard's /control/stats + /control/status → what the screen, phone page and Sentinel show."""
    q, b = st.get("num_dns_queries", 0), st.get("num_blocked_filtering", 0)
    until = status.get("protection_disabled_until")          # ISO time while paused
    left = 0
    if not status.get("protection_enabled", True) and until:
        try:
            from datetime import datetime
            left = max(0, round((datetime.fromisoformat(until.replace("Z", "+00:00")).timestamp() - (now or time.time())) / 60))
        except ValueError:
            left = 0
    clients = []
    for item in (st.get("top_clients") or [])[:6]:
        ip, n = next(iter(item.items()))
        clients.append({"ip": ip, "name": names.get(ip) or ip, "queries": n})
    return {"blocked": b, "queries": q, "pct": round(100 * b / q) if q else 0,
            "top": [next(iter(x)) for x in (st.get("top_blocked_domains") or [])[:6]],
            "clients": clients, "on": bool(status.get("protection_enabled", True)), "paused_min": left,
            "ms": round(st.get("avg_processing_time", 0) * 1000, 1), "local": True}


def stats(names: dict[str, str]) -> dict[str, Any]:
    return summarise(call("/control/stats"), call("/control/status"), names)


# ----- managing it from the phone page / Sentinel (web.py /api/adblock) -----

DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.(?!-)[a-z0-9-]{1,63})*\.?$")
LIST_URL = re.compile(r"^https://[^\s\"'<>]{4,400}$")


def clean_domain(text: str) -> str:
    d = (text or "").strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0].strip(".")
    if not DOMAIN.match(d):
        raise ValueError(f"not a site name: {text!r}")
    return d


def blocked_items(log: dict, names: dict[str, str], lists: dict[int, str], limit: int = 50) -> list[dict[str, Any]]:
    """Query-log entries that were blocked → [{time, domain, device, list, rule}] (newest first)."""
    out = []
    for e in (log.get("data") or [])[:limit]:
        rules = e.get("rules") or []
        lid = rules[0].get("filter_list_id") if rules else None
        out.append({"time": e.get("time", ""), "domain": (e.get("question") or {}).get("name", ""),
                    "device": names.get(e.get("client", "")) or e.get("client", ""),
                    "list": "Your rules" if lid == 0 else lists.get(lid, ""),
                    "rule": rules[0].get("text", "") if rules else ""})
    return out


def overview(names: dict[str, str]) -> dict[str, Any]:
    """Everything the Ad-block panels (phone page, Sentinel) show."""
    fs = call("/control/filtering/status")
    lists = {f["id"]: f["name"] for f in fs.get("filters") or []}
    log = call("/control/querylog?limit=50&response_status=blocked")
    return {"stats": stats(names), "blocked": blocked_items(log, names, lists),
            "lists": [{"name": f["name"], "url": f["url"], "enabled": f["enabled"], "rules": f.get("rules_count", 0),
                       "updated": f.get("last_updated", "")} for f in fs.get("filters") or []],
            "rules": [r for r in fs.get("user_rules") or [] if r.strip() and not r.startswith("!")]}


def _set_rules(change) -> None:
    rules = [r for r in call("/control/filtering/status").get("user_rules") or [] if r.strip()]
    call("/control/filtering/set_rules", {"rules": change(rules)})


def act(body: dict[str, Any]) -> None:
    """One change from the phone page or Sentinel; raises ValueError for anything not allowed."""
    a = body.get("action")
    if a == "pause":
        minutes = int(body.get("minutes") or 10)
        if not 1 <= minutes <= 24 * 60:
            raise ValueError("pause for 1 minute to 24 hours")
        pause(minutes)
    elif a == "resume":
        resume()
    elif a in ("allow", "block"):
        d = clean_domain(body.get("domain", ""))
        rule = f"@@||{d}^$important" if a == "allow" else f"||{d}^"
        _set_rules(lambda rs: [r for r in rs if r not in (f"@@||{d}^$important", f"||{d}^")] + [rule])
    elif a == "unrule":
        rule = str(body.get("rule") or "")
        _set_rules(lambda rs: [r for r in rs if r != rule])
    elif a == "add_list":
        url, name = str(body.get("url") or "").strip(), str(body.get("name") or "").strip()[:80]
        if not LIST_URL.match(url):
            raise ValueError("a blocklist needs an https:// address")
        call("/control/filtering/add_url", {"name": name or url.split("/")[2], "url": url, "whitelist": False}, timeout=60)
    elif a in ("enable_list", "remove_list"):
        url = str(body.get("url") or "")
        f = next((f for f in call("/control/filtering/status").get("filters") or [] if f["url"] == url), None)
        if f is None:
            raise ValueError("no such blocklist")
        if a == "remove_list":
            call("/control/filtering/remove_url", {"url": url, "whitelist": False})
        else:
            call("/control/filtering/set_url", {"url": url, "whitelist": False,
                                                "data": {"name": f["name"], "url": url, "enabled": bool(body.get("on"))}})
    elif a == "refresh":
        call("/control/filtering/refresh", {"whitelist": False}, timeout=60)
    else:
        raise ValueError("unknown ad-block action")
