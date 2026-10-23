"""Fixed settings for the travel router. Interface names are pinned by MAC in /etc/systemd/network/*.link.
Anything that differs between routers (your Tailscale exit nodes, a backup server, a dashboard) lives in
/etc/travelpi/settings.json, written by install.sh – a router without it is a plain travel router with no extras."""
from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any

ETC = Path("/etc/travelpi")
VAR = Path("/var/lib/travelpi")
RUN = Path("/run/travelpi")
RESOLV = RUN / "resolv.conf"        # dnsmasq's upstream servers (it re-reads on change)

UPLINK = "wlup"            # USB Wi-Fi adapter – joins hotel / airport Wi-Fi
AP = "wlap"                # built-in Wi-Fi – our private network
WIRED = ("eth0",)          # hotel Ethernet also works as an uplink
AP_NET = "10.42.0.0/24"
AP_ADDR = "10.42.0.1"
TAILNET = "100.64.0.0/10"          # Tailscale addresses – reachable from the travel Wi-Fi in every mode

DEFAULTS: dict[str, Any] = {
    "name": "TravelPi",
    "tailscale_exits": [],     # [{"id": "home", "node": "my-exit-node", "label": "Home", "where": "Home internet"}]
    "dns_fallback": "",        # a DNS server reached through the tunnel (e.g. your own AdGuard); "" = public DNS
    "sentinel": "",            # Tailscale address of a Sentinel dashboard: "sentinel" then works on the travel Wi-Fi
    "backup": "",              # user@host for the nightly backup over SSH ("" = no backups)
    "home_wifi": "",           # connection name of your home Wi-Fi – full backups only run there
    "vpn_order": ["sg", "jp", "us", "nl", "ch"],    # Auto tries WireGuard countries in this order (closest first)
    "phone_warn_gb": 1.0,      # warn after this much phone data in a day
}
EDITABLE = ("name", "vpn_order", "phone_warn_gb", "tailscale_exits", "dns_fallback", "sentinel")   # from the web pages
FIXED_MODES = {"auto", "tor", "direct", "block"}
HOST = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def load_settings(path: Path = ETC / "settings.json") -> dict[str, Any]:
    try:
        mine = json.loads(path.read_text())
    except (OSError, ValueError):
        mine = {}
    return {**DEFAULTS, **{k: v for k, v in mine.items() if k in DEFAULTS}}


def _ip_or_blank(v: Any, what: str) -> str:
    v = str(v or "").strip()
    if v:
        try:
            ipaddress.IPv4Address(v)
        except ValueError:
            raise ValueError(f"{what} must be an IPv4 address (or empty)") from None
    return v


def clean_settings(body: dict[str, Any], current: dict[str, Any], taken: set[str] | frozenset = frozenset()) -> dict[str, Any]:
    """Changes from the phone page / Sentinel → the full new settings, or ValueError in plain words. Only EDITABLE
    keys change; backup and home_wifi stay as install.sh set them. `taken` = WireGuard exit ids (a Tailscale exit
    can't reuse one)."""
    out = {**DEFAULTS, **current}
    if "name" in body:
        name = str(body["name"] or "").strip()
        if not 1 <= len(name) <= 24 or any(ord(c) < 32 for c in name):
            raise ValueError("The router name needs 1–24 characters")
        out["name"] = name
    if "vpn_order" in body:
        order = body["vpn_order"]
        if not isinstance(order, list) or len(order) > 40 or not all(isinstance(c, str) and re.fullmatch(r"[a-z]{2}", c.lower()) for c in order):
            raise ValueError("The VPN order is a list of two-letter country codes")
        out["vpn_order"] = list(dict.fromkeys(c.lower() for c in order))
    if "phone_warn_gb" in body:
        try:
            gb = float(body["phone_warn_gb"])
        except (TypeError, ValueError):
            raise ValueError("The phone data warning is a number of GB") from None
        if not 0.1 <= gb <= 500:
            raise ValueError("The phone data warning must be between 0.1 and 500 GB")
        out["phone_warn_gb"] = round(gb, 1)
    if "tailscale_exits" in body:
        rows = body["tailscale_exits"]
        if not isinstance(rows, list) or len(rows) > 5:
            raise ValueError("Up to 5 Tailscale exit nodes")
        exits, ids = [], set()
        for e in rows:
            if not isinstance(e, dict):
                raise ValueError("Bad Tailscale exit node")
            node = str(e.get("node") or "").strip().lower()
            if not HOST.match(node):
                raise ValueError(f"'{node}' isn't a Tailscale machine name (letters, numbers and dashes)")
            label = str(e.get("label") or node).strip()[:20] or node
            eid = str(e.get("id") or re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-") or node)[:20]
            if not re.fullmatch(r"[a-z0-9-]{1,20}", eid) or eid in FIXED_MODES or eid in taken or eid in ids:
                raise ValueError(f"Pick a different short name than '{label}'")
            ids.add(eid)
            row = {"id": eid, "node": node, "label": label, "where": str(e.get("where") or f"{label} (Tailscale)")[:40]}
            if e.get("text"):
                row["text"] = str(e["text"])[:60]
            exits.append(row)
        out["tailscale_exits"] = exits
    if "dns_fallback" in body:
        out["dns_fallback"] = _ip_or_blank(body["dns_fallback"], "The fallback DNS server")
    if "sentinel" in body:
        out["sentinel"] = _ip_or_blank(body["sentinel"], "The Sentinel address")
    return out


def save_settings(data: dict[str, Any], path: Path = ETC / "settings.json") -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({k: data[k] for k in DEFAULTS if k in data}, indent=2) + "\n")
    os.chmod(tmp, 0o644)
    tmp.replace(path)


def ts_exits(settings: dict[str, Any]) -> list[dict[str, Any]]:
    """settings' tailscale_exits → exit entries the controller uses."""
    out = []
    for e in settings.get("tailscale_exits") or []:
        if not e.get("node"):
            continue
        label = e.get("label") or e["node"]
        out.append({"id": e.get("id") or e["node"], "kind": "ts", "node": e["node"], "label": label,
                    "where": e.get("where") or f"{label} (Tailscale)", **({"text": e["text"]} if e.get("text") else {})})
    return out


SETTINGS = load_settings()
NAME = SETTINGS["name"]
EXITS = ts_exits(SETTINGS)               # after the WireGuard countries in Auto's failover order
DNS_FALLBACK = SETTINGS["dns_fallback"]
TUNNEL_DNS = [DNS_FALLBACK, "1.1.1.1"] if DNS_FALLBACK else ["1.1.1.1", "9.9.9.9"]   # the Pi's own DNS in VPN modes
KIDS_DNS = "94.140.14.15"                        # AdGuard Family: adult sites blocked, safe search + YouTube restricted
UPLINK_PATTERNS = ("wlup", "eth0", "usb*", "enx*")   # hotel Wi-Fi, Ethernet, phone over USB
PHONE_WARN = int(float(SETTINGS["phone_warn_gb"]) * 1e9)    # warn after this much phone data in a day
BACKUP_AFTER = 60                                # seconds without internet before moving to a backup network
PRIMARY_RETRY = 600                              # on a backup network: try the hotel Wi-Fi again this often
WEB_PORT = 80

MODES = {
    "auto": "Auto – best available VPN",
    "tor": "Tor – anonymous, slow, web only",
    "direct": "Direct – no VPN",
    "block": "Block all internet",
}
TOR_TRANS, TOR_DNS = 9040, 9053

CHECK_EVERY = 10           # seconds between health checks
FAILS_TO_SWITCH = 3        # failed checks before auto moves to the next exit
RETRY_PRIMARY = 600        # auto: try the first exit again after this many seconds
