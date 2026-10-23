"""Fixed settings for the travel router. Interface names are pinned by MAC in /etc/systemd/network/*.link.
Anything that differs between routers (your Tailscale exit nodes, a backup server, a dashboard) lives in
/etc/travelpi/settings.json, written by install.sh – a router without it is a plain travel router with no extras."""
from __future__ import annotations

import json
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
}


def load_settings(path: Path = ETC / "settings.json") -> dict[str, Any]:
    try:
        mine = json.loads(path.read_text())
    except (OSError, ValueError):
        mine = {}
    return {**DEFAULTS, **{k: v for k, v in mine.items() if k in DEFAULTS}}


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
PHONE_WARN = 1_000_000_000                       # warn after this much phone data in a day
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
