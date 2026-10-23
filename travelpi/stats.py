"""Ad-blocking and per-device data numbers.
Per device: a separate nft table (travelpi_acct, never replaced on mode changes) counts bytes to/from each address
on the travel Wi-Fi – Tor traffic included. Ads: AdGuard Home on the Pi (adguard.py)."""
from __future__ import annotations

import json
import subprocess
from typing import Any

from .config import AP, AP_NET

ACCT = f"""table inet travelpi_acct
delete table inet travelpi_acct
table inet travelpi_acct {{
  set up {{ type ipv4_addr; size 512; flags dynamic; counter; }}
  set down {{ type ipv4_addr; size 512; flags dynamic; counter; }}
  chain pre {{
    type filter hook prerouting priority -300; policy accept;
    iifname "{AP}" ip saddr {AP_NET} add @up {{ ip saddr }}
  }}
  chain post {{
    type filter hook postrouting priority 300; policy accept;
    oifname "{AP}" ip daddr {AP_NET} add @down {{ ip daddr }}
  }}
}}
"""


def ensure_acct() -> None:
    if subprocess.run(["nft", "list", "table", "inet", "travelpi_acct"], capture_output=True).returncode:
        subprocess.run(["nft", "-f", "-"], input=ACCT, text=True, check=True, timeout=10)


def parse_set(js: str) -> dict[str, int]:
    """`nft -j list set …` → {ip: bytes}."""
    out: dict[str, int] = {}
    try:
        for item in json.loads(js).get("nftables", []):
            for e in (item.get("set") or {}).get("elem", []):
                el = e.get("elem", {})
                ip, ctr = el.get("val"), (el.get("counter") or {})
                if isinstance(ip, str):
                    out[ip] = int(ctr.get("bytes", 0))
    except ValueError:
        pass
    return out


def read_counters() -> dict[str, int]:
    """Total bytes (up + down) per device address since the table was made."""
    total: dict[str, int] = {}
    for name in ("up", "down"):
        r = subprocess.run(["nft", "-j", "list", "set", "inet", "travelpi_acct", name], capture_output=True, text=True)
        for ip, b in parse_set(r.stdout).items():
            total[ip] = total.get(ip, 0) + b
    return total


def add_deltas(per_mac: dict[str, int], last: dict[str, int], now: dict[str, int], ip_to_mac: dict[str, str]) -> None:
    """Fold new counter readings into today's per-device totals (counters can restart from zero)."""
    for ip, value in now.items():
        prev = last.get(ip)
        delta = value - prev if prev is not None and value >= prev else value if prev is not None else 0
        mac = ip_to_mac.get(ip)
        if mac and delta > 0:
            per_mac[mac] = per_mac.get(mac, 0) + delta
        last[ip] = value
