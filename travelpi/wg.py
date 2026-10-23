"""WireGuard exits: one config per country in /etc/travelpi/wg/<provider>-<cc>.conf (e.g. proton-sg.conf from Proton
VPN's free plan, or any other WireGuard provider). Only one runs at a time (Proton free = one connection) on interface
`wgx`. Devices on the travel Wi-Fi are routed into it by policy routing; the Pi's own traffic (Tailscale, DNS) stays
as it is. Files can be added from the phone page (`save`), which only accepts plain WireGuard settings – no PostUp
or other commands (and `up` never runs wg-quick's hooks anyway)."""
from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from .config import AP, AP_NET, ETC, SETTINGS

WG_DIR = ETC / "wg"
IFACE = "wgx"
TABLE = 51
PRIO_FROM, PRIO_OIF = 5000, 5001          # ahead of Tailscale's rules (5210+)
COUNTRY = {"sg": "Singapore", "ch": "Switzerland", "nl": "Netherlands", "us": "United States", "jp": "Japan",
           "ro": "Romania", "pl": "Poland", "no": "Norway", "ca": "Canada", "mx": "Mexico", "de": "Germany",
           "gb": "United Kingdom", "uk": "United Kingdom", "fr": "France", "au": "Australia", "nz": "New Zealand",
           "hk": "Hong Kong", "kr": "South Korea", "tw": "Taiwan", "id": "Indonesia", "my": "Malaysia", "th": "Thailand",
           "vn": "Vietnam", "ph": "Philippines", "in": "India", "ae": "United Arab Emirates", "za": "South Africa",
           "it": "Italy", "es": "Spain", "pt": "Portugal", "ie": "Ireland", "se": "Sweden", "fi": "Finland",
           "dk": "Denmark", "at": "Austria", "be": "Belgium", "br": "Brazil"}
PREFERRED = list(SETTINGS["vpn_order"])   # auto tries these countries first (closest to home)
NAME = re.compile(r"^([a-z0-9]{1,20})-([a-z]{2})$")
ALLOWED = {"interface": {"privatekey", "address", "dns", "mtu", "listenport"},
           "peer": {"publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive"}}
KEY = re.compile(r"^[A-Za-z0-9+/]{42,43}=$")


def exits(directory: Path = WG_DIR) -> list[dict[str, Any]]:
    """WireGuard countries (<provider>-<cc>.conf), the preferred ones first."""
    out = []
    try:
        files = sorted(directory.glob("*.conf"))
    except OSError:
        files = []
    for f in files:
        m = NAME.match(f.stem.lower())
        if not m:
            continue
        provider, cc = m.groups()
        name = COUNTRY.get(cc, cc.upper())
        if provider == "proton":
            out.append({"id": f.stem, "kind": "wg", "cc": cc, "label": name, "where": f"Proton {name}", "conf": str(f),
                        "text": f"{name} – Proton VPN (free)", "sub": "Proton free", "provider": provider})
        else:
            p = provider.capitalize()
            out.append({"id": f.stem, "kind": "wg", "cc": cc, "label": name, "where": f"{p} {name}", "conf": str(f),
                        "text": f"{name} – {p} VPN", "sub": p, "provider": provider})
    rank = {cc: i for i, cc in enumerate(PREFERRED)}
    return sorted(out, key=lambda e: (rank.get(e["cc"], 99), e["cc"], e["id"]))


def check_conf(text: str) -> str:
    """A WireGuard config from a VPN provider → the same text if it's plain WireGuard settings, else ValueError."""
    if not text or len(text) > 4000:
        raise ValueError("that isn't a WireGuard file")
    section, seen = "", {"interface": set(), "peer": set()}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.fullmatch(r"\[(\w+)\]", line)
        if m:
            section = m.group(1).lower()
            if section not in ALLOWED:
                raise ValueError(f"unexpected section [{m.group(1)}]")
            continue
        if "=" not in line or not section:
            raise ValueError("that isn't a WireGuard file")
        k = line.split("=", 1)[0].strip().lower()
        if k not in ALLOWED[section]:
            raise ValueError(f"{line.split('=', 1)[0].strip()} isn't allowed (plain WireGuard settings only)")
        v = line.split("=", 1)[1].strip()
        if k in ("privatekey", "publickey", "presharedkey") and not KEY.match(v):
            raise ValueError(f"{k} doesn't look like a WireGuard key")
        seen[section].add(k)
    if not {"privatekey", "address"} <= seen["interface"] or not {"publickey", "endpoint", "allowedips"} <= seen["peer"]:
        raise ValueError("the file is missing its key, address or server")
    if not address(text):
        raise ValueError("the file has no IPv4 address")
    return text


def save(provider: str, cc: str, text: str, directory: Path = WG_DIR) -> str:
    """Store a checked config as <provider>-<cc>.conf (replacing that country's old one); returns its id."""
    name = f"{(provider or 'vpn').strip().lower()}-{(cc or '').strip().lower()}"
    if not NAME.match(name):
        raise ValueError("pick a country and a short provider name (letters and numbers)")
    check_conf(text)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / f"{name}.conf"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text.strip() + "\n")
    return name


def remove(exit_id: str, directory: Path = WG_DIR) -> None:
    if not NAME.match(exit_id or ""):
        raise ValueError("no such VPN")
    (directory / f"{exit_id}.conf").unlink(missing_ok=True)


def address(conf_text: str) -> str:
    """First IPv4 Address= of the [Interface] section."""
    m = re.search(r"^\s*Address\s*=\s*([^\n]+)", conf_text, re.M)
    for a in (m.group(1).split(",") if m else []):
        a = a.strip()
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+(/\d+)?", a):
            return a if "/" in a else a + "/32"
    return ""


def _ip(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["ip", *args], capture_output=True, text=True, timeout=10)


def down() -> None:
    for prio in (PRIO_FROM, PRIO_OIF):
        while _ip("rule", "del", "priority", str(prio)).returncode == 0:
            pass
    _ip("route", "flush", "table", str(TABLE))
    _ip("link", "del", IFACE)


def up(exit_: dict[str, Any]) -> None:
    down()
    conf = Path(exit_["conf"]).read_text()
    stripped = subprocess.run(["wg-quick", "strip", exit_["conf"]], capture_output=True, text=True, timeout=10, check=True).stdout
    stripped = "\n".join(l for l in stripped.splitlines() if not l.startswith("#"))
    r = _ip("link", "add", IFACE, "type", "wireguard")
    if r.returncode:
        raise RuntimeError(r.stderr.strip())
    subprocess.run(["wg", "setconf", IFACE, "/dev/stdin"], input=stripped, text=True, check=True, timeout=10)
    m = re.search(r"^\s*MTU\s*=\s*(\d+)", conf, re.M)
    for s in (["-4", "address", "add", address(conf), "dev", IFACE], ["link", "set", IFACE, "mtu", m.group(1) if m else "1420", "up"],
              ["route", "replace", "default", "dev", IFACE, "table", str(TABLE)],
              ["route", "replace", AP_NET, "dev", AP, "table", str(TABLE)],      # the Pi's replies to devices
              ["rule", "add", "from", AP_NET, "lookup", str(TABLE), "priority", str(PRIO_FROM)],
              ["rule", "add", "oif", IFACE, "lookup", str(TABLE), "priority", str(PRIO_OIF)]):
        r = _ip(*s)
        if r.returncode:
            raise RuntimeError(f"ip {' '.join(s)}: {r.stderr.strip()}")


def handshake_age() -> float | None:
    out = subprocess.run(["wg", "show", IFACE, "latest-handshakes"], capture_output=True, text=True, timeout=5).stdout.split()
    if len(out) >= 2 and out[1].isdigit() and int(out[1]):
        return time.time() - int(out[1])
    return None
