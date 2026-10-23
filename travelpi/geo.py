"""Country for the public exit address: Cloudflare's trace gives a country code, except for Tor ("T1"), where we
look the exit address up in Tor's own GeoIP file. Names come from the system's ISO 3166 table."""
from __future__ import annotations

import bisect
import ipaddress
from array import array
from functools import lru_cache

ISO = "/usr/share/zoneinfo/iso3166.tab"
TOR_GEOIP = "/usr/share/tor/geoip"


@lru_cache(maxsize=1)
def _names() -> dict[str, str]:
    out = {}
    try:
        for line in open(ISO, encoding="utf-8"):
            if line[:1] != "#" and "\t" in line:
                cc, name = line.rstrip("\n").split("\t", 1)
                out[cc.upper()] = name
    except OSError:
        pass
    return out


def country_name(cc: str) -> str:
    return _names().get((cc or "").upper(), (cc or "").upper())


class _TorGeo:
    """Tor's geoip file: 'start,end,CC' with addresses as integers, sorted. Loaded on first use (~2 MB in arrays)."""

    def __init__(self, path: str = TOR_GEOIP):
        self.starts, self.ends, self.ccs = array("L"), array("L"), []
        try:
            for line in open(path):
                if line[:1].isdigit():
                    a, b, cc = line.strip().split(",")
                    self.starts.append(int(a))
                    self.ends.append(int(b))
                    self.ccs.append(cc)
        except OSError:
            pass

    def lookup(self, ip: str) -> str:
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return ""
        i = bisect.bisect_right(self.starts, n) - 1
        return self.ccs[i] if i >= 0 and n <= self.ends[i] else ""


_tor: _TorGeo | None = None


def exit_country(public: dict) -> str:
    """'Austria (Tor)', 'Singapore', or '' when unknown."""
    global _tor
    loc = (public or {}).get("loc", "")
    if loc == "T1":
        if _tor is None:
            _tor = _TorGeo()
        cc = _tor.lookup(public.get("ip", ""))
        return f"{country_name(cc)} (Tor)" if cc else "Tor"
    return country_name(loc) if loc and loc != "XX" else ""
