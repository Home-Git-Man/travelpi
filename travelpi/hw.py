"""Hardware health for the dashboard: temperature, power problems, CPU, memory, disk, uptime, Wi-Fi radios."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from typing import Any

from .config import AP, UPLINK

THROTTLE_BITS = {0: "under-voltage now", 1: "CPU capped now", 2: "throttled now", 3: "too hot now",
                 16: "under-voltage since boot", 18: "throttled since boot", 19: "too hot since boot"}


def decode_throttled(value: int) -> list[str]:
    """vcgencmd get_throttled bits → plain words (empty = all good)."""
    return [msg for bit, msg in THROTTLE_BITS.items() if value & (1 << bit)]


def _sh(*cmd: str) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _read(path: str) -> str:
    try:
        return open(path).read().strip()
    except OSError:
        return ""


def adapter(dev: str) -> dict[str, Any] | None:
    if not os.path.exists(f"/sys/class/net/{dev}"):
        return None
    drv = os.path.basename(os.path.realpath(f"/sys/class/net/{dev}/device/driver")) if os.path.exists(
        f"/sys/class/net/{dev}/device/driver") else ""
    info: dict[str, Any] = {"dev": dev, "driver": drv, "mac": _read(f"/sys/class/net/{dev}/address"),
                            "up": _read(f"/sys/class/net/{dev}/operstate") == "up"}
    link = _sh("iw", "dev", dev, "link") if dev == UPLINK else _sh("iw", "dev", dev, "info")
    m = re.search(r"freq: (\d+)", link) or re.search(r"channel \d+ \((\d+) MHz\)", link)
    if m:
        info["band"] = "5 GHz" if int(m.group(1)) > 4000 else "2.4 GHz"
    m = re.search(r"signal: (-?\d+) dBm", link)
    if m:
        info["dbm"] = int(m.group(1))
    m = re.search(r"tx bitrate: ([\d.]+) MBit/s", link)
    if m:
        info["mbit"] = float(m.group(1))
    return info


def _backup() -> dict[str, Any]:
    try:
        return json.loads(_read("/var/lib/travelpi/backup.json") or "{}")
    except ValueError:
        return {}


def hardware() -> dict[str, Any]:
    temp = _read("/sys/class/thermal/thermal_zone0/temp")
    thr = re.search(r"0x([0-9a-fA-F]+)", _sh("vcgencmd", "get_throttled"))
    mem: dict[str, int] = {}
    for line in _read("/proc/meminfo").splitlines():
        k, v = line.split(":", 1)
        mem[k] = int(v.split()[0]) * 1024
    disk = shutil.disk_usage("/")
    load = _read("/proc/loadavg").split()
    return {
        "model": _read("/proc/device-tree/model").rstrip("\x00"),
        "temp_c": round(int(temp) / 1000, 1) if temp else None,
        "power": decode_throttled(int(thr.group(1), 16)) if thr else [],
        "load": float(load[0]) if load else None, "cpus": os.cpu_count(),
        "mem_used": mem.get("MemTotal", 0) - mem.get("MemAvailable", 0), "mem_total": mem.get("MemTotal", 0),
        "disk_used": disk.used, "disk_total": disk.total,
        "uptime": int(float(_read("/proc/uptime").split()[0] or 0)),
        "kernel": os.uname().release,
        "tailscale_ip": _sh("tailscale", "ip", "-4").strip(),
        "tor": _sh("systemctl", "is-active", "tor").strip() == "active",
        "adapters": [a for a in (adapter(UPLINK), adapter(AP)) if a],
        "backup": _backup(),
        "at": time.time(),
    }
