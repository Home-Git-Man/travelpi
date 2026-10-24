"""Network controller: keeps devices on the VPN, fails over between exit nodes, spots hotel login pages,
joins Wi-Fi networks. Runs as root in its own thread; the screen reads `state` and calls the public methods."""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
from datetime import date
from typing import Any

from . import fw, wg
from .geo import exit_country
from .hw import hardware
from . import adguard, stats
from .config import (AP, AP_NET, TAILNET, BACKUP_AFTER, CHECK_EVERY, ETC, EXITS, FAILS_TO_SWITCH, MODES, PHONE_WARN, PRIMARY_RETRY,
                     RESOLV, RETRY_PRIMARY, RUN, SETTINGS, TUNNEL_DNS, UPLINK, VAR, WIRED, EDITABLE, clean_settings,
                     load_settings, save_settings)

log = logging.getLogger("travelpi.net")
LOCAL_RULE = 4900          # ahead of Proton (5000) and Tailscale (5210+)
TAILNET_RULE = 4950
KODI_RULE = 4800           # Kodi's marked (0x33) internet traffic → the active exit's table
USAGE_SAVE_EVERY = 300


def run(*cmd: str, timeout: float = 20, check: bool = False) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        raise RuntimeError((r.stderr or r.stdout).strip()[:200] or f"{cmd[0]} failed")
    return r.stdout


def parse_trace(text: str) -> dict[str, str]:
    """Cloudflare /cdn-cgi/trace → {ip, loc, colo}."""
    kv = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    return {k: kv[k] for k in ("ip", "loc", "colo") if k in kv}


def split_nmcli(line: str) -> list[str]:
    """nmcli -t output: fields separated by ':', literal colons escaped as '\\:'."""
    return [f.replace("\\:", ":").replace("\\\\", "\\") for f in re.split(r"(?<!\\):", line)]


def parse_scan(text: str) -> list[dict[str, Any]]:
    """`nmcli -t -f IN-USE,SSID,SIGNAL,SECURITY dev wifi list` → strongest first, one row per name."""
    best: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        f = split_nmcli(line)
        if len(f) < 4 or not f[1]:
            continue
        row = {"ssid": f[1], "signal": int(f[2] or 0), "secure": f[3] not in ("", "--"), "active": f[0] == "*"}
        cur = best.get(row["ssid"])
        if not cur or row["active"] or (row["signal"] > cur["signal"] and not cur["active"]):
            best[row["ssid"]] = row
    return sorted(best.values(), key=lambda r: (not r["active"], -r["signal"]))


def portal_from_probe(code: str) -> str:
    """HTTP status of the generate_204 probe → 'online' | 'portal' | 'offline'."""
    if code == "204":
        return "online"
    if code and code != "000":
        return "portal"
    return "offline"


def parse_leases(text: str) -> list[dict[str, str]]:
    """dnsmasq.leases lines: '<expiry> <mac> <ip> <hostname|*> <client-id>'."""
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 4:
            out.append({"mac": f[1].lower(), "ip": f[2], "name": "" if f[3] == "*" else f[3]})
    return out


def is_phone_dev(dev: str) -> bool:
    return dev.startswith(("usb", "enx"))


def mbps(bytes_per_s: str) -> float:
    try:
        return round(float(bytes_per_s) * 8 / 1e6, 1)
    except ValueError:
        return 0.0


def exit_in_use(status: dict, node: str) -> bool:
    """`tailscale status --json`: is `node` the active exit node and online?"""
    es = status.get("ExitNodeStatus") or {}
    if not es.get("Online"):
        return False
    peer = (status.get("Peer") or {}).get(es.get("ID") or "", {})
    if not peer:
        peer = next((p for p in (status.get("Peer") or {}).values() if p.get("ExitNode")), {})
    return peer.get("HostName") == node or (peer.get("DNSName") or "").split(".")[0] == node


def next_exit(current: str, order: list[str]) -> str | None:
    """The exit after `current` in a failover order, or None when we've tried them all."""
    i = order.index(current) if current in order else -1
    return order[i + 1] if i + 1 < len(order) else None


def build_modes(exits: list[dict]) -> dict[str, str]:
    """Auto first (when there's any VPN), each WireGuard country, each Tailscale exit, Tor (it rides a Tailscale
    exit), then Direct and Block. A router with no VPN set up only has Direct and Block."""
    out = {"auto": MODES["auto"]} if exits else {}
    out.update({e["id"]: e.get("text") or f"{e['label']} – VPN" for e in exits if e["kind"] == "wg"})
    out.update({e["id"]: e.get("text") or f"{e['label']} – {e['where']}" for e in exits if e["kind"] == "ts"})
    if any(e["kind"] == "ts" for e in exits):
        out["tor"] = MODES["tor"]
    out.update(direct=MODES["direct"], block=MODES["block"])
    return out


def check_ap(ssid: str, password: str) -> tuple[str, str]:
    """New name and password for the travel Wi-Fi → (ssid, password), or ValueError in plain words."""
    ssid, password = (ssid or "").strip(), password or ""
    if not 1 <= len(ssid.encode()) <= 32 or any(ord(c) < 32 or ord(c) == 127 for c in ssid):
        raise ValueError("The Wi-Fi name needs 1–32 characters")
    if not 8 <= len(password) <= 63 or not all(32 <= ord(c) < 127 for c in password):
        raise ValueError("The password needs 8–63 letters, numbers or symbols (no emoji or accents)")
    return ssid, password


def read_env(text: str) -> dict[str, str]:
    """KEY=value lines (values may be shell-quoted) → dict."""
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            try:
                out[k.strip()] = " ".join(shlex.split(v)) if v.strip() else ""
            except ValueError:
                out[k.strip()] = v
    return out


def has_tailscale() -> bool:
    return shutil.which("tailscale") is not None


class Net:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        VAR.mkdir(parents=True, exist_ok=True)
        RUN.mkdir(parents=True, exist_ok=True)
        self.exits: list[dict[str, Any]] = []
        self.modes: dict[str, str] = {}
        self.mode = self._load("mode.json", {}).get("mode", "auto")
        self.exit_id: str | None = None
        self.fails = 0
        self.switched_at = 0.0
        self.portal_until = 0.0          # >0 while the hotel-login window is open
        self.policy = ""
        self.applied_exit: str | None = "?"
        self.dns: list[str] = []
        self.agh_dns: tuple | None = None   # upstreams AdGuard Home on the Pi was last given (None → retry)
        self.usage = self._load("usage.json", {"day": "", "bytes": 0, "phone": 0, "last": {}})
        self.usage.setdefault("phone", 0)
        self.usage.setdefault("devices", {})
        self.dev_last: dict[str, int] = {}
        self.ads_at = 0.0
        self.usage_saved = time.time()
        self.kids: set[str] = set(self._load("kids.json", []))
        self.backup: set[str] = set(self._load("backup.json", []))
        self.speed: dict[str, Any] = self._load("speed.json", {})
        self.fw_key: tuple = ()
        self.offline_since = 0.0
        self.kodi_table: str | None = None       # which routing table Kodi's traffic is sent to (None = main/direct)
        self.primary = self._load("primary.json", {}).get("ssid", "")   # hotel network we left for a backup
        self.backup_since = 0.0
        self.demoted: dict[str, float] = {}      # uplink device → when we pushed it down the route list
        self.state: dict[str, Any] = {"mode": self.mode, "status": "starting", "detail": "Starting…", "exit": None,
                                      "public": {}, "uplink": {}, "clients": 0, "today": 0, "busy": None, "toast": None,
                                      "phone_today": 0, "phone_warn": False, "on_backup": False, "speed": self.speed}
        self.wake = threading.Event()
        self.paused = False                      # set while the pre-trip check drives the exits itself
        self.state["precheck"] = self._load("precheck.json", {})
        self.reload_exits()

    # ----- persistence -----

    @staticmethod
    def _load(name: str, default: Any) -> Any:
        try:
            return json.loads((VAR / name).read_text())
        except (OSError, ValueError):
            return default

    @staticmethod
    def _save(name: str, data: Any) -> None:
        (VAR / name).write_text(json.dumps(data))

    # ----- public (called from the screen) -----

    # ----- exits -----

    def order(self, mode: str | None = None) -> list[str]:
        """Exits a mode may use, in failover order: a single country/Home, Tor = Tailscale exits, Auto = all."""
        mode = mode or self.mode
        ids = [e["id"] for e in self.exits]
        if mode in ids:
            return [mode]
        if mode == "tor":           # Tor runs on the Pi itself, which only rides Tailscale exits
            return [e["id"] for e in self.exits if e["kind"] == "ts"]
        return ids

    def exit(self, exit_id: str | None) -> dict[str, Any] | None:
        return next((e for e in self.exits if e["id"] == exit_id), None)

    def reload_exits(self) -> None:
        """(Re)read the VPN choices – at start and after a WireGuard file is added or removed. A saved mode that no
        longer exists falls back to Auto (or Direct on a router with no VPN at all)."""
        exits = wg.exits() + list(EXITS)    # Auto's order: WireGuard countries, then Tailscale exits
        with self.lock:
            self.exits, self.modes = exits, build_modes(exits)
            if self.mode not in self.modes:
                self.mode = "auto" if "auto" in self.modes else "direct"
            order = self.order()
            self.exit_id = order[0] if order else None
            self.state["mode"] = self.mode
            self.applied_exit, self.fw_key = "?", ()       # next tick re-applies everything
        self.wake.set()

    def add_vpn(self, provider: str, cc: str, text: str) -> str:
        name = wg.save(provider, cc, text)
        self.reload_exits()
        self.state["toast"] = f"VPN added: {self.exit(name)['label'] if self.exit(name) else name}"
        return name

    def remove_vpn(self, exit_id: str) -> None:
        if not (self.exit(exit_id) or {}).get("kind") == "wg":
            raise ValueError("no such VPN")
        if self.applied_exit == exit_id:
            wg.down()
        wg.remove(exit_id)
        self.reload_exits()

    def set_mode(self, mode: str) -> None:
        if mode not in self.modes:
            raise ValueError(f"unknown mode {mode}")
        with self.lock:
            self.mode = mode
            self.portal_until = 0
            self.fails = 0
            order = self.order(mode)
            self.exit_id = order[0] if order else None
            self._save("mode.json", {"mode": mode})
            self.state.update(mode=mode, toast=f"VPN: {self.modes[mode].split(' –')[0]}")
        self.wake.set()

    def start_portal(self) -> None:
        """Open the network for 10 minutes so a phone can sign in to the hotel page."""
        with self.lock:
            self.portal_until = time.time() + 600
            self.state["toast"] = "Hotel login open for 10 min"
        self.wake.set()

    def end_portal(self) -> None:
        with self.lock:
            self.portal_until = 0
            self.fails = 0
        self.wake.set()

    def scan(self) -> list[dict[str, Any]]:
        run("nmcli", "dev", "wifi", "rescan", "ifname", UPLINK, timeout=15)
        time.sleep(3)
        nets = parse_scan(run("nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY", "dev", "wifi", "list", "ifname", UPLINK,
                              "--rescan", "no"))
        known = set(self.known())
        for n in nets:
            n["known"] = n["ssid"] in known
        return nets

    def known(self) -> list[str]:
        out = []
        for line in run("nmcli", "-t", "-f", "NAME,TYPE", "con", "show").splitlines():
            f = split_nmcli(line)
            if len(f) >= 2 and f[1] == "802-11-wireless" and f[0] != "travel-ap":
                out.append(run("nmcli", "-g", "802-11-wireless.ssid", "con", "show", f[0]).strip() or f[0])
        return out

    def connect(self, ssid: str, password: str | None = None) -> str:
        """Join a network on the uplink. Returns '' on success or a short error."""
        self.state["busy"] = f"Joining {ssid}…"
        try:
            if password is None and ssid in self.known():
                name = self._con_for(ssid)
                run("nmcli", "con", "up", "id", name, "ifname", UPLINK, timeout=60, check=True)
            else:
                cmd = ["nmcli", "dev", "wifi", "connect", ssid, "ifname", UPLINK, "name", f"uplink-{ssid}"[:60]]
                if password:
                    cmd += ["password", password]
                run(*cmd, timeout=60, check=True)
                run("nmcli", "con", "modify", f"uplink-{ssid}"[:60], "connection.interface-name", UPLINK,
                    "connection.autoconnect-priority", "10")
            with self.lock:
                self.fails = 0
            self.wake.set()
            return ""
        except Exception as e:
            msg = str(e)
            if "Secrets were required" in msg or "802-11-wireless-security" in msg or "password" in msg.lower():
                return "Wrong password?"
            return msg[:80] or "Couldn't join"
        finally:
            self.state["busy"] = None

    def forget(self, ssid: str) -> None:
        name = self._con_for(ssid)
        if name:
            run("nmcli", "con", "delete", "id", name)

    # ----- devices, kids mode, address copy, backup networks, speed test -----

    @staticmethod
    def _leases() -> list[dict[str, str]]:
        try:
            return parse_leases(open("/var/lib/misc/dnsmasq.leases").read())
        except OSError:
            return []

    def devices(self) -> list[dict[str, Any]]:
        leases = self._leases()
        today = self.usage.get("devices", {})
        online = {m.lower() for m in re.findall(r"Station ([0-9a-fA-F:]{17})", run("iw", "dev", AP, "station", "dump"))}
        seen, out = set(), []
        for d in leases:
            if d["mac"] in seen:
                continue
            seen.add(d["mac"])
            out.append({**d, "online": d["mac"] in online, "kids": d["mac"] in self.kids, "today": today.get(d["mac"], 0)})
        for m in online - seen:
            out.append({"mac": m, "ip": "", "name": "", "online": True, "kids": m in self.kids, "today": today.get(m, 0)})
        return sorted(out, key=lambda d: (not d["online"], d["name"] or "~", d["ip"]))

    def set_kids(self, mac: str, on: bool) -> None:
        mac = mac.lower()
        if not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac):
            raise ValueError("bad device address")
        (self.kids.add if on else self.kids.discard)(mac)
        self._save("kids.json", sorted(self.kids))
        self.state["toast"] = "Kids mode on" if on else "Kids mode off"
        self.wake.set()

    def set_backup(self, ssid: str, on: bool) -> None:
        (self.backup.add if on else self.backup.discard)(ssid)
        self._save("backup.json", sorted(self.backup))

    def _uplink_con(self) -> str:
        return run("nmcli", "-g", "GENERAL.CONNECTION", "dev", "show", UPLINK).strip()

    def clone_state(self) -> str:
        """The address the uplink Wi-Fi uses on this network ('' = the dongle's own)."""
        con = self._uplink_con()
        if not con:
            return ""
        v = run("nmcli", "-g", "802-11-wireless.cloned-mac-address", "con", "show", con).strip().replace("\\", "")
        return v.lower() if re.fullmatch(r"[0-9a-fA-F:]{17}", v) else ""

    def clone(self, mac: str | None) -> str:
        """Use `mac` on the hotel network (so a login made on that device covers us), or None to go back."""
        con = self._uplink_con()
        if not con:
            return "Not on a Wi-Fi network"
        if mac and not re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", mac):
            return "That isn't a device address (aa:bb:cc:dd:ee:ff)"
        self.state["busy"] = "Changing address…"
        try:
            run("nmcli", "con", "modify", con, "802-11-wireless.cloned-mac-address", (mac or "permanent").lower(), check=True)
            run("nmcli", "con", "up", con, "ifname", UPLINK, timeout=60, check=True)
            self.fails = 0
            self.wake.set()
            return ""
        except Exception as e:
            return str(e)[:80]
        finally:
            self.state["busy"] = None

    def speedtest(self) -> dict[str, Any]:
        """Download speed through the VPN and on the hotel line itself, plus latency."""
        self.state["busy"] = "Speed test…"
        try:
            size = 10_000_000 if self.state.get("on_backup") or is_phone_dev((self.state.get("uplink") or {}).get("dev", "")) \
                else 25_000_000
            url = f"https://speed.cloudflare.com/__down?bytes={size}"
            res: dict[str, Any] = {"at": time.time(), "mb": size // 1_000_000}
            ex = self.exit(self.applied_exit)
            via = ["--interface", wg.IFACE] if ex and ex["kind"] == "wg" else []
            out = run("curl", "-s", *via, "-o", "/dev/null", "-m", "30", "-w", "%{speed_download} %{time_namelookup} %{time_connect}", url,
                      timeout=35).split()
            if len(out) == 3:      # latency = TCP connect time, not counting the name lookup
                res["vpn"], res["ping"] = mbps(out[0]), round((float(out[2]) - float(out[1])) * 1000)
            dev = (self.state.get("uplink") or {}).get("dev")
            if dev:
                out = run("curl", "-s", "--interface", dev, "-o", "/dev/null", "-m", "30", "-w", "%{speed_download}", url,
                          timeout=35).split()
                if out:
                    res["line"] = mbps(out[0])
            self.speed = res
            self._save("speed.json", res)
            self.state["speed"] = res
            return res
        finally:
            self.state["busy"] = None

    def precheck(self) -> dict[str, Any]:
        """Pre-trip check (run when the router comes back after weeks in a drawer): security updates, a backup to
        the backup server (if set), every VPN exit tried in turn, and a speed test. Devices on the travel Wi-Fi blip while exits are tried."""
        report: dict[str, Any] = {"at": time.time(), "exits": []}
        self.state["busy"] = "Pre-trip check: updates…"
        try:
            run("unattended-upgrade", timeout=1200)
            report["updates_left"] = run("apt", "list", "--upgradable", timeout=60).count("upgradable from")
            if SETTINGS["backup"]:
                self.state["busy"] = "Pre-trip check: backup…"
                r = subprocess.run(["/opt/travelpi/deploy/travelpi-backup"], capture_output=True, text=True, timeout=600)
                report["backup"] = "ok" if r.returncode == 0 else (r.stderr or r.stdout).strip()[-120:] or "failed"
            else:
                report["backup"] = "off"
            self.paused = True
            for ex in self.exits:
                self.state["busy"] = f"Pre-trip check: trying {ex['label']}…"
                pub: dict[str, str] = {}
                try:
                    self._apply(policy="wg" if ex["kind"] == "wg" else "tunnel", exit_id=ex["id"], dns=TUNNEL_DNS)
                    for _ in range(6):            # up to ~30 s per exit
                        time.sleep(5)
                        pub = self._trace(wg.IFACE) if ex["kind"] == "wg" else (
                            self._trace() if self._exit_active(ex["node"]) else {})
                        if pub:
                            break
                except Exception as e:
                    log.warning("precheck %s: %s", ex["id"], e)
                report["exits"].append({"id": ex["id"], "label": ex["label"], "ok": bool(pub), "ip": pub.get("ip", ""),
                                        "country": exit_country(pub) if pub else ""})
        finally:
            self.paused = False
            self.applied_exit, self.fw_key = "?", ()    # make the next tick put the chosen mode back
            self.wake.set()
            self.state["busy"] = None
        time.sleep(20)                                 # let the normal mode settle, then measure it
        try:
            report["speed"] = self.speedtest()
        except Exception as e:
            report["speed"] = {"error": str(e)[:80]}
        self._save("precheck.json", report)
        self.state["precheck"] = report
        return report

    def _con_for(self, ssid: str) -> str:
        for line in run("nmcli", "-t", "-f", "NAME,TYPE", "con", "show").splitlines():
            f = split_nmcli(line)
            if len(f) >= 2 and f[1] == "802-11-wireless" and f[0] != "travel-ap":
                if (run("nmcli", "-g", "802-11-wireless.ssid", "con", "show", f[0]).strip() or f[0]) == ssid:
                    return f[0]
        return ""

    # ----- the loop -----

    def loop(self) -> None:
        while True:
            try:
                self.tick()
            except Exception:
                log.exception("tick failed")
            self.wake.wait(CHECK_EVERY)
            self.wake.clear()

    def tick(self) -> None:
        if self.paused:
            return
        now = time.time()
        up = self._uplink()
        self._count_usage(up)
        clients = self._clients()
        portal = self.portal_until > now
        self._tor(self.mode == "tor" and not portal)       # Tor runs only while its mode is on
        if self.portal_until and not portal:
            self.portal_until = 0

        if portal or self.mode == "direct":
            self._apply(policy="open", exit_id=None, dns=up.get("dns") or ["1.1.1.1"])
            probe = self._probe_portal() if up.get("connected") else "offline"
            if portal and probe == "online":
                self.end_portal()            # signed in → straight back to the VPN
                self.state["toast"] = "Signed in – VPN back on"
            if portal:
                status, detail = "portal", "Hotel login open – sign in on your phone"
            elif probe == "portal":
                status, detail = "portal_needed", "Direct – the network wants a login"
            else:
                status, detail = ("direct", "Direct – NOT protected by the VPN") if probe == "online" else ("offline", "No internet")
            pub = self._trace() if probe == "online" else {}
            self._publish(status, detail, None, pub, up, clients)
            return

        policy = {"block": "block", "tor": "tor"}.get(self.mode, "tunnel")
        order = self.order()
        if not order:                # no VPN set up at all – only Block gets here
            self._apply(policy="block", exit_id=None, dns=up.get("dns") or ["1.1.1.1"])
            self._publish("blocked", "All internet blocked", None, {}, up, clients)
            return
        if self.exit_id not in order:
            self.exit_id = order[0]
        if self.exit_id != order[0] and now - self.switched_at > RETRY_PRIMARY:
            self.exit_id, self.fails = order[0], 0         # give the first choice another go now and then
        ex = self.exit(self.exit_id)
        if ex["kind"] == "wg" and policy == "tunnel":
            policy = "wg"
        self._apply(policy=policy, exit_id=self.exit_id, dns=TUNNEL_DNS)
        if not up.get("connected"):
            pub = {}
        elif ex["kind"] == "wg":     # devices go through Proton; test that same tunnel
            pub = self._trace(wg.IFACE)
        else:                        # only trust it if Tailscale really routes through the exit node we asked for
            pub = self._trace() if self._exit_active(ex["node"]) else {}
        if pub and self.mode == "tor":
            tor = self._tor_trace()
            if not tor:
                self.fails = 0
                self._publish("connecting", "Tor starting – can take a minute…", ex, pub, up, clients)
                return
            pub = tor
        if pub:
            self.fails = 0
            status = "blocked" if self.mode == "block" else "protected"
            detail = ("All internet blocked" if self.mode == "block" else
                      f"Via Tor (over {ex['label']} VPN) – web only" if self.mode == "tor" else f"Protected via {ex['where']}")
            self._publish(status, detail, ex, pub, up, clients)
            return
        if not up.get("connected"):
            self._publish("offline", "Not connected to Wi-Fi", ex, {}, up, clients)
            return
        self.fails += 1
        if self.fails >= FAILS_TO_SWITCH:
            nxt = next_exit(self.exit_id, order)
            if nxt:
                log.info("exit %s failing, switching to %s", self.exit_id, nxt)
                self.exit_id, self.fails, self.switched_at = nxt, 0, now
                self.state["toast"] = f"Switched to {self.exit(nxt)['label']}"
                self.wake.set()
            else:
                # every exit failed: is it a hotel login page? (devices stay blocked while we look). The Pi's own
                # traffic only rides Tailscale exits, so a Proton tunnel can stay up while the Pi looks.
                if ex["kind"] == "ts":
                    self._apply(policy=policy, exit_id=None, dns=up.get("dns") or ["1.1.1.1"])
                else:
                    self._set_dns(up.get("dns") or ["1.1.1.1"])
                probe = self._probe_portal()
                self.exit_id, self.fails = order[0], 0
                if probe == "portal":
                    self._publish("portal_needed", "This Wi-Fi needs a login – tap Hotel login", ex, {}, up, clients)
                    return
                if probe == "offline":
                    self._publish("offline", "Wi-Fi has no internet", ex, {}, up, clients)
                    return
        self._publish("connecting", f"VPN connecting ({ex['label']})…", ex, {}, up, clients)

    # ----- helpers -----

    @staticmethod
    def _local_route() -> None:
        """Replies to devices on the travel Wi-Fi must go out over it. Tailscale's exit-node table (52) and our Proton
        table (51) both hold a default route that would otherwise swallow them into the tunnel."""
        if not run("ip", "rule", "show", "priority", str(LOCAL_RULE)).strip():
            run("ip", "rule", "add", "to", AP_NET, "lookup", "main", "priority", str(LOCAL_RULE))
            log.info("added local route rule for %s", AP_NET)
        if not run("ip", "rule", "show", "priority", str(TAILNET_RULE)).strip():   # tailnet via Tailscale, even on Proton
            run("ip", "rule", "add", "to", TAILNET, "lookup", "52", "priority", str(TAILNET_RULE))

    def _apply(self, policy: str, exit_id: str | None, dns: list[str]) -> None:
        self._local_route()
        key = (policy, tuple(sorted(self.kids)))
        if key != self.fw_key:
            subprocess.run(["nft", "-f", "-"], input=fw.ruleset(policy, sorted(self.kids)), text=True, check=True, timeout=10)
            self.fw_key = key
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:   # off at boot until the kill switch is in place
                f.write("1")
            self.policy = policy
            log.info("firewall: %s", policy)
        if exit_id != self.applied_exit:
            ex = self.exit(exit_id)
            node = ex["node"] if ex and ex["kind"] == "ts" else ""
            try:   # tailscale fails until it knows its peers (e.g. at boot before there's internet) – retried next tick
                if ex and ex["kind"] == "wg":
                    wg.up(ex)
                else:
                    wg.down()
                if has_tailscale():      # routers without Tailscale only have WireGuard exits
                    run("tailscale", "set", f"--exit-node={node}", "--exit-node-allow-lan-access=false", timeout=20, check=True)
                self.applied_exit = exit_id
                log.info("exit: %s", ex["where"] if ex else "none")
            except Exception as e:
                log.warning("couldn't switch to %s: %s", exit_id, e)
        self._kodi_route(policy)
        self._set_dns(dns)

    def _kodi_route(self, policy: str) -> None:
        """Route Kodi's own internet traffic (IPTV, add-ons) through the active VPN exit, so geo-locked channels see the
        VPN country instead of the Pi's uplink. Kodi's packets are marked 0x33 by the firewall (local/tailnet excluded);
        here we point that mark at the exit's table – the Proton tunnel (51) or the Tailscale exit (52). Off otherwise."""
        table = "51" if policy == "wg" else "52" if policy == "tunnel" else ""
        if table == self.kodi_table:
            return
        for _ in range(3):                           # clear any existing fwmark rule first (idempotent)
            run("ip", "rule", "del", "fwmark", "0x33")
        if table:
            run("ip", "rule", "add", "fwmark", "0x33", "lookup", table, "priority", str(KODI_RULE))
        self.kodi_table = table
        log.info("kodi exit routing: %s", table or "off (direct)")

    def _set_dns(self, dns: list[str]) -> None:
        if dns != self.dns:
            text = "".join(f"nameserver {d}\n" for d in dns)
            RESOLV.write_text(text)
            open("/etc/resolv.conf", "w").write(text)
            self.dns = dns
        want = adguard.upstreams_for(dns, tunnel=dns == TUNNEL_DNS)     # devices' DNS: AdGuard Home on the Pi
        if want != self.agh_dns:
            try:
                adguard.set_upstreams(*want)
                self.agh_dns = want
                log.info("adguard upstream: %s", ", ".join(want[0]))
            except Exception as e:                  # not installed yet / restarting – tried again next tick
                log.info("adguard upstream not set: %s", e)

    def _uplink(self) -> dict[str, Any]:
        """Which uplink is connected (Wi-Fi dongle, Ethernet or a phone over USB), its name, signal and DNS."""
        devs = {}
        for line in run("nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "dev").splitlines():
            f = split_nmcli(line)
            if len(f) >= 4:
                devs[f[0]] = {"type": f[1], "state": f[2], "con": f[3]}
        # the device carrying the default route first (a demoted dead uplink may still be "connected")
        routes = sorted((int(m.group(2) or 0), m.group(1)) for m in
                        re.finditer(r"default .*?dev (\S+)(?:.*?metric (\d+))?", run("ip", "-4", "route", "show", "default")))
        order = list(dict.fromkeys([d for _, d in routes] + [UPLINK, *WIRED] + [d for d in devs if is_phone_dev(d)]))
        for dev in order:
            d = devs.get(dev)
            if d and d["state"].startswith("connected"):
                info: dict[str, Any] = {"connected": True, "dev": dev, "name": d["con"]}
                if dev == UPLINK:
                    for line in run("nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL", "dev", "wifi", "list", "ifname", UPLINK,
                                    "--rescan", "no").splitlines():
                        f = split_nmcli(line)
                        if f[0] == "*":
                            info.update(name=f[1], signal=int(f[2] or 0))
                            break
                else:
                    info["name"] = "Ethernet" if dev in WIRED else "Phone (USB)"
                info["dns"] = [x for x in run("nmcli", "-g", "IP4.DNS", "dev", "show", dev).strip().split(" | ") if x][:2]
                return info
        return {"connected": False}

    def _trace(self, iface: str = "") -> dict[str, str]:
        bind = ["--interface", iface] if iface else []
        out = run("curl", "-s", "-m", "8", *bind, "https://1.1.1.1/cdn-cgi/trace", timeout=12)
        return parse_trace(out) if "ip=" in out else {}

    def _tor(self, on: bool) -> None:
        running = run("systemctl", "is-active", "tor").strip() == "active"
        if on and not running:
            log.info("starting tor")
            run("systemctl", "start", "tor", timeout=30)
        elif not on and running:
            log.info("stopping tor")
            run("systemctl", "stop", "tor", timeout=30)

    def _tor_trace(self) -> dict[str, str]:
        out = run("curl", "-s", "-m", "20", "--socks5-hostname", "127.0.0.1:9050", "https://1.1.1.1/cdn-cgi/trace", timeout=25)
        return parse_trace(out) if "ip=" in out else {}

    def _exit_active(self, node: str) -> bool:
        if not has_tailscale():
            return False
        try:
            st = json.loads(run("tailscale", "status", "--json", timeout=10))
        except ValueError:
            return False
        return exit_in_use(st, node)

    def _probe_portal(self) -> str:
        code = run("curl", "-s", "-m", "6", "-o", "/dev/null", "-w", "%{http_code}",
                   "http://connectivitycheck.gstatic.com/generate_204", timeout=10).strip()
        return portal_from_probe(code)

    def _names(self) -> dict[str, str]:
        return {d["ip"]: d["name"] for d in self._leases() if d.get("name")}

    def adblock_overview(self) -> dict:
        return adguard.overview(self._names())

    def adblock_action(self, body: dict) -> dict:
        adguard.act(body)
        self.ads_at = 0                              # the screen's numbers refresh on the next tick
        return adguard.overview(self._names())

    def adblock(self, pause_minutes: int = 0) -> dict:
        """Pause ad-blocking for a while (sites that break), or turn it back on (0); returns fresh stats."""
        if pause_minutes:
            adguard.pause(pause_minutes)
        else:
            adguard.resume()
        self.ads_at = 0                              # refresh the numbers on the next tick
        return adguard.stats({d["ip"]: d["name"] for d in self._leases() if d.get("name")})

    def _clients(self) -> int:
        return run("iw", "dev", AP, "station", "dump").count("Station ")

    def _count_usage(self, up: dict) -> None:
        today, u = date.today().isoformat(), self.usage
        if u.get("day") != today:
            u.update(day=today, bytes=0, phone=0, warned=False, devices={})
        try:   # per-device data (separate counting table, survives firewall changes)
            stats.ensure_acct()
            ip_mac = {d["ip"]: d["mac"] for d in self._leases()}
            stats.add_deltas(u["devices"], self.dev_last, stats.read_counters(), ip_mac)
        except Exception as e:
            log.warning("device counters: %s", e)
        if time.time() - self.ads_at > 60:
            self.ads_at = time.time()
            try:
                names = {d["ip"]: d["name"] for d in self._leases() if d.get("name")}
                self.state["ads"] = adguard.stats(names)
            except Exception as e:
                log.info("adguard stats: %s", e)
                self.state["ads"] = None
        on_backup = up.get("dev") == UPLINK and up.get("name") in self.backup
        for dev in [UPLINK, *WIRED] + [d for d in os.listdir("/sys/class/net") if is_phone_dev(d)]:
            try:
                rx = int(open(f"/sys/class/net/{dev}/statistics/rx_bytes").read())
                tx = int(open(f"/sys/class/net/{dev}/statistics/tx_bytes").read())
            except OSError:
                continue
            total, last = rx + tx, u["last"].get(dev)
            if last is not None and total >= last:
                u["bytes"] += total - last
                if is_phone_dev(dev) or (dev == UPLINK and on_backup):
                    u["phone"] += total - last
            u["last"][dev] = total
        if u["phone"] >= PHONE_WARN and not u.get("warned"):
            u["warned"] = True
            self.state["toast"] = f"Phone data today: {u['phone'] / 1e9:.1f} GB"
        self.state.update(phone_today=u["phone"], phone_warn=u["phone"] >= PHONE_WARN, on_backup=on_backup)
        if time.time() - self.usage_saved > USAGE_SAVE_EVERY:      # SD cards wear out: not every 10 s
            self.save_usage()

    def save_usage(self) -> None:
        self._save("usage.json", self.usage)
        self.usage_saved = time.time()

    def _publish(self, status: str, detail: str, ex: dict | None, pub: dict, up: dict, clients: int) -> None:
        self._uplink_failover(status, up)
        try:
            self.state["hw"] = hardware()
        except Exception:
            log.exception("hardware info failed")
        if pub:
            pub = {**pub, "country": exit_country(pub)}
        with self.lock:
            self.state.update(status=status, detail=detail, exit=ex, public=pub, uplink=up, clients=clients,
                              today=self.usage["bytes"], mode=self.mode, updated=time.time())
        (RUN / "state.json").write_text(json.dumps({k: v for k, v in self.state.items() if k != "toast"}))

    def _uplink_failover(self, status: str, up: dict) -> None:
        """Hotel internet dead for a minute → use another uplink: a plugged-in phone/Ethernet, else a backup Wi-Fi
        (e.g. your phone's hotspot). On a backup network, try the hotel Wi-Fi again every 10 minutes."""
        now = time.time()
        dead = status == "offline" and up.get("connected")
        self.offline_since = (self.offline_since or now) if dead else 0
        for dev, t in list(self.demoted.items()):            # give demoted uplinks another chance now and then
            if now - t > PRIMARY_RETRY:
                run("nmcli", "dev", "modify", dev, "ipv4.route-metric", "-1")
                del self.demoted[dev]
        on_backup = up.get("dev") == UPLINK and up.get("name") in self.backup
        if on_backup and not self.backup_since:
            self.backup_since = now
        if not on_backup:
            self.backup_since = 0
        if dead and now - self.offline_since > BACKUP_AFTER:
            self.offline_since = now
            others = [d for d in self._connected_uplinks() if d != up.get("dev")]
            if others:
                log.info("uplink %s has no internet – moving traffic to %s", up["dev"], others[0])
                run("nmcli", "dev", "modify", up["dev"], "ipv4.route-metric", "5000")
                self.demoted[up["dev"]] = now
                self.state["toast"] = "No internet here – using your phone"
                self.wake.set()
                return
            if up.get("dev") == UPLINK and not on_backup:
                visible = {n["ssid"] for n in parse_scan(run("nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY", "dev",
                                                             "wifi", "list", "ifname", UPLINK, "--rescan", "no"))}
                spare = next((s for s in sorted(self.backup) if s in visible), None)
                if spare:
                    log.info("%s has no internet – joining backup %s", up.get("name"), spare)
                    self.primary = up.get("name", "")
                    self._save("primary.json", {"ssid": self.primary})
                    self.state["toast"] = f"No internet – switching to {spare}"
                    threading.Thread(target=self.connect, args=(spare,), daemon=True).start()
                    return
        if on_backup and self.primary and now - self.backup_since > PRIMARY_RETRY:
            self.backup_since = now
            visible = {n["ssid"] for n in parse_scan(run("nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY", "dev",
                                                         "wifi", "list", "ifname", UPLINK, "--rescan", "no"))}
            if self.primary in visible:
                log.info("trying %s again", self.primary)
                self.state["toast"] = f"Trying {self.primary} again"
                threading.Thread(target=self.connect, args=(self.primary,), daemon=True).start()

    def _connected_uplinks(self) -> list[str]:
        out = []
        for line in run("nmcli", "-t", "-f", "DEVICE,STATE", "dev").splitlines():
            f = split_nmcli(line)
            if len(f) >= 2 and f[1] == "connected" and (f[0] in (UPLINK, *WIRED) or is_phone_dev(f[0])):
                out.append(f[0])
        return out

    def tv(self, action: str) -> None:
        """Start or stop TV mode (Kodi on the HDMI port)."""
        if action not in ("start", "stop"):
            raise ValueError("start or stop")
        if not os.path.exists("/etc/systemd/system/kodi.service"):
            raise ValueError("TV mode isn't installed (deploy/kodi-install.sh)")
        if action == "start" and subprocess.run(["/usr/local/sbin/hdmi-connected"]).returncode:
            raise ValueError("Plug the router into a TV first (HDMI)")
        run("systemctl", action, "kodi", timeout=30, check=True)
        self.state["toast"] = "TV mode on" if action == "start" else "TV mode off"

    def settings_view(self) -> dict[str, Any]:
        """What the settings sections of the phone page and Sentinel show."""
        cur = load_settings()
        return {"settings": {k: cur[k] for k in EDITABLE}, "tailscale": has_tailscale(),
                "backup": bool(cur.get("backup")), "home_wifi": cur.get("home_wifi", "")}

    def apply_settings(self, body: dict[str, Any]) -> None:
        """Check and save changed settings, then restart the controller so they take effect (a few seconds; the
        travel Wi-Fi itself stays up). Raises ValueError for anything not allowed."""
        cur = load_settings()
        new = clean_settings(body, cur, taken={e["id"] for e in self.exits if e["kind"] == "wg"})
        save_settings(new)
        if new["sentinel"] != cur.get("sentinel"):
            try:
                adguard.set_rewrite("sentinel", new["sentinel"])
            except Exception as e:
                log.warning("sentinel name not updated in AdGuard: %s", e)
        log.info("settings changed – restarting")
        self.save_usage()
        threading.Timer(2, subprocess.Popen, args=(["systemctl", "--no-block", "restart", "travelpi"],)).start()

    def ap_info(self) -> dict[str, str]:
        try:
            env = read_env((ETC / "ap.env").read_text())
        except OSError:
            env = {}
        return {"ssid": env.get("SSID", ""), "password": env.get("PSK", "")}

    def set_ap(self, ssid: str, password: str) -> None:
        """New name/password for the travel Wi-Fi. Every device drops off and has to join again with the new
        details, so the access point restarts a few seconds later (the phone page gets its answer first)."""
        ssid, password = check_ap(ssid, password)
        run("nmcli", "con", "modify", "travel-ap", "802-11-wireless.ssid", ssid, "wifi-sec.psk", password, check=True)
        old = os.umask(0o077)
        try:
            (ETC / "ap.env").write_text(f"SSID={shlex.quote(ssid)}\nPSK={shlex.quote(password)}\n")
        finally:
            os.umask(old)
        log.info("travel Wi-Fi renamed to %s", ssid)

        def restart() -> None:
            time.sleep(3)
            run("nmcli", "con", "up", "travel-ap", timeout=60)
        threading.Thread(target=restart, daemon=True).start()
