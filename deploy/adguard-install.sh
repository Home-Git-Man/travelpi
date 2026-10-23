#!/usr/bin/env bash
# AdGuard Home on the Pi: DNS + ad-blocking for the travel Wi-Fi (setup-network.sh step 12; safe to run again).
#  - official release from GitHub (AdGuardHome_linux_arm64.tar.gz), checked against the release's checksums.txt
#  - DNS on 10.42.0.1:53 only (dnsmasq keeps DHCP, port=0); admin API on 127.0.0.1:3080 only,
#    login in /etc/travelpi/adguard-local.env (root-only)
#  - "travelpi" answers 10.42.0.1 (the phone page); with settings.json: fallback DNS, "sentinel" → its address, and
#    the blocklists copied from your own AdGuard (/etc/travelpi/adguard.env) – otherwise AdGuard's default list
#  - query log in memory only and 24 h of statistics: easy on the SD card
# Upstream DNS is set by travelpi.service per mode (travelpi/adguard.py).
# Usage: sudo bash adguard-install.sh [--upgrade]
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
DIR=/opt/AdGuardHome
ENV=/etc/travelpi/adguard-local.env

if [ ! -x "$DIR/AdGuardHome" ] || [ "${1:-}" = "--upgrade" ]; then
  tag=$(curl -fsS https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest | python3 -c "import json,sys; print(json.load(sys.stdin)['tag_name'])")
  tmp=$(mktemp -d)
  base="https://github.com/AdguardTeam/AdGuardHome/releases/download/$tag"
  curl -fsSL -o "$tmp/AdGuardHome_linux_arm64.tar.gz" "$base/AdGuardHome_linux_arm64.tar.gz"
  curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt"
  (cd "$tmp" && grep -E " (\./)?AdGuardHome_linux_arm64\.tar\.gz$" checksums.txt | sha256sum -c -) \
    || { echo "AdGuard Home download doesn't match its checksum – not installed"; rm -rf "$tmp"; exit 1; }
  systemctl stop AdGuardHome 2>/dev/null || true
  tar -xzf "$tmp/AdGuardHome_linux_arm64.tar.gz" -C /opt
  rm -rf "$tmp"
  echo "AdGuard Home $tag in $DIR"
fi
[ -f /etc/systemd/system/AdGuardHome.service ] || "$DIR/AdGuardHome" -s install
mkdir -p /etc/systemd/system/AdGuardHome.service.d
printf '[Service]\nRestart=always\nRestartSec=3\n' > /etc/systemd/system/AdGuardHome.service.d/travelpi.conf
systemctl daemon-reload

# dnsmasq: DHCP only from now on (frees 10.42.0.1:53 for AdGuard Home)
install -m 644 "$SRC/dnsmasq-travelpi.conf" /etc/dnsmasq.d/travelpi.conf
systemctl restart dnsmasq

if [ ! -f "$DIR/AdGuardHome.yaml" ]; then          # first run: answer the setup wizard through its API
  pass=$(python3 -c "import secrets; print(secrets.token_urlsafe(18))")
  umask 077; printf 'ADGUARD_USER=travelpi\nADGUARD_PASS=%s\n' "$pass" > "$ENV"; umask 022
  systemctl restart AdGuardHome
  for i in $(seq 1 30); do curl -fs -o /dev/null http://127.0.0.1:3000/control/install/get_addresses && break; sleep 1; done
  curl -fsS -X POST http://127.0.0.1:3000/control/install/configure -H 'Content-Type: application/json' \
    -d "{\"web\":{\"ip\":\"127.0.0.1\",\"port\":3080},\"dns\":{\"ip\":\"10.42.0.1\",\"port\":53},\"username\":\"travelpi\",\"password\":\"$pass\"}"
  echo; sleep 3
fi
systemctl enable -q --now AdGuardHome

python3 - <<'PY'
import base64, json, time, urllib.request
env = lambda p: dict(l.split("=", 1) for l in open(p).read().splitlines() if "=" in l)
me = env("/etc/travelpi/adguard-local.env")
try:
    settings = json.load(open("/etc/travelpi/settings.json"))
except (OSError, ValueError):
    settings = {}
fallback = settings.get("dns_fallback") or "9.9.9.9"
def api(base, user, pw, path, body=None, method=None):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                 method=method or ("POST" if body is not None else "GET"))
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode())
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read()
    try:
        return json.loads(raw) if raw.strip() else None
    except ValueError:                     # some calls answer plain text ("OK: added …")
        return raw.decode(errors="replace")
local = lambda path, body=None, method=None: api("http://127.0.0.1:3080", me["ADGUARD_USER"], me["ADGUARD_PASS"], path,
                                               body, method)
for _ in range(30):
    try:
        local("/control/status"); break
    except Exception:
        time.sleep(1)
local("/control/dns_config", {"upstream_dns": ["https://dns.quad9.net/dns-query", "https://cloudflare-dns.com/dns-query"],
                              "fallback_dns": [fallback], "bootstrap_dns": ["9.9.9.9", "1.1.1.1"],
                              "cache_size": 4194304, "cache_optimistic": True, "ratelimit": 0})
local("/control/querylog/config/update", {"enabled": True, "interval": 86400000, "anonymize_client_ip": False,
                                          "ignored": []}, "PUT")
local("/control/stats/config/update", {"enabled": True, "interval": 86400000, "ignored": []}, "PUT")
have = {f["url"] for f in local("/control/filtering/status").get("filters") or []}
import os
if os.path.exists("/etc/travelpi/adguard.env") and settings.get("dns_fallback"):   # your own AdGuard's lists
    try:
        v = env("/etc/travelpi/adguard.env")
        theirs = api(f"http://{settings['dns_fallback']}:3080", v["ADGUARD_USER"], v["ADGUARD_PASS"], "/control/filtering/status")
        for f in theirs.get("filters") or []:
            if f.get("enabled") and f["url"] not in have:
                local("/control/filtering/add_url", {"name": f["name"], "url": f["url"], "whitelist": False})
                print("blocklist added:", f["name"])
    except Exception as e:
        print("couldn't copy your AdGuard's blocklists (kept AdGuard's defaults):", e)
local("/control/filtering/refresh", {"whitelist": False})
# iCloud Private Relay off on the travel Wi-Fi (Apple's way: NXDOMAIN for its entry points). Otherwise Safari skips
# the ad-blocking (and can't reach Tailscale addresses); the router already hides everything behind the VPN.
NO_RELAY = ["||mask.icloud.com^$dnsrewrite=NXDOMAIN", "||mask-h2.icloud.com^$dnsrewrite=NXDOMAIN"]
rules = [r for r in local("/control/filtering/status").get("user_rules") or [] if r.strip()]
if any(r not in rules for r in NO_RELAY):
    local("/control/filtering/set_rules", {"rules": rules + [r for r in NO_RELAY if r not in rules]})
    print("iCloud Private Relay turned off for the travel Wi-Fi")
names = {"travelpi": "10.42.0.1", **({"sentinel": settings["sentinel"]} if settings.get("sentinel") else {})}
have_rw = {r["domain"] for r in local("/control/rewrite/list") or []}
for domain, answer in names.items():
    if domain not in have_rw:
        local("/control/rewrite/add", {"domain": domain, "answer": answer})
print("AdGuard Home configured:", len(local("/control/filtering/status").get("filters") or []), "blocklists")
PY

# query log in memory only (the API has no switch for it)
if grep -q "file_enabled: true" "$DIR/AdGuardHome.yaml"; then
  systemctl stop AdGuardHome
  sed -i 's/file_enabled: true/file_enabled: false/' "$DIR/AdGuardHome.yaml"
  systemctl start AdGuardHome
fi
python3 - <<'PY'                           # does 10.42.0.1 answer DNS? (a raw query – dig isn't installed)
import socket, struct, time
q = struct.pack(">HHHHHH", 0x5470, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
for _ in range(20):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1.5)
        s.sendto(q, ("10.42.0.1", 53)); r = s.recv(512)
        print("DNS on 10.42.0.1: answering (%d answer records)" % struct.unpack(">H", r[6:8])[0]); break
    except OSError:
        time.sleep(1)
else:
    print("DNS on 10.42.0.1: NOT answering")
PY
