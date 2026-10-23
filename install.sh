#!/usr/bin/env bash
# TravelPi installer: turns a Raspberry Pi into a travel router for the family.
#   - a private Wi-Fi of your own (the Pi's built-in Wi-Fi) that every device joins once, anywhere
#   - the hotel / airport / caravan-park Wi-Fi is joined with a USB Wi-Fi adapter (or Ethernet, or a phone over USB)
#   - VPN with a kill switch (free Proton VPN or any WireGuard VPN, optional Tailscale exit nodes), ad-blocking,
#     kids mode, hotel-login helper, data counter – run from the 3.5" touch screen or a phone page
#
# Needs: Raspberry Pi 3B+/4/5 (or Zero 2 W, 2.4 GHz only) with Raspberry Pi OS Lite 64-bit, set up in Raspberry Pi
# Imager with your home Wi-Fi, a user and SSH; plus a USB Wi-Fi adapter that Linux supports out of the box.
#
# Run it on the Pi (over SSH):
#   curl -fsSL https://raw.githubusercontent.com/OWNER/travelpi/main/install.sh | sudo bash
# or from a copy of the code:   sudo bash install.sh
# Run it again to upgrade or change answers; nothing is lost.
set -euo pipefail
REPO=${TRAVELPI_REPO:-https://github.com/OWNER/travelpi.git}
DEST=/opt/travelpi
ETC=/etc/travelpi

say() { printf '\n\033[1;36m%s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
ask() {   # ask "question" "default" → answer (reads the keyboard even when piped from curl)
  local a; read -r -p "$1${2:+ [$2]}: " a </dev/tty || true; printf '%s' "${a:-${2:-}}"
}
yes_no() { case "$(ask "$1 (y/n)" "$2")" in [Yy]*) return 0 ;; *) return 1 ;; esac; }

[ "$(id -u)" = 0 ] || { echo "Please run with sudo: sudo bash install.sh"; exit 1; }
grep -qi "raspberry pi" /proc/device-tree/model 2>/dev/null || { echo "This isn't a Raspberry Pi."; exit 1; }
[ "$(uname -m)" = aarch64 ] || { echo "Needs the 64-bit Raspberry Pi OS (Lite)."; exit 1; }
systemctl is-active -q NetworkManager || { echo "Needs NetworkManager (Raspberry Pi OS Bookworm or newer)."; exit 1; }

say "TravelPi installer – $(tr -d '\0' < /proc/device-tree/model)"
builtin="" usb=""
for d in /sys/class/net/*; do
  drv=$(basename "$(readlink -f "$d/device/driver" 2>/dev/null)")
  [ -d "$d/wireless" ] || [ -d "$d/phy80211" ] || continue
  if [ "$drv" = brcmfmac ]; then builtin=$(basename "$d"); else usb=$(basename "$d"); fi
done
[ -n "$builtin" ] || { echo "Can't find the Pi's built-in Wi-Fi."; exit 1; }
if [ -z "$usb" ]; then
  warn "No USB Wi-Fi adapter found. It joins the hotel Wi-Fi; without one only Ethernet or a phone over USB work."
  yes_no "Carry on anyway?" n || exit 1
fi
warn "Run this from a computer on your home network (SSH). The Pi's Wi-Fi changes at the end, so keep power on."

# ----- questions -----
env_value() {   # env_value KEY → its (shell-quoted) value in ap.env
  [ -f "$ETC/ap.env" ] || return 0
  python3 -c 'import shlex,sys; e=dict(l.split("=",1) for l in open(sys.argv[1]).read().splitlines() if "=" in l); v=e.get(sys.argv[2],""); print(shlex.split(v)[0] if v.strip() else "")' "$ETC/ap.env" "$1"
}
old_ssid=$(env_value SSID)
say "1/5 Your travel Wi-Fi (the network your family's devices join)"
SSID=$(ask "Wi-Fi name" "${old_ssid:-TravelPi}")
while :; do
  PSK=$(ask "Password, 8 or more characters (Enter = make one up / keep the current one)" "")
  [ -z "$PSK" ] || [ ${#PSK} -ge 8 ] && break
  warn "At least 8 characters, please."
done
[ -n "$PSK" ] || PSK=$(env_value PSK)
[ -n "$PSK" ] || PSK=$(python3 -c 'import secrets; a="abcdefghjkmnpqrstuvwxyz23456789"; print("".join(secrets.choice(a) for _ in range(12)))')

say "2/5 Wi-Fi country (sets which Wi-Fi channels are allowed – use your home country)"
COUNTRY=$(ask "Two-letter country code" "$(iw reg get 2>/dev/null | sed -n 's/^country \([A-Z][A-Z]\).*/\1/p' | head -1 | sed 's/00//')")
COUNTRY=${COUNTRY:-AU}

say "3/5 Screen"
SCREEN=n
yes_no "Do you have the 3.5\" MHS / Waveshare-style SPI touch screen (ILI9486) on the pins?" n && SCREEN=y

say "4/5 Tailscale (optional – reach home through your own Tailscale exit node, e.g. for home streaming apps)"
TS=n EXIT_NODE="" EXIT_LABEL=""
if yes_no "Use Tailscale?" n; then
  TS=y
  EXIT_NODE=$(ask "Machine name of your exit node at home (Enter = none for now)" "")
  [ -z "$EXIT_NODE" ] || EXIT_LABEL=$(ask "Short name for it on the screen" "Home")
fi

say "5/5 Router name (shown on the screen and the phone page)"
NAME=$(ask "Name" "TravelPi")

# ----- packages and code -----
say "Installing packages (a few minutes)…"
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq install -y git python3-pil python3-numpy python3-evdev python3-qrcode python3-pytest fonts-dejavu-core \
  dnsmasq nftables iw rsync curl wireguard-tools zstd usbmuxd tor unattended-upgrades >/dev/null
systemctl disable --now dnsmasq >/dev/null 2>&1 || true      # started again by the network setup

SRC=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)
if [ -n "$SRC" ] && [ -d "$SRC/travelpi" ] && [ "$SRC" != "$DEST" ]; then
  mkdir -p "$DEST" && rsync -a --delete --exclude .git --exclude __pycache__ --exclude local "$SRC/" "$DEST/"
elif [ -d "$DEST/.git" ]; then
  git -C "$DEST" pull -q --ff-only
elif [ ! -d "$DEST/travelpi" ]; then
  git clone -q --depth 1 "$REPO" "$DEST"
fi
install -m 755 "$DEST/deploy/travelpi-update" /usr/local/sbin/travelpi-update

if [ "$TS" = y ] && ! command -v tailscale >/dev/null; then
  say "Installing Tailscale…"
  curl -fsSL https://tailscale.com/install.sh | sh
fi

# ----- settings -----
mkdir -p "$ETC" && chmod 755 "$ETC"
python3 - "$NAME" "$EXIT_NODE" "$EXIT_LABEL" "$ETC/settings.json" <<'PY'
import json, os, sys
name, node, label, path = sys.argv[1:5]
try:
    s = json.load(open(path))
except (OSError, ValueError):
    s = {}
s["name"] = name.strip()[:24] or "TravelPi"
if node:
    s["tailscale_exits"] = [{"id": "home", "node": node, "label": label or "Home", "where": f"{label or 'Home'} internet"}]
json.dump(s, open(path, "w"), indent=2)
PY
python3 - "$SSID" "$PSK" "$ETC/ap.env" <<'PY'
import os, shlex, sys
ssid, psk, path = sys.argv[1:4]
if not 1 <= len(ssid.encode()) <= 32 or not 8 <= len(psk) <= 63:
    sys.exit("Wi-Fi name must be 1-32 characters and the password 8-63")
os.umask(0o077)
open(path, "w").write(f"SSID={shlex.quote(ssid)}\nPSK={shlex.quote(psk)}\n")
PY

command -v raspi-config >/dev/null && raspi-config nonint do_wifi_country "$COUNTRY" >/dev/null 2>&1 || iw reg set "$COUNTRY" || true
rfkill unblock wifi 2>/dev/null || true

if [ "$SCREEN" = y ]; then
  CFG=/boot/firmware/config.txt; [ -f "$CFG" ] || CFG=/boot/config.txt
  CMD=/boot/firmware/cmdline.txt; [ -f "$CMD" ] || CMD=/boot/cmdline.txt
  grep -q "^dtparam=spi=on" "$CFG" || echo "dtparam=spi=on" >> "$CFG"
  grep -q "^dtoverlay=piscreen" "$CFG" || echo "dtoverlay=piscreen,speed=32000000,rotate=90" >> "$CFG"
  grep -q "fbcon=map:2" "$CMD" || sed -i '1 s/$/ fbcon=map:2/' "$CMD"
fi

# security updates, never an automatic reboot
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades

say "Setting up the router's network…"
bash "$DEST/deploy/setup-network.sh"

if [ "$TS" = y ] && ! tailscale status >/dev/null 2>&1; then
  say "Sign this router in to Tailscale: open the link below on your phone or computer."
  tailscale up --accept-dns=false --accept-routes=false || warn "Tailscale sign-in didn't finish – run 'sudo tailscale up' later."
fi

cat <<DONE

$(printf '\033[1;32m')TravelPi is installed.$(printf '\033[0m')

  Travel Wi-Fi:  $SSID
  Password:      $PSK          (write it down – you can change it later)
  Control page:  http://10.42.0.1  or  http://travelpi   (from the travel Wi-Fi)

Next:
  1. Reboot (below). The Pi joins your home Wi-Fi with the USB adapter and starts the travel Wi-Fi.
  2. Within 7 minutes, join "$SSID" on your phone and open http://10.42.0.1 – that confirms the setup.
     (If nobody does, the Pi undoes the network changes and reboots, so you can't get locked out.)
  3. Add a VPN on that page: VPN locations → Add a WireGuard VPN file (Proton VPN's free plan works).
  Later: 'sudo travelpi-update' gets the newest version.
DONE
if yes_no "Reboot now?" y; then systemctl reboot; fi
