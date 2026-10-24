#!/usr/bin/env bash
# TV mode: Kodi on the Pi's HDMI port – Plex from home (Plex add-on, over the VPN/Tailscale), free world TV channels
# (iptv-org's public list in the IPTV Simple client) and films from a USB drive. Safe to run again.
#  - runs as its own user "kodi" (no sudo); starts at boot only when a TV is plugged in, or from the phone page/Sentinel
#  - the router's touch screen is hidden from Kodi (udev), so taps on it never reach the TV
#  - HEVC/H.264 hardware decoding needs the KMS display driver (dtoverlay=vc4-kms-v3d) – added if missing; reboot after
# Usage: sudo bash kodi-install.sh
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
export DEBIAN_FRONTEND=noninteractive

apt-get -qq update
apt-get -qq install -y kodi kodi-pvr-iptvsimple kodi-inputstream-adaptive cec-utils >/dev/null

id kodi >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/kodi --shell /usr/sbin/nologin kodi
usermod -aG audio,video,render kodi                # not "input": HDMI-CEC + keyboards come through other paths
install -d -o kodi -g kodi /var/lib/kodi/.kodi/temp /var/lib/kodi/.kodi/userdata/addon_data/pvr.iptvsimple

# the router's touch screen belongs to the router only
cat > /etc/udev/rules.d/90-travelpi-touch.rules <<'RULE'
SUBSYSTEM=="input", ATTRS{name}=="ADS7846 Touchscreen", MODE="0600", GROUP="root", ENV{LIBINPUT_IGNORE_DEVICE}="1"
RULE
udevadm control --reload && udevadm trigger --subsystem-match=input

# free world TV: English-language channels from iptv-org (public, legal streams); change in Kodi → PVR IPTV Simple
SETTINGS=/var/lib/kodi/.kodi/userdata/addon_data/pvr.iptvsimple/instance-settings-1.xml
if [ ! -f "$SETTINGS" ]; then
  cat > "$SETTINGS" <<'XML'
<settings version="2">
    <setting id="kodi_addon_instance_name">World TV (iptv-org)</setting>
    <setting id="kodi_addon_instance_enabled">true</setting>
    <setting id="m3uPathType">1</setting>
    <setting id="m3uUrl">https://iptv-org.github.io/iptv/languages/eng.m3u</setting>
    <setting id="m3uCache">true</setting>
    <setting id="epgPathType">1</setting>
    <setting id="logoFromEpg">1</setting>
</settings>
XML
  chown kodi:kodi "$SETTINGS"
fi

# Kodi's JSON-RPC for the remote on the phone page/Sentinel: on, with a login (port 8080 is firewalled to the Pi itself)
if [ ! -f /etc/travelpi/kodi.env ]; then
  pass=$(python3 -c "import secrets; print(secrets.token_urlsafe(18))")
  umask 077; printf 'KODI_USER=travelpi\nKODI_PASS=%s\n' "$pass" > /etc/travelpi/kodi.env; umask 022
fi
. /etc/travelpi/kodi.env
GUI=/var/lib/kodi/.kodi/userdata/guisettings.xml
if [ ! -f "$GUI" ]; then
  cat > "$GUI" <<XML
<settings version="2">
    <setting id="services.webserver">true</setting>
    <setting id="services.webserverport">8080</setting>
    <setting id="services.webserverauthentication">true</setting>
    <setting id="services.webserverusername">$KODI_USER</setting>
    <setting id="services.webserverpassword">$KODI_PASS</setting>
    <setting id="services.esenabled">false</setting>
    <setting id="services.zeroconf">false</setting>
    <setting id="services.upnp">false</setting>
</settings>
XML
  chown kodi:kodi "$GUI"; chmod 600 "$GUI"
fi
chmod 700 /var/lib/kodi

install -m 755 "$SRC/hdmi-connected" /usr/local/sbin/hdmi-connected
install -m 644 "$SRC/kodi.service" /etc/systemd/system/kodi.service
systemctl daemon-reload
systemctl enable -q kodi

CFG=/boot/firmware/config.txt; [ -f "$CFG" ] || CFG=/boot/config.txt
if ! grep -qE "^dtoverlay=vc4-kms-v3d" "$CFG"; then
  cp -a "$CFG" "$CFG.before-kodi"
  printf '\n# TV mode (Kodi): KMS display driver for hardware video decoding\ndtoverlay=vc4-kms-v3d\n' >> "$CFG"
  echo "Added the KMS display driver – reboot to use TV mode."
fi
echo "Kodi installed. Plug in a TV and reboot, or start it from the phone page (TV)."
