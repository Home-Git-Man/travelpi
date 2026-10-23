#!/usr/bin/env bash
# One-time network setup for the travel router (run as root on the Pi; idempotent).
#  - pins names: NETGEAR dongle → wlup (uplink), built-in Wi-Fi → wlap (private network)
#  - home Wi-Fi profile moves to the dongle; built-in Wi-Fi becomes the travel Wi-Fi access point (10.42.0.1/24),
#    name/password from /etc/travelpi/ap.env (install.sh asks; changeable later on the screen or phone page)
#  - dnsmasq hands out addresses; travelpi.service owns DNS, the kill switch and the VPN
#  - SAFETY: unless /etc/travelpi/net-confirmed exists 7 min after boot, the old settings come back and it reboots.
set -euo pipefail
SSID=TravelPi
SRC=/opt/travelpi/deploy
BK=/etc/travelpi/rollback
mkdir -p /etc/travelpi "$BK"

if [ ! -f "$BK/saved" ]; then
  [ -d /etc/netplan ] && cp -a /etc/netplan "$BK/netplan"
  cp -a /etc/NetworkManager/system-connections "$BK/nm-connections"
  cp -aL /etc/resolv.conf "$BK/resolv.conf" 2>/dev/null || true
  touch "$BK/saved"
fi

# 1. fixed interface names: the Pi's own Wi-Fi is always the access point; ANY USB Wi-Fi adapter is the uplink
#    (so a different dongle is plug-and-play – plug in one at a time)
printf '[Match]\nType=wlan\nDriver=brcmfmac\n[Link]\nName=wlap\n' > /etc/systemd/network/10-wlap.link
printf '[Match]\nType=wlan\nPath=*-usb-*\n[Link]\nName=wlup\nMACAddressPolicy=persistent\n' > /etc/systemd/network/10-wlup.link

# 2. home Wi-Fi (from Raspberry Pi Imager: netplan on Trixie, a NetworkManager profile on Bookworm) now lives on the
#    USB adapter
for f in /etc/netplan/*.yaml; do
  [ -f "$f" ] && grep -q "wifis:" "$f" && sed -i -E 's/^    wlan[01]:$/    wlup:/' "$f"
done
command -v netplan >/dev/null && netplan generate
nmcli -t -f NAME,TYPE con show | while IFS=: read -r name type; do
  [ "$type" = 802-11-wireless ] && [ "$name" != travel-ap ] || continue
  [ -z "$(nmcli -g connection.interface-name con show "$name")" ] && nmcli con modify "$name" connection.interface-name wlup
  true
done

# 3. NetworkManager leaves /etc/resolv.conf to us
printf '[main]\ndns=none\n' > /etc/NetworkManager/conf.d/90-travelpi.conf

# 4. the private access point (5 GHz channel 36 when the built-in Wi-Fi can, else 2.4 GHz channel 6)
if [ ! -f /etc/travelpi/ap.env ]; then
  PSK=$(python3 -c 'import secrets; a="abcdefghjkmnpqrstuvwxyz23456789"; print("".join(secrets.choice(a) for _ in range(12)))')
  umask 077; printf 'SSID=%s\nPSK=%s\n' "$SSID" "$PSK" > /etc/travelpi/ap.env; umask 022
fi
. /etc/travelpi/ap.env
BAND=a; CHANNEL=36
for d in /sys/class/net/*; do
  [ "$(basename "$(readlink -f "$d/device/driver" 2>/dev/null)")" = brcmfmac ] || continue
  phy=$(cat "$d/phy80211/name" 2>/dev/null) || continue
  iw phy "$phy" info | grep -E " 5180(\.0)? MHz" | grep -qv disabled || { BAND=bg; CHANNEL=6; }
done
cat > /etc/NetworkManager/system-connections/travel-ap.nmconnection <<CONF
[connection]
id=travel-ap
uuid=6b1f3a52-7c0e-4f7e-9a51-2d1c0a7e5a10
type=wifi
interface-name=wlap
autoconnect=true
autoconnect-priority=100

[wifi]
mode=ap
ssid=travelpi-setup
band=$BAND
channel=$CHANNEL

[wifi-security]
key-mgmt=wpa-psk
proto=rsn
pairwise=ccmp
group=ccmp
psk=travelpi-setup

[ipv4]
method=manual
address1=10.42.0.1/24

[ipv6]
method=disabled
CONF
chmod 600 /etc/NetworkManager/system-connections/travel-ap.nmconnection
# the real name and password go in through nmcli, which handles spaces and symbols correctly
nmcli con reload
nmcli con modify travel-ap 802-11-wireless.ssid "$SSID" wifi-sec.psk "$PSK"

# 5. DHCP + DNS for devices, forwarding off until the kill switch is loaded
install -m 644 "$SRC/dnsmasq-travelpi.conf" /etc/dnsmasq.d/travelpi.conf
printf 'd /run/travelpi 0755 root root -\nf /run/travelpi/resolv.conf 0644 root root - nameserver 1.1.1.1\n' > /etc/tmpfiles.d/travelpi.conf
systemd-tmpfiles --create /etc/tmpfiles.d/travelpi.conf
printf 'net.ipv4.ip_forward = 0\nnet.ipv6.conf.wlap.disable_ipv6 = 1\n' > /etc/sysctl.d/90-travelpi.conf
printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\n' > /etc/resolv.conf.travelpi
rm -f /etc/resolv.conf && mv /etc/resolv.conf.travelpi /etc/resolv.conf

# 6. services
install -m 644 "$SRC/travelpi.service" /etc/systemd/system/travelpi.service
install -m 755 "$SRC/travelpi-rollback" /usr/local/sbin/travelpi-rollback
install -m 644 "$SRC/travelpi-rollback.service" /etc/systemd/system/travelpi-rollback.service
systemctl daemon-reload
systemctl enable -q dnsmasq travelpi travelpi-rollback
rm -f /etc/travelpi/net-confirmed
update-initramfs -u >/dev/null 2>&1 || true
echo "network setup written – reboot to apply (rollback armed)"

# 7. phone over USB is a backup: its routes rank below hotel Wi-Fi (600) and Ethernet (100)
printf '[connection-phone-usb]\nmatch-device=driver:ipheth,driver:rndis_host,driver:cdc_ncm,driver:cdc_ether\nipv4.route-metric=700\n' \
  > /etc/NetworkManager/conf.d/91-travelpi-phone.conf
DEBIAN_FRONTEND=noninteractive apt-get -qq install -y usbmuxd >/dev/null 2>&1 || true   # iPhone USB tethering
# 8. token for remote control (e.g. Sentinel over Tailscale); the phone page on the travel Wi-Fi needs none
[ -f /etc/travelpi/api.token ] || (umask 077; python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > /etc/travelpi/api.token)

# 9. Tor mode (tor runs only while that mode is on; travelpi.service starts/stops it)
DEBIAN_FRONTEND=noninteractive apt-get -qq install -y tor >/dev/null 2>&1 || true
systemctl disable --now tor >/dev/null 2>&1 || true
if ! grep -q "TravelPi Tor mode" /etc/tor/torrc; then
  cat >> /etc/tor/torrc <<TOR

# TravelPi Tor mode: devices' TCP is redirected here, DNS to the DNSPort
TransPort 10.42.0.1:9040 IsolateClientAddr IsolateDestAddr
DNSPort 10.42.0.1:9053
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
SocksPort 127.0.0.1:9050
ClientUseIPv6 0
TOR
fi

# 10. go easy on the SD card: system logs in memory (lost on reboot, capped at 30 MB)
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=volatile\nRuntimeMaxUse=30M\n' > /etc/systemd/journald.conf.d/90-travelpi.conf
systemctl restart systemd-journald

# 11. nightly backup over SSH – only when settings.json names a backup server (key /root/.ssh/travelpi_backup)
if python3 -c 'import json,sys; sys.exit(0 if json.load(open("/etc/travelpi/settings.json")).get("backup") else 1)' 2>/dev/null; then
  install -m 644 "$SRC/travelpi-backup.service" /etc/systemd/system/travelpi-backup.service
  install -m 644 "$SRC/travelpi-backup.timer" /etc/systemd/system/travelpi-backup.timer
  systemctl daemon-reload
  systemctl enable -q --now travelpi-backup.timer
fi

# 12. AdGuard Home: DNS + ad-blocking for the travel Wi-Fi on the Pi itself (dnsmasq becomes DHCP-only)
bash "$SRC/adguard-install.sh"
