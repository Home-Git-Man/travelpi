# TravelPi – a family travel router on a Raspberry Pi

Turn a Raspberry Pi into a pocket router for trips. Your family's phones, tablets and laptops join **your own Wi-Fi
once** and then work everywhere: hotels, airports, caravan parks, Airbnbs, a phone hotspot in the car. The Pi joins
the local Wi-Fi for you and keeps everyone behind a VPN with a kill switch.

- **VPN with a kill switch**: free Proton VPN (or any WireGuard VPN), optional Tailscale exit node at home; Auto
  picks the best one and fails over. If the VPN drops, nothing leaks.
- **Hotel login helper**: opens the network for 10 minutes so one phone can tick the box on the hotel page, then
  the VPN comes back by itself.
- **Ad and tracker blocking** for every device (AdGuard Home on the Pi).
- **Kids mode** per device: adult sites blocked, safe search, YouTube Restricted. Kids' devices can't change settings.
- **Backups**: a phone over USB or a saved hotspot takes over when the hotel Wi-Fi dies.
- **Data counter** per device, with a warning when you're burning phone data.
- **Use the hotel's device limit to your advantage**: copy one device's address so a login made on it covers everyone.
- **Tor mode**, **speed test**, unattended security updates.
- Run it from a **3.5" touch screen** or from any **phone page** at `http://10.42.0.1` – a screen is optional.

## What you need

- Raspberry Pi 4 or 5 (3B+ works; Zero 2 W works on 2.4 GHz only), a good USB-C supply or power bank (5V 3A)
- A microSD card (16 GB+) with **Raspberry Pi OS Lite (64-bit)**
- A **USB Wi-Fi adapter** that Linux supports out of the box (it joins the hotel Wi-Fi; the Pi's own Wi-Fi becomes
  your private network). Ones with the MT7612U / MT7921AU / RTL8811AU chips work well, and an external antenna
  helps at caravan parks.
- Optional: a 3.5" SPI touch screen (ILI9486, "MHS-3.5" / Waveshare-style), a Proton VPN account (free), Tailscale

## Install

1. In **Raspberry Pi Imager** choose Raspberry Pi OS Lite (64-bit) and, under settings, set a user name, your
   **home Wi-Fi**, your Wi-Fi country, and turn on **SSH**. Write the card and boot the Pi with the USB Wi-Fi
   adapter plugged in.
2. From a computer at home: `ssh <your-user>@<pi-name>.local`, then run

   ```bash
   curl -fsSL https://raw.githubusercontent.com/OWNER/travelpi/main/install.sh | sudo bash
   ```

   It asks for your travel Wi-Fi's name and password, your country, whether you have the screen, and whether to
   use Tailscale. Then it reboots.
3. Within 7 minutes of the reboot, join your new travel Wi-Fi and open **http://10.42.0.1**. That confirms the
   setup. If nobody does, the Pi undoes its network changes so you can't get locked out.
4. On that page: **VPN locations → Add a WireGuard VPN file**. For Proton VPN's free plan: account.protonvpn.com →
   Downloads → WireGuard configuration → pick a free server → Create → download, then choose the file.

Update later with `sudo travelpi-update`. To change answers, run the installer again.

## On the road

1. Plug in the Pi. Your devices join the travel Wi-Fi automatically.
2. On the screen or phone page: **Wi-Fi → Scan → Join** the hotel's network.
3. If it has a sign-in page: **Hotel login → Start**, sign in on your phone, done.
4. The status shows **PROTECTED** with the VPN's country. Red **NOT PROTECTED** means Direct mode (no VPN).

Change the travel Wi-Fi's name or password on the screen (More → Wi-Fi name) or the phone page (Travel Wi-Fi).

## Optional extras (settings.json)

`/etc/travelpi/settings.json` holds the bits that differ per router. All of them are optional:

```json
{
  "name": "TravelPi",
  "tailscale_exits": [{"id": "home", "node": "my-exit-node", "label": "Home", "where": "Home internet"}],
  "dns_fallback": "",
  "sentinel": "",
  "backup": "",
  "home_wifi": "",
  "vpn_order": ["sg", "jp", "us", "nl", "ch"]
}
```

- `tailscale_exits`: your own Tailscale exit nodes, so you can look like you're at home (streaming apps, banking).
- `dns_fallback`: a DNS server reached through the VPN (e.g. your own AdGuard Home).
- `backup` and `home_wifi`: nightly backup over SSH to `user@host`; full backups only on your home Wi-Fi.
- `vpn_order`: which countries Auto tries first (closest to home first).

Restart after changing it: `sudo systemctl restart travelpi`.

## How it works

`travelpi/` is plain Python 3 using only Debian packages: a controller loop (`net.py`) handles the VPN choice,
nftables kill switch (`fw.py`), DNS and failover. `ui.py` draws the touch screen with Pillow, and `web.py` serves
the phone page. AdGuard Home does DNS and ad-blocking, and dnsmasq does DHCP. Hotel networks can't reach the Pi at
all, and IPv6 from devices is dropped so nothing can leak around the VPN.

Tests: `python3 -m pytest tests` (on a Pi).
