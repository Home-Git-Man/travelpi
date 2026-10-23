"""Firewall (nftables table inet travelpi).
Devices on our Wi-Fi, by policy:
  tunnel – out through Tailscale (the exit node) only; nothing leaks if the VPN is down
  wg     – out through the Proton WireGuard tunnel (wgx) only
  open   – straight out the uplink (direct mode, or while signing in to a hotel portal)
  block  – nothing beyond the Pi itself
  tor    – web/app (TCP) redirected into Tor on the Pi (Tor itself rides the VPN); DNS via our AdGuard; rest refused.
           Kids' devices stay on the normal filtered VPN. UDP (e.g. QUIC) is refused, not dropped, so phones fall
           back to TCP at once instead of timing out and calling the network "No Internet".
Always: IPv6 from devices dropped (exit nodes are IPv4 here, so v6 could only leak); TCP MSS clamped to the
outgoing MTU (the tunnel's is 1280, devices assume 1500, pages stall without it); every DNS query from devices goes
to our dnsmasq (AdGuard), kids' devices to AdGuard Family (adult block + safe search, YouTube restricted).
In every mode devices may reach the tailnet (Sentinel, home services) through tailscale0 – http://sentinel works.
Uplinks (hotel Wi-Fi/Ethernet/phone): only replies, DHCP, ICMP and Tailscale's UDP get in – no SSH or web from
the hotel network."""
from __future__ import annotations

from .config import AP, AP_ADDR, AP_NET, KIDS_DNS, TAILNET, TOR_TRANS, UPLINK_PATTERNS

POLICIES = ("tunnel", "open", "block", "tor", "wg")


def ruleset(policy: str, kids: list[str] | tuple[str, ...] = ()) -> str:
    if policy not in POLICIES:
        raise ValueError(policy)
    out_rule = {
        "tunnel": f'iifname "{AP}" oifname "tailscale0" counter accept\n    iifname "{AP}" counter drop',
        "wg": f'iifname "{AP}" oifname "wgx" counter accept\n    iifname "{AP}" counter drop',
        "open": f'iifname "{AP}" oifname != "{AP}" counter accept',
        "block": f'iifname "{AP}" counter drop',
        "tor": (f'iifname "{AP}" ether saddr {{ {", ".join(sorted(m.lower() for m in kids))} }} oifname "tailscale0" accept\n    '
                if kids else "") + f'iifname "{AP}" meta l4proto udp counter reject with icmpx port-unreachable\n    '
                                   f'iifname "{AP}" counter drop',
    }[policy]
    kidset = "{ " + ", ".join(sorted(m.lower() for m in kids)) + " }" if kids else ""
    kids_fwd = f'iifname "{AP}" ether saddr {kidset} tcp dport 853 drop\n    ' if kids else ""
    kids_nat = (f'iifname "{AP}" ether saddr {kidset} meta l4proto {{ tcp, udp }} th dport 53 dnat ip to {KIDS_DNS}\n    '
                if kids else "")
    if policy == "tor":    # after the kids rules, so their traffic never reaches Tor
        notkids = f"ether saddr != {kidset} " if kids else ""
        # DNS stays on our own resolver (AdGuard over the tunnel): Tor's DNSPort is slow and ignores the HTTPS/SVCB
        # lookups iPhones make alongside every A query, so they hang and report "No Internet".
        kids_nat += (f'iifname "{AP}" {notkids}ip daddr != {{ {AP_ADDR}, {TAILNET} }} meta l4proto tcp '
                     f'redirect to :{TOR_TRANS}\n    ')
    up_in = "\n    ".join(
        f'iifname "{p}" ct state established,related accept\n    '
        f'iifname "{p}" meta l4proto {{ icmp, ipv6-icmp }} accept\n    '
        f'iifname "{p}" udp dport {{ 68, 546, 41641 }} accept\n    '
        f'iifname "{p}" drop' for p in UPLINK_PATTERNS)
    return f"""table inet travelpi
delete table inet travelpi
table inet travelpi {{
  chain input {{
    type filter hook input priority -10; policy accept;
    {up_in}
  }}
  chain forward {{
    type filter hook forward priority -10; policy accept;
    iifname "{AP}" meta nfproto ipv6 drop
    tcp flags syn tcp option maxseg size set rt mtu
    oifname "{AP}" ct state established,related counter accept
    oifname "{AP}" drop
    iifname "{AP}" ip daddr {TAILNET} oifname "tailscale0" counter accept
    {kids_fwd}{out_rule}
  }}
  chain prerouting {{
    type nat hook prerouting priority -100; policy accept;
    {kids_nat}iifname "{AP}" meta l4proto {{ tcp, udp }} th dport 53 ip daddr != {AP_ADDR} dnat ip to {AP_ADDR}
  }}
  chain postrouting {{
    type nat hook postrouting priority 100; policy accept;
    ip saddr {AP_NET} oifname != "{AP}" masquerade
  }}
}}
"""
