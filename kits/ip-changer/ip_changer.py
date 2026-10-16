#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ip_changer.py — IP rotator & changer buat authorized pentest.

Fitur:
  - rotate: generate proxy chain config (Tor, SOCKS5, HTTP)
  - source: source IP spoofer (header injection)
  - geo: geo IP changer (VPN/proxy selector)
  - mac: MAC address changer (Linux)
  - check: cek IP sekarang

    python3 ip_changer.py rotate --type tor --count 5
    python3 ip_changer.py source --ip 10.0.0.1
    python3 ip_changer.py geo --country id
    python3 ip_changer.py mac --interface eth0
    python3 ip_changer.py check
"""
import argparse, json, random, socket, subprocess, sys

def rotate_proxy(proxy_type="tor", count=5):
    print(f"[*] Proxy rotation: {proxy_type} x{count}")
    print()
    if proxy_type == "tor":
        print("[*] Tor circuit rotation:")
        print("  # Install tor")
        print("  sudo apt install tor")
        print()
        print("  # Tor config (/etc/tor/torrc)")
        print("  SocksPort 9050")
        print("  ControlPort 9051")
        print("  CookieAuthentication 0")
        print()
        print("  # Rotate circuit:")
        print("  for i in range(" + str(count) + "):")
        print("    echo -e 'AUTHENTICATE\\r\\nSIGNAL NEWNYM\\r\\nQUIT' | nc 127.0.0.1 9051")
        print("    sleep 10")
        print("    curl --socks5 127.0.0.1:9050 https://ipinfo.io/ip")
        print()
        print("[*] Proxychains config (/etc/proxychains.conf):")
        print("  strict_chain")
        print("  proxy_dns")
        print("  tcp_read_time_out 15000")
        print("  tcp_connect_time_out 8000")
        print("  [ProxyList]")
        print("  socks5 127.0.0.1 9050")
    elif proxy_type == "socks5":
        print("[*] SOCKS5 proxy list:")
        proxies = [
            "127.0.0.1:9050",
            "127.0.0.1:9051",
            "127.0.0.1:9052",
        ]
        for i, p in enumerate(proxies[:count], 1):
            print(f"  {i}. socks5 {p}")
    elif proxy_type == "http":
        print("[*] HTTP proxy list:")
        print("  # Format: http://user:pass@ip:port")
        print("  http://proxy1:8080")
        print("  http://proxy2:8080")
    print()
    print("[*] Usage:")
    print("  proxychains curl https://target.com")
    print("  curl --socks5 127.0.0.1:9050 https://target.com")

def source_spoof(ip):
    print(f"[*] Source IP spoofing: {ip}")
    print()
    print("[*] Header injection:")
    headers = {
        "X-Forwarded-For": ip,
        "X-Real-IP": ip,
        "X-Originating-IP": ip,
        "X-Remote-IP": ip,
        "X-Client-IP": ip,
        "X-Forwarded-Host": ip,
        "X-Forwarded-Server": ip,
        "X-HTTP-Host-Override": ip,
        "X-ProxyUser-Ip": ip,
        "X-Custom-IP-Authorization": ip,
        "True-Client-IP": ip,
        "CF-Connecting-IP": ip,
    }
    for h, v in headers.items():
        print(f"  {h}: {v}")
    print()
    print("[*] curl example:")
    print(f"  curl -H 'X-Forwarded-For: {ip}' https://target.com")
    print()
    print("[*] Nmap source IP spoof:")
    print(f"  nmap -S {ip} -e eth0 target.com")
    print()
    print("[*] hping3 source spoof:")
    print(f"  hping3 -a {ip} -S -p 80 target.com")

def geo_change(country="id"):
    print(f"[*] Geo IP changer: {country}")
    print()
    print("[*] VPN services:")
    vpn_list = {
        "id": ["Indonesia", "Singapore", "Malaysia"],
        "us": ["USA", "Canada", "Mexico"],
        "eu": ["Germany", "Netherlands", "France"],
        "asia": ["Japan", "Korea", "Taiwan"],
    }
    locations = vpn_list.get(country.lower(), vpn_list["id"])
    for loc in locations:
        print(f"  - {loc}")
    print()
    print("[*] Tor exit node:")
    print(f"  tor --ExitNodes {{{country}}}")
    print()
    print("[*] Proxy by country:")
    print("  # BrightData, Oxylabs, Smartproxy")
    print("  # Format: http://user:pass@gate.provider.com:port")
    print()
    print("[*] DNS leak test:")
    print("  curl https://dnsleaktest.com")
    print("  curl https://ipleak.net")

def mac_change(interface="eth0"):
    print(f"[*] MAC address changer: {interface}")
    print()
    print("[*] Linux (ip command):")
    print(f"  sudo ip link set {interface} down")
    print(f"  sudo ip link set {interface} address 02:00:00:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}")
    print(f"  sudo ip link set {interface} up")
    print()
    print("[*] Random MAC:")
    mac = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
    print(f"  {mac}")
    print()
    print("[*] Vendor-specific MAC:")
    vendors = {
        "cisco": "00:1A:2B",
        "intel": "00:1B:21",
        "apple": "00:1C:B3",
        "vmware": "00:0C:29",
    }
    for vendor, prefix in vendors.items():
        suffix = ":".join(f"{random.randint(0,255):02x}" for _ in range(3))
        print(f"  {vendor:8}: {prefix}:{suffix}")
    print()
    print("[*] Restore original MAC:")
    print(f"  sudo ip link set {interface} address <original_mac>")

def check_ip():
    print("[*] Current IP check:")
    print()
    print("[*] Commands:")
    print("  curl https://ipinfo.io")
    print("  curl https://ifconfig.me")
    print("  curl https://api.ipify.org")
    print("  curl https://icanhazip.com")
    print()
    print("[*] DNS leak test:")
    print("  curl https://dnsleaktest.com/api/servers")
    print()
    print("[*] WebRTC leak test:")
    print("  https://browserleaks.com/webrtc")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "rotate":
        p = argparse.ArgumentParser()
        p.add_argument("--type", default="tor", choices=["tor", "socks5", "http"])
        p.add_argument("--count", type=int, default=5)
        a = p.parse_args(args[1:])
        rotate_proxy(a.type, a.count)
    elif cmd == "source":
        p = argparse.ArgumentParser()
        p.add_argument("--ip", required=True)
        a = p.parse_args(args[1:])
        source_spoof(a.ip)
    elif cmd == "geo":
        p = argparse.ArgumentParser()
        p.add_argument("--country", default="id")
        a = p.parse_args(args[1:])
        geo_change(a.country)
    elif cmd == "mac":
        p = argparse.ArgumentParser()
        p.add_argument("--interface", default="eth0")
        a = p.parse_args(args[1:])
        mac_change(a.interface)
    elif cmd == "check":
        check_ip()
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
