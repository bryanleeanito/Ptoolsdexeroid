#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fw_bypass.py — Firewall bypass extreme toolkit buat authorized pentest.

Fitur:
  - method: bypass method (fragmentation, tunneling, encoding, etc.)
  - tunnel: tunneling method (DNS, ICMP, HTTP, SSH)
  - evasion: packet evasion (fragment, TTL, window, etc.)
  - protocol: protocol abuse (DNS, ICMP, HTTP, etc.)
  - test: test firewall rules

    python3 fw_bypass.py method --target 10.0.0.1
    python3 fw_bypass.py tunnel --type dns --server 8.8.8.8
    python3 fw_bypass.py evasion --target 10.0.0.1
    python3 fw_bypass.py protocol --proto icmp
    python3 fw_bypass.py test --target 10.0.0.1 --port 80
"""
import argparse, random, socket, struct, sys

# ============ Bypass Methods ============

def bypass_methods(target):
    print(f"[*] Firewall bypass methods: {target}")
    print()
    methods = {
        "fragmentation": {
            "desc": "IP fragmentasi - split packet kecil",
            "cmd": f"nmap -f -p 80,443 {target}",
            "desc2": "nmap --mtu 24 {target}",
        },
        "decoy": {
            "desc": "Decoy scan - samarkan sumber",
            "cmd": f"nmap -D RND:10 -p 80 {target}",
        },
        "source_port": {
            "desc": "Source port spoof (DNS 53)",
            "cmd": f"nmap --source-port 53 -p 80 {target}",
        },
        "mac_spoof": {
            "desc": "MAC address spoof",
            "cmd": f"nmap --spoof-mac 00:11:22:33:44:55 {target}",
        },
        "badsum": {
            "desc": "Bad checksum - bypass stateless FW",
            "cmd": f"nmap --badsum -p 80 {target}",
        },
        "data_length": {
            "desc": "Data length manipulation",
            "cmd": f"nmap --data-length 100 -p 80 {target}",
        },
        "ttl_manipulation": {
            "desc": "TTL manipulation - bypass hop-count filter",
            "cmd": f"nmap --ttl 255 -p 80 {target}",
        },
        "window_size": {
            "desc": "TCP window size manipulation",
            "cmd": f"nmap --window 1024 -p 80 {target}",
        },
    }
    for name, info in methods.items():
        print(f"  [{name}]")
        print(f"    {info['desc']}")
        print(f"    {info['cmd']}")
        print()

# ============ Tunneling ============

def tunneling(tunnel_type, server=None):
    print(f"[*] Tunneling: {tunnel_type}")
    print()
    if tunnel_type == "dns":
        print("[*] DNS tunnel (iodine, dnscat2):")
        print(f"  # Server (authoritative DNS):")
        print(f"  iodine -f -P password {server or 'tunnel.example.com'}")
        print(f"  # Client:")
        print(f"  iodine -f -P password {server or 'tunnel.example.com'}")
        print()
        print("[*] dnscat2:")
        print(f"  dnscat2 --dns server={server or 'tunnel.example.com'},port=53")
        print()
        print("[*] DNS over HTTPS (DoH):")
        print(f"  dns2tcp -r <remote_host> -z <zone> <server>")
    elif tunnel_type == "icmp":
        print("[*] ICMP tunnel (ptunnel, icmptunnel):")
        print(f"  # Server:")
        print(f"  ptunnel -d -p {server or 'server'} -l 8000")
        print(f"  # Client:")
        print(f"  ptunnel -p {server or 'server'} -lp 8000 -da 127.0.0.1 -dp 80")
        print()
        print("[*] icmptunnel:")
        print(f"  icmptunnel -s {server or 'server'}")
        print(f"  icmptunnel -c {server or 'server'}")
    elif tunnel_type == "http":
        print("[*] HTTP tunnel (HTTP CONNECT):")
        print(f"  # Server (Squid):")
        print(f"  http_port 3128")
        print(f"  allowCONNECT")
        print(f"  # Client:")
        print(f"  curl -x http://{server or 'server'}:3128 https://target.com")
        print()
        print("[*] HTTP tunnel (reGeorg, reDuh):")
        print(f"  # Upload tunnel.jsp ke web server")
        print(f"  java -jar reGeorg.jar -tunnel 8080")
    elif tunnel_type == "ssh":
        print("[*] SSH tunnel:")
        print(f"  # Local port forward:")
        print(f"  ssh -L 8080:target:80 user@{server or 'server'}")
        print(f"  # Remote port forward:")
        print(f"  ssh -R 8080:localhost:80 user@{server or 'server'}")
        print(f"  # Dynamic SOCKS proxy:")
        print(f"  ssh -D 1080 user@{server or 'server'}")
        print(f"  # Usage:")
        print(f"  curl --socks5 127.0.0.1:1080 https://target.com")

# ============ Evasion ============

def evasion(target):
    print(f"[*] Packet evasion: {target}")
    print()
    print("[*] IP fragmentation:")
    print(f"  nmap -f -p 80 {target}")
    print(f"  nmap --mtu 8 -p 80 {target}")
    print()
    print("[*] TCP flags:")
    print(f"  nmap -sN -p 80 {target}  # NULL scan")
    print(f"  nmap -sX -p 80 {target}  # Xmas scan")
    print(f"  nmap -sF -p 80 {target}  # FIN scan")
    print()
    print("[*] TTL manipulation:")
    print(f"  nmap --ttl 255 -p 80 {target}")
    print()
    print("[*] TCP window:")
    print(f"  nmap --window 1024 -p 80 {target}")
    print()
    print("[*] Source port:")
    print(f"  nmap --source-port 53 -p 80 {target}")
    print()
    print("[*] MAC spoof:")
    print(f"  nmap --spoof-mac 0 -p 80 {target}")
    print()
    print("[*] Bad checksum:")
    print(f"  nmap --badsum -p 80 {target}")
    print()
    print("[*] Data length:")
    print(f"  nmap --data-length 100 -p 80 {target}")
    print()
    print("[*] Decoy:")
    print(f"  nmap -D RND:10 -p 80 {target}")

# ============ Protocol Abuse ============

def protocol_abuse(proto):
    print(f"[*] Protocol abuse: {proto}")
    print()
    if proto == "dns":
        print("[*] DNS abuse:")
        print("  1. DNS tunnel (iodine, dnscat2)")
        print("  2. DNS exfiltration")
        print("  3. DNS cache poisoning")
        print("  4. DNS rebinding")
        print("  5. DNS over HTTPS (DoH)")
        print()
        print("[*] Tools:")
        print("  iodine, dnscat2, dns2tcp, dnsmasq")
    elif proto == "icmp":
        print("[*] ICMP abuse:")
        print("  1. ICMP tunnel (ptunnel, icmptunnel)")
        print("  2. ICMP exfiltration")
        print("  3. Ping sweep")
        print("  4. ICMP redirect")
        print()
        print("[*] Tools:")
        print("  ptunnel, icmptunnel, hping3")
    elif proto == "http":
        print("[*] HTTP abuse:")
        print("  1. HTTP tunnel (CONNECT)")
        print("  2. HTTP request smuggling")
        print("  3. HTTP parameter pollution")
        print("  4. HTTP response splitting")
        print("  5. HTTP cache poisoning")
        print()
        print("[*] Tools:")
        print("  burp suite, zap, custom scripts")
    elif proto == "smtp":
        print("[*] SMTP abuse:")
        print("  1. SMTP tunnel")
        print("  2. SMTP exfiltration")
        print("  3. SMTP relay abuse")
        print("  4. SMTP open relay")
        print()
        print("[*] Tools:")
        print("  smtp-user-enum, swaks")

# ============ Test ============

def test_fw(target, port):
    print(f"[*] Firewall test: {target}:{port}")
    print()
    print("[*] Port scan:")
    print(f"  nmap -sS -p {port} {target}")
    print(f"  nmap -sT -p {port} {target}")
    print(f"  nmap -sU -p {port} {target}")
    print()
    print("[*] Service detection:")
    print(f"  nmap -sV -p {port} {target}")
    print()
    print("[*] OS detection:")
    print(f"  nmap -O -p {port} {target}")
    print()
    print("[*] Firewall detection:")
    print(f"  nmap -sA -p {port} {target}  # ACK scan")
    print(f"  nmap -sW -p {port} {target}  # Window scan")
    print()
    print("[*] Fragmentation test:")
    print(f"  nmap -f -p {port} {target}")
    print()
    print("[*] Evasion test:")
    print(f"  nmap -D RND:10 -p {port} {target}")
    print(f"  nmap --source-port 53 -p {port} {target}")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "method":
        p = argparse.ArgumentParser()
        p.add_argument("--target", required=True)
        a = p.parse_args(args[1:])
        bypass_methods(a.target)
    elif cmd == "tunnel":
        p = argparse.ArgumentParser()
        p.add_argument("--type", required=True, choices=["dns", "icmp", "http", "ssh"])
        p.add_argument("--server", default=None)
        a = p.parse_args(args[1:])
        tunneling(a.type, a.server)
    elif cmd == "evasion":
        p = argparse.ArgumentParser()
        p.add_argument("--target", required=True)
        a = p.parse_args(args[1:])
        evasion(a.target)
    elif cmd == "protocol":
        p = argparse.ArgumentParser()
        p.add_argument("--proto", required=True, choices=["dns", "icmp", "http", "smtp"])
        a = p.parse_args(args[1:])
        protocol_abuse(a.proto)
    elif cmd == "test":
        p = argparse.ArgumentParser()
        p.add_argument("--target", required=True)
        p.add_argument("--port", type=int, default=80)
        a = p.parse_args(args[1:])
        test_fw(a.target, a.port)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
