#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""anti_lock.py — IP anti-lockout & rate limit bypass toolkit.

Fitur:
  - delay: generate delay config (exponential backoff, jitter)
  - rotate: IP rotation schedule
  - headers: header rotation (UA, Accept, etc.)
  - session: session rotation (cookie, token)
  - fingerprint: browser fingerprint rotation

    python3 anti_lock.py delay --base 1.0 --max 60.0 --attempts 10
    python3 anti_lock.py rotate --ips "1.1.1.1,2.2.2.2,3.3.3.3" --interval 30
    python3 anti_lock.py headers --count 5
    python3 anti_lock.py session --cookies "a=1,b=2,c=3"
    python3 anti_lock.py fingerprint --count 3
"""
import argparse, json, random, string, sys, time

UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]

ACCEPT_LIST = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "application/json, text/plain, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
]

LANG_LIST = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.8",
    "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-GB,en;q=0.9",
]

def delay_config(base=1.0, max_delay=60.0, attempts=10):
    print(f"[*] Delay config: base={base}s, max={max_delay}s, attempts={attempts}")
    print()
    print("[*] Exponential backoff with jitter:")
    for i in range(1, attempts + 1):
        exp_delay = min(base * (2 ** (i - 1)), max_delay)
        jitter = random.uniform(0, exp_delay * 0.5)
        total = exp_delay + jitter
        print(f"  Attempt {i:2}: {total:6.2f}s (exp={exp_delay:.2f}s + jitter={jitter:.2f}s)")
    print()
    print("[*] Fixed delay:")
    for i in range(1, attempts + 1):
        print(f"  Attempt {i:2}: {base:.2f}s")
    print()
    print("[*] Random delay:")
    for i in range(1, attempts + 1):
        delay = random.uniform(base, max_delay)
        print(f"  Attempt {i:2}: {delay:.2f}s")
    print()
    print("[*] Python code:")
    print("  import time, random")
    print(f"  time.sleep(min({base} * (2 ** (attempt - 1)), {max_delay}) + random.uniform(0, {base}))")

def rotate_ips(ips, interval=30):
    ip_list = [ip.strip() for ip in ips.split(",")]
    print(f"[*] IP rotation: {len(ip_list)} IPs, interval={interval}s")
    print()
    for i, ip in enumerate(ip_list, 1):
        print(f"  {i}. {ip} (use for {interval}s)")
    print()
    print("[*] Python code:")
    print("  import time")
    print(f"  ips = {ip_list}")
    print(f"  interval = {interval}")
    print("  for ip in ips:")
    print("      # Use IP")
    print("      time.sleep(interval)")
    print()
    print("[*] curl example:")
    print(f"  curl --interface {ip_list[0]} https://target.com")
    print(f"  curl --resolve target.com:443:{ip_list[0]} https://target.com")

def header_rotation(count=5):
    print(f"[*] Header rotation: {count} variants")
    print()
    for i in range(count):
        ua = random.choice(UA_LIST)
        accept = random.choice(ACCEPT_LIST)
        lang = random.choice(LANG_LIST)
        print(f"  Variant {i+1}:")
        print(f"    User-Agent: {ua[:60]}...")
        print(f"    Accept: {accept[:50]}...")
        print(f"    Accept-Language: {lang}")
        print()
    print("[*] Python code:")
    print("  import random")
    print(f"  ua_list = {UA_LIST[:3]}")
    print("  headers = {")
    print("      'User-Agent': random.choice(ua_list),")
    print("      'Accept': random.choice(accept_list),")
    print("      'Accept-Language': random.choice(lang_list),")
    print("  }")

def session_rotation(cookies):
    cookie_list = [c.strip() for c in cookies.split(",")]
    print(f"[*] Session rotation: {len(cookie_list)} sessions")
    print()
    for i, cookie in enumerate(cookie_list, 1):
        print(f"  Session {i}: {cookie}")
    print()
    print("[*] Python code:")
    print("  import requests")
    print(f"  sessions = {cookie_list}")
    print("  for session in sessions:")
    print("      r = requests.get(url, cookies={'session': session})")
    print()
    print("[*] curl example:")
    print(f"  curl -b 'session={cookie_list[0]}' https://target.com")

def fingerprint_rotation(count=3):
    print(f"[*] Browser fingerprint rotation: {count} variants")
    print()
    fingerprints = [
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        },
        {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Accept-Language": "en-GB,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        },
        {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        },
    ]
    for i, fp in enumerate(fingerprints[:count], 1):
        print(f"  Fingerprint {i}:")
        for k, v in fp.items():
            print(f"    {k}: {v}")
        print()
    print("[*] Python code:")
    print("  import requests")
    print(f"  fingerprints = {fingerprints[:count]}")
    print("  for fp in fingerprints:")
    print("      r = requests.get(url, headers=fp)")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "delay":
        p = argparse.ArgumentParser()
        p.add_argument("--base", type=float, default=1.0)
        p.add_argument("--max", type=float, default=60.0)
        p.add_argument("--attempts", type=int, default=10)
        a = p.parse_args(args[1:])
        delay_config(a.base, a.max, a.attempts)
    elif cmd == "rotate":
        p = argparse.ArgumentParser()
        p.add_argument("--ips", required=True)
        p.add_argument("--interval", type=int, default=30)
        a = p.parse_args(args[1:])
        rotate_ips(a.ips, a.interval)
    elif cmd == "headers":
        p = argparse.ArgumentParser()
        p.add_argument("--count", type=int, default=5)
        a = p.parse_args(args[1:])
        header_rotation(a.count)
    elif cmd == "session":
        p = argparse.ArgumentParser()
        p.add_argument("--cookies", required=True)
        a = p.parse_args(args[1:])
        session_rotation(a.cookies)
    elif cmd == "fingerprint":
        p = argparse.ArgumentParser()
        p.add_argument("--count", type=int, default=3)
        a = p.parse_args(args[1:])
        fingerprint_rotation(a.count)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
