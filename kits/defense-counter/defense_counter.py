#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""defense_counter.py — defense counter & WAF/IDS evasion toolkit.

Fitur:
  - waf: WAF detection & bypass (Cloudflare, Akamai, Imperva, etc.)
  - ids: IDS/IPS evasion (fragmentation, encoding, timing)
  - rate: rate limit detection & bypass
  - captcha: CAPTCHA detection & bypass hints
  - 2fa: 2FA bypass hints

    python3 defense_counter.py waf --target https://target.com
    python3 defense_counter.py ids --target 10.0.0.1 --port 80
    python3 defense_counter.py rate --url https://target.com/api
    python3 defense_counter.py captcha --target https://target.com
    python3 defense_counter.py 2fa --target https://target.com
"""
import argparse, json, random, string, sys, time

def waf_detect(target):
    print(f"[*] WAF detection untuk: {target}")
    print()
    print("[*] Detection methods:")
    print("  1. Header analysis (Server, X-Cache, CF-RAY)")
    print("  2. Error page fingerprint")
    print("  3. Timing analysis")
    print("  4. Payload injection test")
    print()
    print("[*] WAF fingerprints:")
    wafs = {
        "Cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "Akamai": ["x-akamai-transformed", "akamai-grn", "server: akamai"],
        "Imperva": ["x-iinfo", "x-cdn", "server: imperva"],
        "AWS AWS": ["x-amz-cf-id", "x-amz-request-id", "server: awselb"],
        "Sucuri": ["x-sucuri-id", "x-sucuri-cache", "server: sucuri/cloudproxy"],
        "Barracuda": ["x-barracuda", "server: barracuda"],
        "F5 BIG-IP": ["x-cnection", "server: bigip"],
        "Fortinet": ["x-fortigate", "server: fortinet"],
    }
    for waf, sigs in wafs.items():
        print(f"  {waf}:")
        for sig in sigs:
            print(f"    - {sig}")
    print()
    print("[*] Bypass techniques:")
    print("  1. Encoding (URL, hex, unicode, double URL)")
    print("  2. Header injection (X-Forwarded-For, X-Real-IP)")
    print("  3. Chunked transfer encoding")
    print("  4. JSON/XML content-type manipulation")
    print("  5. HTTP parameter pollution")
    print("  6. Case randomization")
    print("  7. Comment injection")
    print("  8. Overlong UTF-8")
    print("  9. HTTP request smuggling")
    print("  10. Cache poisoning")

def ids_evasion(target, port=80):
    print(f"[*] IDS/IPS evasion untuk: {target}:{port}")
    print()
    print("[*] Fragmentation:")
    print(f"  nmap -f -p {port} {target}")
    print(f"  nmap --mtu 24 -p {port} {target}")
    print()
    print("[*] Decoy scan:")
    print(f"  nmap -D RND:10 -p {port} {target}")
    print()
    print("[*] Source port spoof:")
    print(f"  nmap --source-port 53 -p {port} {target}")
    print()
    print("[*] Timing:")
    print(f"  nmap -T0 -p {port} {target}  # Paranoid")
    print(f"  nmap -T1 -p {port} {target}  # Sneaky")
    print()
    print("[*] Encoding:")
    print("  # URL encode payload")
    print("  # Hex encode payload")
    print("  # Unicode encode payload")
    print()
    print("[*] Fragmentation (application layer):")
    print("  # Split payload across multiple requests")
    print("  # Use chunked transfer encoding")
    print("  # Use HTTP pipelining")
    print()
    print("[*] Evasion tools:")
    print("  # fragroute")
    print("  # fragtest")
    print("  # idswakeup")

def rate_detect(url):
    print(f"[*] Rate limit detection: {url}")
    print()
    print("[*] Detection:")
    print("  1. Send 10 rapid requests")
    print("  2. Check for 429 status")
    print("  3. Check Retry-After header")
    print("  4. Check X-RateLimit-* headers")
    print()
    print("[*] Bypass:")
    print("  1. IP rotation (Tor, proxy)")
    print("  2. Header rotation (X-Forwarded-For)")
    print("  3. Session rotation")
    print("  4. Delay between requests")
    print("  5. Jitter (random delay)")
    print("  6. Distributed requests (multiple IPs)")
    print()
    print("[*] Headers to check:")
    rate_headers = [
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
        "Retry-After",
        "X-Rate-Limit-Limit",
        "X-Rate-Limit-Remaining",
        "X-Rate-Limit-Reset",
    ]
    for h in rate_headers:
        print(f"  {h}")

def captcha_detect(target):
    print(f"[*] CAPTCHA detection: {target}")
    print()
    print("[*] Detection:")
    print("  1. Check for reCAPTCHA")
    print("  2. Check for hCaptcha")
    print("  3. Check for Cloudflare Turnstile")
    print("  4. Check for custom CAPTCHA")
    print()
    print("[*] Bypass hints:")
    print("  1. reCAPTCHA: Use audio challenge, token reuse")
    print("  2. hCaptcha: Use accessibility token")
    print("  3. Turnstile: Use headless browser")
    print("  4. Custom: OCR (Tesseract), ML solver")
    print()
    print("[*] Tools:")
    print("  # 2captcha, anti-captcha, capmonster")
    print("  # Tesseract OCR")
    print("  # Selenium + undetected-chromedriver")

def twofa_bypass(target):
    print(f"[*] 2FA bypass hints: {target}")
    print()
    print("[*] Techniques:")
    print("  1. Session hijacking (steal session before 2FA)")
    print("  2. Token reuse (reuse old 2FA token)")
    print("  3. Race condition (submit 2FA before validation)")
    print("  4. Response manipulation (change 200 to 200 OK)")
    print("  5. 2FA bypass via API (skip 2FA endpoint)")
    print("  6. Backup codes (brute force backup codes)")
    print("  7. SMS intercept (SIM swap, SS7)")
    print("  8. TOTP seed extraction")
    print()
    print("[*] API bypass:")
    print("  # Check if API endpoint skips 2FA")
    print("  # Check if 2FA is only enforced on web")
    print("  # Check if 2FA token can be reused")
    print()
    print("[*] Tools:")
    print("  # burp suite (intercept + modify)")
    print("  # mitmproxy")
    print("  # custom scripts")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "waf":
        p = argparse.ArgumentParser()
        p.add_argument("--target", required=True)
        a = p.parse_args(args[1:])
        waf_detect(a.target)
    elif cmd == "ids":
        p = argparse.ArgumentParser()
        p.add_argument("--target", required=True)
        p.add_argument("--port", type=int, default=80)
        a = p.parse_args(args[1:])
        ids_evasion(a.target, a.port)
    elif cmd == "rate":
        p = argparse.ArgumentParser()
        p.add_argument("--url", required=True)
        a = p.parse_args(args[1:])
        rate_detect(a.url)
    elif cmd == "captcha":
        p = argparse.ArgumentParser()
        p.add_argument("--target", required=True)
        a = p.parse_args(args[1:])
        captcha_detect(a.target)
    elif cmd == "2fa":
        p = argparse.ArgumentParser()
        p.add_argument("--target", required=True)
        a = p.parse_args(args[1:])
        twofa_bypass(a.target)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
