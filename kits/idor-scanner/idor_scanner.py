#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""idor_scanner.py — IDOR/BOLA detector buat CTF & authorized testing.

Fitur:
  - enumerate: generate ID range dan test access control
  - diff: bandingkan response user A vs user B
  - pattern: detect ID pattern (sequential, UUID, hash)

    python3 idor_scanner.py enumerate --url "http://api/user/1" --start 1 --end 100
    python3 idor_scanner.py diff --url-a "http://api/user/1" --url-b "http://api/user/2"
    python3 idor_scanner.py pattern --url "http://api/user/1" --sample 20
"""
import argparse, difflib, hashlib, re, sys, urllib.error, urllib.request

UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0 Safari/537.36"

def http_get(url, headers=None, timeout=15):
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(500_000)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(500_000)
    except Exception as e:
        return None, {}, str(e).encode()

def enumerate_ids(url_template, start, end, auth_header=None):
    print(f"[*] Enumerating IDs {start}..{end} via {url_template}")
    headers = {"Authorization": auth_header} if auth_header else None
    findings = []
    baseline_status = None
    for i in range(start, end + 1):
        url = url_template.replace("{id}", str(i))
        status, hdrs, body = http_get(url, headers)
        if status is None:
            print(f"  [{i:4}] ERROR")
            continue
        if baseline_status is None:
            baseline_status = status
        # Flag: different status or significantly different body
        if status != baseline_status:
            print(f"  [{i:4}] {status} <-- BERBEDA dari baseline ({baseline_status})")
            findings.append((i, status, url))
        elif status == 200:
            # Check if body is different (not just "not found")
            body_str = body.decode("utf-8", errors="replace")[:200]
            if "not found" not in body_str.lower() and "forbidden" not in body_str.lower():
                print(f"  [{i:4}] {status} OK ({len(body)} bytes)")
                findings.append((i, status, url))
        else:
            print(f"  [{i:4}] {status}")
    print(f"\n[*] Total findings: {len(findings)}")
    for i, status, url in findings:
        print(f"  ID {i}: {status} -> {url}")
    return findings

def diff(url_a, url_b, auth_a=None, auth_b=None):
    print(f"[*] Diffing responses:")
    print(f"  A: {url_a}")
    print(f"  B: {url_b}")
    h_a = {"Authorization": auth_a} if auth_a else None
    h_b = {"Authorization": auth_b} if auth_b else None
    sa, _, ba = http_get(url_a, h_a)
    sb, _, bb = http_get(url_b, h_b)
    print(f"  A: {sa} ({len(ba)} bytes)")
    print(f"  B: {sb} ({len(bb)} bytes)")
    if sa == sb == 200:
        a_lines = ba.decode("utf-8", errors="replace").splitlines()
        b_lines = bb.decode("utf-8", errors="replace").splitlines()
        diff = list(difflib.unified_diff(a_lines, b_lines, lineterm=""))
        if diff:
            print("\n  [!!!] Response BERBEDA — kemungkinan IDOR:")
            for line in diff[:30]:
                print(f"    {line}")
        else:
            print("\n  [*] Response identik — tidak ada IDOR")
    else:
        print(f"\n  [*] Status berbeda ({sa} vs {sb}) — cek manual")

def pattern(url_template, sample=10):
    print(f"[*] Analyzing ID pattern dari {sample} samples")
    ids = []
    for i in range(1, sample + 1):
        url = url_template.replace("{id}", str(i))
        status, _, body = http_get(url)
        if status == 200:
            ids.append(i)
    if not ids:
        print("[-] Tidak ada ID valid")
        return
    # Check sequential
    is_seq = all(ids[i] + 1 == ids[i + 1] for i in range(len(ids) - 1))
    if is_seq:
        print(f"[+] Pattern: SEQUENTIAL (1, 2, 3, ...)")
        print(f"    -> IDOR likely: coba ID di luar range")
    else:
        print(f"[*] Pattern: NON-SEQUENTIAL")
        print(f"    IDs: {ids}")
    # Check if ID in URL is UUID
    sample_url = url_template.replace("{id}", str(ids[0]))
    if re.search(r"[0-9a-f]{8}-[0-9a-f]{4}", sample_url, re.I):
        print(f"[+] Pattern: UUID (harder to guess)")
    # Check hash-like
    if re.search(r"[0-9a-f]{16,}", sample_url, re.I):
        print(f"[+] Pattern: HASH-like (MD5/SHA)")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "enumerate":
        p = argparse.ArgumentParser()
        p.add_argument("--url", required=True, help="URL template with {id}")
        p.add_argument("--start", type=int, required=True)
        p.add_argument("--end", type=int, required=True)
        p.add_argument("--auth", default=None)
        a = p.parse_args(args[1:])
        enumerate_ids(a.url, a.start, a.end, a.auth)
    elif cmd == "diff":
        p = argparse.ArgumentParser()
        p.add_argument("--url-a", required=True)
        p.add_argument("--url-b", required=True)
        p.add_argument("--auth-a", default=None)
        p.add_argument("--auth-b", default=None)
        a = p.parse_args(args[1:])
        diff(a.url_a, a.url_b, a.auth_a, a.auth_b)
    elif cmd == "pattern":
        p = argparse.ArgumentParser()
        p.add_argument("--url", required=True)
        p.add_argument("--sample", type=int, default=10)
        a = p.parse_args(args[1:])
        pattern(a.url, a.sample)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
