#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kit_common.py — helper bersama gapps-kit (scope gate + HTTP + output).

Scope gate mirip osint.py: default FAIL-CLOSED (host harus di scope.txt),
--authorized = override dengan izin tertulis, pasif (sumber pihak ketiga) lebih longgar.
"""
from __future__ import annotations

import json
import pathlib
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/126.0 Safari/537.36")
DEFAULT_SCOPE = "/root/data/Auth/scope.txt"

def outdir(name: str, out: str) -> pathlib.Path:
    d = pathlib.Path(out) / f"{name}_{time.strftime('%Y%m%d-%H%M%S')}"
    d.mkdir(parents=True, exist_ok=True)
    return d

def save_json(p: pathlib.Path, data) -> pathlib.Path:
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    return p

def host_of(url: str) -> str:
    if "://" in url:
        return urllib.parse.urlparse(url).netloc.lower().split(":")[0]
    return url.split("/")[0].lower().rstrip("/")

def _match(h: str, pat: str) -> bool:
    pat = pat.lower()
    if pat.startswith("*."):
        return h == pat[2:] or h.endswith("." + pat[2:])
    return h == pat

def load_scope(path: str = DEFAULT_SCOPE):
    p = pathlib.Path(path)
    allow, block = [], []
    if not p.exists():
        return False, allow, block
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = line.split()[0]
        (block if host.startswith("!") else allow).append(host.lstrip("!").lower())
    return True, allow, block

def scope_check(url: str, scope_path: str = DEFAULT_SCOPE, authorized: bool = False,
                passive: bool = False) -> str:
    """Gerbang wajib sebelum modul AKTIF menyentuh target."""
    ok, allow, block = load_scope(scope_path)
    h = host_of(url)
    if not ok:
        sys.exit(f"[STOP] scope.txt TIDAK TERBACA ({scope_path}) — fail-closed. "
                 f"Cek path atau pakai --authorized.")
    for p in block:
        if _match(h, p):
            sys.exit(f"[STOP] BLOCKLIST: {h} (rule !{p}) — jangan disentuh.")
    if authorized:
        print(f"[!] --authorized: {h} di luar allowlist — kamu nyatakan punya izin tertulis.")
        return "AUTHORIZED"
    if any(_match(h, p) for p in allow):
        print(f"[✓] IN SCOPE: {h}")
        return "IN SCOPE"
    if passive:
        print(f"[◦] PASIF: {h} sumber pihak ketiga — boleh.")
        return "PASSIVE"
    sys.exit(f"[STOP] FAIL-CLOSED: {h} tidak ada di {scope_path}. "
             f"Tambahkan host ke scope.txt atau pakai --authorized.")

def http_get(url: str, cookie: str = "", timeout: float = 45.0,
             verify_tls: bool = True, ua: str = UA):
    req = urllib.request.Request(url, headers={"User-Agent": ua,
                                               "Cookie": cookie or "",
                                               "Accept-Language": "id,en;q=0.8"})
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, dict(r.headers), r.read().decode("utf-8", "replace"), r.geturl()

def pace_sleep(pace: float) -> None:
    if pace > 0:
        time.sleep(pace)

def summary(title: str, rows: list[tuple[str, str]]) -> None:
    w = max([len(k) for k, _ in rows] + [4])
    print(f"\n── {title} {'─' * max(2, 40 - len(title))}")
    for k, v in rows:
        print(f"  {k:<{w}}  {v}")
