#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""deobfuscate.py — balik编码 JS client Google Apps Script: atob/fromCharCode/
escape/hex-escape + peta kredensial hardcoded (bypass validasi password client-side).

    python3 deobfuscate.py --file page.html            # analisa file tersimpan
    python3 deobfuscate.py --url https://script.google.com/macros/s/XXX/exec --out obf_out

Keluaran: deobfuscated.js (JS sudah di-decode) + secrets.txt (kandidat user/pass).
"""
from __future__ import annotations

import argparse
import base64
import pathlib
import re
import sys
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from kit_common import http_get, outdir, save_json, summary  # noqa: E402

RE_SCRIPT = re.compile(r"(?s)<script\b[^>]*>(.*?)</script>")
RE_B64 = re.compile(r"atob\(\s*['\"]([A-Za-z0-9+/=\s]{4,})['\"]\s*\)")
RE_FCC = re.compile(r"String\.fromCharCode\(\s*([\d,\s]+)\)")
RE_HEX = re.compile(r"['\"]([^'\"]*\\x[0-9a-fA-F]{2}[^'\"]*)['\"]")
RE_ESC = re.compile(r"unescape\(\s*['\"]([^'\"]+)['\"]\s*\)")
RE_CRED_LINE = re.compile(
    r"(?im)^.*(?:user|username|login|guru|admin|pass|sandi|kunci|key|secret|"
    r"token|pin|akses|kata).*$")
RE_JSON_PAIR = re.compile(r"['\"]([\w.\-]{1,40})['\"]\s*:\s*['\"]([^'\"]{2,60})['\"]")
RE_ASSIGN = re.compile(r"(?i)([A-Za-z_][\w]{1,30})\s*[:=]\s*['\"]([^'\"]{2,60})['\"]")

def decode_b64(m):
    raw = re.sub(r"\s+", "", m.group(1))
    raw += "=" * (-len(raw) % 4)  # padding aman
    try:
        return base64.b64decode(raw).decode("utf-8", "replace")
    except Exception:
        return m.group(0)

def decode_fcc(m):
    try:
        return "".join(chr(int(x)) for x in m.group(1).replace("\n", "").split(",") if x.strip())
    except Exception:
        return m.group(0)

def decode_hex(m):
    try:
        return re.sub(r"\\x([0-9a-fA-F]{2})", lambda x: chr(int(x.group(1), 16)), m.group(1))
    except Exception:
        return m.group(0)

def deobfuscate(js: str) -> tuple[str, dict]:
    stat = {"atob": 0, "fromCharCode": 0, "hex": 0, "unescape": 0}
    js, n = RE_B64.subn(lambda m: (stat.__setitem__("atob", stat["atob"] + 1),
                                   decode_b64(m))[1], js)
    js, n = RE_FCC.subn(lambda m: (stat.__setitem__("fromCharCode", stat["fromCharCode"] + 1),
                                   decode_fcc(m))[1], js)
    js, n = RE_HEX.subn(lambda m: (stat.__setitem__("hex", stat["hex"] + 1),
                                   '"' + decode_hex(m) + '"')[1], js)
    js, n = RE_ESC.subn(lambda m: (stat.__setitem__("unescape", stat["unescape"] + 1),
                                   urllib.parse.unquote(m.group(1)))[1], js)
    return js, stat

def extract_secrets(js: str) -> tuple[list[str], list[str]]:
    """Ambil baris kredensial + pasangan key=value (JSON & assignment)."""
    hits: list[str] = []
    pairs: list[str] = []
    for line in js.splitlines():
        credline = bool(RE_CRED_LINE.search(line))
        s = line.strip()
        if credline and 3 < len(s) < 300:
            hits.append(s)
        # JSON-style: {"guru1":"rahasia123"} — key kredensial ATAU value rahasia
        for k, v in RE_JSON_PAIR.findall(line):
            if RE_CRED_LINE.search(k) or (credline and len(v) >= 6 and " " not in v):
                pairs.append(f"{k} = '{v}'")
        # assignment: var TOKEN = '...' (key mengandung kata kredensial)
        for k, v in RE_ASSIGN.findall(line):
            if RE_CRED_LINE.search(k):
                pairs.append(f"{k} = '{v}'")
    return hits, pairs

def main() -> int:
    ap = argparse.ArgumentParser(description="deobfuscate JS Apps Script → secrets")
    ap.add_argument("--file", help="file HTML/JS tersimpan")
    ap.add_argument("--url", help="URL halaman (live, scope-locked)")
    ap.add_argument("--cookie", default="")
    ap.add_argument("--out", default="gapps_obf")
    ap.add_argument("--timeout", type=float, default=45.0)
    a = ap.parse_args()
    if not a.file and not a.url:
        ap.error("butuh --file atau --url")
    if a.file:
        raw = pathlib.Path(a.file).read_text(errors="replace")
        src = a.file
    else:
        from kit_common import scope_check
        scope_check(a.url, authorized=True)  # ambil HTML publik halaman target
        _, _, raw, _ = http_get(a.url, a.cookie, a.timeout)
        src = a.url
    js = "\n".join(RE_SCRIPT.findall(raw)) if "<script" in raw.lower() else raw
    fixed, stat = deobfuscate(js)
    hits, pairs = extract_secrets(fixed)
    d = outdir("obf", a.out)
    (d / "deobfuscated.js").write_text(fixed)
    save_json(d / "stats.json", {"source": src, "decoded": stat})
    (d / "secrets.txt").write_text(
        "── kandidat kredensial (analisa offline — jangan commit/upload!) ──\n"
        + "\n".join(sorted(set(hits))) + "\n\n── pasangan key=value ──\n"
        + "\n".join(sorted(set(pairs))) + "\n")
    print(f"[✓] deobfuscated.js · secrets.txt → {d}")
    summary("hasil deobfuscate",
            [("decode atob", stat["atob"]), ("fromCharCode", stat["fromCharCode"]),
             ("hex \\xNN", stat["hex"]), ("unescape", stat["unescape"]),
             ("baris kredensial", len(set(hits))), ("pasangan key=value", len(set(pairs)))])
    if pairs:
        print("[!] kandidat kuat:")
        for p in sorted(set(pairs))[:20]:
            print(f"    {p}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
