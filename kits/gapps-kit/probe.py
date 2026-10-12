#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gapps_probe.py — recon web app Google Apps Script (school-owned asset scope).

Usage (di BlackArch, target sudah terotorisasi):
    python3 probe.py --url "https://script.google.com/macros/s/<DEPLOY_ID>/exec" --out ./gapps_out
    python3 probe.py --file page_tersimpan.html --out ./gapps_out      # analisa offline

Metodologi (read-only, client-side):
  1. Ambil HTML web app (Google Apps Script HtmlService) → simpan.
  2. Ekstrak PERMUKAAN API server: google.script.run.<fn> yang bisa dipanggil
     siapa saja dari halaman (bila deployment = anyone).
  3. Ekstrak Sheet/Drive/file ID (pola gviz/CSV export tanpa login).
  4. Ekstrak penulisan cookie (session client-side: forge role).
  5. Cek validasi password client-side (hardcoded/aturcara di JS = reverse).
  6. Deteksi obfuscation (eval/atob/fromCharCode) & endpoint fetch/XHR lain.
Output: report.md (triage) · api_surface.txt · console_probe.js · gviz_urls.txt

Etika: hanya untuk aset dalam scope engagement + NDA. Jangan simpan kredensial
asli tanpa redaksi (<REDACTED>) kecuali diminta untuk bukti laporan.
"""
from __future__ import annotations

import argparse
import hashlib
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

# ───────────────────────── pola ekstraksi ─────────────────────────
RE_FN_DIRECT = re.compile(r"google\.script\.run\s*\.\s*([A-Za-z_$][\w$]*)")
RE_FN_CHAIN = re.compile(r"with(?:Success|Failure|UserObject)Handler\s*\([^)]*\)\s*"
                         r"\.\s*([A-Za-z_$][\w$]*)")
RE_SHEET_URL = re.compile(r"/spreadsheets/d/([A-Za-z0-9-_]{20,})")
RE_OPENBYID = re.compile(r"openById\(\s*['\"]([\w-]{20,})['\"]\s*\)")
RE_FILEID = re.compile(r"(?:drive\.google\.com/(?:file/|open\?id=)|docs\.google\.com/"
                       r"(?:document|spreadsheets|presentation)/d/)([A-Za-z0-9-_]{20,})")
RE_COOKIE = re.compile(r"document\.cookie\s*=\s*([^;\n]+)")
RE_COOKIE_FN = re.compile(r"setCookie\s*\(([^)]{3,120})\)", re.I)
RE_HIDDEN = re.compile(r"<input\b[^>]*?type=[\"']?hidden[^>]*>", re.I | re.S)
RE_NAME_ATTR = re.compile(r"name=[\"']([^\"']+)[\"']")
RE_FETCH = re.compile(r"fetch\(\s*['\"]([^'\"]+)['\"]")
RE_XHR = re.compile(r"\.open\(\s*['\"](?:GET|POST)['\"]\s*,\s*['\"]([^'\"]+)['\"]")
RE_SCRIPT_SRC = re.compile(r"<script\b[^>]*?src=[\"']([^\"']+)[\"']")
RE_CRED_LINE = re.compile(r"(?:password|sandi|kunci|passwd|kataSandi|pin)\s*"
                          r"(?:==|===)?\s*[=:]\s*['\"]([^'\"]{1,60})['\"]", re.I)
RE_CRUD_CMP = re.compile(r"(?:==|===|!==|!=)\s*['\"]([^'\"]{1,60})['\"]", re.S)
RE_OBFUS = re.compile(r"\b(eval|atob|unescape|String\.fromCharCode|decodeURIComponent)\s*\(")
RE_PRINTF_API = re.compile(r"google\.script\.(?:run|host\.\w+)")

def fetch(url: str, cookie: str, timeout: float, verify_tls: bool = True):
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Cookie": cookie or "",
                                               "Accept-Language": "id,en;q=0.8"})
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, dict(r.headers), r.read().decode("utf-8", "replace")

def strip_tags(s: str) -> str:
    s = re.sub(r"(?s)<(script|style)[^>]*>.*?</\1>", " ", s)
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    return re.sub(r"\s{2,}", " ", s).strip()

def extract_js_blocks(html: str) -> list[str]:
    return [m.group(1) for m in re.finditer(r"(?s)<script\b[^>]*>(.*?)</script>", html)]

def extract_text(html: str) -> str:
    return strip_tags(html)

def main() -> int:
    ap = argparse.ArgumentParser(description="recon web app Google Apps Script (scope-locked)")
    ap.add_argument("--url", help="URL deployment /exec")
    ap.add_argument("--file", help="analisa HTML tersimpan (tanpa network)")
    ap.add_argument("--cookie", default="", help="cookie sesi (mis. hasil login guru)")
    ap.add_argument("--out", default="gapps_out", help="folder keluaran")
    ap.add_argument("--timeout", type=float, default=45.0)
    ap.add_argument("--pace", type=float, default=2.0, help="jeda antar-request")
    ap.add_argument("--no-verify-tls", action="store_true", help="lewati verifikasi TLS")
    ap.add_argument("--user-agent", default=UA)
    ap.add_argument("--authorized", action="store_true",
                    help="izin tertulis utk target di luar scope.txt")
    ap.add_argument("--scope", default=None, help="path scope.txt alternatif")
    a = ap.parse_args()
    if not a.url and not a.file:
        ap.error("butuh --url atau --file")
    if a.url:  # gerbang scope sebelum fetch (fetch = langkah aktif)
        sys.path.insert(0, str(pathlib.Path(__file__).parent))
        from kit_common import scope_check
        kw = {"authorized": a.authorized}
        if a.scope:
            kw["scope_path"] = a.scope
        scope_check(a.url, **kw)

    outd = pathlib.Path(a.out)
    outd.mkdir(parents=True, exist_ok=True)
    src_note = a.url or a.file
    sha = ""
    if a.file:
        html = pathlib.Path(a.file).read_text(errors="replace")
        status, headers = 200, {"x-source": f"file:{a.file}"}
    else:
        print(f"[*] fetch {a.url}")
        time.sleep(max(0.0, a.pace))
        try:
            status, headers, html = fetch(a.url, a.cookie, a.timeout,
                                           verify_tls=not a.no_verify_tls)
        except Exception as e:
            print(f"[!] gagal fetch: {e}")
            return 2
    sha = hashlib.sha256(html.encode("utf-8", "replace")).hexdigest()[:16]
    (outd / "page.html").write_text(html)
    (outd / "meta.json").write_text(json.dumps(
        {"source": src_note, "status": status,
         "headers": {k: v for k, v in (headers or {}).items()},
         "sha256_16": sha, "ts": time.strftime("%Y-%m-%d %H:%M:%S")},
        indent=2, ensure_ascii=False, default=str))

    js = "\n".join(extract_js_blocks(html))

    # ── 1) permukaan API server ──
    fns = set()
    for rx in (RE_FN_DIRECT, RE_FN_CHAIN):
        for name in rx.findall(js):
            if name not in ("withSuccessHandler", "withFailureHandler",
                            "withUserObject"):
                fns.add(name)
    fns = sorted(fns)
    (outd / "api_surface.txt").write_text("\n".join(fns) + ("\n" if fns else ""))

    # ── 2) Sheet/Drive/File ID ──
    ids: dict[str, set] = {}
    for label, rx in (("sheet_url", RE_SHEET_URL), ("openById", RE_OPENBYID),
                      ("drive_file", RE_FILEID)):
        ids[label] = sorted(set(rx.findall(js)) | set(rx.findall(html)))
    gviz_lines = []
    for kind in ("sheet_url", "openById"):
        for sid in ids[kind]:
            base = f"https://docs.google.com/spreadsheets/d/{sid}"
            gviz_lines += [
                f"{base}/gviz/tq?tqx=out:csv",                 # CSV semua sheet tanpa login
                f"{base}/gviz/tq?tqx=out:csv&sheet=Sheet1",
                f"{base}/export?format=csv",
                f"{base}/htmlview",
                f"{base}/edit",
            ]
    (outd / "gviz_urls.txt").write_text("\n".join(gviz_lines) + ("\n" if gviz_lines else ""))

    # ── 3) cookie sesi client-side ──
    cookies = [m.group(1).strip() for m in RE_COOKIE.finditer(js)]
    cookie_fns = [m.group(1).strip() for m in RE_COOKIE_FN.finditer(js)]
    cookie_names = []
    for c in cookies:
        name = c.split("=", 1)[0].strip().strip('"\'')
        if name and re.match(r"^[\w.-]+$", name):
            cookie_names.append(name)

    # ── 4) validasi password client-side ──
    creds = sorted(set(RE_CRED_LINE.findall(js)))
    cmps = sorted({c for c in RE_CRUD_CMP.findall(js) if len(c) >= 3})[:40]
    cred_lines = [l.strip()[:160] for l in js.splitlines()
                  if re.search(r"password|sandi|kunci|passwd|kataSandi", l, re.I)
                  and ("=" in l or "==" in l)][:30]

    # ── 5) endpoint lain & script eksternal ──
    eps = sorted(set(RE_FETCH.findall(js)) | set(RE_XHR.findall(js)))
    exts = [s for s in RE_SCRIPT_SRC.findall(html) if s.startswith("http")]

    # ── 6) obfuscation ──
    obf = RE_OBFUS.findall(js)
    obf_count = len(obf)

    # ── 7) form hidden fields (nama parameter doGet/doPost) ──
    hidden_names = []
    for tag in RE_HIDDEN.findall(html):
        m = RE_NAME_ATTR.search(tag)
        if m:
            hidden_names.append(m.group(1))

    # ── laporan triage ──
    L = [f"# gapps_probe — triage {src_note}", "",
         f"- status HTTP: {status} · sha256(html) 16: `{sha}`",
         f"- ukuran html: {len(html):,} B · js ekstrak: {len(js):,} B", ""]
    def sect(t, items, hint=""):
        L.append(f"\n## {t}")
        if hint:
            L.append(f"> {hint}")
        if items:
            L.extend([f"- `{x}`" for x in items])
        else:
            L.append("- (tidak terdeteksi)")
        L.append("")

    sect("1 · Permukaan API server (google.script.run)", fns,
         "setiap nama ini bisa dipanggil dari console browser: "
         "google.script.run.withSuccessHandler(console.log).<nama>() — bila ada "
         "'get*'/'list*'/'all*', risiko bocor TERBESAR (sering SELECT baris "
         "termasuk kolom password).")
    if any(re.search(r"(?i)(all|semua|list|get|data|dump|admin|guru|user|akun)", f) for f in fns):
        L.append("⚠️ ada fungsi dengan pola all/list/get/admin → **prioritas probe**.")
        L.append("")
    sect("2 · Sheet/Drive/file ID", [f"{k}: {v}" for k, v in ids.items() if v],
         "kalau sheet share 'anyone with the link', gviz_urls.txt mengekstrak "
         "SEMUA baris tanpa login — sebagai developer sekolah, ini pola umum.")
    sect("3 · Cookie sesi (client-side)", cookie_names + cookie_fns,
         "kalau role/identitas ada di cookie yang ditulis JS (documen.cookie), "
         "session bisa di-forge: cukup ganti nilai identitas → bypass login.")
    sect("4 · Validasi password di sisi klien", cred_lines + [f"literal: {c}" for c in creds],
         "kalau password dibandingkan di JS (== / === / atob), "
         "semua password bisa dibalik dari source — cek console browser.")
    sect("5 · Endpoint fetch/XHR lain", eps + exts)
    sect("6 · Form hidden (nama parameter)", hidden_names,
         "nama parameter = kamus untuk probing doGet/doPost (?mode=&user=&role=).")
    sect("7 · Obfuscation", [f"jumlah pemanggilan: {obf_count}",
                             *[f"`{o}(` di baris {i+1}" for i, o in enumerate(obf[:10])]],
         "eval/atob/fromCharCode menandakan logika disembunyikan — "
         "tempel potongan itu ke console & trace hasilnya.")
    if cmps:
        L += ["\n## String pembanding terlihat di JS (bukan password, tapi kandidat)",
              ", ".join(f"`{c}`" for c in cmps), ""]

    # ── console probe generator ──
    probe = ["// gapps_probe — tempel di DevTools console HANYA di halaman deployment",
             "// yang sedang kamu uji (terotorisasi). Jalankan: (async () => { ... })()",
             "const fns = " + json.dumps(fns, ensure_ascii=False, indent=1) + ";",
             "const out = {};",
             "for (const fn of fns) {",
             "  try {",
             "    await new Promise((res) => {",
             "      let done = false;",
             "      const t = setTimeout(() => { if (!done) { done = true;",
             "        console.log(fn, '=> TIMEOUT'); res(); } }, 15000);",
             "      google.script.run",
             "        .withSuccessHandler((v) => { if (!done) { done = true; clearTimeout(t);",
             "          out[fn] = v; console.log(fn, '=>', JSON.stringify(v).slice(0, 2000)); res(); } })",
             "        .withFailureHandler((e) => { if (!done) { done = true; clearTimeout(t);",
             "          console.log(fn, 'FAIL', JSON.stringify(e)); res(); } })",
             "        [fn]();",
             "    });",
             "  } catch (e) { console.log(fn, 'ERR', String(e)); }",
             "}",
             "console.log('=== RINGKAS (salin) ===');",
             "console.log(JSON.stringify(out, null, 1).slice(0, 20000));"]
    (outd / "console_probe.js").write_text("\n".join(probe) + "\n")

    # hasil ringkas
    risk = []
    if any(re.search(r"(?i)(all|semua|list|get|data|dump|admin|guru|user|akun)", f) for f in fns):
        risk.append("API server mencurigakan (semua/list/get) — bocor data?")
    if gviz_lines:
        risk.append("Ada Sheet/Drive ID — cek share setting + gviz export")
    if cookie_names or cookie_fns:
        risk.append("Cookie ditulis client-side — session bisa forge")
    if creds or cred_lines:
        risk.append("Indikasi validasi password di sisi klien")
    if obf_count >= 3:
        risk.append(f"Obfuscation JS ({obf_count}x) — logika disembunyikan")
    (outd / "report.md").write_text("\n".join(L) + "\n")
    print("[✓] report.md · api_surface.txt · console_probe.js · gviz_urls.txt · page.html")
    print(f"    source: {src_note} · API fn: {len(fns)} · IDs: "
          f"{sum(len(v) for v in ids.values())} · cookie: {len(cookie_names)}")
    if risk:
        print("[!] temuan prioritas:")
        for r in risk:
            print(f"    - {r}")
    print(f"[i] output lengkap: {outd.resolve()}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
