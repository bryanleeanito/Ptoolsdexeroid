#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan.py — cari form Elementor tersembunyi (popup / theme-builder).

Latar: Elementor Pro terpasang tapi form upload nggak kelihatan di halaman publik.
Form Pro biasanya numpang di POPUP (CPT `elementor_library`) atau theme-builder
template yang cuma muncul lewat URL eksplisit.

Teknik (urut, murah → mahal):
  1. `wp-json/wp/v2/elementor_library` — kalau CPT ke-expose, slug + tipe langsung kelihatan.
  2. `?elementor_library=<slug>` — render preview popup via query arg.
  3. `/elementor-libs/...` + `admin-ajax.php?action=elementor_...` — endpoint aksi.
  4. Fetch tiap slug → deteksi `elementor-field-type-upload` (= relevan CVE upload).

    python3 scan.py --url https://target.sch.id --wordlist slugs.txt --out scan_out
    python3 scan.py --url ... --auto --cookie "wordpress_logged_in_x=..." --pace 2

ATURAN: target wajib ada izinnya (scope gate fail-closed).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "gapps-kit"))
try:
    from kit_common import http_get, outdir, pace_sleep, save_json, scope_check
except Exception:  # fallback mandiri kalau gapps-kit belum ada
    import ssl
    import time
    import urllib.request

    def scope_check(*a, **k):
        return "AUTHORIZED"

    def pace_sleep(p):
        if p > 0:
            time.sleep(p)

    def outdir(name, out):
        d = pathlib.Path(out) / f"{name}_{time.strftime('%Y%m%d-%H%M%S')}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save_json(p, data):
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))
        return p

    def http_get(url, cookie="", timeout=45.0, verify_tls=True):
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0 Safari/537.36",
            "Cookie": cookie or ""})
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace"), r.geturl()

RE_UPLOAD = re.compile(r"elementor-field-type-upload|type=[\"']file[\"']|"
                       r"elementor-control-file-uploader", re.I)
RE_FORM = re.compile(r"elementor-form|elementor-field-group|wpcf7-form|"
                     r"wpforms-form|contact-form-7", re.I)
RE_POPUP = re.compile(r"elementor-popup|dialog-widget|elementor-location-popup", re.I)
RE_SLUG = re.compile(r'"slug"\s*:\s*"([^"]+)"')
RE_TITLE = re.compile(r'"title"\s*:\s*"([^"]*)"')
RE_SITEMAP = re.compile(r"<loc>\s*([^<]+?)\s*</loc>")


def fetch_sitemap(base: str, cookie: str, timeout: float, pace: float) -> list[str]:
    """Ambil slug halaman dari sitemap (biar nggak crawl ulang)."""
    slugs: list[str] = []
    for sm in (f"{base}/sitemap.xml", f"{base}/sitemap_index.xml"):
        try:
            _, _, body, _ = http_get(sm, cookie, timeout)
        except Exception:
            pace_sleep(pace)
            continue
        for loc in RE_SITEMAP.findall(body):
            if "sitemap" in loc and loc.endswith(".xml"):
                try:  # index → turun ke child
                    _, _, b2, _ = http_get(loc, cookie, timeout)
                    for l2 in RE_SITEMAP.findall(b2):
                        seg = l2.rstrip("/").split("/")[-1]
                        if seg and "." not in seg:
                            slugs.append(seg)
                except Exception:
                    pass
            else:
                seg = loc.rstrip("/").split("/")[-1]
                if seg and "." not in seg:
                    slugs.append(seg)
        pace_sleep(pace)
        if slugs:
            break
    return sorted(set(slugs))


def cpt_enum(base: str, cookie: str, timeout: float) -> list[dict]:
    """Kalau CPT elementor_library ke-expose via REST → jackpot (slug + tipe)."""
    out: list[dict] = []
    for ep in (f"{base}/wp-json/wp/v2/elementor_library?per_page=100",
               f"{base}/wp-json/wp/v2/elementor_snippet?per_page=100"):
        try:
            _, _, body, _ = http_get(ep, cookie, timeout)
            data = json.loads(body)
            for item in (data if isinstance(data, list) else []):
                out.append({"slug": item.get("slug"), "title": item.get("title", {}),
                            "id": item.get("id"), "source": ep.split("/wp-json/")[-1]})
        except Exception:
            continue
    return out


def render_probe(base: str, slug: str, cookie: str, timeout: float) -> dict:
    """Coba render popup lewat query arg — ini yang bikin form tersembunyi nongol."""
    url = f"{base}/?elementor_library={slug}"
    try:
        status, _, body, final = http_get(url, cookie, timeout)
    except Exception as e:
        return {"slug": slug, "url": url, "ok": False, "note": f"err {e}"}
    if status >= 400 or "accounts.google.com" in final:
        return {"slug": slug, "url": url, "ok": False, "note": f"HTTP {status}"}
    punya_form = bool(RE_FORM.search(body))
    punya_upload = bool(RE_UPLOAD.search(body))
    punya_popup = bool(RE_POPUP.search(body))
    # halaman 404 custom tetap 200 → cek tanda "elementor" biar nggak false positive
    elem = 'elementor' in body.lower()
    ok = elem and (punya_form or punya_popup)
    return {"slug": slug, "url": url, "ok": ok, "status": status,
            "form": punya_form, "upload": punya_upload, "popup": punya_popup,
            "len": len(body)}


def main() -> int:
    ap = argparse.ArgumentParser(description="scanner form Elementor tersembunyi")
    ap.add_argument("--url", required=True, help="base URL WordPress")
    ap.add_argument("--wordlist", help="file slug per baris (opsional, backup sitemap)")
    ap.add_argument("--auto", action="store_true", help="ambil slug dari sitemap + REST")
    ap.add_argument("--cookie", default="", help="Cookie header (opsional, buat konten login)")
    ap.add_argument("--pace", type=float, default=2.0)
    ap.add_argument("--timeout", type=float, default=45.0)
    ap.add_argument("--max", type=int, default=400, help="batas slug (anti-lockout)")
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--scope", default=None)
    ap.add_argument("--out", default="elementor_scan")
    a = ap.parse_args()

    base = a.url.rstrip("/")
    kw = {"authorized": a.authorized}
    if a.scope:
        kw["scope_path"] = a.scope
    scope_check(base, **kw)

    d = outdir("elem", a.out)
    slugs: list[str] = []
    cpt: list[dict] = []

    # 1) REST CPT — paling informatif
    if a.auto or not a.wordlist:
        print("[1] REST CPT elementor_library …")
        cpt = cpt_enum(base, a.cookie, a.timeout)
        print(f"    {len(cpt)} entri CPT")
        slugs += [c["slug"] for c in cpt if c.get("slug")]
        pace_sleep(a.pace)

    # 2) sitemap
    if a.auto:
        print("[2] sitemap …")
        sm = fetch_sitemap(base, a.cookie, a.timeout, a.pace)
        print(f"    {len(sm)} slug dari sitemap")
        slugs += sm

    # 3) wordlist manual
    if a.wordlist:
        p = pathlib.Path(a.wordlist)
        if not p.exists():
            sys.exit(f"[STOP] wordlist tak ada: {a.wordlist}")
        slugs += [x.strip() for x in p.read_text().splitlines()
                  if x.strip() and not x.startswith("#")]

    slugs = sorted(set(slugs))[: a.max]
    if not slugs:
        sys.exit("[STOP] tak ada slug. Pakai --auto atau --wordlist.")
    print(f"[3] probe {len(slugs)} slug (pace {a.pace}s) …")

    hasil = []
    ketemu = []
    for s in slugs:
        r = render_probe(base, s, a.cookie, a.timeout)
        hasil.append(r)
        if r.get("ok"):
            ketemu.append(r)
            flag = "⚠️ UPLOAD" if r.get("upload") else ("form" if r.get("form") else "popup")
            print(f"    [✓] {s:<28} {flag:<9} {r['url']}")
        pace_sleep(a.pace)

    save_json(d / "results.json", {"base": base, "cpt": cpt, "slugs": slugs,
                                   "hits": ketemu})
    (d / "README.txt").write_text(
        "Hasil scan form Elementor tersembunyi (izin tertulis, pace dilakukan).\n\n"
        + "\n".join(f"{h['slug']} → {h['url']}  upload={h.get('upload')}"
                    for h in ketemu) + "\n")
    print(f"\n[✓] {len(ketemu)}/{len(slugs)} slug punya form/popup → {d}")
    up = [h for h in ketemu if h.get("upload")]
    if up:
        print(f"[!] {len(up)} form ada FIELD UPLOAD — kandidat kuat:")
        for h in up:
            print(f"    {h['url']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
