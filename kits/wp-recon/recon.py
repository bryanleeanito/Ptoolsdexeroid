#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""recon.py — pra-recon WordPress: username enum + fingerprint + deteksi lockout.

Ini bagian DEPAN rantai:
    wp-recon → (users.txt) → wordlist-sekolah → wp-auth-tester → egress-rotator

Semua langkah GET / passive-ish (pace dihormati, tanpa brute-force):

  1. Username enum
     - REST `/wp-json/wp/v2/users` (sering kebuka tanpa auth)
     - author archive `/?author=N` → redirect ke `/author/<slug>/`
  2. Fingerprint plugin/theme (readme.txt / style.css punya versi)
     → versi ini yang nentuin relevansi CVE (mis. Elementor Pro, Divi)
  3. Deteksi WAF/lockout dari header + keberadaan plugin → patokan pace buat tester

    python3 recon.py --url https://target.sch.id --out recon_out
    python3 recon.py --url ... --author-max 10 --pace 1.5 --authorized

ATURAN: target wajib ada izinnya (scope gate fail-closed).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gapps-kit"))
try:
    from kit_common import http_get, outdir, pace_sleep, save_json, scope_check
except Exception:
    sys.exit("[STOP] kit_common tidak ketemu — jalankan dari dalam repo Ptoolsdexeroid.")

RE_AUTHOR = re.compile(r"/author/([A-Za-z0-9._-]+)/?", re.I)
RE_GENERATOR = re.compile(r'<meta name="generator" content="([^"]+)"', re.I)
RE_USER_LOGIN = re.compile(r'"slug"\s*:\s*"([^"]+)"')
RE_USER_NAME = re.compile(r'"name"\s*:\s*"([^"]+)"')

# plugin yang relevan buat misi (slug → kenapa penting)
PLUGIN_DICARI = {
    "elementor": "page builder — cek versi Pro (CVE upload)",
    "elementor-pro": "form upload Pro — kunci utama",
    "divi": "builder — cek versi (CVE auth bypass)",
    "wordfence": "WAF/lockout → patokan pace tester",
    "wp-file-manager": "RCE historis",
    "duplicator": "RCE historis",
    "contact-form-7": "form + upload",
    "wpforms-lite": "form",
    "classic-editor": "sinyal usia situs",
}
WAF_HEADER = {
    "server": "server banner", "cf-ray": "Cloudflare", "x-sucuri-id": "Sucuri WAF",
    "x-waf": "WAF generik", "x-frame-options": "clickjacking guard",
    "x-powered-by": "teknologi bocor",
}


def aman_url(u: str) -> str:
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u.rstrip("/")


def ambil(url: str, cookie: str, timeout: float) -> tuple[int, str, dict, str]:
    try:
        status, hdr, body, final = http_get(url, cookie, timeout)
        return status, body, {k.lower(): v for k, v in hdr.items()}, final
    except Exception as e:
        return 0, "", {}, str(e)


def enum_users(base: str, cookie: str, timeout: float, pace: float) -> list[dict]:
    users: list[dict] = []
    # (a) REST API
    st, body, _, _ = ambil(f"{base}/wp-json/wp/v2/users?per_page=100", cookie, timeout)
    pace_sleep(pace)
    if st == 200 and body.strip().startswith("["):
        try:
            for it in json.loads(body):
                users.append({"sumber": "rest", "login": it.get("slug"),
                              "nama": (it.get("name") or ""), "id": it.get("id")})
        except Exception:
            pass
    # (b) author archive
    terlihat = {u["login"] for u in users}
    for n in range(1, 11):
        st, _, hdr, final = ambil(f"{base}/?author={n}", cookie, timeout)
        pace_sleep(pace)
        m = RE_AUTHOR.search(final or "")
        if m and m.group(1) not in terlihat:
            terlihat.add(m.group(1))
            users.append({"sumber": f"author={n}", "login": m.group(1),
                          "nama": "", "id": n})
    return users


def fingerprint(base: str, cookie: str, timeout: float, pace: float) -> dict:
    fp: dict = {"plugin": {}, "tema": {}, "wp_version": None, "waf": {}, "header": {}}

    st, body, hdr, _ = ambil(f"{base}/", cookie, timeout)
    pace_sleep(pace)
    for h, ket in WAF_HEADER.items():
        if h in hdr:
            fp["header"][h] = f"{hdr[h]} ({ket})"
    m = RE_GENERATOR.search(body)
    if m:
        fp["wp_version"] = m.group(1)

    for slug, alasan in PLUGIN_DICARI.items():
        st, rd, _, _ = ambil(f"{base}/wp-content/plugins/{slug}/readme.txt",
                              cookie, timeout)
        pace_sleep(pace)
        if st == 200 and ("Stable tag" in rd or "Contributors" in rd):
            ver = re.search(r"Stable tag:\s*([^\r\n]+)", rd, re.I)
            fp["plugin"][slug] = {"versi": ver.group(1).strip() if ver else "?",
                                  "kenapa": alasan}
            if slug == "wordfence":
                fp["waf"]["wordfence"] = "aktif — pakai pace besar / rotasi egress"

    # tema aktif: dari markup halaman
    st, body, _, _ = ambil(f"{base}/", cookie, timeout)
    pace_sleep(pace)
    for tm in re.finditer(r"/wp-content/themes/([A-Za-z0-9_-]+)/", body):
        slug = tm.group(1)
        if slug not in fp["tema"]:
            st2, css, _, _ = ambil(f"{base}/wp-content/themes/{slug}/style.css",
                                   cookie, timeout)
            pace_sleep(pace)
            nama = re.search(r"Theme Name:\s*([^\r\n]+)", css, re.I)
            ver = re.search(r"Version:\s*([^\r\n]+)", css, re.I)
            fp["tema"][slug] = {
                "nama": nama.group(1).strip() if nama else slug,
                "versi": ver.group(1).strip() if ver else "?",
            } if st2 == 200 else {"nama": slug, "versi": "?"}
    return fp


def main() -> int:
    ap = argparse.ArgumentParser(description="pra-recon WordPress (enum user + fingerprint)")
    ap.add_argument("--url", required=True, help="base URL situs WP")
    ap.add_argument("--cookie", default="")
    ap.add_argument("--author-max", type=int, default=10)
    ap.add_argument("--pace", type=float, default=1.5)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--scope", default=None)
    ap.add_argument("--out", default="wp_recon")
    a = ap.parse_args()

    base = aman_url(a.url)
    kw = {"authorized": a.authorized}
    if a.scope:
        kw["scope_path"] = a.scope
    scope_check(base, **kw)
    d = outdir("recon", a.out)

    print(f"[1] username enum @ {base} …")
    users = enum_users(base, a.cookie, a.timeout, a.pace)
    print(f"    {len(users)} username: {', '.join(u['login'] or '?' for u in users) or '-'}")

    print("[2] fingerprint …")
    fp = fingerprint(base, a.cookie, a.timeout, a.pace)
    for s, v in fp["plugin"].items():
        print(f"    [plugin] {s:<18} v{v['versi']:<10} — {v['kenapa']}")
    for s, v in fp["tema"].items():
        print(f"    [tema]   {s:<18} {v['nama']} v{v['versi']}")
    if fp["wp_version"]:
        print(f"    [wp]     {fp['wp_version']}")
    for h, v in fp["header"].items():
        print(f"    [header] {h}: {v}")
    for w, v in fp["waf"].items():
        print(f"    [⚠ WAF]  {w}: {v}")

    if users:
        (d / "users.txt").write_text(
            "\n".join(u["login"] for u in users if u["login"]) + "\n")
        print(f"\n[✓] users.txt ({len(users)}) → {d}")
    save_json(d / "fingerprint.json", fp)

    # rekomendasi pace ke tester
    pace_saran = 25.0
    if fp["plugin"].get("wordfence") or "cf-ray" in fp["header"]:
        pace_saran = 60.0
        print(f"\n[!] WAF/Cloudflare terdeteksi → saran pace wp-auth-tester: {pace_saran:.0f}s "
              f"+ --rotate tor --rotate-every 5")
    else:
        print(f"\n[→] lanjut: python3 ../wp-auth-tester/tester.py "
              f"--url {base}/wp-login.php --users-file {d}/users.txt "
              f"--wordlist <hasil wordlist-sekolah> --pace {pace_saran:.0f} --authorized")
    return 0


if __name__ == "__main__":
    sys.exit(main())
