#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gviz_fetch.py — coba tarik isi Google Sheet TANPA login (gviz/export/htmlview).

Pelajaran dari kasus sekolah: URL Sheet ID sering kebocor dari HTML/JS Apps Script.
Kalau Sheet-nya "anyone with link = viewer", endpoint publik ini balikin data mentah.

    python3 gviz_fetch.py --sheet 1AbCdEf... --out sheet_dumps
    python3 gviz_fetch.py --sheet-ids ids.txt --pace 2

Endpoint yang dicoba (urut → stop di kali pertama sukses):
  1. /gviz/tq?tqx=out:csv            (gviz publik)
  2. /export?format=csv               (export langsung)
  3. /htmlview                        (render publik)
  4. /export?format=xlsx              (biner — dicek magic PK)
Deteksi gagal: redirect ke accounts.google.com / login / empty body.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from kit_common import (http_get, outdir, pace_sleep, save_json,  # noqa: E402
                        scope_check, summary)

LOGIN_SIGNS = ("accounts.google.com", "ServiceLogin", "Sign in", "Masuk",
               "usechooser", "v2/accept")
RE_GSHEET_URL = re.compile(r"(?:docs\.google\.com/spreadsheets/d/|/spreadsheets/d/)"
                           r"([A-Za-z0-9_-]{20,})")


def sheet_id_from(url: str) -> str | None:
    m = RE_GSHEET_URL.search(url)
    return m.group(1) if m else None


def looks_like_data(status: int, final_url: str, body: bytes | str,
                    ctype: str = "") -> tuple[bool, str]:
    txt = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    if "accounts.google.com" in final_url or "/ServiceLogin" in final_url:
        return False, "redirect → login"
    if status >= 400:
        return False, f"HTTP {status}"
    if any(s.lower() in txt[:4000].lower() for s in LOGIN_SIGNS):
        return False, "render halaman login"
    if isinstance(body, bytes):
        if body[:2] == b"PK":
            return True, "xlsx (PK zip) ✓"
        return False, "bukan biner data"
    if len(txt) < 40:
        return False, "kosong/terlalu kecil"
    # gviz csv: ada baris data / header kolom
    rows = [r for r in txt.splitlines() if r.strip()]
    if len(rows) >= 1 and ("," in txt or "\t" in txt):
        return True, f"CSV {len(rows)} baris ✓"
    return True, f"HTML {len(txt)} B (dicek manual)"


def try_endpoints(sid: str, cookie: str, pace: float, timeout: float,
                  origin: str = "https://docs.google.com"):
    base = f"{origin}/spreadsheets/d/{sid}"
    cands = [
        ("gviz_csv", f"{base}/gviz/tq?tqx=out:csv", False),
        ("gviz_csv_sheet1", f"{base}/gviz/tq?tqx=out:csv&sheet=0", False),
        ("export_csv", f"{base}/export?format=csv", False),
        ("export_csv_gid", f"{base}/export?format=csv&gid=0", False),
        ("htmlview", f"{base}/htmlview", False),
        ("export_xlsx", f"{base}/export?format=xlsx", True),
    ]
    for name, url, is_bytes in cands:
        try:
            status, hdr, body, final = http_get(url, cookie, timeout)
        except Exception as e:
            yield {"endpoint": name, "url": url, "ok": False, "note": f"err {e}"}
            pace_sleep(pace)
            continue
        if is_bytes:
            txt = body.decode("utf-8", "replace")
            raw = txt.encode("utf-8", "surrogateescape")
            ok, note = looks_like_data(status, final, raw)
        else:
            ok, note = looks_like_data(status, final, body)
        yield {"endpoint": name, "url": url, "status": status,
               "ok": ok, "note": note, "final": final,
               "_body": body if ok else None}
        pace_sleep(pace)
        if ok and is_bytes is False:
            return  # cukup satu endpoint sukses → stop


def main() -> int:
    ap = argparse.ArgumentParser(description="dump Sheet via gviz/export (publik)")
    ap.add_argument("--sheet", help="Sheet ID atau URL dokumen")
    ap.add_argument("--sheet-ids", help="file berisi ID/URL per baris")
    ap.add_argument("--cookie", default="", help="opsional: Cookie header")
    ap.add_argument("--out", default="sheet_dumps")
    ap.add_argument("--pace", type=float, default=2.0, help="jeda antar request (s)")
    ap.add_argument("--timeout", type=float, default=45.0)
    ap.add_argument("--base", default="https://docs.google.com",
                    help="origin dokumen (untuk mock/E2E)")
    ap.add_argument("--authorized", action="store_true",
                    help="sheet ini milik target yang kubut izin")
    ap.add_argument("--scope", default=None)
    a = ap.parse_args()

    ids: list[str] = []
    if a.sheet:
        m = sheet_id_from(a.sheet) or a.sheet
        ids.append(m)
    if a.sheet_ids:
        for line in pathlib.Path(a.sheet_ids).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ids.append(sheet_id_from(line) or line)
    if not ids:
        ap.error("butuh --sheet atau --sheet-ids")

    kw = {"authorized": a.authorized}
    if a.scope:
        kw["scope_path"] = a.scope
    scope_check(a.base if "://" in a.base else f"https://{a.base}", **kw)

    d = outdir("sheet", a.out)
    all_res = []
    for sid in ids:
        print(f"\n[→] Sheet {sid[:16]}…")
        found = None
        for res in try_endpoints(sid, a.cookie, a.pace, a.timeout, a.base.rstrip("/")):
            print(f"    {res['endpoint']:<16} {'[✓]' if res['ok'] else '[✗]'} {res['note']}")
            all_res.append({k: v for k, v in res.items() if not k.startswith("_")})
            if res.get("_body"):
                found = res
                ext = "csv" if "csv" in res["endpoint"] else "html"
                (d / f"{sid[:24]}_{res['endpoint']}.{ext}").write_text(res["_body"])
                print(f"    → SIMPAN: {d}/{sid[:24]}_{res['endpoint']}.{ext}")
        if not found:
            print("    (semua endpoint tertutup — sheet private / login wajib)")
    save_json(d / "results.json", all_res)
    summary("gviz dump",
            [("sheet dicoba", len(ids)),
             ("endpoint sukses", sum(1 for r in all_res if r.get("ok"))),
             ("file tersimpan", len([f for f in d.iterdir()
                                     if f.name != "results.json"]))])
    print(f"[✓] {d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
