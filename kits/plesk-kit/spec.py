#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plesk_openapi_parser.py - audit OpenAPI/Swagger: temukan endpoint TANPA auth.

Kerja pada DOKUMEN spec, bukan menyerang target. Zero network touch kecuali
--url eksplisit diberikan.

    python3 plesk_openapi_parser.py --in spec.json
    python3 plesk_openapi_parser.py --in spec.yaml --min-risk publik
    python3 plesk_openapi_parser.py --in spec.json --format json --out hasil.json

Aturan OpenAPI yang dipakai untuk menilai status auth (ini inti nilainya):

  * operasi TANPA field `security` -> inherit dari root `security`
  * `security: []`  (list kosong)  -> EKSPLISIT publik, override global
  * `security: [{}]` (ada objek kosong) -> anonymous diizinkan (tanpa kredensial)
  * `security: [{{"scheme": [...]}}]` -> butuh skema tsb
  * root tanpa `security` + operasi tanpa `security` -> TIDAK ADA auth terdeklarasi
                                          (belum tentu publik - perlu verifikasi)

Output: tabel endpoint, diurutkan dari yang paling berisiko (publik dulu).
"""
from __future__ import annotations

import argparse, json, pathlib, sys

METODE = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


def muat(path: str):
    p = pathlib.Path(path)
    if not p.exists():
        sys.exit(f"[STOP] file tak ada: {path}")
    teks = p.read_text(encoding="utf-8", errors="replace")
    try:
        return json.loads(teks), "json"
    except json.JSONDecodeError:
        pass
    try:
        import yaml  # opsional
        return yaml.safe_load(teks), "yaml"
    except ImportError:
        sys.exit("[STOP] bukan JSON valid, dan PyYAML tidak terpasang.\n"
                 "       Solusi: convert dulu -> `python3 -m json.tool spec.yaml > spec.json`")


def nilai_auth(op_security, root_security):
    """-> (kode, keterangan, daftar_skema)."""
    if op_security is not None:
        sec = op_security
        asal = "operasi"
    else:
        sec = root_security
        asal = "global"
    if sec is None:
        return ("NONE", "tidak ada `security` terdeklarasi", [])
    if sec == []:
        return ("PUBLIC", f"eksplisit publik (`security: []` di {asal})", [])
    skema = []
    anonim = False
    for req in sec:
        if req == {}:
            anonim = True
        else:
            skema += list(req.keys())
    if anonim:
        return ("ANON", f"anonymous diizinkan (`[{{}}]` di {asal})", skema)
    return ("AUTH", f"butuh {', '.join(sorted(set(skema))) or '?'} ({asal})", skema)


URUT = {"PUBLIC": 0, "ANON": 1, "NONE": 2, "AUTH": 3}


def audit(spec: dict) -> list:
    root_sec = spec.get("security")
    hasil = []
    paths = spec.get("paths") or {}
    for jalan, oper in paths.items():
        if not isinstance(oper, dict):
            continue
        # parameter tingkat path ikut menentukan konteks
        for metode in METODE:
            op = oper.get(metode)
            if not isinstance(op, dict):
                continue
            kode, ket, skema = nilai_auth(op.get("security", None) if "security" in op else None,
                                          root_sec)
            hasil.append({
                "metode": metode.upper(),
                "jalan": jalan,
                "kode": kode,
                "keterangan": ket,
                "skema": sorted(set(skema)),
                "summary": op.get("summary", ""),
                "operationId": op.get("operationId", ""),
            })
    hasil.sort(key=lambda x: (URUT[x["kode"]], x["jalan"]))
    return hasil


def main():
    ap = argparse.ArgumentParser(description="audit spec OpenAPI: cari endpoint tanpa auth")
    ap.add_argument("--in", dest="inp", required=True, help="file .json / .yaml")
    ap.add_argument("--out", default="", help="tulis hasil JSON ke file")
    ap.add_argument("--format", choices=["tabel", "json"], default="tabel")
    ap.add_argument("--min-risk", choices=["publik", "anonim", "semua"],
                    default="semua",
                    help="publik = hanya `security: []`; anonim = + `[{}]`")
    a = ap.parse_args()

    spec, fmt = muat(a.inp)
    if not isinstance(spec, dict) or "paths" not in spec:
        sys.exit("[STOP] bukan dokumen OpenAPI (tidak ada kunci `paths`)")

    info = spec.get("info", {})
    hasil = audit(spec)
    if a.min_risk == "publik":
        hasil = [h for h in hasil if h["kode"] == "PUBLIC"]
    elif a.min_risk == "anonim":
        hasil = [h for h in hasil if h["kode"] in ("PUBLIC", "ANON")]

    print(f"[*] spec {fmt} · {info.get('title','(tanpa judul)')} "
          f"v{info.get('version','?')} · {len(spec.get('paths') or {})} path")
    print(f"[*] operasi dianalisis: {len(hasil)}\n")

    if a.format == "json":
        keluar = json.dumps({"sumber": a.inp, "judul": info.get("title", ""),
                             "versi": info.get("version", ""),
                             "jumlah": len(hasil), "operasi": hasil},
                            indent=2, ensure_ascii=False)
        if a.out:
            pathlib.Path(a.out).write_text(keluar, encoding="utf-8")
            print(f"[OK] {a.out}")
        else:
            print(keluar)
        return 0

    if not hasil:
        print("[i] tidak ada operasi yang cocok dengan filter")
        return 0

    # ringkasan dulu
    rekap = {}
    for h in hasil:
        rekap[h["kode"]] = rekap.get(h["kode"], 0) + 1
    print("[ringkasan]")
    label = {"PUBLIC": "PUBLIC  (security: [] )", "ANON": "ANONIM  ([{}] - tanpa kredensial)",
             "NONE": "NONE    (tak ada security)", "AUTH": "AUTH    (butuh skema)"}
    for k in ("PUBLIC", "ANON", "NONE", "AUTH"):
        if k in rekap:
            print(f"  {rekap[k]:>4}  {label[k]}")
    print()

    print(f"{'RISIKO':<8} {'METHOD':<7} {'JALAN':<48} KETERANGAN")
    print("-" * 110)
    for h in hasil:
        jalan = h["jalan"] if len(h["jalan"]) <= 46 else h["jalan"][:45] + "~"
        print(f"{h['kode']:<8} {h['metode']:<7} {jalan:<48} {h['keterangan']}")

    bebas = [h for h in hasil if h["kode"] in ("PUBLIC", "ANON")]
    if bebas:
        print(f"\n[!] {len(bebas)} operasi bisa dipanggil TANPA kredensial - "
              f"verifikasi manual sebelum dilaporkan")
        print("    (spec bisa saja tidak lengkap; auth bisa ditegakkan di gateway)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
