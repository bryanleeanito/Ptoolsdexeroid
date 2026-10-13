#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plesk_cve_checker.py - cocokkan versi Plesk dengan advisory resmi (lokal).

Murni lookup dokumen, zero network, TIDAK mengeksploitasi apa pun. Hanya
menjawab: "CVE mana yang sudah patch, mana yang belum, mana datanya meragukan".

    python3 plesk_cve_checker.py --version 18.0.80.5 --db advisories.json
    python3 plesk_cve_checker.py --version 18.0.80 --db advisories.json --format json

FORMAT VERSES PLESK (dari `plesk -v`, docs resmi):
    Product version: Plesk Obsidian 18.0.65.2   <- EMPAT field
    Build date:      2024/11/22 08:00
    Revision:        738ea4038904b53a068e522aa7c64390f4f29d5f

FORMAT BUILD:  <MMmm><YYMMDD>.<rev>   contoh 1800260925.18
                     18.0  2026-09-25  rev 18
PERINGATAN: build TIDAK memuat nomor update (".80" tidak ada di dalamnya),
jadi --build SAJA TIDAK CUKUP untuk analisis. Pakai --version dari `plesk -v`.

Perbandingan: kedua sisi dipadkan ke 4 field dengan nol, sehingga
    18.0.80      -> (18,0,80,0)
    18.0.80.5    -> (18,0,80,5)
18.0.80 < 18.0.80.5 -> MUNGKIN_VULN.  (18.0.80 = 18.0.80.0 = Update 0)

FIELD `dasar` pada tiap advisory menandai kualitas datanya:
    tercatat   - versi patch ditulis eksplisit di sumber
    inferensi - saya turunkan dari rentang "affects X sebelum Y"
    konflik   - dua sumber beda keterangan -> SELALU verifikasi manual
"""
from __future__ import annotations

import argparse, datetime, json, pathlib, re, sys

VER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?$")
BUILD_RE = re.compile(r"^(\d{4})(\d{6})\.(\d+)$")
PAD = 4


def pad(t: tuple) -> tuple:
    return tuple(t) + (0,) * (PAD - len(t))


def parse_versi(s: str) -> tuple:
    m = VER_RE.match((s or "").strip())
    if not m:
        sys.exit(f"[STOP] format versi tak dikenal: {s!r} (harus X.Y.Z atau X.Y.Z.N)")
    return tuple(int(x) for x in m.groups() if x is not None)


def parse_build(b: str) -> dict:
    """Hanya tanggal + rev. TIDAK menghasilkan versi (nomor update tak ada di sini)."""
    m = BUILD_RE.match((b or "").strip())
    if not m:
        return {}
    mm, ymd, rev = m.groups()
    try:
        tgl = datetime.date(2000 + int(ymd[:2]), int(ymd[2:4]), int(ymd[4:6]))
    except ValueError:
        tgl = None
    return {"mentah": b, "major_minor": f"{int(mm[:2])}.{int(mm[2:])}",
            "tanggal": tgl.isoformat() if tgl else None, "rev": int(rev)}


def banding(target: tuple, fixed: str) -> str:
    if not fixed:
        return "TANPA_FIXED"
    m = VER_RE.match(str(fixed).strip())
    if not m:
        return "TANPA_FIXED"
    fv = pad(tuple(int(x) for x in m.groups() if x is not None))
    return "PATCHED" if target >= fv else "MUNGKIN_VULN"


def muat_db(path: str) -> dict:
    p = pathlib.Path(path)
    if not p.exists():
        sys.exit(f"[STOP] db tak ada: {path}\n"
                 f'       schema: {{"sumber":"...","diambil":"YYYY-MM-DD",'
                 f'"advisories":[{{"cve":"CVE-....","judul":"...",'
                 f'"severity":"high","fixed_in":"18.0.xx.y",'
                 f'"dasar":"tercatat","url":"..."}}]}}')
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        sys.exit(f"[STOP] db bukan JSON valid: {e}")
    if not isinstance(d, dict) or "advisories" not in d:
        sys.exit('[STOP] db tidak punya kunci "advisories"')
    return d



def parse_sweep(s: str) -> list:
    try:
        if "-" in s:
            lo, hi = s.split("-", 1)
            r = list(range(int(lo), int(hi) + 1))
        else:
            r = [int(s)]
    except ValueError:
        sys.exit(f"[STOP] --sweep harus angka atau rentang, mis. 0-9 (dapat: {s!r})")
    if not r or len(r) > 25:
        sys.exit("[STOP] --sweep maksimal 25 nilai")
    return r


def jalankan_sweep(base3: tuple, mikro: list, db: dict, fmt: str, out: str) -> int:
    """Klasifikasi tiap advisory terhadap SELURUH rentang Update sekaligus."""
    versis = [base3 + (m,) for m in mikro]
    rows = []
    for adv in db["advisories"]:
        fixed = str(adv.get("fixed_in", "") or "")
        ambang = None
        m = VER_RE.match(fixed) if fixed else None
        if not m:
            kelas, ket = "DATA_KURANG", "sumber tak menyebut fixed_in -> tak bisa disimpulkan"
        else:
            fv = pad(tuple(int(x) for x in m.groups() if x is not None))
            st = [("PATCHED" if v >= fv else "MUNGKIN_VULN") for v in versis]
            if all(x == "PATCHED" for x in st):
                kelas, ket = "PASTI_TERPATCH", "sudah patch di SELURUH rentang"
            elif all(x == "MUNGKIN_VULN" for x in st):
                kelas, ket = ("PASTI_TERDAMPAK",
                              f"terdampak di SELURUH rentang (fixed_in={fixed})")
            else:
                ambang = next(mikro[i] for i, x in enumerate(st) if x == "PATCHED")
                kelas = "KONDISIONAL"
                ket = f"VULN jika Update < {ambang}, PATCHED jika >= {ambang}"
        rows.append({"cve": adv.get("cve", "?"), "severity": adv.get("severity", "?"),
                     "kelas": kelas, "ambang": ambang, "keterangan": ket,
                     "fixed_in": fixed, "dasar": adv.get("dasar", "tercatat"),
                     "judul": adv.get("judul", "")})

    urut = {"PASTI_TERDAMPAK": 0, "KONDISIONAL": 1, "DATA_KURANG": 2,
            "PASTI_TERPATCH": 3}
    rows.sort(key=lambda r: (urut[r["kelas"]], r["cve"]))
    rekap = {}
    for r in rows:
        rekap[r["kelas"]] = rekap.get(r["kelas"], 0) + 1

    if fmt == "json":
        keluar = json.dumps({"rentang": f"{base3[0]}.{base3[1]}.{base3[2]}."
                                       f"{min(mikro)}..{max(mikro)}",
                             "db": db.get("sumber", ""), "rekap": rekap,
                             "advisories": rows}, indent=2, ensure_ascii=False)
        if out:
            pathlib.Path(out).write_text(keluar, encoding="utf-8")
            print(f"[OK] {out}")
        else:
            print(keluar)
        return 0

    print(f"[*] rentang target : {base3[0]}.{base3[1]}.{base3[2]}."
          f"{min(mikro)} .. {base3[0]}.{base3[1]}.{base3[2]}.{max(mikro)}")
    print(f"[*] db : {db.get('sumber','')} ambil={db.get('diambil','?')}\n")
    print("[ringkasan]")
    for k in ("PASTI_TERDAMPAK", "KONDISIONAL", "DATA_KURANG", "PASTI_TERPATCH"):
        if k in rekap:
            print(f"  {rekap[k]:>4}  {k}")
    print()
    tampil = [r for r in rows if r["kelas"] != "PASTI_TERPATCH"]
    if not tampil:
        print("[OK] tak ada advisory terbuka di rentang ini")
        return 0
    print(f"{'KELAS':<17} {'CVE':<16} {'SEV':<9} {'AMBANG':<8} {'DASAR':<10} KETERANGAN")
    print("-" * 112)
    for r in tampil:
        amb = str(r["ambang"]) if r["ambang"] is not None else "-"
        print(f"{r['kelas']:<17} {r['cve']:<16} {str(r['severity']):<9} "
              f"{amb:<8} {r['dasar']:<10} {r['keterangan'][:44]}")
    pasti = [r for r in rows if r["kelas"] == "PASTI_TERDAMPAK"]
    if pasti:
        print(f"\n[!] {len(pasti)} CVE TERDAMPAK DI SEMUA NILAI RENTANG - "
              "tak peduli Update berapa pun")
        for r in pasti:
            print(f"    - {r['cve']} ({r['severity']}) {r['judul'][:56]}")
    kon = [r for r in rows if r["kelas"] == "KONDISIONAL"]
    if kon:
        print(f"\n[i] {len(kon)} CVE KONDISIONAL - butuh angka Update PASTI "
              "buat menentukan. Itulah gunanya `plesk -v`.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="cocokkan versi Plesk vs advisory resmi (lokal, tanpa eksploitasi)")
    ap.add_argument("--version", default="",
                    help="versi dari `plesk -v`, contoh 18.0.80 atau 18.0.80.9")
    ap.add_argument("--build", default="",
                    help="opsional, hanya utk info tanggal build (BUKAN versi)")
    ap.add_argument("--db", required=True)
    ap.add_argument("--sweep", default="",
                    help="analisis ketidakpastian rentang Update, mis. 0-9. "
                         "Butuh --version 3 field (18.0.80). Tiap CVE diklasifikasi: "
                         "PASTI_TERDAMPAK / PASTI_TERPATCH / KONDISIONAL / DATA_KURANG")
    ap.add_argument("--format", choices=["tabel", "json"], default="tabel")
    ap.add_argument("--out", default="")
    a = ap.parse_args()

    if not a.version:
        if a.build:
            sys.exit("[STOP] --build saja TIDAK cukup: nomor update tidak ada di "
                     "dalam build number.\n       Ambil versi lengkap:  plesk -v")
        sys.exit("[STOP] butuh --version (dari `plesk -v`)")

    info_build = parse_build(a.build) if a.build else {}
    target = pad(parse_versi(a.version))
    db = muat_db(a.db)

    if a.sweep:
        v3 = parse_versi(a.version)
        if len(v3) != 3:
            sys.exit("[STOP] --sweep butuh --version 3 field, mis. 18.0.80 "
                     "(rentang Update-nya yang di-sweep)")
        return jalankan_sweep(v3, parse_sweep(a.sweep), db, a.format, a.out)

    rows = []
    for adv in db["advisories"]:
        st = banding(target, str(adv.get("fixed_in", "") or ""))
        rows.append({"cve": adv.get("cve", "?"), "severity": adv.get("severity", "?"),
                     "judul": adv.get("judul", ""), "fixed_in": adv.get("fixed_in", ""),
                     "dasar": adv.get("dasar", "tercatat"), "status": st,
                     "url": adv.get("url", "")})
    urut = {"MUNGKIN_VULN": 0, "TANPA_FIXED": 1, "PATCHED": 2}
    rows.sort(key=lambda r: (urut[r["status"]], r["cve"]))

    rekap, konflik = {}, 0
    for r in rows:
        rekap[r["status"]] = rekap.get(r["status"], 0) + 1
        if r["dasar"] == "konflik":
            konflik += 1

    if a.format == "json":
        keluar = json.dumps({"target": {"versi": a.version, "build": info_build},
                             "db": {"sumber": db.get("sumber", ""),
                                    "diambil": db.get("diambil", ""),
                                    "jumlah": len(rows)},
                             "rekap": rekap, "advisories": rows},
                            indent=2, ensure_ascii=False)
        if a.out:
            pathlib.Path(a.out).write_text(keluar, encoding="utf-8")
            print(f"[OK] {a.out}")
        else:
            print(keluar)
        return 0

    print(f"[*] target : Plesk {a.version}")
    if info_build:
        print(f"    build  : {a.build} -> mm={info_build['major_minor']} "
              f"tanggal={info_build['tanggal']} rev={info_build['rev']}")
    print(f"[*] db     : {db.get('sumber','(tanpa sumber)')} "
          f"ambil={db.get('diambil','?')} · {len(rows)} advisory\n")
    print(f"[ringkasan] MUNGKIN_VULN={rekap.get('MUNGKIN_VULN',0)}  "
          f"TANPA_FIXED={rekap.get('TANPA_FIXED',0)}  "
          f"PATCHED={rekap.get('PATCHED',0)}  konflik={konflik}\n")
    if not rows:
        print("[i] db kosong")
        return 0

    tampil = [r for r in rows if r["status"] != "PATCHED"]
    if not tampil:
        print(f"[OK] tak ada advisory yang belum patch di versi ini "
              f"({rekap.get('PATCHED',0)} sudah PATCHED)")
    else:
        print(f"{'STATUS':<14} {'CVE':<16} {'SEV':<9} {'FIXED':<11} "
              f"{'DASAR':<10} JUDUL")
        print("-" * 108)
        for r in tampil:
            print(f"{r['status']:<14} {r['cve']:<16} {str(r['severity']):<9} "
                  f"{str(r['fixed_in'] or '-'):<11} {r['dasar']:<10} "
                  f"{r['judul'][:36]}")

    print(f"\n[i] {rekap.get('PATCHED',0)} advisory sudah PATCHED "
          f"(lihat --format json untuk daftar lengkap)")
    if rekap.get("TANPA_FIXED", 0):
        print("[!] TANPA_FIXED = sumber tidak menyebut versi patch -> status "
              "tidak bisa disimpulkan")
    if konflik:
        print(f"[!] {konflik} advisory berlabel `dasar: konflik` (sumber beda "
              "keterangan) - jangan masuk laporan sebelum diverifikasi")
    print("[!] MUNGKIN_VULN = versi target < versi patch tercatat. INDIKASI, "
          "bukan bukti -")
    print("    cocokkan dengan changelog resmi sebelum dilaporkan.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
