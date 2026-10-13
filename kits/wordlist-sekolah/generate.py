#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""generate.py — generator wordlist password sekolah Indonesia (WP / cPanel / FTP).

Pola umum password admin sekolah Indonesia yang dituju:
    <sekolah><tahun> · <sekolah>@<tahun> · <nama.guru><tahun> · <nisn> · <nama><123>
Generator ini menurunkan varian nama sekolah (morphology lokal: "SMAN 3 Malang"
→ smantiga / sman3malang / sma_n_3_malang / ...), lalu dimutasi (leet, kapital,
pemisah, tempel tahun).

    python3 generate.py --sekolah "SMAN 3 Malang" --names-file names.txt \\
        --tahun 2026,2025,1945 --profile wp --out wordlist.txt
    python3 generate.py --sekolah "SMPN 13 Malang" --profile all --min-len 6

ATURAN: hanya untuk target yang ada izin tertulisnya. Pace & anti-lockout tetap
berlaku di sisi tool pemakai (hydra/wpffuf).
"""
from __future__ import annotations

import argparse
import itertools
import pathlib
import re
import sys

# ───────────────────────── morphology Indonesia ─────────────────────────
TERBILANG = {
    0: "nol", 1: "satu", 2: "dua", 3: "tiga", 4: "empat", 5: "lima",
    6: "enam", 7: "tujuh", 8: "delapan", 9: "sembilan", 10: "sepuluh",
    11: "sebelas", 12: "dua belas", 13: "tiga belas", 14: "empat belas",
    15: "lima belas", 16: "enam belas", 17: "tujuh belas",
    18: "delapan belas", 19: "sembilan belas", 20: "dua puluh",
}
ROMAN = {1: "i", 2: "ii", 3: "iii", 4: "iv", 5: "v", 6: "vi", 7: "vii",
         8: "viii", 9: "ix", 10: "x", 11: "xi", 12: "xii", 13: "xiii",
         14: "xiv", 15: "xv", 16: "xvi", 17: "xvii", 18: "xviii",
         19: "xix", 20: "xx"}

# jenjang + singkatan yang lazim dibaca orang sebagai "nama sekolah"
JENJANG = {
    "sma": ["sma", "sman", "smanegeri", "smknegeri"],
    "smk": ["smk", "smkn", "smknegeri"],
    "smp": ["smp", "smpn", "smpnegeri"],
    "sd": ["sd", "sdn", "sdnegeri"],
    "mts": ["mts", "mtsn"],
    "ma": ["ma", "man"],
}

# kata generik yang sering jadi bagian password admin sekolah
KATA_UMUM = [
    "admin", "administrator", "password", "passw0rd", "sandi", "kunci",
    "operator", "tu", "tatausaha", "kepsek", "kepala", "guru", "staff",
    "sekolah", "akademik", "siswa", "kelas", "belajar", "mengajar",
    "indonesia", "merdeka", "rahasia", "sayang", "cinta", "juara",
    "gampang", "mudah", "123456", "12345678", "qwerty", "qwertyuiop",
    "letmein", "welcome", "test", "guest", "root", "toor",
]

LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
SEPARATORS = ["", "_", "-", ".", "@"]


def terbilang(n: int) -> str:
    if n in TERBILANG:
        return TERBILANG[n]
    if n < 100:
        belasan, puluhan = divmod(n, 10)
        if puluhan == 0:
            return f"{TERBILANG[belasan]} puluh"
        return f"{TERBILANG[belasan]} puluh {TERBILANG[puluhan]}"
    return str(n)


def angka_varian(n: int) -> list[str]:
    """Semua wujud '3' yang mungkin ditulis orang: 3, tiga, iii."""
    out = {str(n), terbilang(n).replace(" ", "")}
    if n in ROMAN:
        out.add(ROMAN[n])
    return sorted(out)


def token_sekolah(teks: str) -> tuple[list[str], list[str]]:
    """Pisah jadi (token_jenjang, token_sisa). 'SMAN 3 Malang' → (['sman'], ['3','malang'])."""
    t = re.sub(r"[^a-zA-Z0-9 ]+", " ", teks.lower())
    kata = [w for w in t.split() if w]
    jenjang: list[str] = []
    while kata and kata[0] in {j for v in JENJANG.values() for j in v}:
        jenjang.append(kata.pop(0))
    # 'sma n 3' → jenjang 'sma' + 'n' jadi bagian jenjang
    while kata and kata[0] == "n" and jenjang:
        kata.pop(0)
        jenjang[0] += "n"
    return jenjang, kata


def varian_sekolah(teks: str) -> list[str]:
    """Turunkan seluruh kemungkinan 'nama sekolah' yang diketik orang."""
    jenjang, sisa = token_sekolah(teks)
    if not jenjang:
        jenjang = ["sekolah"]
    j = jenjang[0]                      # sman / smkn / smpn ...
    jenjang_penuh = JENJANG.get(j[:3], [j])[0] if j[:3] in JENJANG else j
    angka = [x for x in sisa if x.isdigit()]
    kota = [x for x in sisa if not x.isdigit()]
    n = int(angka[0]) if angka else 0
    hasil: set[str] = set()

    for a in (angka_varian(n) if n else [""]):
        for base in (j, jenjang_penuh, j.rstrip("n") or j, j.replace("n", " negeri ")):
            b = base.strip()
            hasil.add(f"{b}{a}")
            hasil.add(f"{b} {a}".strip())
            if kota:
                k = "".join(kota)
                hasil.add(f"{b}{a}{k}")
                hasil.add(f"{b} {a} {k}".strip())
                hasil.add(f"{b}_{a}_{k}".strip("_"))
                hasil.add(f"{k}{a}")
                hasil.add(f"{k} {a}".strip())
    # pola khas: "smantiga" (sma+n+tiga tanpa pemisah)
    if n:
        hasil.add(f"{j.rstrip('n')}{terbilang(n).replace(' ', '')}")
        hasil.add(f"{j}{terbilang(n).replace(' ', '')}")
        if kota:
            hasil.add(f"{j.rstrip('n')}{terbilang(n).replace(' ', '')}{''.join(kota)}")
    hasil.update(kota)
    hasil.update("".join(kota))
    hasil.discard("")
    hasil.discard("sekolah")
    return sorted(hasil, key=len)


def mutasi(kata: str, tahun: list[str], deep: bool) -> set[str]:
    """Bentuk dasar → ratusan varian password yang lazim."""
    keluar: set[str] = set()
    dasar = {kata, kata.lower(), kata.upper(), kata.capitalize()}
    for d in list(dasar):
        keluar.add(d)
        for sep in SEPARATORS:
            for y in tahun:
                keluar.add(f"{d}{sep}{y}")
                keluar.add(f"{y}{sep}{d}")
        if deep:  # leet + tahun kombinasi
            leet = "".join(LEET.get(c, c) for c in d.lower())
            keluar.update({leet, leet.upper(), leet.capitalize()})
            for y in tahun:
                keluar.add(f"{leet}{y}")
                keluar.add(f"{leet}@{y}")
        # angka ekor umum
        keluar.update({f"{d}123", f"{d}1234", f"{d}12345", f"{d}!",
                       f"{d}2024", f"{d}2025", f"{d}2026"})
    return keluar


def nama_guru_varian(nama: str, tahun: list[str], deep: bool) -> set[str]:
    """'Budi Santoso' → budi, santoso, budisantoso, b.santoso, bsantoso, ..."""
    bersih = re.sub(r"[^a-zA-Z ]", " ", nama).lower().split()
    if not bersih:
        return set()
    depan, belakang = bersih[0], bersih[-1]
    tengah = bersih[1:-1]
    kandidat = {depan, belakang, f"{depan}{belakang}", f"{depan}.{belakang}",
                f"{depan[0]}{belakang}", f"{depan}_{belakang}"}
    if tengah:
        kandidat.add(f"{depan}{tengah[0]}{belakang}")
    keluar: set[str] = set()
    for k in kandidat:
        keluar |= mutasi(k, tahun, deep)
    return keluar


def build(args) -> set[str]:
    tahun = [t.strip() for t in args.tahun.split(",") if t.strip()]
    keluar: set[str] = set()

    if args.sekolah:
        for v in varian_sekolah(args.sekolah):
            keluar |= mutasi(v, tahun, args.deep)

    if args.names_file:
        p = pathlib.Path(args.names_file)
        if not p.exists():
            sys.exit(f"[STOP] file nama tidak ada: {args.names_file}")
        for line in p.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            nama = line.split("|")[0].strip()     # format opsional: Nama|peran
            keluar |= nama_guru_varian(nama, tahun, args.deep)

    if args.extras:
        for e in args.extras.split(","):
            e = e.strip()
            if e:
                keluar |= mutasi(e, tahun, args.deep)

    if args.profile in ("wp", "all"):
        for w in KATA_UMUM:
            keluar |= mutasi(w, tahun, False)

    if args.profile in ("cpanel", "ftp", "all"):
        # pola hosting murah: user=ftp/cpanel/nama-domain, pass sama / sama+123
        dom = (args.domain or "").replace("www.", "").split(".")[0] if args.domain else ""
        basis = ["ftp", "cpanel", "webmail", "admin"]
        if dom:
            basis += [dom, f"{dom}ftp", f"{dom}2026"]
        for b in basis:
            keluar |= mutasi(b, tahun, False)

    if args.min_len:
        keluar = {x for x in keluar if len(x) >= args.min_len}
    if args.max_len:
        keluar = {x for x in keluar if len(x) <= args.max_len}
    return keluar


def main() -> int:
    ap = argparse.ArgumentParser(description="wordlist password sekolah Indonesia")
    ap.add_argument("--sekolah", help='mis. "SMAN 3 Malang"')
    ap.add_argument("--names-file", help="satu nama per baris, format opsional: Nama|peran")
    ap.add_argument("--tahun", default="2026,2025,2024,1945,1973,2020",
                    help="tahun dipisah koma")
    ap.add_argument("--extras", help="kata tambahan/NIS/NIP dipisah koma")
    ap.add_argument("--domain", help="domain target utk pola cpanel/ftp")
    ap.add_argument("--profile", choices=["wp", "cpanel", "ftp", "all"], default="wp")
    ap.add_argument("--deep", action="store_true",
                    help="tambah mutasi leet (ukuran naik ~5x)")
    ap.add_argument("--min-len", type=int, default=4)
    ap.add_argument("--max-len", type=int, default=0, help="0 = tanpa batas")
    ap.add_argument("--out", default="wordlist.txt")
    a = ap.parse_args()
    if not (a.sekolah or a.names_file or a.extras):
        ap.error("butuh --sekolah / --names-file / --extras")

    hasil = build(a)
    urut = sorted(hasil, key=lambda x: (len(x), x))
    pathlib.Path(a.out).write_text("\n".join(urut) + "\n")
    print(f"[✓] {len(urut):,} kata → {a.out}")
    print(f"    varian sekolah : {len(varian_sekolah(a.sekolah)) if a.sekolah else 0}")
    print(f"    tahun          : {a.tahun}")
    print(f"    deep (leet)    : {'ya' if a.deep else 'tidak'}")
    print(f"    panjang         : {len(urut[0]) if urut else 0}–{len(urut[-1]) if urut else 0}")
    print("    contoh:", " ".join(urut[:8]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
