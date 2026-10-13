#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""crack_helper.py — deteksi jenis hash → susun perintah hashcat yang benar.

Bagian akhir rantai gapps-kit:
    probe → gviz_fetch (dump Sheet, kadang kolomnya hash) → crack_helper → hashcat

Kenapa perlu: menebak `-m` salah = hashcat diam atau bilang "token unrecognized"
padahal udah jalan 2 jam. Tool ini nebak dari struktur hash + prefix khas.

    python3 crack_helper.py --file hashes.txt --wordlist wl.txt --rules dive.rule
    python3 crack_helper.py --hash '$P$B...' --wordlist wl.txt
    python3 crack_helper.py --file hashes.txt --plan          # cuma deteksi + rencana

ATURAN: hashcat/wordlist jalan di BlackArch. Di sini cuma nyusun rencana.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

# ── deteksi ──
# Tier 1: punya prefix khas → PASTI (keyakinan 3)
PREFIX = [
    (3200, "bcrypt",           r"^\$2[abxy]?\$\d\d\$[./A-Za-z0-9]{53}$"),
    (1800, "sha512crypt $6$",  r"^\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$"),
    (7400, "sha256crypt $5$",  r"^\$5\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$"),
    (500,  "md5crypt $1$",     r"^\$1\$(rounds=\d+\$)?[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"),
    (400,  "phpass $P$/$H$ (WordPress)", r"^\$[PH]\$[./0-9A-Za-z]{31,35}$"),
]
# Tier 2: hex polos — panjangnya unik utk algoritma, TAPI 32 hex bisa banyaked
ALT_32 = [(0, "MD5 (raw)"), (1000, "NTLM"), (900, "MD4"), (3000, "LM")]


def deteksi(h: str) -> list[tuple[int, str, int]]:
    """Kembalikan [(kode, nama, keyakinan)] — 3=pasti, 2=kemungkinan besar, 1=tebakan."""
    h = h.strip()
    if not h:
        return []
    for kode, nama, pola in PREFIX:
        if re.match(pola, h):
            return [(kode, nama, 3)]
    if re.fullmatch(r"[a-fA-F0-9]{32}", h):
        # di konteks web/sekolah, MD5 jauh lebih mungkin dari NTLM
        return [(0, "MD5 (raw)", 2)] + [(k, n, 1) for k, n in ALT_32[1:]]
    if re.fullmatch(r"[a-fA-F0-9]{40}", h):
        return [(100, "SHA1 (raw)", 2)]
    if re.fullmatch(r"[a-fA-F0-9]{64}", h):
        return [(1400, "SHA256 (raw)", 2)]
    if re.fullmatch(r"[a-fA-F0-9]{128}", h):
        return [(1700, "SHA512 (raw)", 2)]
    if ":" in h:                       # hash:salt → mode turunan, perlu kolom salt
        return [(10, "md5($salt.$pass) [butuh salt]", 1)]
    return [(-1, "TIDAK DIKENALI", 0)]


def rencana(kode: int, nama: str, wordlist: str, rules: str, mask: str) -> list[str]:
    """Susun urutan serangan yang masuk akal utk jenis hash itu."""
    if kode < 0:
        return []
    dasar = f"hashcat -m {kode} hashes.txt {wordlist}"
    out = []
    if rules:
        out.append(f"# fase 1 — wordlist + rule (paling cepat)\n{dasar} -r {rules} --potfile-path hc.pot")
        out.append(f"# fase 2 — rule lebih agresif\n{dasar} -r /usr/share/hashcat/rules/best64.rule")
    else:
        out.append(f"# fase 1 — wordlist polos\n{dasar} --potfile-path hc.pot")
    if mask:
        out.append(f"# fase 3 — mask utk NIS/tahun ({mask})\n"
                   f"{dasar} -a 3 '{mask}' -i --increment-min=4")
    # kandidat khusus konteks sekolah
    out.append("# fase 4 — mutasi Indonesia khas (tambah manual ke wordlist):\n"
               "#   <sekolah><tahun>  <nama.guru><tahun>  <tahun>@<sekolah>\n"
               "#   123456  qwerty  admin  sandi  merdeka  sayang")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="deteksi hash → rencana hashcat")
    ap.add_argument("--file", help="file hash per baris")
    ap.add_argument("--hash", help="satu hash")
    ap.add_argument("--wordlist", default="wordlist.txt")
    ap.add_argument("--rules", default="dive.rule",
                    help="file rule utk fase 1 ('' untuk kosong)")
    ap.add_argument("--mask", default="?d?d?d?d?d?d?d?d",
                    help="mask fase 3 (default: 8 digit = NISN)")
    ap.add_argument("--plan", action="store_true", help="cuma deteksi, jangan tulis perintah")
    ap.add_argument("--out", default="crack_plan.sh")
    a = ap.parse_args()

    if a.file:
        p = pathlib.Path(a.file)
        if not p.exists():
            sys.exit(f"[STOP] file tak ada: {a.file}")
        daftar = [x.strip() for x in p.read_text(errors="replace").splitlines()
                  if x.strip() and not x.startswith("#")]
    elif a.hash:
        daftar = [a.hash.strip()]
    else:
        ap.error("butuh --file atau --hash")
    if not daftar:
        sys.exit("[STOP] tak ada hash")

    # ringkas per jenis (simpan keyakinan tertinggi)
    rekap: dict[tuple[int, str], list[str]] = {}
    yakin_map: dict[tuple[int, str], int] = {}
    for h in daftar[:5000]:
        kandidat = deteksi(h)
        if not kandidat:
            continue
        kode, nama, yakin = kandidat[0]                # kandidat teratas
        kunci = (kode, nama)
        rekap.setdefault(kunci, []).append(h)
        yakin_map[kunci] = max(yakin_map.get(kunci, 0), yakin)

    LABEL = {3: "pasti", 2: "tinggi", 1: "tebakan", 0: "?"}
    print(f"[i] {len(daftar)} hash → {len(rekap)} jenis terdeteksi\n")
    print(f"{'kode':<6} {'keyakinan':<10} {'jenis':<34} jumlah")
    print("─" * 70)
    for kunci, isi in sorted(rekap.items(), key=lambda x: -len(x[1])):
        kode, nama = kunci
        print(f"{kode:<6} {LABEL.get(yakin_map.get(kunci, 0), '?'):<10} "
              f"{nama:<34} {len(isi)}")
    if (-1, "TIDAK DIKENALI") in rekap:
        print("\n[!] ada hash tak dikenal — kirim cuplikan saja ke aku (jangan full).")

    if a.plan:
        return 0

    # tulis rencana per jenis
    baris = ["#!/usr/bin/env bash", "# auto-generated crack_plan.sh",
             "# jalankan di BlackArch. Jangan di host lokal.", ""]
    for (kode, nama), isi in sorted(rekap.items(), key=lambda x: -len(x[1])):
        if kode < 0:
            continue
        baris.append(f"# ── {nama} ({kode}) · {len(isi)} hash ──")
        tmp = pathlib.Path(f"hashes_{kode}.txt")
        tmp.write_text("\n".join(isi) + "\n")
        baris += rencana(kode, nama, a.wordlist, a.rules, a.mask)
        baris.append("")
    pathlib.Path(a.out).write_text("\n".join(baris) + "\n")
    print(f"\n[✓] {a.out} + hash_<kode>.txt per jenis")
    return 0


if __name__ == "__main__":
    sys.exit(main())
