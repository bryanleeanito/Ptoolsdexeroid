#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tests.py - uji E2E decode.py. Semua SOAL tiruan dibangkitkan di memori,
tidak ada file yang perlu disiapkan manual, tanpa jaringan.

    python3 tests.py          # semua tes
    python3 tests.py -v       # tampilkan keluaran tiap tes

Keluaran: N tes, PASS/FAIL per baris, exit code 0 hanya kalau semua lulus.
"""
from __future__ import annotations

import base64
import codecs
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
DECODE = os.path.join(HERE, "decode.py")
VERBOSE = "-v" in sys.argv[1:]

# ---------------------------------------------------------------- muat decode
_spec = importlib.util.spec_from_file_location("decode_mod", DECODE)
D = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(D)

FLAG = "flag{d3c0d3_th3_l4y3rs}"


def caesar(s: str, k: int) -> str:
    a = "abcdefghijklmnopqrstuvwxyz"
    A = a.upper()
    return s.translate(str.maketrans(a + A, a[k:] + a[:k] + A[k:] + A[:k]))


def soal() -> dict[str, str]:
    """Semua fixture soal. Kunci = id, nilai = input untuk decode.py."""
    INV = {v: k for k, v in D.MORSE.items()}
    x = base64.b64encode(codecs.encode(FLAG, "rot_13").encode()).decode()
    return {
        "b64-1lapis": base64.b64encode(FLAG.encode()).decode(),
        "rantai-4lapis": base64.b64encode(x.encode().hex().encode()).decode(),
        "caesar-3": caesar(FLAG, 3),
        "hex": FLAG.encode().hex(),
        "double-url": urllib.parse.quote(urllib.parse.quote(FLAG, safe=""),
                                         safe=""),
        "morse": " ".join(INV[c] for c in FLAG.upper()),
        "binary": "".join(f"{ord(c):08b}" for c in FLAG),
        "reverse": FLAG[::-1],
        "rot13": codecs.encode(FLAG, "rot_13"),
        "base64-url-base64": base64.b64encode(
            urllib.parse.quote(
                base64.b64encode(FLAG.encode()).decode(), safe="").encode()
        ).decode(),
        "url-2lapis-hex": base64.b64encode(
            FLAG.encode().hex().encode()).decode(),
    }


# --------------------------------------------------------------------- runner
_hasil: list[tuple[str, bool, str]] = []


def jalankan(nama: str, fungsi) -> None:
    try:
        pesan = fungsi()
        ok = True
        if pesan is False:
            ok, pesan = False, "mengembalikan False"
    except Exception as e:                      # noqa: BLE001
        ok, pesan = False, f"{type(e).__name__}: {e}"
    _hasil.append((nama, ok, str(pesan) if pesan is not True else ""))
    if VERBOSE or not ok:
        tanda = "PASS" if ok else "FAIL"
        print(f"  [{tanda}] {nama}" + (f"  <- {pesan}" if not ok else ""))


def jalankan_decode(arg: list[str], teks: str | None = None,
                    stdin: str | None = None) -> str:
    """Panggil decode.py, kembalikan stdout+stderr gabungan."""
    cmd = [sys.executable, DECODE] + arg
    if teks is not None:
        cmd.append(teks)
    p = subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                       timeout=30, cwd=tempfile.gettempdir())
    return p.stdout + p.stderr


def ada_flag(out: str) -> bool:
    return "[FLAG] flag{" in out or "[FLAG] FLAG{" in out.upper()


# ================================================================ TEST BODY
S = soal()


def t_rantai_otomatis():
    """Semua soal berlapis harus sampai ke flag{ asli tanpa argumen apa pun."""
    for kunci, nilai in S.items():
        out = jalankan_decode(["--in", _simpan(kunci, nilai)])
        if not ada_flag(out):
            return f"{kunci} tak sampai flag -> {out[-200:]}"
    return True


def _simpan(nama: str, isi: str) -> str:
    d = os.path.join(tempfile.gettempdir(), "ctfkit_test")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, nama + ".txt")
    with open(p, "w", encoding="utf-8") as f:
        f.write(isi)
    return p


def t_rot13_bukan_saudara_kandung():
    """Syarat: berhenti di flag{ KETAT, bukan synt{...} (rot13) sebelumnya."""
    out = jalankan_decode(["--in", _simpan("r13", codecs.encode(FLAG, "rot_13"))])
    if "synt{" in out:
        return f"berhenti di rot13: {out[-160:]}"
    return ada_flag(out) or "flag{d3c0d3" in out


def t_caesar_brute():
    out = jalankan_decode(["--caesar", caesar(FLAG, 3)])
    if "FLAG KETEMU" not in out:
        return "tak menandai geser yang benar"
    if "flag{d3c0d3" not in out:
        return "tak menampilkan plaintext"
    return True


def t_caesar_tidak_bohong():
    """geser 0 (input apa adanya) JANGAN ditandai FLAG KETEMU."""
    out = jalankan_decode(["--caesar", caesar(FLAG, 3)])
    for baris in out.splitlines():
        if "geser  0" in baris and "FLAG KETEMU" in baris:
            return f"geser 0 keliru ditandai: {baris}"
    return True


def t_xor_tembus_ke_flag():
    """XOR 0x42 atas base64(flag) -> hex. Harus tetap sampai flag."""
    enc = bytes(b ^ 0x42 for b in base64.b64encode(FLAG.encode()))
    out = jalankan_decode(["--xor", enc.hex()])
    if not ada_flag(out):
        return f"key benar tak terpilih: {out[-220:]}"
    return True


def t_vigenere_dekripsi():
    enc = D.vigenere(FLAG, "ctf", geser=1)          # enkripsi = arah +1
    out = jalankan_decode(["--vigenere", "ctf", enc])
    if "flag{d3c0d3" not in out:
        return f"tak membalik plaintext: {out[-200:]}"
    return True


def t_vigenere_arah():
    """Pastikan arah benar-benar dekripsi, bukan enkripsi ulang."""
    if D.vigenere(D.vigenere(FLAG, "ctf", geser=1), "ctf") != FLAG:
        return "dekripsi(enkripsi(x)) != x -> arah salah"
    return True


def t_teks_polos_tak_diputar():
    """Teks biasa harus STOP, jangan diacak jadi sampah."""
    out = jalankan_decode(["--in", _simpan("polos",
                                           "ini teks biasa sudah terbaca sekali")])
    if "lapis terbongkar" in out:
        return f"masih memutar teks terbaca: {out[-200:]}"
    return True


_ALFABET_SAMPAH = "QqWwEeRrTtYyZz1234567890+/="
SAMPAH = "".join(_ALFABET_SAMPAH[i % len(_ALFABET_SAMPAH)]
                 for i in range(60))


def t_sampah_tidak_hasilkan_flag():
    """Input acak TIDAK boleh menghasilkan flag palsu."""
    out = jalankan_decode(["--in", _simpan("acak", SAMPAH)])
    if "[FLAG]" in out:
        return f"FALSE POSITIVE flag: {out[-200:]}"
    return True


def t_sampah_diberi_peringatan():
    out = jalankan_decode(["--in", _simpan("acak2", SAMPAH)])
    if "lapis terbongkar" in out and "TIDAK menghasilkan teks bermakna" not in out:
        return "merakit rantai tapi tak memberi peringatan sampah"
    return True


def t_morse_pemisah_huruf():
    """1 spasi = pemisah huruf -> hasilnya harus 'FLAG{...}' tanpa spasi."""
    INV = {v: k for k, v in D.MORSE.items()}
    out = jalankan_decode(["--in", _simpan("morse", " ".join(INV[c]
                                                             for c in FLAG.upper()))])
    if "F L A G" in out:
        return "huruf terpisah spasi - pemisah kata salah"
    return ada_flag(out)


def t_max_layer_dibatasi():
    """--max-layer harus membatasi kedalaman, bukan loop terbuka."""
    x = base64.b64encode(codecs.encode(FLAG, "rot_13").encode()).decode()
    isi = base64.b64encode(x.encode().hex().encode()).decode()
    out = jalankan_decode(["--in", _simpan("dalam", isi), "--max-layer", "1"])
    if "lapis 2" in out:
        return "max-layer 1 diabaikan"
    return True


def t_tolak_max_layer_ngawur():
    out = jalankan_decode(["--in", _simpan("x", "abc"), "--max-layer", "999"])
    if "--max-layer harus 1..64" not in out:
        return f"tak menolak nilai di luar 1..64: {out[-160:]}"
    return True


def t_tolak_tanpa_input():
    out = jalankan_decode([])
    if "butuh argumen teks" not in out:
        return f"tak menolak input kosong: {out[-160:]}"
    return True


def t_file_hilang():
    out = jalankan_decode(["--in", "/tmp/tidak_ada_ctfkit_zzz.txt"])
    if "gagal baca" not in out:
        return f"tak menangani file hilang: {out[-160:]}"
    return True


def t_out_file():
    p = os.path.join(tempfile.gettempdir(), "ctfkit_keluaran.txt")
    if os.path.exists(p):
        os.remove(p)
    jalankan_decode(["--in", _simpan("o", S["b64-1lapis"]), "--out", p])
    isi = open(p, encoding="utf-8").read() if os.path.exists(p) else ""
    if FLAG not in isi:
        return f"--out tak menulis hasil: {isi!r}"
    return True


def t_tidak_kerasukan_flag_palsu():
    """Bentuk {x} biasa (prefix tak dikenal) tak boleh diklaim FLAG KETEMU."""
    out = jalankan_decode(["--caesar", "abc{defghij_klmnop}"])
    if "FLAG KETEMU" in out:
        return f"klaim FLAG untuk format tak dikenal: {out[-160:]}"
    return True


def t_stdlib_saja():
    """Kit harus jalan tanpa dependensi apa pun."""
    src = open(DECODE, encoding="utf-8").read()
    for p in ("import requests", "import numpy", "from Crypto", "import bs4"):
        if p in src:
            return f"dependensi asing: {p}"
    return True


# ==================================================================== JALANKAN
JUMLAH = [
    ("rantai otomatis: 11 soal", t_rantai_otomatis),
    ("berhenti di flag{ ketat, bukan synt{ (rot13)", t_rot13_bukan_saudara_kandung),
    ("--caesar brute sampai plaintext", t_caesar_brute),
    ("--caesar geser 0 tak diklaim FLAG", t_caesar_tidak_bohong),
    ("--xor key benar tetap menang walau hasilnya base64", t_xor_tembus_ke_flag),
    ("--vigenere dekripsi benar arah", t_vigenere_arah),
    ("--vigenere mengembalikan plaintext", t_vigenere_dekripsi),
    ("teks polos STOP, tak diputar", t_teks_polos_tak_diputar),
    ("sampah tak menghasilkan flag palsu", t_sampah_tidak_hasilkan_flag),
    ("sampah diberi peringatan", t_sampah_diberi_peringatan),
    ("morse: pemisah huruf vs kata benar", t_morse_pemisah_huruf),
    ("--max-layer membatasi kedalaman", t_max_layer_dibatasi),
    ("tolak --max-layer di luar 1..64", t_tolak_max_layer_ngawur),
    ("tolak tanpa input", t_tolak_tanpa_input),
    ("file hilang ditangani (bukan traceback)", t_file_hilang),
    ("--out menulis hasil akhir", t_out_file),
    ("format {x} asing tak diklaim FLAG", t_tidak_kerasukan_flag_palsu),
    ("stdlib saja, nol dependensi", t_stdlib_saja),
]


def main() -> int:
    print(f"[*] decode.py - {len(JUMLAH)} tes\n")
    for nama, fn in JUMLAH:
        jalankan(nama, fn)
    lolos = sum(1 for _, ok, _ in _hasil if ok)
    gagal = len(_hasil) - lolos
    print(f"\n{'='*60}")
    print(f"  HASIL: {lolos}/{len(_hasil)} PASS"
          + (f", {gagal} GAGAL" if gagal else " - semua lulus"))
    if gagal:
        print("  gagal:")
        for nama, ok, pesan in _hasil:
            if not ok:
                print(f"    - {nama}: {pesan}")
    print("=" * 60)
    return 1 if gagal else 0


if __name__ == "__main__":
    sys.exit(main())
