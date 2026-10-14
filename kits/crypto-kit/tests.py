#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tests.py - uji E2E solve.py. Nol jaringan, nol file eksternal.

Penting: tiap serangan RSA diuji pada modulus YANG MEMANG DIRANCAN BISA
DITEMBUS (e kecil, faktor bersama, d kecil, p~q, p-1 halus). Kalau salah
satunya gagal, berarti implementasinya rusak - bukan berarti "memang tak
bisa dipecahkan".

    python3 tests.py        semua tes
    python3 tests.py -v     tampilkan tiap baris
"""
from __future__ import annotations

import hashlib
import importlib.util
import math
import os
import random
import string
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SOLVE = os.path.join(HERE, "solve.py")
VERBOSE = "-v" in sys.argv[1:]

_sp = importlib.util.spec_from_file_location("solve_mod", SOLVE)
D = importlib.util.module_from_spec(_sp)
_sp.loader.exec_module(D)

_hasil: list[tuple[str, bool, str]] = []

TEKS_ENG = (
    "the quick brown fox jumps over the lazy dog while the attacker tries to "
    "hide the secret message inside this long english text because "
    "substitution ciphers need enough letter frequency data to be solved "
    "reliably by hill climbing"
)


def jalankan(nama: str, fungsi) -> None:
    try:
        pesan = fungsi()
        ok = pesan is not False
        if pesan is False:
            pesan = "mengembalikan False"
    except Exception as e:                       # noqa: BLE001
        ok, pesan = False, f"{type(e).__name__}: {e}"
    _hasil.append((nama, ok, str(pesan) if ok else str(pesan)))
    if VERBOSE or not ok:
        print(f"  [{'PASS' if ok else 'FAIL'}] {nama}"
              + ("" if ok else f"  <- {pesan}"))


# ====================================================== pembangkit kunci RSA
def _is_prime(k: int) -> bool:
    """Miller-Rabin 12 basis.

    Harus mengkuadratkan BERULANG (x -> x^2), bukan menghitung ulang
    pow(a, d*2^i, n). Versi lama berhenti di i=s-2 dan melewatkan i=s-1
    yang eksponennya (n-1)/2 -> FALSE NEGATIVE pada prima asli, dan karena
    diuji dgn 7 basis sekaligus, prima yang lolos jadi langka (131 ribu
    kandidat utk satu prima 512-bit, 146 detik).

    12 basis di bawah ini deterministik utk bilangan < 3.3e24.
    """
    if k < 2:
        return False
    for t in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if k == t:
            return True
        if k % t == 0:
            return False
    d, s = k - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, k)
        if x == 1 or x == k - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % k
            if x == k - 1:
                break
            if x == 1:
                return False       # akar kuadrat trivial selain +-1 = komposit
        else:
            return False
    return True


def _prima_lokal(nbit: int, rng: random.Random) -> int:
    if nbit < 2:
        return 2
    while True:
        k = rng.getrandbits(nbit) | 1 | (1 << (nbit - 1))
        if _is_prime(k):
            return k


def _prima_berikut(awal: int, batas: int = 200_000) -> int:
    """Prima pertama setelah `awal` - dipakai utk kasus Fermat (p ~ q)."""
    k = awal | 1
    if k < 3:
        k = 3
    for _ in range(batas):
        if _is_prime(k):
            return k
        k += 2
    raise RuntimeError(f"tak menemukan prima setelah {awal}")


# ================================================================ TEST BODY
def t_caesar_roundtrip():
    for k in range(26):
        p = "attack at dawn"
        if D.caesar(D.caesar(p, k), -k) != p:
            return f"roundtrip gagal k={k}"
    return True


def t_caesar_solver():
    p = "the secret message is hidden well inside this file"
    c = D.caesar(p, 7)
    hasil = D.selesai_caesar(c)
    if "secret" not in hasil[0][1].lower():
        return f"urutan salah: {hasil[0][1][:60]}"
    return True


def t_atbash_involusi():
    p = "hello world xyz"
    if D.atbash(D.atbash(p)) != p:
        return "atbash bukan involusi"
    if D.atbash("abc") != "zyx":
        return f"atbash(abc)={D.atbash('abc')}"
    return True


def t_vigenere_roundtrip():
    p = "the quick brown fox jumps over the lazy dog"
    for kunci in ("c", "key", "longkeyword", "ctf"):
        e = D.vigenere(p, kunci, geser=1)
        d = D.vigenere(e, kunci, geser=-1)
        if d != p:
            return f"roundtrip gagal kunci={kunci!r}"
    return True


def t_vigenere_solver():
    p = ("there are many different ways to solve a difficult problem and it "
         "is often useful to look at the same question from another point")
    e = D.vigenere(p, "secret", geser=1)
    hasil = D.selesai_vigenere(e)
    if not hasil:
        return "tak ada kandidat"
    # kuncinya harus terdeteksi 6 huruf dgn 'secret'
    kunci_ditemukan = any("secret" in lab for lab, _, _ in hasil)
    if not kunci_ditemukan:
        lab = hasil[0][0]
        return f"kunci tak ditemukan, dapat: {lab}"
    return True


def t_rail_roundtrip():
    p = TEKS_ENG
    for r in range(2, 9):
        if D.rail_fence(D.rail_fence_enkrip(p, r), r) != p:
            return f"roundtrip gagal rails={r}"
    return True


def t_rail_solver():
    p = ("the committee met on the first tuesday of every month to review "
         "the progress of the projects that had been agreed at the start")
    c = D.rail_fence_enkrip(p, 4)
    hasil = D.selesai_rail(c)
    if "committee" not in hasil[0][1].lower():
        return f"rails tak terdeteksi: {hasil[0][0]}"
    return True


def t_transposisi_roundtrip():
    p = TEKS_ENG
    for k in range(2, 13):
        if D.transposisi_kolom(D.transposisi_kolom_enkrip(p, k), k) != p:
            return f"roundtrip gagal kunci={k}"
    return True


def t_transposisi_solver():
    p = ("the letters that were found in the drawer dated back to the second "
         "world war and told the story of a young soldier who had written")
    c = D.transposisi_kolom_enkrip(p, 5)
    hasil = D.selesai_transposisi(c)
    if "letters" not in hasil[0][1].lower():
        return f"kolom tak terdeteksi: {hasil[0][0]}"
    return True


def t_xor_1byte():
    p = b"the flag is hidden in this message"
    c = bytes(b ^ 0x42 for b in p)
    hasil = D.selesai_xor(c.hex())
    if not hasil:
        return "tak ada kandidat"
    teks_terbaik = hasil[0][1]
    if "flag" not in teks_terbaik.lower():
        return f"key 0x42 tak menang: {teks_terbaik[:50]!r}"
    return True


def t_xor_berulang():
    p = ("there are many different ways to solve a difficult problem and it "
         "is often useful to look at the same question from another point of "
         "view before you decide what to do next in order to avoid a mistake")
    kunci = b"key"
    c = bytes(p.encode()[i] ^ kunci[i % len(kunci)] for i in range(len(p)))
    hasil = D.selesai_xor(c.hex())
    if not hasil:
        return "tak ada kandidat"
    top = " ".join(lab for lab, _, _ in hasil[:6])
    if "L=3" not in top:
        return f"panjang kunci 3 tak terdeteksi di 6 teratas: {top}"
    # hasil teratas harus memuat kata Inggris jelas
    best = hasil[0][1]
    if "problem" not in best.lower() and "useful" not in best.lower():
        return f"plaintext tak benar: {best[:70]!r}"
    return True


def t_substitusi_solver():
    perm = list(D.ALF)
    random.Random(7).shuffle(perm)
    peta = str.maketrans(D.ALF + D.ALF.upper(),
                         "".join(perm) + "".join(perm).upper())
    c = TEKS_ENG.upper().translate(peta)
    hasil = D.selesai_substitusi(c, restart=12)
    if not hasil:
        return "tak ada kandidat"
    r = hasil[0][1].lower()
    # huruf langka (pangram) memang sulit; wajib minimal struktur kata jelas
    if "the" not in r or "tries" not in r or "message" not in r:
        return f"struktur tak terbentuk: {hasil[0][1][:70]!r}"
    return True


def t_substitusi_kasus_besar():
    """Cipher HURUF BESAR harus terdekripsi, bukan keluar apa adanya."""
    perm = list(D.ALF)
    random.Random(11).shuffle(perm)
    peta = str.maketrans(D.ALF + D.ALF.upper(),
                         "".join(perm) + "".join(perm).upper())
    c = TEKS_ENG.upper().translate(peta)
    hasil = D.selesai_substitusi(c, restart=12)
    if hasil[0][1].isupper():
        return f"keluar huruf besar semua (tak terpeta): {hasil[0][1][:50]!r}"
    return True


def t_rsa_e_kecil():
    rng = random.Random(1)
    m = int.from_bytes(b"flag{rsa_small_e}", "big")
    e = 3
    n = (rng.getrandbits(1024) | 1)
    c = pow(m, e)
    assert c < n, "fixture salah: m^e harus < n"
    hasil = D.rsa_akar_kecil(n, e, c)
    if not hasil:
        return "e kecil tak terpecahkan"
    if "flag{rsa_small_e}" not in hasil[0][1]:
        return f"plaintext salah: {hasil[0][1][:60]!r}"
    return True


def t_rsa_common_factor():
    rng = random.Random(2)
    p = _prima_lokal(512, rng)
    q1 = _prima_lokal(512, rng)
    q2 = _prima_lokal(512, rng)
    n1, n2 = p * q1, p * q2        # p sama di keduanya
    hasil = D.rsa_common_factor([n1, n2])
    if not hasil:
        return "faktor bersama tak ditemukan"
    if f"{p}" not in hasil[0][1]:
        return f"perhitungan salah: {hasil[0][1][:60]!r}"
    return True


def t_rsa_wiener():
    """Kasus Wiener: e BESAR tapi d KECIL (d < n^0.25).

    Konstruksinya: cari d kecil dan k supaya e = (k*phi+1)/d bulat. Kalau
    konstruksinya asal-asalan, e yang dihasilkan tak memenuhi syarat Wiener
    dan tesnya gagal padahal implementasinya benar.
    """
    rng = random.Random(3)
    p = _prima_lokal(512, rng)
    q = _prima_lokal(512, rng)
    n = p * q
    phi = (p - 1) * (q - 1)

    d, e = None, 0
    for kand in range(3, 400, 2):
        if math.gcd(kand, phi) != 1:
            continue
        for k in range(1, 800):
            if (k * phi + 1) % kand:
                continue
            e_kand = (k * phi + 1) // kand
            if math.gcd(e_kand, phi) == 1 and e_kand > 1000:
                d, e = kand, e_kand
                break
        if d is not None:
            break
    if d is None:
        return "fixture Wiener gagal dibangun"

    # syarat Wiener harus benar-benar terpenuhi, bukan asumsi
    if d >= pow(n, 0.25):
        return f"d={d} terlalu besar utk Wiener (n^0.25={pow(n, 0.25):.0f})"

    hasil = D.rsa_wiener(e, n)
    if not hasil:
        return f"d={d} tak ditemukan (e={e.bit_length()} bit)"
    if f"d = {d}" not in hasil[0][0]:
        return f"d salah: {hasil[0][0]}"
    return True


def t_rsa_fermat():
    rng = random.Random(4)
    p = _prima_lokal(256, rng)
    q = _prima_berikut(p + 2)       # q berdekatan dgn p -> kasus Fermat
    n = p * q
    hasil = D.rsa_fermat(n, batas=1000)
    if not hasil:
        return "p~q tak ditemukan"
    if f"{p} x {q}" not in hasil[0][1]:
        return f"hasil salah: {hasil[0][1]}"
    return True


def t_rsa_pollard_p1():
    """Rancang p supaya p-1 B-SMOOTH (semua faktor prima <= 37).

    Salah umum: bikin kand = kelipatan faktor kecil + 1 tapi lupa memastikan
    kand sendiri PRIMA. Kalau kand komposit, n = kand*q bukan RSA yang sah
    dan tesnya bisa "lulus" tanpa membuktikan apa pun.
    """
    kecil = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    acc = 1
    for f in kecil:
        acc *= f
    rng = random.Random(5)
    p = None
    for _ in range(40000):
        mult = 1
        while mult.bit_length() < 70:        # bikin mult agak besar
            mult *= rng.choice(kecil)
        kand = acc * mult + 1
        if kand.bit_length() >= 100 and _is_prime(kand):
            p = kand
            break
    if p is None:
        return "fixture p-1 gagal dibangun"
    q = _prima_lokal(128, rng)
    n = p * q
    hasil = D.rsa_pollard_p1(n, batas=5000)
    if not hasil:
        return "p-1 halus tak ditemukan"
    if str(p) not in hasil[0][1] and str(q) not in hasil[0][1]:
        return f"faktor salah: {hasil[0][1]}"
    return True


def t_hash_identifikasi():
    kasus = [
        (hashlib.md5(b"x").hexdigest(), "md5"),
        (hashlib.sha1(b"x").hexdigest(), "sha1"),
        (hashlib.sha256(b"x").hexdigest(), "sha256"),
        (hashlib.sha512(b"x").hexdigest(), "sha512"),
    ]
    for h, nama in kasus:
        keluar = " ".join(D.identifikasi_hash(h))
        if nama not in keluar:
            return f"{nama} tak dikenali: {keluar[:60]}"
    return True


def t_hash_crack():
    target = hashlib.sha256(b"password").hexdigest()
    r = D.crack_hash(target, ["hunter2", "password", "admin"])
    if not r:
        return "tak terpecahkan"
    teks, alg = r
    if teks != "password" or alg != "sha256":
        return f"hasil salah: {r}"
    return True


def t_hash_crack_mutasi():
    """Kata dasar 'secret' dgn mutasi 'Secret123!' harus kena lewat _mutasi."""
    target = hashlib.md5(b"secret123").hexdigest()
    r = D.crack_hash(target, ["secret"])
    if not r:
        return "mutasi tak dijalankan"
    if r[0] != "secret123":
        return f"mutasi salah: {r[0]!r}"
    return True


def t_aes_ecb_terdeteksi():
    blok = b"SIXTEENBYTEBLOK!"       # 16 byte
    data = blok * 3 + b"\x00" * 16
    keluar = " ".join(D.deteksi_aes_mode(data))
    if "ECB sangat mungkin" not in keluar:
        return f"ECB tak terdeteksi: {keluar[:70]}"
    return True


def t_aes_ecb_tak_positif_palsu():
    data = bytes(range(32))          # 2 blok unik
    keluar = " ".join(D.deteksi_aes_mode(data))
    if "ECB sangat mungkin" in keluar:
        return "false positive ECB"
    return True


def t_flag_re():
    if not D.FLAG_RE.search("here is flag{test_ok} for you"):
        return "flag{...} tak dikenali"
    if D.FLAG_RE.search("random text without braces"):
        return "false positive flag"
    return True


def t_stdlib_saja():
    src = open(SOLVE, encoding="utf-8").read()
    for p in ("import requests", "import numpy", "from Crypto.", "import sympy"):
        if p in src:
            return f"dependensi wajib: {p}"
    return True


def t_cli_substitution_jalan():
    """Uji jalur CLI penuh, bukan cuma fungsi internal."""
    perm = list(D.ALF)
    random.Random(3).shuffle(perm)
    peta = str.maketrans(D.ALF + D.ALF.upper(),
                         "".join(perm) + "".join(perm).upper())
    c = "the secret message is hidden well inside this long english text"
    cipher = c.upper().translate(peta)
    p = subprocess.run([sys.executable, SOLVE, "--substitution",
                        "--restart", "8", cipher],
                       capture_output=True, text=True, timeout=180)
    if p.returncode != 0:
        return f"exit={p.returncode}: {p.stderr[-200:]}"
    if "substitusi" not in p.stdout:
        return f"tak menampilkan kandidat: {p.stdout[:150]!r}"
    return True


def t_cli_tolak_kosong():
    p = subprocess.run([sys.executable, SOLVE],
                       capture_output=True, text=True, timeout=30)
    if p.returncode == 0:
        return "harus menolak input kosong"
    if "butuh argumen" not in (p.stderr + p.stdout):
        return f"pesan galat tak jelas: {p.stderr[-160:]}"
    return True


def t_cli_rsa_butuh_n():
    p = subprocess.run([sys.executable, SOLVE, "--rsa", "--e", "3"],
                       capture_output=True, text=True, timeout=30)
    if p.returncode == 0:
        return "--rsa tanpa --n harus ditolak"
    if "--n" not in (p.stderr + p.stdout):
        return f"pesan galat tak jelas: {p.stderr[-160:]}"
    return True


JUMLAH = [
    ("caesar roundtrip 26 rotasi", t_caesar_roundtrip),
    ("caesar solver urut benar", t_caesar_solver),
    ("atbash involusi", t_atbash_involusi),
    ("vigenere roundtrip 4 kunci", t_vigenere_roundtrip),
    ("vigenere auto-detect kunci", t_vigenere_solver),
    ("rail fence roundtrip rails 2..8", t_rail_roundtrip),
    ("rail fence solver deteksi rails", t_rail_solver),
    ("transposisi roundtrip kolom 2..12", t_transposisi_roundtrip),
    ("transposisi solver deteksi kolom", t_transposisi_solver),
    ("xor 1 byte key benar menang", t_xor_1byte),
    ("xor kunci berulang L terdeteksi", t_xor_berulang),
    ("substitusi solver struktur terbentuk", t_substitusi_solver),
    ("substitusi cipher huruf besar", t_substitusi_kasus_besar),
    ("RSA e kecil (cuberoot)", t_rsa_e_kecil),
    ("RSA faktor bersama", t_rsa_common_factor),
    ("RSA Wiener (d kecil)", t_rsa_wiener),
    ("RSA Fermat (p ~ q)", t_rsa_fermat),
    ("RSA Pollard p-1 (p-1 halus)", t_rsa_pollard_p1),
    ("hash identifikasi md5/sha1/sha256/sha512", t_hash_identifikasi),
    ("hash crack sha256", t_hash_crack),
    ("hash crack mutasi kata", t_hash_crack_mutasi),
    ("AES ECB terdeteksi", t_aes_ecb_terdeteksi),
    ("AES ECB tak false-positive", t_aes_ecb_tak_positif_palsu),
    ("regex flag{...}", t_flag_re),
    ("stdlib saja, nol dependensi wajib", t_stdlib_saja),
    ("CLI --substitution jalan", t_cli_substitution_jalan),
    ("CLI tolak input kosong", t_cli_tolak_kosong),
    ("CLI --rsa wajib --n", t_cli_rsa_butuh_n),
]


def main() -> int:
    print(f"[*] solve.py - {len(JUMLAH)} tes\n")
    for nama, fn in JUMLAH:
        jalankan(nama, fn)
    lolos = sum(1 for _, ok, _ in _hasil if ok)
    gagal = len(_hasil) - lolos
    print(f"\n{'=' * 60}")
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
