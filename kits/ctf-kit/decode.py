#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""decode.py - pembongkar lapisan encoding utk CTF (misc / crypto / forensics).

Di hampir semua soal misc, teks dibungkus BEBERAPA lapis encoding. Membongkarnya
manual = menebak-nebak dan lupa urutannya. Skrip ini menjajaki SEMUA kandidat
decoder pada tiap lapis, menilai mana yang paling mirip teks terbaca (sinyal
terkuat: ada `flag{...}`), lalu MENGULANGI sampai stabil.

    python3 decode.py "WmxhZ3s...X0A="          # rantai otomatis (default)
    python3 decode.py --in soal.txt
    python3 decode.py --caesar "khoor zruog"     # putar 26 rotasi, skor terbaik
    python3 decode.py --xor "0a1b2c..."          # brute 1 byte key
    python3 decode.py --vigenere "..." --key KATA
    python3 decode.py --xor --hex                # input dalam heksadesimal
    python3 decode.py "..." --max-layer 12 --show-candidate

Stdlib murni, tanpa jaringan.

Kenapa skoring? Karena banyak decoder yang SALING BISA diterapkan (base64
menghasilkan teks yang bisa dianggap hex, dst). Yang menentukan bukan urutan
tapi HASIL: kandidat hanya diterima kalau skornya benar-benar membaik, dan
sepenuhnya terbaca. Kalau tidak, berhenti - jangan memutar-mutar teks yang
sudah jadi.
"""
from __future__ import annotations

import argparse, base64, re, string, sys, urllib.parse

# ---------------------------------------------------------------- sinyal flag
# Pola flag CTF pada umumnya. Ini skor TERTINGGI: kalau ketemu, rantai STOP.
FLAG_KETAT = re.compile(
    r"\b(?:flag|ctf|picoctf|hackthebox|htb|ductf|thm|ohs|fcsc|ais3|dctf|watevr"
    r"|midnight|seccon|hitcon|google|fbctf|umass|srdnlen)\s*\{[^{}\s]{1,300}\}",
    re.I)
FLAG_LONGGAR = re.compile(r"\b[A-Za-z0-9_]{2,15}\{[^{}\s]{4,300}\}")

# kosakata Inggris frekuensi tinggi - penanda teks yang benar-benar terbaca
KATA = frozenset("""
the of and to in a is that for it as with be by on or not you all had we one
their said what been has when who will more no if out so up into do time each
which their there use can may first other then now find any new work part take
get like long make well even back most people its over state year good could
our after than just such some these would them see way had been many too little
word about then them these her would make like him into time has look two more
write go see number no way could people my first water been call who oil its
now find long down day did get come made may part called use each how she all
way about many than them these some her would make like him into time has
file data key value name text user pass code byte bit json xml http request
""".split())

# frekuensi huruf Inggris (a..z)
FREK_EN = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702, "f": 2.228,
    "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153, "k": 0.772, "l": 4.025,
    "m": 2.406, "n": 6.749, "o": 7.507, "p": 1.929, "q": 0.095, "r": 5.987,
    "s": 6.327, "t": 9.056, "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150,
    "y": 1.974, "z": 0.074,
}

B58_ALFABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-.-.--": "!", "-....-": "-", "-..-.": "/", ".-..-.": '"', "...-..-": "$",
    ".--.-.": "@", "-...-": "=", ".-.-.": "+",
    # ekstensi non-ITU yang lazim dipakai soal CTF (flag{...})
    "-...-.": "{", "-...--": "}", "..--.-": "_", "...-.-": "\n",
    "-.--.": "(", "-.--.-": ")",
}


# ------------------------------------------------------------------ utilitas
def ke_teks(b: bytes) -> str | None:
    """bytes -> str terbaca, atau None kalau bukan teks yang berguna."""
    if not b:
        return None
    for enc in ("utf-8", "latin-1"):
        try:
            t = b.decode(enc)
        except UnicodeDecodeError:
            continue
        if _keterbacaan(t) >= 0.90:
            return t
    return None


def _keterbacaan(t: str) -> float:
    if not t:
        return 0.0
    baik = sum(1 for c in t if 32 <= ord(c) < 127 or c in "\n\t")
    return baik / len(t)


def skor(t: str) -> float:
    """Skor keterbacaan. -inf = tolak. flag{...} = menang mutlak."""
    if not t:
        return -1e18
    keterbacaan = _keterbacaan(t)
    if keterbacaan < 0.92:
        return -1e18 + keterbacaan * 1e3
    if FLAG_KETAT.search(t):
        return 1e9
    if FLAG_LONGGAR.search(t):
        return 5e8

    kata = re.findall(r"[A-Za-z']+", t.lower())
    hits = sum(1 for w in kata if w in KATA)
    bonus_kata = hits * 25.0

    huruf = [c.lower() for c in t if c.isalpha()]
    bonus_huruf = 0.0
    if len(huruf) >= 20:
        total = len(huruf)
        # chi-squared vs frekuensi Inggris (makin kecil makin mirip)
        chi = 0.0
        for h, eks in FREK_EN.items():
            amil = huruf.count(h) / total * 100.0
            e = eks or 0.01
            chi += (amil - e) ** 2 / e
        bonus_huruf = max(0.0, 60.0 - chi / 12.0)

    kecil = sum(1 for c in t if c.islower()) / len(t)
    return keterbacaan * 60.0 + bonus_kata + bonus_huruf + kecil * 30.0


def _bersih(t: str) -> str:
    return "".join(t.split())


def tanda(t: str) -> str:
    """Penanda hasil. `flag{` prefix ketat = yakin; pola `xxx{...}` = CUMA MIRIP.

    Dipisah karena bentuk `synt{...}` (rot13) atau `iodj{...}` (caesar) juga
    kena pola longgar - menandainya 'FLAG' bikin laporan penuh kebohongan.
    """
    if FLAG_KETAT.search(t):
        return " <== FLAG KETEMU"
    if FLAG_LONGGAR.search(t):
        return " <== ? bentuk mirip flag (cek manual)"
    return ""


def ada_flag_ketat(t: str) -> bool:
    return bool(FLAG_KETAT.search(t))


def jumlah_kata(t: str, min_len: int = 1) -> int:
    """Hitung kosakata umum. min_len=3 supaya huruf tunggal 'a'/'i' tak bikin
    sampah terlihat 'bermakna'."""
    return sum(1 for w in re.findall(r"[A-Za-z']+", t.lower())
               if len(w) >= min_len and w in KATA)


# ------------------------------------------------------------------ decoder
def d_base64(t: str) -> str | None:
    s = _bersih(t)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s) or len(s) < 4:
        return None
    s += "=" * (-len(s) % 4)
    return ke_teks(base64.b64decode(s, validate=True))


def d_base64url(t: str) -> str | None:
    s = _bersih(t).replace("-", "+").replace("_", "/")
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s) or len(s) < 4:
        return None
    s += "=" * (-len(s) % 4)
    try:
        return ke_teks(base64.b64decode(s, validate=True))
    except Exception:
        return None


def d_base32(t: str) -> str | None:
    s = _bersih(t).upper()
    if not re.fullmatch(r"[A-Z2-7]+={0,6}", s) or len(s) < 8:
        return None
    s += "=" * (-len(s) % 8)
    try:
        return ke_teks(base64.b32decode(s))
    except Exception:
        return None


def d_base85(t: str) -> str | None:
    s = "".join(t.split())
    if len(s) < 5 or not re.fullmatch(r"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+", s):
        return None
    try:
        return ke_teks(base64.a85decode(s.encode(), adobe=False))
    except Exception:
        return None


def d_base58(t: str) -> str | None:
    s = "".join(t.split())
    if len(s) < 4 or any(c not in B58_ALFABET for c in s):
        return None
    n = 0
    for c in s:
        n = n * 58 + B58_ALFABET.index(c)
    panjang = (n.bit_length() + 7) // 8 or 1
    b = n.to_bytes(panjang, "big")
    b = b"\x00" * (len(s) - len(s.lstrip("1"))) + b
    return ke_teks(b)


def d_hex(t: str) -> str | None:
    s = _bersih(t)
    if len(s) < 4 or len(s) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    return ke_teks(bytes.fromhex(s))


def d_url(t: str) -> str | None:
    if "%" not in t:
        return None
    r = urllib.parse.unquote(t)
    return r if r != t and _keterbacaan(r) >= 0.95 else None


def d_quotedprintable(t: str) -> str | None:
    if "=" not in t or not re.search(r"=[0-9A-Fa-f]{2}", t):
        return None
    try:
        r = t.encode().decode("quoted-printable")
    except Exception:
        return None
    return r if r != t and _keterbacaan(r) >= 0.95 else None


def d_binary(t: str) -> str | None:
    s = _bersih(t)
    if len(s) < 16 or len(s) % 8 or not re.fullmatch(r"[01]+", s):
        return None
    return ke_teks(bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8)))


def d_morse(t: str) -> str | None:
    """Standar: 1 spasi = pemisah HURUF, `/` atau 2+ spasi = pemisah KATA.

    Salah paham di sini bikin hasilnya `F L A G { ... }` - huruf kepisah semua,
    regex flag tak pernah kena.
    """
    s = t.strip()
    if not re.fullmatch(r"[.\-/\s]+", s):
        return None
    if "." not in s and "-" not in s:
        return None
    keluar = []
    for kata in re.split(r"\s*/\s*|\s{2,}", s):
        kata = kata.strip()
        if not kata:
            continue
        huruf = []
        for tok in kata.split():
            if tok not in MORSE:
                return None          # token tak dikenal -> morse-nya beda tabel
            huruf.append(MORSE[tok])
        keluar.append("".join(huruf))
    r = " ".join(keluar)
    return r if len(r) >= 3 else None


def d_rot13(t: str) -> str | None:
    if not re.search(r"[A-Za-z]", t):
        return None
    return t.translate(str.maketrans(
        string.ascii_lowercase + string.ascii_uppercase,
        string.ascii_lowercase[13:] + string.ascii_lowercase[:13]
        + string.ascii_uppercase[13:] + string.ascii_uppercase[:13]))


def d_atbash(t: str) -> str | None:
    if not re.search(r"[A-Za-z]", t):
        return None
    return t.translate(str.maketrans(
        string.ascii_lowercase + string.ascii_uppercase,
        string.ascii_lowercase[::-1] + string.ascii_uppercase[::-1]))


def d_reverse(t: str) -> str | None:
    if len(t.strip()) < 6:
        return None
    return t[::-1]


def d_newline_reverse(t: str) -> str | None:
    if "\n" not in t:
        return None
    r = "\n".join(t.splitlines()[::-1])
    return r if r != t else None


def d_double_url(t: str) -> str | None:
    r = urllib.parse.unquote(urllib.parse.unquote(t))
    return r if r != t and _keterbacaan(r) >= 0.95 else None


DAFTAR: list[tuple[str, object]] = [
    ("base64", d_base64),
    ("base64url", d_base64url),
    ("base32", d_base32),
    ("base85", d_base85),
    ("base58", d_base58),
    ("hex", d_hex),
    ("url", d_url),
    ("double-url", d_double_url),
    ("quoted-printable", d_quotedprintable),
    ("binary", d_binary),
    ("morse", d_morse),
    ("rot13", d_rot13),
    ("atbash", d_atbash),
    ("reverse", d_reverse),
    ("reverse-baris", d_newline_reverse),
]


# ------------------------------------------------------- brute force eksplisit
def caesar(t: str, geser: int) -> str:
    return t.translate(str.maketrans(
        string.ascii_lowercase + string.ascii_uppercase,
        string.ascii_lowercase[geser:] + string.ascii_lowercase[:geser]
        + string.ascii_uppercase[geser:] + string.ascii_uppercase[:geser]))


def semua_caesar(t: str) -> list[tuple[int, str, float]]:
    out = []
    for k in range(26):
        r = caesar(t, k)
        out.append((k, r, skor(r)))
    return sorted(out, key=lambda x: -x[2])


def xor_serangkaian(b: bytes, k: int) -> bytes:
    return bytes(x ^ k for x in b)


def semua_xor(t: str) -> list[tuple[int, str, float]]:
    try:
        raw = bytes.fromhex(_bersih(t)) if re.fullmatch(
            r"[0-9a-fA-F\s]+", _bersih(t)) and len(_bersih(t)) % 2 == 0 \
            else t.encode("latin-1", "replace")
    except Exception:
        raw = t.encode("latin-1", "replace")
    out = []
    for k in range(256):
        r = ke_teks(xor_serangkaian(raw, k))
        if r is None:
            continue
        out.append((k, r, skor(r)))
    return sorted(out, key=lambda x: -x[2])


def vigenere(t: str, kunci: str, geser: int = -1) -> str:
    """geser=-1 = DEKRIPSI (yang dipakai `--vigenere`), geser=+1 = enkripsi.

    Kesalahan klasik: pakai arah yang sama di dua sisi -> keluaran malah
    makin jauh dari plaintext. `--vigenere` HARUS menggeser mundur.
    """
    kunci = [c for c in kunci.lower() if c.isalpha()]
    if not kunci:
        return t
    out, i = [], 0
    for c in t:
        if c.isalpha():
            dasar = string.ascii_uppercase if c.isupper() else string.ascii_lowercase
            g = (ord(kunci[i % len(kunci)]) - ord("a")) * geser
            out.append(dasar[(dasar.index(c) + g) % 26])
            i += 1
        else:
            out.append(c)
    return "".join(out)


# --------------------------------------------------------------------- rantai
def lahirkan(t: str) -> list[tuple[str, str]]:
    """Semua kandidat hasil decode + skornya, diurutkan menurun."""
    hasil = []
    for nama, fn in DAFTAR:
        try:
            r = fn(t)
        except Exception:
            continue
        if not r or r == t:
            continue
        s = skor(r)
        if s <= -1e17:
            continue
        hasil.append((nama, r, s))
    # jalur brute yang cuma masuk kalau hasilnya benar-benar bagus
    for k, r, s in semua_caesar(t)[:1]:
        if s > skor(t) + 40 and (FLAG_KETAT.search(r) or FLAG_LONGGAR.search(r)
                                 or s > skor(t) + 80):
            hasil.append((f"caesar(k={k})", r, s))
    hasil.sort(key=lambda x: -x[2])
    return [(n, r) for n, r, _ in hasil]


BUDGET_NODE = 400


def rantai(t: str, maks: int, tunjuk_kandidat: bool = False):
    """BFS sampai ketemu flag, atau node budget habis. -> (langkah, teks_akhir).

    KENAPA BFS, BUKAN SERAKAH (skor-wajib-naik):
    lapis antara - string hex, string base64 - entropinya tinggi dan
    chi-squared-nya kebetulan bagus, jadi SKORNYA LEBIH TINGGI dari teks
    aslinya. Syarat "skor harus naik" berhenti setelah 1 lapis padahal masih
    ada 3 lagi. Dengan BFS semua jalur dijelajahi (cabang: 2 kandidat terbaik),
    berhenti SEGERA begitu flag muncul (jalur terpendek menang), dan kalau tak
    ada flag baru ambil terminal dengan skor tertinggi.

    `terkunjung` mencegah oscilasi (mis. reverse lalu reverse balik).
    """
    from collections import deque

    antre = deque([(t, [])])
    terkunjung = {t}
    terbaik = (skor(t), t, [])            # (skor, teks, jalan)
    panjang = None                        # jalur dgn flag FORMAT LONGGAR
    node = 0

    while antre and node < BUDGET_NODE:
        kini, jalan = antre.popleft()
        node += 1
        if jalan and FLAG_KETAT.search(kini):
            return jalan, kini             # flag{...} asli: jalur terpendek menang
        if panjang is None and jalan and FLAG_LONGGAR.search(kini):
            panjang = (jalan, kini)        # simpan, tapi JANGAN berhenti -
        if len(jalan) >= maks:             # siapa tahu di bawahnya ada flag{ asli
            continue
        kandidat = lahirkan(kini)
        if tunjuk_kandidat and len(kandidat) > 1:
            alt = ", ".join(n for n, _ in kandidat[1:4])
            print(f"    [kandidat lain @ lapis {len(jalan)+1}]: {alt}",
                  file=sys.stderr)
        for nama, berikut in kandidat[:2]:   # batasi cabang, jangan meledak
            if berikut in terkunjung:
                continue
            terkunjung.add(berikut)
            j2 = jalan + [(nama, kini, berikut)]
            if FLAG_KETAT.search(berikut):
                return j2, berikut
            if len(berikut) >= 3:
                antre.append((berikut, j2))
            s = skor(berikut)
            if s > terbaik[0] and len(berikut) >= 3:
                terbaik = (s, berikut, j2)
            if panjang is None and FLAG_LONGGAR.search(berikut):
                panjang = (j2, berikut)

    if panjang:                           # habis menjelajah, tak ketemu flag{
        return panjang                    # pakai yang longgar ini saja
    return terbaik[2], terbaik[1]


def _potong(s: str, n: int = 160) -> str:
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[:n] + f"... [+{len(s)-n} char]"


# ----------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(
        description="bongkar lapisan encoding utk CTF (rantai otomatis)")
    ap.add_argument("teks", nargs="?", default="", help="input langsung")
    ap.add_argument("--in", dest="inp", default="", help="baca input dari file")
    ap.add_argument("--caesar", action="store_true", help="brute 26 rotasi")
    ap.add_argument("--xor", action="store_true", help="brute 1 byte key (256)")
    ap.add_argument("--vigenere", metavar="KUNCI", default="", help="decode Vigenere")
    ap.add_argument("--hex", action="store_true", help="input adalah heksadesimal")
    ap.add_argument("--max-layer", type=int, default=8, help="batas lapis (default 8)")
    ap.add_argument("--top", type=int, default=5, help="kandidat tampil per lapis")
    ap.add_argument("--show-candidate", action="store_true",
                    help="cetak kandidat alternatif tiap lapis")
    ap.add_argument("--out", default="", help="tulis hasil akhir ke file")
    a = ap.parse_args()

    if not a.teks and not a.inp:
        ap.error("butuh argumen teks atau --in FILE")
    if a.max_layer < 1 or a.max_layer > 64:
        ap.error("--max-layer harus 1..64")
    if a.top < 1 or a.top > 26:
        ap.error("--top harus 1..26")

    teks = a.teks
    if a.inp:
        try:
            teks = open(a.inp, encoding="utf-8", errors="replace").read().strip()
        except OSError as e:
            print(f"[STOP] gagal baca {a.inp}: {e}", file=sys.stderr)
            return 1
    if not teks:
        print("[STOP] input kosong", file=sys.stderr)
        return 1

    if a.hex and re.fullmatch(r"[0-9a-fA-F\s]+", teks):
        teks = _bersih(teks)
        if len(teks) % 2 == 0:
            try:
                teks = bytes.fromhex(teks).decode("latin-1")
            except Exception:
                pass

    # ---- mode eksplisit
    if a.caesar:
        print(f"[*] Caesar brute dari: {_potong(teks)}\n")
        for k, r, s in semua_caesar(teks)[:a.top]:
            print(f"  geser {k:>2} (skor {s:7.1f}){tanda(r)}: {_potong(r)}")
        return 0

    if a.xor:
        print(f"[*] XOR 1-byte brute dari: {_potong(teks)}\n")
        hasil = semua_xor(teks)
        if not hasil:
            print("[i] tak ada key yang menghasilkan teks terbaca")
            return 1
        # KUNCI: hasil XOR sering MASIH ter-encode (mis. base64). Skor mentah
        # rendah -> key yang benar bisa kalah dari sampah. Makanya tiap kandidat
        # dibongkar sampai habis dulu, baru diberi peringkat: flag menang mutlak.
        kandidat = []
        for k, r, _ in hasil:
            langkah, akhir = rantai(r, 6)
            urut = 1_000_000_000 if ada_flag_ketat(akhir) else skor(akhir)
            kandidat.append((urut, k, r, akhir, langkah))
        kandidat.sort(key=lambda x: -x[0])
        for urut, k, r, akhir, langkah in kandidat[:a.top]:
            beda = f" [+{len(langkah)} lapis]" if langkah else ""
            print(f"  key 0x{k:02x}{beda}{tanda(akhir)}: {_potong(akhir)}")
        if not any(ada_flag_ketat(a_) for _, _, _, a_, _ in kandidat[:a.top]):
            print("\n[i] tak ada key yang sampai ke flag{...} - coba --caesar,"
                  " atau kombinasikan manual dgn --in setelah XOR.")
        return 0

    if a.vigenere:
        r = vigenere(teks, a.vigenere)          # geser mundur = dekripsi
        _, akhir = rantai(r, 6)
        print(f"[*] Vigenere dekripsi key={a.vigenere!r}")
        print(f"    {_potong(r)}{tanda(r)}")
        # cuma tunjukkan sambungan rantai kalau memang sampai ke flag{
        if akhir != r and ada_flag_ketat(akhir):
            print(f"    [+bongkar lanjutan]{tanda(akhir)} {_potong(akhir)}")
        if a.out:
            open(a.out, "w", encoding="utf-8").write(r)
            print(f"[OK] {a.out}")
        return 0

    # ---- mode default: rantai otomatis
    print(f"[*] input  : {_potong(teks)}")
    print(f"[*] skor awal: {skor(teks):.1f}"
          + ("  (sudah ada flag)" if FLAG_KETAT.search(teks) else ""))
    langkah, akhir = rantai(teks, a.max_layer, a.show_candidate)

    if not langkah:
        print("\n[i] tak ada lapis yang bisa dibongkar lagi.")
        print("    Kalau yakin ini ter-encode, coba --caesar / --xor / --vigenere.")
        print(f"\n[hasil] {_potong(akhir)}")
        return 0

    print(f"\n[*] {len(langkah)} lapis terbongkar:\n")
    for i, (nama, _, sesudah) in enumerate(langkah, 1):
        print(f"  lapis {i}. {nama:<18} skor {skor(sesudah):8.1f}{tanda(sesudah)}")
        print(f"          {_potong(sesudah)}")

    ketat = FLAG_KETAT.search(akhir)
    print(f"\n[hasil akhir] {_potong(akhir, 400)}")
    if ketat:
        print(f"[FLAG] {ketat.group(0)}")
    else:
        if FLAG_LONGGAR.search(akhir):
            print(f"[?] {FLAG_LONGGAR.search(akhir).group(0)}")
            print("    bentuknya {x} tapi prefix-nya bukan daftar prefix CTF "
                  "yang dikenal -> bisa jadi cuma rot13/caesar. Cek: "
                  "--caesar / --vigenere.")
        if len(langkah) and jumlah_kata(akhir, min_len=3) == 0:
            print("[!] rantai di atas TIDAK menghasilkan teks bermakna "
                  "(nol kosakata ≥3 huruf) - kemungkinan ini cuma sampah yang "
                  "diputar-putar. Jangan laporkan sebagai hasil.")
    if a.out:
        open(a.out, "w", encoding="utf-8").write(akhir)
        print(f"[OK] ditulis ke {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
