#!/usr/bin/env python3
"""Generate drill pack latihan CTF jeorpadic (decoder/crypto/forensics).

Hasil: soal/ (file latihan) + jawaban.json (kunci).
Deterministik — seed di-hardcode biar hasil sama di mesin mana pun.
Jalankan: python3 gen_drills.py
"""
import base64
import json
import math
import pathlib
import random
import struct
import zipfile
import zlib

random.seed(20261114)  # tanggal penyisihan :)

HERE = pathlib.Path(__file__).parent
SOAL = HERE / "soal"


def caesar_enc(t, k):
    out = []
    for ch in t:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + k) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def vigenere_enc(t, key):
    k = [ord(c) - ord("a") for c in key.lower() if c.isalpha()]
    out, j = [], 0
    for ch in t:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + k[j % len(k)]) % 26 + base))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def rail_enc(t, k=3):
    rails = [""] * k
    r, d = 0, 1
    for ch in t:
        rails[r] += ch
        r += d
        if r == 0 or r == k - 1:
            d = -d
    return "".join(rails)


def xor_enc(t, key=0x37):
    return bytes(b ^ key for b in t.encode()).hex()


# ---------- helper RSA (deterministik, stdlib only) ----------

_PRIMA_KECIL = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def is_prime(n):
    """Miller-Rabin dengan saksi tetap — cukup untuk drill (bukan kripto produksi)."""
    if n < 2:
        return False
    for p in _PRIMA_KECIL:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in _PRIMA_KECIL:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def rand_prime(bits):
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(n):
            return n


def next_prime(n):
    n += 1 if n % 2 == 0 else 2
    while not is_prime(n):
        n += 2
    return n


def flag_ke_m(f):
    return int.from_bytes(f.encode(), "big")


def rsa_file(judul, n, e, c):
    return (f"# {judul}\n"
            f"n = {n}\n"
            f"e = {e}\n"
            f"c = {c}\n")


def chunk(tag, data):
    c = tag + data
    return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c))


def make_png(flag, mode):
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\x00\x00\x00")
    if mode == "text":
        body = chunk(b"tEXt", b"Comment\x00" + flag.encode()) + chunk(b"IDAT", idat)
    else:  # tail: data nyempil SETELAH IEND
        body = chunk(b"IDAT", idat)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + body + chunk(b"IEND", b"")
    if mode == "tail":
        png += b"\nJANGANHAPUS:" + flag.encode()
    return png


def main():
    SOAL.mkdir(exist_ok=True)
    jawaban = []

    def simpan(nama, isi, flag, kategori, catatan, kunci=None):
        p = SOAL / nama
        if isinstance(isi, str):
            p.write_text(isi, encoding="utf-8")
        else:
            p.write_bytes(isi)
        entri = {"file": nama, "flag": flag, "kategori": kategori,
                 "catatan": catatan}
        if kunci:
            entri["kunci"] = kunci
        jawaban.append(entri)
        print(f"  + {nama}")

    # ---------- decoder (encode berlapis, peka huruf besar/kecil) ----------
    f = "flag{decoder_base64_tingkat1}"
    simpan("d1_b64.txt", base64.b64encode(f.encode()).decode() + "\n", f, "decoder", "b64 polos")

    f = "flag{decoder_rot13_lalu_b64}"
    simpan("d2_rot_b64.txt", base64.b64encode(caesar_enc(f, 13).encode()).decode() + "\n",
           f, "decoder", "rot13 -> b64")

    f = "flag{decoder_caesar7_b64}"
    simpan("d3_caesar_b64.txt", base64.b64encode(caesar_enc(f, 7).encode()).decode() + "\n",
           f, "decoder", "caesar k=7 -> b64")

    f = "flag{decoder_b64_lalu_hex}"
    simpan("d4_b64_hex.txt",
           base64.b64encode(f.encode().hex().encode()).decode() + "\n",
           f, "decoder", "b64 -> hex")

    # ---------- crypto (raw cipher, kunci dipakai latihan crack) ----------
    pesan = "serahkan dokumen rahasia ke markas sebelum fajar flag{caesar_kunci_13}"
    simpan("c1_caesar.txt", caesar_enc(pesan, 13) + "\n",
           "flag{caesar_kunci_13}", "crypto", "caesar k=13")

    # plaintext Inggris; kunci dicatat di jawaban (banyak soal vigenere CTF
    # memang kasih hint kunci — IOC auto-crack = latihan bonus terpisah)
    pesan = "the supply ship departs from the harbor at midnight flag{vigenere_merdeka}"
    simpan("c2_vigenere.txt", vigenere_enc(pesan, "merdeka") + "\n",
           "flag{vigenere_merdeka}", "crypto",
           "vigenere key=merdeka (decrypt: classics.py vigenere '<teks>' --key merdeka)",
           kunci="merdeka")

    pesan = "sinyal radio diamati setiap malam pukul dua belas flag{xor_byte_tunggal}"
    simpan("c3_xor.txt", xor_enc(pesan) + "\n",
           "flag{xor_byte_tunggal}", "crypto", "xor 1 byte (hex)")

    pesan = "kirimdokumenrahasiakepadasiapayangmembaca flag{railfence_r3}"
    simpan("c4_railfence.txt", rail_enc(pesan, 3) + "\n",
           "flag{railfence_r3}", "crypto", "rail fence k=3")

    # ---------- RSA (serangan: ctf-crypto/rsa.py) ----------
    # r1: small-e — m^e < n tanpa padding -> m = akar-e-integer(c)
    f = "flag{rsa_small_e_tanpa_padding}"
    while True:
        p, q = rand_prime(512), rand_prime(512)
        if p != q and (p - 1) % 3 and (q - 1) % 3:
            break
    n, e = p * q, 3
    c = pow(flag_ke_m(f), e, n)
    simpan("r1_small_e.txt",
           rsa_file("RSA small-e: pesan dipangkatkan 3 tanpa padding", n, e, c),
           f, "crypto", "rsa small-e: python ../ctf-crypto/rsa.py --n <n> --e 3 --c <c>")

    # r2: Fermat — p dan q berdekatan -> faktorisasi bertingkat
    f = "flag{rsa_fermat_selisih_kecil}"
    while True:
        p = rand_prime(256)
        q = next_prime(p + random.randrange(1, 1000))
        if math.gcd(65537, (p - 1) * (q - 1)) == 1:
            break
    n, e = p * q, 65537
    c = pow(flag_ke_m(f), e, n)
    simpan("r2_fermat.txt",
           rsa_file("RSA Fermat: n = p*q, p dan q berdekatan", n, e, c),
           f, "crypto", "rsa fermat: python ../ctf-crypto/rsa.py --n <n> --e 65537 --c <c>")

    # r3: Wiener — d kecil -> pecahan berlanjut e/n
    f = "flag{rsa_wiener_d_kecil}"
    while True:
        p, q = rand_prime(256), rand_prime(256)
        phi = (p - 1) * (q - 1)
        d = random.randrange(1 << 31, 1 << 47) | 1
        if p != q and math.gcd(d, phi) == 1:
            break
    e = pow(d, -1, phi)
    n = p * q
    c = pow(flag_ke_m(f), e, n)
    simpan("r3_wiener.txt",
           rsa_file("RSA Wiener: private exponent d kecil", n, e, c),
           f, "crypto", "rsa wiener: python ../ctf-crypto/rsa.py --n <n> --e <e> --c <c>")

    # ---------- forensics (file beneran) ----------
    f = "flag{png_teks_tersembunyi}"
    simpan("f1_komentar.png", make_png(f, "text"), f, "forensics", "chunk tEXt PNG")

    f = "flag{zip_komen_aneh}"
    zp = SOAL / "f2_zip_komen.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("catatan.txt", "file biasa, tidak ada apa-apa di sini\n")
        zf.comment = f.encode()
    jawaban.append({"file": "f2_zip_komen.zip", "flag": f, "kategori": "forensics",
                    "catatan": "komentar zip"})
    print("  + f2_zip_komen.zip")

    f = "flag{data_nyempil_belakang}"
    simpan("f3_nyempil.png", make_png(f, "tail"), f, "forensics", "data setelah IEND")

    f = "flag{whitespace_morse_biner}"
    bits = "".join(format(b, "08b") for b in f.encode())
    ws = "".join(" " if b == "0" else "\t" for b in bits)
    simpan("f4_spasi.txt",
           "baris kosong di bawah ini bukan kosong...\n" + ws + "\n",
           f, "forensics", "spasi=0 tab=1")

    (HERE / "jawaban.json").write_text(
        json.dumps(jawaban, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[OK] {len(jawaban)} drill -> soal/ + jawaban.json")


if __name__ == "__main__":
    main()
