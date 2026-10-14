#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""decode.py — chain decoder serba bisa buat soal CTF (misc/encoding).
Input: string langsung, file, atau stdin. Auto-detect + decode berantai (BFS),
deteksi flag di tiap tahap. Tanpa dependensi, tanpa jaringan.

    python3 decode.py "RmxhZ3s..."
    python3 decode.py --file encoded.txt
    echo "SGVsbG8=" | python3 decode.py
"""
import argparse, base64, re, string, sys
from typing import Any, Callable, Optional

FLAG_RX = re.compile(r"(?:flag|ctf|dexero|picoctf|hack|htb)\s*[{(][A-Za-z0-9_!@#$%^&*+\-=:. /]{3,120}[})]", re.I)

BOB58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BOB62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
MORSE = {".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e",
         "..-.": "f", "--.": "g", "....": "h", "..": "i", ".---": "j",
         "-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o",
         ".--.": "p", "--.-": "q", ".-.": "r", "...": "s", "-": "t",
         "..-": "u", "...-": "v", ".--": "w", "-..-": "x", "-.--": "y",
         "--..": "z", "-----": "0", ".----": "1", "..---": "2",
         "...--": "3", "....-": "4", ".....": "5", "-....": "6",
         "--...": "7", "---..": "8", "----.": "9"}


def _try(fn: Callable[[], Any]) -> Optional[str]:
    try:
        r = fn()
        return r if isinstance(r, str) and r else None
    except Exception:
        return None


def _b64_to_str(data: bytes) -> Optional[str]:
    try:
        return data.decode("utf-8")
    except Exception:
        try:
            return data.decode("latin-1")
        except Exception:
            return None


def d_b64(s):
    t = s.strip()
    if len(t) % 4:
        t += "=" * (4 - len(t) % 4)
    for fn in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            out = _b64_to_str(fn(t))
            if out:
                return out
        except Exception:
            continue
    return None


def d_b32(s):
    t = s.strip().upper()
    t += "=" * ((8 - len(t) % 8) % 8)
    return _try(lambda: base64.b32decode(t).decode("utf-8", "strict"))


def _bignum_decode(s, alphabet):
    n = 0
    for ch in s:
        k = alphabet.find(ch)
        if k < 0:
            return None
        n = n * len(alphabet) + k
    if n == 0:
        return "0"
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    return _try(lambda: out.decode("utf-8"))


def d_b58(s):
    return _bignum_decode(s.strip(), BOB58)


def d_b62(s):
    return _bignum_decode(s.strip(), BOB62)


def d_b85(s):
    return _try(lambda: base64.a85decode(s.strip()).decode("utf-8")) or \
        _try(lambda: base64.b85decode(s.strip()).decode("utf-8"))


def d_hex(s):
    t = re.sub(r"^0x", "", s.strip()).replace(" ", "")
    if len(t) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", t):
        return None
    return _try(lambda: bytes.fromhex(t).decode("utf-8"))


def d_url(s):
    import urllib.parse
    u = urllib.parse.unquote_plus(s)
    return u if u != s else None


def d_unicode_esc(s):
    t = _try(lambda: s.encode().decode("unicode_escape"))
    return t if t and t != s else None


def d_rot13(s):
    r = s.translate(str.maketrans(
        string.ascii_lowercase + string.ascii_uppercase,
        string.ascii_lowercase[13:] + string.ascii_lowercase[:13] +
        string.ascii_uppercase[13:] + string.ascii_uppercase[:13]))
    return r if r != s else None


def d_atbash(s):
    low = string.ascii_lowercase[::-1]
    up = string.ascii_uppercase[::-1]
    r = s.translate(str.maketrans(string.ascii_letters, low + up))
    return r if r != s else None


def d_reverse(s):
    r = s[::-1]
    return r if r != s and len(s) > 2 else None


def d_binary(s):
    t = s.split()
    if not t or not all(re.fullmatch(r"[01]{8,}", x) for x in t[:20]):
        return None
    try:
        return bytes(int(x, 2) for x in t).decode("utf-8")
    except Exception:
        return None


def d_morse(s):
    t = s.replace("/", " ").split()
    if len(t) < 2 or not all(re.fullmatch(r"[.\-]+", x) for x in t):
        return None
    try:
        return "".join(MORSE[x] for x in t)
    except KeyError:
        return None


def d_xor_single(s):
    b = s.encode("latin-1", "replace")
    best, bestscore = None, -1
    for k in range(1, 256):
        o = bytes(x ^ k for x in b)
        if not o.isascii():
            continue
        vis = sum(32 <= c < 127 or c in (9, 10, 13) for c in o) / len(o)
        if vis > bestscore:
            bestscore, best = vis, o.decode("ascii", "replace")
    if best and bestscore > 0.9 and best != s:
        return best
    return None


DECODERS = [
    ("base64", d_b64), ("base32", d_b32), ("base58", d_b58),
    ("base62", d_b62), ("base85", d_b85), ("hex", d_hex),
    ("url", d_url), ("unicode-escape", d_unicode_esc), ("rot13", d_rot13),
    ("atbash", d_atbash), ("reverse", d_reverse), ("binary", d_binary),
    ("morse", d_morse), ("xor-single", d_xor_single),
]


def is_clean_text(s):
    if not s or len(s) > 20000:
        return False
    vis = sum(c.isprintable() or c in "\n\r\t" for c in s)
    return vis / len(s) > 0.92


def bfs(start, depth=6):
    seen, flags, hasil = {start}, [], []
    frontier = [(start, 0, [])]
    while frontier:
        nxt = []
        for cur, d, jalur in frontier:
            if d >= depth:
                continue
            for name, fn in DECODERS:
                out = fn(cur)
                if out is None or not is_clean_text(out):
                    continue
                key = out.strip()
                if key in seen:
                    continue
                seen.add(key)
                jalan = jalur + [f"{name}"]
                hasil.append((out, jalan))
                m = FLAG_RX.search(out)
                if m:
                    flags.append((m.group(0), jalan))
                nxt.append((out, d + 1, jalan))
        frontier = nxt
    return hasil, flags


def hashid(s):
    t = s.strip()
    pola = [
        (r"^[0-9a-f]{32}$", "MD5 / NTLM / MD4 (32 hex)"),
        (r"^[0-9a-f]{40}$", "SHA1 (40 hex)"),
        (r"^[0-9a-f]{56}$", "SHA224 (56 hex)"),
        (r"^[0-9a-f]{64}$", "SHA256 (64 hex)"),
        (r"^\$2[aby]\$", "bcrypt"),
        (r"^\$argon2", "Argon2"),
        (r"^[0-9a-f]+:[0-9a-f]+$", "unix crypt (salt:hash)"),
    ]
    return [ket for rx, ket in pola if re.match(rx, t)]


def main():
    ap = argparse.ArgumentParser(description="chain decoder CTF (base/rot/xor/morse/...)")
    ap.add_argument("text", nargs="?", help="string ter-encode (default: stdin)")
    ap.add_argument("--file", help="baca input dari file")
    ap.add_argument("--depth", type=int, default=6, help="kedalaman rantai decode (default 6)")
    ap.add_argument("--hashid", action="store_true", help="cek tipe hash input")
    a = ap.parse_args()
    if a.text:
        src = a.text
    elif a.file:
        src = open(a.file, encoding="utf-8", errors="replace").read().strip()
    elif not sys.stdin.isatty():
        src = sys.stdin.read().strip()
    else:
        ap.error("butuh argumen text, --file, atau stdin")
    if a.hashid:
        t = hashid(src)
        print("[hashid]", ", ".join(t) if t else "tak dikenali")
        if not t:
            return 1
    print(f"[*] input ({len(src)} char): {src[:80]}{'…' if len(src) > 80 else ''}")
    hasil, flags = bfs(src, a.depth)
    if not hasil:
        print("[i] tak ada decode yang menghasilkan teks valid")
        return 1
    print(f"\n[ditemukan {len(hasil)} hasil decode unik]")
    for out, jalan in hasil[:40]:
        ringkas = out.replace("\n", "\\n")[:100]
        print(f"  [{' → '.join(jalan)}]  {ringkas}")
    if len(hasil) > 40:
        print(f"  … +{len(hasil) - 40} lagi")
    if flags:
        print("\n[!!! FLAG KETEMU]")
        for fl, jalan in flags:
            print(f"  {fl}   (via {' → '.join(jalan)})")
        return 0
    print("\n[i] belum ada pola flag — coba --depth lebih dalam atau manual dari hasil di atas")
    return 0


if __name__ == "__main__":
    sys.exit(main())
