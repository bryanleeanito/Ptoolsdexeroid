#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""classics.py — cipher klasik buat soal CTF (caesar/vigenere/xor/substitution).
Tanpa dependensi, offline. Skor bahasa Inggris buat brute-force.

    python3 classics.py caesar "Khoor Zruog"
    python3 classics.py vigenere "rijvs jeij wdmv" --key-len 3
    python3 classics.py xor "..." --key 0x42
    python3 classics.py subst "..." --auto
"""
import argparse, math, re, string, sys
from collections import Counter

FREQ = {"a": 8.2, "b": 1.5, "c": 2.8, "d": 4.3, "e": 12.7, "f": 2.2,
        "g": 2.0, "h": 6.1, "i": 7.0, "j": 0.15, "k": 0.77, "l": 4.0,
        "m": 2.4, "n": 6.7, "o": 7.5, "p": 1.9, "q": 0.095, "r": 6.0,
        "s": 6.3, "t": 9.1, "u": 2.8, "v": 0.98, "w": 2.4, "x": 0.15,
        "y": 2.0, "z": 0.074}
BIGRAM = {"th": 3.5, "he": 2.9, "in": 2.3, "er": 2.1, "an": 1.9, "on": 1.6,
          "en": 1.5, "at": 1.4, "ou": 1.4, "ed": 1.4, "ha": 1.3, "to": 1.3,
          "it": 1.3, "or": 1.3, "is": 1.2, "hi": 1.2, "es": 1.2, "ng": 1.1}
ALPH = string.ascii_lowercase


def iq_score(t):
    """Indeks kemiripan vs bahasa Inggris (1.0 = huruf rata semua)."""
    c = Counter(ch for ch in t.lower() if ch in ALPH)
    n = sum(c.values())
    if n < 4:
        return 0.0
    h = -sum((v / n) * math.log2(v / n) for v in c.values())
    return h


def eng_score(t):
    """Skor keterbacaan: frekuensi huruf + bigram umum."""
    s, c = 0.0, Counter(ch for ch in t.lower() if ch in ALPH)
    n = sum(c.values())
    if n:
        s += sum(-abs(c[l] / n * 100 - f) for l, f in FREQ.items()) / 10
    low = re.sub(r"[^a-z]", "", t.lower())
    s += sum(2.0 for a, b in zip(low, low[1:]) if a + b in BIGRAM)
    s -= 0.5 * len(re.findall(r"[^a-zA-Z\s.,'\"!?;:\-]", t))
    return s


def caesar(text, shift):
    r = []
    for ch in text:
        if ch in string.ascii_lowercase:
            r.append(ALPH[(ALPH.index(ch) + shift) % 26])
        elif ch in string.ascii_uppercase:
            r.append(ALPH[(ALPH.index(ch.lower()) + shift) % 26].upper())
        else:
            r.append(ch)
    return "".join(r)


def cmd_caesar(text):
    hasil = sorted(((eng_score(caesar(text, k)), k) for k in range(26)),
                   reverse=True)
    print("[caesar] top-3:")
    for sc, k in hasil[:3]:
        print(f"  shift={k:>2}  score={sc:7.1f}  {caesar(text, k)[:70]}")
    return caesar(text, hasil[0][1])


def vigenere(text, key, decrypt=True):
    r, ki = [], 0
    for ch in text:
        if ch.lower() in ALPH:
            k = ALPH.index(key[ki % len(key)].lower())
            if decrypt:
                k = -k              # dekripsi = geser MUNDUR (bukan maju)
            off = (ALPH.index(ch.lower()) + k) % 26
            r.append(ALPH[off].upper() if ch.isupper() else ALPH[off])
            ki += 1
        else:
            r.append(ch)
    return "".join(r)


def guess_key_len(text, max_len=20):
    """Tebak panjang kunci via average IOC per langkah."""
    letters = [c.lower() for c in text if c.lower() in ALPH]
    n = len(letters)
    if n < 50:
        return []
    hasil = []
    for L in range(1, min(max_len, n // 5) + 1):
        iocs = []
        for i in range(L):
            col = letters[i::L]
            cnt = Counter(col)
            m = len(col)
            iocs.append(sum(v * (v - 1) for v in cnt.values()) / (m * (m - 1)) if m > 1 else 0)
        avg = sum(iocs) / len(iocs)
        hasil.append((abs(avg - 0.0667), L, avg))
    hasil.sort()
    return hasil


def cmd_vigenere(text, key=None, key_len=None):
    if key:
        out = vigenere(text, key)
        print(f"[vigenere] key={key}")
        print(f"  {out}")
        return out
    print("[vigenere] tebak panjang kunci (IOC):")
    for d, L, avg in guess_key_len(text)[:3]:
        print(f"  len={L:<3} ioc={avg:.4f} (jauh 0.0667: {d:.4f})")
    L = key_len or guess_key_len(text)[0][1]
    print(f"[*] brute key len={L} per kolom (frekuensi tertinggi)…")
    letters = [c.lower() for c in text if c.lower() in ALPH]
    key = ""
    for i in range(L):
        col = letters[i::L]
        best = max(ALPH, key=lambda l: (col.count(l) - FREQ[l] / 5))
        # shift kolom: huruf frekuensi tertinggi -> 'e'
        key += ALPH[(ALPH.index(best) - ALPH.index("e")) % 26]
    out = vigenere(text, key)
    print(f"[vigenere] key={key}")
    for cand_key in (key, caesar(key, 0)):
        pass
    # refine: coba semua shift dari key tebakan
    refined = sorted(((eng_score(vigenere(text, caesar(key, s))), s) for s in range(26)),
                     reverse=True)
    key2 = caesar(key, refined[0][0] and refined[0][1])
    out = vigenere(text, key2)
    print(f"[vigenere] key hasil refine={key2}")
    print(f"  {out[:120]}")
    return out


def cmd_xor(text, key=None):
    raw = text.encode("latin-1", "replace")
    if key:
        if key.startswith("0x"):
            kb = bytes([int(key, 16) & 0xFF])
        elif key.isdigit():
            kb = bytes([int(key) & 0xFF])
        else:
            kb = key.encode()
        out = bytes(raw[i] ^ kb[i % len(kb)] for i in range(len(raw)))
        print(f"[xor] key={key!r}")
        print(f"  {out.decode('latin-1', 'replace')}")
        return out.decode("latin-1", "replace")
    hasil = []
    for k in range(1, 256):
        o = bytes(x ^ k for x in raw).decode("latin-1", "replace")
        hasil.append((eng_score(o), k, o))
    hasil.sort(reverse=True)
    print("[xor-single] top-3:")
    for sc, k, o in hasil[:3]:
        print(f"  key=0x{k:02x} ({chr(k) if 32 <= k < 127 else '?'})  score={sc:7.1f}  {o[:60]}")
    return hasil[0][2]


def cmd_subst(text, auto=True, key=""):
    """Substitusi monoalphabetic — hill-climb acak (sering menang di CTF)."""
    import random
    letters = [c.lower() for c in text if c.lower() in ALPH]
    if len(letters) < 30:
        print("[STOP] teks terlalu pendek buat substitution")
        return text
    target = Counter(letters)

    def apply(k):
        m = str.maketrans(k, ALPH)
        return text.lower().translate(m)

    def sc(t):
        return eng_score(t)

    best_k, best_s = key or ALPH, -1e9
    if key:
        best_s = sc(apply(key))
        print(f"[subst] key awal: {key}")
    random.seed(0)
    for _ in range(120):
        k = list(best_k)
        for _ in range(random.randint(1, 3)):
            i, j = random.randrange(26), random.randrange(26)
            k[i], k[j] = k[j], k[i]
        s = sc(apply("".join(k)))
        if s > best_s:
            best_s, best_k = s, "".join(k)
    out = apply(best_k)
    print(f"[subst] key (plain->cipher): {best_k}")
    print(f"  {out[:120]}")
    return out


def main():
    ap = argparse.ArgumentParser(description="cipher klasik CTF (offline)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("caesar", help="brute semua 26 shift")
    p.add_argument("text")
    p = sub.add_parser("vigenere", help="decrypt vigenere (--key atau tebak)")
    p.add_argument("text")
    p.add_argument("--key")
    p.add_argument("--key-len", dest="kl", type=int)
    p = sub.add_parser("xor", help="xor single-byte brute / key eksplisit")
    p.add_argument("text")
    p.add_argument("--key", help="0xNN / desimal / string")
    p = sub.add_parser("subst", help="monoalphabetic hill-climb")
    p.add_argument("text")
    p.add_argument("--key", default="", help="key parsial (opsional)")
    a = ap.parse_args()
    {"caesar": cmd_caesar, "vigenere": lambda t: cmd_vigenere(t, a.key, a.kl),
     "xor": lambda t: cmd_xor(t, a.key), "subst": lambda t: cmd_subst(t, key=a.key)}[a.cmd](a.text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
