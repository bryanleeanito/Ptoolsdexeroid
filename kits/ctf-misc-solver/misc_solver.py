#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""misc_solver.py — auto-classifier + solver buat soal misc CTF.

Fitur:
  - classify: deteksi jenis encoding/hash dari string
  - solve: auto-decode chain sampai ketemu flag
  - hashid: identifikasi jenis hash
  - xor: brute single-byte XOR

    python3 misc_solver.py classify "SGVsbG8gV29ybGQ="
    python3 misc_solver.py solve "flag{test}" --encoding base64
    python3 misc_solver.py hashid "5f4dcc3b5aa765d61d8327deb882cf99"
    python3 misc_solver.py xor "1b37373331363f78151b7f2b78343133"
"""
import argparse, base64, binascii, hashlib, itertools, re, string, sys

FLAG_RX = re.compile(r"(?:flag|ctf|dexero|picoctf|htb)\s*[{(][A-Za-z0-9_!@#$%^&*+\-=:. /]{3,120}[})]", re.I)

def classify(s: str):
    print(f"[*] Classifying: {s[:80]}")
    results = []
    # Base64
    try:
        decoded = base64.b64decode(s)
        if decoded and all(c in string.printable.encode() for c in decoded):
            results.append(("base64", decoded.decode("ascii", errors="replace")))
    except Exception:
        pass
    # Base32
    try:
        decoded = base64.b32decode(s.upper())
        if decoded and all(c in string.printable.encode() for c in decoded):
            results.append(("base32", decoded.decode("ascii", errors="replace")))
    except Exception:
        pass
    # Hex
    try:
        decoded = bytes.fromhex(s)
        if decoded and all(c in string.printable.encode() for c in decoded):
            results.append(("hex", decoded.decode("ascii", errors="replace")))
    except Exception:
        pass
    # URL decode
    try:
        from urllib.parse import unquote
        decoded = unquote(s)
        if decoded != s:
            results.append(("url", decoded))
    except Exception:
        pass
    # ROT13
    decoded = s.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
    if decoded != s:
        results.append(("rot13", decoded))
    # Binary
    if re.match(r"^[01\s]+$", s):
        try:
            binary = s.replace(" ", "")
            decoded = bytes(int(binary[i:i+8], 2) for i in range(0, len(binary), 8))
            if all(c in string.printable.encode() for c in decoded):
                results.append(("binary", decoded.decode("ascii", errors="replace")))
        except Exception:
            pass
    # Morse
    if re.match(r"^[.\-\s/]+$", s):
        MORSE = {'.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9'}
        try:
            words = s.strip().split(" / ")
            decoded = "".join("".join(MORSE.get(c, "?") for c in w.split()) for w in words)
            results.append(("morse", decoded))
        except Exception:
            pass
    if results:
        for enc, val in results:
            print(f"  [+] {enc:10}: {val[:80]}")
    else:
        print("  [-] Tidak terdeteksi encoding umum")
    return results

def solve(s: str, max_depth: int = 5):
    print(f"[*] Auto-solving: {s[:80]}")
    current = s
    chain = []
    for depth in range(max_depth):
        results = classify(current)
        if not results:
            break
        # Pick first result
        enc, decoded = results[0]
        chain.append(enc)
        print(f"  [{depth+1}] {enc}: {decoded[:80]}")
        if FLAG_RX.search(decoded):
            print(f"\n[!!!] FLAG DITEMUKAN: {FLAG_RX.search(decoded).group()}")
            print(f"      Chain: {' -> '.join(chain)}")
            return decoded
        current = decoded
    print("[-] Flag tidak ditemukan dalam", max_depth, "langkah")
    return None

def hashid(h: str):
    print(f"[*] Identifying hash: {h}")
    hashes = {
        32: ["MD5", "MD4", "NTLM", "MD2", "MD4"],
        40: ["SHA1", "SHA-1", "MySQL", "Tiger-160"],
        56: ["SHA-224", "Tiger-192"],
        64: ["SHA-256", "SHA-2-256"],
        96: ["SHA-384"],
        128: ["SHA-512", "SHA-2-512"],
    }
    length = len(h)
    if length in hashes:
        for name in hashes[length]:
            print(f"  [+] Kemungkinan: {name}")
    else:
        print(f"  [-] Hash length tidak dikenal ({length} chars)")
    # Check charset
    if re.match(r"^[0-9a-fA-F]+$", h):
        print("  [+] Charset: hex")
    elif re.match(r"^[0-9a-fA-F$]+$", h):
        print("  [+] Charset: crypt")

def xor_brute(hex_str: str):
    print(f"[*] Single-byte XOR brute: {hex_str}")
    try:
        data = bytes.fromhex(hex_str)
    except Exception:
        print("[-] Invalid hex")
        return
    results = []
    for key in range(256):
        decoded = bytes(b ^ key for b in data)
        if all(c in string.printable.encode() for c in decoded):
            text = decoded.decode("ascii")
            score = sum(1 for c in text if c.isalpha() or c == " ")
            results.append((score, key, text))
    results.sort(reverse=True)
    for score, key, text in results[:5]:
        print(f"  key=0x{key:02x} ({chr(key) if 32 <= key < 127 else '?'}): {text[:80]}")
    if results and FLAG_RX.search(results[0][2]):
        print(f"\n[!!!] FLAG: {FLAG_RX.search(results[0][2]).group()}")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "classify":
        if len(args) < 2:
            print("Usage: misc_solver.py classify <string>")
            return
        classify(args[1])
    elif cmd == "solve":
        p = argparse.ArgumentParser()
        p.add_argument("string")
        p.add_argument("--depth", type=int, default=5)
        a = p.parse_args(args[1:])
        solve(a.string, a.depth)
    elif cmd == "hashid":
        if len(args) < 2:
            print("Usage: misc_solver.py hashid <hash>")
            return
        hashid(args[1])
    elif cmd == "xor":
        if len(args) < 2:
            print("Usage: misc_solver.py xor <hex>")
            return
        xor_brute(args[1])
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
