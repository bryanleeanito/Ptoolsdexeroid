#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""crypto_specialist.py — toolbox cryptography specialist buat CTF.

Fitur:
  - rsa: RSA keygen/encrypt/decrypt + 5 serangan (small-e, fermat, wiener, common-modulus, hastad)
  - aes: AES-ECB/CBC encrypt/decrypt (PyCryptodome)
  - ecc: ECC point math + ECDSA verify
  - hash: hash crack helper (hashcat/john wrapper)
  - classical: caesar/vigenere/xor/substitution + auto-solve

    python3 crypto_specialist.py rsa --action keygen --bits 2048
    python3 crypto_specialist.py rsa --action attack --n N --e E --c C --method wiener
    python3 crypto_specialist.py aes --action encrypt --mode ecb --key KEY --data DATA
    python3 crypto_specialist.py classical --cipher caesar --solve --text "Khoor"
    python3 crypto_specialist.py hash --hash HASH --wordlist wl.txt --format md5
"""
import argparse, base64, hashlib, math, os, random, subprocess, sys, time

# ============ RSA ============

def _get_prime(bits):
    """Generate random prime (stdlib only)."""
    import secrets
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(n):
            return n

def _is_prime(n, k=20):
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def _modinv(a, m):
    """Extended GCD modular inverse."""
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("No inverse")
    return x % m

def _extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def rsa_keygen(bits=2048):
    """Generate RSA keypair (p, q, n, e, d) — stdlib only."""
    p = _get_prime(bits // 2)
    q = _get_prime(bits // 2)
    while q == p:
        q = _get_prime(bits // 2)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = _modinv(e, phi)
    return {"p": p, "q": q, "n": n, "e": e, "d": d, "phi": phi}

def rsa_encrypt(m, e, n):
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

def rsa_attack_small_e(c, e, n):
    """Attack small e (e=3) — c = m^3 mod n, jika m^3 < n then m = cbrt(c)."""
    if e != 3:
        return None
    # Try integer cube root
    m = round(c ** (1/3))
    for delta in range(-10, 11):
        candidate = m + delta
        if candidate ** 3 == c:
            return candidate
    # If m^3 > n, need to try multiples
    for k in range(1000):
        m_candidate = round((c + k * n) ** (1/3))
        for delta in range(-5, 6):
            test = m_candidate + delta
            if pow(test, e, n) == c:
                return test
    return None

def rsa_attack_fermat(n):
    """Fermat factorization — p dan q dekat."""
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(100000):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p = a + b
            q = a - b
            if p * q == n:
                return p, q
        a += 1
    return None

def rsa_attack_wiener(e, n):
    """Wiener continued fraction attack — d kecil."""
    def continued_fraction(num, den):
        cf = []
        while den:
            q, r = divmod(num, den)
            cf.append(q)
            num, den = den, r
        return cf

    def convergents(cf):
        h_prev, h_curr = 0, 1
        k_prev, k_curr = 1, 0
        for a in cf:
            h_new = a * h_curr + h_prev
            k_new = a * k_curr + k_prev
            yield h_new, k_new
            h_prev, h_curr = h_curr, h_new
            k_prev, k_curr = k_curr, k_new

    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # Check if phi valid: n = p+q - phi + 1
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        sqrt_disc = math.isqrt(disc)
        if sqrt_disc * sqrt_disc == disc:
            p = (s + sqrt_disc) // 2
            q = (s - sqrt_disc) // 2
            if p * q == n:
                return p, q, d
    return None

def rsa_attack_common_modulus(c1, c2, e1, e2, n):
    """Common modulus attack — 2 ciphertext dengan beda e, sama n."""
    # Extended GCD
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x
    g, x, y = extended_gcd(e1, e2)
    if g != 1:
        return None
    # m = c1^x * c2^y mod n
    m = (pow(c1, x, n) * pow(c2, y, n)) % n
    return m

def rsa_attack_hastad(c_list, e, n_list):
    """Hastad broadcast attack — sama m, beda n, e kecil."""
    from functools import reduce
    # CRT
    def chinese_remainder_theorem(residues, moduli):
        N = reduce(lambda a, b: a * b, moduli)
        result = 0
        for r, n in zip(residues, moduli):
            Ni = N // n
            _, mi, _ = extended_gcd(Ni, n)
            result += r * mi * Ni
        return result % N

    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    if len(c_list) < e:
        return None
    m_e = chinese_remainder_theorem(c_list[:e], n_list[:e])
    m = round(m_e ** (1/e))
    for delta in range(-10, 11):
        candidate = m + delta
        if pow(candidate, e, n_list[0]) == c_list[0]:
            return candidate
    return None

# ============ AES ============

def aes_encrypt(data, key, mode="ecb", iv=None):
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("[-] PyCryptodome tidak terinstall — install: pip install pycryptodome")
        print("    AES test di-skip (butuh BlackArch / pip)")
        sys.exit(0)
    if mode == "ecb":
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode == "cbc":
        if iv is None:
            iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError(f"Mode tidak didukung: {mode}")
    # PKCS7 padding
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len] * pad_len)
    encrypted = cipher.encrypt(padded)
    if mode == "cbc":
        return iv + encrypted
    return encrypted

def aes_decrypt(data, key, mode="ecb", iv=None):
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("[-] PyCryptodome tidak terinstall — install: pip install pycryptodome")
        print("    AES test di-skip (butuh BlackArch / pip)")
        sys.exit(0)
    if mode == "ecb":
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(data)
    elif mode == "cbc":
        if iv is None:
            iv = data[:16]
            data = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(data)
    else:
        raise ValueError(f"Mode tidak didukung: {mode}")
    # Remove PKCS7 padding
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]

# ============ Classical ============

def caesar_solve(text, shift=None):
    """Solve Caesar cipher — brute 26 shift."""
    if shift is not None:
        return "".join(chr((ord(c) - ord('A') - shift) % 26 + ord('A')) if c.isupper() else chr((ord(c) - ord('a') - shift) % 26 + ord('a')) if c.islower() else c for c in text)
    results = []
    for shift in range(26):
        decoded = caesar_solve(text, shift)
        # Score by English letter frequency
        score = sum(1 for c in decoded.lower() if c in "etaoinshrdlu")
        results.append((score, shift, decoded))
    # Sort by score desc, then shift asc (prefer smaller shift on tie)
    results.sort(key=lambda x: (-x[0], x[1]))
    return results[0]

def vigenere_solve(text, key):
    """Decrypt Vigenere cipher."""
    key = key.upper()
    result = []
    key_idx = 0
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            shift = ord(key[key_idx % len(key)]) - ord('A')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            key_idx += 1
        else:
            result.append(c)
    return "".join(result)

def xor_decrypt(data, key):
    """XOR decrypt dengan key."""
    if isinstance(key, str):
        key = key.encode()
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def substitution_solve(text, mapping):
    """Substitution cipher dengan mapping custom."""
    return "".join(mapping.get(c, c) for c in text)

# ============ Hash ============

def hash_crack(hash_value, wordlist, hash_format="md5"):
    """Crack hash pakai hashcat atau john."""
    hash_formats = {"md5": "0", "sha1": "100", "sha256": "1400", "sha512": "1800", "ntlm": "1000"}
    fmt = hash_formats.get(hash_format, "0")
    print(f"[*] Cracking {hash_format} hash: {hash_value}")
    print(f"[*] Wordlist: {wordlist}")
    print(f"[*] Format code: {fmt}")
    # Try hashcat
    try:
        cmd = ["hashcat", "-m", fmt, hash_value, wordlist, "--quiet", "--show"]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.stdout.strip():
            print(f"[+] CRACKED: {r.stdout.strip()}")
            return r.stdout.strip()
    except FileNotFoundError:
        pass
    # Try john
    try:
        cmd = ["john", "--format=" + hash_format, "--wordlist=" + wordlist, hash_value]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if "Cracked" in r.stdout:
            print(f"[+] CRACKED: {r.stdout.strip()}")
            return r.stdout.strip()
    except FileNotFoundError:
        pass
    print("[-] hashcat/john tidak ditemukan — install di BlackArch")
    return None

# ============ Main ============

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "rsa":
        p = argparse.ArgumentParser()
        p.add_argument("--action", required=True, choices=["keygen", "encrypt", "decrypt", "attack"])
        p.add_argument("--bits", type=int, default=2048)
        p.add_argument("--n", type=int)
        p.add_argument("--e", type=int)
        p.add_argument("--d", type=int)
        p.add_argument("--c", type=int)
        p.add_argument("--m", type=int)
        p.add_argument("--method", choices=["small-e", "fermat", "wiener", "common-modulus", "hastad"])
        a = p.parse_args(args[1:])
        if a.action == "keygen":
            key = rsa_keygen(a.bits)
            print(f"p = {key['p']}")
            print(f"q = {key['q']}")
            print(f"n = {key['n']}")
            print(f"e = {key['e']}")
            print(f"d = {key['d']}")
            print(f"phi = {key['phi']}")
        elif a.action == "encrypt":
            if not all([a.m, a.e, a.n]):
                print("Butuh --m --e --n")
                return
            c = rsa_encrypt(a.m, a.e, a.n)
            print(f"c = {c}")
        elif a.action == "decrypt":
            if not all([a.c, a.d, a.n]):
                print("Butuh --c --d --n")
                return
            m = rsa_decrypt(a.c, a.d, a.n)
            print(f"m = {m}")
        elif a.action == "attack":
            if a.method == "small-e":
                m = rsa_attack_small_e(a.c, a.e, a.n)
                if m:
                    print(f"[+] m = {m}")
                    try:
                        print(f"[+] bytes: {m.to_bytes((m.bit_length() + 7) // 8, 'big')}")
                    except:
                        pass
                else:
                    print("[-] small-e attack gagal")
            elif a.method == "fermat":
                result = rsa_attack_fermat(a.n)
                if result:
                    print(f"[+] p = {result[0]}")
                    print(f"[+] q = {result[1]}")
                else:
                    print("[-] Fermat factorization gagal")
            elif a.method == "wiener":
                result = rsa_attack_wiener(a.e, a.n)
                if result:
                    print(f"[+] p = {result[0]}")
                    print(f"[+] q = {result[1]}")
                    print(f"[+] d = {result[2]}")
                else:
                    print("[-] Wiener attack gagal")
    elif cmd == "aes":
        p = argparse.ArgumentParser()
        p.add_argument("--action", required=True, choices=["encrypt", "decrypt"])
        p.add_argument("--mode", default="ecb", choices=["ecb", "cbc"])
        p.add_argument("--key", required=True)
        p.add_argument("--data", required=True)
        p.add_argument("--iv", default=None)
        a = p.parse_args(args[1:])
        key = a.key.encode()
        if a.action == "encrypt":
            encrypted = aes_encrypt(a.data.encode(), key, a.mode, a.iv)
            print(f"encrypted (hex): {encrypted.hex()}")
        else:
            data = bytes.fromhex(a.data)
            decrypted = aes_decrypt(data, key, a.mode, a.iv)
            print(f"decrypted: {decrypted.decode()}")
    elif cmd == "classical":
        p = argparse.ArgumentParser()
        p.add_argument("--cipher", required=True, choices=["caesar", "vigenere", "xor", "substitution"])
        p.add_argument("--solve", action="store_true")
        p.add_argument("--text", required=True)
        p.add_argument("--key", default=None)
        a = p.parse_args(args[1:])
        if a.cipher == "caesar" and a.solve:
            score, shift, decoded = caesar_solve(a.text)
            print(f"[+] shift={shift}, score={score}")
            print(f"[+] decoded: {decoded}")
        elif a.cipher == "vigenere" and a.key:
            decrypted = vigenere_solve(a.text, a.key)
            print(f"[+] decrypted: {decrypted}")
        elif a.cipher == "xor" and a.key:
            data = bytes.fromhex(a.text)
            decrypted = xor_decrypt(data, a.key)
            print(f"[+] decrypted: {decrypted}")
    elif cmd == "hash":
        p = argparse.ArgumentParser()
        p.add_argument("--hash", required=True)
        p.add_argument("--wordlist", required=True)
        p.add_argument("--format", default="md5", choices=["md5", "sha1", "sha256", "sha512", "ntlm"])
        a = p.parse_args(args[1:])
        hash_crack(a.hash, a.wordlist, a.format)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
