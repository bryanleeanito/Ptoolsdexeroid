#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rsa.py — solver RSA klasik CTF (offline + lookup factordb opsional).
Input hex atau desimal. Serang otomatis: cek dulu kelemahannya baru eksekusi.

    python rsa.py --n N --e 3 --c C                  # coba semua serangan
    python rsa.py --n N --e E --c C --p P --q Q      # dekrip kalau tau p,q
    python rsa.py --n N --factordb                   # coba factor via factordb
    python rsa.py --pairs p1.txt p2.txt              # common modulus / Hastad
"""
import argparse, json, math, pathlib, re, sys, urllib.request

def isqrt(n):
    return math.isqrt(n)

def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y

def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("tidak punya modular inverse")
    return x % m

def iroot(n, e):
    """Akar e-t-integer: x^e <= n < (x+1)^e."""
    if n < 0:
        return None
    lo, hi = 0, 1 << ((n.bit_length() + e - 1) // e + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** e <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo if lo ** e == n else None

def to_bytes(m):
    if m == 0:
        return b"\x00"
    length = (m.bit_length() + 7) // 8
    return m.to_bytes(length, "big")

def print_flag(m, label):
    b = to_bytes(m)
    try:
        t = b.decode("utf-8")
    except Exception:
        t = b.decode("latin-1", "replace")
    vis = sum(c.isprintable() or c in "\n\r\t" for c in t) / max(len(t), 1)
    print(f"  [{label}] m={m}")
    print(f"  [{label}] text={t[:120]!r} (printable {vis:.0%})")
    return t

# ---------- serangan ----------

def at_small_e(n, e, c):
    """c = m^e mod n, tapi m^e < n -> m = iroot(c, e)."""
    if e > 65535 or e < 2:
        return None  # e besar bukan "small-e" — iroot tidak masuk akal
    m = iroot(c, e)
    if m is not None:
        print(f"[*] SMALL-E: c < n, akar e-integer tepat ketemu!")
        return print_flag(m, "small-e")
    return None

def at_fermat(n):
    """n = p*q dengan p ~ q (fermat factorization)."""
    a = isqrt(n)
    if a * a < n:
        a += 1
    for i in range(1 << 20):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            print(f"[*] FERMAT: p ~ q (selisih {q - p}) -> p={p} q={q}")
            return p, q
        a += 1
    return None

def at_wiener(n, e):
    """Wiener: d kecil -> pecahan berlanjut e/n."""
    def cf(n, d):
        out = []
        while d:
            q = n // d
            out.append(q)
            n, d = d, n % d
        return out

    def conv(a):
        nums, dens = [0, 1], [1, 0]
        for k in a:
            nums.append(k * nums[-1] + nums[-2])
            dens.append(k * dens[-1] + dens[-2])
        return list(zip(nums, dens))

    for k, d in conv(cf(e, n)):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # x^2 - (n-phi+1)x + n = 0
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc >= 0 and isqrt(disc) ** 2 == disc:
            print(f"[*] WIENER: d kecil ketemu d={d}")
            return d
    return None

def at_common_modulus(n, e1, c1, e2, c2):
    """m^e1, m^e2 dengan gcd(e1,e2)=1 -> Bezout -> m."""
    g, a, b = egcd(e1, e2)
    if g != 1:
        print(f"[i] common-modulus: gcd(e1,e2)={g} != 1")
        return None
    if a < 0:
        c1 = modinv(c1, n)
        a = -a
    if b < 0:
        c2 = modinv(c2, n)
        b = -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    print("[*] COMMON-MODULUS: m ketemu!")
    return print_flag(m, "common-mod")

def at_hastad(pairs):
    """Hastad broadcast: c_i = m^e mod n_i, e kecil -> CRT."""
    e = pairs[0][0]
    ns = [p[1] for p in pairs]
    cs = [p[2] for p in pairs]
    if len(pairs) < e:
        print(f"[i] Hastad butuh >= e={e} pasang, cuma {len(pairs)}")
        return None
    N = 1
    for n in ns:
        N *= n
    m_e = 0
    for ni, ci in zip(ns, cs):
        Mi = N // ni
        m_e += ci * Mi * modinv(Mi, ni)
    m_e %= N
    m = iroot(m_e, e)
    if m is not None:
        print("[*] HASTAD: m ketemu via CRT!")
        return print_flag(m, "hastad")
    print("[i] Hastad: m^e > N, perlu lebih banyak pasang atau padding")
    return None

def at_phi(n, p, q, e, c):
    phi = (p - 1) * (q - 1)
    try:
        d = modinv(e, phi)
    except ValueError:
        print(f"[!] gcd(e,phi) != 1 — e={e} tidak valid untuk p,q ini (cek lagi e)")
        return None
    m = pow(c, d, n)
    print(f"[*] DEKrip dengan p,q: d={d}")
    return print_flag(m, "pq")

def at_factordb(n):
    """Lookup factordb.com (butuh internet, pasif)."""
    url = f"http://factordb.com/api?query={n}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ctf-rsa/1.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
        status = data.get("status", "?")
        fac = data.get("factors", [])
        print(f"[*] FACTORDB status={status}")
        if status in ("FF", "CF") and fac:
            for v, exp in fac:
                print(f"    faktor: {v} ^{exp}")
            if all(int(v).bit_length() < 4096 for v, _ in fac):
                vals = [(int(v), int(e)) for v, e in fac]
                print(f"    → jalankan ulang dengan --p <faktor1> --q <faktor2> buat dekrip")
                return vals
        return fac
    except Exception as ex:
        print(f"[!] factordb gagal: {ex}")
        return None

# ---------- driver ----------

def parse_num(s):
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)

def main():
    ap = argparse.ArgumentParser(description="solver RSA klasik CTF")
    ap.add_argument("--n")
    ap.add_argument("--e", default="65537")
    ap.add_argument("--c")
    ap.add_argument("--d")
    ap.add_argument("--p")
    ap.add_argument("--q")
    ap.add_argument("--factordb", action="store_true")
    ap.add_argument("--pairs", nargs="+", help="file json [{e,n,c},...] buat common-modulus/hastad")
    a = ap.parse_args()

    if a.pairs:
        semua = []
        for f in a.pairs:
            semua.append(json.loads(pathlib.Path(f).read_text()))
        # kelompokkan per n utk common-modulus, kelompokkan per e utk hastad
        per_n = {}
        for x in semua:
            per_n.setdefault(x["n"], []).append(x)
        for n, lst in per_n.items():
            if len(lst) >= 2:
                at_common_modulus(n, lst[0]["e"], lst[0]["c"], lst[1]["e"], lst[1]["c"])
        per_e = {}
        for x in semua:
            per_e.setdefault(x["e"], []).append(x)
        for e, lst in per_e.items():
            if len(lst) >= e:
                at_hastad([(x["e"], x["n"], x["c"]) for x in lst])
        return 0

    if not a.n:
        ap.error("butuh --n (atau --pairs)")
    n, e = parse_num(a.n), parse_num(a.e)
    c = parse_num(a.c) if a.c else None

    cinfo = f", c={c.bit_length()} bit" if c else ""
    print(f"[*] n ({n.bit_length()} bit), e={e}{cinfo}")
    # pasangan p,q eksplisit
    if a.p and a.q:
        at_phi(n, parse_num(a.p), parse_num(a.q), e, c)
        return 0
    if a.d:
        d = parse_num(a.d)
        m = pow(c, d, n) if c else None
        if m is not None:
            print_flag(m, "d")
        return 0
    if c is not None:
        at_small_e(n, e, c)
    r = at_fermat(n)
    if r:
        p, q = r
        if c is not None:
            at_phi(n, p, q, e, c)
    if c is not None and e:
        at_wiener(n, e)
    if a.factordb:
        at_factordb(n)
    print("[i] selesai. kalau semua serangan zonk: cek padding/skema lain (OAEP, Rabin, Paillier) atau cari leak p di source.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
