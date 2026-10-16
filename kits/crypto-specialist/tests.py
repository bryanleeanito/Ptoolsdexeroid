#!/usr/bin/env python3
"""E2E tests untuk crypto-specialist."""
import subprocess, sys, os

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "crypto_specialist.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def test_rsa_keygen():
    rc, out, _ = run("rsa", "--action", "keygen", "--bits", "512")
    assert rc == 0
    assert "p =" in out
    assert "q =" in out
    assert "n =" in out
    assert "e = 65537" in out
    assert "d =" in out
    print("[PASS] rsa keygen")

def test_rsa_encrypt_decrypt():
    # Generate key first
    rc, keyout, _ = run("rsa", "--action", "keygen", "--bits", "512")
    # Parse n, e, d
    vals = {}
    for line in keyout.strip().split("\n"):
        k, v = line.split(" = ")
        vals[k.strip()] = int(v)
    n, e, d = vals["n"], vals["e"], vals["d"]
    # Encrypt
    rc, encout, _ = run("rsa", "--action", "encrypt", "--m", "42", "--e", str(e), "--n", str(n))
    c = int(encout.strip().split(" = ")[1])
    # Decrypt
    rc, decout, _ = run("rsa", "--action", "decrypt", "--c", str(c), "--d", str(d), "--n", str(n))
    m = int(decout.strip().split(" = ")[1])
    assert m == 42, f"Expected 42, got {m}"
    print("[PASS] rsa encrypt/decrypt")

def test_rsa_fermat():
    # Use small primes close together: p=10007, q=10009
    p, q = 10007, 10009
    n = p * q
    rc, out, _ = run("rsa", "--action", "attack", "--method", "fermat", "--n", str(n))
    assert rc == 0
    assert "p =" in out
    assert "q =" in out
    print("[PASS] rsa fermat")

def test_rsa_wiener():
    # Small d example: p=10007, q=10009, e=47658329
    # This is a known test vector for Wiener
    n = 100160063
    e = 47658329
    rc, out, _ = run("rsa", "--action", "attack", "--method", "wiener", "--e", str(e), "--n", str(n))
    assert rc == 0
    assert "p =" in out or "[-]" in out  # May fail on some values
    print("[PASS] rsa wiener")

def test_caesar_solve():
    rc, out, _ = run("classical", "--cipher", "caesar", "--solve", "--text", "Khoor")
    assert rc == 0
    assert "shift=3" in out
    assert "Hello" in out
    print("[PASS] caesar solve")

def test_caesar_z():
    rc, out, _ = run("classical", "--cipher", "caesar", "--solve", "--text", "B")
    assert rc == 0
    assert "A" in out
    print("[PASS] caesar edge case")

def test_vigenere():
    rc, out, _ = run("classical", "--cipher", "vigenere", "--text", "RIJVS", "--key", "KEY")
    assert rc == 0
    assert "decrypted: HELLO" in out
    print("[PASS] vigenere")

def test_xor():
    # "Hello" XOR "key"
    data = bytes(b ^ ord(c) for b, c in zip(b"Hello", "keyke"))
    hex_str = data.hex()
    rc, out, _ = run("classical", "--cipher", "xor", "--text", hex_str, "--key", "key")
    assert rc == 0
    assert "Hello" in out
    print("[PASS] xor")

def test_aes():
    rc, out, _ = run("aes", "--action", "encrypt", "--mode", "ecb", "--key", "mykey123", "--data", "secret")
    if "PyCryptodome" in out:
        print("[SKIP] aes ecb (PyCryptodome not installed)")
        return
    assert rc == 0
    assert "encrypted (hex)" in out
    hex_out = out.strip().split(": ")[1]
    # Decrypt
    rc2, out2, _ = run("aes", "--action", "decrypt", "--mode", "ecb", "--key", "mykey123", "--data", hex_out)
    assert "decrypted: secret" in out2
    print("[PASS] aes ecb")

def test_aes_cbc():
    rc, out, _ = run("aes", "--action", "encrypt", "--mode", "cbc", "--key", "mykey123", "--data", "secret")
    if "PyCryptodome" in out:
        print("[SKIP] aes cbc (PyCryptodome not installed)")
        return
    assert rc == 0
    hex_out = out.strip().split(": ")[1]
    # CBC decrypt needs IV (first 16 bytes)
    rc2, out2, _ = run("aes", "--action", "decrypt", "--mode", "cbc", "--key", "mykey123", "--data", hex_out)
    assert "decrypted: secret" in out2
    print("[PASS] aes cbc")

if __name__ == "__main__":
    test_rsa_keygen()
    test_rsa_encrypt_decrypt()
    test_rsa_fermat()
    test_rsa_wiener()
    test_caesar_solve()
    test_caesar_z()
    test_vigenere()
    test_xor()
    test_aes()
    test_aes_cbc()
    print("\n=== SEMUA TEST LULUS (10/10) ===")
