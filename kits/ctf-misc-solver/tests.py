#!/usr/bin/env python3
"""E2E tests untuk ctf-misc-solver."""
import subprocess, sys, os

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "misc_solver.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def test_classify_base64():
    rc, out, _ = run("classify", "SGVsbG8gV29ybGQ=")
    assert "base64" in out
    assert "Hello World" in out
    print("[PASS] classify base64")

def test_classify_hex():
    rc, out, _ = run("classify", "48656c6c6f")
    assert "hex" in out
    assert "Hello" in out
    print("[PASS] classify hex")

def test_classify_rot13():
    rc, out, _ = run("classify", "Uryyb")
    assert "rot13" in out
    assert "Hello" in out
    print("[PASS] classify rot13")

def test_classify_morse():
    rc, out, _ = run("classify", ".... . .-.. .-.. ---")
    assert "morse" in out
    assert "HELLO" in out
    print("[PASS] classify morse")

def test_classify_binary():
    rc, out, _ = run("classify", "01001000 01100101 01101100 01101100 01101111")
    assert "binary" in out
    assert "Hello" in out
    print("[PASS] classify binary")

def test_solve():
    import base64
    flag = "flag{test_solve}"
    encoded = base64.b64encode(flag.encode()).decode()
    rc, out, _ = run("solve", encoded)
    assert "flag" in out.lower() or "FLAG" in out
    print("[PASS] solve")

def test_hashid_md5():
    rc, out, _ = run("hashid", "5f4dcc3b5aa765d61d8327deb882cf99")
    assert "MD5" in out
    print("[PASS] hashid MD5")

def test_hashid_sha1():
    rc, out, _ = run("hashid", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
    assert "SHA1" in out or "SHA-1" in out
    print("[PASS] hashid SHA1")

def test_xor():
    # "Hello World" XOR 0x42
    import binascii
    data = bytes(b ^ 0x42 for b in b"Hello World")
    hex_str = binascii.hexlify(data).decode()
    rc, out, _ = run("xor", hex_str)
    assert "0x42" in out
    assert "Hello World" in out
    print("[PASS] xor")

if __name__ == "__main__":
    test_classify_base64()
    test_classify_hex()
    test_classify_rot13()
    test_classify_morse()
    test_classify_binary()
    test_solve()
    test_hashid_md5()
    test_hashid_sha1()
    test_xor()
    print("\n=== SEMUA TEST LULUS (9/9) ===")
