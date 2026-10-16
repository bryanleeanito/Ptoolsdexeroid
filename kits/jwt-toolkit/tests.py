#!/usr/bin/env python3
"""E2E tests untuk jwt-toolkit."""
import json, subprocess, sys, os

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "jwt_toolkit.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def test_decode():
    # Buat token valid dulu
    _, out, _ = run("forge", "--payload", '{"user":"test","role":"user"}', "--alg", "HS256", "--secret", "secret123")
    tok = out.strip()
    assert tok.count(".") == 2, "Token harusnya 3 segment"
    rc, out2, _ = run("decode", tok)
    assert rc == 0
    assert '"user": "test"' in out2
    assert '"alg": "HS256"' in out2
    print("[PASS] decode")

def test_verify():
    _, out, _ = run("forge", "--payload", '{"user":"admin"}', "--alg", "HS256", "--secret", "secret123")
    tok = out.strip()
    rc, out2, _ = run("verify", tok, "--secret", "secret123")
    assert "VALID" in out2
    rc, out3, _ = run("verify", tok, "--secret", "wrong")
    assert "INVALID" in out3
    print("[PASS] verify")

def test_forge_none():
    _, out, _ = run("forge", "--payload", '{"user":"admin","role":"admin"}', "--alg", "none")
    tok = out.strip()
    assert tok.endswith("."), "alg=none harusnya ada trailing dot"
    rc, out2, _ = run("decode", tok)
    assert '"role": "admin"' in out2
    print("[PASS] forge alg=none")

def test_forge_hs256():
    _, out, _ = run("forge", "--payload", '{"sub":"1234"}', "--alg", "HS256", "--secret", "key")
    tok = out.strip()
    rc, out2, _ = run("verify", tok, "--secret", "key")
    assert "VALID" in out2
    print("[PASS] forge HS256")

def test_crack():
    # Buat token dengan secret known
    _, out, _ = run("forge", "--payload", '{"user":"victim"}', "--alg", "HS256", "--secret", "password123")
    tok = out.strip()
    # Buat wordlist
    wl = os.path.join(KIT_DIR, "_test_wordlist.txt")
    with open(wl, "w") as f:
        f.write("wrong1\nwrong2\npassword123\nwrong3\n")
    rc, out2, _ = run("crack", tok, "--wordlist", wl)
    assert "password123" in out2
    os.remove(wl)
    print("[PASS] crack")

def test_attack_none():
    _, out, _ = run("forge", "--payload", '{"admin":true}', "--alg", "none")
    tok = out.strip()
    rc, out2, _ = run("attack", tok)
    assert "CRITICAL" in out2
    assert "alg=none" in out2
    print("[PASS] attack: alg=none detection")

def test_attack_weak_secret():
    _, out, _ = run("forge", "--payload", '{"user":"test"}', "--alg", "HS256", "--secret", "123456")
    tok = out.strip()
    wl = os.path.join(KIT_DIR, "_test_wordlist.txt")
    with open(wl, "w") as f:
        f.write("admin\n123456\npassword\n")
    rc, out2, _ = run("attack", tok, "--secret-file", wl)
    assert "HIGH" in out2
    assert "123456" in out2
    os.remove(wl)
    print("[PASS] attack: weak secret detection")

def test_attack_kid():
    _, out, _ = run("forge", "--payload", '{"user":"test"}', "--alg", "HS256", "--secret", "x", "--header", '{"kid":"../../etc/passwd"}')
    tok = out.strip()
    rc, out2, _ = run("attack", tok)
    assert "path traversal" in out2
    print("[PASS] attack: kid path traversal")

if __name__ == "__main__":
    test_decode()
    test_verify()
    test_forge_none()
    test_forge_hs256()
    test_crack()
    test_attack_none()
    test_attack_weak_secret()
    test_attack_kid()
    print("\n=== SEMUA TEST LULUS (8/8) ===")
