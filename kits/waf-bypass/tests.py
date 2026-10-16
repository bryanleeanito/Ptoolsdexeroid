#!/usr/bin/env python3
"""E2E tests untuk waf-bypass."""
import subprocess, sys, os

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "waf_bypass.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def test_encode_url():
    rc, out, _ = run("encode", "--payload", "' OR 1=1--", "--method", "url")
    assert rc == 0
    assert "%27" in out
    print("[PASS] encode url")

def test_encode_double_url():
    rc, out, _ = run("encode", "--payload", "' OR 1=1--", "--method", "double-url")
    assert rc == 0
    assert "%2527" in out
    print("[PASS] encode double-url")

def test_encode_hex():
    rc, out, _ = run("encode", "--payload", "A", "--method", "hex")
    assert "41" in out
    print("[PASS] encode hex")

def test_encode_unicode():
    rc, out, _ = run("encode", "--payload", "A", "--method", "unicode")
    assert "u0041" in out or "U0041" in out.upper()
    print("[PASS] encode unicode")

def test_encode_space2comment():
    rc, out, _ = run("encode", "--payload", "SELECT * FROM users", "--method", "space2comment")
    assert "/**/" in out
    print("[PASS] encode space2comment")

def test_encode_mixed():
    rc, out, _ = run("encode", "--payload", "hello", "--method", "mixed")
    assert rc == 0
    print("[PASS] encode mixed")

def test_headers():
    rc, out, _ = run("headers", "--target", "http://target/test")
    assert rc == 0
    assert "X-Forwarded-For" in out
    assert "X-Real-IP" in out
    assert "Googlebot" in out
    print("[PASS] headers")

def test_chunked():
    rc, out, _ = run("chunked", "--payload", "GET /admin HTTP/1.1")
    assert rc == 0
    assert "Transfer-Encoding" in out or "chunked" in out.lower()
    print("[PASS] chunked")

def test_json():
    rc, out, _ = run("json", "--payload", '{"id":"1"}')
    assert rc == 0
    assert "application/json" in out
    print("[PASS] json")

def test_fuzz():
    rc, out, _ = run("fuzz", "--param", "id", "--values", "1,2,3")
    assert rc == 0
    assert "id=1" in out
    print("[PASS] fuzz")

if __name__ == "__main__":
    test_encode_url()
    test_encode_double_url()
    test_encode_hex()
    test_encode_unicode()
    test_encode_space2comment()
    test_encode_mixed()
    test_headers()
    test_chunked()
    test_json()
    test_fuzz()
    print("\n=== SEMUA TEST LULUS (10/10) ===")
