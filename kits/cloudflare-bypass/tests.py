#!/usr/bin/env python3
"""E2E tests untuk cloudflare-bypass."""
import subprocess, sys, os

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "cf_bypass.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def test_origin():
    rc, out, _ = run("origin", "--domain", "target.com")
    assert rc == 0
    assert "SecurityTrails" in out
    assert "Censys" in out
    assert "crt.sh" in out
    print("[PASS] origin")

def test_header():
    rc, out, _ = run("header", "--target", "https://target.com/admin")
    assert rc == 0
    assert "X-Forwarded-For" in out
    assert "CF-Connecting-IP" in out
    assert "Googlebot" in out
    print("[PASS] header")

def test_chunked():
    rc, out, _ = run("chunked", "--payload", "GET /admin HTTP/1.1")
    assert rc == 0
    assert "Transfer-Encoding" in out or "chunked" in out.lower()
    print("[PASS] chunked")

def test_cache():
    rc, out, _ = run("cache", "--url", "https://target.com/?cb=random")
    assert rc == 0
    assert "Cache" in out
    assert "poisoning" in out.lower()
    print("[PASS] cache")

def test_direct():
    rc, out, _ = run("direct", "--ip", "103.56.206.81", "--host", "target.com")
    assert rc == 0
    assert "103.56.206.81" in out
    assert "curl" in out
    print("[PASS] direct")

if __name__ == "__main__":
    test_origin()
    test_header()
    test_chunked()
    test_cache()
    test_direct()
    print("\n=== SEMUA TEST LULUS (5/5) ===")
