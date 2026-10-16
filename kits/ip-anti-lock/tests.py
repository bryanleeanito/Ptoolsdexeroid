#!/usr/bin/env python3
"""E2E tests untuk ip-anti-lock."""
import subprocess, sys, os

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "anti_lock.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def test_delay():
    rc, out, _ = run("delay", "--base", "1.0", "--max", "60.0", "--attempts", "5")
    assert rc == 0
    assert "Exponential" in out
    assert "jitter" in out
    print("[PASS] delay")

def test_rotate():
    rc, out, _ = run("rotate", "--ips", "1.1.1.1,2.2.2.2", "--interval", "30")
    assert rc == 0
    assert "1.1.1.1" in out
    assert "2.2.2.2" in out
    print("[PASS] rotate")

def test_headers():
    rc, out, _ = run("headers", "--count", "3")
    assert rc == 0
    assert "User-Agent" in out
    assert "Accept" in out
    print("[PASS] headers")

def test_session():
    rc, out, _ = run("session", "--cookies", "a=1,b=2")
    assert rc == 0
    assert "a=1" in out
    assert "b=2" in out
    print("[PASS] session")

def test_fingerprint():
    rc, out, _ = run("fingerprint", "--count", "2")
    assert rc == 0
    assert "User-Agent" in out
    assert "Accept-Language" in out
    print("[PASS] fingerprint")

if __name__ == "__main__":
    test_delay()
    test_rotate()
    test_headers()
    test_session()
    test_fingerprint()
    print("\n=== SEMUA TEST LULUS (5/5) ===")
