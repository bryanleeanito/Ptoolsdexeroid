#!/usr/bin/env python3
"""E2E tests untuk ip-changer."""
import subprocess, sys, os

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "ip_changer.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def test_rotate_tor():
    rc, out, _ = run("rotate", "--type", "tor", "--count", "3")
    assert rc == 0
    assert "NEWNYM" in out
    assert "9050" in out
    print("[PASS] rotate tor")

def test_rotate_socks5():
    rc, out, _ = run("rotate", "--type", "socks5")
    assert rc == 0
    assert "socks5" in out
    print("[PASS] rotate socks5")

def test_source():
    rc, out, _ = run("source", "--ip", "10.0.0.1")
    assert rc == 0
    assert "X-Forwarded-For" in out
    assert "10.0.0.1" in out
    print("[PASS] source")

def test_geo():
    rc, out, _ = run("geo", "--country", "id")
    assert rc == 0
    assert "Indonesia" in out
    print("[PASS] geo")

def test_mac():
    rc, out, _ = run("mac", "--interface", "eth0")
    assert rc == 0
    assert "02:00:00" in out
    print("[PASS] mac")

def test_check():
    rc, out, _ = run("check")
    assert rc == 0
    assert "ipinfo.io" in out
    print("[PASS] check")

if __name__ == "__main__":
    test_rotate_tor()
    test_rotate_socks5()
    test_source()
    test_geo()
    test_mac()
    test_check()
    print("\n=== SEMUA TEST LULUS (6/6) ===")
