#!/usr/bin/env python3
"""E2E tests untuk sherlock-osint (offline-safe)."""
import subprocess, sys, os

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "sherlock.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout, r.stderr

def test_username():
    rc, out, _ = run("username", "--target", "testuser", "--limit", "5")
    assert rc == 0
    assert "platforms" in out
    print("[PASS] username")

def test_email():
    rc, out, _ = run("email", "--target", "john@example.com")
    assert rc == 0
    assert "breach" in out.lower() or "haveibeenpwned" in out
    assert "gravatar" in out.lower() or "Gravatar" in out
    print("[PASS] email")

def test_phone():
    rc, out, _ = run("phone", "--target", "+6281234567890")
    assert rc == 0
    assert "WhatsApp" in out or "wa.me" in out
    assert "Telegram" in out or "t.me" in out
    print("[PASS] phone")

def test_domain():
    rc, out, _ = run("domain", "--target", "example.com")
    assert rc == 0
    assert "WHOIS" in out or "whois" in out
    assert "subfinder" in out
    print("[PASS] domain")

def test_social():
    rc, out, _ = run("social", "--target", "testuser")
    assert rc == 0
    assert "Instagram" in out
    assert "Twitter" in out
    assert "Facebook" in out
    print("[PASS] social")

def test_correlate():
    rc, out, _ = run("correlate", "--username", "johndoe", "--email", "johndoe@example.com")
    assert rc == 0
    assert "MATCHES" in out or "johndoe" in out
    print("[PASS] correlate")

def test_report():
    rc, out, _ = run("report", "--target", "testuser")
    assert rc == 0
    assert "OSINT Report" in out
    assert "Sherlock" in out or "sherlock" in out
    print("[PASS] report")

if __name__ == "__main__":
    test_username()
    test_email()
    test_phone()
    test_domain()
    test_social()
    test_correlate()
    test_report()
    print("\n=== SEMUA TEST LULUS (7/7) ===")
