#!/usr/bin/env python3
"""E2E tests untuk defense-counter."""
import subprocess, sys, os

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "defense_counter.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def test_waf():
    rc, out, _ = run("waf", "--target", "https://target.com")
    assert rc == 0
    assert "Cloudflare" in out
    assert "Akamai" in out
    assert "Imperva" in out
    print("[PASS] waf")

def test_ids():
    rc, out, _ = run("ids", "--target", "10.0.0.1", "--port", "80")
    assert rc == 0
    assert "Fragmentation" in out
    assert "Decoy" in out
    assert "source-port" in out
    print("[PASS] ids")

def test_rate():
    rc, out, _ = run("rate", "--url", "https://target.com/api")
    assert rc == 0
    assert "429" in out
    assert "Retry-After" in out
    assert "X-RateLimit" in out
    print("[PASS] rate")

def test_captcha():
    rc, out, _ = run("captcha", "--target", "https://target.com")
    assert rc == 0
    assert "reCAPTCHA" in out
    assert "hCaptcha" in out
    assert "Turnstile" in out
    print("[PASS] captcha")

def test_2fa():
    rc, out, _ = run("2fa", "--target", "https://target.com")
    assert rc == 0
    assert "Session hijacking" in out
    assert "Token reuse" in out
    assert "Race condition" in out
    print("[PASS] 2fa")

if __name__ == "__main__":
    test_waf()
    test_ids()
    test_rate()
    test_captcha()
    test_2fa()
    print("\n=== SEMUA TEST LULUS (5/5) ===")
