#!/usr/bin/env python3
"""E2E tests untuk sqli-helper (mock lokal, tanpa network)."""
import subprocess, sys, os

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "sqli_helper.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def test_tamper():
    rc, out, _ = run("tamper", "--payload", "' OR 1=1--")
    assert rc == 0
    assert "' OR 1=1--" in out
    assert "/**/" in out  # comment variant
    assert "%" in out  # URL encoded variant
    print("[PASS] tamper")

def test_tamper_case():
    rc, out, _ = run("tamper", "--payload", "SELECT * FROM users")
    assert rc == 0
    # Should have case variant
    lines = [l for l in out.strip().split("\n") if l.strip()]
    assert len(lines) >= 5, f"Expected 5+ variants, got {len(lines)}"
    print("[PASS] tamper case variants")

def test_tamper_url_encode():
    rc, out, _ = run("tamper", "--payload", "' OR '1'='1")
    assert rc == 0
    assert "%27" in out or "%2527" in out  # URL encoded
    print("[PASS] tamper URL encode")

def test_tamper_comment():
    rc, out, _ = run("tamper", "--payload", "UNION SELECT")
    assert rc == 0
    assert "/**/" in out
    print("[PASS] tamper comment injection")

def test_tamper_space_variants():
    rc, out, _ = run("tamper", "--payload", "OR 1=1")
    assert rc == 0
    assert "+" in out or "%0a" in out or "%09" in out
    print("[PASS] tamper space variants")

def test_help():
    rc, out, _ = run()
    assert "probe" in out
    assert "blind" in out
    assert "tamper" in out
    assert "union" in out
    print("[PASS] help")

if __name__ == "__main__":
    test_tamper()
    test_tamper_case()
    test_tamper_url_encode()
    test_tamper_comment()
    test_tamper_space_variants()
    test_help()
    print("\n=== SEMUA TEST LULUS (6/6) ===")
