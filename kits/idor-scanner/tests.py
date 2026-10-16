#!/usr/bin/env python3
"""E2E tests untuk idor-scanner (mock lokal)."""
import subprocess, sys, os

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "idor_scanner.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def test_help():
    rc, out, _ = run()
    assert "enumerate" in out
    assert "diff" in out
    assert "pattern" in out
    print("[PASS] help")

def test_enumerate_no_network():
    # Test that it handles connection errors gracefully
    rc, out, _ = run("enumerate", "--url", "http://localhost:1/{id}", "--start", "1", "--end", "3")
    assert rc == 0
    assert "ERROR" in out or "Total findings" in out
    print("[PASS] enumerate (no network)")

def test_diff_no_network():
    rc, out, _ = run("diff", "--url-a", "http://localhost:1/a", "--url-b", "http://localhost:1/b")
    assert rc == 0
    print("[PASS] diff (no network)")

def test_pattern_no_network():
    rc, out, _ = run("pattern", "--url", "http://localhost:1/{id}", "--sample", "3")
    assert rc == 0
    print("[PASS] pattern (no network)")

if __name__ == "__main__":
    test_help()
    test_enumerate_no_network()
    test_diff_no_network()
    test_pattern_no_network()
    print("\n=== SEMUA TEST LULUS (4/4) ===")
