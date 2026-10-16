#!/usr/bin/env python3
"""E2E tests untuk elementor-bypass."""
import subprocess, sys, os

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "elementor_bypass.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def test_rest():
    rc, out, _ = run("rest", "--url", "https://target.com", "--action", "cpt")
    assert rc == 0
    assert "/wp-json/wp/v2/types" in out
    assert "elementor_library" in out
    print("[PASS] rest")

def test_template():
    rc, out, _ = run("template", "--url", "https://target.com", "--id", "123")
    assert rc == 0
    assert "elementor_library" in out
    assert "preview" in out.lower()
    print("[PASS] template")

def test_form():
    rc, out, _ = run("form", "--url", "https://target.com", "--id", "456")
    assert rc == 0
    assert "elementor_pro_forms_send_form" in out
    assert "nonce" in out.lower()
    print("[PASS] form")

def test_upload():
    rc, out, _ = run("upload", "--url", "https://target.com", "--file", "shell.php")
    assert rc == 0
    assert "Double extension" in out
    assert "Null byte" in out
    assert "Magic bytes" in out
    print("[PASS] upload")

def test_auth():
    rc, out, _ = run("auth", "--url", "https://target.com")
    assert rc == 0
    assert "nonce" in out.lower()
    assert "AJAX" in out
    assert "Privilege escalation" in out
    print("[PASS] auth")

if __name__ == "__main__":
    test_rest()
    test_template()
    test_form()
    test_upload()
    test_auth()
    print("\n=== SEMUA TEST LULUS (5/5) ===")
