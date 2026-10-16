#!/usr/bin/env python3
"""E2E tests untuk security-protect."""
import subprocess, sys, os

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "security_protect.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def test_headers():
    rc, out, _ = run("headers", "--domain", "example.com")
    assert rc == 0
    assert "Strict-Transport-Security" in out
    assert "Content-Security-Policy" in out
    assert "X-Frame-Options" in out
    print("[PASS] headers")

def test_audit():
    rc, out, _ = run("audit", "--path", "/tmp")
    assert rc == 0
    print("[PASS] audit")

def test_hardening():
    rc, out, _ = run("hardening", "--level", "2")
    assert rc == 0
    assert "Intermediate" in out
    assert "sysctl" in out
    print("[PASS] hardening")

def test_firewall_block():
    rc, out, _ = run("firewall", "--action", "block", "--ip", "10.0.0.1")
    assert rc == 0
    assert "iptables" in out
    assert "nftables" in out
    print("[PASS] firewall block")

def test_firewall_allow():
    rc, out, _ = run("firewall", "--action", "allow", "--ip", "10.0.0.1")
    assert rc == 0
    assert "iptables" in out
    print("[PASS] firewall allow")

def test_monitor():
    rc, out, _ = run("monitor", "--log", "/var/log/apache2/access.log")
    assert rc == 0
    assert "SQLi" in out
    assert "XSS" in out
    assert "fail2ban" in out
    print("[PASS] monitor")

def test_backup():
    rc, out, _ = run("backup", "--source", "/var/www", "--dest", "/backup")
    assert rc == 0
    assert "rsync" in out
    assert "integrity" in out
    print("[PASS] backup")

if __name__ == "__main__":
    test_headers()
    test_audit()
    test_hardening()
    test_firewall_block()
    test_firewall_allow()
    test_monitor()
    test_backup()
    print("\n=== SEMUA TEST LULUS (7/7) ===")
