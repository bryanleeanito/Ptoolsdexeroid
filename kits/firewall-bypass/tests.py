#!/usr/bin/env python3
"""E2E tests untuk firewall-bypass."""
import subprocess, sys, os

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "fw_bypass.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def test_method():
    rc, out, _ = run("method", "--target", "10.0.0.1")
    assert rc == 0
    assert "fragmentation" in out
    assert "decoy" in out
    assert "source_port" in out
    print("[PASS] method")

def test_tunnel_dns():
    rc, out, _ = run("tunnel", "--type", "dns", "--server", "8.8.8.8")
    assert rc == 0
    assert "iodine" in out
    assert "dnscat2" in out
    print("[PASS] tunnel dns")

def test_tunnel_icmp():
    rc, out, _ = run("tunnel", "--type", "icmp", "--server", "10.0.0.1")
    assert rc == 0
    assert "ptunnel" in out
    print("[PASS] tunnel icmp")

def test_tunnel_http():
    rc, out, _ = run("tunnel", "--type", "http", "--server", "10.0.0.1")
    assert rc == 0
    assert "CONNECT" in out
    print("[PASS] tunnel http")

def test_evasion():
    rc, out, _ = run("evasion", "--target", "10.0.0.1")
    assert rc == 0
    assert "fragmentation" in out
    assert "NULL scan" in out
    assert "Decoy" in out
    print("[PASS] evasion")

def test_protocol_dns():
    rc, out, _ = run("protocol", "--proto", "dns")
    assert rc == 0
    assert "iodine" in out
    assert "exfiltration" in out
    print("[PASS] protocol dns")

def test_protocol_icmp():
    rc, out, _ = run("protocol", "--proto", "icmp")
    assert rc == 0
    assert "ptunnel" in out
    print("[PASS] protocol icmp")

def test_test():
    rc, out, _ = run("test", "--target", "10.0.0.1", "--port", "80")
    assert rc == 0
    assert "nmap" in out
    assert "ACK scan" in out
    print("[PASS] test")

if __name__ == "__main__":
    test_method()
    test_tunnel_dns()
    test_tunnel_icmp()
    test_tunnel_http()
    test_evasion()
    test_protocol_dns()
    test_protocol_icmp()
    test_test()
    print("\n=== SEMUA TEST LULUS (8/8) ===")
