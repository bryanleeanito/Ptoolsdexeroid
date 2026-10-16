#!/usr/bin/env python3
"""E2E tests untuk extreme-efficiency v2 (T14s G1 tuned)."""
import subprocess, sys, os

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "extreme_mode.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def test_parallel():
    rc, out, _ = run("parallel", "--tools", "echo,echo", "--target", "test")
    assert rc == 0
    assert "Parallel" in out
    print("[PASS] parallel")

def test_cache():
    rc, out, _ = run("cache", "--tool", "echo", "--args", "hello", "--ttl", "60")
    assert rc == 0
    assert "Cache" in out
    print("[PASS] cache")

def test_auto():
    rc, out, _ = run("auto", "--chain", "echo -> cat")
    assert rc == 0
    assert "Auto chain" in out
    print("[PASS] auto")

def test_hwinfo():
    rc, out, _ = run("hwinfo")
    assert rc == 0
    assert "CPU" in out
    assert "Preset" in out
    print("[PASS] hwinfo")

def test_preset_stealth():
    rc, out, _ = run("preset", "--mode", "stealth")
    assert rc == 0
    assert "Stealth" in out
    assert "-T2" in out
    print("[PASS] preset stealth")

def test_preset_balanced():
    rc, out, _ = run("preset", "--mode", "balanced")
    assert rc == 0
    assert "Balanced" in out
    assert "-T3" in out
    print("[PASS] preset balanced")

def test_preset_max():
    rc, out, _ = run("preset", "--mode", "max")
    assert rc == 0
    assert "Max Power" in out
    assert "-T4" in out
    print("[PASS] preset max")

def test_minimize():
    rc, out, _ = run("minimize", "--tool", "nuclei")
    assert rc == 0
    assert "-c" in out
    print("[PASS] minimize")

def test_monitor():
    rc, out, _ = run("monitor", "--pid", "1234")
    assert rc == 0
    assert "top" in out
    print("[PASS] monitor")

def test_schedule():
    rc, out, _ = run("schedule", "--tool", "nmap -sV", "--cron", "0 2 * * *")
    assert rc == 0
    assert "Crontab" in out
    print("[PASS] schedule")

if __name__ == "__main__":
    test_parallel()
    test_cache()
    test_auto()
    test_hwinfo()
    test_preset_stealth()
    test_preset_balanced()
    test_preset_max()
    test_minimize()
    test_monitor()
    test_schedule()
    print("\n=== SEMUA TEST LULUS (11/11) ===")
