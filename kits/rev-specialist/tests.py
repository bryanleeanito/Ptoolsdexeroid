#!/usr/bin/env python3
"""E2E tests untuk rev-specialist."""
import os, struct, subprocess, sys, tempfile

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "rev_specialist.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def make_test_binary():
    """Buat binary test dengan konten menarik."""
    data = bytearray(256)
    # Add some strings
    data[0:5] = b"flag{"
    data[5:10] = b"test}"
    # Add anti-debug string
    data[50:70] = b"IsDebuggerPresent\x00"
    # Add crypto constant (MD5 init)
    data[100:104] = struct.pack("<I", 0x67452301)
    # Add crypto string
    data[150:154] = b"MD5\x00"
    # Add UPX marker
    data[200:204] = b"UPX!"
    return bytes(data)

def test_ghidra():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 100)
        path = f.name
    outpath = path + ".java"
    rc, out, _ = run("ghidra", "--binary", path, "--output", outpath)
    assert rc == 0
    assert os.path.exists(outpath)
    with open(outpath) as f:
        content = f.read()
    assert "analyzeAll" in content
    assert "INTERESTING STRINGS" in content
    os.unlink(path)
    os.unlink(outpath)
    print("[PASS] ghidra")

def test_patch_nop():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 256)
        path = f.name
    rc, out, _ = run("patch", "--binary", path, "--offset", "0x10", "--type", "nop", "--len", "16")
    assert rc == 0
    assert "NOP" in out
    assert os.path.exists(path + ".bak")
    os.unlink(path)
    os.unlink(path + ".bak")
    print("[PASS] patch nop")

def test_patch_jump():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 256)
        path = f.name
    rc, out, _ = run("patch", "--binary", path, "--offset", "0x10", "--type", "jump", "--target", "0x100")
    assert rc == 0
    assert "JMP" in out
    os.unlink(path)
    os.unlink(path + ".bak")
    print("[PASS] patch jump")

def test_patch_shellcode():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 256)
        path = f.name
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x48\x31\xc0")  # xor rax, rax
        sc_path = f.name
    rc, out, _ = run("patch", "--binary", path, "--offset", "0x10", "--type", "shellcode", "--target-file", sc_path)
    assert rc == 0
    assert "Shellcode" in out
    os.unlink(path)
    os.unlink(path + ".bak")
    os.unlink(sc_path)
    print("[PASS] patch shellcode")

def test_protocol():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 100)
        path = f.name
    rc, out, _ = run("protocol", "--file", path, "--fields", "4s,I")
    assert rc == 0
    assert "Hex dump" in out
    assert "4s" in out
    os.unlink(path)
    print("[PASS] protocol")

def test_decompile():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 100)
        path = f.name
    rc, out, _ = run("decompile", "--binary", path, "--function", "main")
    assert rc == 0
    assert "Ghidra" in out
    assert "radare2" in out
    assert "objdump" in out
    os.unlink(path)
    print("[PASS] decompile")

def test_anti_detect():
    data = make_test_binary()
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        path = f.name
    rc, out, _ = run("anti", "--binary", path)
    assert rc == 0
    assert "anti-debug" in out
    assert "UPX" in out
    assert "MD5" in out
    os.unlink(path)
    print("[PASS] anti detect")

def test_anti_clean():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 256)
        path = f.name
    rc, out, _ = run("anti", "--binary", path)
    assert rc == 0
    assert "Tidak ada" in out
    os.unlink(path)
    print("[PASS] anti clean")

if __name__ == "__main__":
    test_ghidra()
    test_patch_nop()
    test_patch_jump()
    test_patch_shellcode()
    test_protocol()
    test_decompile()
    test_anti_detect()
    test_anti_clean()
    print("\n=== SEMUA TEST LULUS (8/8) ===")
