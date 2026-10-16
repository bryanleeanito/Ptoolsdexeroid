#!/usr/bin/env python3
"""E2E tests untuk rev-toolkit."""
import os, struct, subprocess, sys, tempfile

KIT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(KIT_DIR, "rev_toolkit.py")

def run(*args):
    r = subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

def make_elf():
    """Buat minimal ELF64 header."""
    elf = bytearray(64)
    elf[0:4] = b"\x7fELF"
    elf[4] = 2  # 64-bit
    elf[5] = 1  # little endian
    elf[6] = 1  # ELF version
    # e_type=2 (EXEC), e_machine=0x3E (x86_64)
    struct.pack_into("<H", elf, 16, 2)
    struct.pack_into("<H", elf, 18, 0x3E)
    # e_version
    struct.pack_into("<I", elf, 20, 1)
    # e_entry = 0x400000
    struct.pack_into("<Q", elf, 24, 0x400000)
    # e_phoff = 64
    struct.pack_into("<Q", elf, 32, 64)
    # e_shoff = 0
    struct.pack_into("<Q", elf, 40, 0)
    # e_flags
    struct.pack_into("<I", elf, 48, 0)
    # e_ehsize=64, e_phentsize=56, e_phnum=1
    struct.pack_into("<H", elf, 52, 64)
    struct.pack_into("<H", elf, 54, 56)
    struct.pack_into("<H", elf, 56, 1)
    # e_shentsize=64, e_shnum=0, e_shstrndx=0
    struct.pack_into("<H", elf, 58, 64)
    struct.pack_into("<H", elf, 60, 0)
    struct.pack_into("<H", elf, 62, 0)
    return bytes(elf)

def test_strings():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x00\x01\x02hello_world\x00\x03\x04another_string_here\x00")
        f.write(b"\x00\x00\x00\x00short\x00")
        path = f.name
    rc, out, _ = run("strings", path, "--min", "6")
    assert "hello_world" in out
    assert "another_string_here" in out
    assert "short" not in out  # len=5 < min=6
    os.unlink(path)
    print("[PASS] strings")

def test_elf():
    elf = make_elf()
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(elf)
        path = f.name
    rc, out, _ = run("elf", path)
    assert "64-bit" in out
    assert "x86_64" in out
    assert "little" in out
    assert "0x400000" in out
    os.unlink(path)
    print("[PASS] elf")

def test_patch_nop():
    rc, out, _ = run("patch", "--type", "nop", "--offset", "0x400500", "--len", "16")
    assert "0x400500" in out
    assert "0x90" in out
    print("[PASS] patch nop")

def test_patch_shellcode():
    rc, out, _ = run("patch", "--type", "shellcode", "--offset", "0x400500")
    assert "execve" in out
    print("[PASS] patch shellcode")

def test_r2gen():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x7fELF")
        path = f.name
    r2path = path + ".r2"
    rc, out, _ = run("r2gen", path, "--output", r2path)
    assert os.path.exists(r2path)
    with open(r2path) as f:
        content = f.read()
    assert "aaa" in content
    assert "izz~flag" in content
    os.unlink(path)
    os.unlink(r2path)
    print("[PASS] r2gen")

def test_upx_detect():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 20 + b"UPX!" + b"\x00" * 10)
        path = f.name
    rc, out, _ = run("upx", path)
    assert "UPX" in out
    assert "upx -d" in out
    os.unlink(path)
    print("[PASS] upx detect")

def test_upx_clean():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 50)
        path = f.name
    rc, out, _ = run("upx", path)
    assert "Tidak terdeteksi" in out
    os.unlink(path)
    print("[PASS] upx clean")

if __name__ == "__main__":
    test_strings()
    test_elf()
    test_patch_nop()
    test_patch_shellcode()
    test_r2gen()
    test_upx_detect()
    test_upx_clean()
    print("\n=== SEMUA TEST LULUS (7/7) ===")
