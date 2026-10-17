#!/usr/bin/env python3
"""Verifikasi semua drill bisa diselesaikan pakai kit Ptoolsdexeroid.

Routing per soal sesuai cara main yang diajarkan di README masing-masing:
  d* / c4 / f4  -> ctf-decoder/decode.py  (rantai otomatis)
  c1            -> decode.py --caesar
  c2            -> ctf-crypto/classics.py vigenere (tebak kunci IOC)
  c3            -> decode.py --xor --hex
  r1..r3        -> ctf-crypto/rsa.py (auto-serang: small-e/Fermat/Wiener)
  f1..f3        -> ctf-forensics/probe.py
Jalankan setelah gen_drills.py:  python3 verify_drills.py
"""
import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
KITS = HERE.parent
DECODER = KITS / "ctf-decoder" / "decode.py"
CLASSICS = KITS / "ctf-crypto" / "classics.py"
RSA = KITS / "ctf-crypto" / "rsa.py"
PROBE = KITS / "ctf-forensics" / "probe.py"
JAWABAN = HERE / "jawaban.json"
SOAL = HERE / "soal"


def _run(args, stdin=None):
    r = subprocess.run([sys.executable, *args], capture_output=True,
                       text=True, timeout=90, input=stdin)
    return r.stdout + r.stderr


def cek_auto(path, flag):
    return flag in _run([str(DECODER), "--in", str(path)])


def cek_caesar(path, flag):
    return flag in _run([str(DECODER), "--in", str(path), "--caesar"])


def cek_xor(path, flag):
    return flag in _run([str(DECODER), "--in", str(path), "--xor", "--hex"])


def cek_vigenere(path, flag, kunci=None):
    teks = path.read_text(encoding="utf-8").strip()
    args = [str(CLASSICS), "vigenere", teks]
    if kunci:
        args += ["--key", kunci]
    return flag in _run(args)


def cek_probe(path, flag):
    return flag in _run([str(PROBE), str(path)])


def cek_rsa(path, flag):
    """Parse n/e/c dari file soal -> serang otomatis pakai rsa.py."""
    kv = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([nec])\s*=\s*(\d+)$", line)
        if m:
            kv[m.group(1)] = m.group(2)
    if len(kv) != 3:
        print(f"    (file RSA tidak lengkap: {sorted(kv)})")
        return False
    out = _run([str(RSA), "--n", kv["n"], "--e", kv["e"], "--c", kv["c"]])
    return flag in out


RUTE = {
    "d1_b64.txt": cek_auto,
    "d2_rot_b64.txt": cek_auto,
    "d3_caesar_b64.txt": cek_auto,
    "d4_b64_hex.txt": cek_auto,
    "c1_caesar.txt": cek_caesar,
    "c2_vigenere.txt": cek_vigenere,
    "c3_xor.txt": cek_xor,
    "c4_railfence.txt": cek_auto,
    "r1_small_e.txt": cek_rsa,
    "r2_fermat.txt": cek_rsa,
    "r3_wiener.txt": cek_rsa,
    "f1_komentar.png": cek_probe,
    "f2_zip_komen.zip": cek_probe,
    "f3_nyempil.png": cek_probe,
    "f4_spasi.txt": cek_auto,
}


def main():
    data = json.loads(JAWABAN.read_text(encoding="utf-8-sig"))
    lulus = 0
    for item in data:
        p = SOAL / item["file"]
        cek = RUTE.get(item["file"])
        if not p.exists():
            print(f"  [✗] {item['file']}: file hilang — jalankan gen_drills.py")
            continue
        if cek is None:
            print(f"  [✗] {item['file']}: tak ada rute verifikasi")
            continue
        ok = cek(p, item["flag"], item.get("kunci")) if cek is cek_vigenere \
            else cek(p, item["flag"])
        print(f"  [{'✓' if ok else '✗'}] {item['file']} ({item['kategori']})")
        lulus += ok
    print(f"\n[hasil] {lulus}/{len(data)} drill terverifikasi")
    return 0 if lulus == len(data) else 1


if __name__ == "__main__":
    sys.exit(main())
