# ctf-kit — pindah ke ctf-decoder + ctf-crypto

Kit ini sudah DIGABUNG (2026-10-14) biar gak dobel:

- **decode.py, tests.py (18 tes), CHEATSHEET.md** ? pindah ke
  [`kits/ctf-decoder/`](../ctf-decoder/) — digabung dengan base62,
  unicode-escape, hashid, dan dukungan stdin.
- **caesar/xor/vigenere mode cepat** tetap ada di `decode.py`
  (`--caesar` / `--xor` / `--vigenere`).
- **Vigenere panjang-kunci otomatis (IOC) + substitution hill-climb** ?
  [`kits/ctf-crypto/classics.py`](../ctf-crypto/).

Jangan tambah kode baru di sini — ke ctf-decoder / ctf-crypto saja.
