# ctf-decoder — chain decoder serbaguna (misc/encoding)

Auto-detect + decode berantai (BFS, depth 6): base64/32/58/62/85, hex, URL,
unicode-escape, rot13, atbash, reverse, binary, morse, xor-single-byte.
Deteksi pola flag di tiap tahap. `--hashid` bonus deteksi tipe hash.
Stdlib-only, offline.

```bash
python3 decode.py "RmxhZ3s..."            # string
python3 decode.py --file encoded.txt      # file
echo "SGVsbG8=" | python3 decode.py       # stdin
python3 decode.py deadbeef --hashid       # + identifikasi hash
```

Contoh nyata: input `c3ludHtlYmcxM19xaHloX29uZnI2NF95bnR2fQ==` →
rantai `base64 → rot13` → `flag{rot13_dulu_base64_lagi}` ketemu otomatis.
