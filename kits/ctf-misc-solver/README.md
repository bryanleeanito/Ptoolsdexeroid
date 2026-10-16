# ctf-misc-solver v1.0

Auto-classifier + solver buat soal misc CTF.

## Perintah

```bash
python3 misc_solver.py classify "SGVsbG8gV29ybGQ="
python3 misc_solver.py solve "RkxBR3t0ZXN0fQ==" --depth 5
python3 misc_solver.py hashid "5f4dcc3b5aa765d61d8327deb882cf99"
python3 misc_solver.py xor "1b37373331363f78151b7f2b78343133"
```

## Fitur

| Perintah | Fungsi |
|---|---|
| `classify` | Deteksi encoding (base64/32, hex, url, rot13, binary, morse) |
| `solve` | Auto-decode chain sampai ketemu flag |
| `hashid` | Identifikasi jenis hash dari length |
| `xor` | Brute single-byte XOR |

## Encoding support

Base64, Base32, Hex, URL, ROT13, Binary, Morse — 7 decoder.

## Catatan

- `solve` pakai greedy (pick first match) — belum BFS.
- `xor` brute 256 key, rank by printable score.
