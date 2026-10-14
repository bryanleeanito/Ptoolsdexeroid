# ctf-decoder — pembongkar lapisan encoding (misc/crypto/forensics)

Rantai otomatis: di tiap lapis, SEMUA kandidat decoder dijajaki, dinilai
skor keterbacaan (flag{ ketat = menang mutlak), diulang sampai stabil atau
budget node habis. Berhenti SEGERA begitu `flag{...}` asli muncul — bukan
`synt{...}` hasil rot13. Stdlib murni, offline.

Decoder: **base64/64url/32/85/58/62, hex, url, double-url, quoted-printable,
unicode-escape, binary, morse (dengan tanda baca + kurung kurawal), rot13,
atbash, reverse, reverse-baris**. Mode eksplisit: `--caesar` (26 rotasi +
skor), `--xor` (brute 1-byte, tiap kandidat dibongkar rantai dulu), 
`--vigenere KUNCI` (dekripsi, arah otomatis). Bonus: `--hashid` (identifikasi
tipe hash), dukungan stdin.

```bash
python3 decode.py "WmxhZ3s...X0A="        # rantai otomatis
python3 decode.py --in soal.txt
echo "SGVsbG8=" | python3 decode.py       # stdin
python3 decode.py --caesar "khoor zruog"
python3 decode.py --xor "0a1b2c..."       # hex input
python3 decode.py --vigenere "uhos{...}" ctf
python3 decode.py deadbeef... --hashid
python3 tests.py                          # 18 tes E2E, semua offline
```

Bentuk encoding tanpa tool: lihat [CHEATSHEET.md](CHEATSHEET.md).

Merge 2026-10-14: basis skoring+BFS dari `ctf-kit` (Tab Sekolah) +
base62/unicode-escape/hashid/stdin dari versi BFS (Tab Rumah).
Vigenere panjang-kunci otomatis + substitution hill-climb → `ctf-crypto`.
