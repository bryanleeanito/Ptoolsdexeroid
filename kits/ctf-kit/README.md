# ctf-kit v1.0

Pembongkar **lapisan encoding** untuk kategori *misc / crypto* — satu perintah
membongkar rantai penuh, tanpa nebak-nebak urutannya. Stdlib murni, tanpa
jaringan.

```
python3 decode.py "WmxhZ3s...X0A="          # rantai otomatis (default)
python3 decode.py --in soal.txt
python3 decode.py --caesar "iodj{g3f0g3...}"   # putar 26 rotasi, skor terbaik
python3 decode.py --xor "0a1b2c..."            # brute 1 byte key
python3 decode.py --vigenere ctf --in cipher.txt    # dekripsi Vigenère
python3 decode.py "..." --max-layer 12 --show-candidate
python3 tests.py                               # 18 tes
```

Cara mengenali bentuk encoding tanpa tool: [`CHEATSHEET.md`](CHEATSHEET.md).

## Kenapa perlu ini

Di hampir semua soal *misc*, teks dibungkus **beberapa** lapis. Membongkar
manual berarti menebak-nebak urutan, dan tiap salah tebak harus mulai lagi.

Masalahnya bukan "belum ketemu decoder yang tepat" — decoder base64 ada di
mana-mana. Masalahnya **keputusan berhenti**:

1. **Lapis antara bisa jadi skornya lebih tinggi dari teks aslinya.**
   String hex dan string base64 entropinya tinggi, chi-squared-nya kebetulan
   bagus. Karena itu pendekatan *"terus decode selama hasilnya makin
   terbaca"* **berhenti setelah satu lapis** — persis yang terlihat pada soal
   4 lapis pada tes di bawah.
   Kit ini memakai **BFS**: semua jalur dijelajahi, berhenti segera begitu
   `flag{...}` asli muncul (jalur terpendek menang).
2. **Hasil XOR sering masih ter-encode.** XOR 0x42 atas `base64(flag)` tidak
   menghasilkan flag — menghasilkan teks base64, yang skornya *rendah* karena
   tak punya kosakata. Kalau peringkat hanya memakai skor mentah, key yang
   benar kalah dari sampah. Karena itu `--xor` **membongkar tiap kandidat
   sampai habis dulu**, baru diberi peringkat; `flag{` menang mutlak.
3. **Rot13 dan Caesar punya bentuk `{...}` yang sama.** `synt{q3p0q3...}`
   kena pola "mirip flag". Menandainya sebagai FLAG menghasilkan laporan
   palsu. Kit ini memisah: `flag{` prefix ketat = **FLAG KETEMU**, pola
   `{x}` asing = **"bentuk mirip, cek manual"** — dan tetap menjelajah sampai
   ke prefix ketat bila memang ada.

## Decoder yang didukung

| jenis | catatan |
|---|---|
| base64, base64url, base32, base85, base58 | termasuk varian URL-safe |
| hex, url, double-url, quoted-printable | |
| binary (8-bit), morse | morse pakai pemisah huruf vs kata yang benar |
| rot13, atbash, caesar (brute 26) | caesar otomatis masuk kandidat tiap lapis |
| reverse string, reverse-baris | |
| xor 1-byte (brute 256), vigenère (butuh kunci) | mode eksplisit |

## Pemisahan sinyal flag

```python
FLAG_KETAT  = flag|ctf|picoctf|hackthebox|htb|ductf|thm|...{...}   # yakin
FLAG_LONGGAR = <kata apa pun>{...}   # cuma bentuknya mirip
```

`decode.py` tidak pernah mengklaim `FLAG KETEMU` untuk yang kedua.

## Aturan berhenti

- **Batas lapis** `--max-layer` (default 8, maks 64) dan **budget node** 400.
- `terkunjung` mencegah oscilasi (reverse lalu reverse balik).
- Cabang dibatasi 2 kandidat terbaik per lapis supaya tak meledak.
- Kalau akhirnya tak ada `flag{` **dan** nol kosakata ≥3 huruf, skrip menulis
  `[!]` peringatan bahwa kemungkinan itu cuma sampah yang diputar-putar.

## Status uji

`python3 tests.py` — **18/18 PASS**, ~0.5 detik, nol dependensi, nol jaringan.

| tes | yang dijaga |
|---|---|
| rantai otomatis 11 soal | base64, 4 lapis, caesar, hex, double-url, morse, binary, reverse, rot13, 3 lapis campur |
| berhenti di `flag{` ketat | `synt{...}` (rot13) tak dianggap selesai |
| `--caesar` / geser 0 | geser 0 tak diklaim FLAG |
| `--xor` key benar tetap menang | key 0x42 atas base64-flag |
| `--vigenere` arah | `dekripsi(enkripsi(x)) == x` |
| teks polos STOP | input terbaca tak diputar jadi sampah |
| sampah | tak menghasilkan flag palsu, tapi tetap diberi peringatan |
| morse | pemisah huruf vs kata tak tertukar |
| batas & error | `--max-layer` dibatasi, input kosong ditolak, file hilang ditangani (bukan traceback), `--out` menulis |
| kontrak | format `{x}` asing tak diklaim FLAG, stdlib saja |

## Batasan

- **Tidak** mendekripsi AES/DES — butuh key dari soal.
- **Vigenère** tidak menebak kunci; harus diberi eksplisit.
- Morse `{`/`}` bukan standar ITU — tiap soal bisa beda simbol. Lihat
  [`CHEATSHEET.md`](CHEATSHEET.md) §3.
