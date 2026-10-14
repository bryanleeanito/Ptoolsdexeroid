# crypto-kit v1.0

Penyelesai **cipher & kripto** untuk kategori kriptografi CTF. Offline penuh,
stdlib murni — `Cryptodome` dipakai kalau ada, tapi bukan syarat.

```
python3 solve.py "khoor zruog"                 # auto: coba semua metode
python3 solve.py --caesar "..."
python3 solve.py --substitution "..."          # alfabet tunggal (hill-climb)
python3 solve.py --xor "0a1b2c..."             # 1 byte + kunci berulang
python3 solve.py --vigenere "..."              # deteksi panjang kunci sendiri
python3 solve.py --rail "..."                  # rail fence
python3 solve.py --transposisi "..."           # transposisi kolom
python3 solve.py --hash 5d41402abc4b2a76... --wordlist list.txt
python3 solve.py --rsa --n N --e E --c C       # serangan RSA
python3 solve.py --rsa --n n1 --n n2 --e E     # gcd antar modulus
python3 solve.py --aes --hex 53616c7361...     # deteksi ECB/CBC
python3 tests.py                               # 28 tes
```

Tiap penyelesai mengembalikan **daftar kandidat terurut**, bukan satu jawaban.
Di CTF soalnya sering ambigu — kamu yang memutuskan mana yang masuk akal.

## Kenapa begini, bukan pakai tool jadi

Tiga masalah yang muncul waktu bikin, dan semuanya membuat hasil terlihat
"sudah benar" padahal belum:

1. **Substitution nyangkut di local optimum.** Hill-climb frekuensi huruf
   berhenti dengan 2–4 huruf langka masih tertukar (`BROWN`→`LROJN`,
   `QUICK`→`QUIFP`) — huruf seperti j/q/z/x muncul sekali jadi sinyal
   statistiknya tipis. Dua perbaikan:
   - Statistik bigram/trigram **dibangun dari korpus yang ditanam di file
     ini**, bukan tabel angka mati. Angka yang dikarang sendiri bikin
     skornya "mungkin" tapi bukan bahasa.
   - **Tahap akhir berbasis kosakata**: hitung kata yang dikenal, lalu tukar
     pasangan huruf selama jumlahnya naik. Sinyalnya diskret, jadi huruf
     langka tadi terkunci begitu kata yang benar muncul.
2. **Nilai delta harus inkremental.** Versi pertama membangun ulang plaintext
   tiap kali satu pasangan ditukar → O(panjang) per evaluasi → 40 restart ×
   325 swap jadi puluhan juta operasi. Sekarang hanya bigram/trigram yang
   *mengandung* huruf tertukar yang dihitung ulang.
3. **RSA butuh modulus yang memang dirancan bisa ditembus.** Tes yang memakai
   prima acak 2048-bit cuma membuktikan "tak bisa dipecahkan". Setiap serangan
   di kit ini diuji pada kasus yang sengaja dirancan lemah (e kecil, faktor
   bersama, d kecil, p ≈ q, p-1 halus).

## Serangan RSA yang tersedia

| metode | syarat | dipicu otomatis oleh |
|---|---|---|
| akar pangkat | `m^e < n` | `--rsa` |
| faktor bersama | ≥2 modulus punya prima sama | `--n n1 --n n2` |
| Wiener | `d` kecil | `--rsa` |
| Fermat | `p` dan `q` berdekatan | `--rsa` |
| Pollard p-1 | `p-1` hanya berfaktor halus | `--rsa` |

Kalau ada `pubkey.pem` berisi banyak kunci, ekstrak semua `n` lalu masukkan
sekaligus — serangan faktor bersama cuma bisa jalan kalau `n`-nya dikumpulkan.

## Deteksi hash

Panjang hex menentukan algoritma: `32` md5/ntlm · `40` sha1 · `56` sha224 ·
`64` sha256 · `96` sha384 · `128` sha512 · `8`/`16` berarti **truncated**,
bukan kriptografis. Pemecahan memakai wordlist + mutasi (kapitalisasi,
dibalik, akhiran angka/simbol).

## Status uji

`python3 tests.py` — **28/28 PASS, ~25 detik**, nol jaringan, nol file eksternal.

| kelompok | isi |
|---|---|
| round-trip | caesar 26 rotasi · vigenere 4 kunci · rail 2..8 · transposisi 2..12 |
| solver | caesar · vigenere auto-detect · rail · transposisi · substitusi (termasuk cipher huruf besar) |
| XOR | 1 byte · kunci berulang (panjang L terdeteksi via IC) |
| RSA | e kecil · faktor bersama · Wiener · Fermat · Pollard p-1 |
| hash | identifikasi md5/sha1/sha256/sha512 · crack · mutasi kata |
| AES | ECB terdeteksi · tak false-positive |
| kontrak | regex `flag{...}` · stdlib saja · CLI tolak input kosong · `--rsa` wajib `--n` |

### Bug yang ketahuan waktu menulis tes

Tesnya sendiri yang menangkapnya — layak dicatat karena semuanya lolos review
sekali baca:

- **Miller-Rabin salah rumus.** Versi awal berhenti mengkuadrat di `i=s-2` dan
  melewatkan `i=s-1` (eksponen `(n-1)/2`) → **false negative pada prima
  asli**. Karena diuji dengan 7 basis, prima jadi langka: **146 detik** untuk
  menghasilkan satu prima 512-bit (131.397 kandidat). Setelah diperbaiki ke
  pengkuadratan berulang: **0,012 detik**, dan prima yang dihasilkan
  terverifikasi ulang lewat MR 12-basis independen.
- **Fixture Pollard p-1 tak memastikan kandidatnya prima.** `kelipatan faktor
  kecil + 1` bisa komposit — tesnya bisa "lulus" tanpa membuktikan apa pun.
- **Fixture Fermat** memakai `if _prima_lokal.__name__ and ...` — selalu
  bernilai benar, jadi loop berhenti di kandidat yang belum tentu prima.

## Batasan

- Substitusi teks pendek (< ±80 huruf) memang ambigu — hasil terbaik yang
  diberikan bisa saja huruf langka masih tertukar. Untuk akurasi lebih tinggi,
  sediakan kamus besar: `--kamus /usr/share/dict/words`.
- **Vigenère tidak menebak kunci**; `--vigenere KUNCI` untuk kunci eksplisit,
  tanpa argumen untuk deteksi otomatis.
- RSA tak menyerang kunci 2048-bit yang sehat — memang tidak ada jalur yang
  masuk akal. Kit ini hanya menangkap parameter yang salah.
- AES hanya mendeteksi mode dan mendekripsi bila kuncinya sudah diketahui.
