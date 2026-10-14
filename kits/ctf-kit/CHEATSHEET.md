# CHEATSHEET — identifikasi encoding & rumus cepat CTF

Pendamping [`decode.py`](decode.py). Isinya buat **kamu yang menatap layar
dan bingung ini bentuk apa** — bukan untuk dijalankan.

---

## 1. Kenali dari bentuknya (lihat sekali, langsung tahu)

| Ciri yang kelihatan | Kemungkinan | Perintah |
|---|---|---|
| `QmFzZTY0...` huruf campur, `+`/`=` di ekor | **base64** | `python3 decode.py "..."` |
| `...-` di ekor pakai `-` `_` | **base64url** (JWT, token) | otomatis terdeteksi |
| huruf kapital semua + `234567` + `=` | **base32** | otomatis |
| `c3RyaW5n` polos, semua huruf kecil+angka | **base58** (bitcoin) | otomatis |
| `666c6167...` hanya `0-9a-f`, panjang genap | **hex** | otomatis |
| `%66%6c%61%67` ada `%`+2 hex | **URL encoding** | otomatis |
| `01100110...` hanya `0`/`1`, panjang kelipatan 8 | **binary** | otomatis |
| `..-. .-.. .- --.` titik-garis | **morse** | otomatis |
| `...=` ada `=` tapi bukan `=` ekor base64 | **quoted-printable** (email) | otomatis |
| `}synt{` baca mundur | **reverse string** | otomatis |
| `synt{` tiap huruf mundur 13 | **rot13** | otomatis |
| `iodj{` huruf digeser rata | **caesar** | `--caesar` |
| `WmxhZ3s` campur tapi semua huruf | **caesar/xor/vigenere** | `--caesar` / `--xor` |
| `n` besar + `e` kecil, angka raksasa | **RSA** → lihat §4 | manual |
| `PD9waH...` di dalam JPEG/PNG | **file diselipkan** → `binwalk`/`foremost` | manual |
| teks acak, entropi tinggi, ada header aneh | **AES/openssl** → cari key di soal | manual |

> Aturan praktis: **kalau hasil decode-nya masih berbentuk seperti daftar di
> atas, artinya masih ada lapis lagi.** Jalankan ulang `decode.py` — dia
> memang sengaja mengulang sampai berhenti sendiri.

---

## 2. Perintah Python sekali jalan (tanpa file)

```python
# decode apapun cepat
python3 -c "import base64,sys;print(base64.b64decode(sys.argv[1]))" 'QmFzZTY0'

# semua rotasi caesar sekaligus
python3 -c "
t='khoor'
for k in range(26):
    print(k, ''.join(chr((ord(c)-97+k)%26+97) if c.islower() else c for c in t))"

# xor brute 1 byte (kalau hex)
python3 -c "
import sys; r=bytes.fromhex(sys.argv[1])
for k in range(256):
    d=bytes(x^k for x in r)
    if d.isascii() and d.decode().isprintable(): print(hex(k), d)" '0a1b2c'

# balik string
python3 -c "print('FLAG'[::-1])"

# hex -> ascii
python3 -c "print(bytes.fromhex('666c6167'))"

# rot13 cepat
python3 -c "import codecs,sys;print(codecs.encode(sys.argv[1],'rot_13'))" 'synt'
```

---

## 3. Morse (tabel lengkap, termasuk ekstensi soal CTF)

`decode.py` memakai tabel ini persis. Spasi tunggal = **pemisah huruf**,
`/` atau 2 spasi = **pemisah kata**.

```
A .-      B -...    C -.-.    D -..     E .      F ..-.
G --.     H ....    I ..      J .---    K -.-    L .-..
M --      N -.      O ---     P .--.    Q --.-   R .-.
S ...     T -       U ..-     V ...-    W .--    X -..-
Y -.--    Z --..
0 -----   1 .----   2 ..---   3 ...--   4 ....-  5 .....
6 -....   7 --...   8 ---..   9 ----.
. .-.-.-  , --..--  ? ..--..  ! -.-.--  - ....-  / -..-.
" .-..-.  $ ...-..- @ .--.-.  = -...-   + .-.-.
{ -...-.  } -...--  _ ..--.-  ( -.--.   ) -.--.-   [ekstensi CTF]
```

> `{` `}` `_` **bukan morse ITU** — tiap soal bisa pakai simbol lain.
> Kalau `decode.py` bilang "tak ada lapis", coba ganti pemetaan kurung
> kurawal dengan simbol yang dipakai soalmu.

---

## 4. RSA — jalur cepat

Cek berurutan, berhenti begitu ketemu:

1. **`e = 3` dan `m^e < n`** → cukup akar pangkat tiga, tanpa faktorisasi.
   ```python
   python3 -c "print(round(pow(c,1/3),-3))"   # cek dengan integer cube root
   ```
2. **`n` kecil** (< 2^40) → `factordb.com`, atau `RsaCtfTool`.
3. **`n` berbagi faktor** dengan `n` lain di soal → `gcd(n1, n2)`.
4. **`d` kecil** → Wiener attack (`RsaCtfTool --Wiener`).
5. **`p` dan `q` dekat** → `(p-q)` kecil, coba `isqrt(n)` lalu geser.
6. **`p-1` / `q-1` halus** → Pollard's p-1.

Kalau sudah keluar `p`,`q`:
```python
d = pow(e, -1, (p-1)*(q-1))
m = pow(c, d, n)
```

---

## 5. Yang sering bikin nyangkut

| Gejala | Penyebab sebenarnya |
|---|---|
| decode sukses tapi isinya masih acak | **ada lapis lagi** — jalankan `decode.py` ulang |
| `--xor` tak ketemu key | hasilnya masih base64 → `decode.py` sudah menangani ini; kalau manual, decode dulu baru XOR |
| morse jadi `F L A G { ... }` | pemisah huruf/kata tertukar → lihat §3 |
| `--vigenere` hasilnya makin jauh | arahnya kebalik — dekripsi harus **geser mundur** |
| base64 gagal di `openssl` | padding `=` hilang atau input punya newline |
| `flag` ketat tak kena | prefix bukan daftar umum → cek bentuk `{...}` di output `decode.py` |

---

## 6. Batasan yang perlu kamu tahu

- `decode.py` **tidak** mendekripsi AES/DES — butuh key dari soal.
- **Vigenère** butuh kunci eksplisit (`--vigenere KUNCI`); tidak ditebak.
- Morse punya ambigu soal `{`/`}` — lihat catatan di §3.
- Kalau rantai menghasilkan teks tapi **nol kosakata umum**, skrip memberi
  peringatan `[!]` — kemungkinan itu sampah yang diputar-putar, bukan jawaban.
