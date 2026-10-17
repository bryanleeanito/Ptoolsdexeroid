# ctf-drills — paket latihan jeorpadic (soal + kunci)

15 drill otomatis buat latihan sebelum lomba (PLAY IT! PLUS, 14 Nov).
Semua soal sudah diverifikasi bisa diselesaikan kit Ptoolsdexeroid —
artinya kalau kamu stuck, tooling-nya pasti BUKAN penyebabnya.

## Cara main (urutan penting!)

1. **Kerjakan sendiri dulu** — buka `soal/<file>`, pakai petunjuk di
   `catatan` dalam `jawaban.json` TAPI jangan buka `flag`-nya.
2. Kalau stuck >15 menit, baru pakai kit:
   ```bash
   python3 ../ctf-decoder/decode.py --in soal/d1_b64.txt          # rantai otomatis
   python3 ../ctf-decoder/decode.py --in soal/c1_caesar.txt --caesar
   python3 ../ctf-decoder/decode.py --in soal/c3_xor.txt --xor --hex
   python3 ../ctf-crypto/classics.py vigenere "$(cat soal/c2_vigenere.txt)" --key merdeka
   python3 ../ctf-crypto/rsa.py --n <n> --e <e> --c <c>   # r1–r3, serang otomatis
   python3 ../ctf-forensics/probe.py soal/f1_komentar.png
   ```
3. Baru boleh buka `jawaban.json` buat cek.

## Isi

| file | kategori | teknik |
|---|---|---|
| d1_b64.txt | decoder | base64 polos |
| d2_rot_b64.txt | decoder | rot13 → base64 |
| d3_caesar_b64.txt | decoder | caesar k=7 → base64 |
| d4_b64_hex.txt | decoder | base64 → hex |
| c1_caesar.txt | crypto | caesar k=13 (brute) |
| c2_vigenere.txt | crypto | vigenere key=merdeka (decrypt) |
| c3_xor.txt | crypto | xor 1-byte, input hex |
| c4_railfence.txt | crypto | rail fence k=3 |
| r1_small_e.txt | crypto | RSA small-e (m^3 < n → integer root) |
| r2_fermat.txt | crypto | RSA Fermat (p ~ q) |
| r3_wiener.txt | crypto | RSA Wiener (d kecil) |
| f1_komentar.png | forensics | chunk tEXt PNG |
| f2_zip_komen.zip | forensics | komentar ZIP |
| f3_nyempil.png | forensics | data setelah IEND |
| f4_spasi.txt | forensics | stego spasi/tab (0/1) |

## Regenerasi / verifikasi ulang

```bash
python3 gen_drills.py      # tulis ulang soal/ + jawaban.json (deterministik)
python3 verify_drills.py   # buktiin semua masih bisa diselesaikan kit
```

## Rencana 4 minggu (ringkas)

- **Minggu 1**: d1–d4 + c1, c3 — kuasai `decode.py` (auto + `--caesar`/`--xor`).
- **Minggu 2**: c2, c4 + drill RSA r1–r3 (small-e, Fermat, Wiener —
  semua otomatis di `ctf-crypto/rsa.py`).
- **Minggu 3**: f1–f4 — kuasai `probe.py`; lanjut ke `ctf-web/recon_ctf.py`.
- **Minggu 4**: simulasi — minta teman bikin soal, atau daftar room picoCTF
  / CTFtime buat latihan timing. Jangan lupa `ctf-pwn/prep_blackarch.sh`.
