# ctf-crypto — cipher klasik + RSA solver (offline)

**classics.py**: caesar brute (26 shift + skor keterbacaan), vigenère
(tebak panjang kunci via IOC + refine frekuensi), xor single-byte brute /
key eksplisit, monoalphabetic substitution (hill-climb 120 restart).

**rsa.py**: auto-serang RSA klasik —
- small-e (`m^e < n` → integer root)
- Fermat (p ~ q)
- Wiener (d kecil, pecahan berlanjut)
- common modulus (Bezout)
- Hastad broadcast (CRT)
- dekrip kalau tau p,q
- lookup factordb.com (`--factordb`, butuh internet)

```bash
python3 classics.py caesar "Wkh txlfn eurzq ira…"
python3 classics.py vigenere "uhos{ixcszrga…}" --key lemon
python3 classics.py xor "…" --key 0x42
python3 classics.py subst "xuoqz…" --auto

python3 rsa.py --n N --e 3 --c C          # coba semua serangan
python3 rsa.py --n N --e E --c C --p P --q Q
python3 rsa.py --n N --factordb
python3 rsa.py --pairs p1.json p2.json    # common-modulus / Hastad
```

Verifikasi lokal: caesar ✓ xor ✓ vigenere ✓ rsa small-e ✓ fermat ✓ wiener ✓
