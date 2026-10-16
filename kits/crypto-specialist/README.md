# crypto-specialist v1.0

Toolbox cryptography specialist — RSA, AES, ECC, classical ciphers, hash crack.

## Perintah

```bash
# RSA
python3 crypto_specialist.py rsa --action keygen --bits 2048
python3 crypto_specialist.py rsa --action encrypt --m 42 --e 65537 --n N
python3 crypto_specialist.py rsa --action decrypt --c C --d D --n N
python3 crypto_specialist.py rsa --action attack --method fermat --n N
python3 crypto_specialist.py rsa --action attack --method wiener --e E --n N
python3 crypto_specialist.py rsa --action attack --method small-e --c C --e 3 --n N

# AES
python3 crypto_specialist.py aes --action encrypt --mode ecb --key mykey123 --data "secret"
python3 crypto_specialist.py aes --action decrypt --mode ecb --key mykey123 --data HEX

# Classical
python3 crypto_specialist.py classical --cipher caesar --solve --text "Khoor"
python3 crypto_specialist.py classical --cipher vigenere --text "cipher" --key "key"
python3 crypto_specialist.py classical --cipher xor --text "1a2b3c" --key "key"

# Hash
python3 crypto_specialist.py hash --hash HASH --wordlist wl.txt --format md5
```

## RSA Attacks

| Attack | Kondisi |
|---|---|
| small-e | e=3, m^3 < n |
| fermat | p dan q dekat |
| wiener | d kecil (< n^0.25) |
| common-modulus | 2 ciphertext, beda e, sama n |
| hastad | broadcast, e kecil, beda n |

## AES

- ECB dan CBC mode
- PKCS7 padding
- Key: string → bytes
- **Butuh PyCryptodome** (`pip install pycryptodome`) — auto-skip dengan pesan kalau belum ada

## Classical

- Caesar (brute 26 shift + frequency score)
- Vigenere (decrypt dengan key)
- XOR (hex → bytes)
- Substitution (mapping custom)

## Hash Crack

- hashcat & john wrapper
- Format: md5, sha1, sha256, sha512, ntlm

## Aturan pakai

- RSA keygen: default 2048-bit (4096 untuk production)
- Hash crack: butuh hashcat/john di BlackArch
- Classical: offline, no deps
