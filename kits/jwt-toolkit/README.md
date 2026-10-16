# jwt-toolkit v1.0

Decode/verify/forge/crack JWT buat CTF & web app testing.

## Perintah

```bash
python3 jwt_toolkit.py decode <token>
python3 jwt_toolkit.py verify <token> --secret <secret>
python3 jwt_toolkit.py forge --payload '{"user":"admin","role":"admin"}' --alg none
python3 jwt_toolkit.py crack <token> --wordlist wordlist.txt
python3 jwt_toolkit.py attack <token> --secret-file wordlist.txt
```

## Yang bisa dideteksi

| Attack | Keterangan |
|---|---|
| `alg=none` | Signature bypass total |
| Weak secret | Brute HMAC dari wordlist |
| `kid` path traversal | `../../etc/passwd` di kid header |
| `kid` injection | Template/SQL di kid |
| `jku`/`x5u` | URL injection di header |
| Alg confusion | RS256→HS256 (butuh pub key) |
| Expired token | Cek `exp` claim |

## Aturan pakai

- Pakai hanya di target terotorisasi / CTF arena.
- Output crack = credential → jangan di-commit.
