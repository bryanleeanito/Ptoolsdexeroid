# sqli-helper v1.0

SQL injection helper buat CTF & authorized penetration testing.

## Perintah

```bash
python3 sqli_helper.py probe --url "http://target/item?id=1" --param id
python3 sqli_helper.py blind --url "http://target/item?id=1" --param id --delay 5
python3 sqli_helper.py tamper --payload "' OR 1=1--"
python3 sqli_helper.py union --url "http://target/item?id=1" --param id
```

## Mode

| Mode | Fungsi |
|---|---|
| `probe` | Error-based detection (18 signature DB) |
| `blind` | Time-based blind (benchmark + threshold) |
| `tamper` | Generate 10+ evasion variants |
| `union` | Column counter (1-20) |

## Signature DB

MySQL, PostgreSQL, SQLite, MSSQL, Oracle, ODBC — 18 error signature.

## Aturan pakai

- **Wajib** ada otorisasi tertulis / CTF scope.
- Jangan production target tanpa izin.
- Output berisi payload — jangan di-commit ke repo publik.
