# wp-auth-tester

Jembatan `wordlist-sekolah` → eksekusi nyata pada form login WordPress.

```bash
python3 tester.py --url https://target/wp-login.php \
    --user admin --wordlist wordlist.txt --pace 25 --max 40 --authorized
```

## Kenapa bukan hydra biasa

| Fitur | Kenapa penting |
|---|---|
| **Deteksi lockout otomatis** | 429 / "too many attempts" / captcha / Wordfence → **berhenti seketika** (default). Nggak dipaksa, IP nggak makin kotor. |
| **Deteksi sukses pakai sinyal kuat** | cookie `wordpress_logged_in_*` ATAU redirect ke `/wp-admin/` — bukan nebak dari beda panjang body. |
| **Integrasi egress rotator** | `--rotate tor` kirim `SIGNAL NEWNYM` tiap N percobaan; `--rotate pool` geser proxy dari file. |

## Anti-lockout (default)

- `--pace 25` (detik) · `--max 40` (total percobaan)
- Berhenti otomatis saat kena lockout
- `--rotate-every 10` → ganti egress sebelum IP kena blokir permanen

> Jangan diturunkan sembarangan. Kalau target punya WAF/IDS aktif, naikkan pace.

## Field custom

Form bukan standar? Set `--ufield` / `--pfield` (default `log`/`pwd`).
Contoh: `--ufield username --pfield user_pass`.

## Verifikasi

E2E lawan mock lokal:
- ✅ password benar terdeteksi (`SUKSES` + cookie)
- ✅ 429 → `LOCKOUT` + STOP (nggak lanjut nembak)
- ✅ rotasi Tor `NEWNYM` fire tiap N percobaan, lockout tetap kebaca

## Scope

Wajib `--authorized` (atau host di `scope.txt`) — modul ini **aktif & offensive**.
