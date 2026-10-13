# hosting-tester

Credential tester utk **cPanel** & **FTP** — bagian HOSTING dari rantai.
Nemenin `wp-auth-tester`, tapi protokol & sinyal sukses/gagalnya beda total,
makanya alurnya juga beda dan dipisah sendiri.

```bash
python3 tester.py --target sekolah.sch.id --mode cpanel \
    --users-file u.txt --pass-file p.txt --pace 3 --authorized

python3 tester.py --target sekolah.sch.id --mode ftp \
    --users-file u.txt --pass-file p.txt --rotate tor --authorized
```

## Rantai

```
wordlist-sekolah ──┬── users.txt ──→ wp-recon ──→ wp-auth-tester
                   └── pass FTP/cPanel ────────→ hosting-tester ──→ egress-rotator
```

## Mode

| mode | port default | protokol | sinyal SUKSES | sinyal GAGAL |
|---|---|---|---|---|
| `ftp` | 21 | `ftplib` | `230 User logged in` | `530 Login incorrect` |
| `ftps` | 990 | `ftplib` | idem | idem |
| `cpanel` | 2083 | HTTPS POST `/login/` | `Set-Cookie: cpsession` atau redirect `/home` | masih di halaman login / 401 |
| `cpanel-http` | 2082 | HTTP POST | idem | idem |

`--port` untuk override, `--url` kalau cPanel-nya di belakang reverse proxy.

## Deteksi lockout — beda per protokol

Ini bagian paling penting, karena lockout yang **salah dibaca** bikin kamu
lanjuk nembak waktu server lagi nolak koneksi (bukti jelek + buang-buang egress).

| Protokol | Sinyal lockout | Kenapa gampang salah tafsir |
|---|---|---|
| FTP | `421 Too many connections` | ftplib melempar 4xx sebagai **`error_temp`**, bukan `error_perm`. Salah tangkap = dianggap "koneksi rusak", bukan lockout |
| cPanel | HTTP `429` / "temporarily blocked" | Sering datang dari **CSF/LFD** (firewall host), bukan dari aplikasi — jadi bukan soal password |

**3× lockout beruntun → STOP otomatis.** Jangan dipaksa; tunggu jendela lockout
habis atau putar egress (`--rotate tor --rotate-every 10`).

## Verifikasi (E2E lawan mock)

| Uji | Hasil |
|---|---|
| FTP sukses | ✅ `tu:smantiga2026` → `230 logged in` |
| FTP lockout | ✅ `421` kebaca `⛔`, **STOP setelah 3×** |
| cPanel sukses | ✅ `admin:admin2026` → cookie `cpsession` ke-deteksi |

## Keluaran

- `cracked.txt` — `user:pass` yang tembus (ditulis begitu ketemu)
- `hasil.json` — semua percobaan + durasi, siap jadi evidence

## Catatan

- `--insecure` utk TLS self-signed (hosting sekolah sering begitu)
- `--max N` = batas keras percobaan, wajib dipakai di lingkungan produksi
- `kit_common` cuma punya `http_get` — POST cPanel dibikin lokal di tool ini
- Scope gate fail-closed; localhost selalu diizinkan utk mock
