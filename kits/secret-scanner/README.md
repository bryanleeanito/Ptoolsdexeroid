# secret-scanner v1.0

Cari **secret / credential ter-hardcode** di hasil dump apa pun — output
`probe.py`, `gviz_fetch.py`, `deobfuscate.py`, capture header, log, CSV.

```
python3 scan.py --in recon_out/ --out scan_out
python3 scan.py --in sheet.csv --ext csv
python3 scan.py --in dump.js --show --i-know    # nilai ASLI (hati-hati)
```

## Kenapa perlu ini

Semua kit di repo ini **menghasilkan dump**. Belum ada yang nyari rahasia
di dalamnya. Kit ini nutup celah itu: setelah recon, jalankan scanner ini
sebelum simpan/lapor.

## 10 pola deteksi

| severity | pola | contoh bentuk |
|---|---|---|
| critical | Private key | `-----BEGIN RSA PRIVATE KEY-----` |
| high | AWS Access Key | `AKIA` + 16 huruf kapital |
| high | GitHub token | `ghp_`/`gho_`/`ghs_` + 36 char, `github_pat_` |
| high | Google API key | `AIza` + 35 char |
| high | URL kredensial | `https://user:pass@host` |
| high | Bearer token | `Bearer <20+ char>` |
| medium | Google Sheet ID | `/spreadsheets/d/<25+ char>` → pintu `gviz_export` |
| medium | GAS script ID | `/macros/s/AKfycb<20+ char>` |
| medium | JWT | `eyJ...<segmen2>.<segmen3>` |
| medium | Credential hardcode | `password: "..."`, `apikey=...`, dst |

## Fitur penting

- **Redact by default** — nilai dipotong jadi `AIza..5q6r (len 39)`.
  Sesuai aturan repo: kredensial asli **tidak boleh** bocor ke laporan/log.
  `--show` **wajib** disertai `--i-know`, kalau tidak tetap di-redact.
- **Fail-safe on binary** — file ber-null-byte / gagal di-decode / >8 MB
  dilewati, bukan di-crash.
- **False-positive filter** — `BUKAN_SECRET` menampilk nilai yang memang
  bukan rahasia (`true`, `null`, `********`, `changeme`, `example`, ...).
- **Tanpa jaringan** — murni analisis lokal. Aman dipakai offline.

## Output

- `scan_out/scan_<timestamp>/secrets.json` — temuan terstruktur
  (`nilai: null` saat redact)
- `scan_out/scan_<timestamp>/report.md` — tabel siap tempel ke laporan

## Opsi

| flag | fungsi |
|---|---|
| `--in` | file atau folder (rekursif) — **wajib** |
| `--out` | folder output (default `scan_out`) |
| `--ext` | filter ekstensi, mis. `html,js,csv` |
| `--min-severity` | `low`/`medium`/`high`/`critical` (default `low`) |
| `--show --i-know` | tampilkan nilai asli |

## Catatan etika

Alat bantu **AUDIT**. Kalau ketemu secret milik orang lain: **jangan dipakai**
— catat, redact, laporkan ke pemiliknya.

## Status uji

E2E lolos (2026-10-13): 10 file contoh → **10/10 pola terdeteksi tepat**,
`********`/`changeme` tidak jadi false positive, file binary dilewati,
redaction terverifikasi di `secrets.json` + `report.md`.
