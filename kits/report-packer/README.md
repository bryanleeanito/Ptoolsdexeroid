# report-packer v1.0

Rangkai **output semua kit** jadi **satu laporan gabungan**.

```
python3 pack.py --in ~/recon_out --out report_out
python3 pack.py --in a.json b.json --format json
python3 pack.py --in hasil/ --judul "Penjajakan X" --target "x.sch.id"
```

## Kenapa perlu ini

Tiap kit menulis JSON dengan bentuk **berbeda-beda**:

| kit | file | bentuk |
|---|---|---|
| `secret-scanner` | `secrets.json` | `temuan[]` + `jumlah` |
| `elementor-scanner` | `results.json` | `slugs[]` + `hits[]` |
| `hosting-tester` | `hasil.json` | `target`, `total`, `sukses`, `detail[]` |
| `wp-recon` | `fingerprint.json` | `plugin{}`, `header{}`, `waf` |
| `gapps-kit/api_probe` | `api_surface.json` | `url`, `functions[]` |
| `osint-kzldx` | `intel.json` | `{sumber: {topik: [...]}}` |

Sebelumnya tiap hasil harus dibuka satu-satu. Modul ini merangkumnya jadi
satu dokumen + satu JSON agregat.

## Deteksi otomatis

Sumber dikenali dari **kunci khas di dalam isi file**, bukan nama file.
Jadi kamu boleh rename `hasil.json` jadi apa pun — tetap kebaca.

File yang bentuknya nggak dikenali **tidak bikin gagal** — masuk seksi
`lainnya` dan dirender generik.

## Fitur penting

- **Redact ulang (defense in depth)** — packer memindai ulang seluruh isi
  terhadap pola rahasia (AWS/GitHub/Google key, Bearer, private key).
  Kalau ada kit yang lupa redact, nilainya dipotong lagi di sini jadi
  `AKIA..6789 [len 20, REDACTED-ULANG]`. Diverifikasi lewat uji fixture
  yang sengaja berisi secret mentah.
- **Dedup path absolut** — file yang dilewatkan lewat banyak path
  (`--in a.json folder/`) tidak dihitung dua kali.
- **Fail-safe** — file JSON rusak dicatat di seksi "Gagal dibaca",
  bukan menghentikan seluruh proses.

## Output

- `laporan_<timestamp>/laporan.md` — ringkasan + seksi per sumber, siap kirim
- `laporan_<timestamp>/laporan.json` — agregat terstruktur

## Opsi

| flag | fungsi |
|---|---|
| `--in` | file `.json` dan/atau folder (boleh campur, rekursif) — **wajib** |
| `--out` | folder output (default `report_out`) |
| `--format` | `md` / `json` / `both` (default) |
| `--judul` | judul laporan |
| `--target` | nama target (dicetak di kepala laporan) |

## Status uji

E2E lolos (2026-10-13): 7 fixture mewakili 7 format → **7/7 terdeteksi tepat**
(termasuk 1 format tak dikenal masuk `lainnya`), dedup terbukti (8 → 7 file),
redact-ulang terbukti menghapus key AWS mentah dari kedua output.
