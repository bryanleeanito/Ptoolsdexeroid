# wordlist-sekolah

Generator wordlist password khas admin sekolah Indonesia. Murni logika, tanpa jaringan.

```bash
python3 generate.py --sekolah "SMAN 3 Malang" \
    --names-file names.txt --domain smantiga.sch.id \
    --profile all --deep --out wordlist.txt
```

## Yang diturunkan otomatis

**Morphology nama sekolah** — `SMAN 3 Malang` →
`sman3` · `sman3malang` · `sman3_malang` · `smantiga` (sma+n+tiga) · `sma n 3 malang` ·
`smanegeri3malang` · roman `smaniiimalang` · `malang3` · dst (57 varian terukur).

**Nama guru/TU** — baris `Budi Santoso|guru` → `budi` `santoso` `budisantoso`
`b.santoso` `bsantoso` `budi_santoso` + semua mutasi.

**Mutasi** — tempel/hotung tahun (`2026`,`2025`,`1945`,`1973`) dengan pemisah
`_ - . @` dan tanpa pemisah · leet (`a→4 e→3 i→1 o→0 s→5 t→7`) · ekor `123` `!` `2026`.

**Profil**
- `wp` → + kata umum admin (admin/operator/tu/kepsek/sandi/merdeka/qwerty…)
- `cpanel`/`ftp` → pola hosting murah (`ftp` `cpanel` `webmail` `<domain>` `<domain>ftp`)

## Argumen

| Flag | Fungsi |
|---|---|
| `--deep` | tambah mutasi leet (ukuran ~5×) |
| `--min-len` / `--max-len` | saring panjang (default min 4 — `ftp` jadi ke-saring, pakai `--min-len 3`) |
| `--extras` | kata bebas / NIS / NIP dipisah koma |
| `--tahun` | daftar tahun (default `2026,2025,2024,1945,1973,2020`) |

## Verifikasi

E2E: `SMAN 3 Malang --deep --profile all` → **22.997 kata**; `smantiga2026`,
`sman3malang@2025`, `budisantoso2026`, `admin2026`, `smantigaftp` semuanya ada ✓.
