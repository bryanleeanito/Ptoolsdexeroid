# elementor-scanner

Cari form Elementor yang **nggak kelihatan** di halaman publik (popup / theme-builder).

```bash
python3 scan.py --url https://target.sch.id --auto --pace 2 --authorized
python3 scan.py --url ... --wordlist slugs.txt --cookie "wordpress_logged_in_x=..."
```

## Kenapa perlu

Elementor Pro sering nyimpen form upload di **popup** (CPT `elementor_library`) atau
template theme-builder yang cuma muncul lewat URL eksplisit. Hasilnya: fitur upload
ada dan aktif tapi nggak keindeks di crawl biasa.

## Urutan teknik (murah → mahal)

1. `wp-json/wp/v2/elementor_library?per_page=100` — kalau CPT ke-expose, slug + tipe langsung kelihatan.
2. Sitemap → kumpul slug halaman (biar nggak crawl ulang).
3. `?elementor_library=<slug>` — paksa render popup via query arg.
4. Deteksi `elementor-field-type-upload` / `type="file"` → **kandidat upload**.

Slug non-Elementor (halaman biasa yang balikin 200) otomatis **ditolak** — nggak ada
false positive dari halaman 404 custom.

## Keluaran

- `results.json` — seluruh hasil + CPT
- `README.txt` — daftar hit + URL-nya
- Baris `⚠️ UPLOAD` di console = form dengan field unggahan

## Verifikasi

E2E lawan mock WP: 2 CPT kebaca, 1 form **upload** + 1 popup biasa ketemu,
2 slug sitemap non-Elementor ditolak ✓.

## Scope

Butuh `--authorized` atau host di `scope.txt` (ini langkah aktif).
