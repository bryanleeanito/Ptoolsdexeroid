# wp-recon

Pra-recon WordPress — bagian **depan** rantai. Tugasnya nyediakan username valid
dan tahu target pakai WAF apa, sebelum `wp-auth-tester` nembak.

```bash
python3 recon.py --url https://target.sch.id --pace 1.5 --authorized
```

## Rantai penuh

```
wp-recon ─┬─ users.txt ──────────────┐
          └─ fingerprint (WAF/versi) ┼→ wp-auth-tester → egress-rotator
                                     │
wordlist-sekolah ── wordlist.txt ────┘
```

## Yang dilakukan (semua GET, tanpa brute-force)

### 1. Username enum
- REST `/wp-json/wp/v2/users?per_page=100` — sering kebuka tanpa auth
- Author archive `/?author=N` → redirect ke `/author/<slug>/`

Hasil ditulis ke `users.txt` (format langsung dipakai `tester.py --users-file`).

### 2. Fingerprint
- `wp-content/plugins/<slug>/readme.txt` → **Stable tag** = versi
- `wp-content/themes/<slug>/style.css` → Theme Name + Version
- meta `generator` → versi WordPress

Plugin yang dicek karena relevan: `elementor`, `elementor-pro`, `divi`,
`wordfence`, `wp-file-manager`, `duplicator`, `contact-form-7`, `wpforms-lite`.
Versi di sini yang nentuin **relevansi CVE** (mis. Elementor Pro 4.2.1).

### 3. Deteksi WAF → saran pace
Baca header (`cf-ray`, `server`, `x-sucuri-id`, …) + keberadaan plugin Wordfence.

| Kondisi | Rekomendasi |
|---|---|
| Wordfence / Cloudflare ada | `--pace 60` + `--rotate tor --rotate-every 5` |
| bersih | `--pace 25` |

Rekomendasi ini langsung dicetak siap tempel ke `tester.py`.

## Keluaran

- `users.txt` — username valid
- `fingerprint.json` — versi plugin/tema, header, catatan WAF

## Verifikasi

E2E lawan mock WP: 2 username kebaca · `elementor-pro v4.2.1` terdeteksi ·
wordfence + cf-ray → saran pace 60s ✓ · tema Astra + WP 6.4.2 ✓

## Scope

Butuh `--authorized` atau host di `scope.txt`.
