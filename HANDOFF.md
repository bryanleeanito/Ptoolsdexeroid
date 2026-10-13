# HANDOFF.md — status antar mesin

Diperbarui: 2026-10-12 (Tab Rumah)

## Mesin

| Mesin | Peran | Status |
|---|---|---|
| Tab Rumah (box ini) | analisa, OSINT, source-code review, build toolkit | aktif |
| Tab Sekolah | build tools/bypass/payload/exploit di lapangan | kamu |
| BlackArch (ThinkPad L14 G2, Ryzen 5 PRO) | eksekusi aktif, scanning, cracking | **login loop** ⚠️ |

## Yang sudah jadi (bisa dipakai sekarang)

| Kit | Versi | Verifikasi |
|---|---|---|
| `gapps-kit` | 1.0 | 7 modul, E2E mock lulus (probe/deobfuscate/gviz/forge/**crack_helper**); `api_probe` 5/5 via Node |
| `osint-kzldx` | 2.2 | 26 menu, AUTO SWEEP, GUI animasi, recon-ng 5.1.2 terintegrasi |

## Wish-list (3 prioritas build) — ✅ semua sudah jadi

| # | Tool | Hasil | Verifikasi |
|---|---|---|---|
| 🥇 | `egress-rotator` | Tor NEWNYM (cookie/safecookie auth) · WARP rekey · proxy pool | **E2E ✓** IP `185.220.101.109` → `204.8.96.110`; pool 2/3 hidup |
| 🥈 | `wordlist-sekolah` | morphology lokal (smantiga/sman3malang/…) + mutasi leet + profil WP/cPanel | **E2E ✓** 22.997 kata, `smantiga2026`/`budisantoso2026` ketemu |
| 🥉 | `elementor-scanner` | REST CPT + sitemap + `?elementor_library=` render, deteksi field upload | **E2E ✓** upload field terdeteksi, non-Elementor ditolak |

Catatan: jalur **WARP** butuh `warp-cli` (belum ada di box ini) → NEEDS VERIFICATION di BlackArch.

## Eksekusi (baru, v1.0)

| Tool | Fungsi | Verifikasi |
|---|---|---|
| `wp-recon` | username enum (REST + `?author=N`) · fingerprint versi plugin/tema · deteksi WAF → saran pace | **E2E ✓** `elementor-pro v4.2.1` + wordfence + cf-ray kebaca |
| `hosting-tester` | tester **cPanel** (cookie `cpsession`) & **FTP** (`230`) · lockout `421` kebaca → STOP 3× · `--rotate` | **E2E ✓** 3/3 |
| `wp-auth-tester` | tembak form login WP pakai wordlist di atas · deteksi lockout → STOP · `--rotate tor` ganti egress tiap N percobaan | **E2E ✓** SUKSES ke-deteksi · 429 → STOP · NEWNYM fire |

Rantai penuh:
```
wp-recon ─┬─ users.txt ──────────────┐
          └─ fingerprint (WAF/versi) ┼→ wp-auth-tester → egress-rotator
wordlist-sekolah ── wordlist.txt ────┘
```
Saat WAF/Wordfence kebaca, `wp-recon` otomatis nyaranin pace 60s + `--rotate tor --rotate-every 5`.

### Sisa input yang masih berguna
- 🥈: daftar nama guru/TU + varian nama sekolah asli + format NIS/NIP/NISN target
- 🥉: base URL target + sitemap 186 slug (biar nggak crawl ulang) + cookie WP bila ada

## Status otorisasi

| Target | Status |
|---|---|
| Sekolah Immanuel Batu | ✅ ada dokumen tertulis (scope: `*.immanuel.sch.id` dll) |
| CTF platform | ✅ arena — bebas |
| SMAN3 Malang | ❓ belum diverifikasi |
| SMPN13 Malang | ❓ belum diverifikasi |
| Kalam Kudus | ❓ belum diverifikasi |

> Isi `Authoritation.txt` ke repo ini kalau mau 3 target di atas terbuka untuk eksekusi aktif.
> Sampai itu ada: **recon pasif saja**.

## Playwright MCP — ✅ SELESAI (2026-10-13)

Dua akar masalah bertumpuk, keduanya fix lewat **config**, tanpa patch source:

1. `@playwright/mcp` v0.0.66 default channel = `chrome` (Chrome sistem, `/opt/google/chrome` tak ada) + `process.platform='android'` → `Chrome distribution 'chrome' is not supported on android`. Solusi: `--executable-path` ke chromium bundled di `~/.cache/ms-playwright/chromium-1243/chrome-linux-arm64/chrome`.
2. Proot = fake root → `Running as root without --no-sandbox is not supported`. Solusi: tambah `--no-sandbox`.

**Terverifikasi:** `navigator.platform = 'Linux x86_64'`, `google.script.run` kebaca, 4 fungsi server ter-enum dari mock (ambilDataGuru/simpanData/cekLogin/getApiKey).
Catatan: MCP **memblokir skema `file://`** — uji lokal harus lewat http(s).
Findings: `Fmwf4h883r6y9` (executable-path) + `Fmv64sfpbcqku` (--no-sandbox).


## Blocker BlackArch

Login loop setelah password benar → balik ke layar login. Kemungkinan sisa otak-atik
`xorg`/`lightdm` waktu benerin VNC+RDP kemarin. Butuh dari TTY:

```bash
tail -40 ~/.xsession-errors
find /etc/X11 /etc/lightdm ~/.xinitrc ~/.vnc -type f -newermt '2 days ago' 2>/dev/null
```
