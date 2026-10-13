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
| `gapps-kit` | 1.0 | 6 modul, E2E mock lulus semua (probe/deobfuscate/gviz/forge); `api_probe` butuh `playwright` |
| `osint-kzldx` | 2.2 | 26 menu, AUTO SWEEP, GUI animasi, recon-ng 5.1.2 terintegrasi |

## Wish-list (3 prioritas build) — ✅ semua sudah jadi

| # | Tool | Hasil | Verifikasi |
|---|---|---|---|
| 🥇 | `egress-rotator` | Tor NEWNYM (cookie/safecookie auth) · WARP rekey · proxy pool | **E2E ✓** IP `185.220.101.109` → `204.8.96.110`; pool 2/3 hidup |
| 🥈 | `wordlist-sekolah` | morphology lokal (smantiga/sman3malang/…) + mutasi leet + profil WP/cPanel | **E2E ✓** 22.997 kata, `smantiga2026`/`budisantoso2026` ketemu |
| 🥉 | `elementor-scanner` | REST CPT + sitemap + `?elementor_library=` render, deteksi field upload | **E2E ✓** upload field terdeteksi, non-Elementor ditolak |

Catatan: jalur **WARP** butuh `warp-cli` (belum ada di box ini) → NEEDS VERIFICATION di BlackArch.

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

## Blocker BlackArch

Login loop setelah password benar → balik ke layar login. Kemungkinan sisa otak-atik
`xorg`/`lightdm` waktu benerin VNC+RDP kemarin. Butuh dari TTY:

```bash
tail -40 ~/.xsession-errors
find /etc/X11 /etc/lightdm ~/.xinitrc ~/.vnc -type f -newermt '2 days ago' 2>/dev/null
```
