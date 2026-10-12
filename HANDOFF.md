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

## Wish-list (3 prioritas build)

| # | Tool | Input yang dibutuhkan |
|---|---|---|
| 🥇 | Egress rotator | (a) punya WARP+ key / VPN / proxy list? (b) IP sekolah NAT atau sendiri? (c) confirm jalan di BlackArch |
| 🥈 | Wordlist sekolah ID | varian nama sekolah · daftar nama guru/TU · format NIS/NIP/NISN · tahun penting · username valid yang sudah diketahui |
| 🥉 | Elementor hidden-form scanner | base URL · cookie/nonce WP **atau** izin unauth crawl · konfirmasi versi Pro 4.2.1 · sitemap 186 slug |

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
