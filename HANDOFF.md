# HANDOFF.md — status antar mesin

Diperbarui: 2026-10-14 (Tab Rumah)

## Mesin

> **Push sudah jalan (2026-10-13).** Autentikasi via `gh` device flow (scope `repo`/`gist`/`read:org`), remote `origin` = HTTPS. Deploy key SSH opsional — kalau mau dipasang, `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHadAkwkJoRoHgoPmLYqUChiE9lTz3i0DLp9D8we7loY` + centang **Allow write access**.

| Mesin | Peran | Status |
|---|---|---|
| Tab Rumah (box ini) | analisa, OSINT, source-code review, build toolkit | aktif |
| Tab Sekolah | build tools/bypass/payload/exploit di lapangan | kamu |
| BlackArch (ThinkPad L14 G2, Ryzen 5 PRO) | eksekusi aktif, scanning, cracking, pwn | ✅ **FIX** (2026-10-11) |

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
| `secret-scanner` | cari secret ter-hardcode di semua dump (10 pola: private key, AWS/GitHub/Google key, URL-auth, Bearer, Sheet-ID, GAS-ID, JWT, cred hardcode) · **redact by default** · fail-safe binary | **E2E ✓ 10/10 pola** |
| `report-packer` | rangkai output SEMUA kit jadi 1 laporan (deteksi sumber dari kunci JSON, bukan nama file) · **redact-ulang defense in depth** · dedup path | **E2E ✓ 7/7 format** |
| `target-inventory` | katalog target + **generator `scope.txt`** (satu-satunya sumber gerbang fail-closed semua kit) · izin `tertulis` saja yang keluar · `--check` = pre-flight semantik identik `kit_common` | **E2E ✓** |
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


## Target lomba — PLAY IT! PLUS CTF (nasional, daring)

| Milestone | Tanggal |
|---|---|
| Deadline pendaftaran | 09 Nov 2026 (Rp25k/orang, tim 3-5 orang, daftar: bit.ly/CTFPLAYITPLUS) |
| Technical meeting | 10 Nov 2026 |
| **Babak Penyisihan (Jeopardy)** | **14 Nov 2026** |
| Final Day & Awards | 28 Nov 2026 (kemungkinan Attack & Defense) |

Kategori: Web, Crypto, Forensics, Reverse, Binary — semua tercakup kit di atas.

Rencana latihan (prioritas bobot soal jeorpadic umum):
1. **Crypto+decoder** (cepat poin): cryptohack.org + kit sendiri
2. **Web** (bobot terbesar): PortSwigger Academy (SQLi/LFI/SSTI/IDOR) + lab DVWA
3. **Forensics**: zsteg/steghide/binwalk di BlackArch + writeup CTFtime
4. **Pwn**: ret2win → ret2libc → fmt string (pwnable.kr / overthewire)
5. **Reverse**: r2 basic → crackme sederhana
6. **H-3**: simulasi soal jeorpadic lama (CTFtime past events) + rapikan infra

Untuk final A&D (kalau jadi): siapkan kemampuan patching service (audit
source → fix) + exploit service tim lain (sama pakai kit web/pwn yang ada).

## CTF kits — persiapan lomba jeorpadic online (2026-10-14)

Semua kategori kecakup: web, OSINT, crypto, forensics, misc/encoding, pwn/rev.

| Kit | Fungsi | Verifikasi |
|---|---|---|
| `ctf-decoder` | pembongkar lapisan encoding: 17 decoder (base64/32/58/62/85, hex, url, morse, rot13, …) + skor+flag-ketat stop, `--caesar`/`--xor`/`--vigenere`, `--hashid`, 18 tes E2E, CHEATSHEET | **E2E ✓ 18/18 tes** (merge ctf-kit Tab Sekolah + fitur Tab Rumah) |
| `ctf-crypto` | caesar/vigenere(xor/subst hill-climb) + RSA solver (small-e, Fermat, Wiener, common-modulus, Hastad, factordb) | **E2E ✓** caesar/xor/vigenere/small-e/fermat/wiener |
| `ctf-forensics` | magic 40+ format, entropi, EXIF+GPS detect, chunk PNG, hidden-data setelah IEND/FFD9/trailer, ZIP/PDF | **E2E ✓** after-IEND + tEXt + zip comment |
| `ctf-web` | header+keamanan, JWT auto-decode, comment/form/hidden, leak path scan, --js endpoint+key | smoke lokal ✓ |
| `ctf-pwn` | checklist workflow + `prep_blackarch.sh` (pwntools/gdb/ropper/one_gadget/r2) | jalankan di BlackArch saat ada internet |
| `ctfd-solver` | solver CTFd universal: login (token/form+nonce), list, fetch attachment, sweep flags.json, autosolve rantai-decode | **E2E mock 6/6 ✓** |

Target aktif: **ctf.smkpgri3malang.web.id** (akun leeanito, peringkat 3).
⚠️ 2026-10-14: situsnya 500 di route login/HTML (API scoreboard jalan) —
server-side bug, lapor panitia. Solver sudah siap begitu balik:
`export CTF_URL=... CTF_USER=leeanito CTF_PASS=...` lalu `python3 ctfd.py list`.

Rantai kerja jeorpadic:
```
soal misc ──── ctf-decoder (decode sampai flag)
soal crypto ── ctf-crypto classics → rsa.py --n/--e/--c → factordb
soal web ───── ctf-web recon → (manual: Burp/ffuf SQLi/LFI/SSTI)
soal forensic ─ ctf-forensics probe --all → (stego berat: blackarch zsteg/steghide)
soal pwn ───── prep_blackarch.sh sekali → gdb/pwntools/r2 di BlackArch
soal osint ─── osint-kzldx (sudah matang)
```

Catatan: `--factordb` butuh internet; sisanya offline semua.

## Status BlackArch — ✅ SELESAI (2026-10-11)

Dua masalah berurutan sudah beres lewat pipeline copy-partisi→fix→restore:
1. **Login loop** (9–10 Okt): session cache XFCE corrupt + `.dmrc` salah →
   dibersihkan, **i3 dipasang** sebagai session utama.
2. **SDDM mati** (11 Okt): partial upgrade Qt6 (base 6.12 vs declarative 6.11 →
   `libQt6Qml.so.6: undefined symbol`, status=127) → 7 paket Qt6 di-sejajarkan
   ke 6.12.0-1, fprintd dimask. Verifikasi 22/22 sample MD5.

Aturan anti-ulang: **jangan `pacman -Sy <paket>`** — selalu `pacman -Syu` dulu
(full update) baru install, atau `pacman -Syu <paket>` sekali jalan.
