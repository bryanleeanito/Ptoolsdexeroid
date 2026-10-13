# Ptoolsdexeroid

Gudang toolkit + jembatan handoff antar mesin (Tab Rumah ↔ Tab Sekolah ↔ BlackArch).
Dibuat 2026-10-12.

## Struktur

```
kits/
├── gapps-kit/       v1.0  — bypass Google Apps Script web app (6 modul)
├── osint-kzldx/     v2.2  — suite OSINT 26 menu + AUTO SWEEP + GUI animasi
├── egress-rotator/  v1.0  — Tor NEWNYM · WARP rekey · proxy pool (E2E ✓)
├── wordlist-sekolah/v1.0  — kamus password sekolah Indonesia (E2E ✓)
└── elementor-scanner/v1.0 — cari form Elementor tersembunyi (E2E ✓)
HANDOFF.md             — status antar mesin + wish-list input
```

## Cara pakai antar mesin

```bash
# sekali saja di mesin baru
git clone https://github.com/bryanleeanito/Ptoolsdexeroid.git
cd Ptoolsdexeroid

# ambil update terbaru
git pull

# pakai kit
python3 kits/gapps-kit/probe.py --help
python3 "kits/osint-kzldx/osint.py" --help
```

## Aturan repo

1. **Token/API key = env var aja.** Nggak pernah di-commit, nggak pernah di config.
   `.gitignore` sudah jaga `*.token`, `.secrets/`, `*.env`.
2. **Output kerja (`*_out/`, `gapps_*/`, dumps) jangan di-commit** — itu evidence, bukan source.
3. Kit pakai **scope gate fail-closed**: modul aktif butuh `--authorized` atau host ada di
   `scope.txt`. Eksekusi aktif cuma untuk target terotorisasi.
4. `kits/osint-kzldx/` dulunya bernama `Osint by kzldx` — diganti biar path tanpa spasi
   (mulus buat git/rsync).

## Changelog

- **2026-10-13** — tambah 3 kit: `egress-rotator`, `wordlist-sekolah`, `elementor-scanner` (semua E2E mock/lokal ✓).
- **2026-10-12** — repo dibuat. `gapps-kit` v1.0 + `osint-kzldx` v2.2 masuk.
