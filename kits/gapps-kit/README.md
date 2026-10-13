# gapps-kit — toolkit bypass Google Apps Script (web app sekolah)

Kit analisa/pentest **authorization & data-exposure** pada Google Apps Script web app
(deployment `/exec`), dibangun dari kasus "Penjajakan Digital". Semua modul `scope-gated`
(fail-closed ke `/root/data/Auth/scope.txt`, override `--authorized`).

> Aturan main: aktif hanya untuk target yang ada izin tertulisnya (bounty scope /
> surat tugas). Pacing anti-lockout default 2s. Jangan commit isi `secrets.txt`,
> `sheet_dumps/`, `resp_*.json` ke mana pun.

## Alur kerja

```
1. probe.py        → audit statis halaman: API surface, Sheet/Drive ID, cookie,
                     password literal di JS, endpoint fetch/XHR   (RECON, aman)
2. deobfuscate.py  → balik atob/fromCharCode/hex → kandidat kredensial hardcoded
3. api_probe.py    → headless: enumerate + panggil google.script.run (privat functions)
4. gviz_fetch.py   → tarik isi Sheet tanpa login (gviz/export/htmlview)
5. forge_cookie.py → enumerasi identitas via Cookie inject + bukti per kandidat
```

Prioritas dampak (dari tertinggi):
`api_probe` (data internal) → `gviz_fetch` (dump sheet) → `forge_cookie` (privilege
escalation ke identitas guru) → `deobfuscate` (bypass client-side password).

## Modul

| File | Fungsi | Status |
|---|---|---|
| `probe.py` | audit statis: surface API, ID Sheet, cookie, password-in-JS | E2E mock ✓ |
| `deobfuscate.py` | decode JS obf → `secrets.txt` | E2E mock ✓ |
| `api_probe.py` | `google.script.run` enumeration + call (playwright) | **JS logika TERBUKTI 5/5** via `verify_api_js.py` (Node, tanpa browser) — wrapper Python butuh `playwright` → BlackArch |
| `verify_api_js.py` | harness: buktikan JS_ENUM/JS_CALL di Node dgn stub | E2E ✓ — nangkep 2 bug false-positive |
| `gviz_fetch.py` | Sheet dump via gviz/export | E2E mock ✓ |
| `forge_cookie.py` | cookie identity enumeration + evidence | E2E mock ✓ |
| `kit_common.py` | scope gate, HTTP helper, output | bersama |

## Contoh pakai

```bash
# 1) audit halaman deployment (static, aman):
python3 probe.py --url 'https://script.google.com/macros/s/AKfyc.../exec' --out recon

# 2) decode JS hardcoded creds:
python3 deobfuscate.py --url 'https://script.google.com/macros/s/AKfyc.../exec' --out obf

# 3) panggil fungsi privat dari sisi klien:
python3 api_probe.py --url 'https://script.google.com/macros/s/AKfyc.../exec' --out api

# 4) dump sheet ID yang bocor dari HTML:
python3 gviz_fetch.py --sheet 1AbCdEfGhIjKlMnOpQrStUvWxYz --out sheet

# 5) enumerasi identitas guru via cookie:
python3 forge_cookie.py --url 'https://script.google.com/macros/s/AKfyc.../exec' \
    --cookie-name role --values-file users.txt --ok-sig 'Data Guru' --pace 2
```

## Status modul (semua lulus uji lokal)

| Modul | Fungsi | Verifikasi |
|---|---|---|
| `kit_common.py` | `http_get` (cookie + auto-redirect), `scope_check` **fail-closed**, `outdir`/`save_json`, `pace_sleep` | dipakai semua modul |
| `probe.py` | audit static HTML/JS deployment → daftar `google.script.run` + API key + meta | **E2E ✓** (4 fungsi kebaca) |
| `deobfuscate.py` | decode JS hardcoded (`atob` / `fromCharCode` / hex) → JSON akun | **E2E ✓** (3 akun + KEY) |
| `gviz_fetch.py` | dump query gviz Sheet → CSV/JSON | **E2E ✓** (3 baris) |
| `forge_cookie.py` | bake SID cookie dari akun JSON → cek akses tiap akun | **E2E ✓** (3/6 lolos, wajar) |
| `api_probe.py` | panggil fungsi privat dari sisi klien (`--js-enum` bersih) | **5/5 diverifikasi Node** |
| `verify_api_js.py` | harness Node — jalankan kode API asli di luar browser | **5/5 ✓** |
| `crack_helper.py` | deteksi jenis hash → rencana `hashcat` (mode `-m` benar, 4 fase) | **E2E ✓** (10 hash → 9 jenis) |

## Catatan operasional (BlackArch)

- `api_probe.py` **jangan lewat Tor** (Google 429/penolakan) — jalankan direct.
- Pacing default 2s; `--max 60` di `forge_cookie` = batas keras anti-lockout.
- Semua keluaran ditaruh di `<out>_<timestamp>/` biar gampang di-zip jadi evidence pack.
- `probe.py` dulu ada di `src/redteam/` — sudah pindah ke sini (satu sumber kebenaran).
