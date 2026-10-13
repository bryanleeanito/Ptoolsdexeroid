# plesk-kit v1.0

Tiga alat analisis **Plesk Obsidian** — semua **zero network touch** kecuali
`api.py` yang memang klien. Format diambil dari dokumentasi resmi Plesk,
bukan tebakan.

```
python3 cve.py  --version 18.0.80 --sweep 0-9 --db advisories_plesk.json
python3 api.py  --url https://host:8443/enterprise/control/agent.php
python3 spec.py --in openapi.json
```

Rincian analisis versi 18.0.80 ada di [`ANALYSIS.md`](ANALYSIS.md).

## Kenapa perlu ini

Tiga masalah yang muncul di lapangan dan semuanya berujung pada **false
positive di laporan** kalau ditangani asal-asalan:

1. **Versi Plesk punya 4 field** (`18.0.65.2`), sedangkan build number
   (`1800260925.18`) hanya memuat `major.minor` + tanggal + rev —
   **nomor Update tidak ada di dalamnya**. Menebak versi dari build
   menghasilkan `18.00.0` dan membuat semua CVE terbaca "vulnerable".
2. **Aggregator AI (OpenCVE/Strix) saling bertentangan** soal identitas CVE.
   Tertangkap NVD: tiga deskripsi tertukar di kueri awal. Sekarang urutan
   kepercayaan: **NVD utk deskripsi, KB Plesk utk rentang patch,
   aggregator hanya pelengkap**.
3. **Error code `1010` bukan rate limit.** Plesk `1010` = *Access to Plesk
   Panel denied* (IP/akses ditolak). Menunggu lalu retry tidak
   menyelesaikannya — itu beda masalah, beda solusi.

## `cve.py` — pencocokan versi vs advisory

```
python3 cve.py --version 18.0.80 --db advisories_plesk.json
python3 cve.py --version 18.0.80 --sweep 0-9 --db advisories_plesk.json
python3 cve.py --version 18.0.80 --db advisories_plesk.json --format json --out hasil.json
```

`--sweep` dipakai saat nomor Update belum pasti: tiap CVE diklasifikasi
terhadap **seluruh rentang** sekaligus.

| kelas | arti |
|---|---|
| `PASTI_TERDAMPAK` | terdampak di semua nilai rentang |
| `KONDISIONAL` | ada ambang — tampil `VULN jika Update < N` |
| `DATA_KURANG` | sumber tidak menyebut `fixed_in` |
| `PASTI_TERPATCH` | sudah patch di seluruh rentang |

`--build` **tidak bisa** dipakai tanpa `--version`: skrip berhenti dan
menyuruh ambil `plesk -v`, bukan menebak.

Field `dasar` pada tiap advisory menandai kualitas datanya:
`tercatat` (dikutip langsung) · `inferensi` (diturunkan dari rentang) ·
`komponen` (celah Apache/nginx yang dibundel Plesk, bukan Plesk inti).

## `api.py` — klien XML API, format resmi

Endpoint: `POST /enterprise/control/agent.php`. Empat cara auth yang
**didokumentasikan** Plesk:

| `--auth` | header yang dikirim |
|---|---|
| `header` (default) | `HTTP_AUTH_LOGIN` / `HTTP_AUTH_PASSWD` |
| `basic` | `Authorization: Basic base64(user:pass)` |
| `key` | `KEY: <secret key>` |

Gaya `header` inilah yang menghilangkan error
*"Authentication method is not specified"* — auth memang harus lewat header,
bukan di dalam packet.

**Dua mode:**

- `probe` (default) — kirim packet `get_protos` **tanpa kredensial**.
  Nol tebakan sandi. Hanya menanyakan: API nyala? versi didukung?
- `creds --creds FILE --i-know-what-i-do` — tebak kredensial, **terbatas**.

### Patuh `security_audit_protocol.md` §0

| butir | penerapan di skrip |
|---|---|
| 3 — jeda ≥ 2,5 dtk; stop 2× BLOCK | floor **keras**: `--delay 0.1` otomatis dinaikkan ke 2.5s; `2× 403 → PAUSE` tepat di percobaan ke-2 |
| 6 — brute-force wajib konfirmasi | mode `creds` **menolak jalan** tanpa `--i-know-what-i-do` |

**Tidak pernah loop tanpa batas** — `--repeat` default 1, maksimum 3;
`--max` maksimum 50. Skrip juga **berhenti sendiri begitu kredensial valid
ketemu**, karena melanjutkan cuma menambah risiko lockout tanpa guna.

Errcode yang memaksa berhenti seketika: `1012` (locked login), `1011`
(account disabled), `1010` (access denied), `1024` (limit reached).

### Gerbang scope

Disalin persis dari `gapps-kit/kit_common.py`. Fail-closed: `scope.txt`
tak terbaca = STOP, host di luar allowlist = STOP, kena blocklist `!` = STOP.
`--authorized` hanya untuk menyatakan izin tertulis di luar `scope.txt`.

## `spec.py` — audit spec OpenAPI

Cari endpoint yang bisa dipanggil tanpa kredensial. Bekerja pada **dokumen**,
bukan menyerang target.

```
python3 spec.py --in spec.json --min-risk publik
python3 spec.py --in spec.yaml --format json --out hasil.json
```

Aturan OpenAPI yang dipakai untuk menilai:

- operasi tanpa `security` → **mewarisi** root `security`
- `security: []` → eksplisit publik (override global)
- `security: [{}]` → anonymous diizinkan
- tak ada `security` di keduanya → `NONE` (belum tentu publik — perlu
  verifikasi; auth bisa ditegakkan di gateway)

## Data

`advisories_plesk.json` — 17 CVE per 2026-10-13. Di dalamnya sudah
ditandai mana yang **sudah patch di 18.0.80** dan jangan dilaporkan:
`CVE-2026-48614`, `CVE-2026-58046`, `CVE-2025-65518`, `CVE-2026-42945`.

Isi DB berubah tiap kali Plesk merilis update — **fetch ulang secara
berkala**, dan ganti placeholder `CVE-0000-18081-CRIT` begitu nomor CVE
resmi untuk fix critical di 18.0.81 terbit.

## Status uji

E2E lolos (2026-10-13), semuanya lewat **mock server lokal** — tidak ada
target nyata yang disentuh:

| skrip | tes | hasil |
|---|---|---|
| `cve.py` | 7 | lolos — mode titik, `--sweep`, batas `--sweep`, versi 4-field ditolak, JSON valid |
| `api.py` | 16 | lolos — 4 gerbang scope, flag `--i-know-what-i-do`, probe ok, 1001→sukses→stop, 1010 stop, 429 stop, 2×403 pause, hint 1005/1029, 6 batas argumen, `basic` auth, JSON valid |
| `spec.py` | 5 | lolos — 4 kasus auth (`PUBLIC`/`ANON`/`NONE`/`AUTH`), filter `--min-risk`, JSON, file hilang, file non-OpenAPI |

Salinan kerja ada di `/root/data/pentest/scripts/` (path `--db` dan
`DEFAULT_SCOPE` mengacu ke sana). Kalau mengubah salah satu, **sinkronkan
manual** — sama seperti `gapps-kit`.
