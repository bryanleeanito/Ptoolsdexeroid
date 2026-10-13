# target-inventory v1.0

Katalog target + **generator `scope.txt`**. Semua kit lain punya gerbang
fail-closed yang baca `scope.txt` — kit inilah yang bikin file itu.

```
python3 inventory.py --add-host sman3malang.sch.id --izin tertulis \
    --tanggal-izin 2026-10-13 --bukti "Authoritation.txt baris 3"
python3 inventory.py --list
python3 inventory.py --emit-scope
python3 inventory.py --check https://sman3malang.sch.id/login
python3 inventory.py --validate /root/data/Auth/scope.txt
```

## Kenapa `scope.txt` harus di-generate

`scope.txt` adalah gerbang keamanan tertinggi di repo ini: kalau file-nya
tidak terbaca, **semua kit modul aktif berhenti** (fail-closed). Tapi selama
ini file itu diedit tangan, sehingga gampang nyasar dari catatan izin yang
sebenarnya — bisa saja ada host di scope padahal izinnya sudah ditarik.

Kit ini membalik logikanya:

```
targets.json  (sumber kebenaran, ada metadata izin)
     │
     └── --emit-scope ──>  scope.txt  (artefak, jangan diedit tangan)
```

## Status izin

| `izin` | masuk `scope.txt`? |
|---|---|
| `tertulis` | **ya** |
| `lisan` | tidak (tercatat, tapi ditahan) |
| `pending` | tidak |
| `ditarik` | tidak |

Target yang ditahan tetap muncul sebagai **komentar** di `scope.txt` — jadi
riwayatnya kebaca saat audit, tapi tidak pernah jadi allowlist.

## Semantik = persis `kit_common.scope_check()`

Fungsi `host_of()` dan `cocok()` di kit ini **disalin persis** dari
`kit_common.py`, supaya `--check` benar-benar pre-flight, bukan tebakan:

- 1 host per baris, hanya **token pertama** yang dipakai
- `#` komentar, baris kosong diabaikan
- `!host` = blocklist, **selalu menang** atas allowlist
- `*.domain` mencakup `domain` + seluruh subdomainnya
- pembandingan case-insensitive

## Mode

| flag | fungsi |
|---|---|
| `--add-host` | tambah/ubah target (boleh `*.domain`) |
| `--izin` | `tertulis` / `lisan` / `pending` / `ditarik` |
| `--tanggal-izin`, `--bukti`, `--catatan` | metadata izin |
| `--alias` | alias dipisah koma |
| `--blok` | blocklist spesifik dipisah koma |
| `--nonaktif` | tandai target dinonaktifkan |
| `--list` | tabel inventaris |
| `--emit-scope` | tulis `scope.txt` |
| `--check <url>` | dry-run: host ini masuk scope? (exit 1 kalau tidak) |
| `--validate <file>` | lint `scope.txt` |

`--inv` dan `--scope` bisa dioverride (dipakai untuk uji tanpa menyentuh
`/root/data/Auth/` yang asli).

## Catatan `--authorized`

Semua kit punya flag `--authorized` yang **mengabaikan allowlist** dan
menyatakan kamu punya izin di luar daftar. Kit ini tidak bisa mencegah itu —
tapi `--check` membantumu memastikan host memang sudah seharusnya di scope
sebelum kamu tergoda memakai `--authorized`.

## Status uji

E2E lolos (2026-10-13):
- 3 target (tertulis/pending/ditarik) → hanya 1 yang keluar di `scope.txt`,
  2 sisanya jadi komentar
- `--check`: host sendiri + alias = DALAM SCOPE; pending/ditarik/eksternal = LUAR SCOPE
- wildcard `*.sekolahku.sch.id` mencakup subdomain, dan `!admin.…` tetap menang (BLOCK)
- `--validate`: file sehat exit 0; file rusak exit 1 dengan **4 masalah per baris**
  (huruf besar, >1 token, duplikat, `!` tanpa host)
- file tidak ada → fail-closed, exit 1
