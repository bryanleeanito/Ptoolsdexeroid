# idor-scanner v1.0

IDOR/BOLA (Broken Object Level Authorization) detector buat CTF & authorized testing.

## Perintah

```bash
python3 idor_scanner.py enumerate --url "http://api/user/{id}" --start 1 --end 100
python3 idor_scanner.py diff --url-a "http://api/user/1" --url-b "http://api/user/2"
python3 idor_scanner.py pattern --url "http://api/user/{id}" --sample 20
```

## Mode

| Mode | Fungsi |
|---|---|
| `enumerate` | Scan ID range, deteksi response berbeda |
| `diff` | Bandingkan response 2 user (unified diff) |
| `pattern` | Deteksi ID pattern (sequential/UUID/hash) |

## Deteksi

- Status code berbeda dari baseline
- Body response berbeda (bukan "not found")
- ID sequential = IDOR likely
- UUID/hash = harder but still possible

## Aturan pakai

- **Wajib** otorisasi tertulis / CTF scope.
- Jangan scan production API tanpa izin.
- Rate limit: tambah delay manual jika perlu.
