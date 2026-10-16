# ip-changer v1.0

IP rotator & changer buat authorized pentest.

## Perintah

```bash
python3 ip_changer.py rotate --type tor --count 5
python3 ip_changer.py source --ip 10.0.0.1
python3 ip_changer.py geo --country id
python3 ip_changer.py mac --interface eth0
python3 ip_changer.py check
```

## Fitur

| Perintah | Fungsi |
|---|---|
| `rotate` | Proxy chain config (Tor, SOCKS5, HTTP) |
| `source` | Source IP spoofer (header injection) |
| `geo` | Geo IP changer (VPN/proxy selector) |
| `mac` | MAC address changer (Linux) |
| `check` | Cek IP sekarang |

## Proxy Types

- **Tor**: NEWNYM rotation via control port
- **SOCKS5**: Local SOCKS5 proxy
- **HTTP**: HTTP proxy with auth

## Aturan pakai

- **Wajib** otorisasi tertulis / CTF scope
- Jangan produksi tanpa izin
- MAC changer butuh root
