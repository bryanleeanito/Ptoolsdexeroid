# cloudflare-bypass v1.0

Cloudflare bypass toolkit buat authorized pentest.

## Perintah

```bash
python3 cf_bypass.py origin --domain target.com
python3 cf_bypass.py header --target "https://target.com/admin"
python3 cf_bypass.py chunked --payload "GET /admin HTTP/1.1\r\nHost: target.com\r\n"
python3 cf_bypass.py cache --url "https://target.com/?cb=random"
python3 cf_bypass.py direct --ip 103.56.206.81 --host target.com
```

## Fitur

| Perintah | Fungsi |
|---|---|
| `origin` | Origin IP discovery (DNS history, censys, SSL) |
| `header` | Header injection bypass CF |
| `chunked` | Chunked transfer encoding |
| `cache` | Cache poisoning/deception |
| `direct` | Direct IP access (origin) |

## Origin Discovery

- DNS History (SecurityTrails, ViewDNS)
- Censys / Shodan
- SSL Certificate (crt.sh)
- Subdomain enumeration

## Bypass Techniques

- X-Forwarded-For / X-Real-IP / CF-Connecting-IP
- X-Original-URL / X-Rewrite-URL
- Bot UA (Googlebot, Bingbot)
- Cache poisoning
- HTTP Request Smuggling

## Aturan pakai

- **Wajib** otorisasi tertulis / CTF scope
- Jangan produksi tanpa izin
- Output = attack artifact
