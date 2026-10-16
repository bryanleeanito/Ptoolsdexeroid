# ip-anti-lock v1.0

IP anti-lockout & rate limit bypass toolkit.

## Perintah

```bash
python3 anti_lock.py delay --base 1.0 --max 60.0 --attempts 10
python3 anti_lock.py rotate --ips "1.1.1.1,2.2.2.2,3.3.3.3" --interval 30
python3 anti_lock.py headers --count 5
python3 anti_lock.py session --cookies "a=1,b=2,c=3"
python3 anti_lock.py fingerprint --count 3
```

## Fitur

| Perintah | Fungsi |
|---|---|
| `delay` | Exponential backoff + jitter |
| `rotate` | IP rotation schedule |
| `headers` | Header rotation (UA, Accept, Lang) |
| `session` | Session/cookie rotation |
| `fingerprint` | Browser fingerprint rotation |

## Delay Strategies

- **Exponential backoff**: 1s, 2s, 4s, 8s, 16s...
- **Jitter**: Random 0-50% dari exponential
- **Fixed**: Constant delay
- **Random**: Random between base and max

## Aturan pakai

- **Wajib** otorisasi tertulis / CTF scope
- Jangan produksi tanpa izin
- Rate limit = legal boundary
