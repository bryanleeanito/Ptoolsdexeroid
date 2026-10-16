# defense-counter v1.0

Defense counter & WAF/IDS evasion toolkit.

## Perintah

```bash
python3 defense_counter.py waf --target https://target.com
python3 defense_counter.py ids --target 10.0.0.1 --port 80
python3 defense_counter.py rate --url https://target.com/api
python3 defense_counter.py captcha --target https://target.com
python3 defense_counter.py 2fa --target https://target.com
```

## Fitur

| Perintah | Fungsi |
|---|---|
| `waf` | WAF detection & bypass (CF, Akamai, Imperva, AWS, etc.) |
| `ids` | IDS/IPS evasion (fragmentation, decoy, timing) |
| `rate` | Rate limit detection & bypass |
| `captcha` | CAPTCHA detection & bypass hints |
| `2fa` | 2FA bypass hints |

## WAF Fingerprints

- Cloudflare, Akamai, Imperva, AWS WAF, Sucuri, Barracuda, F5, Fortinet

## IDS Evasion

- Fragmentation (`-f`, `--mtu`)
- Decoy scan (`-D RND:10`)
- Source port spoof (`--source-port 53`)
- Timing (`-T0`, `-T1`)

## Aturan pakai

- **Wajib** otorisasi tertulis / CTF scope
- Jangan produksi tanpa izin
- Defense counter = detection & evasion knowledge
