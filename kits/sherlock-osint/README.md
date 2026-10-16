# sherlock-osint v1.0

OSINT investigation toolkit ala Sherlock Holmes — cari clue, korelasikan data, bikin profil target.

## Perintah

```bash
python3 sherlock.py username --target john_doe
python3 sherlock.py email --target john@example.com
python3 sherlock.py phone --target +6281234567890
python3 sherlock.py domain --target example.com
python3 sherlock.py social --target john_doe
python3 sherlock.py correlate --username john_doe --email john@example.com
python3 sherlock.py report --target john_doe
```

## Fitur

| Perintah | Fungsi |
|---|---|
| `username` | Cari username di 40+ platform |
| `email` | Email OSINT (breach, reputation, gravatar) |
| `phone` | Phone OSINT (carrier, messaging, reverse lookup) |
| `domain` | Domain OSINT (DNS, WHOIS, subdomain, tech stack) |
| `social` | Social media profiling |
| `correlate` | Korelasikan semua data jadi 1 profil |
| `report` | Generate laporan investigasi |

## Correlation Engine

- Cross-reference username ↔ email ↔ phone ↔ domain
- Deteksi pola (email local part = username, phone suffix = username, dll)
- Generate profil konsolidat

## Social Engineering Clues

- Profile picture → Google reverse image
- Bio/description → lokasi, pekerjaan, interest
- Posts → rutinitas, lokasi, kontak
- Friends/followers → jaringan sosial
- Tagged photos → lokasi, aktivitas
- Check-ins → lokasi favorit
- Hashtags → interest, komunitas

## Aturan pakai

- **Wajib** otorisasi tertulis / CTF scope
- Jangan stalking tanpa izin
- Output = investigation artifact
- Hanya data publik (OSINT)
