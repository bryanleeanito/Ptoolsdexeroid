# egress-rotator

Rotasi jalur keluar biar lockout berbasis-IP (Wordfence dsb) nggak ngenain kita.

```bash
python3 rotate.py tor --check                    # lihat egress IP via Tor
python3 rotate.py tor --newnym --check           # rotate + verifikasi IP berubah
python3 rotate.py pool --proxies pool.txt --check
python3 rotate.py tor --exec "ffuf -u ... -w wl.txt"
```

## Tiga jalur

| Jalur | Cara kerja | Syarat |
|---|---|---|
| `tor` | `SIGNAL NEWNYM` ke ControlPort → circuit baru = IP baru | `ControlPort 9051` + `CookieAuthentication 1` (atau `HashedControlPassword`) di torrc |
| `warp` | rekey/reconnect Cloudflare WARP (`registration delete` + `connect`) | `warp-cli` terpasang |
| `pool` | rotasi proxy dari file, cek egress IP tiap proxy | file proxy per baris |

Format baris proxy didukung: `host:port`, `http://host:port`, `socks5h://host:port`.

## Catatan

- Verifikasi IP lewat `check.torproject.org/api/ip` + `api.ipify.org` (fallback otomatis).
- NEWNYM butuh 10–30 detik sampai circuit baru benar-benar kepakai.
- Tor cuma nolong kalau target **menerima** Tor. Banyak target menolak IP exit Tor —
  kalau gitu pakai `pool` atau `warp`.

## Verifikasi

E2E lokal: IP `185.220.101.109` → `204.8.96.110` setelah NEWNYM ✓ · pool 2/3 hidup ✓
· `socks5h://` ke-parse benar ✓. Jalur **WARP** = NEEDS VERIFICATION (butuh `warp-cli`).
