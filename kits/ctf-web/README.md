# ctf-web — recon cepat web jeorpadic (read-only)

Persiapan pertama buat soal web: dump header (cek header keamanan hilang),
cookie → **JWT ke-decode otomatis**, comment HTML, form/hidden input/param,
scan pola flag, cek jalur bocor (`/.git/HEAD`, `/.env`, `/flag.txt`, `robots.txt`,
`phpinfo.php`, backup file, …), `--js` ikut fetch script & gali endpoint + key
hardcode.

```bash
python3 recon_ctf.py http://challenge.ctf/web
python3 recon_ctf.py http://target/ --all --js
```

Alur lanjutan setelah recon: kalau ketemu param/form → tembak manual
(SQLi/LFI/SSTI) pakai Burp/ffuf; kalau ketemu source bocor → `secret-scanner`.
