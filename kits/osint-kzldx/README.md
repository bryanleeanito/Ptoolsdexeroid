# OSINT by kzldx v2.2

Toolkit OSINT + security-check modular (**single-file**, menu interaktif) untuk BlackArch — dipakai agent (OpenCode) maupun manual oleh kzldx. Semua query HTTP lewat **Tor** (default), target wajib lolos **scope guard fail-closed** (`~/tools/immpack/scope.txt`).

> ⚠️ Layanan pihak ketiga di dalam tool (mesin cari, crt.sh, Wayback, Shodan, HIBP, dll) adalah **sumber pasif yang diizinkan** (keputusan user R212). Menyentuh **target** tetap diblokir bila tidak IN SCOPE.

## MENU (cara utama — tanpa hafal -command)
```bash
osint                       # ← MENU interaktif (alias di ~/bin/osint)
osint menu sman1batu.sch.id # menu dengan target awal
```
```
angka = jalankan · 't <target>' = set target · 'q' = keluar

  1) Cek Scope (fail-closed)
  2) DNS + Mail Security (SPF/DMARC/DKIM)
  3) Whois
  4) Subdomain (enum: subfinder+crt+wayback)
  5) Subdomain LIVE (probe HTTP)          ← status/title/server tiap sub
  6) TechStack (fingerprint dalam)        ← CMS/framework/cookie/versi
  7) Web Fingerprint (header/TLS)
  8) KERENTANAN (nuclei)                  ← mode cepat/penuh, rate 3/dtk
  9) CELAH/Exposure (path sensitif)       ← .git/.env/backup/actuator/…
 10) Wayback historis
 11) Port Scan (nmap via Tor)
 12) Email harvest (masking PII)
 13) Dork siap pakai
 14) People / pola email @target
 15) Laporan penuh (run → report.md)
 16) TOOLS: hydra/msf/sqlmap/whatweb      ← submenu tools populer
 17) JS endpoint extractor (rahasia/API)  ← endpoint tersembunyi + hardcoded secret
 18) Screenshot (playwright via Tor)      ← bukti visual per halaman/host
```

## Intel otomatis (R217 — deteksi → ⚠ kerentanan → 🔧 teknik)
**Setiap modul yang mendeteksi sesuatu langsung menampilkan panel `⚠ INTELIJEN`**
berisi: severity · topik · **kerentanan** ringkas · **teknik lanjutan** (apa yang
bisa dikerjakan/diuji berikutnya, plus mitigasi).

- Modul terpasang: `techstack` `web` `dns` `mail` `sublive` `celah` `jsfind`
  `ports` `wayback` `vuln` (nuclei) — **69 rule** di `INTEL_KB` (CMS, header
  keamanan, SPF/DMARC/DKIM, panel/login, port servis, path .git/.env/backup,
  secret JS, jQuery/Bootstrap lawas, dsb).
- Hasil akumulasi disimpan di `output/<host>_<ts>/intel.json` (per source+topik,
  tidak dobel saat run ulang) dan **ikut masuk `report.md`** pada `osint run`.
- Tambah rule: sunting daftar `INTEL_KB` di `osint.py` — format
  `(kata-kunci, topik, SEV, kerentanan, teknik)`.

## Tampilan (UI v2.2)
- Banner ASCII `OSINT` **gradient 5 warna** dengan efek **mesin ketik** per karakter.
- **Boot checklist** berjalan: `OK/FAIL` untuk konfigurasi · Tor :9050 · scope.txt · tool inti.
- **Panel status**: Tor/pace/scope/NDA (kotak double-edge), **panel TARGET** (hijau in-scope /
  merah luar-scope + jam live), **panel MENU** (box rounded, nomor kuning, garis `│`).
- Sebelum tiap modul jalan: **sweep progress** `▰▰▱▱ … 100%` → panel berat `▶ label` → centang `✔`.
- Prompt `❯ Pilih >` dan `❯` cyan di semua input.
- **Otomatis plain** saat output di-pipe atau flag `--quiet` (aman untuk script/agent).

## Mode CLI (tetap tersedia untuk script/agent)
```bash
osint -h
osint dns <target> --out
osint subs <target> --out
osint vuln <target> --mode quick          # critical + exposure/config/cve
osint vuln <target> --severity critical,high --list auto --timeout 21600
                                          # PENUH × semua host sublive.txt (scope divalidasi)
osint celah <target>
osint sublive <target>
osint jsfind <target>                     # endpoint + rahasia dari file JS
osint shot <target> --list auto           # screenshot semua host live (PNG)
osint techstack <target>                  # + --whatweb utk enrich non-Tor
osint run <target> --skip email           # pipeline penuh → report.md
```

## Modul & keluaran (folder `output/<host>_<timestamp>/`)
| Menu | Perintah | Fungsi | File |
|---|---|---|---|
| 1 | `scope` | Cek scope fail-closed | — |
| 2 | `dns`+`mail` | Rekaman DNS + SPF/DMARC/DKIM/MTA-STS + analisis | `dns.json`, `mail.json` |
| 3 | `whois` | Registrasi domain (fallback CLI bila lib gagal) | `whois.json` |
| 4 | `subs` | subfinder + crt.sh + Wayback (+`--amass`), anotasi scope | `subs.txt/json` |
| 5 | `sublive` | Probe HTTP paralel (6-thread, TLS longgar) → status/title | `sublive.txt/json` |
| 6 | `techstack` | 24 signature: CMS/framework/js/waf/panel + cookie+header+versi | `techstack.json` |
| 7 | `web` | Probe `/` robots sitemap security.txt + header + TLS SAN | `web.json` |
| 8 | `vuln` | **nuclei** rate-3/dtk via socks5; `--list auto` = semua host sublive (scope-validated); **anti-unresponsive R219**: `-timeout 30 -retries 2 -mhe 9999 -duc` (latensi Tor 6–14 dtk) | `nuclei.txt`, `vuln_targets.txt` |
| 9 | `celah` | 48 path sensitif + baseline soft-404 (verdict MENARIK/TERPROTEKSI) | `celah.json` |
| 10 | `wayback` | CDX historis + **filter file sensitif** | `wayback*.txt/json` |
| 11 | `ports` | nmap **via Tor** (proxychains `-sT` + kurasi `nmap_tor_ports`) | `nmap.*` |
| 12 | `email` | Panen email (PII masking) | `emails.txt` |
| 13 | `dork` | 16 dork siap klik | `dork.json` |
| 14 | `people` | People-search + 6 pola email @target | `people.json` |
| 15 | `run` | Pipeline penuh: dns·mail·whois·subs·sublive·wayback·web·techstack·jsfind·celah·email·dork | `report.md`, `all.json` |
| 16 | `tools` | hydra (anti-lockout) / msf / sqlmap / whatweb / nuclei | `*.log` |
| 17 | `jsfind` | Ekstrak endpoint internal/eksternal + rahasia hardcoded (AWS/JWT/creds) | `js_endpoints.txt`, `jsfind.json` |
| 18 | `shot` | Screenshot playwright/chromium **via Tor** (apex atau `--list auto`) | `screenshots/*.png`, `shot.json` |
| 19 | `export` | intel.json → findings.jsonl (integrasi GreyHat) | `findings.jsonl` |
| 20 | `waybackdiff` | **v2.1**: diff snapshot wayback TERTUA vs live sekarang (difflib; `--url` utk path spesifik) | `waybackdiff.json`, `waybackdiff.diff` |
| 21 | `graf` | **v3.0**: pohon subdomain → graphviz dot + SVG (lokal, tanpa network) | `graf.dot`, `graf.svg`, `graf.json` |
| 22 | `report` | **v3.0**: report.md terbaru → report.html mandiri (dark theme, stdlib) | `report.html` |
| 23 | `favicon` | **v2.2**: mmh3 hash ikon (link rel=icon — kutip/polos — + /favicon.ico, dedupe) → pivot Shodan/FOFA; `--file` mode lokal | `favicon.json` |
| 24 | `trackers` | **v2.2**: ekstrak ID analytics/verify (GA4/GTM/FB-pixel/hotjar/matomo/dll) → pivot "ID sama = tim sama" | `trackers.json` |
| 25 | `asn` | **v2.2**: RIPEstat network-info + as-overview + RDAP → ASN/holder/prefix + dork `asn:ASxxxx` | `asn.json` |
| 26 | `reconng` | **v2.2**: wrapper recon-ng (SOURCE=target; default hackertarget; `--cmd` utk perintah global) | `reconng.json`, `reconng.log` |

> **AUTO SWEEP** — menu `a` (standar) / `af` (full) menjalankan semua modul urut menu → 1
> sampai akhir · `--skip` utk lewati · CLI: `python3 osint.py auto <target> [--full] [--skip dns,...]`.
> Otomatis juga: `graf.svg` (kalau ada `subs.json`) + `report.html` + durasi & ringkasan.

## Baru v2.1 (6 Okt 2026 — mesin analisis Ubuntu)
- **3 modul baru** di atas (waybackdiff / graf / report) — E2E teruji.
- **FIX footgun argparse**: flag global (`--out`/`--authorized`/`--quiet`) yang ditaruh
  SEBELUM subcommand ditimpa `default=False` subparser (argparse) → senyap hilang.
  Contoh dulu: `osint.py --out dns x` tidak menyimpan; `osint.py --authorized ports x`
  **override scope hilang**. Kini `default=SUPPRESS` di parent — posisi bebas.
- **PySocks wajib** utk Tor via requests (`pip install pysocks`). Tanpa ini semua modul
  Tor gagal senyap (`no response`). Boot checklist kini menampilkan baris `PySocks`.
- **Portabilitas config**: `output_dir`/`scope_file` mengikuti mesin (backup:
  `config.json.bak-blackarch`). Deps: `apt install whois graphviz`.
- **Fix `_html_text`**: teks HTML dipecah per-elemen → unified diff terbaca
  (dulu 1 blok raksasa, diff cuma 5 baris).

## Baru v2.2 — RedTeam Edition (6 Okt 2026 sore)
Sumber inspirasi: hacktricks `external-recon-methodology` (§Favicon · §Trackers · §ASNs ·
`github-leaked-secrets.md` · `wide-source-code-search.md`) + playbook `notes/playbooks/google-dorks.md`.
- **4 modul baru** (tabel 23–26 di atas) — semua E2E teruji.
- **Dork +10 entri (16 → 26)**: token GitHub modern (`ghp_`/`github_pat_`/`xoxb-`/`AKIA`),
  file rahasia `.env`/`id_rsa`, grep.app · Sourcegraph · SearchCode, secret cloud,
  AI API key, subdomain listing, CCTV/IoT, breach selector IntelX.
- **graf + node DNS** dari `dns.json`: A→IP (ellipse) · NS (component) · MX (cds)
  — melengkapi backlog "graf subdomain/IP/NS".
- **mmh3 pure-Python fallback** (`_mmh3_32`): 0 mismatch / 1000 sample vs paket mmh3;
  vector `foo = -156908512` cocok. Paket `mmh3` direkomendasikan (sudah terpasang).
- Fix: regex favicon dukung atribut polos (`rel=icon href=data:,`) + tolak `data:` URI + dedupe hash sama.
- **bgpview.io MATI** (DNS gagal lokal & via Tor) → modul `asn` pindah ke **RIPEstat** (no key).

## Recon-ng 5.1.2 (partner engine, v2.2)
- Lokasi `tools/repo/recon-ng` · symlink `recon-ng`/`recon-cli` di PATH · **109 modul** (marketplace).
- E2E: `recon-cli -w lab -m recon/domains-hosts/hackertarget -o SOURCE=example.com -x`
  → host masuk `~/.recon-ng/workspaces/<dom>/data.db` (SQLite).
- **PATCH lokal** `recon/core/framework.py` (2 baris): proxy upstream hardcode `http://` →
  dukung `socks5h://` (Tor). Via tool: `python3 osint.py reconng <target>` otomatis
  `-g proxy=socks5h://127.0.0.1:9050` bila Tor hidup.
- Modul dgn API key (github/shodan/censys/hibp/bing) → isi via `recon-cli -C 'keys add'`.
- Deps opsional terpasang: `xlsxwriter` + `dicttoxml` (modul reporting xlsx/xml aktif).

## Tools submenu (16) — Konfirmasi wajib
- **hydra**: `-t 3 -W 3` otomatis (skill brute-aman-antilockout) + peringatan lockout + ketik `YA` + opsi Tor.
- **metasploit**: msfconsole auxiliary scanner — **tanpa Tor** → wajib ketik `TANPA TOR`.
- **sqlmap**: `--level 1 --risk 1 --delay 2 --tor` → ketik `YA`.
- **whatweb**: jalan langsung (proxy whatweb hanya HTTP, Tor socks tak didukung).

## Flag Global
`--no-tor` · `--pace N` (default 3 dtk) · `--authorized` (override scope, harus punya izin tertulis) · `--out` · `--quiet`.

## Konfigurasi (`config.json`)
`tor_proxy`, `use_tor`, `pace`, `timeout`, `output_dir` (default: `output/` di folder ini), `scope_file`, `hibp_api_key`, `nuclei_proxy`, `nuclei_timeout` (30 — jangan < latensi Tor!), `nuclei_retries` (2), `nuclei_mhe` (9999), `nmap_via_tor`, `nmap_tor_ports`, `wayback_limit`, `dkim_selectors`.

## Footgun yang sudah diuji (jangan diulang)
1. **nmap `-F` via Tor MACET >20 menit** → port silent-drop + proxychains serial 15s/closed. Solusi: daftar kurasi `nmap_tor_ports` (30 port, ±100 dtk) + `pc_nmap.conf` (socks5, timeout pendek).
2. **python-whois error DNS di Py3.14** → fallback otomatis ke binari `whois`.
3. **crawl email tanpa batas** → timeout; kini maks 15 link + skip aset.
4. **WAF mx-page** balas 403 31.013B untuk path sensitif = normal (bukan banned), homepage tetap 200.

## Scope (kebijakan R216 — MODE BEBAS default)
**`enforce_scope: false` (default):** allowlist TIDAK dipakai — semua modul
(aktif & pasif) boleh target apa pun; panel TARGET tampil `● MODE BEBAS` (cyan),
tanpa warning merah. Sisa pengaman: **blocklist proyek lain** (`!domain` di
scope.txt) tetap ditolak selama `enforce_blocklist: true`.

| Kunci `config.json` | Default | Efek |
|---|---|---|
| `enforce_scope` | **false** | `false` = bebas semua modul · `true` = skema R215 (lihat tabel) |
| `enforce_blocklist` | **true** | domain `!` di scope.txt tetap exit 2 (baik untuk kelas mana pun) |

**Skema lama (aktif bila `enforce_scope: true`)** — khusus kerja pentest terkontrak:

| Kelas | Modul | Scope |
|---|---|---|
| **◦ PASIF** (data publik pihak ketiga: DNS·whois·crt.sh·Wayback·dork·people·HIBP — *tanpa traffic langsung ke target*) | `dns` `mail` `whois` `subs` `wayback` `dork` `people` `leak` | Boleh target mana pun (catatan `◦ OSINT PASIF`), kecuali blocklist |
| **AKTIF** (langsung menyentuh server target) | `web` `sublive` `techstack` `celah` `vuln` `jsfind` `shot` `email` `ports` `tools` `run` | Fail-closed: wajib `scope.txt` / `--authorized` |

- Menu menandai item pasif dengan `◦` + legenda baris bawah (ikut mode aktif).

## Etika & Batasan (WAJIB)
1. Default **mode bebas** (`enforce_scope: false`) — semua modul boleh target apa pun.
   Pengaman tersisa: **blocklist proyek lain** (`!domain` di scope.txt, exit 2) +
   kepatuhan hukum di tangan operator (target = milik/izin tertulis).
   Untuk kerja pentest terkontrak, set `enforce_scope: true` → kembali fail-closed
   (aktif wajib scope.txt, pasif bebas).
2. Data pribadi: **guard DIMATIKAN 2026-10-05** -- salin/ekspor/publikasi utk laporan diizinkan; buktikan keberadaan & dampak = format laporan.
3. Scan berat (nuclei) tunggal + rate rendah; stop bila 403/429/508 masif.
4. Hasil `report.md` = bahan laporan GreyHat; verifikasi manual sebelum diserahkan.

## Struktur Folder
```
Osint by kzldx/
├── osint.py        # toolkit utama (single-file, menu + 20 subcommand)
├── config.json     # konfigurasi (Tor, pace, output, API key)
├── pc_nmap.conf    # proxychains khusus nmap (socks5, timeout pendek)
├── README.md       # dokumen ini
├── IDEE.txt        # backlog pengembangan
└── output/         # semua hasil scan per-invokasi
```
