# Ptoolsdexeroid

Gudang toolkit + jembatan handoff antar mesin (Tab Rumah ↔ Tab Sekolah ↔ BlackArch).
Dibuat 2026-10-12.

## Struktur

```
kits/
├── gapps-kit/       v1.0  — bypass Google Apps Script web app (7 modul)
├── osint-kzldx/     v2.2  — suite OSINT 26 menu + AUTO SWEEP + GUI animasi
├── egress-rotator/  v1.0  — Tor NEWNYM · WARP rekey · proxy pool (E2E ✓)
├── wordlist-sekolah/v1.0  — kamus password sekolah Indonesia (E2E ✓)
├── elementor-scanner/v1.0 — cari form Elementor tersembunyi (E2E ✓)
├── wp-recon/        v1.0  — username enum + fingerprint + deteksi WAF (E2E ✓)
├── wp-auth-tester/  v1.0  — tembak form login WP, lockout-aware (E2E ✓)
├── hosting-tester/  v1.0  — tester cPanel & FTP, deteksi lockout (E2E ✓)
├── secret-scanner/  v1.0  — cari secret ter-hardcode di semua dump (E2E ✓)
├── report-packer/   v1.0  — rangkai output semua kit jadi 1 laporan (E2E ✓)
├── target-inventory/v1.0  — katalog target + generator scope.txt (E2E ✓)
├── ctf-decoder/     v1.0  — pembongkar lapisan encoding 17 jenis + 18 tes (E2E ✓)
├── ctf-crypto/      v1.0  — cipher klasik + RSA solver 6 serangan (E2E ✓)
├── ctf-forensics/   v1.0  — magic/EXIF/chunk/hidden-data scanner (E2E ✓)
├── ctf-web/         v1.0  — recon web jeorpadic: header/JWT/leak path (E2E ✓)
├── ctf-pwn/         v1.0  — checklist + prep script BlackArch (pwntools/gdb/r2)
├── ctfd-solver/     v1.0  — solver CTFd API: login/list/fetch/sweep/autosolve (E2E mock ✓)
├── ctf-drills/      v1.0  — 12 drill latihan + kunci (12/12 terverifikasi kit)
├── crypto-specialist/ v1.0 — RSA keygen/5 attacks + AES + classical + hash crack (E2E ✓)
├── rev-specialist/    v1.0 — Ghidra gen + binary patch + protocol analyzer + anti-detect (E2E ✓)
├── waf-bypass/        v1.0  — WAF bypass: encoding, headers, chunked, JSON, HPP (E2E ✓)
├── cloudflare-bypass/ v1.0  — CF bypass: origin IP, header, chunked, cache, direct (E2E ✓)
├── elementor-bypass/  v1.0  — Elementor: REST, template, form, upload, auth bypass (E2E ✓)
├── ip-changer/        v1.0  — IP rotator: proxy, source spoof, geo, MAC (E2E ✓)
├── ip-anti-lock/      v1.0  — Anti-lockout: delay, rotate, headers, session (E2E ✓)
├── defense-counter/   v1.0  — WAF/IDS evasion, rate limit, CAPTCHA, 2FA (E2E ✓)
├── webshell-manager/  v1.0  — Webshell: detect, obfuscate, generate, manage (E2E ✓)
├── payload-generator/ v1.0  — Payload: PHP/ASPX/JSP/Python + reverse shell (E2E ✓)
├── sherlock-osint/   v1.0  — OSINT investigation: username/email/phone/domain + correlation (E2E ✓)
├── jwt-toolkit/      v1.0  — decode/verify/forge/crack JWT + attack analyzer (E2E ✓)
├── rev-toolkit/      v1.0  — strings/ELF parse/patch template/r2gen/UPX detect (E2E ✓)
├── sqli-helper/      v1.0  — SQLi probe/blind/tamper/union column counter (E2E ✓)
├── idor-scanner/     v1.0  — IDOR/BOLA enumerate/diff/pattern detector (E2E ✓)
├── ctf-misc-solver/  v1.0  — auto-classifier 7 encoding + hashid + XOR brute (E2E ✓)
├── crypto-specialist/ v1.0 — RSA keygen/5 attacks + AES + classical + hash crack (E2E ✓)
└── rev-specialist/    v1.0  — Ghidra gen + binary patch + protocol analyzer + anti-detect (E2E ✓)
HANDOFF.md             — status antar mesin + wish-list input
```

## Cara pakai antar mesin

```bash
# sekali saja di mesin baru
git clone https://github.com/bryanleeanito/Ptoolsdexeroid.git
cd Ptoolsdexeroid

# ambil update terbaru
git pull

# pakai kit
python3 kits/gapps-kit/probe.py --help
python3 "kits/osint-kzldx/osint.py" --help
```

## Aturan repo

1. **Token/API key = env var aja.** Nggak pernah di-commit, nggak pernah di config.
   `.gitignore` sudah jaga `*.token`, `.secrets/`, `*.env`.
2. **Output kerja (`*_out/`, `gapps_*/`, dumps) jangan di-commit** — itu evidence, bukan source.
3. Kit pakai **scope gate fail-closed**: modul aktif butuh `--authorized` atau host ada di
   `scope.txt`. Eksekusi aktif cuma untuk target terotorisasi.
4. `kits/osint-kzldx/` dulunya bernama `Osint by kzldx` — diganti biar path tanpa spasi
   (mulus buat git/rsync).

## Changelog

- **2026-10-16** — tambah `sherlock-osint` (OSINT investigation: username/email/phone/domain + correlation engine + report generator). Total 33 kit.
- **2026-10-16** — tambah 8 kit bypass & payload: `waf-bypass`, `cloudflare-bypass`, `elementor-bypass`, `ip-changer`, `ip-anti-lock`, `defense-counter`, `webshell-manager`, `payload-generator`. Total 32 kit.
- **2026-10-16** — tambah 2 kit specialist: `crypto-specialist` (RSA keygen/5 attacks + AES + classical + hash crack), `rev-specialist` (Ghidra gen + binary patch + protocol analyzer + anti-detect). Total 24 kit.
- **2026-10-16** — tambah 5 kit: `jwt-toolkit` (decode/verify/forge/crack JWT + attack analyzer), `rev-toolkit` (strings/ELF/patch/r2gen/UPX), `sqli-helper` (probe/blind/tamper/union), `idor-scanner` (enumerate/diff/pattern), `ctf-misc-solver` (auto-classifier + hashid + XOR). Total 22 kit.
- **2026-10-14** — tambah `ctf-drills` (12 soal latihan + kunci, verifikasi
  otomatis 12/12). Perbaikan nyata dari latihan: `decode.py` (FLAG_KETAT
  deteksi `flag` setelah underscore; rantai STOP kalau input sudah berflag;
  cabang BFS jamin decoder struktural; decoder baru railfence + whitespace;
  `--in` tak lagi strip whitespace payload stego) + `classics.py` (arah
  dekripsi Vigenere kebalik).
- **2026-10-14** — tambah `ctfd-solver` (login form+nonce & token API, list,
  fetch, sweep flags.json, autosolve rantai-decode; E2E mock 6/6). Merge
  `ctf-kit` → `ctf-decoder`.
- **2026-10-14** — tambah 5 kit CTF buat lomba jeorpadic online: `ctf-decoder`
  (chain decode 14 jenis), `ctf-crypto` (caesar/vigenere/xor/subst + RSA
  small-e/fermat/wiener/common-modulus/Hastad/factordb), `ctf-forensics`
  (magic/EXIF/chunk PNG/hidden-data), `ctf-web` (recon header/JWT/leak path),
  `ctf-pwn` (checklist + prep BlackArch).
- **2026-10-13** — tambah `target-inventory` (scope.txt jadi build artifact).
- **2026-10-13** — tambah `report-packer` (agregasi laporan lintas kit).
- **2026-10-13** — tambah `secret-scanner` (10 pola deteksi, redact by default), `wp-recon`, `hosting-tester`, `crack_helper`. Playwright MCP beres.
- **2026-10-13** — tambah 3 kit: `egress-rotator`, `wordlist-sekolah`, `elementor-scanner` (semua E2E mock/lokal ✓).
- **2026-10-12** — repo dibuat. `gapps-kit` v1.0 + `osint-kzldx` v2.2 masuk.
