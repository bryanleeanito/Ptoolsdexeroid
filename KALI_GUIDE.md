# KALI_GUIDE.md — Panduan AI Agent OpenCode di Kali Linux

> **Target mesin:** ThinkPad T14s G1 · Ryzen 5 PRO 4650U (6C/12T) · 16GB RAM · Kali Linux
> **Repo:** Ptoolsdexeroid (private) · 35 kit · semua E2E verified
> **Terakhir update:** 2026-10-16

---

## 1. Cara AI Agent Memakai Repo Ini

### 1.1 Load Context (WAJIB sebelum mulai)

```bash
# Baca panduan ini dulu
cat ~/Ptoolsdexeroid/KALI_GUIDE.md

# Cek kit tersedia
ls ~/Ptoolsdexeroid/kits/

# Cek status repo
cd ~/Ptoolsdexeroid && git status -sb
```

### 1.2 Pilih Kit Berdasarkan Kebutuhan

| Kebutuhan | Kit | Perintah |
|---|---|---|
| CTF Crypto | `ctf-crypto`, `crypto-specialist` | `python3 kits/ctf-crypto/solve.py` |
| CTF Forensics | `ctf-forensics` | `python3 kits/ctf-forensics/probe.py` |
| CTF Web | `ctf-web`, `jwt-toolkit`, `sqli-helper` | `python3 kits/ctf-web/recon_ctf.py` |
| CTF Pwn/Rev | `ctf-pwn`, `rev-toolkit`, `rev-specialist` | `python3 kits/rev-toolkit/rev_toolkit.py` |
| CTF Misc | `ctf-decoder`, `ctf-misc-solver` | `python3 kits/ctf-misc-solver/misc_solver.py` |
| OSINT | `sherlock-osint`, `osint-kzldx` | `python3 kits/sherlock-osint/sherlock.py` |
| WAF Bypass | `waf-bypass`, `defense-counter` | `python3 kits/waf-bypass/waf_bypass.py` |
| Cloudflare Bypass | `cloudflare-bypass` | `python3 kits/cloudflare-bypass/cf_bypass.py` |
| Elementor Bypass | `elementor-bypass` | `python3 kits/elementor-bypass/elementor_bypass.py` |
| IP Rotation | `ip-changer`, `ip-anti-lock` | `python3 kits/ip-changer/ip_changer.py` |
| Firewall Bypass | `firewall-bypass` | `python3 kits/firewall-bypass/fw_bypass.py` |
| Webshell | `webshell-manager` | `python3 kits/webshell-manager/webshell_manager.py` |
| Payload | `payload-generator` | `python3 kits/payload-generator/payload_gen.py` |
| Defense | `security-protect` | `python3 kits/security-protect/security_protect.py` |
| Efficiency | `extreme-efficiency` | `python3 kits/extreme-efficiency/extreme_mode.py` |

### 1.3 Workflow Cepat

```bash
# 1. Recon pasif (OSINT)
python3 kits/sherlock-osint/sherlock.py username --target <username>
python3 kits/sherlock-osint/sherlock.py domain --target <domain>

# 2. Recon aktif (network)
nmap -sV -T3 --max-rate 200 <target>
subfinder -d <domain> | httpx -silent

# 3. Web testing
python3 kits/ctf-web/recon_ctf.py <url>
python3 kits/jwt-toolkit/jwt_toolkit.py attack <token>
python3 kits/sqli-helper/sqli_helper.py probe --url <url> --param id

# 4. Bypass
python3 kits/waf-bypass/waf_bypass.py encode --payload "<payload>" --method double-url
python3 kits/cloudflare-bypass/cf_bypass.py origin --domain <domain>

# 5. Post-exploit
python3 kits/payload-generator/payload_gen.py reverse --type bash --ip <ip> --port 4444
python3 kits/webshell-manager/webshell_manager.py generate --type php --method command

# 6. Defense
python3 kits/security-protect/security_protect.py headers --domain <domain>
python3 kits/security-protect/security_protect.py audit --path /var/www/html
```

---

## 2. Mode Extreme Efficiency (T14s G1 Tuned)

### 2.1 Preset

```bash
# Stealth (recon pasif, anti-detection)
python3 kits/extreme-efficiency/extreme_mode.py preset --mode stealth

# Balanced (default daily)
python3 kits/extreme-efficiency/extreme_mode.py preset --mode balanced

# Max Power (lab/offline target)
python3 kits/extreme-efficiency/extreme_mode.py preset --mode max
```

### 2.2 Auto Chain

```bash
# Recon chain: subfinder -> httpx -> ffuf -> nuclei
python3 kits/extreme-efficiency/extreme_mode.py auto --chain "subfinder -d target.com -> httpx -silent -> ffuf -w wordlist.txt -u https://target.com/FUZZ -t 12 -rate 50 -> nuclei -l live.txt -c 8 -rl 50"
```

### 2.3 Parallel Execution

```bash
# Jalankan multi-tool secara paralel
python3 kits/extreme-efficiency/extreme_mode.py parallel --tools "nmap -sV,httpx -silent,ffuf -w wordlist.txt" --target 10.0.0.1
```

### 2.4 Cache

```bash
# Cache hasil tool biar tidak repeat
python3 kits/extreme-efficiency/extreme_mode.py cache --tool nmap --args "-sV 10.0.0.1" --ttl 3600
```

---

## 3. Prioritas & Urgensi

### 3.1 CTF Competition (Deadline Mendesak)

```
Priority 1: CTF kits (decoder, crypto, forensics, web, pwn)
Priority 2: OSINT (sherlock-osint)
Priority 3: Bypass (waf-bypass, sqli-helper)
```

### 3.2 Penetration Test (Authorized)

```
Priority 1: Recon (osint-kzldx, sherlock-osint)
Priority 2: Web testing (ctf-web, jwt-toolkit, sqli-helper)
Priority 3: Bypass (waf-bypass, cloudflare-bypass, elementor-bypass)
Priority 4: Post-exploit (payload-generator, webshell-manager)
Priority 5: Defense (security-protect)
```

### 3.3 Defensive Security

```
Priority 1: Audit (security-protect audit)
Priority 2: Hardening (security-protect hardening)
Priority 3: Monitoring (security-protect monitor)
Priority 4: Backup (security-protect backup)
```

---

## 4. Hardware Optimization (T14s G1)

### 4.1 CPU (6 Core / 12 Thread)

```bash
# Max parallel workers
python3 -c "import multiprocessing; print(multiprocessing.cpu_count())"  # 12

# Nice priority
nice -n 10 <command>  # Balanced
nice -n 15 <command>  # Stealth
nice -n 0 <command>   # Max
```

### 4.2 RAM (16 GB)

```bash
# Limit RAM per tool
ulimit -v 2097152  # 2GB (balanced)
ulimit -v 524288   # 512MB (stealth)
ulimit -v 8388608  # 8GB (max)
```

### 4.3 Network

```bash
# Rate limit
nmap --max-rate 200 <target>   # Balanced
nmap --max-rate 50 <target>    # Stealth
nmap --max-rate 1000 <target>  # Max
```

---

## 5. Quick Reference

### 5.1 Semua Kit (35)

| Kategori | Kit |
|---|---|
| CTF | ctf-decoder, ctf-crypto, ctf-forensics, ctf-web, ctf-pwn, ctf-misc-solver, ctf-drills, ctfd-solver |
| Crypto | crypto-kit, crypto-specialist |
| Reverse | rev-toolkit, rev-specialist |
| OSINT | osint-kzldx, sherlock-osint |
| Bypass | waf-bypass, cloudflare-bypass, elementor-bypass, firewall-bypass |
| IP | ip-changer, ip-anti-lock, egress-rotator |
| Defense | defense-counter, security-protect |
| Exploit | payload-generator, webshell-manager |
| Efficiency | extreme-efficiency |
| Other | gapps-kit, plesk-kit, secret-scanner, report-packer, target-inventory, wordlist-sekolah, wp-recon, wp-auth-tester, hosting-tester, elementor-scanner |

### 5.2 Environment Variables

```bash
# API keys (jangan hardcode!)
export GITHUB_TOKEN="xxx"
export SHODAN_API_KEY="xxx"
export CENSYS_API_ID="xxx"
export CENSYS_API_SECRET="xxx"
```

### 5.3 Common Commands

```bash
# Update repo
cd ~/Ptoolsdexeroid && git pull

# Run tests
python3 kits/<kit>/tests.py

# Check kit info
python3 kits/<kit>/<script>.py --help
```

---

## 6. Safety & Legal

1. **Wajib otorisasi tertulis** sebelum eksekusi aktif
2. **Scope gate fail-closed**: modul aktif butuh `--authorized` atau host ada di `scope.txt`
3. **Jangan produksi tanpa izin**
4. **Cleanup wajib** setelah testing
5. **Output = attack artifact**, jangan di-commit ke repo publik
6. **Rate limit = legal boundary**

---

## 7. Troubleshooting

| Masalah | Solusi |
|---|---|
| Module tidak found | `pip install pycryptodome` |
| Permission denied | `sudo` atau cek file permission |
| Network timeout | Cek koneksi, tambah timeout |
| Tool tidak ada | `apt install <tool>` atau `pip install <tool>` |
| Test gagal | Cek dependency, baca error message |

---

**END OF GUIDE**
