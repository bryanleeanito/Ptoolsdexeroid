#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSINT by kzldx SUITE v2.2 — Toolkit OSINT modular (BlackArch + Tor).
AUTHOR : Lee (Rexycho) + OpenCode agent
DESC   : Satu CLI untuk seluruh siklus OSINT: scope-guard → DNS/Whois/Mail →
         subdomain → web fingerprint → wayback → email harvest → dork → laporan.
         Fail-closed scope (mirip MCP secops), semua HTTP lewat Tor (configurable).

CATATAN SCOPE: endpoint pihak ketiga dalam file ini (mesin cari, crt.sh,
         Wayback, Shodan, HIBP, dsb) adalah SUMBER OSINT pasif — diizinkan
         user (R212). Menyentuh TARGET tetap wajib lolos require_scope().
KEBIJAKAN R215 (user): OSINT PASIF boleh target di luar scope.txt —
         modul dns/whois/subs/mail/wayback/dork/people/leak (data sumber
         publik pihak ketiga, tanpa traffic langsung ke target). Modul AKTIF
         (web/sublive/techstack/celah/vuln/jsfind/shot/email/ports/tools/run)
         tetap fail-closed. BLOCKLIST (!…) berlaku MUTLAK untuk keduanya.
KEBIJAKAN R216 (user): enforce_scope=false (DEFAULT) — allowlist scope
         DIKELUARKAN dari alur harian; semua modul bebas target apa pun
         (senyap, tanpa warning merah). Sisa pengaman hanya blocklist
         proyek lain (enforce_blocklist=true). config.json enforce_scope=true
         → kembali ke skema R215 (pasif bebas / aktif fail-closed).

MODUL  : scope dns whois subs web ports mail wayback dork email people leak run

CONTOH :
  python3 osint.py scope sman1batu.sch.id
  python3 osint.py run sman1batu.sch.id            # pipeline penuh + report.md
  python3 osint.py subs sman1batu.sch.id           # subfinder+crt.sh+wayback
  python3 osint.py wayback sman1batu.sch.id        # URL historis + filter sensitif
  python3 osint.py dork sman1batu.sch.id           # cetak dork siap-klik
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import difflib
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

# ─────────────────────────── KONFIG ───────────────────────────
BASE = Path(__file__).resolve().parent
DEFAULT_CONFIG = {
    "tor_proxy": "socks5h://127.0.0.1:9050",
    "use_tor": True,
    "pace": 3.0,               # jeda detik antar-request massal
    "timeout": 30,
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "output_dir": str(BASE / "output"),
    "scope_file": os.path.expanduser("~/tools/immpack/scope.txt"),
    "hibp_api_key": "",        # opsional: kunci API HIBP
    "nuclei_proxy": "socks5://127.0.0.1:9050",   # "" = tanpa proxy
    "nmap_via_tor": True,      # nmap wajib via proxychains4 (-sT) — doctrine Tor
    "nmap_tor_ports": "21,22,25,53,80,110,143,443,445,465,587,993,995,1433,1521,2049,3000,3306,3389,5000,5432,5900,6379,8000,8080,8443,8888,9090,9200,27017",
    "wayback_limit": 20000,
    "dkim_selectors": ["default", "google", "selector1", "selector2", "k1", "mail", "s1", "s2"],
    # KEBIJAKAN R216 (user): OSINT by kzldx = tool bebas — allowlist TIDAK dipakai.
    #   enforce_scope true → kembali fail-closed lama (utk kerja pentest terkontrak).
    #   enforce_blocklist → 3 domain proyek lain di scope.txt (!…) tetap ditolak.
    "enforce_scope": False,
    "enforce_blocklist": False,   # DIMATIKAN 2026-10-05 (user) — blocklist nonaktif
}

def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    p = BASE / "config.json"
    if p.exists():
        try:
            cfg.update(json.loads(p.read_text()))
        except Exception as e:
            print(f"[!] config.json gagal dibaca ({e}) — pakai default", file=sys.stderr)
    # O10 (Dev GreyHat 2026-10-05): portability — path asal BlackArch mungkin
    # tidak ada di mesin ini (mis. Windows). Fallback diam2, config tak diubah.
    try:
        if cfg.get("output_dir") and not Path(cfg["output_dir"]).parent.exists():
            cfg["output_dir"] = str(BASE / "output")
        if cfg.get("scope_file"):
            _sf = Path(os.path.expanduser(cfg["scope_file"]))
            if not _sf.exists():
                for _alt in (BASE / "scope.txt", Path.home() / "tools" / "immpack" / "scope.txt"):
                    if _alt.exists():
                        cfg["scope_file"] = str(_alt)
                        break
    except Exception:
        pass
    return cfg

CFG = load_config()

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    CONS = Console(width=120)
    RICH = True
except Exception:  # fallback tanpa rich
    class _C:
        def print(self, *a, **k): print(*a)
    CONS = _C()
    Table = Panel = Text = None
    box = None
    RICH = False

# ─────────────────────────── SCOPE (fail-closed) ───────────────────────────
def host_of(value: str) -> str:
    s = str(value or "").strip().lower()
    if not s: return ""
    if "://" in s: s = s.split("://", 1)[1]
    return s.split("/")[0].split(":")[0].split("@")[-1]

def _load_scope() -> tuple[bool, list[str], list[str]]:
    allow, block = [], []
    try:
        for raw in Path(CFG["scope_file"]).read_text().splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line: continue
            tok = line.split()[0].lower()
            (block if tok.startswith("!") else allow).append(tok.lstrip("!"))
        return True, allow, block
    except Exception:
        return False, [], []

def _match(host: str, pat: str) -> bool:
    if not host or not pat: return False
    if host == pat: return True
    if pat.startswith("*."): return host.endswith(pat[1:])
    return host.endswith("." + pat)

def scope_verdict(target: str) -> str:
    ok, allow, block = _load_scope()
    h = host_of(target)
    if not ok:
        return "scope.txt TIDAK TERBACA — SEMUA di luar cakupan (fail-closed)."
    for p in block:
        if _match(h, p): return f"BLOCKLIST — jangan disentuh: {h} (rule: !{p})"
    for p in allow:
        if _match(h, p): return f"IN SCOPE: {h} (rule: {p})"
    return f"OUT OF SCOPE (fail-closed): {h} tidak ada di scope.txt."

def require_scope(target: str, authorized: bool, passive: bool = False) -> str:
    """Gerbang scope. R216 (user): default NONAKTIF — enforce_scope=false →
    semua modul (aktif/pasif) boleh target apa pun, SENYAP tanpa halangan.
    Yang tersisa: blocklist proyek lain ('!' di scope.txt) bila
    enforce_blocklist=true. Set enforce_scope=true di config.json untuk
    kembali ke mode fail-closed lama (kerja pentest terkontrak)."""
    v = scope_verdict(target)
    if not CFG.get("enforce_scope"):
        if CFG.get("enforce_blocklist", True) and v.startswith("BLOCKLIST"):
            CONS.print(f"[red]  ✗ {v}[/red]")
            CONS.print("[red]    Blocklist proyek lain — matikan dgn enforce_blocklist=false bila memang perlu.[/red]")
            sys.exit(2)
        return v                       # mode bebas: lewat tanpa suara
    if v.startswith("IN SCOPE"):
        CONS.print(f"[green]  ✓ {v}[/green]")
    elif authorized:
        CONS.print(f"[yellow]  ⚠ {v}[/yellow]")
        CONS.print("[yellow]  ⚠ OVERRIDE --authorized aktif — Anda menyatakan punya izin tertulis.[/yellow]")
    elif passive and v.startswith("OUT OF SCOPE"):
        CONS.print(f"[yellow]  ◦ {v}[/yellow]")
        CONS.print("[yellow]    OSINT PASIF: data dari sumber publik/pihak ketiga (DNS·whois·crt.sh·Wayback);"
                   " tanpa traffic langsung ke target. Blocklist TETAP berlaku.[/yellow]")
    else:
        CONS.print(f"[red]  ✗ {v}[/red]")
        CONS.print("[red]    Ditolak (fail-closed). Tambahkan ke scope.txt atau pakai --authorized bila punya izin terpisah.[/red]")
        sys.exit(2)
    return v

# ─────────────────────────── HTTP (Tor) ───────────────────────────
import requests as _rq

def session() -> "_rq.Session":
    s = _rq.Session()
    s.headers.update({"User-Agent": CFG["user_agent"]})
    if CFG["use_tor"]:
        s.proxies.update({"http": CFG["tor_proxy"], "https": CFG["tor_proxy"]})
    s.verify = True
    return s

def http_get(url: str, timeout: int | None = None, stream: bool = False, verify: bool = True):
    try:
        return session().get(url, timeout=timeout or CFG["timeout"], stream=stream,
                             allow_redirects=True, verify=verify)
    except Exception as e:
        return e  # dikembalikan agar pemanggil bisa bedakan error vs respons

def http_ok(url: str, **kw):
    r = http_get(url, **kw)
    return r if not isinstance(r, Exception) else None

try:
    import urllib3 as _u3
    _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
except Exception:
    pass

def tor_up() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 9050), timeout=3):
            return True
    except Exception:
        return False

# ─────────────────────────── UTIL ───────────────────────────
SESSION_OUT: Path | None = None   # satu folder per invokasi CLI (di-set di main)

def outdir(target: str, mk: bool = True) -> Path:
    global SESSION_OUT
    if SESSION_OUT is None:       # lazy: menu interaktif mengisi saat target diset
        slug = re.sub(r"[^A-Za-z0-9._-]", "_", host_of(target) or "target")
        SESSION_OUT = Path(CFG["output_dir"]) / f"{slug}_{_dt.datetime.now():%Y%m%d-%H%M%S}"
    d = SESSION_OUT
    if mk: d.mkdir(parents=True, exist_ok=True)
    return d

def save_json(path: Path, data) -> Path:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    return path

def sh(cmd: list[str], timeout: int = 300) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, f"tool tidak ada: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "timeout"

def have(binname: str) -> bool:
    return shutil.which(binname) is not None

def section(title: str):
    CONS.print(f"\n[bold cyan]══ {title} {'═' * max(2, 70 - len(title))}[/bold cyan]")

def tbl(headers, rows, title=None):
    if Table is None:
        print(" | ".join(map(str, headers)))
        for r in rows: print(" | ".join(map(str, r)))
        return
    t = Table(*headers, box=box.SIMPLE_HEAVY, title=title)
    for r in rows:
        t.add_row(*[str(x) for x in r])
    CONS.print(t)

# ─────────────────────────── INTEL: deteksi → kerentanan + teknik ───────────────────────────
# (kata-kunci-lowercase, topik, SEV, ⚠ kerentanan, 🔧 teknik lanjutan)
INTEL_KB = [
    (("wordpress", "wp-content", "wp-json", "wp-login", "wp-admin"), "WordPress",
     "HIGH", "Core/plugin/theme sering CVE; enumerasi user via REST; brute login; xmlrpc amplifikasi",
     "nuclei -tags wordpress,cve · GET /wp-json/wp/v2/users · cek /xmlrpc.php · wp-content listing · admin → theme-editor"),
    (("woocommerce",), "WooCommerce",
     "HIGH", "Transaksi/PPI; log & endpoint REST order rawan IDOR/kebocoran",
     "enum /wp-json/wc/v3/ · cek /wp-content/uploads/wc-logs/ · nuclei -tags woocommerce"),
    (("elementor",), "Elementor",
     "MED", "Template REST & file JSON exposure; riwayat RCE via upload (Pro)",
     "GET /wp-json/elementor/ · cek /wp-content/uploads/elementor/ · nuclei -tags elementor"),
    (("jet-elements", "jetengine"), "JetElements/JetEngine",
     "MED", "API template Elementor bisa baca konten tanpa auth?",
     "GET /wp-json/jet-elements-api/v1/elementor-template?id=1 (bandingkan id)"),
    (("drupal",), "Drupal",
     "HIGH", "Core/ekstensi lama → kelas SA-CORE; settings.php leak",
     "nuclei -tags drupal · cek /CHANGELOG.txt /core/install.php /sites/default/settings.php"),
    (("joomla",), "Joomla",
     "MED", "configuration.php backup & ekstensi lama rawan",
     "nuclei -tags joomla · cek /administrator/ · dork ext:bak configuration.php"),
    (("laravel", "xsrf-token", "laravel_session"), "Laravel",
     "HIGH", "APP_KEY/.env bocor → forgery cookie sesi & deserialisasi",
     "GET /.env · /storage/logs/laravel.log · nuclei -tags laravel · ignition RCE bila debug on"),
    (("spring", "actuator", "jolokia"), "Spring Boot Actuator",
     "CRIT", "/actuator/env & heapdump bocorkan kredensial & memori proses",
     "GET /actuator/env /actuator/heapdump /jolokia/exec · nonaktifkan di publik"),
    (("asp.net", "x-aspnet", "viewstate"), "ASP.NET",
     "MED", "trace.axd/web.config leak; ViewState tanpa MAC → tampering",
     "cek /trace.axd /web.config · uji __VIEWSTATE tanpa merusak"),
    (("php",), "Runtime PHP",
     "MED", "phpinfo leak path/versi; upload & deserialisasi klasik",
     "cari /info.php · ?phpinfo=1 · nuclei -tags php · batasi upload"),
    (("apache",), "Apache httpd",
     "MED", "Header versi → CVE httpd; kelas mod_status/traversal",
     "nuclei -tags apache,cve · cek /server-status · sembunyikan header Server"),
    (("nginx",), "Nginx",
     "LOW", "off-by-slash alias traversal & status page terbuka",
     "cek /nginx_status · verifikasi alias root sensitif"),
    (("openresty",), "OpenResty/WAF",
     "INFO", "WAF layer-7: rate-limit & challenge (delay session)",
     "teknik N4: delay ≥6s, rotasi header/UA, chunked, rotasi sirkuit Tor"),
    (("litespeed",), "LiteSpeed",
     "LOW", "Cache-control bisa bocorkan status login via cache",
     "cek X-LiteSpeed-Cache saat login · purge berkala"),
    (("iis",), "Microsoft IIS",
     "MED", "web.config leak; WebDAV/PUT method aktif?",
     "cek /web.config · OPTIONS/PUT (hanya bila diizinkan)"),
    (("cloudflare",), "Cloudflare",
     "INFO", "IP asli tersembunyi → cari direct-IP utk bypass WAF",
     "riwayat DNS A lama · SMTP banner · Host-header ke IP · email header"),
    (("bunnycdn", "cdn"), "CDN/WAF depan",
     "INFO", "403 CDN ≠ larangan mutlak — bedakan soft-404 vs proteksi",
     "bandingkan ukuran respons & latensi · tes method lain · stop 403/429/508"),
    (("cpanel", "whm"), "cPanel/WHM",
     "HIGH", "Panel hosting publik → brute-force kredensial",
     "hydra http-post-form -t 3 -W 3 + konfirmasi YA · daftar kecil · MFA"),
    (("plesk",), "Plesk",
     "HIGH", "Panel publik → brute & kelas CVE panel",
     "update patch level · hydra anti-lockout · rate-limit login"),
    (("webmail", "roundcube", "squirrelmail"), "Webmail",
     "HIGH", "Login email publik → akses komunikasi sekolah",
     "uji form login anti-lockout · cek SSO/OAuth · MFA"),
    (("missing strict-transport-security", "hsts"), "HSTS",
     "MED", "Downgrade/sniff HTTPS pada kunjungan pertama",
     "tambah Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    (("missing content-security-policy", "content-security-policy"), "CSP",
     "MED", "XSS tanpa mitigasi berlapis",
     "CSP nonce dlm mode report-only dulu · larang inline/eval"),
    (("missing x-frame-options", "x-frame-options"), "X-Frame-Options",
     "MED", "Clickjacking pada halaman sensitif",
     "X-Frame-Options: DENY / frame-ancestors 'none'"),
    (("missing x-content-type-options",), "X-Content-Type-Options",
     "LOW", "MIME-sniffing", "nosniff pada semua respons"),
    (("header server", "x-powered-by", "x-aspnet-version", "x-generator"), "Fingerprint versi header",
     "LOW", "Versi terekspos → pencarian CVE jauh lebih cepat",
     "hapus/rewrite header Server & X-Powered-By di reverse proxy"),
    (("dmarc: tidak ada", "dmarc absen", "dmarc tidak"), "DMARC absen",
     "HIGH", "Domain bisa dipalsukan → phishing dgn nama domain sendiri",
     "tambah _dmarc TXT p=quarantine → p=reject · audit laporan DMARC"),
    (("spf: tidak ada", "spf absen"), "SPF absen",
     "HIGH", "Kirim email sebagai domain target (spoof) tanpa halangan",
     "v=spf1 include:… -all · pairing DMARC p=reject"),
    (("spf +all",), "SPF +all",
     "CRIT", "SEMUA IP diizinkan kirim sebagai domain → spoof bebas total",
     "ganti +all → -all · audit mekanisme · DMARC p=reject"),
    (("spf ~all", "spf softfail"), "SPF softfail (~all)",
     "MED", "Spoof hanya diarahkan ke spam — belum ditolak keras",
     "naikkan ke -all setelah audit include/mechanism"),
    (("spf tanpa mekanisme",), "SPF tanpa -all/~all",
     "MED", "Tanpa mekanisme akhir → keputusan ditanggung penerima",
     "akhiri rekaman dgn -all"),
    (("dkim",), "DKIM tak terdeteksi",
     "MED", "Email tak terotentikasi → gampang dianggap palsu/spam",
     "aktifkan DKIM sign di MTA · verifikasi selector"),
    (("dmarc policy: none", "p=none"), "DMARC p=none",
     "MED", "Hanya monitoring — pelanggaran tak ditolak",
     "naikkan p=quarantine/reject setelah laporan bersih"),
    ((".git",), "Eksploitasi .git terbuka",
     "CRIT", "Source penuh + histori commit → kredensial lama",
     "git-dumper (read-only) → audit secret → rotasi kredensial"),
    ((".env",), "File .env terbuka",
     "CRIT", "DB creds & APP_KEY/secret aplikasi terekspos",
     "simpan bukti (NDA) · rotasi semua kunci · blokir akses"),
    (("wp-config.php",), "Backup wp-config",
     "CRIT", "Kredensial database WordPress", "simpan/ekspor bukti utk laporan (guard PII off 2026-10-05) - rotasi pass DB"),
    ((".sql",), "Dump database",
     "CRIT", "Isi DB (data pribadi siswa) → risiko PII massal",
     "salin/ekspor isi diizinkan utk laporan (guard off 2026-10-05) - buktikan dampak - lapor"),
    (("backup",), "Arsip backup terbuka",
     "MED", "Backup sering berisi dump/kredensial lama",
     "baca header/ukuran (read-only) · rotasi kredensial bila terbukti"),
    (("phpinfo",), "phpinfo terbuka",
     "MED", "Path instal, versi, env internal bocor",
     "hapus/blokir file info di produksi"),
    (("adminer", "phpmyadmin"), "phpMyAdmin/Adminer",
     "HIGH", "UI DB langsung → kredensial & eksekusi query",
     "IP allowlist + rate-limit · password kuat · MFA"),
    ((".docker",), "Docker exposure",
     "MED", "config.json → kredensial registry/cloud",
     "rotasi token · jangan ekspos docker.sock"),
    (("console", "debugger", "profiler", "elmah", "trace.axd"), "Halaman debug aktif",
     "MED", "Stack trace & data internal bocor",
     "matikan debug mode produksi · batasi 403 internal"),
    (("readme.html", "license.txt"), "File default CMS",
     "LOW", "Mengonfirmasi CMS + versi utk pencarian CVE",
     "hapus file default · update core"),
    (("wayback",), "Arsip Wayback sensitif",
     "MED", "File lama (.env/backup) bisa masih hidup via snapshot",
     "bandingkan snapshot lama vs sekarang · cek hidup-mati · buktikan"),
    (("robots.txt", "disallow"), "robots.txt",
     "INFO", "Peta endpoint; path Disallow = kandidat enumerasi",
     "baca Disallow → masukkan ke sapuan celah"),
    (("security.txt",), "security.txt",
     "INFO", "Kontak responsible disclosure tersedia", "catat penanggung jawab utk laporan"),
    (("aws accesskey",), "Kunci AWS terekspos",
     "CRIT", "Akses cloud (S3/EC2) bila policy longgar",
     "rotasi IAM key · uji izin read-only · audit CloudTrail"),
    (("private key",), "Private key hardcoded",
     "CRIT", "Key material → peniruan TLS/SSH",
     "rotasi key · audit pemakaian"),
    (("hardcoded cred", "basic auth url"), "Kredensial hardcoded",
     "HIGH", "User/pass dalam kode/URL",
     "rotasi · pindah ke server-side"),
    (("jwt",), "Token JWT",
     "MED", "Secret lemah/alg:none → forgery sesi",
     "uji algorithm confusion · hashcat utk secret · expiry singkat"),
    (("google api key",), "API key Google",
     "LOW", "Quota disalahpakai bila tanpa restriction",
     "batasi referrer/API di konsol"),
    (("s3 bucket",), "Bucket S3 publik",
     "MED", "Objek terbaca/tulis publik",
     "ACL private · block public access · encrypt"),
    (("jquery",), "jQuery lama",
     "MED", "CVE-2020-11022/11023 XSS bila <3.5",
     "upgrade ≥3.5 · hindari .html() dgn input"),
    (("bootstrap",), "Bootstrap lama",
     "MED", "XSS sanitizer bila <3.4/4.3", "upgrade · sanitize output"),
    (("21/tcp", "ftp"), "FTP terbuka",
     "MED", "Kredensial plaintext; anonymous write?",
     "uji anonymous read-only · pindah SFTP · hydra -t1 -W3 + konfirmasi"),
    (("25/tcp", "smtp"), "SMTP terbuka",
     "INFO", "Potensi open-relay & spoofing bila auth longgar",
     "uji relay non-destruktif · pastikan auth wajib"),
    (("3389", "ms-wbt-server", "remote desktop"), "RDP terbuka",
     "HIGH", "Brute-force & kelas RDP (BlueKeep)",
     "NLA wajib · batasi login · VPN · hydra anti-lockout bila diizinkan"),
    (("445", "smb"), "SMB terbuka",
     "CRIT", "Kelas EternalBlue & share anonim",
     "enum4linux -a (read-only) · matikan SMBv1 · share minimal"),
    (("3306", "mysql"), "MySQL terbuka",
     "HIGH", "Brute-force & akses DB langsung",
     "bind 127.0.0.1 · user terbatas · lewat VPN"),
    (("1433", "mssql"), "MSSQL terbuka",
     "HIGH", "xp_cmdshell bila misconfig → RCE",
     "batasi akses · matikan xp_cmdshell · audit login"),
    (("27017", "mongo"), "MongoDB terbuka",
     "CRIT", "No-auth → seluruh koleksi (PII)", "aktifkan auth · bind internal"),
    (("6379", "redis"), "Redis terbuka",
     "CRIT", "Write crontab/SSH key → RCE", "bind + auth · tanpa KEYS sembarangan"),
    (("9200", "elastic"), "Elasticsearch terbuka",
     "CRIT", "Indeks log/data penuh (PII)", "aktifkan auth · jangan publik"),
    (("5900", "vnc"), "VNC terbuka",
     "HIGH", "Desktop plaintext tanpa enkripsi", "SSH tunnel/TLS · password kuat"),
    (("login", "masuk", "sign in"), "Halaman login terlihat",
     "MED", "Titik brute-force utama aplikasi",
     "hydra -t 3 -W 3 + konfirmasi · spraying kandidat kecil · MFA"),
    (("403", "401"), "Respons proteksi massal",
     "INFO", "Proteksi ada — bedakan soft-block vs larangan",
     "GET/POST/OPTIONS/HPP · bandingkan ukuran · stop 429/508"),
    (("nuclei temuan",), "Hasil nuclei",
     "INFO", "Temuan otomatis wajib verifikasi non-destruktif",
     "repro read-only → kumpulkan bukti → susun laporan severity"),
    (("presensi", "absensi", "ppdb", "ujian", "nilai"), "Aplikasi akademik (PII siswa)",
     "INFO", "Menyentuh data siswa → batas NDA & PII berlaku",
     "salin/ekspor isi utk laporan diizinkan (guard off 2026-10-05) - buktikan dampak"),
    (("analytics", "gtm", "meta pixel"), "Tracker pihak ketiga",
     "INFO", "Data pengunjung sekolah mengalir ke pihak ketiga",
     "cocokkan kebijakan privasi & persetujuan orang tua"),
    (("dual-stack", "aaaa"), "IPv6 (AAAA) belum ada",
     "LOW", "Riwayat subdomain IPv6 tak terlihat", "cek riwayat AAAA & AAAA target alternatif"),
]
_SEVCOL = {"CRIT": "red", "HIGH": "red", "MED": "yellow", "LOW": "cyan", "INFO": "dim"}

def intel_hits(dets) -> list[tuple[str, str, str, str]]:
    """Cocokkan string deteksi modul dgn KB → (topik, sev, kerentanan, teknik)."""
    blob = " ".join(str(x) for x in dets).lower()
    if not blob: return []
    out, seen = [], set()
    for keys, topik, sev, v, t in INTEL_KB:
        if topik in seen: continue
        if any(k in blob for k in keys):
            seen.add(topik)
            out.append((topik, sev, v, t))
    return out

def intel_panel(target: str, dets, source: str) -> list:
    """Panel ⚠ kerentanan + 🔧 teknik lanjutan utk deteksi baru + simpan intel.json."""
    hits = intel_hits(dets)
    if not hits: return []
    dom = host_of(target)
    if RICH:
        body = Text()
        for topik, sev, v, t in hits:
            body.append(f" {sev:<4} ", style=f"bold {_SEVCOL.get(sev, 'white')}")
            body.append(f"{topik}\n", style="bold white")
            body.append(f"   ⚠ {v}\n", style="yellow")
            body.append(f"   🔧 {t}\n\n", style="green")
        CONS.print(Panel(body, title="[bold magenta]⚠ INTELIJEN — kerentanan & teknik[/bold magenta]",
                         subtitle=f"[dim]{source}[/dim]", box=box.ROUNDED,
                         border_style="magenta", padding=(0, 1)))
    else:
        for topik, sev, v, t in hits:
            print(f"[{sev}] {topik}\n  ⚠ {v}\n  🔧 {t}")
    # simpan (timpa entri source+topik sama agar tak dobel saat run ulang)
    try:
        p = outdir(dom) / "intel.json"
        old = json.loads(p.read_text()) if p.exists() else []
        if not isinstance(old, list): old = []
    except Exception:
        old = []
    old = [e for e in old if not (e.get("source") == source and e.get("topik") in
                                  {h[0] for h in hits})]
    for topik, sev, v, t in hits:
        old.append({"source": source, "topik": topik, "sev": sev, "vuln": v, "teknik": t,
                    "ts": _dt.datetime.now().isoformat(timespec="seconds")})
    try:
        save_json(outdir(dom) / "intel.json", old)
    except Exception:
        pass
    return hits

# ─────────────────────────── DNS ───────────────────────────
def _resolve(name: str, rtype: str, server: str | None = None, lifetime: float = 8.0) -> list[str]:
    try:
        import dns.resolver
        res = dns.resolver.Resolver(configure=True)
        if server:
            res.nameservers = [server]
        res.lifetime = lifetime
        ans = res.resolve(name, rtype, raise_on_no_answer=False)
        if ans is None or ans.rrset is None:
            return []
        out = []
        for rr in ans:
            v = rr.to_text()
            if rtype in ("MX", "SOA", "SRV"):
                v = " ".join(str(x) for x in rr)
            out.append(v)
        return out
    except Exception:
        return []

def mod_dns(target: str, args) -> dict:
    require_scope(target, args.authorized, passive=True)
    dom = host_of(target)
    dns_server = getattr(args, "server", None)
    types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
    data: dict = {"domain": dom, "resolver": dns_server or "sistem", "records": {}}
    for t in types:
        data["records"][t] = _resolve(dom, t, dns_server)
    # Rekaman turunan
    data["records"]["_dmarc TXT"] = _resolve(f"_dmarc.{dom}", "TXT", dns_server)
    data["records"]["_mta-sts TXT"] = _resolve(f"_mta-sts.{dom}", "TXT", dns_server)
    data["records"]["_domainkey TXT"] = _resolve(f"_domainkey.{dom}", "TXT", dns_server)
    for sel in CFG["dkim_selectors"]:
        v = _resolve(f"{sel}._domainkey.{dom}", "TXT", dns_server)
        if v: data["records"][f"DKIM[{sel}] TXT"] = v
    # Analisis
    notes = []
    txts = " ".join(data["records"].get("TXT", []))
    if "v=spf1" in txts:
        m = re.search(r'v=spf1([^"]*)', txts)
        notes.append(f"SPF: {m.group(0)[:160]}")
        tail = (m.group(1) if m else "")
        if "+all" in tail:
            notes.append("SPF +all (SEMUA IP boleh kirim sebagai domain)")
        elif "~all" in tail:
            notes.append("SPF ~all softfail (spoof lolos ke folder spam)")
        elif "-all" not in tail:
            notes.append("SPF tanpa mekanisme akhir -all/~all")
    else:
        notes.append("SPF: TIDAK ADA")
    dmarc = data["records"].get("_dmarc TXT", [])
    if not dmarc:
        notes.append("DMARC: TIDAK ADA (spoofing email terbuka)")
    else:
        pol = " ".join(dmarc)
        q = re.search(r"p=([a-z]+)", pol)
        notes.append(f"DMARC policy: {q.group(1) if q else '?'}")
    if not data["records"]["AAAA"]:
        notes.append("AAAA: belum dual-stack")
    # Tampilkan
    rows = []
    for t, vals in data["records"].items():
        if vals: rows.append((t, "; ".join(v[:110] for v in vals)[:400]))
    tbl(["REKAM", "NILAI"], rows, title=f"DNS {dom}")
    for n in notes: CONS.print(f"  [yellow]• {n}[/yellow]")
    data["notes"] = notes
    intel_panel(target, [f"dns {n}" for n in notes], "dns")
    if args.out:
        save_json(outdir(dom) / "dns.json", data)
    return data

# ─────────────────────────── WHOIS ───────────────────────────
def mod_whois(target: str, args) -> dict:
    require_scope(target, args.authorized, passive=True)
    dom = host_of(target)
    data: dict = {"domain": dom}
    err = ""

    def _map(w) -> dict:
        def g(k, alt=""):
            v = w.get(k, alt)
            if isinstance(v, list): return ", ".join(str(x) for x in v)
            return str(v or alt)
        d = {
            "domain": dom,
            "registrar": g("registrar"),
            "org": g("org"),
            "name": g("name"),
            "country": g("country"),
            "emails": g("emails"),
            "created": g("creation_date"),
            "expires": g("expiration_date"),
            "updated": g("updated"),
            "name_servers": g("name_servers"),
            "status": g("status"),
        }
        return d if any(v for k, v in d.items() if k != "domain") else {}

    def _hasil() -> bool:
        return bool(data.get("registrar") or data.get("name_servers") or data.get("created"))

    # engine 1: pip whois (rusak di Py3.14 / tidak terpasang)
    try:
        import whois as _w
        d = _map(_w.whois(dom))
        if d:
            d["engine"] = "python-whois"
            data = d
    except Exception as e:
        err = str(e)

    # engine 2: whois_shim — integrasi Dev GreyHat (subprocess, Py3.14-safe)
    if not _hasil():
        try:
            import whois_shim as _ws
            d = _map(_ws.whois(dom))
            if d:
                d["engine"] = "whois_shim"
                data = d
                err = ""
        except Exception as e:
            err = f"{err} / shim: {e}"

    # engine 3: binari whois sistem (port-43 langsung)
    if not _hasil():
        rc, out = sh(["whois", dom], timeout=60)
        if rc == 0 and len(out) > 100:
            data = {"domain": dom, "engine": "cli-whois", "raw": out[:8000]}
        else:
            data = {"domain": dom, "error": f"{err} / cli: {out[:200]}"}
    rows = [(k, str(v)[:150]) for k, v in data.items() if v and k != "domain"]
    tbl(["FIELD", "NILAI"], rows, title=f"Whois {dom}")
    if args.out: save_json(outdir(dom) / "whois.json", data)
    return data

# ─────────────────────────── SUBDOMAIN ───────────────────────────
def _crtsh(dom: str) -> set[str]:
    out = set()
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(dom)}&output=json"
    r = http_ok(url, timeout=45)
    if not r: return out
    try:
        for row in r.json():
            nm = (row.get("name_value") or "").strip().lower()
            for part in nm.splitlines():
                part = part.strip().lstrip("*.")
                if part.endswith("." + dom) or part == dom:
                    out.add(part)
    except Exception:
        pass
    return out

def _wayback_subs(dom: str) -> set[str]:
    out = set()
    url = ("http://web.archive.org/cdx/search/cdx?url=*." + urllib.parse.quote(dom)
           + "&fl=original&collapse=urlkey&limit=4000")
    r = http_ok(url, timeout=60)
    if not r: return out
    for line in (r.text or "").splitlines():
        m = re.match(r"https?://([^/:?#]+)", line.strip())
        if m:
            h = m.group(1).lower()
            if h.endswith("." + dom) or h == dom:
                out.add(h)
    return out

def mod_subs(target: str, args) -> dict:
    require_scope(target, args.authorized, passive=True)
    dom = host_of(target)
    found: set[str] = set()
    src: dict[str, int] = {}

    if have("subfinder"):
        rc, out = sh(["subfinder", "-d", dom, "-silent", "-timeout", "30"], timeout=180)
        s = {l.strip().lower() for l in out.splitlines() if l.strip().endswith(dom)}
        src["subfinder"] = len(s); found |= s
    else:
        src["subfinder"] = -1

    s = _crtsh(dom); src["crt.sh"] = len(s); found |= s; time.sleep(CFG["pace"])

    if getattr(args, "wayback", True):
        s = _wayback_subs(dom); src["wayback"] = len(s); found |= s

    if getattr(args, "amass", False) and have("amass"):
        rc, out = sh(["amass", "enum", "-passive", "-d", dom], timeout=600)
        s = {l.strip().lower() for l in out.splitlines() if l.strip().endswith(dom)}
        src["amass"] = len(s); found |= s

    ok, allow, _ = _load_scope()
    rows = []
    for h in sorted(found):
        ins = any(_match(h, p) for p in allow) if ok else False
        rows.append((h, "✓ IN" if ins else "· out"))
    tbl(["SUBDOMAIN", "SCOPE"], rows[:80], title=f"Subdomain {dom} — total {len(found)}")
    data = {"domain": dom, "count": len(found), "by_source": src, "subdomains": sorted(found)}
    if args.out:
        d = outdir(dom)
        save_json(d / "subs.json", data)
        (d / "subs.txt").write_text("\n".join(sorted(found)) + "\n")
    return data

# ─────────────────────────── WEB FINGERPRINT ───────────────────────────
def mod_web(target: str, args) -> dict:
    require_scope(target, args.authorized)
    dom = host_of(target)
    base = target if "://" in target else f"https://{dom}"
    data: dict = {"url": base, "probes": {}, "tech": set()}
    probes = ["", "robots.txt", "sitemap.xml", ".well-known/security.txt", "security.txt", "favicon.ico"]
    for path in probes:
        url = f"{base.rstrip('/')}/{path}"
        r = http_ok(url, timeout=CFG["timeout"])
        if r is None:
            data["probes"][path or "/"] = "ERR"
            continue
        info = {"status": r.status_code, "len": len(r.content), "ct": r.headers.get("Content-Type", "")}
        if path in ("", "robots.txt", "sitemap.xml") and r.status_code == 200:
            body = r.text[:200000]
            m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
            if m: info["title"] = m.group(1).strip()[:120]
            if path == "":
                for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "Link",
                          "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security",
                          "Set-Cookie"):
                    if h in r.headers: info[h] = str(r.headers[h])[:160]
                gen = re.search(r'<meta name="generator" content="([^"]+)"', body, re.I)
                if gen:
                    info["generator"] = gen.group(1)
                    data["tech"].add(gen.group(1).split()[0])
                for name, pat in [("WordPress", r"/wp-content/"), ("Elementor", r"elementor"),
                                  ("Laravel", r"laravel|XSRF-TOKEN"), ("Drupal", r"Drupal.settings"),
                                  ("Joomla", r"/media/jui/"), ("WooCommerce", r"woocommerce"),
                                  ("WAF", r"mx-page|cloudflare")]:
                    if re.search(pat, body, re.I): data["tech"].add(name)
        data["probes"][path or "/"] = info
        time.sleep(CFG["pace"])

    # https validity ringkas
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((dom, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=dom) as ssock:
                cert = ssock.getpeercert()
                data["tls"] = {
                    "subject": dict(x[0] for x in cert.get("subject", ())),
                    "issuer": dict(x[0] for x in cert.get("issuer", ())),
                    "notAfter": cert.get("notAfter"),
                    "san": [v for k, v in cert.get("subjectAltName", [])][:12],
                }
    except Exception as e:
        data["tls"] = {"error": str(e)[:100]}

    data["tech"] = sorted(data["tech"])
    rows = []
    for p, info in data["probes"].items():
        if isinstance(info, dict):
            rows.append((p, info.get("status"), info.get("len"), info.get("title", "") or info.get("ct", "")))
        else:
            rows.append((p, info, "-", ""))
    tbl(["PATH", "STS", "LEN", "TITLE/CT"], rows, title=f"Web {base}")
    if data.get("tls"): CONS.print(f"  [cyan]TLS:[/cyan] {str(data['tls'])[:300]}")
    if data["tech"]: CONS.print(f"  [cyan]Tech:[/cyan] {', '.join(data['tech'])}")
    # ── INTEL ──
    dets = list(data["tech"])
    info0 = data["probes"].get("/", {})
    if isinstance(info0, dict):
        for h in ("Strict-Transport-Security", "Content-Security-Policy",
                  "X-Frame-Options", "X-Content-Type-Options"):
            if h not in info0: dets.append(f"missing {h}")
        for h in ("Server", "X-Powered-By", "X-AspNet-Version"):
            if h in info0: dets.append(f"header {h}: {info0[h]}")
        if info0.get("generator"): dets.append(str(info0["generator"]))
    rb = data["probes"].get("robots.txt")
    if isinstance(rb, dict) and rb.get("status") == 200: dets.append("robots.txt 200 disallow")
    sc = data["probes"].get("security.txt")
    if isinstance(sc, dict) and sc.get("status") == 200: dets.append("security.txt 200")
    if isinstance(data.get("tls"), dict) and data["tls"].get("error"): dets.append("tls error")
    intel_panel(target, dets, "web")
    if args.out: save_json(outdir(dom) / "web.json", data)
    return data

# ─────────────────────────── PORTS (nmap, LANGSUNG/non-Tor) ───────────────────────────
def mod_ports(target: str, args) -> dict:
    require_scope(target, args.authorized)
    dom = host_of(target)
    if not have("nmap"):
        print("[!] nmap tidak ada"); return {}
    d = outdir(dom)
    via_tor = bool(CFG.get("nmap_via_tor", True)) and CFG["use_tor"]
    cmd = []
    if via_tor:
        pconf = BASE / "pc_nmap.conf"
        if not have("proxychains4") or not pconf.exists():
            CONS.print("[red]  ! proxychains4/pc_nmap.conf tidak ada — batal (nmap non-Tor dilarang doctrine)[/red]")
            return {"error": "proxychains4/pc_nmap.conf hilang"}
        cmd += ["proxychains4", "-f", str(pconf), "-q"]
    cmd += ["nmap", "-Pn", "-T3", "--open", "-oA", str(d / "nmap")]
    if via_tor:
        # socks5+Tor: -F macet (ada port silent-drop) → daftar kurasi + host-timeout
        cmd += ["-sT", "--host-timeout", "240s", "-p", CFG.get("nmap_tor_ports", "21,22,25,80,443,445,3306,5432,8080,8443")]
    if getattr(args, "deep", False):
        cmd += ["-sV", "-sC"] + ([] if via_tor else ["--top-ports", "1000"])
    elif not via_tor:
        cmd += ["-F"]
    cmd.append(dom)
    CONS.print(f"  [dim]jalan {'via Tor (proxychains, -sT kurasi)' if via_tor else 'LANGSUNG (non-Tor!)'}: {' '.join(cmd)}[/dim]")
    rc, out = sh(cmd, timeout=getattr(args, "timeout", 900))
    print(out[-4000:])
    # ── INTEL: port terbuka → kerentanan + teknik ──
    dets = [l.strip().lower() for l in out.splitlines()
            if re.match(r"^\d+/tcp\s+open", l.strip())]
    intel_panel(target, dets, "ports")
    return {"rc": rc, "via_tor": via_tor, "output_file": str(d / "nmap.nmap")}

# ─────────────────────────── MAIL ───────────────────────────
def mod_mail(target: str, args) -> dict:
    require_scope(target, args.authorized, passive=True)
    dom = host_of(target)
    data: dict = {"domain": dom}
    data["mx"] = _resolve(dom, "MX")
    data["spf"] = [t for t in _resolve(dom, "TXT") if "v=spf1" in t]
    data["dmarc"] = _resolve(f"_dmarc.{dom}", "TXT")
    data["mta_sts"] = _resolve(f"_mta-sts.{dom}", "TXT")
    data["dkim"] = {}
    for sel in CFG["dkim_selectors"]:
        v = _resolve(f"{sel}._domainkey.{dom}", "TXT")
        if v: data["dkim"][sel] = v
    rows = [("MX", "; ".join(data["mx"]) or "—"),
            ("SPF", "; ".join(data["spf"]) or "TIDAK ADA"),
            ("DMARC", "; ".join(data["dmarc"]) or "TIDAK ADA"),
            ("MTA-STS", "; ".join(data["mta_sts"]) or "—"),
            ("DKIM", ", ".join(data["dkim"]) or "—")]
    tbl(["ITEM", "NILAI"], rows, title=f"Mail {dom}")
    # IP MX + reputasi ringkas
    mxips = []
    for mx in data["mx"]:
        host = mx.split()[-1].rstrip(".")
        for ip in _resolve(host, "A"):
            mxips.append((host, ip))
    if mxips: tbl(["MX HOST", "IP"], mxips)
    data["mx_ip"] = mxips
    # catatan
    notes = []
    if not data["dmarc"]: notes.append("DMARC absen → domain bisa dipalsukan utk phishing")
    if not data["spf"]: notes.append("SPF absen")
    else:
        s = " ".join(data["spf"])
        if "+all" in s: notes.append("SPF +all (SEMUA IP boleh kirim sebagai domain)")
        elif "~all" in s: notes.append("SPF ~all softfail (spoof lolos ke folder spam)")
        elif "-all" not in s: notes.append("SPF tanpa mekanisme akhir -all/~all")
    if not data["dkim"]: notes.append("DKIM tak ditemukan dgn selector umum")
    for n in notes: CONS.print(f"  [yellow]• {n}[/yellow]")
    data["notes"] = notes
    intel_panel(target, [f"mail {n}" for n in notes], "mail")
    if args.out: save_json(outdir(dom) / "mail.json", data)
    return data

# ─────────────────────────── WAYBACK ───────────────────────────
SENSITIVE = ["wp-config", ".env", ".git", ".sql", "backup", "dump", "config.php", "phpmyadmin",
             "adminer", ".bak", ".old", ".zip", ".tar", "log", "token", "secret", "credential",
             "password", "aws", "id_rsa", ".htaccess", "wp-admin", "login", "db_", "database",
             "invoice", "raport", "nilai", "siswa", "presensi", "export", "upload"]

def mod_wayback(target: str, args) -> dict:
    require_scope(target, args.authorized, passive=True)
    dom = host_of(target)
    url = ("http://web.archive.org/cdx/search/cdx?url=" + urllib.parse.quote(dom)
           + "/*&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey"
           + f"&limit={CFG['wayback_limit']}")
    r = http_ok(url, timeout=90)
    data: dict = {"domain": dom}
    if r is None or r.status_code != 200:
        data["error"] = str(r)[:200] if r else "no response"
        print(f"[!] CDX gagal: {data['error']}")
        return data
    try:
        rows = r.json()
    except Exception:
        rows = [l.split() for l in (r.text or "").splitlines() if l.strip()]
    head = ["original", "timestamp", "statuscode", "mimetype"]
    body = rows
    if rows and isinstance(rows[0], list) and rows[0][:1] == ["original"]:
        head, body = rows[0], rows[1:]
    idx = {k: i for i, k in enumerate(head)}
    urls = [row for row in body if len(row) >= 2]
    years: dict = {}
    statuses: dict = {}
    sens = []
    for row in urls:
        orig = row[idx.get("original", 0)]
        ts = row[idx.get("timestamp", 1)] if len(row) > 1 else ""
        st = row[idx.get("statuscode", 2)] if len(row) > 2 else ""
        if len(str(ts)) >= 4: years[str(ts)[:4]] = years.get(str(ts)[:4], 0) + 1
        statuses[str(st)] = statuses.get(str(st), 0) + 1
        low = orig.lower()
        if any(p in low for p in SENSITIVE): sens.append(orig)
    data.update({"total": len(urls), "per_year": dict(sorted(years.items())),
                 "per_status": statuses, "sensitive_count": len(sens)})
    tbl(["TAHUN", "JUMLAH"], list(data["per_year"].items()), title=f"Wayback {dom}")
    CONS.print(f"  [cyan]total URL unik:[/cyan] {len(urls)} · [cyan]status:[/cyan] {data['per_status']}")
    if sens:
        tbl(["URL SENSITIF (kandidat)"], [(u[:150],) for u in sens[:40]], title=f"Filter sensitif — {len(sens)}")
        intel_panel(target, [f"wayback {len(sens)} url sensitif .env backup sql"], "wayback")
    if args.out:
        d = outdir(dom)
        save_json(d / "wayback.json", data)
        (d / "wayback_urls.txt").write_text("\n".join(u[idx.get("original", 0)] for u in urls) + "\n")
        if sens: (d / "wayback_sensitive.txt").write_text("\n".join(sorted(set(sens))) + "\n")
    return data

# ─────────────────────────── WAYBACK DIFF (v2.1) ───────────────────────────
def _html_text(raw: str) -> str:
    """Ekstrak teks terlihat dari HTML (bs4 bila ada, fallback regex).

    Pertahankan pemisah baris per-elemen → unified diff terbaca (bukan 1 blok).
    """
    try:
        from bs4 import BeautifulSoup
        txt = BeautifulSoup(raw, "html.parser").get_text("\n", strip=True)
    except Exception:
        txt = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", "\n", raw)
        txt = re.sub(r"(?s)<[^>]+>", "\n", txt)
    txt = txt.replace("&nbsp;", " ").replace("&amp;", "&")
    lines = [re.sub(r"[ \t]+", " ", l).strip() for l in txt.splitlines()]
    return "\n".join(l for l in lines if l)

def _norm_body(text: str) -> str:
    """Normalisasi konten sebelum diff: HTML → teks terlihat; teks → trim baris."""
    head = text[:2000].lower()
    if "<html" in head or "<!doctype" in head:
        return _html_text(text)
    return "\n".join(l.rstrip() for l in text.splitlines() if l.strip())

def mod_waybackdiff(target: str, args) -> dict:
    """Diff halaman: snapshot wayback TERTUA vs kondisi LIVE sekarang (passive).

    v2.1 — IDEE.txt #4. CDX cari semua snapshot → ambil tertua & terbaru,
    render `id_` (original tanpa toolbar wayback), fetch live, difflib ratio.
    """
    require_scope(target, args.authorized, passive=True)
    dom = host_of(target)
    url = getattr(args, "url", None) or (target if "://" in target else f"https://{dom}/")
    if "://" not in url: url = "https://" + url
    data: dict = {"domain": dom, "url": url}
    cdx = ("http://web.archive.org/cdx/search/cdx?url=" + urllib.parse.quote(url, safe="")
           + "&output=json&fl=timestamp,statuscode,length&limit=5000")
    r = http_ok(cdx, timeout=90)
    if r is None or r.status_code != 200:
        data["error"] = str(r)[:200] if r else "no response"
        print(f"[!] CDX gagal: {data['error']}")
        return data
    try:
        rows = r.json()
    except Exception:
        rows = [l.split() for l in (r.text or "").splitlines() if l.strip()]
    body = rows
    if rows and isinstance(rows[0], list) and rows[0][:1] == ["timestamp"]:
        body = rows[1:]
    stamps = sorted({(str(row[0]), str(row[1]) if len(row) > 1 else "-")
                     for row in body if row and str(row[0]).isdigit()})
    if not stamps:
        data["error"] = "tidak ada snapshot utk URL ini"
        print("[!] waybackdiff: tidak ada snapshot utk URL ini")
        return data
    ts_old, st_old = stamps[0]
    ts_new, st_new = stamps[-1]

    def snap(ts: str) -> str | None:
        rr = http_ok(f"https://web.archive.org/web/{ts}id_/{url}", timeout=90)
        return rr.text if rr is not None and rr.status_code == 200 else None

    old_raw = snap(ts_old)
    live = http_ok(url, timeout=60)
    now = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    if old_raw is None or live is None:
        data["error"] = "gagal ambil snapshot wayback" if old_raw is None else "gagal fetch live"
        print(f"[!] waybackdiff: {data['error']}")
        return data
    a = _norm_body(old_raw)[:200000]
    b = _norm_body(live.text or "")[:200000]
    ratio = round(difflib.SequenceMatcher(None, a, b).ratio(), 4)
    diff_txt = "\n".join(list(difflib.unified_diff(
        a.splitlines(), b.splitlines(),
        fromfile=f"wayback:{ts_old}", tofile=f"live:{now}", lineterm=""))[:600])
    data.update({
        "snapshot_old": ts_old, "snapshot_new": ts_new,
        "status_old": st_old, "status_new": st_new,
        "status_live": getattr(live, "status_code", None),
        "len_old": len(a), "len_live": len(b),
        "len_delta_pct": round((len(b) - len(a)) / max(len(a), 1) * 100, 1),
        "similarity": ratio,
    })
    tbl(["JENIS", "TIMESTAMP", "STATUS", "PANJANG(teks)"],
        [("wayback tertua", ts_old, st_old, len(a)),
         ("wayback terbaru", ts_new, st_new, "-"),
         ("live sekarang", now, data["status_live"], len(b))],
        title=f"Wayback Diff — {url}")
    warn = ("[red]MIRIP[/red]" if ratio > 0.95 else
            "[yellow]BEDA SEDIKIT[/yellow]" if ratio > 0.6 else "[bold red]JAUH BERUBAH[/bold red]")
    CONS.print(f"  kemiripan teks: [cyan]{ratio:.1%}[/cyan] {warn}"
               f" · delta panjang: {data['len_delta_pct']:+}% · {len(diff_txt.splitlines())} baris diff")
    if args.out:
        d = outdir(dom)
        save_json(d / "waybackdiff.json", data)
        (d / "waybackdiff.diff").write_text(diff_txt + "\n")
        CONS.print(f"  [dim]simpan: {d}/waybackdiff.json + .diff[/dim]")
    return data

# ─────────────────────────── REPORT → HTML (v3.0) ───────────────────────────
def _md2html(md: str) -> str:
    """Markdown subset (heading/tabel/list/code/hr/inline) → HTML. Murni stdlib."""
    import html as _h
    L = md.splitlines()
    o: list[str] = []
    i = 0

    def inline(s: str) -> str:
        s = _h.escape(s, quote=False)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
        s = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<i>\1</i>", s)
        return re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', s)

    def cells(row: str) -> list[str]:
        return [c.strip() for c in row.strip().strip("|").split("|")]

    while i < len(L):
        ln = L[i]
        if ln.startswith("```"):
            j, buf = i + 1, []
            while j < len(L) and not L[j].startswith("```"):
                buf.append(L[j]); j += 1
            o.append("<pre>" + _h.escape("\n".join(buf)) + "</pre>")
            i = j + 1; continue
        m = re.match(r"^(#{1,6})\s+(.*)$", ln)
        if m:
            lv = len(m.group(1))
            o.append(f"<h{lv}>{inline(m.group(2))}</h{lv}>"); i += 1; continue
        if re.match(r"^\s*([-*_])(\s*\1){2,}\s*$", ln):
            o.append("<hr>"); i += 1; continue
        if ("|" in ln and i + 1 < len(L) and "-" in L[i + 1]
                and re.match(r"^\s*\|?[\s:|-]+\|[\s:|-]*$", L[i + 1])):
            head = cells(ln); i += 2
            rows = []
            while i < len(L) and "|" in L[i] and L[i].strip():
                rows.append(cells(L[i])); i += 1
            o.append("<table><thead><tr>"
                     + "".join(f"<th>{inline(c)}</th>" for c in head)
                     + "</tr></thead><tbody>")
            for row in rows:
                o.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in row) + "</tr>")
            o.append("</tbody></table>"); continue
        if re.match(r"^\s*[-*]\s+\S", ln):
            items = []
            while i < len(L) and re.match(r"^\s*[-*]\s+\S", L[i]):
                items.append(inline(re.sub(r"^\s*[-*]\s+", "", L[i]))); i += 1
            o.append("<ul>" + "".join(f"<li>{x}</li>" for x in items) + "</ul>"); continue
        if re.match(r"^\s*\d+\.\s+\S", ln):
            items = []
            while i < len(L) and re.match(r"^\s*\d+\.\s+\S", L[i]):
                items.append(inline(re.sub(r"^\s*\d+\.\s+", "", L[i]))); i += 1
            o.append("<ol>" + "".join(f"<li>{x}</li>" for x in items) + "</ol>"); continue
        if not ln.strip():
            i += 1; continue
        buf = []
        while (i < len(L) and L[i].strip()
               and not re.match(r"^(#{1,6}\s|```|\s*[-*]\s|\s*\d+\.\s)", L[i])
               and "|" not in L[i]):
            buf.append(L[i]); i += 1
        o.append("<p>" + inline(" ".join(buf)) + "</p>")
    return "\n".join(o)

def cmd_report(target: str, args) -> None:
    """report.md terbaru → report.html mandiri (dark theme, tanpa dependensi)."""
    root = Path(CFG["output_dir"])
    cands = sorted(root.glob("*/report.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    if target and not target.startswith("@"):
        dom = host_of(target)
        cands = [p for p in cands if dom and dom in p.parent.name] or cands
    if not cands:
        CONS.print("[yellow]belum ada report.md — jalankan `run <target>` dulu[/yellow]")
        return
    src = cands[0]
    md = src.read_text(errors="replace")
    tm = re.search(r"^#\s+(.+)$", md, re.M)
    title = tm.group(1).strip() if tm else src.parent.name
    body = _md2html(md)
    page = f"""<!DOCTYPE html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ --fg:#d7dae0; --mut:#8b949e; --acc:#58a6ff; --bg:#0d1117; --card:#161b22; --bd:#30363d; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--fg);
  font:15px/1.65 "JetBrains Mono",ui-monospace,Consolas,monospace; }}
header {{ background:linear-gradient(135deg,#161b22,#0d1117 60%);
  border-bottom:2px solid var(--acc); padding:28px 5vw 20px; }}
header h1 {{ margin:0 0 6px; font-size:24px; color:#fff; }}
header .meta {{ color:var(--mut); font-size:12px; }}
main {{ max-width:1000px; margin:0 auto; padding:28px 5vw 60px; }}
h2 {{ color:var(--acc); border-bottom:1px solid var(--bd); padding-bottom:6px;
  margin-top:34px; font-size:18px; }}
h3 {{ color:#79c0ff; margin-top:24px; font-size:15px; }}
table {{ border-collapse:collapse; width:100%; margin:14px 0; font-size:13px; display:block;
  overflow-x:auto; }}
th,td {{ border:1px solid var(--bd); padding:7px 10px; text-align:left; }}
th {{ background:#1f2430; color:#79c0ff; }}
tr:nth-child(even) td {{ background:#12161d; }}
pre {{ background:#12161d; border:1px solid var(--bd); border-left:3px solid var(--acc);
  padding:12px 14px; overflow-x:auto; border-radius:4px; font-size:13px; }}
code {{ background:#1f2430; padding:1px 5px; border-radius:3px; color:#ffa657; font-size:13px; }}
pre code {{ background:none; padding:0; color:var(--fg); }}
ul,ol {{ padding-left:22px; }}
li {{ margin:3px 0; }}
a {{ color:var(--acc); }}
hr {{ border:none; border-top:1px solid var(--bd); margin:26px 0; }}
footer {{ color:var(--mut); font-size:11px; text-align:center; padding:18px;
  border-top:1px solid var(--bd); }}
</style></head>
<body>
<header><h1>{title}</h1>
<div class="meta">target: {src.parent.name} · {_dt.datetime.now():%Y-%m-%d %H:%M WIB} · Generator: OSINT by kzldx v2.2</div></header>
<main>
{body}
</main>
<footer>OSINT by kzldx — laporan generated · handle sesuai NDA/scope</footer>
</body></html>
"""
    dst = src.with_name("report.html")
    dst.write_text(page)
    CONS.print(f"[green]HTML laporan:[/green] {dst}")
    CONS.print(f"  [dim]{len(page):,} bytes · {title}[/dim]")

# ─────────────────────────── GRAF SUBDOMAIN (v3.0) ───────────────────────────
def mod_graf(target: str, args) -> dict:
    """Pohon subdomain → graphviz dot + SVG (lokal, tanpa network).

    v3.1 — IDEE.txt #6. Sumber: subs.json run sesi ini / run terbaru utk dom.
    """
    require_scope(target, args.authorized, passive=True)
    dom = host_of(target)
    root = Path(CFG["output_dir"])
    cands: list[Path] = []
    if SESSION_OUT and (SESSION_OUT / "subs.json").exists():
        cands.append(SESSION_OUT / "subs.json")
    cands += sorted(root.glob(f"{dom}_*/subs.json"),
                    key=lambda p: p.stat().st_mtime, reverse=True)
    if not cands:
        CONS.print("[yellow]subs.json belum ada — jalankan `subs <target>` dulu[/yellow]")
        return {"domain": dom, "error": "subs.json tidak ada"}
    src = cands[0]
    raw = json.loads(src.read_text(errors="replace"))
    # tambahan: node DNS dari dns.json bila ada (A=IP · NS · MX — backlog "graf subdomain/IP/NS")
    dns_rec: dict = {}
    dns_p = src.parent / "dns.json"
    if dns_p.exists():
        try:
            dns_rec = (json.loads(dns_p.read_text(errors="replace")) or {}).get("records", {}) or {}
        except Exception:
            dns_rec = {}
    hosts: set[str] = set()
    pat = re.compile(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}")

    def walk(x):
        if isinstance(x, str):
            for m in pat.findall(x.lower()):
                if m == dom or m.endswith("." + dom):
                    hosts.add(m)
        elif isinstance(x, dict):
            for v in x.values(): walk(v)
        elif isinstance(x, list):
            for v in x: walk(v)

    walk(raw)
    hosts.add(dom)
    # edge: parent terdekat dalam set; tak ada parent → ke apex
    edges = []
    for h in sorted(hosts):
        if h == dom: continue
        rest = h.split(".", 1)[1] if "." in h else ""
        parent = rest if rest in hosts else dom
        edges.append((parent, h))
    # warna per label subdomain relatif apex (www, mail, ppdb, ...)
    palette = ["#58a6ff", "#7ee787", "#ffa657", "#d2a8ff", "#79c0ff",
               "#f778ba", "#56d4dd", "#e3b341"]

    def lab_of(h: str) -> str:
        if h == dom or not h.endswith("." + dom):
            return dom
        return h[: -(len(dom) + 1)].split(".")[0]

    labels = sorted({lab_of(h) for h in hosts if h != dom})
    color = {lb: palette[i % len(palette)] for i, lb in enumerate(labels)}

    dot = ["digraph G {", "  rankdir=LR;", '  graph [bgcolor="#0d1117",pad=0.3];',
           '  node [shape=box,style="rounded,filled",fontname="monospace",'
           'fontsize=10,fontcolor="#d7dae0",color="#30363d"];',
           '  edge [color="#30363d"];',
           f'  "{dom}" [fillcolor="#b08800",fontcolor="#000",style="rounded,filled,bold"];']
    for h in sorted(hosts):
        if h == dom: continue
        dot.append(f'  "{h}" [fillcolor="{color.get(lab_of(h), "#21262d")}"];')
    for p, h in edges:
        dot.append(f'  "{p}" -> "{h}";')
    # node DNS: IP (ellipse), NS (component), MX (cds) — edge dari apex
    dns_nodes = 0
    for ip in (dns_rec.get("A") or [])[:20]:
        dot.append(f'  "ip:{ip}" [shape=ellipse,fillcolor="#8b949e",fontcolor="#0d1117",label="{ip}"];')
        dot.append(f'  "{dom}" -> "ip:{ip}";'); dns_nodes += 1
    for ns in (dns_rec.get("NS") or [])[:12]:
        ns2 = str(ns).rstrip(".")
        dot.append(f'  "ns:{ns2}" [shape=component,fillcolor="#d2a8ff",fontcolor="#0d1117",label="{ns2}"];')
        dot.append(f'  "{dom}" -> "ns:{ns2}";'); dns_nodes += 1
    for mx in (dns_rec.get("MX") or [])[:12]:
        mx2 = str(mx).rstrip(".")
        dot.append(f'  "mx:{mx2}" [shape=cds,fillcolor="#f778ba",fontcolor="#0d1117",label="{mx2}"];')
        dot.append(f'  "{dom}" -> "mx:{mx2}";'); dns_nodes += 1
    dot.append("}")
    dot_txt = "\n".join(dot) + "\n"
    outd = src.parent if src.parent != root else outdir(dom)
    (outd / "graf.dot").write_text(dot_txt)
    svg = outd / "graf.svg"
    if shutil.which("dot"):
        rc, log = sh(["dot", "-Tsvg", "-o", str(svg), str(outd / "graf.dot")], timeout=60)
        if rc != 0:
            CONS.print(f"[yellow]dot gagal (rc={rc}): {log[:150]}[/yellow]")
    else:
        CONS.print("[yellow]graphviz tidak ada — hanya graf.dot (apt install graphviz)[/yellow]")
    data = {"domain": dom, "source": str(src), "hosts": len(hosts),
            "edges": len(edges), "labels": len(labels), "dns_nodes": dns_nodes,
            "dot": str(outd / "graf.dot"), "svg": str(svg) if svg.exists() else None}
    rows = [("host total", len(hosts)), ("edge", len(edges)),
            ("cluster label", len(labels))]
    if dns_nodes:
        rows.append(("node DNS (A/NS/MX)", dns_nodes))
    rows.append(("sumber", src.parent.name))
    tbl(["METRIK", "NILAI"], rows, title=f"Graf Subdomain {dom}")
    if svg.exists():
        CONS.print(f"  [green]SVG:[/green] {svg}")
    if args.out:
        save_json(outd / "graf.json", data)
    return data

# ─────────────────────── MMH3 (favicon hash — Shodan/FOFA) ───────────────────────
def _mmh3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86-32 pure-Python — fallback bila paket mmh3 absen."""
    def rotl(x: int, r: int) -> int:
        return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF
    c1, c2 = 0xcc9e2d51, 0x1b873593
    h, n = seed & 0xFFFFFFFF, len(data)
    for i in range(0, n - n % 4, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & 0xFFFFFFFF; k = rotl(k, 15); k = (k * c2) & 0xFFFFFFFF
        h ^= k; h = rotl(h, 13); h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF
    tail = data[n - n % 4:]
    if tail:
        k = int.from_bytes(tail + b"\x00" * (4 - len(tail)), "little")
        k = (k * c1) & 0xFFFFFFFF; k = rotl(k, 15); k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= n
    h ^= h >> 16; h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= h >> 13; h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= h >> 16
    return h - 0x100000000 if h & 0x80000000 else h

def _favicon_hash(content: bytes) -> int:
    """Hash favicon ala Shodan: mmh3(base64.encodebytes(bytes)) — resep canonical."""
    payload = base64.encodebytes(content)
    try:
        import mmh3
        return int(mmh3.hash(payload))
    except Exception:
        return _mmh3_32(payload)

# ─────────────────────────── FAVICON HASH (v2.2-redteam) ───────────────────────────
# dukung rel terkutip ("shortcut icon"), & atribut polos tanpa kutip (rel=icon)
ICON_REL = re.compile(
    r'''(?is)<link[^>]+rel=(?:"[^"]*icon[^"]*"|'[^']*icon[^']*'|[^\s>]*icon[^\s>]*)[^>]*>''')

def mod_favicon(target: str, args) -> dict:
    """mmh3 favicon hash → pivot cari aset se-organisasi di Shodan/FOFA.

    Inspirasi: hacktricks external-recon-methodology §Favicon — hash sama
    = aset/kemungkinan aset yang sama. Sumber: <link rel=icon> + /favicon.ico.
    """
    require_scope(target, args.authorized, passive=True)
    dom = host_of(target)
    data: dict = {"domain": dom, "icons": []}
    items: list = []                      # (kind, value)
    fpath = getattr(args, "file", None)
    if fpath:
        p = Path(fpath)
        if not p.exists():
            print(f"[!] file tidak ada: {fpath}")
            return {"error": "file tidak ada"}
        items.append(("file", str(p)))
    else:
        base = target if "://" in target else f"https://{dom}/"
        urls: list[str] = []
        home = http_ok(base, timeout=45)
        if home is not None and getattr(home, "status_code", 0) == 200:
            for tag in ICON_REL.findall(home.text or "")[:10]:
                m = re.search(r'''(?is)href=["']?([^"'>\s]+)["']?''', tag)
                if m:
                    href = urllib.parse.urljoin(base, m.group(1))
                    # data:/javascript: ditolak (kosong / bukan aset ikon)
                    if href.startswith("http") and not href.startswith("data:"):
                        urls.append(href)
        urls.append(urllib.parse.urljoin(base, "/favicon.ico"))
        seen = set()
        for u in urls:
            if u not in seen:
                seen.add(u); items.append(("url", u))
    for kind, src in items[:8]:
        if kind == "file":
            try:
                raw = Path(src).read_bytes()
            except Exception as e:
                print(f"[!] baca {src}: {e}"); continue
            label = Path(src).name
        else:
            r = http_ok(src, timeout=30)
            if r is None or getattr(r, "status_code", 0) != 200 or not getattr(r, "content", b""):
                continue
            raw = r.content; label = src
        if not raw:
            continue
        sha16 = hashlib.sha256(raw).hexdigest()[:16]
        if any(e["sha256_16"] == sha16 for e in data["icons"]):
            continue          # dedupe: path beda, isi & hash sama
        h = _favicon_hash(raw)
        sh = f"https://www.shodan.io/search?query=http.favicon.hash%3A{h}"
        fo = ("https://fofa.info/result?qbase64="
              + base64.b64encode(f'icon_hash="{h}"'.encode()).decode())
        data["icons"].append({"source": label, "size": len(raw),
                              "sha256_16": sha16,
                              "mmh3": h, "dorks": {"shodan": sh, "fofa": fo}})
    if not data["icons"]:
        print("[!] tidak ada ikon terambil (favicon tidak ada / semua gagal)")
        return data
    tbl(["SUMBER", "UKURAN", "SHA256(16)", "MMH3"],
        [(e["source"][-58:], f"{e['size']} B", e["sha256_16"], e["mmh3"])
         for e in data["icons"]],
        title=f"Favicon Hash {dom}")
    for e in data["icons"]:
        CONS.print(f"  [cyan]{e['mmh3']}[/cyan] · Shodan: {e['dorks']['shodan']}")
        CONS.print(f"        · FOFA: {e['dorks']['fofa']}")
    CONS.print("  [dim]hash sama di hasil orang lain → aset/kemungkinan aset sama[/dim]")
    if args.out:
        d = outdir(dom)
        save_json(d / "favicon.json", data)
    return data

# ─────────────────────────── TRACKERS (v2.2-redteam) ───────────────────────────
TRACKER_SIG = [
    ("Google Analytics UA", r"(UA-\d{4,10}-\d{1,4})"),
    ("Google Analytics 4", r"\b(G-[A-Z0-9]{8,})\b"),
    ("Google Tag Manager", r"\b(GTM-[A-Z0-9]{4,})\b"),
    ("Google AdSense", r"(ca-pub-\d{6,})"),
    ("Google site-verify", r'''name=["']google-site-verification["'][^>]*content=["']([^"']+)["']'''),
    ("Facebook Pixel", r"""fbq\(['"]init['"],\s*['"](\d{5,})['"]"""),
    ("Bing site-verify", r'''name=["']msvalidate\.01["'][^>]*content=["']([^"']+)["']'''),
    ("Yandex verify", r'''name=["']yandex-verification["'][^>]*content=["']([^"']+)["']'''),
    ("Hotjar", r"\b(hotjar-\d{4,})\b"),
    ("Matomo/Piwik", r"(?:matomo|piwik)\.php[^\"']*[?&]idsite=(\d+)"),
]

def mod_trackers(target: str, args) -> dict:
    """Ekstrak ID tracker/analytics dari homepage → pivot aset (hacktricks §Trackers).

    ID sama di 2 situs = kemungkinan dikelola tim/organisasi yang sama.
    """
    require_scope(target, args.authorized, passive=False)
    dom = host_of(target)
    base = target if "://" in target else f"https://{dom}/"
    r = http_ok(base, timeout=45)
    if r is None or getattr(r, "status_code", 0) != 200:
        print(f"[!] gagal fetch homepage: {base}")
        return {"domain": dom, "error": "homepage gagal"}
    html = r.text or ""
    found: dict = {}
    for kind, pat in TRACKER_SIG:
        for m in re.findall(pat, html):
            val = m if isinstance(m, str) else m[0]
            if val and len(val) > 3:
                found.setdefault(kind, set()).add(val)
    data = {"domain": dom,
            "trackers": [{"kind": k, "id": v} for k, vs in sorted(found.items())
                         for v in sorted(vs)]}
    if not data["trackers"]:
        print("[*] tidak ada tracker dikenal di homepage")
        if args.out: save_json(outdir(dom) / "trackers.json", data)
        return data
    tbl(["JENIS", "ID"],
        [(k, v) for k, vs in sorted(found.items()) for v in sorted(vs)],
        title=f"Trackers {dom}")
    pivots = [v for vs in found.values() for v in vs]
    CONS.print("  [dim]pivot (ID sama → situs terkait):[/dim]")
    for v in pivots[:8]:
        q = urllib.parse.quote(f'"{v}"')
        CONS.print(f"    {v} → https://www.google.com/search?q={q}")
    CONS.print("  [dim]atau: spyonweb.com / builtwith.com / publicwww.com (butuh akun)[/dim]")
    if args.out:
        save_json(outdir(dom) / "trackers.json", data)
    return data

# ─────────────────────────── ASN / IP RANGE (v2.2-redteam) ───────────────────────────
def mod_asn(target: str, args) -> dict:
    """IP target → ASN/org/CIDR (RIPEstat + RDAP) → dork Shodan asn:.

    Inspirasi: hacktricks external-recon §ASNs — rentang IP perusahaan →
    cari domain lain di IP serentang (scope-aware).
    """
    require_scope(target, args.authorized, passive=True)
    dom = host_of(target)
    try:
        ip = socket.gethostbyname(dom)
    except Exception as e:
        print(f"[!] resolve gagal: {e}")
        return {"domain": dom, "error": "resolve gagal"}
    data: dict = {"domain": dom, "ip": ip, "asns": [], "org": "", "country": "",
                  "prefix": ""}
    # RIPEstat network-info → ASN + prefix (bgpview.io MATI 2026; RIPEstat no-key)
    r = http_ok(f"https://stat.ripe.net/data/network-info/data.json?resource={ip}",
                timeout=45)
    asn_ids: list = []
    if r is not None and getattr(r, "status_code", 0) == 200:
        try:
            jd = r.json().get("data") or {}
            asn_ids = jd.get("asns") or []
            data["prefix"] = str(jd.get("prefix") or "")
        except Exception:
            pass
    rr = http_ok(f"https://rdap.org/ip/{ip}", timeout=45)
    if rr is not None and getattr(rr, "status_code", 0) == 200:
        try:
            jr = rr.json()
            data["org"] = str(jr.get("name") or "")
            data["country"] = str(jr.get("country") or "")
            data["rdap_handle"] = str(jr.get("handle") or "")
        except Exception:
            pass
    for a in asn_ids[:8]:
        try:
            asn_n = int(a)
        except Exception:
            continue
        holder = ""
        rh = http_ok(
            f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn_n}",
            timeout=45)
        if rh is not None and getattr(rh, "status_code", 0) == 200:
            try:
                holder = str((rh.json().get("data") or {}).get("holder") or "")
            except Exception:
                pass
        data["asns"].append({"asn": asn_n, "name": holder, "prefix": data["prefix"]})
    if not data["asns"] and not data["org"]:
        print("[!] RIPEstat + RDAP tidak memberi data")
        return data
    rows = [(f"AS{a['asn']}", a["name"] or "-", a["prefix"] or "-")
            for a in data["asns"]]
    if not rows:
        rows = [("-", data["org"] or "-", f"RDAP {data.get('rdap_handle','')}")]
    tbl(["ASN", "HOLDER", "PREFIX"], rows, title=f"ASN {dom} → {ip}")
    if data["org"]:
        CONS.print(f"  [cyan]RDAP org:[/cyan] {data['org']} · {data['country']}")
    data["dorks"] = [f"https://www.shodan.io/search?query=asn%3AAS{a['asn']}"
                     for a in data["asns"]]
    for u in data["dorks"]:
        CONS.print(f"  [dim]Shodan pivot:[/dim] {u}")
    CONS.print("  [dim]catatan: rentang IP sah utk enumerasi HANYA bila masuk scope engagement[/dim]")
    if args.out:
        save_json(outdir(dom) / "asn.json", data)
    return data

# ─────────────────────────── RECON-NG WRAPPER (partner engine) ───────────────────────────
def cmd_reconng(target: str, args) -> None:
    """Jalankan modul recon-ng utk target (wrapper; workspace recon-ng per-domain).

    Default: recon/domains-hosts/hackertarget (passive, pihak ketiga).
    --cmd utk perintah global recon-ng (mis: "show hosts").
    """
    require_scope(target, args.authorized, passive=True)
    dom = host_of(target)
    if not shutil.which("recon-cli"):
        print("[!] recon-cli tidak ada di PATH (install: tools/repo/recon-ng)")
        return
    gcmd = getattr(args, "cmd", None)
    if gcmd:
        argv = ["recon-cli", "--no-version", "--no-analytics", "-w", dom, "-C", gcmd]
    else:
        mod = getattr(args, "module", None) or "recon/domains-hosts/hackertarget"
        argv = ["recon-cli", "--no-version", "--no-analytics", "-w", dom,
                "-m", mod, "-o", f"SOURCE={dom}", "-x"]
    if CFG.get("use_tor") and tor_up():
        argv += ["-g", "proxy=socks5h://127.0.0.1:9050"]
    rc, out = sh(argv, timeout=300)
    # bersihkan: warning dependency/syntax + ANSI color
    clean = re.sub(r"\x1b\[[0-9;]*m", "", out)
    noise_re = re.compile(r"key not set|disabled\.|SyntaxWarning|^  \S|"
                          r"No module provided|Version check disabled")
    lines = [l for l in clean.splitlines() if not noise_re.search(l)]
    tail = "\n".join(lines[-30:])
    print(tail)
    CONS.print(f"  [dim]rc={rc} · workspace: ~/.recon-ng/workspaces/{dom}[/dim]")
    if args.out:
        d = outdir(dom)
        save_json(d / "reconng.json", {"domain": dom, "argv": argv, "rc": rc,
                                       "output": tail})
        (d / "reconng.log").write_text(out)
    return

# ─────────────────────────── DORK ───────────────────────────
DORKS = [
    ("Google — file sensitif", 'site:{t} ext:sql OR ext:bak OR ext:env OR ext:log OR ext:csv OR "password"'),
    ("Google — admin/login", 'site:{t} inurl:admin OR inurl:login OR inurl:wp-login OR inurl:dashboard'),
    ("Google — panel", 'site:{t} intitle:"index of" OR intitle:"admin panel" OR intitle:"cpanel"'),
    ("Google — dokumen", 'site:{t} filetype:xlsx OR filetype:pdf OR filetype:docx "daftar" OR "rapor"'),
    ("Google — error leak", 'site:{t} "warning:" OR "fatal error" OR "stack trace" OR "mysqli"'),
    ("Google — email", 'site:{t} "@{t}" OR "email" OR "telepon"'),
    ("GitHub — rahasia", '"{d}" AND (password OR api_key OR secret OR aws_access) path:*.env'),
    ("GitHub search URL", 'https://github.com/search?q=%22{d}%22+password&type=code'),
    ("GitLab search URL", 'https://gitlab.com/search?search=%22{d}%22'),
    ("Shodan", 'https://www.shodan.io/search?query=hostname%3A{d}'),
    ("Censys", 'https://search.censys.io/search?resource=hosts&q={d}'),
    ("URLScan", 'https://urlscan.io/search/#domain%3A{d}'),
    ("OTX AlienVault", 'https://otx.alienvault.com/indicator/domain/{d}'),
    ("Telegram", 'https://t.me/s/{t}'),
    ("Paste/cari dokumen", 'site:{t} inurl:backup OR inurl:upload OR inurl:files'),
    ("JS file (endpoint tersembunyi)", 'site:{t} ext:js inurl:wp-content OR inurl:assets'),
    # — tambahan redteam edition (hacktricks external-recon + playbook google-dorks) —
    ("GitHub — token modern", '"{d}" (ghp_ OR github_pat_ OR xoxb- OR AKIA)'),
    ("GitHub — file rahasia", 'site:github.com "{d}" (".env" OR "id_rsa" OR "credentials.json")'),
    ("grep.app (code search)", 'https://grep.app/search?q={d}'),
    ("Sourcegraph (code search)", 'https://sourcegraph.com/search?q=context:global+{d}'),
    ("SearchCode", 'https://searchcode.com/?q={d}'),
    ("Secret cloud", 'site:{t} "AWS_SECRET_ACCESS_KEY" OR "SECRET_KEY" OR "client_secret"'),
    ("AI API key", '"{d}" ("OPENAI_API_KEY" OR "ANTHROPIC_API_KEY")'),
    ("Subdomain listing", 'site:*.{t} -www -mail'),
    ("CCTV/IoT panel", 'site:{t} inurl:view.php.shtml OR inurl:view/index.shtml OR inurl:viewer'),
    ("Breach selector (IntelX)", 'https://intelx.io/?term={d}'),
]

def mod_dork(target: str, args) -> dict:
    dom = host_of(target)
    full = dom                    # {d} = domain penuh (aman untuk search)
    org = dom.split(".")[0]       # {o} = label pertama (org GitHub dsb)
    rows = []
    for name, tpl in DORKS:
        url = tpl.format(t=dom, d=full, o=org)
        rows.append((name, url))
    tbl(["TIPE", "QUERY"], rows, title=f"Dork {dom}")
    CONS.print("  [dim]klik/paste ke mesin cari — ini OSINT pasif, tidak menyentuh target[/dim]")
    data = {"domain": dom, "dorks": [{"name": n, "query": q} for n, q in rows]}
    if args.out: save_json(outdir(dom) / "dork.json", data)
    return data

# ─────────────────────────── EMAIL HARVEST ───────────────────────────
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-z]{2,})", re.I)

def mod_email(target: str, args) -> dict:
    require_scope(target, args.authorized)
    dom = host_of(target)
    base = target if "://" in target else f"https://{dom}"
    pages = [base + "/", base + "/kontak/", base + "/contact/", base + "/tentang/",
             base + "/privacy-policy/", base + "/feed/"]
    found: dict[str, set] = {}
    fetched = 0
    MAX_LINKS = 15   # batas link internal per invokasi (anti-lambat)
    ASSET = re.compile(r"\.(css|js|png|jpe?g|gif|svg|webp|woff2?|ttf|ico|pdf|zip|mp4)(\?|$)", re.I)
    for url in pages:
        r = http_ok(url, timeout=20)
        if r is None or r.status_code != 200:
            time.sleep(CFG["pace"]); continue
        text = re.sub(r"<[^>]+>", " ", r.text[:400000])
        for m in EMAIL_RE.finditer(text):
            mail = m.group(0).lower()
            found.setdefault(mail, set()).add(url)
        # telusuri maks MAX_LINKS link internal (halaman saja, bukan aset)
        for lm in re.finditer(r'href="(https?://' + re.escape(dom) + r'/[^"#]*)"', r.text):
            if len(found) >= 30 or fetched >= MAX_LINKS: break
            link = lm.group(1)
            if ASSET.search(link): continue
            fetched += 1
            r2 = http_ok(link, timeout=15)
            if r2 is None or r2.status_code != 200:
                time.sleep(CFG["pace"]); continue
            t2 = re.sub(r"<[^>]+>", " ", r2.text[:200000])
            for m in EMAIL_RE.finditer(t2):
                found.setdefault(m.group(0).lower(), set()).add(link)
            time.sleep(CFG["pace"])
        time.sleep(CFG["pace"])
    if not found:
        CONS.print("[yellow]• tidak ada email terlihat di halaman publik[/yellow]")
    own = sorted(m for m in found if m.endswith(dom))
    other = sorted(m for m in found if not m.endswith(dom))
    tbl(["EMAIL @TARGET", "SUMBER"], [(m, ", ".join(sorted(found[m]))[:80]) for m in own], title="Email terkumpul")
    if other:
        CONS.print(f"  [yellow]email pihak-ketiga (masking utk laporan): {len(other)} — "
                   f"{', '.join(o.split('@')[0][:3]+'***@…' for o in other[:8])}[/yellow]")
    data = {"domain": dom, "own": own, "third_party_count": len(other),
            "third_party": other,
            "third_party_masked": [m.split("@")[0][:3] + "***@" + m.split("@")[1] for m in other]}
    if args.out:
        d = outdir(dom)
        save_json(d / "email.json", data)
        (d / "emails.txt").write_text("\n".join(own + other) + "\n")
    return data

# ─────────────────────────── PEOPLE / EMAIL PATTERN ───────────────────────────
ENGINES = [
    ("Google", 'https://www.google.com/search?q=%22{q}%22'),
    ("Google (site)", 'https://www.google.com/search?q=site%3A{t}+%22{q}%22'),
    ("Bing", 'https://www.bing.com/search?q=%22{q}%22'),
    ("DuckDuckGo", 'https://duckduckgo.com/?q=%22{q}%22'),
    ("LinkedIn", 'https://www.linkedin.com/search/results/all/?keywords=%22{q}%22'),
    ("GitHub", 'https://github.com/search?q=%22{q}%22&type=users'),
    ("X/Twitter", 'https://x.com/search?q=%22{q}%22'),
    ("Facebook", 'https://www.facebook.com/search/top?q=%22{q}%22'),
    ("Instagram", 'https://www.instagram.com/explore/tags/{q}/'),
    ("Telegram", 'https://t.me/s/{q}'),
]
PATTERNS = ["{f}.{l}", "{f}{l}", "{f}_{l}", "{i}.{l}", "{i}{l}", "{l}.{f}"]

def mod_people(target: str, args) -> dict:
    q = args.query or target
    dom = host_of(target) if "." in target else ""
    rows = []
    for name, tpl in ENGINES:
        rows.append((name, tpl.format(q=urllib.parse.quote(q), t=dom or q)))
    tbl(["MESIN", "URL"], rows, title=f"People search: {q}")
    data = {"query": q, "links": [{"engine": n, "url": u} for n, u in rows]}
    if dom and getattr(args, "name", None):
        parts = [p for p in re.split(r"\s+", args.name.strip().lower()) if p]
        if len(parts) >= 2:
            f, l = parts[0], parts[-1]
            i = f[0]
            fmts = [p.format(f=f, l=l, i=i) for p in PATTERNS]
            tbl(["POLA EMAIL @target"], [(f"{x}@{dom}",) for x in fmts])
            data["email_patterns"] = [f"{x}@{dom}" for x in fmts]
    if args.out: save_json(outdir(dom or "people") / "people.json", data)
    return data

# ─────────────────────────── LEAK (HIBP) ───────────────────────────
def mod_leak(target: str, args) -> dict:
    email = args.query or target
    dom = host_of(email.split("@")[-1]) if "@" in email else ""
    data: dict = {"email": email}  # email_masked DINONAKTIFKAN 2026-10-05
    key = CFG.get("hibp_api_key", "")
    if not key:
        CONS.print("[yellow]• HIBP API key belum diisi (config.json → hibp_api_key).[/yellow]")
        CONS.print("  Ambil dari situs HIBP lalu isi. Tanpa key = tidak ada request keluar.")
        return data
    r = http_ok(f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false",
                timeout=30, headers={"hibp-api-key": key})
    if r is None:
        data["error"] = "request gagal"
    elif r.status_code == 200:
        try:
            rows = r.json()
            data["breaches"] = [{"name": b.get("Name"), "date": b.get("BreachDate"),
                                 "data_classes": b.get("DataClasses")} for b in rows]
            tbl(["BREACH", "TANGGAL", "JENIS DATA"],
                [(b["name"], b["date"], ", ".join(b["data_classes"] or [])[:60]) for b in data["breaches"]],
                title="Hasil HIBP")
        except Exception:
            data["raw"] = r.text[:300]
    elif r.status_code == 404:
        CONS.print("[green]• Tidak ditemukan di breach yang diketahui HIBP[/green]")
        data["breaches"] = []
    else:
        data["status"] = r.status_code
    if args.out: save_json(outdir(dom or "leak") / "leak.json", data)
    return data

# ─────────────────────────── SUBDOMAIN LIVE (probe HTTP) ───────────────────────────
def mod_sublive(target: str, args) -> dict:
    require_scope(target, args.authorized)
    dom = host_of(target)
    d = outdir(dom)
    subs: list[str] = []
    if (d / "subs.txt").exists():
        subs = [l.strip() for l in (d / "subs.txt").read_text().splitlines() if l.strip()]
    else:
        cand = sorted(Path(CFG["output_dir"]).glob(f"{dom}_*/subs.txt"))
        if cand:
            subs = [l.strip() for l in cand[-1].read_text().splitlines() if l.strip()]
    if not subs:
        CONS.print("[yellow]  belum ada daftar subs → jalankan modul 'subs' dulu[/yellow]")
        return {}
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def probe(h: str) -> dict:
        for scheme in ("https", "http"):
            r = http_ok(f"{scheme}://{h}", timeout=15, verify=False)
            if r is not None:
                title = ""
                m = re.search(r"<title>(.*?)</title>", (r.text or "")[:60000], re.I | re.S)
                if m: title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
                return {"host": h, "scheme": scheme, "status": r.status_code,
                        "server": r.headers.get("Server", ""), "title": title,
                        "len": len(r.content), "final": str(r.url)}
        return {"host": h, "status": 0}

    rows = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(probe, h) for h in subs]
        for f in as_completed(futs):
            rows.append(f.result())
    rows.sort(key=lambda x: x["host"])
    live = [r for r in rows if r.get("status")]
    dead = len(subs) - len(live)
    tbl(["HOST", "STS", "SERVER", "TITLE"],
        [(r["host"], r["status"], str(r.get("server", ""))[:24], r.get("title", "")) for r in live],
        title=f"Live {len(live)}/{len(subs)} (mati: {dead})")
    dets = []
    for r in live:
        srv = str(r.get("server", "")).lower()
        ttl = str(r.get("title", "")).lower()
        if srv: dets.append(f"server {srv}")
        if any(k in ttl for k in ("login", "admin", "mail", "cpanel", "webmail",
                                  "dashboard", "masuk", "phpmyadmin")):
            dets.append(f"login page {ttl[:40]}")
        if r.get("status") in (401, 403): dets.append(f"{r['status']} proteksi")
    intel_panel(target, dets, "sublive")
    data = {"total": len(subs), "live": len(live), "hosts": rows}
    save_json(d / "sublive.json", data)
    (d / "sublive.txt").write_text("\n".join(
        f"{r['scheme']}://{r['host']}" for r in live if r.get("status")) + "\n")
    CONS.print(f"  [green]tersimpan:[/green] {d}/sublive.txt")
    return data

# ─────────────────────────── TECHSTACK ───────────────────────────
TECH_SIGS = [
    ("WordPress", "cms", r"/wp-content/|/wp-includes/|wp-json"),
    ("WooCommerce", "plugin", r"woocommerce"),
    ("Elementor", "plugin", r"elementor"),
    ("Joomla", "cms", r"/media/jui/|joomla!"),
    ("Drupal", "cms", r"drupal\.settings|/sites/default/"),
    ("Laravel", "framework", r"laravel|xsrf-token"),
    ("CodeIgniter", "framework", r"ci_session"),
    ("Django", "framework", r"csrfmiddlewaretoken"),
    ("ASP.NET", "framework", r"asp\.net|__viewstate|x-aspnet-version"),
    ("React/Next", "js", r"__next_data__|react-dom"),
    ("Vue/Nuxt", "js", r"__nuxt__|vue\."),
    ("Angular", "js", r"ng-version|angular[.-]"),
    ("Bootstrap", "css", r"bootstrap(\.min)?\.(css|js)"),
    ("jQuery", "js", r"jquery[.-]"),
    ("Cloudflare", "waf", r"cf-ray|cloudflare"),
    ("OpenResty", "server", r"openresty"),
    ("LiteSpeed", "server", r"litespeed"),
    ("Varnish", "server", r"x-varnish"),
    ("cPanel/WHM", "panel", r"cpanel|whm|webmail"),
    ("Plesk", "panel", r"plesk"),
    ("GTM", "analytics", r"googletagmanager|gtm\.js"),
    ("Google Analytics", "analytics", r"google-analytics|gtag\("),
    ("Meta Pixel", "analytics", r"fbevents|connect\.facebook"),
    ("Bootstrap Colorbox", "plugin", r"colorbox"),
]
COOKIE_SIG = {
    "PHPSESSID": "PHP", "laravel_session": "Laravel", "ci_session": "CodeIgniter",
    "ASP.NET_SessionId": "ASP.NET", "JSESSIONID": "Java", "wordpress_logged_in": "WordPress",
    "XSRF-TOKEN": "Laravel/Angular", "__Host-": "modern-hardened",
}

def mod_techstack(target: str, args) -> dict:
    require_scope(target, args.authorized)
    dom = host_of(target)
    base = target if "://" in target else f"https://{dom}"
    data: dict = {"url": base, "tech": {}, "headers": {}, "cookies": [], "version": ""}
    r = http_ok(base + "/", timeout=CFG["timeout"], verify=False)
    if r is None:
        print("[!] homepage tak terjangkau"); return {"error": "unreachable"}
    body = (r.text or "")[:600000]
    hdr_blob = " ".join(f"{k}:{v}" for k, v in r.headers.items())
    blob = body + " " + hdr_blob
    for name, kind, pat in TECH_SIGS:
        if re.search(pat, blob, re.I):
            data["tech"][name] = kind
    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "X-Drupal-Cache",
              "CF-RAY", "Via", "X-LiteSpeed-Cache", "X-Shopify-Stage"):
        if h in r.headers: data["headers"][h] = str(r.headers[h])[:160]
    sc = r.headers.get("Set-Cookie", "")
    for cname, fw in COOKIE_SIG.items():
        if cname.lower() in sc.lower():
            data["cookies"].append(f"{fw}({cname})")
            data["tech"].setdefault(fw, "cookie")
    gen = re.search(r'<meta name="generator" content="([^"]+)"', body, re.I)
    if gen:
        data["generator"] = gen.group(1)
        m = re.search(r"(\d+[\d.]*)", gen.group(1))
        if m: data["version"] = m.group(1)
    m = re.search(r"wp-includes/js/[^\"']+\?ver=([\d.]+)", body)
    if m and "WordPress" in data["tech"]:
        data["version"] = m.group(1)
    # deteksi CMS via header Link / emoji path
    if "wp-json" in hdr_blob or "rel=\"https://api.w.org/\"" in body:
        data["tech"].setdefault("WordPress", "header")
    # ringkas utk tabel
    rows = [(k, v) for k, v in sorted(data["tech"].items())]
    for k, v in data["headers"].items(): rows.append((f"hdr:{k}", v))
    for c in data["cookies"]: rows.append(("cookie", c))
    tbl(["TECH/BUKTI", "NILAI"], rows, title=f"TechStack {base}")
    if data["version"]: CONS.print(f"  [cyan]versi terdeteksi:[/cyan] {data['version']}")
    # enrich opsional: whatweb (langsung/non-Tor — proxy whatweb hanya HTTP, Tor socks tak dukung)
    if getattr(args, "whatweb", False):
        CONS.print("  [yellow]whatweb jalan LANGSUNG (non-Tor)[/yellow]")
        rc, out = sh(["whatweb", "--color=never", "-t", "3", base], timeout=180)
        data["whatweb"] = out[:4000]
        print(out[:3000])
    # ── INTEL: tiap deteksi → ⚠ kerentanan + 🔧 teknik ──
    dets = list(data["tech"]) + [f"header {k}: {v}" for k, v in data["headers"].items()]
    dets += [f"cookie {c}" for c in data["cookies"]]
    if data.get("generator"): dets.append(f"generator {data['generator']}")
    if data.get("version"): dets.append(f"versi {data['version']}")
    for h in ("Strict-Transport-Security", "Content-Security-Policy",
              "X-Frame-Options", "X-Content-Type-Options"):
        if h not in r.headers: dets.append(f"missing {h}")
    intel_panel(target, dets, "techstack")
    save_json(outdir(dom) / "techstack.json", data)
    return data

# ─────────────────────────── KERENTANAN (nuclei) ───────────────────────────
def mod_vuln(target: str, args) -> dict:
    require_scope(target, args.authorized)
    dom = host_of(target)
    if not have("nuclei"):
        print("[!] nuclei tidak ada"); return {}
    d = outdir(dom)
    base = target if "://" in target else f"https://{dom}"
    sev = getattr(args, "severity", None) or "critical,high"
    tags = getattr(args, "tags", None)
    if getattr(args, "mode", None) == "quick":
        sev, tags = "critical", "exposure,config,cve,misconfig"
    # R219 RCA: latensi via Tor 6–14 dtk → timeout 10 + mhe default 30 = SEMUA host
    # "unresponsive 30x" & diskip diam-diam (exit=0, temuan 0 = false-success).
    cmd = ["nuclei", "-severity", sev,
           "-rate-limit", "3",
           "-retries", str(CFG.get("nuclei_retries", 2)),
           "-timeout", str(CFG.get("nuclei_timeout", 30)),
           "-mhe", str(CFG.get("nuclei_mhe", 9999)),
           "-duc", "-nc",
           "-o", str(d / "nuclei.txt")]
    # target: daftar file (sublive) ATAU satu URL — semua divalidasi scope dulu
    lst = getattr(args, "list_file", None)
    if lst == "auto":
        cand = sorted(Path(CFG["output_dir"]).glob(f"{dom}_*/sublive.txt"))
        lst = str(cand[-1]) if cand else None
        if not lst:
            CONS.print("[yellow]  sublive.txt tidak ada → jalankan 'sublive' dulu; fallback ke apex[/yellow]")
    n_targets = 1
    if lst and Path(lst).exists():
        ok, allow, block = _load_scope()
        raw = [l.strip() for l in Path(lst).read_text().splitlines() if l.strip()]
        clean, skipped = [], []
        for h in raw:
            hh = host_of(h)
            in_s = ok and any(_match(hh, p) for p in allow) and not any(_match(hh, p) for p in block)
            (clean if in_s else skipped).append(h)
        if skipped:
            CONS.print(f"  [yellow]{len(skipped)} host di luar scope dibuang dari daftar scan[/yellow]")
        if clean:
            tf = d / "vuln_targets.txt"
            tf.write_text("\n".join(clean) + "\n")
            cmd += ["-l", str(tf)]
            n_targets = len(clean)
        else:
            cmd += ["-u", base]
    else:
        cmd += ["-u", base]
    if tags: cmd += ["-tags", tags]
    if CFG["use_tor"] and CFG.get("nuclei_proxy"):
        cmd += ["-p", CFG["nuclei_proxy"]]
    CONS.print(f"  [dim]{' '.join(cmd)}[/dim]")
    CONS.print(f"  [yellow]nuclei jalan — {n_targets} target, rate 3/dtk (bisa berjam-jam)[/yellow]")
    rc, out = sh(cmd, timeout=getattr(args, "timeout", 1800))
    findings = []
    f = d / "nuclei.txt"
    if f.exists():
        findings = [l for l in f.read_text().splitlines() if l.strip()]
    print(out[-2500:])
    if findings:
        tbl(["TEMUAN nuclei"], [(x[:150],) for x in findings[:40]], title=f"{len(findings)} temuan")
        sevs = sorted({m.group(1) for x in findings
                       if (m := re.match(r"\[([a-z]+)\]", x.strip()))})
        intel_panel(target, [f"nuclei temuan {len(findings)} {','.join(sevs)}"], "vuln")
    else:
        CONS.print("[green]  ✓ tidak ada temuan severity ini (bukan berarti aman)[/green]")
    data = {"url": base, "severity": sev, "tags": tags, "rc": rc, "count": len(findings),
            "findings": findings}
    save_json(d / "nuclei_meta.json", data)
    return data

# ─────────────────────────── CELAH / EXPOSURE (path sensitif) ───────────────────────────
CELAK_PATHS = [
    "/.git/config", "/.git/HEAD", "/.env", "/.env.backup", "/.env.local", "/.env.production",
    "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.save", "/wp-config.php.old",
    "/config.php.bak", "/config.php~", "/configuration.php.bak",
    "/backup.sql", "/dump.sql", "/db.sql", "/database.sql", "/site.sql",
    "/phpmyadmin/", "/pma/", "/adminer.php", "/adminer/",
    "/.svn/entries", "/.hg/hgrc", "/.DS_Store", "/.idea/workspace.xml",
    "/server-status", "/server-info", "/phpinfo.php", "/info.php",
    "/wp-content/debug.log", "/wp-content/backup/", "/storage/logs/laravel.log",
    "/backup.zip", "/site.zip", "/www.zip", "/html.zip",
    "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/swagger-ui.html", "/api/docs", "/graphql", "/graphiql",
    "/console", "/debugger/", "/_profiler", "/elmah.axd", "/trace.axd",
    "/readme.html", "/README.md", "/LICENSE.txt", "/.well-known/assetlinks.json",
]

def mod_celah(target: str, args) -> dict:
    require_scope(target, args.authorized)
    dom = host_of(target)
    base = target if "://" in target else f"https://{dom}"
    # baseline soft-404
    bl = http_ok(base + "/halaman-tidak-ada-r213", timeout=15, verify=False)
    bst = bl.status_code if bl else 404
    blen = len(bl.content) if bl else 0
    CONS.print(f"  [dim]baseline soft-404: {bst} / {blen}B[/dim]")
    rows, menarik, proteksi = [], [], 0
    for p in CELAK_PATHS:
        r = http_ok(base + p, timeout=15, verify=False)
        if r is None:
            rows.append((p, 0, 0, "err")); time.sleep(CFG["pace"]); continue
        st, ln = r.status_code, len(r.content)
        if st in (401, 403):
            v = "TERPROTEKSI"; proteksi += 1
        elif st in (404, 410):
            v = "absen"
        elif st == 200 and (bst != 200 and ln > 0 or abs(ln - blen) > 400):
            v = "MENARIK"; menarik.append((p, st, ln))
        elif st in (500, 503):
            v = "ERROR?"; menarik.append((p, st, ln))
        elif st == 200:
            v = "MENARIK"; menarik.append((p, st, ln))
        else:
            v = "cek"
        rows.append((p, st, ln, v))
        time.sleep(CFG["pace"])
    tbl(["PATH", "STS", "LEN", "VERDICT"],
        [r for r in rows if r[3] != "absen"],
        title=f"Celah {base} — menarik: {len(menarik)}, terproteksi: {proteksi}")
    if not menarik:
        CONS.print("[green]  ✓ tidak ada path sensitif terbuka pada sapuan ini[/green]")
    # ── INTEL ──
    dets = [f"path {p} {s}" for p, s, l in menarik]
    if proteksi: dets.append(f"{proteksi} path 403 terproteksi")
    intel_panel(target, dets, "celah")
    data = {"url": base, "baseline": {"status": bst, "len": blen},
            "interesting": [{"path": p, "status": s, "len": l} for p, s, l in menarik],
            "protected_count": proteksi,
            "scan": [{"path": p, "status": s, "len": l, "v": v} for p, s, l, v in rows]}
    save_json(outdir(dom) / "celah.json", data)
    return data

# ─────────────────────────── JS ENDPOINT EXTRACTOR ───────────────────────────
JS_SECRETS = [
    ("AWS AccessKey", r"AKIA[0-9A-Z]{16}"),
    ("Google API key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("JWT", r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{5,}"),
    ("PRIVATE KEY", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("hardcoded cred", r"(?i)(api[_-]?key|apikey|client[_-]?secret|secret|password|passwd|token)\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']"),
    ("basic auth url", r"https?://[a-z0-9._%-]+:[^@/\s]+@[a-z0-9._-]+"),
    ("s3 bucket", r"[a-z0-9._-]+\.s3[.-][a-z0-9.-]*amazonaws\.com"),
]

def mod_jsfind(target: str, args) -> dict:
    require_scope(target, args.authorized)
    dom = host_of(target)
    base = target if "://" in target else f"https://{dom}"
    r = http_ok(base + "/", timeout=CFG["timeout"], verify=False)
    if r is None:
        print("[!] homepage tak terjangkau"); return {"error": "unreachable"}
    body = (r.text or "")
    # kumpulkan URL .js same-origin (maks 12) + inline script
    cand = set()
    for m in re.finditer(r"""(?:src|href)\s*=\s*["']([^"']+\.js[^"']*)["']""", body, re.I):
        cand.add(urllib.parse.urljoin(base + "/", m.group(1)))
    inline = re.findall(r"<script[^>]*>(.*?)</script>", body, re.I | re.S)
    js_texts: list[tuple[str, str]] = [("<inline>", "\n".join(inline)[:400000])]
    same = [u for u in sorted(cand) if host_of(u) == dom][:12]
    ext = [u for u in sorted(cand) if host_of(u) != dom][:5]
    for u in same + ext:
        rr = http_ok(u, timeout=15, verify=False)
        if rr is not None and rr.status_code == 200:
            js_texts.append((u, (rr.text or "")[:400000]))
        time.sleep(CFG["pace"])
    blob = "\n".join(t for _, t in js_texts)
    # ekstrak endpoint
    eps: set[str] = set()
    for m in re.finditer(r"""https?://[^\s"'`\\)]{4,120}""", blob):
        eps.add(m.group(0))
    for m in re.finditer(r"""["'`](/[a-zA-Z0-9_][a-zA-Z0-9_\-./]{2,80})["'`]""", blob):
        eps.add(m.group(1))
    eps = {e for e in eps if not re.search(r"\.(png|jpe?g|gif|svg|woff2?|ttf|css|map)(\?|$)", e, re.I)}
    own = sorted(e for e in eps if e.startswith("/") or dom in e)
    other = sorted(e for e in eps if e not in own)
    # rahasia
    hits = []
    for name, pat in JS_SECRETS:
        for m in re.finditer(pat, blob):
            s = m.group(0)
            masked = s[:10] + "…" + s[-4:] if len(s) > 18 else s[:6] + "…"
            hits.append((name, masked))
    tbl([f"ENDPOINT @{dom}"], [(e,) for e in own[:60]],
        title=f"{len(own)} endpoint internal (dari {len(js_texts)} file JS)")
    if other:
        CONS.print(f"  [dim]+ {len(other)} endpoint eksternal (CDN/api pihak-ketiga) — lihat js_endpoints.txt[/dim]")
    if hits:
        tbl(["RAHASIA TERDETEKSI", "CUPLIKAN"], sorted(set(hits)), title="⚠ cek manual!")
    else:
        CONS.print("  [green]  ✓ tidak ada rahasia hardcoded terdeteksi di JS[/green]")
    d = outdir(dom)
    # ── INTEL ──
    intel_panel(target, [f"secret {n}" for n, _ in sorted(set(hits))] +
                [f"endpoint {e}" for e in own[:20]], "jsfind")
    save_json(d / "jsfind.json", {"endpoint_internal": own, "endpoint_external": other,
                                  "secrets": [{"type": n, "sample": s} for n, s in sorted(set(hits))],
                                  "files": [u for u, _ in js_texts]})
    (d / "js_endpoints.txt").write_text("\n".join(own + other) + "\n")
    return {"internal": len(own), "external": len(other), "secrets": len(hits)}

# ─────────────────────────── SCREENSHOT (playwright) ───────────────────────────
def mod_shot(target: str, args) -> dict:
    require_scope(target, args.authorized)
    dom = host_of(target)
    base = target if "://" in target else f"https://{dom}"
    urls = [base + "/"]
    lst = getattr(args, "list_file", None)
    if lst == "auto":
        cand = sorted(Path(CFG["output_dir"]).glob(f"{dom}_*/sublive.txt"))
        if cand:
            urls += [l.strip() for l in cand[-1].read_text().splitlines()
                     if l.strip() and host_of(l) == dom][:15]
    urls = list(dict.fromkeys(urls))[:16]
    d = outdir(dom) / "screenshots"
    d.mkdir(parents=True, exist_ok=True)
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        print(f"[!] playwright tidak tersedia: {e}"); return {}
    shots = []
    try:
        with sync_playwright() as pw:
            launch_kw = {"executable_path": "/sbin/chromium",
                         "args": ["--no-sandbox", "--disable-gpu"]}
            b = pw.chromium.launch(**launch_kw)
            ctx_kw = {"ignore_https_errors": True,
                      "user_agent": CFG["user_agent"]}
            if CFG["use_tor"]:
                ctx_kw["proxy"] = {"server": CFG["tor_proxy"].replace("socks5h", "socks5")}
            ctx = b.new_context(**ctx_kw)
            pg = ctx.new_page()
            for i, u in enumerate(urls):
                rec = {"url": u, "status": 0, "title": "", "file": ""}
                try:
                    resp = pg.goto(u, timeout=30000, wait_until="domcontentloaded")
                    rec["status"] = resp.status if resp else 0
                    rec["title"] = pg.title()[:120]
                    fname = f"{i:02d}-" + re.sub(r"[^A-Za-z0-9._-]", "_", host_of(u) + urllib.parse.urlparse(u).path)[:80] + ".png"
                    pg.screenshot(path=str(d / fname))
                    rec["file"] = fname
                    CONS.print(f"  [green]✓[/green] {rec['status']} {u} → {fname}")
                except Exception as e:
                    rec["error"] = str(e)[:120]
                    CONS.print(f"  [red]✗[/red] {u} — {rec['error']}")
                shots.append(rec)
            b.close()
    except Exception as e:
        print(f"[!] playwright gagal: {e}"); return {"error": str(e)}
    save_json(outdir(dom) / "shot.json", {"shots": shots})
    return {"count": len([s for s in shots if s.get("file")]), "dir": str(d)}

# ─────────────────────────── TOOLS INTERAKTIF (hydra/msf/sqlmap/whatweb) ───────────────────────────
def _pfx() -> str:
    return "\033[36m❯ \033[0m" if anim_on() else ""

def _ask(prompt: str, default: str = "") -> str:
    try:
        v = input(f"{_pfx()}{prompt}" + (f" [{default}]" if default else "") + ": ").strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return v or default

def _confirm(word: str = "YA") -> bool:
    try:
        ans = input(f"{_pfx()}  ketik {word} untuk eksekusi (lain = batal): ").strip()
    except (EOFError, KeyboardInterrupt):
        return False
    return ans == word

def tool_hydra(target: str, args) -> dict:
    """Brute kredensial aman-anti-lockout (sesuai skill brute-aman-antilockout)."""
    require_scope(target, args.authorized)
    host = host_of(target)
    svc = _ask("layanan (ssh/ftp/smb/rdp/mysql/pop3/imap/http-post-form)", "ssh")
    user = _ask("username (awali @ utk file userlist)", "admin")
    pfl = _ask("password list", "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017-top1000.txt")
    form = ""
    if svc == "http-post-form":
        form = _ask("path form  mis. /login:user=^USER^&pass=^PASS^:F=Salah")
        if not form:
            print("[!] path form wajib — batal"); return {}
    cmd = ["hydra", "-t", "3", "-W", "3"]
    cmd += ["-L", user[1:]] if user.startswith("@") else ["-l", user]
    cmd += ["-P", pfl, host]
    cmd += ["http-post-form", form] if svc == "http-post-form" else [svc]
    print("\n  PERINGATAN (skill brute-aman-antilockout):")
    print("  • risiko ACCOUNT LOCKOUT target & IP ban bila kebijakan akun tak diketahui")
    print("  • -t 3 -W 3 sudah dipasang (jangan naikkan >4)")
    print("  • stop-condition: 429 / 403 mendadak / gejala lockout → BERHENTI")
    print(f"  CMD: {' '.join(cmd)}")
    if not _confirm("YA"):
        print("  dibatalkan."); return {}
    via_tor = _ask("lewat Tor (rotasi IP, port non-HTTP sering ditolak)? y/n", "n") == "y"
    if via_tor:
        cmd = ["proxychains4", "-f", os.path.expanduser("~/.proxychains4.conf"), "-q"] + cmd
    CONS.print("  [yellow]hydra jalan…[/yellow]")
    rc, out = sh(cmd, timeout=3600)
    print(out[-3000:])
    d = outdir(host)
    (d / "hydra.log").write_text(out)
    return {"rc": rc, "cmd": " ".join(cmd), "log": str(d / "hydra.log")}

def tool_msf(target: str, args) -> dict:
    require_scope(target, args.authorized)
    host = host_of(target)
    mods = [("1", "auxiliary/scanner/portscan/tcp", "portscan TCP"),
            ("2", "auxiliary/scanner/http/http_options", "HTTP OPTIONS"),
            ("3", "auxiliary/scanner/ssh/ssh_version", "SSH version"),
            ("4", "auxiliary/scanner/ftp/ftp_version", "FTP version"),
            ("5", "auxiliary/scanner/smtp/smtp_enum", "SMTP enum"),
            ("6", "auxiliary/scanner/smb/smb_version", "SMB version")]
    for n, m, lab in mods: print(f"   {n}) {lab:<16} {m}")
    ch = _ask("pilih modul", "1")
    mod = next((m for n, m, _ in mods if n == ch), None)
    if not mod: print("[!] pilihan tak dikenal"); return {}
    print("\n  ⚠ Metasploit TIDAK bisa lewat Tor (msfconsole tanpa socks) → IP asli terlihat.")
    print(f"  CMD: msfconsole -q -x 'use {mod}; set RHOSTS {host}; set THREADS 2; run; exit'")
    if not _confirm("TANPA TOR"):
        print("  dibatalkan."); return {}
    cmd = ["msfconsole", "-q", "-x", f"use {mod}; set RHOSTS {host}; set THREADS 2; run; exit"]
    CONS.print("  [yellow]msfconsole jalan (bisa ~1–2 menit untuk load)…[/yellow]")
    rc, out = sh(cmd, timeout=900)
    print(out[-3000:])
    d = outdir(host)
    (d / "msf.log").write_text(out)
    return {"rc": rc, "module": mod, "log": str(d / "msf.log")}

def tool_sqlmap(target: str, args) -> dict:
    require_scope(target, args.authorized)
    url = _ask("URL target dgn parameter  (mis. https://host/page?id=1)")
    if not url.startswith("http"):
        print("[!] URL harus http(s) — batal"); return {}
    require_scope(url, args.authorized)   # host dalam URL wajib in-scope
    cmd = ["sqlmap", "-u", url, "--batch", "--level", "1", "--risk", "1",
           "--delay", "2",
           "--tor", "--tor-type=socks5", "--tor-port", "9050"]
    print("\n  CMD:", " ".join(cmd))
    print("  (level1/risk1 = ringan; stop bila 403/429/508)")
    if not _confirm("YA"):
        print("  dibatalkan."); return {}
    CONS.print("  [yellow]sqlmap jalan…[/yellow]")
    rc, out = sh(cmd, timeout=3600)
    print(out[-3000:])
    d = outdir(host_of(url))
    (d / "sqlmap.log").write_text(out)
    return {"rc": rc, "log": str(d / "sqlmap.log")}

def tool_whatweb(target: str, args) -> dict:
    require_scope(target, args.authorized)
    base = target if "://" in target else f"https://{host_of(target)}"
    CONS.print("  [yellow]whatweb jalan LANGSUNG (proxy-nya hanya HTTP, Tor socks tak didukung)[/yellow]")
    rc, out = sh(["whatweb", "--color=never", "-t", "3", base], timeout=180)
    print(out[:4000])
    d = outdir(host_of(target))
    (d / "whatweb.log").write_text(out)
    return {"rc": rc, "output": out[:4000]}

def cmd_tools(target: str, args) -> None:
    items = [("1", "nmap port scan (via Tor)", lambda: mod_ports(target, args)),
             ("2", "hydra brute kredensial (anti-lockout)", lambda: tool_hydra(target, args)),
             ("3", "metasploit auxiliary scanner", lambda: tool_msf(target, args)),
             ("4", "sqlmap SQLi (via Tor, ringan)", lambda: tool_sqlmap(target, args)),
             ("5", "whatweb fingerprint", lambda: tool_whatweb(target, args)),
             ("6", "nuclei kerentanan", lambda: mod_vuln_menu(target, args)),
             ("0", "kembali", None)]
    while True:
        CONS.print("\n[bold cyan]══ TOOLS ══[/bold cyan]")
        for n, lab, _ in items: print(f"   {n}) {lab}")
        ch = _ask("pilih tools", "0")
        if ch == "0": return
        act = next((f for n, _, f in items if n == ch and f), None)
        if not act: print("  pilihan tak dikenal"); continue
        try:
            act()
        except SystemExit:
            raise
        except Exception as e:
            CONS.print(f"[red]  gagal: {e}[/red]")

def mod_vuln_menu(target: str, args) -> dict:
    """Wrapper interaktif utk mod_vuln: pilih mode + sumber target."""
    mode = _ask("mode (1=cepat: critical+exposure · 2=PENUH: critical,high)", "1")
    src = _ask("target (1=apex · 2=sublive.txt semua host live · 3=path file)", "1")
    lf = None
    if src == "2": lf = "auto"
    elif src == "3": lf = _ask("path file daftar target")
    ns = argparse.Namespace(**{**vars(args), "mode": "quick" if mode == "1" else "full",
                              "severity": None, "tags": None, "list_file": lf})
    return mod_vuln(target, ns)

# ─────────────────────────── MENU INTERAKTIF ───────────────────────────
def _dns_mail(t, a):
    mod_dns(t, a); mod_mail(t, a)

# ─────────────────────────── UI: animasi, panel, box ───────────────────────────
PALETTE = ["#00e5ff", "#4d9dff", "#8f5bff", "#ff4dd2", "#ffb84d"]
_LETTERS = {
    "O": [r"  ___  ", r" / _ \ ", "| | | |", "| |_| |", r" \___/ "],
    "S": [" _____ ", "| ____|", "|  _|  ", "| |___ ", "|_____|"],
    "I": [" ___ ", "|_ _|", " | | ", " | | ", "|_|  "],
    "N": [r" _   _ ", r"| \ | |", r"|  \| |", r"| |\  |", r"|_| \_|"],
    "T": [" _____ ", "|_   _|", "  | |  ", "  | |  ", "  |_|  "],
}
LOGO = ["".join(_LETTERS[c][i] for c in "OSINT") for i in range(5)]
ANIM: bool = sys.stdout.isatty()
_SPD: float = float(CFG.get("anim_speed") or 1.0)      # animasi: CLI --speed > config

def anim_on() -> bool:
    return bool(ANIM and RICH and getattr(sys.stdout, "isatty", lambda: True)())

def _grad_style(i: int, n: int) -> str:
    return f"bold {PALETTE[min(len(PALETTE) - 1, int(i / max(1, n) * len(PALETTE)))]}"

def typewrite(s: str, delay: float = 0.01, style: str | None = None, grad: bool = False):
    """Tulis karakter demi karakter (efek mesin ketik) — hanya di terminal."""
    if not RICH:
        print(s); return
    if not anim_on():
        CONS.print(f"[{style}]{s}[/]" if style else s)
        return
    for i, ch in enumerate(s):
        CONS.print(Text(ch, style=(_grad_style(i, len(s)) if grad else style)), end="")
        time.sleep(delay / _SPD)
    CONS.print()
    if anim_on() and RICH:    # kursor block berkedip 3x (efek terminal aktif)
        for _ in range(3):
            CONS.print(" ▌", end="\r", crop=False)
            time.sleep(0.20 / _SPD)
            CONS.print("   ", end="\r", crop=False)
            time.sleep(0.20 / _SPD)
        CONS.print()

def sweep(label: str, steps: int = 16, delay: float = 0.03):
    """Bar progress bergerak ▰▱ sebelum eksekusi modul."""
    if not anim_on(): return
    w = 22
    for i in range(steps + 1):
        f = int(i / steps * w)
        bar = "▰" * f + "▱" * (w - f)
        CONS.print(f"   {label:<32} [cyan]{bar}[/cyan] [dim]{int(i / steps * 100):>3}%[/dim]",
                   end="\r", overflow="ignore", crop=False)
        time.sleep(delay / _SPD)
    CONS.print(" " * 74, end="\r", crop=False)

def _port_open(port: int, host: str = "127.0.0.1", t: float = 0.6) -> bool:
    try:
        s = socket.create_connection((host, port), t); s.close(); return True
    except Exception:
        return False

def ui_banner():
    """Banner ASCII 'OSINT' gradient warna + efek mesin ketik + cek boot."""
    if not anim_on():
        CONS.print("[bold blue]OSINT by kzldx[/bold blue] v2.2 — MENU INTERAKTIF")
        ui_boot()          # checklist tetap tampil di mode plain (deteksi PySocks/Tor mati)
        return
    CONS.print()
    n = max(len(r) for r in LOGO) or 1

    def _logo_lines(shift: int = 0):
        for row in LOGO:
            t = Text()
            for i, ch in enumerate(row.ljust(n)):
                if ch == " ":
                    t.append(" ")
                else:
                    t.append(ch, style=_grad_style((i + shift) % n, n))
            yield t

    for row in LOGO:                    # reveal awal: karakter demi karakter
        for i, ch in enumerate(row):
            CONS.print(" " if ch == " " else Text(ch, style=_grad_style(i, n)), end="")
            time.sleep(0.007 / _SPD)
        CONS.print()
    for shift in (2, 4, 0):             # wave: gelombang gradien melintas 3x
        os.write(1, f"\033[{len(LOGO)}A".encode())  # naik baris (bypass Rich)
        for t in _logo_lines(shift):
            CONS.print(t)
        time.sleep(0.15 / _SPD)
    typewrite("  O S I N T   b y   k z l d x   ·   v 2 . 2   ·   B l a c k A r c h",
              0.011, style="bold magenta")
    ui_boot()

def _socks_ok() -> bool:
    """PySocks = wajib utk requests lewat socks5h:// (tanpa ini: semua modul Tor gagal senyap)."""
    try:
        import socks  # noqa: F401
        return True
    except Exception:
        return False

def ui_boot():
    """Checklist boot berjalan (OK/FAIL) seperti startup profesional."""
    checks = [
        ("konfigurasi & config.json", True),
        ("tor socks5 :9050", _port_open(9050)),
        ("PySocks (proxy Tor via requests)", _socks_ok() or not CFG["use_tor"]),
        ("scope.txt · fail-closed", _load_scope()[0]),
        ("tool inti (nmap · nuclei · subfinder)",
         all(have(x) for x in ("nmap", "nuclei", "subfinder"))),
    ]
    for name, ok in checks:
        if anim_on():
            for f in ("⠋", "⠙", "⠸", "⠴", "⠦"):   # spinner mini sebelum hasil
                CONS.print(f"   {f}  {name}", end="\r", overflow="ignore", crop=False)
                time.sleep(0.05 / _SPD)
        if RICH:
            mark = Text(" OK ", style="bold black on green") if ok else Text("FAIL", style="bold white on red")
            CONS.print("   ", mark, Text(f"  {name}", style="dim"))
        else:
            print(f"   [{'OK ' if ok else 'FAIL'}] {name}")

def ui_header():
    """Panel info status (Tor / pace / scope / NDA)."""
    tor = CFG["use_tor"]
    tor_ok = _port_open(9050)
    if not anim_on():
        warn = " · TOR MATI/PORT TERTUTUP!" if tor and not tor_ok else ""
        CONS.print(f"[bold blue]OSINT by kzldx v2.2[/bold blue] · Tor: {'ON' if tor else 'OFF'}"
                   f"{warn} · pace {CFG['pace']}s")
        return
    tcol = "green" if (tor and tor_ok) else ("red" if tor else "dim")
    ttxt = "ON" if (tor and tor_ok) else ("MATI!" if tor else "OFF")
    body = Text.assemble((" Tor ", "dim"), (ttxt, f"bold {tcol}"),
                         ("   ·   pace ", "dim"), (f"{CFG['pace']}s", "bold cyan"),
                         ("   ·   scope ", "dim"), ("FAIL-CLOSED", "bold yellow"),
                         ("   ·   NDA ", "dim"), ("AKTIF", "bold magenta"))
    CONS.print(Panel(body, box=box.DOUBLE_EDGE, border_style="blue", padding=(0, 1), expand=False))

def ui_target(target: str, verdict: str):
    """Bar status target berwarna (hijau in-scope / merah luar / abu belum diset)."""
    if not anim_on():
        CONS.print(f"\nTarget: {target or '-'} → {verdict}")
        return
    if not target:
        color, icon = "dim", "○"
        txt = "(belum diset — ketik: t <domain>)"
    elif verdict.startswith("BLOCKLIST") or not verdict.startswith(
            ("IN SCOPE", "MODE BEBAS")):
        color, icon = "red", "✖"
        txt = f"{target}   {verdict}"
    elif verdict.startswith("IN SCOPE"):
        color, icon = "green", "●"
        txt = f"{target}   {verdict}"
    else:  # MODE BEBAS
        color, icon = "cyan", "●"
        txt = f"{target}   {verdict}"
    body = Text.assemble((f" {icon} ", f"bold {color}"), (txt, "bold white"),
                         (f"  ⏱ {time.strftime('%H:%M:%S')}", "dim"))
    CONS.print(Panel(body, title="[bold]TARGET[/bold]", box=box.ROUNDED,
                     border_style=color, padding=(0, 1), expand=False))

def ui_menu():
    """Panel menu mewah (box rounded) — 19 item bernomor kuning."""
    if CFG.get("enforce_scope"):
        legend = ("  ◦ OSINT pasif — boleh target di luar scope (blocklist tetap ditolak) · "
                  "tanpa ◦ = aktif, wajib lolos scope")
    else:
        legend = ("  mode bebas: semua modul target apa pun · ◦ = OSINT pasif (sumber pihak ketiga) · "
                  "blocklist proyek lain tetap ditolak · a = AUTO SWEEP semua · af = +nuclei/nmap")
    if not anim_on():
        for n, lab, _, _ in MENU_ITEMS:
            print(f"  {n.rjust(2)}) {lab}")
        print(legend)
        return
    rows = Text()
    for i, (n, lab, _, _) in enumerate(MENU_ITEMS):
        rows.append(f" {n:>2} ", style="bold yellow")
        rows.append("│", style="cyan")
        rows.append(f" {lab}", style="white")
        if i < len(MENU_ITEMS) - 1:
            rows.append("\n")
    CONS.print(Panel(rows, title="[bold cyan]≡ MENU[/bold cyan]",
                     subtitle="[dim]t <target> · q keluar · a = AUTO SWEEP · af = AUTO+full[/dim]",
                     box=box.ROUNDED, border_style="cyan", padding=(0, 2)))
    CONS.print(f"[dim]{legend}[/dim]")

def ui_run(label: str):
    """Sweep progress + panel berat sebelum modul dijalankan."""
    sweep(f"▸ menjalankan {label}")
    if anim_on():
        CONS.print(Panel(Text(f"▶ {label}", style="bold bright_cyan"),
                         box=box.HEAVY, border_style="bright_cyan", padding=(0, 1)))
    else:
        section(label)

def ui_done(label: str):
    if anim_on():
        CONS.print(f"   [bold green]✔[/bold green] [dim]{label} selesai[/dim]")

def ui_prompt() -> str:
    if anim_on():
        return "\033[1;36m❯ \033[0m\033[1mPilih\033[0m > "
    return "pilih> "

def menu_verdict(target: str) -> str:
    """Teks utk panel TARGET — mode bebas tampil netral, bukan merah."""
    if not target: return "(belum diset)"
    v = scope_verdict(target)
    if CFG.get("enforce_scope"): return v
    if v.startswith("BLOCKLIST"): return v
    return "MODE BEBAS — target apa pun boleh (enforce_scope=false)"

def cmd_scope_info(target: str, args) -> dict:
    """Menu item 1: status mode scope."""
    if not CFG.get("enforce_scope"):
        CONS.print("[cyan]  ◆ MODE BEBAS (enforce_scope=false) — semua modul jalan di target apa pun.[/cyan]")
        if CFG.get("enforce_blocklist", True):
            CONS.print("[dim]    Blocklist proyek lain ('!' di scope.txt) masih aktif; "
                       "matikan via config.json enforce_blocklist.[/dim]")
    else:
        CONS.print("[yellow]  ◆ Mode fail-closed (enforce_scope=true) — aktif = wajib scope.txt / --authorized; "
                   "pasif = bebas.[/yellow]")
    CONS.print(f"  {scope_verdict(target) if target else '(belum diset — ketik: t <domain>)'}")
    return {}

# ─────────── EXPORT intel.json → findings.jsonl (integrasi Dev GreyHat) ───────────
def cmd_export(target: str, args) -> dict:
    """Bridge GreyHat: semua intel.json di output/ → findings.jsonl (PII aman).

    - target kosong  : semua run di output/
    - target diset   : hanya run folder <target>_<ts>
    - args.out (menu): append ke BASE/findings.jsonl bila --append tidak diisi
    """
    sys.path.insert(0, str(BASE))
    import intel_to_findings as itf
    argv = ["--intel-dir", str(BASE / "output")]
    dom = host_of(target) if target else ""
    if dom:
        argv += ["--target", dom]
    append_to = getattr(args, "append", "") or ""
    if not append_to and getattr(args, "out", False):
        append_to = str(BASE / "findings.jsonl")
    if append_to:
        argv += ["--append", append_to, "--dedupe"]
    rc = itf.main(argv)
    if rc == 2:
        CONS.print("[red]  ! export gagal (cek argumen)[/red]")
    elif append_to and rc != 1:
        CONS.print(f"[green]  ✓ findings → {append_to}[/green]")
    return {"rc": rc}

MENU_ITEMS = [
    ("1",  "Cek Scope / status mode",                  False, cmd_scope_info),
    ("2",  "DNS + Mail Security (SPF/DMARC/DKIM) ◦",  True,  _dns_mail),
    ("3",  "Whois ◦",                                  True,  mod_whois),
    ("4",  "Subdomain (enum: subfinder+crt+wayback) ◦", True,  mod_subs),
    ("5",  "Subdomain LIVE (probe HTTP)",             True,  mod_sublive),
    ("6",  "TechStack (fingerprint dalam)",           True,  mod_techstack),
    ("7",  "Web Fingerprint (header/TLS)",            True,  mod_web),
    ("8",  "KERENTANAN (nuclei)",                     True,  mod_vuln_menu),
    ("9",  "CELAH/Exposure (path sensitif)",          True,  mod_celah),
    ("10", "Wayback historis ◦",                       True,  mod_wayback),
    ("11", "Port Scan (nmap via Tor)",                True,  mod_ports),
    ("12", "Email harvest (masking PII)",             True,  mod_email),
    ("13", "Dork siap pakai ◦",                        False, mod_dork),
    ("14", "People / pola email @target ◦",            False, mod_people),
    ("15", "Laporan penuh (run → report.md)",         True,  lambda t, a: cmd_run(t, a)),
    ("16", "TOOLS: hydra/msf/sqlmap/whatweb",         True,  cmd_tools),
    ("17", "JS endpoint extractor (rahasia/API)",     True,  mod_jsfind),
    ("18", "Screenshot (playwright via Tor)",         True,  mod_shot),
    ("19", "Export intel → findings.jsonl ◦",         False, cmd_export),
    ("20", "Wayback DIFF (snapshot lama vs live) ◦",   True,  mod_waybackdiff),
    ("21", "Graf subdomain (graphviz → SVG) ◦",        True,  mod_graf),
    ("22", "Laporan → HTML (report.md → .html) ◦",     False, cmd_report),
    ("23", "Favicon hash → pivot Shodan/FOFA",         True,  mod_favicon),
    ("24", "Tracker/analytics ID → pivot aset",        True,  mod_trackers),
    ("25", "ASN/IP range (RIPEstat+RDAP) ◦",           True,  mod_asn),
    ("26", "recon-ng (partner engine, SOURCE=target)", True,  cmd_reconng),
]

def cmd_menu(args) -> None:
    global ANIM
    if getattr(args, "quiet", False): ANIM = False
    target = getattr(args, "target", "") or ""
    # atribut default agar semua modul bisa dipanggil dari menu
    args.out = True
    for k, v in (("query", None), ("name", None), ("skip", ""), ("severity", None),
                 ("tags", None), ("mode", None), ("server", None)):
        if not hasattr(args, k): setattr(args, k, v)
    ui_banner()          # ASCII gradient animasi + checklist boot
    ui_header()          # panel Tor/pace/scope/NDA
    while True:
        v = menu_verdict(target)
        ui_target(target, v)
        ui_menu()
        try:
            ch = input(ui_prompt()).strip()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if not ch: continue
        if ch.lower() in ("q", "0", "quit", "exit", "keluar"): break
        if ch.lower() in ("t", "set", "target", "-t", "--target"):
            CONS.print("  [dim]set target pakai: 't <domain>' · '-t <domain>' · '--target <domain>' · ketik langsung domain/URL[/dim]"); continue

        # set target — semua bentuk yang diterima:
        # "t X" · "-t X" · "--target X" · "--target=X" · langsung domain · langsung URL
        raw = ch.strip()
        is_cmd = False
        for pfx in ("--target=", "--target ", "-t ", "target ", "set ", "t "):
            if ch.lower().startswith(pfx):
                raw = ch[len(pfx):].strip()
                is_cmd = True
                break
        if is_cmd and not raw:
            CONS.print("  [yellow]maka: t <domain>/<url>[/yellow]"); continue
        looks_like_url = raw.lower().startswith(("http://", "https://", "www."))
        looks_like_domain = (
            ("." in raw or "@" in raw) and " " not in raw and len(raw) >= 4
            and re.match(r"^[A-Za-z0-9._%+\-@:/?#\[\]!$&'()*+,;=~]+$", raw) is not None
        )
        if is_cmd or looks_like_url or looks_like_domain:
            target = raw.strip('"').strip("'").rstrip("/")
            CONS.print(f"  → target diset: [bold]{target}[/bold] · {menu_verdict(target)}")
            continue
        if ch.lower() == "a" or ch.lower() in ("auto", "sweep", "semua",
                                               "af", "a full", "auto full"):
            if not target:
                target = _ask("target (domain/URL)")
                if not target:
                    CONS.print("  [yellow]batal[/yellow]"); continue
            low = ch.lower()
            want_full = low in ("af", "a full", "auto full")
            prev = getattr(args, "full", False)
            args.full = want_full
            try:
                cmd_auto(target, args)
                ui_done("AUTO SWEEP")
            except SystemExit:
                raise
            except KeyboardInterrupt:
                CONS.print("\n[yellow]AUTO SWEEP dihentikan (Ctrl-C) — hasil modul yg sudah jalan tetap tersimpan[/yellow]")
            finally:
                args.full = prev
            continue
        item = next((it for it in MENU_ITEMS if it[0] == ch), None)
        if not item:
            CONS.print(f"  [yellow]{ch!r} bukan pilihan dikenal[/yellow] — pakai: nomor menu, 't <domain>', URL langsung, atau 'auto'/'a'"); continue
        _, lab, need_t, fn = item
        if need_t and not target:
            target = _ask("target (domain/URL)")
            if not target:
                CONS.print("  [yellow]batal (tanpa target)[/yellow]"); continue
        ui_run(lab)      # sweep ▰▱ + panel "▶ label"
        try:
            fn(target, args)
            ui_done(lab) # centang ✔
        except SystemExit:
            raise
        except Exception as e:
            CONS.print(f"[red]  ! {lab} gagal: {e}[/red]")

# ─────────────────────────── AUTO SWEEP ───────────────────────────
def cmd_auto(target: str, args) -> None:
    """AUTO SWEEP — semua modul non-interaktif berurutan (1 sampai akhir).

    Default: sweep standar (pasif + fingerprint + pivot OSINT). `--full` menambah
    nuclei · nmap · shot · recon-ng. Menu ofensif `tools` (hydra/msf/sqlmap/
    whatweb) TIDAK pernah masuk daftar otomatis.
    """
    require_scope(target, args.authorized)
    dom = host_of(target)
    d = outdir(dom)
    args.out = True
    t0 = time.time()
    mode = "FULL" if getattr(args, "full", False) else "standar"
    CONS.print(f"[bold]AUTO SWEEP ({mode}) — output → {d}[/bold]")
    results: dict = {"scope": scope_verdict(target)}

    def _rc():
        cmd_reconng(target, args)
        return {"note": "lihat reconng.json + reconng.log"}

    # (no, key, label, fn) — urutan meniru MENU_ITEMS
    plan: list = [
        ("2",  "dns",       "DNS + SPF/DMARC/DKIM",  lambda: mod_dns(target, args)),
        ("2",  "mail",      "Mail Security",          lambda: mod_mail(target, args)),
        ("3",  "whois",     "Whois",                  lambda: mod_whois(target, args)),
        ("4",  "subs",      "Subdomain enum",        lambda: mod_subs(target, args)),
        ("5",  "sublive",   "Subdomain LIVE",        lambda: mod_sublive(target, args)),
        ("6",  "techstack", "TechStack",             lambda: mod_techstack(target, args)),
        ("7",  "web",       "Web Fingerprint",       lambda: mod_web(target, args)),
        ("10", "wayback",   "Wayback",               lambda: mod_wayback(target, args)),
        ("20", "waybackdiff", "Wayback DIFF",        lambda: mod_waybackdiff(target, args)),
        ("23", "favicon",   "Favicon hash",          lambda: mod_favicon(target, args)),
        ("24", "trackers",  "Trackers",              lambda: mod_trackers(target, args)),
        ("25", "asn",       "ASN/CIDR",              lambda: mod_asn(target, args)),
        ("13", "dork",      "Dork",                  lambda: mod_dork(target, args)),
        ("12", "email",     "Email harvest",         lambda: mod_email(target, args)),
        ("14", "people",    "People",                lambda: mod_people(target, args)),
        ("9",  "celah",     "Celah/Exposure",        lambda: mod_celah(target, args)),
        ("17", "jsfind",    "JS endpoints",          lambda: mod_jsfind(target, args)),
    ]
    if getattr(args, "full", False):
        plan += [
            ("8",  "vuln",   "nuclei (vuln)", lambda: mod_vuln(target, args)),
            ("11", "ports",  "nmap ports",    lambda: mod_ports(target, args)),
            ("18", "shot",   "Screenshot",    lambda: mod_shot(target, args)),
            ("26", "reconng", "recon-ng",     _rc),
        ]
    total = len(plan)
    stats: dict = {}
    for i, (n, key, lab, fn) in enumerate(plan, 1):
        if key in (getattr(args, "skip", "") or "").split(","):
            stats[key] = "lewati"
            CONS.print(f"[dim]  [{i}/{total}] {lab} — LEWAT (--skip)[/dim]")
            continue
        try:
            ui_run(f"[{i}/{total}] {lab}")
            results[key] = fn()
            stats[key] = "OK"
            ui_done(f"[{i}/{total}] {lab}")
        except SystemExit:
            raise
        except Exception as e:
            stats[key] = f"gagal: {str(e)[:80]}"
            CONS.print(f"[red]  ! {lab} gagal: {e}[/red]")
    save_json(d / "all.json", results)
    rep = build_report(dom, d, results)
    # artefak lampiran (graf butuh subs.json dari SESSION_OUT yang sama)
    try:
        mod_graf(target, args)
    except Exception as e:
        CONS.print(f"[yellow]graf gagal: {e}[/yellow]")
    try:
        cmd_report(target, args)
    except Exception as e:
        CONS.print(f"[yellow]report.html gagal: {e}[/yellow]")
    ok = sum(1 for v in stats.values() if v == "OK")
    tbl(["#", "MODUL", "STATUS"],
        [[n, lab, stats.get(key, "")] for (n, key, lab, _) in plan],
        title="AUTO SWEEP — RINGKASAN")
    section("SELESAI")
    CONS.print(f"[green]Laporan:[/green] {rep}")
    CONS.print(f"[green]Data mentah:[/green] {d}/all.json")
    CONS.print(f"[green]Durasi:[/green] {time.time() - t0:.0f}s · {ok}/{total} modul OK · mode {mode}")

# ─────────────────────────── REPORT / RUN ───────────────────────────
def build_report(dom: str, d: Path, results: dict) -> Path:
    L = [f"# Laporan OSINT — {dom}", "",
         f"Tanggal: {_dt.datetime.now():%Y-%m-%d %H:%M WIB} · Generator: OSINT by kzldx v2.2", "",
         "> Sumber: DNS/Whois publik, crt.sh, Wayback CDX, permukaan HTTP. Semua query lewat Tor."]
    order = [("scope", "Scope"), ("dns", "DNS & Email Security"), ("mail", "Mail"),
             ("whois", "Whois"), ("subs", "Subdomain"), ("sublive", "Subdomain LIVE"),
             ("wayback", "Riwayat Wayback"), ("waybackdiff", "Wayback DIFF"),
             ("web", "Fingerprint Web"), ("techstack", "TechStack"), ("favicon", "Favicon"),
             ("trackers", "Trackers"), ("asn", "ASN"), ("celah", "Celah/Exposure"),
             ("jsfind", "JS endpoints"), ("email", "Email terkumpul"), ("people", "People"),
             ("dork", "Dork lanjutan"), ("vuln", "Kerentanan (nuclei)"),
             ("ports", "Port Scan"), ("shot", "Screenshot"), ("reconng", "recon-ng")]
    for key, title in order:
        if key not in results: continue
        L += [f"\n## {title}", ""]
        val = results[key]
        if key == "scope":
            L.append(f"- {val}")
        elif key in ("dns", "mail", "whois", "web", "email", "wayback", "sublive",
                     "waybackdiff", "techstack", "favicon", "trackers", "asn",
                     "celah", "jsfind", "people", "vuln", "ports", "shot", "reconng"):
            L.append("```json")
            L.append(json.dumps(val, indent=2, ensure_ascii=False, default=str)[:6000])
            L.append("```")
        elif key == "subs":
            subs = val.get("subdomains", [])
            L.append(f"- Total: **{len(subs)}** (sumber: {val.get('by_source')})")
            for s in subs[:120]: L.append(f"  - `{s}`")
        elif key == "dork":
            for dd in val.get("dorks", []): L.append(f"- **{dd['name']}**: `{dd['query']}`")
    # intel.json → seksi khusus di laporan
    intel_blk: list[str] = []
    try:
        ip = d / "intel.json"
        if ip.exists():
            intel = json.loads(ip.read_text())
            if isinstance(intel, list) and intel:
                intel_blk = ["", "## Intel otomatis (deteksi → ⚠ kerentanan → 🔧 teknik)", ""]
                for e in intel[:60]:
                    intel_blk.append(f"- **[{e.get('sev', '?')}] {e.get('topik')}** "
                                     f"({e.get('source')}): {e.get('vuln')}")
                    intel_blk.append(f"  - Teknik: {e.get('teknik')}")
    except Exception:
        intel_blk = []
    if intel_blk: L += intel_blk
    L += ["\n## Temuan cepat (otomatis — verifikasi manual sebelum laporan klien)", ""]
    notes = []
    for k in ("dns", "mail"):
        v = results.get(k)
        if isinstance(v, dict):
            for n in v.get("notes", []):
                notes.append(f"- [{k}] {n}")
    if isinstance(results.get("wayback"), dict) and results["wayback"].get("sensitive_count"):
        notes.append(f"- [wayback] {results['wayback']['sensitive_count']} URL kandidat file sensitif — lihat `wayback_sensitive.txt`")
    if not notes: notes.append("- (tidak ada catatan otomatis)")
    L += notes
    p = d / "report.md"
    p.write_text("\n".join(L))
    return p

def cmd_run(target: str, args) -> None:
    require_scope(target, args.authorized)
    dom = host_of(target)
    d = outdir(dom)
    args.out = True
    CONS.print(f"[bold]Output → {d}[/bold]")
    results: dict = {"scope": scope_verdict(target)}
    steps = [("dns", lambda: mod_dns(target, args)),
             ("mail", lambda: mod_mail(target, args)),
             ("whois", lambda: mod_whois(target, args)),
             ("subs", lambda: mod_subs(target, args)),
             ("sublive", lambda: mod_sublive(target, args)),
             ("wayback", lambda: mod_wayback(target, args)),
             ("web", lambda: mod_web(target, args)),
             ("techstack", lambda: mod_techstack(target, args)),
             ("jsfind", lambda: mod_jsfind(target, args)),
             ("celah", lambda: mod_celah(target, args)),
             ("email", lambda: mod_email(target, args)),
             ("dork", lambda: mod_dork(target, args))]
    for name, fn in steps:
        if name in (getattr(args, "skip", "") or "").split(","):
            CONS.print(f"[dim]  lewati {name} (--skip)[/dim]"); continue
        try:
            section(name.upper())
            results[name] = fn()
        except SystemExit:
            raise
        except Exception as e:
            CONS.print(f"[red]  ! {name} gagal: {e}[/red]")
            results[name] = {"error": str(e)}
    save_json(d / "all.json", results)
    rep = build_report(dom, d, results)
    section("SELESAI")
    CONS.print(f"[green]Laporan:[/green] {rep}")
    CONS.print(f"[green]Data mentah:[/green] {d}/all.json")

# ─────────────────────────── CLI ───────────────────────────
def main():
    ap = argparse.ArgumentParser(
        prog="osint.py",
        description="OSINT by kzldx Suite v2.2 — OSINT modular fail-closed + Tor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Contoh: python3 osint.py run sman1batu.sch.id --out")
    ap.add_argument("--no-tor", action="store_true", help="nonaktifkan Tor (langsung)")
    ap.add_argument("--pace", type=float, default=None, help="jeda detik antar-request massal")
    ap.add_argument("--authorized", action="store_true",
                    help="override scope: Anda menyatakan punya izin tertulis (dicatat di layar)")
    ap.add_argument("--out", action="store_true", help="simpan hasil ke folder output/")
    ap.add_argument("--quiet", action="store_true", help="tanpa hiasan rich")
    ap.add_argument("--speed", type=float, default=None,
                    help="kecepatan animasi: >1 lebih cepat, <1 lebih lambat (override config anim_speed)")
    # flag yang juga BOLEH ditaruh setelah subcommand: dns target --out
    # CATATAN: default=SUPPRESS agar nilai dari parser induk TIDAK ditimpa
    # default subparser (argparse: subnamespace menimpa namespace induk).
    # Dulu: `osint.py --out dns x` → out balik False; `--authorized` di depan hilang.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--out", action="store_true", default=argparse.SUPPRESS,
                        help="simpan hasil ke folder output/")
    common.add_argument("--server", help="server DNS khusus (modul dns)")
    common.add_argument("--authorized", action="store_true", default=argparse.SUPPRESS,
                        help="override scope: punya izin tertulis")
    common.add_argument("--quiet", action="store_true", default=argparse.SUPPRESS,
                        help="tanpa animasi/hiasan")
    common.add_argument("--speed", type=float, default=argparse.SUPPRESS,
                        help="kecepatan animasi (>1 cepat, <1 lambat)")
    sub = ap.add_subparsers(dest="cmd", required=False)

    def add(name, fn, tip):
        p = sub.add_parser(name, help=tip, parents=[common])
        p.add_argument("target", help="domain/host/URL/nama-tergantung-modul")
        p.set_defaults(fn=lambda a, _f=fn: _f(a.target, a))
        return p

    def _scope_cmd(target, a):
        v = scope_verdict(target)
        if not CFG.get("enforce_scope"):
            blocked = CFG.get("enforce_blocklist", True) and v.startswith("BLOCKLIST")
            if blocked:
                print(v); print("blocklist aktif (enforce_blocklist=true)"); sys.exit(2)
            print("MODE BEBAS (enforce_scope=false) — target bebas dipakai modul mana pun")
            print(f"allowlist: {v} — tidak berlaku pada mode ini")
            sys.exit(0)
        print(v)
        sys.exit(0 if (v.startswith("IN SCOPE") or a.authorized) else 2)
    add("scope", _scope_cmd, "cek scope fail-closed")
    add("dns", mod_dns, "rekaman DNS penuh + SPF/DMARC/DKIM analisis")
    add("whois", mod_whois, "registrasi domain")
    p = add("subs", mod_subs, "subdomain (subfinder+crt.sh+wayback)")
    p.add_argument("--no-wayback", dest="wayback", action="store_false")
    p.add_argument("--amass", action="store_true", help="tambah amass -passive (lambat)")
    add("web", mod_web, "fingerprint HTTP + TLS")
    p = add("ports", mod_ports, "nmap (langsung/non-Tor)")
    p.add_argument("--deep", action="store_true", help="-sV -sC top-1000")
    p.add_argument("--timeout", type=int, default=900)
    add("mail", mod_mail, "MX/SPF/DMARC/DKIM/MTA-STS")
    add("wayback", mod_wayback, "URL historis + filter file sensitif")
    p = add("waybackdiff", mod_waybackdiff, "diff snapshot wayback tertua vs live sekarang")
    p.add_argument("--url", help="URL spesifik (default: https://<target>/)")
    add("graf", mod_graf, "graf pohon subdomain (graphviz → SVG, lokal)")
    p = add("favicon", mod_favicon, "mmh3 hash favicon → pivot Shodan/FOFA")
    p.add_argument("--file", help="hash file ikon lokal (tanpa network)")
    add("trackers", mod_trackers, "ekstrak tracker ID → pivot aset sama-tim")
    add("asn", mod_asn, "ASN/IP range via RIPEstat+RDAP + dork shodan asn")
    p = add("reconng", cmd_reconng, "wrapper modul recon-ng (SOURCE=target)")
    p.add_argument("--module", help="modul recon-ng (default: recon/domains-hosts/hackertarget)")
    p.add_argument("--cmd", help="perintah global recon-ng (mis: 'show hosts') — lewati -m")
    add("dork", mod_dork, "kumpulan dork siap pakai")
    add("email", mod_email, "panen email dari halaman target")
    p = add("people", mod_people, "tautan people-search + pola email")
    p.add_argument("--query", help="kata kunci orang (default=target)")
    p.add_argument("--name", help="nama lengkap → tebak pola email @target")
    p = add("leak", mod_leak, "cek kebocoran email (HIBP, butuh API key)")
    p.add_argument("--query", help="email (default=target)")
    p = sub.add_parser("auto", help="AUTO SWEEP semua modul non-interaktif (urut menu)",
                       parents=[common])
    p.add_argument("target")
    p.add_argument("--full", action="store_true",
                   help="+ nuclei / nmap / shot / recon-ng")
    p.add_argument("--skip", help="lewati modul (koma): dns,subs,wayback,email,...")
    p.set_defaults(fn=lambda a: cmd_auto(a.target, a))
    p = sub.add_parser("run", help="PIPELINE PENUH → report.md", parents=[common])
    p.add_argument("target")
    p.add_argument("--skip", help="lewati modul (koma): subs,wayback,email,web")
    p.set_defaults(fn=lambda a: cmd_run(a.target, a))
    p = add("sublive", mod_sublive, "probe HTTP semua subdomain (butuh subs.txt)")
    add("techstack", mod_techstack, "fingerprint tech mendalam (CMS/framework/header/cookie)")
    p = add("vuln", mod_vuln, "scan kerentanan via nuclei (rate 3/dtk)")
    p.add_argument("--severity", default=None, help="critical,high / critical / dll")
    p.add_argument("--tags", default=None, help="filter template: exposure,config,cve")
    p.add_argument("--mode", choices=["quick", "full"], default=None, help="quick = critical+exposure")
    p.add_argument("--list", dest="list_file", default=None,
                   help="file daftar target ('auto' = sublive.txt terbaru; divalidasi scope)")
    p.add_argument("--timeout", type=int, default=1800)
    add("celah", mod_celah, "sapuan path sensitif (.git/.env/backup/actuator/dll)")
    add("jsfind", mod_jsfind, "ekstrak endpoint & rahasia dari file JS target")
    p = add("shot", mod_shot, "screenshot halaman (playwright/chromium via Tor)")
    p.add_argument("--list", dest="list_file", default=None,
                   help="'auto' = screenshot semua host di sublive.txt")
    p = add("tools", cmd_tools, "submenu: nmap/hydra/metasploit/sqlmap/whatweb/nuclei")
    p = sub.add_parser("export", help="intel.json → findings.jsonl (integrasi GreyHat)",
                       parents=[common])
    p.add_argument("--target", default="", help="filter run per domain (default: semua)")
    p.add_argument("--append", default="", help="tujuan findings.jsonl (default: cetak / --out → findings.jsonl)")
    p.set_defaults(fn=lambda a: cmd_export(a.target, a))
    p = sub.add_parser("report", help="render report.md terbaru → report.html",
                       parents=[common])
    p.add_argument("target", nargs="?", default="",
                   help="domain (kosong = laporan terbaru mana pun)")
    p.set_defaults(fn=lambda a: cmd_report(a.target, a))
    p = sub.add_parser("menu", help="MENU interaktif (ini juga default bila tanpa argumen)",
                       parents=[common])
    p.add_argument("target", nargs="?", default="", help="target awal (opsional)")
    p.set_defaults(fn=cmd_menu)

    args = ap.parse_args()
    global _SPD
    if getattr(args, "speed", None) is not None:
        _SPD = max(0.1, float(args.speed))   # jangan 0/negatif
    if not hasattr(args, "fn"):
        args.fn = cmd_menu          # tanpa subcommand → menu interaktif
    if args.no_tor: CFG["use_tor"] = False
    if args.pace is not None: CFG["pace"] = args.pace
    if getattr(args, "out", False) and args.cmd != "run": args.out = True

    # satu folder output untuk SELURUH invokasi ini (semua modul → folder sama)
    global SESSION_OUT, ANIM
    if getattr(args, "quiet", False): ANIM = False
    _t = getattr(args, "target", "") or ""
    if _t and not _t.startswith("@") and " " not in _t:
        SESSION_OUT = Path(CFG["output_dir"]) / f"{host_of(_t) or 'target'}_{_dt.datetime.now():%Y%m%d-%H%M%S}"

    if args.fn is not cmd_menu:
        ui_header()      # baris status CLI (animasi bila tty, plain bila pipe/--quiet)
    args.fn(args)

if __name__ == "__main__":
    main()
