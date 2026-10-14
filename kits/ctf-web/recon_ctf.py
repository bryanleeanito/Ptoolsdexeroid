#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""recon_ctf.py — recon cepat soal web jeopardy CTF (read-only, non-destruktif).
Dump header/cookie (JWT ke-decode), comment source, form/param, cek jalur bocor
(robots/.git/flag.txt/dll), fingerprint, scan JS endpoint. Butuh internet.

    python3 recon_ctf.py http://challenge.ctf/web
    python3 recon_ctf.py http://target/ --js --all
"""
import argparse, base64, json, re, ssl, sys, urllib.error, urllib.parse, urllib.request

UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0 Safari/537.36"
FLAG_RX = re.compile(r"(?:flag|ctf|dexero|picoctf|htb)\s*[{(][A-Za-z0-9_!@#$%^&*+\-=:. /]{3,120}[})]", re.I)
LEAK_PATHS = ["/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/flag.txt",
              "/flag", "/flag.php", "/phpinfo.php", "/server-status", "/.DS_Store",
              "/backup", "/index.php.bak", "/index.php~", "/.git/config",
              "/.svn/entries", "/web.config", "/composer.json", "/package.json",
              "/debug", "/admin", "/.well-known/security.txt", "/readme.txt",
              "/LICENSE", "/crossdomain.xml", "/security.txt"]


def http(url, method="GET", timeout=15.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(500_000)
            return r.status, dict(r.headers), body, r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(500_000), url
    except Exception as e:
        return None, {}, b"", url


def b64url_json(seg):
    try:
        pad = "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + pad))
    except Exception:
        return None


def decode_jwt(tok):
    parts = tok.split(".")
    if len(parts) != 2:
        return None
    return b64url_json(parts[0]), b64url_json(parts[1])


def decode_cookie(v):
    if v.count(".") == 2 and v.startswith("eyJ"):
        dec = decode_jwt(v)
        if dec:
            return {"jwt_header": dec[0], "jwt_payload": dec[1]}
    return {}


def scan_flag(text, label, temuan):
    for m in FLAG_RX.finditer(text):
        temuan.append((label, m.group(0)))


def main():
    ap = argparse.ArgumentParser(description="recon web jeorpadic CTF (read-only)")
    ap.add_argument("url")
    ap.add_argument("--js", action="store_true", help="ikut fetch file JS & cari endpoint")
    ap.add_argument("--all", action="store_true", help="cek semua jalur bocor (default: yang penting saja)")
    a = ap.parse_args()
    base = a.url if "://" in a.url else "http://" + a.url
    origin = urllib.parse.urlparse(base)
    host = origin.netloc
    temuan = []

    print(f"[*] target: {base}\n")
    print("── HEADERS " + "─" * 50)
    st, hdr, body, final = http(base)
    if st is None:
        print(f"[STOP] tak bisa konek ke {base}")
        return 1
    print(f"  status={st}  final={final}")
    for k, v in hdr.items():
        print(f"  {k}: {v[:100]}")
    missing = [h for h in ("X-Frame-Options", "Content-Security-Policy",
                           "Strict-Transport-Security") if h not in hdr]
    if missing:
        print(f"  [i] header keamanan hilang: {', '.join(missing)}")

    print("\n── COOKIES " + "─" * 50)
    for c in hdr.get("Set-Cookie", "").split("\n"):
        if not c:
            continue
        nama = c.split("=", 1)[0]
        print(f"  {c[:120]}")
        ekstra = decode_cookie(c.split("=", 1)[1].split(";")[0])
        for kk, vv in ekstra.items():
            print(f"    [{kk}] {json.dumps(vv)[:200]}")

    txt = body.decode("utf-8", "replace")
    scan_flag(txt, "halaman-utama", temuan)

    print("\n── HTML " + "─" * 50)
    comments = re.findall(r"<!--(.*?)-->", txt, re.S)
    for c in comments[:10]:
        c = c.strip()
        if c:
            print(f"  [comment] {c[:150]}")
            scan_flag(c, "comment", temuan)
    forms = re.findall(r"<form[^>]*>", txt, re.I)
    for f in forms[:5]:
        print(f"  [form] {f[:150]}")
    hiddens = re.findall(r"<input[^>]*type=[\"']hidden[\"'][^>]*>", txt, re.I)
    for h in hiddens[:10]:
        print(f"  [hidden] {h[:150]}")
    inputs = re.findall(r"<input[^>]*name=[\"']([^\"']+)[\"']", txt, re.I)
    if inputs:
        print(f"  [param input] {inputs[:15]}")
    scripts = re.findall(r"<script[^>]*src=[\"']([^\"']+)[\"']", txt, re.I)
    links = re.findall(r"href=[\"']([^\"']+)[\"']", txt, re.I)
    print(f"  [script src] {scripts[:8]}")
    scan_flag(txt, "sumber", temuan)

    print("\n── JALUR BOCOR " + "─" * 45)
    paths = LEAK_PATHS if a.all else ["/robots.txt", "/.git/HEAD", "/.env",
                                      "/flag.txt", "/flag", "/sitemap.xml",
                                      "/.DS_Store", "/phpinfo.php"]
    for path in paths:
        u = f"{origin.scheme}://{host}{path}"
        st2, h2, b2, _ = http(u, timeout=8)
        if st2 and st2 < 400 and b2 and not (st2 == 404):
            isi = b2[:120].decode("utf-8", "replace").replace("\n", " ")
            print(f"  [{st2}] {path}  → {isi}")
            scan_flag(b2.decode("utf-8", "replace"), path, temuan)

    if a.js:
        print("\n── JS ENDPOINT " + "─" * 43)
        for src in scripts:
            ju = urllib.parse.urljoin(base, src)
            _, _, jb, _ = http(ju, timeout=10)
            if not jb:
                continue
            jt = jb.decode("utf-8", "replace")
            eps = set(re.findall(r"[\"'](/[a-zA-Z0-9_\-./]{2,60})[\"']", jt))
            eps |= set(re.findall(r"https?://[\w.\-]+/[\w.\-/?=&]{2,60}", jt))
            keys = re.findall(r"(?:api[_-]?key|token|secret|password)\s*[:=]\s*[\"']([^\"']{6,})", jt, re.I)
            print(f"  {ju}:")
            for e in list(eps)[:15]:
                print(f"    endpoint {e}")
            for k in keys[:5]:
                print(f"    [!!! key hardcode] {k[:8]}…")
            scan_flag(jt, src, temuan)

    print("\n── RINGKASAN " + "─" * 46)
    if temuan:
        print("  [!!! FLAG]")
        for s, f in temuan:
            print(f"    {f}   (via {s})")
        return 0
    print("  belum ada flag. lanjut: coba parameter injection manual (sql/xss/lfi) atau buka JS satu-satu")
    return 0


if __name__ == "__main__":
    sys.exit(main())
