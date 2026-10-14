#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ctfd.py — solver universal CTFd API buat lomba jeorpadic.
Login (token API / form+nonce), list, download file, submit flag, autosolve
misc (rantai decode via ../ctf-decoder), sweep flags.json. Stdlib-only.

    export CTF_URL=https://ctf.contoh.id CTF_USER=aku CTF_PASS=rahasia
    python3 ctfd.py status                 # siapa aku + posisi
    python3 ctfd.py list                   # semua challenge + solved?
    python3 ctfd.py fetch --all            # unduh semua attachment
    python3 ctfd.py submit 12 "flag{...}"  # kirim 1 flag
    python3 ctfd.py sweep flags.json       # submit semua flag di file
    python3 ctfd.py autosolve              # decode file misc lalu submit

Password TIDAK pernah di-commit: env CTF_PASS / --pass-file / prompt.
"""
from __future__ import annotations

import argparse, http.cookiejar, json, os, pathlib, re, sys, time, urllib.error
import urllib.parse, urllib.request

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/126.0 Safari/537.36")
HERE = pathlib.Path(__file__).resolve().parent
JAR = http.cookiejar.MozillaCookieJar(str(HERE / ".cookies"))


# ------------------------------------------------------------------ http dasar
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Jangan ikut redirect 302 — kita mau lihat kode aslinya + cookie masuk."""
    def redirect_request(self, *a, **k):
        return None


def _opener():
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), _NoRedirect)
    return op, jar


_OPENER, _JAR = _opener()


def req(method, url, data=None, json_body=None, timeout=30.0, retries=3):
    """HTTP dengan retry (server CTF kadang500 sesaat). -> (status, dict|str|bytes)"""
    headers = {"User-Agent": UA, "Accept": "application/json,text/html,*/*"}
    body = None
    if json_body is not None:
        body = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
    elif data is not None:
        body = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    last = None
    for i in range(retries):
        r = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with _OPENER.open(r, timeout=timeout) as resp:
                isi = resp.read()
                ct = resp.headers.get("Content-Type", "")
                if "json" in ct:
                    return resp.status, json.loads(isi)
                return resp.status, isi.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            isi = e.read()
            try:
                return e.code, json.loads(isi)
            except Exception:
                return e.code, isi.decode("utf-8", "replace")
        except Exception as e:
            last = e
            time.sleep(1.5 * (i + 1))
    raise ConnectionError(f"gagal {method} {url}: {last}")


def base():
    return os.environ.get("CTF_URL", "").rstrip("/")


def akun():
    u = os.environ.get("CTF_USER", "")
    p = os.environ.get("CTF_PASS", "")
    pf = os.environ.get("CTF_PASS_FILE", "")
    if not p and pf and pathlib.Path(pf).exists():
        p = pathlib.Path(pf).read_text().strip()
    return u, p


# ----------------------------------------------------------------------- login
def login():
    b = base()
    u, p = akun()
    if not b:
        sys.exit("[STOP] set env CTF_URL dulu (mis. https://ctf.contoh.id)")
    if not u or not p:
        sys.exit("[STOP] set env CTF_USER & CTF_PASS (atau CTF_PASS_FILE)")

    # jalur 1: token API
    st, out = req("POST", f"{b}/api/v1/tokens",
                  json_body={"username": u, "password": p, "type": "user"})
    if st == 200 and isinstance(out, dict) and out.get("success"):
        tok = out["data"]["value"]
        _OPENER.addheaders = [("Authorization", f"Token {tok}")]
        print(f"[OK] login via API token ({u})")
        return "token"

    # jalur 2: form login + nonce (Flask-Login / CTFd klasik)
    st, hal = req("GET", f"{b}/login")
    if st != 200 or not isinstance(hal, str):
        print(f"[!] GET /login = HTTP {st} — server bermasalah? coba lagi nanti")
        return None
    m = re.search(r'<input[^>]*name=["\']?nonce["\']?[^>]*>', hal)
    nonce = ""
    if m:
        v = re.search(r'value=["\']?([^"\'\s>]+)', m.group(0))
        if v:
            nonce = v.group(1)
    st, out = req("POST", f"{b}/login",
                  data={"name": u, "password": p, "nonce": nonce, "_submit": ""})
    if st in (200, 302):
        # verifikasi: /api/v1/users/me harus200
        st2, me = req("GET", f"{b}/api/v1/users/me")
        if st2 == 200 and isinstance(me, dict) and me.get("success"):
            print(f"[OK] login via form ({me['data'].get('name', u)})")
            return "form"
        print(f"[!] login form tampak masuk tapi /users/me = {st2} — cek server")
        return None
    print(f"[!] POST /login = HTTP {st}: {str(out)[:120]}")
    return None


def me():
    st, out = req("GET", f"{base()}/api/v1/users/me")
    if st == 200 and isinstance(out, dict) and out.get("success"):
        return out["data"]
    return None


# ------------------------------------------------------------------- challenge
def daftar():
    st, out = req("GET", f"{base()}/api/v1/challenges")
    if st != 200 or not isinstance(out, dict) or not out.get("success"):
        print(f"[!] gagal list (HTTP {st}): {str(out)[:150]}")
        return []
    return out["data"]


def detail(cid):
    st, out = req("GET", f"{base()}/api/v1/challenges/{cid}")
    if st == 200 and isinstance(out, dict) and out.get("success"):
        return out["data"]
    return None


def unduh(cid, nama):
    d = HERE / "files" / re.sub(r"[^\w.\-]+", "_", nama)[:60]
    d.mkdir(parents=True, exist_ok=True)
    st, out = req("GET", f"{base()}/api/v1/challenges/{cid}/file")
    # CTFd: /files/ langsung; fallback ke link di detail
    if st == 200 and isinstance(out, (bytes, str)):
        data = out.encode("latin-1") if isinstance(out, str) else out
        (d / "attachment.bin").write_bytes(data)
        print(f"  [file] {d}/attachment.bin ({len(data)} B)")
        return True
    return False


def submit(cid, flag):
    st, out = req("POST", f"{base()}/api/v1/challenges/attempt",
                  json_body={"challenge_id": int(cid), "submission": flag})
    if st == 200 and isinstance(out, dict) and out.get("success"):
        status = out["data"].get("status", "?")
        return status
    return f"http-{st}"


# ---------------------------------------------------------------- autosolve
def _muat_decoder():
    """Import decode.py dari ctf-decoder sibling (ada setelah git clone)."""
    p = HERE.parent / "ctf-decoder" / "decode.py"
    if not p.exists():
        return None
    import importlib.util
    spec = importlib.util.spec_from_file_location("ctfdec", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def cari_flag_di_teks(mod, teks):
    m = mod.FLAG_KETAT.search(teks)
    if m:
        return m.group(0)
    for kandidat in _kumpulkan_kandidat(teks):
        fl = _bongkar(mod, kandidat)
        if fl:
            return fl
    return None


def _kumpulkan_kandidat(teks):
    """Teks utuh + token encode yang terdeteksi di dalamnya."""
    yield teks
    for tok in re.findall(r"[A-Za-z0-9+/=_\-]{16,}", teks):
        yield tok


def _bongkar(mod, teks):
    """Rantai decode; kalau keluar flag{... tanpa kurung tutup, tutup dulu."""
    langkah, akhir = mod.rantai(teks, 8)
    m = mod.FLAG_KETAT.search(akhir)
    if m:
        return m.group(0)
    # kasus klasik: base64 berhenti sebelum '}' karena } di luar blob
    if re.search(r"\b(?:flag|ctf|dexero)\s*\{[^{}\s]{3,300}$", akhir, re.I):
        m = mod.FLAG_KETAT.search(akhir + "}")
        if m:
            return m.group(0)
    return None


# ----------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="solver CTFd API (lomba jeorpadic)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    sub.add_parser("list")
    p = sub.add_parser("fetch"); p.add_argument("id", nargs="?"); p.add_argument("--all", action="store_true")
    p = sub.add_parser("submit"); p.add_argument("id"); p.add_argument("flag")
    p = sub.add_parser("sweep"); p.add_argument("file")
    sub.add_parser("autosolve")
    a = ap.parse_args()

    if not login():
        sys.exit("[STOP] login gagal — kalau server 500 terus, lapor admin CTF")
    b = base()

    if a.cmd == "status":
        m = me()
        if m:
            print(f"[me] {m.get('name')} (id {m.get('id')}) score={m.get('score', '?')}")
        st, sb = req("GET", f"{b}/api/v1/scoreboard")
        if st == 200 and isinstance(sb, dict):
            for pos, row in enumerate(sb.get("data", []), 1):
                if row.get("name") == (m or {}).get("name"):
                    print(f"[posisi] #{pos} dari {len(sb['data'])} — {row.get('score')} poin")
                    break
        return 0

    if a.cmd == "list":
        rows = daftar()
        print(f"[{len(rows)} challenge]")
        for c in rows:
            tanda = "✓" if c.get("solved_by_me") else "·"
            files = f" [{len(c.get('files') or [])} file]" if c.get("files") else ""
            print(f"  {tanda} #{c['id']:<3} {c.get('category','?'):<12} "
                  f"{c.get('value',0):>4}p  {c.get('name','?')}{files}")
        solved = sum(1 for c in rows if c.get("solved_by_me"))
        print(f"  → {solved}/{len(rows)} solved")
        return 0

    if a.cmd == "fetch":
        rows = daftar()
        target = [c for c in rows if a.all or str(c["id"]) == str(a.id)]
        if not target:
            sys.exit(f"[STOP] challenge id {a.id} tak ada")
        for c in target:
            d = detail(c["id"])
            if not d:
                print(f"  [!] #{c['id']} detail gagal")
                continue
            print(f"  #{d['id']} {d['name']}")
            for f in d.get("files") or []:
                u = f if f.startswith("http") else b + f
                st, out = req("GET", u)
                if st == 200:
                    data = out.encode("latin-1") if isinstance(out, str) else out
                    nama = pathlib.Path(urllib.parse.urlparse(u).path).name or "file"
                    dd = HERE / "files" / re.sub(r"[^\w.\-]+", "_", c["name"])[:50]
                    dd.mkdir(parents=True, exist_ok=True)
                    (dd / nama).write_bytes(data)
                    print(f"    [file] {dd / nama} ({len(data)} B)")
        return 0

    if a.cmd == "submit":
        hasil = submit(a.id, a.flag)
        tanda = {"correct": "✓ BENAR", "incorrect": "✗ salah",
                 "already_solved": "= sudah solved"}.get(hasil, hasil)
        print(f"[#{a.id}] {tanda}")
        return 0 if hasil in ("correct", "already_solved") else 1

    if a.cmd == "sweep":
        data = json.loads(pathlib.Path(a.file).read_text(encoding="utf-8-sig"))
        rows = {c["id"]: c for c in daftar()}
        ok = salah = 0
        for item in data:
            cid, flag = str(item["id"]), item["flag"]
            c = rows.get(int(cid)) if cid.isdigit() else None
            if c and c.get("solved_by_me"):
                print(f"  [skip] #{cid} sudah solved")
                continue
            hasil = submit(cid, flag)
            if hasil in ("correct", "already_solved"):
                ok += 1
                print(f"  [✓] #{cid} {c['name'] if c else ''} — {hasil}")
            else:
                salah += 1
                print(f"  [✗] #{cid} — {hasil}")
            time.sleep(0.5)
        print(f"\n[ringkas] {ok} benar, {salah} salah/skip-error")
        return 0 if ok else 1

    if a.cmd == "autosolve":
        mod = _muat_decoder()
        if not mod:
            sys.exit("[STOP] ctf-decoder/decode.py tak ketemu (clone lengkap dulu)")
        rows = daftar()
        ketemu = 0
        for c in rows:
            if c.get("solved_by_me"):
                continue
            d = detail(c["id"])
            if not d:
                continue
            # 1) teks deskripsi
            fl = cari_flag_di_teks(mod, d.get("description") or "")
            # 2) file lampiran
            if not fl:
                for f in d.get("files") or []:
                    u = f if f.startswith("http") else b + f
                    st, out = req("GET", u)
                    if st != 200:
                        continue
                    teks = out if isinstance(out, str) else None
                    if teks is None:
                        try:
                            teks = out.decode("utf-8")
                        except Exception:
                            continue
                    fl = cari_flag_di_teks(mod, teks)
                    if fl:
                        break
            if fl:
                hasil = submit(c["id"], fl)
                tanda = "✓" if hasil in ("correct", "already_solved") else f"✗({hasil})"
                print(f"  [{tanda}] #{c['id']} {c['name']} → {fl}")
                if hasil in ("correct", "already_solved"):
                    ketemu += 1
            time.sleep(0.4)
        print(f"\n[autosolve] {ketemu} flag terkirim dari challenge terbuka")
        return 0


if __name__ == "__main__":
    sys.exit(main())
