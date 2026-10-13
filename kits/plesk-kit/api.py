#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plesk_xml_api_proper.py - klien XML API Plesk: format resmi + pacing patuh doktrin.

Endpoint resmi : POST /enterprise/control/agent.php   (panel default :8443)
Packet resmi   : <?xml version="1.0" encoding="UTF-8"?>
                 <packet version="1.6.9.1">...</packet>

Empat cara auth YANG DIDOKUMENTASIKAN (docs.plesk.com):
  header   HTTP_AUTH_LOGIN / HTTP_AUTH_PASSWD   <- default, ini yg bikin error
                                                "Authentication method is not
                                                 specified" hilang
  basic    Authorization: Basic base64(user:pass)
  key      KEY: <secret key>
  session  <server><create_session>...  lalu pakai <session-id>

DUA MODE:
  probe   (default)  packet get_protos TANPA kredensial. Nol tebakan sandi.
                     Bertanya saja: "XML API nyala? versi didukung?"
  creds   --creds F --i-know-what-i-do
                     tebak kredensial, TERBATAS dan berhenti sendiri.

PATUH security_audit_protocol.md §0:
  butir 3 : jeda >= 2.5 dtk antar-request (floor KERAS, --delay tak bisa di
            bawahnya); berhenti pada 2x BLOCK berturut -> PAUSE, jangan spam
  butir 6 : brute-force wajib --i-know-what-i-do (risiko lockout)
TIDAK PERNAH loop tanpa batas: --repeat default 1, maksimum 3.

CATATAN soal error 1010: di Plesk itu "Access to Plesk Panel denied" - IP atau
API diblokir, BUKAN rate limit. Menunggu lalu retry tidak menyelesaikannya.
(Kalau yang kamu lihat justru Cloudflare 1010 "Access Denied: Bad Bot",
retry agresif malah memperparah.)
"""
from __future__ import annotations

import argparse, base64, http.cookiejar, json, pathlib, re, sys, time
import urllib.error, urllib.parse, urllib.request

DEFAULT_SCOPE = "/root/data/Auth/scope.txt"
DASAR = 2.5          # floor jeda (detik) dari §0 butir 3
MAKS_REPEAT = 3

# --- semantik gate: disalin persis dari gapps-kit/kit_common.py -------------
def host_of(url: str) -> str:
    if "://" in url:
        return urllib.parse.urlparse(url).netloc.lower().split(":")[0]
    return url.split("/")[0].lower().rstrip("/")

def _match(h: str, pat: str) -> bool:
    pat = pat.lower()
    if pat.startswith("*."):
        return h == pat[2:] or h.endswith("." + pat[2:])
    return h == pat

def load_scope(path=DEFAULT_SCOPE):
    p = pathlib.Path(path)
    allow, block = [], []
    if not p.exists():
        return False, allow, block
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = line.split()[0]
        (block if host.startswith("!") else allow).append(host.lstrip("!").lower())
    return True, allow, block

def scope_check(url: str, scope_path=DEFAULT_SCOPE, authorized=False) -> str:
    """Gerbang wajib. Fail-closed: scope tak terbaca = STOP."""
    ok, allow, block = load_scope(scope_path)
    h = host_of(url)
    if not ok:
        sys.exit(f"[STOP] scope.txt TIDAK TERBACA ({scope_path}) — fail-closed.")
    for p in block:
        if _match(h, p):
            sys.exit(f"[STOP] BLOCKLIST: {h} (rule !{p}) — jangan disentuh.")
    if authorized:
        print(f"[!] --authorized: {h} di luar allowlist — kamu nyatakan ada izin tertulis.")
        return "AUTHORIZED"
    if any(_match(h, p) for p in allow):
        return "IN_SCOPE"
    sys.exit(f"[STOP] {h} TIDAK ADA di scope.txt — fail-closed. "
             f"Tambahkan dulu lewat target-inventory, atau pakai --authorized "
             f"(hanya kalau ada dokumen izin tertulis).")
# ---------------------------------------------------------------------------

VER_RE = re.compile(r"<errcode>\s*(\d+)\s*</errcode>", re.S)
TEX_RE = re.compile(r"<errtext>(.*?)</errtext>", re.S | re.I)
OK_RE  = re.compile(r"<status>\s*ok\s*</status>", re.S)

STOP_SEGERA = {
    "1012": "Locked login — AKUN TERKUNCI. HENTIKAN. Retry = makin terkunci.",
    "1011": "Account disabled — akun dimatikan. HENTIKAN.",
    "1010": "Access to Plesk Panel denied — IP/akses DITOLAK. Ini BUKAN rate "
            "limit: menunggu lalu retry percuma. Cek panel.ini [api] enabled, "
            "atau whitelist IP di Tools & Settings > Security Policy.",
    "1004": "Plesk initial setup belum selesai.",
    "1030": "License expired.",
}
STOP_BLOKIR = {"1024": "Limit reached"}


def bangun_packet(ver: str) -> str:
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<packet version="{ver}">\n'
            "  <server>\n    <get_protos/>\n  </server>\n</packet>\n")


def header_auth(mode: str, login: str, secret: str) -> list:
    if mode == "header":
        return [("HTTP_AUTH_LOGIN", login), ("HTTP_AUTH_PASSWD", secret)]
    if mode == "basic":
        tok = base64.b64encode(f"{login}:{secret}".encode()).decode()
        return [("Authorization", f"Basic {tok}")]
    if mode == "key":
        return [("KEY", secret)]
    return []


def kirim(url, packet, hdrs, jar, timeout):
    """-> dict(status_http, ok, errcode, errtext, ringkas)."""
    req = urllib.request.Request(url, data=packet.encode("utf-8"), method="POST")
    req.add_header("Content-Type", "text/xml")
    req.add_header("HTTP_PRETTY_PRINT", "TRUE")
    req.add_header("User-Agent", "PleskApiClient/1.6.9.1")
    for k, v in hdrs:
        req.add_header(k, v)
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=__import__("ssl")._create_unverified_context()))
    try:
        r = opener.open(req, timeout=timeout)
        body = r.read(65536).decode("utf-8", "replace")
        code = r.status
    except urllib.error.HTTPError as e:
        body = e.read(65536).decode("utf-8", "replace")
        code = e.code
    except Exception as e:
        return {"status_http": 0, "ok": False, "errcode": "", "errtext": "",
                "ringkas": f"{type(e).__name__}: {e}", "transport": True}
    m = VER_RE.search(body)
    t = TEX_RE.search(body)
    return {"status_http": code, "ok": bool(OK_RE.search(body)),
            "errcode": m.group(1) if m else "",
            "errtext": (t.group(1).strip() if t else "")[:200],
            "ringkas": f"HTTP {code}", "transport": False}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="XML API Plesk - format resmi, pacing patuh doktrin, tanpa loop")
    ap.add_argument("--url", required=True,
                    help="endpoint, mis. https://host:8443/enterprise/control/agent.php")
    ap.add_argument("--scope", default=DEFAULT_SCOPE)
    ap.add_argument("--authorized", action="store_true",
                    help="nyatakan target punya izin tertulis DI LUAR scope.txt")
    ap.add_argument("--mode", choices=["probe", "creds"], default="probe")
    ap.add_argument("--auth", choices=["header", "basic", "key"], default="header",
                    help="cara kirim kredensial (default: header, gaya docs resmi)")
    ap.add_argument("--packet-version", default="1.6.9.1",
                    help="versi packet XML API (default 1.6.9.1)")
    ap.add_argument("--creds", default="", help="file user:pass (mode creds)")
    ap.add_argument("--i-know-what-i-do", action="store_true",
                    help="wajib utk mode creds (risiko lockout, §0 butir 6)")
    ap.add_argument("--login", default="admin")
    ap.add_argument("--key", default="", help="secret key (mode --auth key)")
    ap.add_argument("--delay", type=float, default=3.0,
                    help="jeda antar-request detik (floor 2.5, default 3.0)")
    ap.add_argument("--max", type=int, default=5,
                    help="batas KERAS percobaan kredensial (default 5, maks 50)")
    ap.add_argument("--repeat", type=int, default=1,
                    help=f"ulang seluruh rangkaian (default 1, maks {MAKS_REPEAT})")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--out", default="")
    a = ap.parse_args()

    jalur = scope_check(a.url, a.scope, a.authorized)
    print(f"[scope] {host_of(a.url)} -> {jalur}")

    if a.mode == "creds":
        if not a.i_know_what_i_do:
            sys.exit("[STOP] mode creds butuh --i-know-what-i-do (§0 butir 6: "
                     "brute-force wajib konfirmasi, risiko lockout).")
        if not a.creds:
            sys.exit("[STOP] mode creds butuh --creds FILE (baris user:pass).")
        p = pathlib.Path(a.creds)
        if not p.exists():
            sys.exit(f"[STOP] file creds tak ada: {a.creds}")
        daftar = [l.strip() for l in p.read_text(errors="replace").splitlines()
                  if l.strip() and not l.startswith("#")]
        if not daftar:
            sys.exit("[STOP] file creds kosong.")
        if len(daftar) > a.max:
            print(f"[i] {len(daftar)} baris, dipangkas ke batas --max={a.max}")
            daftar = daftar[:a.max]
    else:
        daftar = [None]

    if a.repeat < 1 or a.repeat > MAKS_REPEAT:
        sys.exit(f"[STOP] --repeat harus 1..{MAKS_REPEAT} (tak ada loop tanpa batas).")
    if a.max < 1 or a.max > 50:
        sys.exit("[STOP] --max harus 1..50.")
    jeda = max(a.delay, DASAR)
    if a.delay < DASAR:
        print(f"[!] --delay {a.delay}s di bawah floor doktrin -> dinaikkan ke {DASAR}s")

    packet0 = bangun_packet(a.packet_version)
    hasil = []
    blok_berturut = 0
    berhenti = None

    for putaran in range(a.repeat):
        for kred in daftar:
            if berhenti:
                break
            if kred is None:
                hdr = []
                label = "probe get_protos (tanpa kredensial)"
            else:
                u, _, s = kred.partition(":")
                if not s:
                    print(f"[lewati] format salah (butuh user:pass): {kred[:30]}")
                    continue
                hdr = header_auth(a.auth, u, s)
                label = f"{a.auth} {u}:{'*'*len(s)}"

            r = kirim(a.url, packet0, hdr, http.cookiejar.CookieJar(), a.timeout)
            r["percobaan"] = label
            r["putaran"] = putaran + 1
            hasil.append(r)

            ec = r["errcode"]
            if ec in STOP_SEGERA:
                berhenti = f"errcode {ec}: {STOP_SEGERA[ec]}"
            elif ec in STOP_BLOKIR:
                berhenti = f"errcode {ec}: {STOP_BLOKIR[ec]}"
            elif r["status_http"] in (403, 429):
                blok_berturut += 1
                if blok_berturut >= 2:
                    berhenti = (f"2x BLOCK berturut (HTTP {r['status_http']}) -> "
                                f"PAUSE. Ini §0 butir 3: jangan spam retry.")
            elif r["transport"]:
                berhenti = f"gagal transport: {r['ringkas']}"
            else:
                blok_berturut = 0

            ket = f"HTTP {r['status_http']}"
            if ec:
                ket += f" errcode={ec}"
            if r["errtext"]:
                ket += f" {r['errtext'][:70]}"
            print(f"  [{len(hasil):>2}] {label:<34} {ket}")
            if r["ok"] and kred is not None:
                berhenti = ("kredensial VALID ditemukan -> BERHENTI. Lanjut "
                            "mencoba cuma menambah risiko lockout tanpa guna.")
                print(f"       -> AUTH OK (status=ok). {berhenti}")
            elif r["ok"]:
                print("       -> XML API hidup & versi packet didukung.")
            if berhenti:
                print(f"\n[STOP] {berhenti}")
                break
            if kred is not None or putaran < a.repeat - 1:
                time.sleep(jeda)

        if berhenti:
            break
        if putaran < a.repeat - 1:
            print(f"  [i] putaran {putaran+1} selesai -> jeda {jeda}s")
            time.sleep(jeda)

    sukses = [h for h in hasil if h["ok"]]
    kode = {}
    for h in hasil:
        if h["errcode"]:
            kode[h["errcode"]] = kode.get(h["errcode"], 0) + 1

    print(f"\n[ringkasan] permintaan={len(hasil)} ok={len(sukses)} "
          f"jeda={jeda}s errcode={kode or '-'}")
    if berhenti:
        print(f"[alasan berhenti] {berhenti}")
    if not sukses and kode.get("1001"):
        print("[i] 1001 = Authentication failed (sandi salah) -> METODE AUTH "
              "BENAR, cuma kredensialnya yang belum cocok.")
    if kode.get("1005"):
        print("[i] 1005 = versi packet tak didukung -> coba --packet-version 1.6.7.0")
    if kode.get("1029") or kode.get("1003"):
        print("[i] auth method tak dikenal -> coba --auth basic / --auth key")

    if a.out:
        pathlib.Path(a.out).write_text(json.dumps(
            {"url": a.url, "scope": jalur, "mode": a.mode, "auth": a.auth,
             "packet_version": a.packet_version, "jeda": jeda,
             "berhenti": berhenti, "rekap_errcode": kode,
             "jumlah_ok": len(sukses), "hasil": hasil},
            indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[OK] {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
