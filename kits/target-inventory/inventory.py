#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""inventory.py - katalog target + generator scope.txt (fail-closed).

scope.txt adalah BUILD ARTIFACT yang di-generate, bukan file yang diedit
tangan. Sumber kebenaran = targets.json. Ini mencegah scope.txt nyasar dari
catatan izin yang sebenarnya.

    python3 inventory.py --add-host x.sch.id --izin tertulis \\
        --tanggal-izin 2026-10-13 --bukti "Authoritation.txt baris 3"
    python3 inventory.py --list
    python3 inventory.py --emit-scope
    python3 inventory.py --check https://x.sch.id/login
    python3 inventory.py --validate /root/data/Auth/scope.txt

Aturan yang dipegang INI sama persis dengan kit_common.scope_check():
  * 1 host per baris, hanya token pertama yang dipakai
  * '#' = komentar, baris kosong diabaikan
  * '!' di depan = blocklist (SELALU menang atas allowlist)
  * '*.domain' cocokkan domain itu + seluruh subdomain
  * pembandingan case-insensitive
  * file tak terbaca = FAIL-CLOSED -> semua kit modul aktif berhenti

Hanya target ber-izin 'tertulis' yang dibuang ke scope.txt. Target 'pending'
atau 'ditarik' TIDAK pernah masuk - ini bagian dari gate fail-closed.
"""
from __future__ import annotations

import argparse, json, pathlib, sys, time

IZIN_VALID = ("tertulis", "lisan", "pending", "ditarik")
SCOPENYA = "/root/data/Auth/scope.txt"


def baca_inv(p: pathlib.Path) -> dict:
    if not p.exists():
        return {"targets": []}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        d.setdefault("targets", [])
        return d
    except Exception as e:
        sys.exit(f"[STOP] targets.json rusak: {e}")


def tulis_inv(p: pathlib.Path, d: dict) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)


# --- semantik yang sama dengan kit_common (jangan diubah sembarangan) ---
def host_of(url: str) -> str:
    import urllib.parse
    if "://" in url:
        return urllib.parse.urlparse(url).netloc.lower().split(":")[0]
    return url.split("/")[0].lower().rstrip("/")


def cocok(h: str, pat: str) -> bool:
    pat = pat.lower()
    if pat.startswith("*."):
        return h == pat[2:] or h.endswith("." + pat[2:])
    return h == pat


def emit_scope(targets):
    """Bangun isi scope.txt. Hanya izin 'tertulis' + aktif yang keluar."""
    baris = [
        "# scope.txt - DIGENERATE oleh target-inventory, JANGAN diedit tangan.",
        "# Sumber kebenaran: targets.json. Regenerate: inventory.py --emit-scope",
        f"# digenerate: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    n = 0
    for t in targets:
        if not t.get("aktif", True):
            baris.append(f"# DILEWAT (nonaktif): {t.get('host')}")
            continue
        if t.get("izin") != "tertulis":
            baris.append(f"# DILEWAT (izin={t.get('izin')}): {t.get('host')}")
            continue
        for b in t.get("blok", []):
            baris.append(f"!{b}")
        baris.append(t["host"])
        n += 1
        for a in t.get("alias", []):
            baris.append(a)
    baris.append("")
    return baris, n


def parse_scope(baris: list):
    allow, block = [], []
    for b in baris:
        b = b.strip()
        if not b or b.startswith("#"):
            continue
        host = b.split()[0]
        (block if host.startswith("!") else allow).append(host.lstrip("!").lower())
    return allow, block


def cek_host(h: str, allow: list, block: list) -> str:
    for p in block:
        if cocok(h, p):
            return f"BLOCK (rule !{p})"
    if any(cocok(h, p) for p in allow):
        return "DALAM SCOPE"
    return "LUAR SCOPE"


def main():
    ap = argparse.ArgumentParser(description="katalog target + generator scope.txt")
    ap.add_argument("--inv", default="/root/data/Auth/targets.json",
                    help="path inventaris (sumber kebenaran)")
    ap.add_argument("--scope", default=SCOPENYA, help="path scope.txt tujuan")
    ap.add_argument("--add-host", help="tambah/ubah target: host (boleh *.domain)")
    ap.add_argument("--izin", choices=IZIN_VALID, help="status izin")
    ap.add_argument("--tanggal-izin", default="", help="tanggal izin (YYYY-MM-DD)")
    ap.add_argument("--bukti", default="", help="rujukan bukti izin, mis. 'Auth.txt baris 3'")
    ap.add_argument("--catatan", default="")
    ap.add_argument("--alias", default="", help="alias dipisah koma")
    ap.add_argument("--blok", default="", help="blocklist spesifik dipisah koma")
    ap.add_argument("--nonaktif", action="store_true", help="tandai target nonaktif")
    ap.add_argument("--list", action="store_true", help="tampilkan tabel inventaris")
    ap.add_argument("--emit-scope", action="store_true", help="generate scope.txt")
    ap.add_argument("--check", help="dry-run: host/url ini masuk scope?")
    ap.add_argument("--validate", help="lint file scope.txt yang sudah ada")
    a = ap.parse_args()

    inv = pathlib.Path(a.inv)

    # ---- ADD / UPDATE ----
    if a.add_host:
        d = baca_inv(inv)
        h = host_of(a.add_host)
        t = next((x for x in d["targets"] if x["host"] == h), None)
        if t is None:
            t = {"host": h, "aktif": True, "izin": "pending"}
            d["targets"].append(t)
            aksi = "TAMBAH"
        else:
            aksi = "UBAH"
        if a.izin:
            t["izin"] = a.izin
        if a.tanggal_izin:
            t["tanggal_izin"] = a.tanggal_izin
        if a.bukti:
            t["bukti"] = a.bukti
        if a.catatan:
            t["catatan"] = a.catatan
        if a.alias:
            t["alias"] = [x.strip() for x in a.alias.split(",") if x.strip()]
        if a.blok:
            t["blok"] = [x.strip() for x in a.blok.split(",") if x.strip()]
        if a.nonaktif:
            t["aktif"] = False
        t["diperbarui"] = time.strftime("%Y-%m-%d %H:%M:%S")
        tulis_inv(inv, d)
        print(f"[OK] {aksi} {h} (izin={t.get('izin')}) -> {inv}")
        if t.get("izin") != "tertulis":
            print(f"[!] izin '{t.get('izin')}' -> TIDAK akan masuk scope.txt")
        return 0

    # ---- LIST ----
    if a.list:
        d = baca_inv(inv)
        if not d["targets"]:
            print("[i] inventaris kosong. Tambah: --add-host <host> --izin <status>")
            return 0
        print(f"{'HOST':<28} {'IZIN':<10} {'TANGGAL':<12} {'AKTIF':<6} BUKTI")
        print("-" * 90)
        for t in sorted(d["targets"], key=lambda x: x["host"]):
            print(f"{t['host']:<28} {t.get('izin','-'):<10} "
                  f"{t.get('tanggal_izin','-'):<12} "
                  f"{'ya' if t.get('aktif', True) else 'tidak':<6} "
                  f"{t.get('bukti','-')}")
        siap = [t for t in d["targets"] if t.get("izin") == "tertulis" and t.get("aktif", True)]
        print(f"\n{len(siap)}/{len(d['targets'])} target siap masuk scope.txt")
        return 0

    # ---- EMIT SCOPE ----
    if a.emit_scope:
        d = baca_inv(inv)
        baris, n = emit_scope(d["targets"])
        p = pathlib.Path(a.scope)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("\n".join(baris), encoding="utf-8")
        print(f"[OK] scope.txt -> {p} ({n} host allowlist)")
        if n == 0:
            print("[!] 0 host! Semua kit modul aktif akan FAIL-CLOSED sampai ada "
                  "target berizin tertulis.")
        else:
            print("[i] ingat: --authorized di kit akan MENYINGKIR allowlist ini.")
        return 0

    # ---- CHECK (dry-run) ----
    if a.check:
        if not pathlib.Path(a.scope).exists():
            sys.exit(f"[STOP] scope.txt tak terbaca ({a.scope}) -> fail-closed")
        allow, block = parse_scope(pathlib.Path(a.scope).read_text(
            errors="replace").splitlines())
        h = host_of(a.check)
        hasil = cek_host(h, allow, block)
        print(f"{h} -> {hasil}")
        return 0 if hasil == "DALAM SCOPE" else 1

    # ---- VALIDATE ----
    if a.validate:
        p = pathlib.Path(a.validate)
        if not p.exists():
            sys.exit(f"[STOP] {p} tidak ada -> semua kit modul aktif akan berhenti")
        teks = p.read_text(errors="replace")
        allow, block = parse_scope(teks.splitlines())
        # NB: periksa BARIS MENTAH, bukan allow/block - yang sudah dinormalkan
        # parse_scope (split()[0] + lower), jadi spasi/kapital tak akan terlihat.
        masalah = []
        dilihat = set()
        for nomor, raw in enumerate(teks.splitlines(), 1):
            b = raw.strip()
            if not b or b.startswith("#"):
                continue
            bagian = b.split()
            token = bagian[0]
            if len(bagian) > 1:
                masalah.append(f"baris {nomor}: '{b}' >1 token - cuma '{token}' yang dipakai")
            if token != token.lower():
                masalah.append(f"baris {nomor}: '{token}' berhuruf besar - akan jadi '{token.lower()}'")
            if token in dilihat:
                masalah.append(f"baris {nomor}: '{token}' duplikat")
            dilihat.add(token)
            if token == "!":
                masalah.append(f"baris {nomor}: '!' tanpa host (akan jadi blocklist kosong)")
        wild = [x for x in allow if x.startswith("*.")]
        print(f"[OK] {p}")
        print(f"     allowlist : {len(allow)}   blocklist : {len(block)}   wildcard: {len(wild)}")
        for w in wild:
            print(f"     wildcard  : {w} -> mencakup subdomain")
        if masalah:
            print(f"[!] {len(masalah)} masalah:")
            for m in masalah:
                print("     -", m)
        return 1 if masalah else 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
