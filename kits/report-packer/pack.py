#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pack.py - rangkai output semua kit jadi SATU laporan gabungan.

Tiap kit menulis JSON dengan bentuk berbeda. Modul ini MENDETEKSI sumber
lewat kunci khas di dalam isi file (bukan nama file), lalu merangkumnya.

    python3 pack.py --in ~/recon_out --out report_out
    python3 pack.py --in a.json b.json --format json

Sumber dikenali: secret-scanner, elementor-scanner, hosting-tester,
wp-recon, gapps-kit/api_probe, osint-kzldx. Selain itu tampil generik.

CATATAN KEAMANAN: packer MENGULANG redaction. Kalau ada kit yang lupa
redact, nilai mirip secret dipotong lagi di sini (defense in depth).
"""
from __future__ import annotations

import argparse, json, pathlib, re, sys, time

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
RE_SECRET = re.compile(
    r"\bAIza[0-9A-Za-z_-]{35}\b|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    r"|\b(?:ghp|gho|ghs)_[A-Za-z0-9]{36}\b|\bBearer\s+[A-Za-z0-9_.-]{20,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I)


def redact_lagi(v):
    """Potong nilai yang masih memuat secret (jaga2 bila kit lupa redact)."""
    if isinstance(v, str) and RE_SECRET.search(v):
        return f"{v[:4]}..{v[-4:]} [len {len(v)}, REDACTED-ULANG]"
    return v


def tekan(o):
    """Terapkan redact_lagi rekursif ke seluruh struktur."""
    if isinstance(o, dict):
        return {k: tekan(v) for k, v in o.items()}
    if isinstance(o, list):
        return [tekan(v) for v in o]
    return redact_lagi(o)


def cari_json(paths):
    """Kumpulkan file .json; DEDUP berdasarkan path absolut supaya file yang
    dilewatkan lewat banyak path tidak dihitung dua kali."""
    out, seen = [], set()
    for p in paths:
        p = pathlib.Path(p)
        if p.is_file() and p.suffix.lower() == ".json":
            kandidat = [p]
        elif p.is_dir():
            kandidat = sorted(x for x in p.rglob("*.json") if x.is_file())
        else:
            kandidat = []
        for c in kandidat:
            kunci = str(c.resolve())
            if kunci not in seen:
                seen.add(kunci)
                out.append(c)
    return out


def deteksi(d):
    """Kenali sumber dari kunci khas -> (nama, ringkasan, daftar_temuan)."""
    if isinstance(d, dict):
        if isinstance(d.get("temuan"), list):
            n = d.get("jumlah", len(d["temuan"]))
            return ("secret-scanner", f"{n} temuan rahasia", d["temuan"])
        if "hits" in d and "slugs" in d:
            return ("elementor-scanner",
                    f"{len(d.get('hits', []))}/{len(d.get('slugs', []))} slug kena",
                    d.get("hits", []))
        if "sukses" in d and "detail" in d:
            return ("hosting-tester",
                    f"{d.get('sukses')}/{d.get('total')} sukses",
                    d.get("detail", []))
        if isinstance(d.get("plugin"), dict) and ("header" in d or "waf" in d):
            return ("wp-recon",
                    f"{len(d['plugin'])} plugin, {len(d.get('header', {}))} header",
                    [d])
        if isinstance(d.get("functions"), list) and "url" in d:
            return ("gapps-kit/api_probe",
                    f"{len(d['functions'])} fungsi terdaftar", d["functions"])
        if d and all(isinstance(v, dict) for v in d.values()):
            return ("osint-kzldx", f"{len(d)} sumber intel", [d])
    return ("lainnya", "format tidak dikenali", [d])


def jenisku_sev(o, temuan):
    """Kumpulkan severity apa pun yang ada di dalam temuan."""
    for t in temuan:
        if isinstance(t, dict):
            s = str(t.get("severity") or t.get("sev") or "").lower()
            if s in SEV:
                yield s
    return


def baris_kv(o, tingkat=0, L=None, maks=40):
    """Render dict generik jadi daftar key: value (untuk sumber tak dikenal)."""
    if L is None:
        L = []
    if isinstance(o, dict):
        for k, v in list(o.items())[:maks]:
            if isinstance(v, (dict, list)):
                L.append("  " * tingkat + f"- **{k}**")
                baris_kv(v, tingkat + 1, L, maks)
            else:
                L.append("  " * tingkat + f"- {k}: `{v}`")
    elif isinstance(o, list):
        for v in o[:maks]:
            if isinstance(v, (dict, list)):
                baris_kv(v, tingkat, L, maks)
            else:
                L.append("  " * tingkat + f"- `{v}`")
    return L


def main():
    ap = argparse.ArgumentParser(description="rangkai output kit jadi laporan")
    ap.add_argument("--in", dest="inp", nargs="+", required=True,
                    help="file .json dan/atau folder (rekursif)")
    ap.add_argument("--out", default="report_out")
    ap.add_argument("--format", choices=["md", "json", "both"], default="both")
    ap.add_argument("--judul", default="Laporan gabungan toolkit")
    ap.add_argument("--target", default="", help="nama target (opsional)")
    a = ap.parse_args()

    files = cari_json(a.inp)
    if not files:
        sys.exit("[STOP] tidak ada file .json yang ketemu")

    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    paket, gagal = [], []
    for p in files:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            gagal.append(f"{p}: {e}")
            continue
        kit, ringkas, temuan = deteksi(d)
        paket.append({
            "file": str(p), "kit": kit, "ringkas": ringkas,
            "mtime": p.stat().st_mtime,
            "temuan": tekan(temuan), "mentah": tekan(d),
        })

    # rekap per kit
    rekap = {}
    for x in paket:
        r = rekap.setdefault(x["kit"], {"n": 0, "sev": {}, "file": []})
        r["n"] += 1
        r["file"].append(x["file"])
        for s in jenisku_sev(x["mentah"], x["temuan"]):
            r["sev"][s] = r["sev"].get(s, 0) + 1

    d_out = pathlib.Path(a.out or ".") / ("laporan_" + time.strftime("%Y%m%d-%H%M%S"))
    d_out.mkdir(parents=True, exist_ok=True)

    gabung = {
        "dibuat": ts, "judul": a.judul, "target": a.target,
        "jumlah_file": len(paket), "gagal_dibaca": gagal,
        "rekap_per_kit": rekap,
        "paket": [{"file": x["file"], "kit": x["kit"],
                   "ringkas": x["ringkas"], "temuan": x["temuan"]} for x in paket],
    }

    if a.format in ("json", "both"):
        (d_out / "laporan.json").write_text(
            json.dumps(gabung, indent=2, ensure_ascii=False), encoding="utf-8")

    if a.format in ("md", "both"):
        L = [f"# {a.judul}", ""]
        if a.target:
            L += [f"**Target:** `{a.target}`  ", ""]
        L += [f"Dibuat: {ts} · {len(paket)} file JSON · {len(rekap)} sumber", ""]
        L += ["## Ringkasan per sumber", "", "| sumber | file | severity |",
              "|---|---|---|"]
        for kit in sorted(rekap):
            r = rekap[kit]
            sv = ", ".join(f"{k} {v}" for k, v in
                           sorted(r["sev"].items(), key=lambda x: SEV[x[0]])) or "-"
            L.append(f"| `{kit}` | {r['n']} | {sv} |")
        if rekap.get("lainnya"):
            L += ["", "> ada file berformat tak dikenali — cek seksi `lainnya`."]
        L += ["", "## Isi laporan", ""]
        for x in sorted(paket, key=lambda z: z["mtime"]):
            L += [f"### `{x['kit']}` — {x['ringkas']}", "",
                  f"Sumber: `{x['file']}`", ""]
            L += baris_kv(x["temuan"]) or ["_(kosong)_"]
            L.append("")
        if gagal:
            L += ["## Gagal dibaca", ""] + [f"- `{g}`" for g in gagal]
        (d_out / "laporan.md").write_text("\n".join(L) + "\n", encoding="utf-8")

    print(f"[*] {len(paket)} file dari {len(rekap)} sumber")
    for kit in sorted(rekap):
        print(f"    {rekap[kit]['n']:>3}  {kit}")
    if gagal:
        print(f"[!] {len(gagal)} file gagal dibaca")
    print(f"[OK] {d_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
