#!/usr/bin/env python3
"""O9 — Ekspor intel.json (OSINT by kzldx) → findings.jsonl.

Usage:
  python osint/patches/intel_to_findings.py --intel "Osint by kzldx/output/<run>/intel.json" --target example.sch.id
  python osint/patches/intel_to_findings.py --intel-dir "Osint by kzldx/output" --append findings/findings.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent


def _append_rows(path: str, rows: list) -> int:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return len(rows)


def findings_io_load(path: str) -> list:
    rows = []
    try:
        with Path(path).open("r", encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return rows

# intel.json pola umum: {source: {topic: [ {sev?, kerentanan?, teknik?, ...} ] }}
# atau list of dict. Kita fleksibel-parse.


def _iter_hits(obj, target: str):
    if isinstance(obj, list):
        for x in obj:
            yield from _iter_hits(x, target)
        return
    if not isinstance(obj, dict):
        return
    # bentuk: {topic: {...}} / {source: [hits]} / flat hit
    if any(k in obj for k in ("sev", "severity", "kerentanan", "vuln", "vuln", "title", "topik")):
        yield obj
        return
    for _k, v in obj.items():
        yield from _iter_hits(v, target)


_SEV_ALIAS = {"crit": "critical", "med": "medium", "hi": "high", "informational": "info"}


def _norm_sev(raw: str) -> str:
    s = str(raw or "info").lower()
    s = _SEV_ALIAS.get(s, s)
    return s if s in ("critical", "high", "medium", "low", "info") else "info"


def hit_to_finding(hit: dict, target: str, source: str) -> dict:
    sev = _norm_sev(hit.get("sev") or hit.get("severity") or "info")
    title = (
        hit.get("kerentanan")
        or hit.get("vuln")
        or hit.get("title")
        or hit.get("topik")
        or hit.get("topic")
        or "OSINT intel hit"
    )
    detail_parts = []
    for key in ("topik", "topic", "vuln", "kerentanan", "teknik", "mitigasi", "detail", "note"):
        if hit.get(key):
            detail_parts.append(f"**{key}:** {hit[key]}")
    return {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M WIB"),
        "severity": sev,
        "title": f"[osint-intel:{hit.get('source') or source}] {title}"[:300],
        "target": target,
        "detail": "\n".join(detail_parts)[:4000],
        "evidence": json.dumps(hit, ensure_ascii=False)[:2000],
        "vector": None,
    }


def load_intel(path: Path) -> dict | list:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def convert(path: Path, target: str) -> list[dict]:
    data = load_intel(path)
    out: list[dict] = []
    # source top-level bila dict of source→...
    sources: dict[str, object]
    if isinstance(data, dict):
        sources = data
    else:
        sources = {"list": data}
    for source, body in sources.items():
        for hit in _iter_hits(body, target):
            out.append(hit_to_finding(hit, target, str(source)))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--intel", default="", help="satu file intel.json")
    ap.add_argument("--intel-dir", default=str(BASE / "output"), help="scan **/intel.json (default: output/)")
    ap.add_argument("--target", default="", help="override target (default: infer)")
    ap.add_argument("--append", default="", help="findings.jsonl tujuan")
    ap.add_argument("--dedupe", action="store_true",
                    help="lewati (target,judul) yang sudah ada di file --append")
    args = ap.parse_args(argv)

    files: list[Path] = []
    if args.intel:
        files.append(Path(args.intel))
    if args.intel_dir:
        files.extend(Path(args.intel_dir).glob("**/intel.json"))
    if not files:
        print("butuh --intel atau --intel-dir", file=sys.stderr)
        return 2

    seen: set[tuple] = set()
    if args.dedupe and args.append and Path(args.append).exists():
        for r in findings_io_load(args.append):
            seen.add((r.get("target"), r.get("title")))

    all_rows: list[dict] = []
    for fp in files:
        # infer target dari nama folder run: <host>_<ts>
        name = fp.parent.name
        infer = name.rsplit("_", 1)[0] if "_" in name else name
        if args.target and infer.lower() != args.target.lower().strip():
            continue  # filter: hanya run milik target ini
        tgt = args.target or infer
        try:
            all_rows.extend(convert(fp, tgt))
        except (json.JSONDecodeError, OSError) as e:
            print(f"skip {fp}: {e}", file=sys.stderr)

    if seen:
        fresh = [r for r in all_rows if (r.get("target"), r.get("title")) not in seen]
        dup = len(all_rows) - len(fresh)
        if dup:
            print(f"dedupe: {dup} duplikat dilewati")
        all_rows = fresh

    if args.append:
        n = _append_rows(args.append, all_rows)
        print(f"OK append {n} findings → {args.append}")
    else:
        for r in all_rows:
            print(json.dumps(r, ensure_ascii=False))
    return 0 if all_rows else 1


if __name__ == "__main__":
    raise SystemExit(main())

