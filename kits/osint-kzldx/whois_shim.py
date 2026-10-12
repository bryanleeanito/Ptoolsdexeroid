#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""whois_shim — fallback whois Py3.14-safe (integrasi Dev GreyHat, 2026-10-05).

Dipakai osint.py.mod_whois saat `import whois` / `_w.whois()` gagal.
Engine: binari `whois` sistem (port-43) via subprocess — tanpa paket pip.
Kompatibel panggilan: `whois(dom)` → objek dengan `.get(k, default)`.
"""
from __future__ import annotations

import shutil
import subprocess


class WhoisResult(dict):
    def get(self, k, default=""):  # type: ignore[override]
        return dict.get(self, k, default)


def whois(domain: str) -> WhoisResult:
    res = WhoisResult(domain=domain)
    exe = shutil.which("whois")
    if not exe:
        return res  # kosong → pemanggil lanjut ke fallback berikutnya
    try:
        r = subprocess.run(
            [exe, domain],
            capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace",
        )
        raw = r.stdout or ""
    except (subprocess.TimeoutExpired, OSError):
        return res
    res["raw"] = raw[:8000]
    if len(raw) < 100:
        return res

    for line in raw.splitlines():
        if ":" not in line or line.startswith("%") or line.startswith(">>>"):
            continue
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if not v:
            continue
        if k == "registrar" and not res.get("registrar"):
            res["registrar"] = v
        elif k in ("org", "organisation", "organization") and not res.get("org"):
            res["org"] = v
        elif k in ("name", "registrant name") and not res.get("name"):
            res["name"] = v
        elif k == "country" and not res.get("country"):
            res["country"] = v
        elif "creation date" in k or k == "created":
            res.setdefault("creation_date", v)
        elif "expiration date" in k or "registrar registration expiration" in k:
            res.setdefault("expiration_date", v)
        elif "updated date" in k or k == "updated":
            res.setdefault("updated", v)
        elif k in ("name server", "nserver", "nameserver"):
            ns = v.lower().split()[0].rstrip(".")
            lst = res.setdefault("name_servers", [])
            if ns and ns not in lst:
                lst.append(ns)
        elif k in ("domain status", "status"):
            lst = res.setdefault("status", [])
            if v not in lst:
                lst.append(v)
        elif k in ("email", "e-mail") and "@" in v:
            lst = res.setdefault("emails", [])
            if v not in lst:
                lst.append(v)
    return res


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python whois_shim.py <domain>")
        raise SystemExit(2)
    r = whois(sys.argv[1])
    for k, v in r.items():
        print(f"{k}: {v}")
