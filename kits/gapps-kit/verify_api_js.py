#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_api_js.py — buktikan JS_ENUM/JS_CALL milik api_probe.py TANPA playwright.

Ambil potongan JS persis dari api_probe.py, jalankan di Node 26 dengan stub
`google.script.run` + `document`, lalu assert hasilnya. Ini yang bikin status
api_probe turun dari "belum teruji" jadi "logika teruji".
"""
import pathlib
import re
import subprocess
import sys
import tempfile

KIT = pathlib.Path(__file__).parent
PROBE = KIT / "api_probe.py"
MOCK = pathlib.Path("/tmp/opencode/mock_gscript.html")


def ambil(src: str, nama: str) -> str:
    m = re.search(rf'{nama}\s*=\s*r?"""(.*?)"""', src, re.S)
    if not m:
        sys.exit(f"[STOP] {nama} tidak ketemu di {PROBE}")
    return m.group(1)


def main() -> int:
    src = PROBE.read_text()
    js_enum = ambil(src, "JS_ENUM")
    js_call = ambil(src, "JS_CALL")
    if not MOCK.exists():
        sys.exit(f"[STOP] mock tidak ada: {MOCK}")

    harness = f"""
const fs = require('fs');
const html = fs.readFileSync({str(MOCK)!r}, 'utf8');
globalThis.document = {{ documentElement: {{ outerHTML: html }} }};

const DATA = {{
  getDataGuru: [{{ nama: 'Budi Santoso' }}, {{ nama: 'Siti' }}],
  getDataSiswa: ['9A'],
}};
let okCb = () => {{}}, errCb = () => {{}};
const api = {{
  withSuccessHandler(cb) {{ okCb = cb; return api; }},
  withFailureHandler(cb) {{ errCb = cb; return api; }},
}};
for (const n of ['getDataGuru','getDataSiswa','hapusRekam','simpanLog']) {{
  api[n] = function (a) {{ setTimeout(() => okCb({{ fn: n, arg: a, rows: DATA[n] }}), 5); return api; }};
}}
globalThis.google = {{ script: {{ run: api }} }};
globalThis.window = {{ google: globalThis.google }};

const JS_ENUM = ({js_enum});
const JS_CALL = ({js_call});

const found = JS_ENUM();
console.log('ENUM=' + JSON.stringify(found.sort()));

(async () => {{
  const ok = await JS_CALL(['getDataGuru', []]);
  console.log('CALL_OK=' + JSON.stringify(ok));

  const hilang = await JS_CALL(['fungsiYangTidakAda', []]);   // mock: tidak dipanggil okCb
  console.log('CALL_HILANG=' + JSON.stringify(hilang));
}})();
"""
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                     dir="/tmp/opencode") as f:
        f.write(harness)
        js = f.name
    r = subprocess.run(["node", js], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        print(r.stderr[:1200])
        return 2
    print(r.stdout.strip())

    baris = dict(x.split("=", 1) for x in r.stdout.strip().splitlines() if "=" in x)
    import json
    found = json.loads(baris["ENUM"])
    ok = json.loads(baris["CALL_OK"])
    gagal = json.loads(baris["CALL_HILANG"])

    cek = [
        ("4 fungsi server terdeteksi", len(found) == 4),
        ("getDataGuru & getDataSiswa ada",
         "getDataGuru" in found and "getDataSiswa" in found),
        ("properti bawaan dibuang",
         not any(x in found for x in ("withSuccessHandler", "withFailureHandler",
                                      "then", "catch"))),
        ("CALL sukses balikin data", ok.get("ok") is True
         and ok.get("data", {}).get("fn") == "getDataGuru"),
        ("fungsi tak dikenal → timeout/error, bukan crash",
         gagal.get("ok") is False),
    ]
    print()
    gagal_total = 0
    for label, lolos in cek:
        print(f"  {'[✓]' if lolos else '[✗]'} {label}")
        gagal_total += 0 if lolos else 1
    print(f"\n{'[✓] JS api_probe TERBUKTI' if not gagal_total else '[✗] ADA GAGAL'} "
          f"({len(cek)-gagal_total}/{len(cek)})")
    return 0 if not gagal_total else 1


if __name__ == "__main__":
    sys.exit(main())
