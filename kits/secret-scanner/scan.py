#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan.py - cari secret / credential ter-hardcode di hasil dump.
Input: file atau folder rekursif (hasil probe/gviz_fetch/deobfuscate/log).
  Redact by default - fail-safe on binary - tanpa jaringan.
    python3 scan.py --in recon_out/ --out scan_out
    python3 scan.py --in dump.js --show --i-know
"""
import argparse, json, pathlib, re, sys, time

POLA = [
 ("private-key","Private key",r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----","critical","kunci privat"),
 ("aws-key","AWS Access Key",r"\b(?:AKIA|ASIA|ABIA)[0-9A-Z]{16}\b","high","kunci AWS"),
 ("gh-token","GitHub token",r"\b(?:ghp|gho|ghs)_[A-Za-z0-9]{36}\b","high","token GitHub"),
 ("gapi-key","Google API key",r"\bAIza[0-9A-Za-z_-]{35}\b","high","API key Google"),
 ("url-auth","URL kredensial",r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s:@]+@\S+","high","user:pass di URL"),
 ("bearer","Bearer token",r"\bBearer\s+([A-Za-z0-9_.-]{20,})","high","token bearer"),
 ("sheet-id","Google Sheet ID",r"/spreadsheets/d/([A-Za-z0-9_-]{25,})","medium","pintu gviz"),
 ("gas-id","GAS script ID",r"/macros/s/(AKfycb[A-Za-z0-9_-]{20,})","medium","ID eksekusi GAS"),
 ("jwt","JWT",r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b","medium","JWT terekspos"),
 ("cred","Credential hardcode",r"\b(?:password|passwd|pwd|secret|api_?key|token)\b\s*[:=]\s*[\"']?([^\"'\s;,)]{4,})","medium","nilai di kode/CSV"),
]
BUKAN={"true","false","null","undefined","none","nil","string","number","boolean","object","function","required","password","secret","token","apikey","hidden","text","empty","example","placeholder","changeme","********","masked"}
SEV={"critical":0,"high":1,"medium":2,"low":3}
TXT={".html",".htm",".js",".json",".csv",".txt",".xml",".md",".log",".env",".yml",".py",".sh",".php",".css",".ini",".conf",".sql"}

def redact(v):
    v=v.strip()
    return ("*"*len(v)) if len(v)<=6 else f"{v[:4]}..{v[-4:]} (len {len(v)})"

def baca(p):
    try: b=p.read_bytes()
    except Exception: return None
    if len(b)>8_000_000 or b"\x00" in b[:8192]: return None
    for e in ("utf-8","latin-1"):
        try: return b.decode(e)
        except Exception: pass
    return None

def main():
    ap=argparse.ArgumentParser(description="cari secret ter-hardcode di dump")
    ap.add_argument("--in",dest="inp",required=True)
    ap.add_argument("--out",default="scan_out")
    ap.add_argument("--ext",default="")
    ap.add_argument("--min-severity",choices=["critical","high","medium","low"],default="low")
    ap.add_argument("--show",action="store_true")
    ap.add_argument("--i-know",dest="iknow",action="store_true")
    a=ap.parse_args()
    if a.show and not a.iknow:
        print("[!] --show tanpa --i-know -> nilai tetap di-redact"); a.show=False
    show=a.show
    inp=pathlib.Path(a.inp)
    if not inp.exists(): sys.exit(f"[STOP] input tak ada: {a.inp}")
    ext={e if e.startswith(".") else "."+e for e in a.ext.replace(" ","").split(",") if e} if a.ext else TXT
    files=[inp] if inp.is_file() else [p for p in sorted(inp.rglob("*")) if p.is_file() and not p.name.startswith(".") and p.suffix.lower() in ext]
    if not files: sys.exit("[STOP] tak ada file yang cocok")
    print(f"[*] memindai {len(files)} file dari {inp}")
    d=pathlib.Path(a.out or ".")/("scan_"+time.strftime("%Y%m%d-%H%M%S")); d.mkdir(parents=True,exist_ok=True)
    rx=[(i,n,re.compile(p,re.I),s) for i,n,p,s,_ in POLA]
    semua=[]; gagal=[]
    for p in files:
        t=baca(p)
        if t is None: gagal.append(str(p)); continue
        for ln,baris in enumerate(t.splitlines(),1):
            for i,n,r,s in rx:
                for m in r.finditer(baris):
                    val=next((g for g in m.groups() if g),m.group(0))
                    if i=="cred" and val.lower() in BUKAN: continue
                    semua.append({"pola":i,"nama":n,"severity":s,"file":str(p),"baris":ln,"nilai":val if show else None,"cuplik":redact(val)})
    amb=SEV[a.min_severity]
    semua=[t for t in semua if SEV[t["severity"]]<=amb]
    semua.sort(key=lambda t:(SEV[t["severity"]],t["file"],t["baris"]))
    if not semua:
        print("[OK] bersih - tak ada secret terdeteksi")
        if gagal: print(f"    ({len(gagal)} file binary dilewati)")
        return 0
    rekap={}
    for t in semua: rekap[t["nama"]]=rekap.get(t["nama"],0)+1
    print("\n[ditemukan]")
    for n,k in sorted(rekap.items(),key=lambda x:-x[1]): print(f"  {k:>4}  {n}")
    with open(d/"secrets.json","w") as f:
        json.dump({"input":str(inp),"jumlah":len(semua),"dilewati_binary":gagal,"temuan":semua},f,indent=2,ensure_ascii=False); f.flush()
    L=["# Laporan secret-scan","",f"Input: {inp} - {len(semua)} temuan","","| severity | file:baris | jenis | nilai |","|---|---|---|---|"]
    for t in semua:
        v=t["nilai"] or t["cuplik"]
        L.append(f"| {t['severity']} | {t['file']}:{t['baris']} | {t['nama']} | {v} |")
    if gagal: L+=["",f"_Dilewati (binary): {len(gagal)} file_"]
    (d/"report.md").write_text("\n".join(L)+"\n")
    print(f"\n[OK] {d/'secrets.json'}"); print(f"[OK] {d/'report.md'}")
    if not show: print("[i] nilai di-redact. Pakai --show --i-know untuk lihat aslinya.")
    return 0

if __name__=="__main__":
    sys.exit(main())
