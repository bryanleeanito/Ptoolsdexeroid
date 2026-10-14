#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe.py — analisa file forensik CTF (offline, stdlib-only).
Identifikasi magic, strings + grep flag, chunk PNG, EXIF JPEG dasar,
data tersembunyi setelah EOF, entropi, list ZIP/PDF.

    python3 probe.py challenge.png
    python3 probe.py dump.bin --strings
    python3 probe.py *.jpg --all
"""
import argparse, json, math, pathlib, re, struct, sys, zipfile
from collections import Counter

FLAG_RX = re.compile(rb"(?:flag|ctf|dexero|picoctf|hack|htb)\s*[{(][A-Za-z0-9_!@#$%^&*+\-=:. /]{3,120}[})]", re.I)
MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "PNG"), (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF87a"), (b"GIF89a", "GIF89a"),
    (b"PK\x03\x04", "ZIP/DOCX/APK"), (b"%PDF", "PDF"),
    (b"\x7fELF", "ELF"), (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7z"), (b"BZh", "BZ2"),
    (b"\x1f\x8b", "GZ"), (b"RIFF", "RIFF(WAV/AVI)"),
    (b"ID3", "MP3"), (b"\x00\x00\x01\xba", "MPEG"),
    (b"BM", "BMP?"), (b"II*\x00", "TIFF-LE"), (b"MM\x00*", "TIFF-BE"),
    (b"SQLite format 3\x00", "SQLite"), (b"\xca\xfe\xba\xbe", "Java-class/FatBin"),
    (b"\x0a\x0d\x0d\x0a", "PCAPNG"), (b"d4\xc3\xb2\xa1", "PCAP-le"),
    (b"\x50\x4d\x4f\x43\x43\x4d\x4f\x43", "PMOCCMO"), (b"\xd0\xcf\x11\xe0", "OLE2/DOC"),
    (b"fLaC", "FLAC"), (b"OggS", "OGG"), (b"\x00\x00\x00\x0cftyp", "MP4"),
]


def entropi(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def strings_raw(b, minlen=4):
    out = []
    cur = bytearray()
    for ch in b:
        if 32 <= ch < 127:
            cur.append(ch)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii"))
    return out


def strings_utf16le(b, minlen=4):
    out, cur = [], []
    for i in range(0, len(b) - 1, 2):
        ch = b[i] + (b[i + 1] << 8)
        if 32 <= ch < 127 and b[i + 1] == 0:
            cur.append(chr(ch))
        else:
            if len(cur) >= minlen:
                out.append("".join(cur))
            cur = []
    if len(cur) >= minlen:
        out.append("".join(cur))
    return out


def scan_flag(b, label):
    temuan = [m.group(0).decode("latin-1", "replace") for m in FLAG_RX.finditer(b)]
    if temuan:
        print(f"  [!!! FLAG via {label}]")
        for f in set(temuan):
            print(f"    {f}")
    return temuan


def analisa_png(b, detail):
    pos, chunks = 8, []
    texts = []
    while pos + 8 <= len(b):
        ln = struct.unpack(">I", b[pos:pos + 4])[0]
        typ = b[pos + 4:pos + 8]
        data = b[pos + 8:pos + 8 + ln]
        chunks.append((typ.decode("latin-1", "replace"), ln))
        if typ in (b"tEXt", b"zTXt", b"iTXt"):
            texts.append((typ.decode(), data[:200].decode("latin-1", "replace")))
        pos += 12 + ln
        if typ == b"IEND":
            if pos < len(b):
                print(f"  [!!!] {len(b) - pos} byte SETELAH IEND — data tersembunyi!")
                scan_flag(b[pos:], "after-IEND")
            break
    if detail:
        print("  chunks:", ", ".join(f"{t}({l})" for t, l in chunks[:20]))
    for t, v in texts:
        print(f"  [{t}] {v[:150]}")


def analisa_jpeg(b, detail):
    pos = 2
    while pos + 4 <= len(b):
        if b[pos] != 0xFF:
            break
        mkr = b[pos + 1]
        if mkr == 0xD9:
            if pos + 2 < len(b):
                print(f"  [!!!] {len(b) - pos - 2} byte SETELAH FFD9 — data tersembunyi!")
                scan_flag(b[pos + 2:], "after-FFD9")
            return
        if mkr in (0xD8, 0x01) or 0xD0 <= mkr <= 0xD7:
            pos += 2
            continue
        seglen = struct.unpack(">H", b[pos + 2:pos + 4])[0]
        seg = b[pos + 4:pos + 2 + seglen]
        if mkr == 0xE0:
            print(f"  [APP0] {seg[:4].decode('latin-1','replace')}")
        elif mkr == 0xE1 and seg.startswith(b"Exif"):
            print(f"  [EXIF] APP1 {seglen} byte")
            parse_exif_tiff(seg[6:])
        elif mkr == 0xFE:
            print(f"  [COM] {seg.decode('latin-1','replace')[:150]}")
        elif 0xE2 <= mkr <= 0xEF:
            print(f"  [APP{mkr-0xE0}] {seglen} byte")
        pos += 2 + seglen
    print("  [!] FFD9 tak ketemu — JPEG mungkin terpotong/ada pendahulu")


def parse_exif_tiff(t):
    if len(t) < 8:
        return
    endian = "<" if t[:2] == b"II" else ">"
    try:
        ifd_off = struct.unpack(endian + "I", t[4:8])[0]
        cnt = struct.unpack(endian + "H", t[ifd_off:ifd_off + 2])[0]
        tags = {0x010F: "Make", 0x0110: "Model", 0x0131: "Software",
                0x8298: "Copyright", 0x8769: "ExifIFD", 0x8825: "GPSIFD",
                0x013B: "Artist"}
        for i in range(cnt):
            e = ifd_off + 2 + i * 12
            tag, typ, num = struct.unpack(endian + "HHI", t[e:e + 8])
            if tag == 0x8825:
                print("    [!!! GPS IFD ADA — lokasi mungkin tertanam]")
            if tag in tags and tags[tag] not in ("ExifIFD", "GPSIFD"):
                if typ == 2:
                    off = struct.unpack(endian + "I", t[e + 8:e + 12])[0]
                    val = t[off:off + num].rstrip(b"\x00").decode("latin-1", "replace")
                    print(f"    {tags[tag]}: {val}")
    except Exception as ex:
        print(f"    (parse EXIF gagal: {ex})")


def analisa_gif(b, detail):
    pos = 13
    while pos < len(b):
        if b[pos] == 0x3B:  # trailer
            if pos + 1 < len(b):
                print(f"  [!!!] {len(b)-pos-1} byte SETELAH trailer GIF")
                scan_flag(b[pos+1:], "after-GIF")
            return
        if b[pos] == 0x21:  # extension
            lbl = b[pos+1]
            if lbl == 0xFE:  # comment
                p = pos + 2
                cm = bytearray()
                while p < len(b) and b[p] != 0:
                    ln = b[p]; cm += b[p+1:p+1+ln]; p += 1 + ln
                print(f"  [GIF-COMMENT] {cm.decode('latin-1','replace')[:150]}")
            pos += 2
            while pos < len(b) and b[pos] != 0:
                pos += 1 + b[pos]
            pos += 1
        elif b[pos] == 0x2C:  # image descriptor
            return  # cukup, sisa = data gambar
        else:
            return


def analisa_zip(b, detail):
    try:
        import io
        z = zipfile.ZipFile(io.BytesIO(b))
        enc = 0
        for i in z.infolist():
            flag = "ENKRIPSI" if i.flag_bits & 1 else ""
            if i.flag_bits & 1:
                enc += 1
            if detail or flag:
                print(f"  {i.filename}  {i.file_size}B  {flag}")
        cm = z.comment
        if cm:
            print(f"  [ZIP-COMMENT] {cm.decode('latin-1','replace')[:150]}")
            scan_flag(cm, "zip-comment")
        print(f"  [{len(z.infolist())} entri, {enc} terkunci]")
    except Exception as ex:
        print(f"  (zip gagal: {ex})")


def analisa_pdf(b, detail):
    teks = b[:200000]
    for pat, nama in [(b"/JavaScript", "JavaScript"), (b"/JS", "JS"),
                      (b"/OpenAction", "OpenAction"), (b"/Launch", "Launch"),
                      (b"/EmbeddedFile", "EmbeddedFile"),
                      (b"/Encrypt", "Encrypt")]:
        if pat in teks:
            print(f"  [PDF] marker {nama} ADA")
    m = re.search(rb"/Title\s*\(([^)]*)\)", teks)
    if m:
        print(f"  [PDF] Title: {m.group(1)[:100].decode('latin-1','replace')}")


def main():
    ap = argparse.ArgumentParser(description="analisa file forensik CTF")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--strings", action="store_true", help="cetak semua strings")
    ap.add_argument("--all", action="store_true", help="mode lengkap + detail")
    a = ap.parse_args()
    semua_flag = []
    for fp in a.files:
        p = pathlib.Path(fp)
        if not p.exists():
            print(f"[STOP] tak ada: {fp}")
            continue
        b = p.read_bytes()
        jenis = next((j for magic, j in MAGIC if b.startswith(magic)), "tak dikenal")
        print(f"\n══ {p.name} ══ {len(b)} byte | magic: {jenis} | entropi: {entropi(b):.2f}/8.0")
        if jenis == "PNG":
            analisa_png(b, a.all)
        elif jenis == "JPEG":
            analisa_jpeg(b, a.all)
        elif jenis.startswith("GIF"):
            analisa_gif(b, a.all)
        elif jenis.startswith("ZIP"):
            analisa_zip(b, a.all)
        elif jenis == "PDF":
            analisa_pdf(b, a.all)
        semua_flag += scan_flag(b, "raw")
        # entropi per blok — deteksi bagian terkompresi/terenkripsi di tengah file
        if a.all and len(b) > 4096:
            blok = len(b) // 16
            es = [entropi(b[i*blok:(i+1)*blok]) for i in range(16)]
            tinggi = [f"{e:.1f}" for e in es]
            print(f"  entropi/blok: {' '.join(tinggi)}")
        s = strings_raw(b)
        s16 = strings_utf16le(b)
        if a.strings:
            for x in s + s16:
                print(f"  s| {x[:150]}")
        for x in s + s16:
            semua_flag += scan_flag(x.encode("latin-1", "replace"), "strings")
    if semua_flag:
        print(f"\n[!!! TOTAL {len(set(semua_flag))} flag unik ditemukan]")
        return 0
    print("\n[i] tak ada pola flag — kalau soal minta password zip: cek README soal / strings aneh / EXIF")
    return 0


if __name__ == "__main__":
    sys.exit(main())
