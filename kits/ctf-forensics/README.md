# ctf-forensics — analisa file offline (stdlib-only)

Identifikasi magic (40+ format), entropi total + per-blok, strings ASCII/UTF-16LE
+ grep pola flag, lalu parser khusus:

- **PNG**: chunk walk, tEXt/zTXt/iTXt dump, **data setelah IEND**
- **JPEG**: APP0-APP15, EXIF dasar (Make/Model/Software/**deteksi GPS IFD**),
  comment, **data setelah FFD9**
- **GIF**: comment extension, **data setelah trailer**
- **ZIP**: list entri, entri terkunci, comment
- **PDF**: marker berbahaya (/JavaScript, /OpenAction, /Launch, /EmbeddedFile)

```bash
python3 probe.py challenge.png --all       # PNG lengkap + entropi/blok
python3 probe.py foto.jpg                  # EXIF + hidden data
python3 probe.py dump.bin --strings        # strings penuh
python3 probe.py a.png b.jpg c.zip         # batch
```

Verifikasi lokal: PNG after-IEND ✓ tEXt ✓ ZIP comment ✓
