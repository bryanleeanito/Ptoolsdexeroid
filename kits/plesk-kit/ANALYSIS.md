# Plesk 18.0.80 — Analisis CVE (rentang Update)
Tanggal: 2026-10-13 · DB: kits/plesk-kit/advisories_plesk.json (skrip juga jalan dari /root/data/pentest/)

## Fakta format (mencegah false positive)
- `plesk -v` menghasilkan **4 field**: `Product version: Plesk Obsidian 18.0.65.2`
- Build `1800260925.18` = `18.0` + tanggal `2026-09-25` + rev 18.
  **Nomor Update (`.80`, `.9`) TIDAK ada di build number.**
  -> `--build` tanpa `--version` = STOP (jangan menebak).
- Tanggal build 2026-09-25 cocok dgn changelog "18.0.80 Update 9 — 29 Sep 2026",
  jadi versi riil kemungkinan `18.0.80.9` — TAPI belum dikonfirmasi `plesk -v`.
- Dampak: `18.0.80.0` = 7 CVE kondisional terbuka; `18.0.80.9` = 0. Selisih 7x.

## Tangga ambang patch (rentang 18.0.80.0 .. 18.0.80.9)
| Ambang | CVE | Sev | Jenis |
|---|---|---|---|
| < 1 | CVE-2026-64636 | high | SQLi panel DB (inferensi) |
| < 1 | CVE-2026-64637 | critical | XML-RPC reseller -> session root |
| < 2 | CVE-2026-64639 | critical | DB cloning -> RCE |
| < 4 | CVE-2026-65642 | high | IDOR db pelanggan lain |
| < 5 | CVE-2026-67394 | critical | LPE OS command injection |
| < 6 | CVE-2026-67397 | critical | Path traversal -> root |
| < 7 | CVE-2026-68488 | critical | Backup Manager TOCTOU -> root |

**Jika Update >= 7: ketujuhnya sudah PATCHED.** Sisa: 1 placeholder (fix critical di 18.0.81)
+ 5 CVE yang sumbernya belum menyebut rentang (DATA_KURANG).

## Sudah PATCHED di 18.0.80 (jangan dilaporkan)
- CVE-2026-48614 (XML API -> file write root, fix 18.0.78)
- CVE-2026-58046 (blind SQLi XML-RPC, fix 18.0.79.4)
- CVE-2025-65518 (DoS get_password.php, fix 18.0.73)
- CVE-2026-42945 (nginx rewrite module; nginx bundel 1.30.5 > rentang 1.30.0) — komponen

## Kesalahan kueri awal (sudah dikoreksi via NVD)
Aggregator AI (OpenCVE/Strix) **saling bertentangan**. Tertangkap NVD:
- `CVE-2026-44962` = XPath injection di APS Application Catalog (BUKAN database cloning)
- `CVE-2026-64639` = incorrect database cloning, fix 18.0.80.2 (bukan IDOR/18.0.80.4)
- `CVE-2026-65642` = IDOR "18.0.80 through 18.0.80.3" (bukan symlink)
- "XML API file write root" = `CVE-2026-48614`, bukan 64636/64637

Aturan yang dipakai sekarang: **NVD utk deskripsi, KB Plesk utk rentang patch,
aggregator AI hanya pelengkap.**

## Error code Plesk (bukan rate limit!)
`1001` auth gagal · `1005` versi tak didukung · `1006` permission denied ·
**`1010` Access to Plesk Panel denied** · `1011` account disabled ·
`1012` locked login · `1014` XML rusak · `1024` limit reached · `1029` auth method tak dikenal
-> `1010` = IP/akses ditolak (cek `panel.ini [api] enabled`, whitelist IP).
   **Menunggu lalu retry TIDAK menyelesaikannya.**

## Tool
```
cd kits/plesk-kit
python3 cve.py --version 18.0.80 --sweep 0-9 --db advisories_plesk.json
python3 cve.py --version 18.0.80.9 --db advisories_plesk.json
python3 api.py --url https://HOST:8443/enterprise/control/agent.php
python3 spec.py --in spec.json
```
