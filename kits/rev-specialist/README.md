# rev-specialist v1.0

Reverse engineering specialist toolbox — Ghidra script gen, binary patcher, protocol analyzer, decompiler helper, anti-analysis detector.

## Perintah

```bash
# Ghidra
python3 rev_specialist.py ghidra --binary target --output script.java

# Patch
python3 rev_specialist.py patch --binary target --offset 0x400500 --type nop --len 16
python3 rev_specialist.py patch --binary target --offset 0x400500 --type jump --target 0x401000
python3 rev_specialist.py patch --binary target --offset 0x400500 --type shellcode --target-file shell.bin

# Protocol
python3 rev_specialist.py protocol --file capture.bin --fields "4s,I,H"

# Decompile
python3 rev_specialist.py decompile --binary target --function main

# Anti-analysis
python3 rev_specialist.py anti --binary target
```

## Fitur

| Fitur | Fungsi |
|---|---|
| `ghidra` | Generate Ghidra script (auto-analysis + string + crypto constant) |
| `patch` | NOP sled, JMP rel32, shellcode inject (auto-backup) |
| `protocol` | Hex dump + field extraction (4s, 8s, 16s, I, H, B) |
| `decompile` | Command helper untuk Ghidra/r2/objdump/strings |
| `anti` | Detect anti-debug, anti-VM, packer, crypto strings |

## Patch Types

| Type | Keterangan |
|---|---|
| `nop` | NOP sled (0x90) |
| `jump` | JMP rel32 (E9) — butuh --target |
| `shellcode` | Inject dari file — butuh --target-file |

## Protocol Fields

| Field | Size | Format |
|---|---|---|
| `4s` | 4 bytes | Raw bytes |
| `8s` | 8 bytes | Raw bytes |
| `16s` | 16 bytes | Raw bytes |
| `I` | 4 bytes | uint32 LE |
| `H` | 2 bytes | uint16 LE |
| `B` | 1 byte | uint8 |

## Aturan pakai

- `patch` auto-backup ke `.bak`
- `ghidra` butuh Ghidra terinstall
- `decompile` butuh r2/Ghidra/objdump
- `anti` stdlib only
