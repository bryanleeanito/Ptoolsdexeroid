# rev-toolkit v1.0

Helper reverse engineering buat CTF — strings, ELF parse, patch template, r2 script generator, UPX detect.

## Perintah

```bash
python3 rev_toolkit.py strings <binary> [--min 6]
python3 rev_toolkit.py elf <binary>
python3 rev_toolkit.py patch --type nop --offset 0x400500 --len 16
python3 rev_toolkit.py r2gen <binary> [--output script.r2]
python3 rev_toolkit.py upx <binary>
```

## Output

| Perintah | Output |
|---|---|
| `strings` | Offset + printable string |
| `elf` | Class, arch, endian, entry, sections |
| `patch` | Template patch (NOP/jmp/shellcode) |
| `r2gen` | radare2 script otomatis |
| `upx` | Deteksi + command unpack |

## Catatan

- `strings` + `elf` jalan di box ini (Python stdlib only).
- `r2gen` butuh radare2 di BlackArch.
- `upx` butuh `upx-ucl` di BlackArch.
