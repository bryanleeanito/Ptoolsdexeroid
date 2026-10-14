# ctf-pwn — pwn & reverse (BlackArch)

Kategori pwn/rev dikerjakan **di BlackArch**, bukan Windows.
Kit ini cuma berisi checklist + script persiapan environment.

## Persiapan sekali jalan (di BlackArch, butuh internet)

```bash
bash kits/ctf-pwn/prep_blackarch.sh
```

Isi: pwntools, gdb + pwndbg, radare2, ropper, one_gadget, seccomp-tools,
python-pip, xxd, strace, ltrace, nasm, ghex.

## Workflow pwn klasik

```bash
# 1. amati binary
file chall && checksec --file=chall          # RELRO/Canary/NX/PIE
strings -n 6 chall | grep -iE 'flag|cat|sh'  # petunjuk
rabin2 -I chall; rabin2 -z chall             # radare2

# 2. jalankan lokal
./chall                                      # cek input handling

# 3. debug
gdb ./chall                                  # pwndbg: cyclic 200 → cek offset
pwn template ./chall                         # skeleton exploit

# 4. exploit remote
python3 exploit.py HOST PORT                 # pwnlib
```

## Tips jeorpadic

- **ret2win**: overflow → RIP ke fungsi `win()`/`system("/bin/sh")`
- **ret2libc**: leak `puts@GOT` → hitung base libc → `system("/bin/sh")`
- **fmt string**: `%p` leak stack/ASLR → `%n` tulis arbitrary
- **ROPgadget --binary chall --only "pop|ret"** buat chain
- Kalau NX + PIE + canary: canary leak via `%p`/overflow baca dulu, baru chain
- Docker compose soal → jalankan lokal identik versi libc (LD_PRELOAD/LD_LIBRARY_PATH)

## Reverse workflow

```bash
r2 -A chall        # analisa → afl (fungsi), pdf @main, iz (string xref)
ghidra-headless   # kalau ada, decompile massal
```

Flag biasanya: `cat /flag`, `flag{...}` string, atau hasil decrypt di fungsi tertentu.
