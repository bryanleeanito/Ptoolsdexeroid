#!/usr/bin/env bash
# prep_blackarch.sh — install toolkit pwn/rev sekali jalan di BlackArch.
# Jalankan: bash prep_blackarch.sh
set -e
echo "[*] update db + full upgrade dulu (WAJIB biar gak partial upgrade)"
sudo pacman -Syyu --noconfirm || { echo "[!] upgrade gagal — cek koneksi/pacman lock"; exit 1; }

PKGS=(
  python-pwntools python-pip
  gdb gef
  radare2 cutter
  ropper one_gadget
  seccomp-tools
  xxd strace ltrace nasm ghex
  python-capstone python-keystone python-unicorn
  patchelf libc6-dbg
)
echo "[*] install: ${PKGS[*]}"
sudo pacman -S --needed --noconfirm "${PKGS[@]}"

echo "[*] pasang pwndbg (kalau gef gagal/ganti preferensi)"
if ! command -v gef >/dev/null 2>&1; then
  git clone --depth 1 https://github.com/pwndbg/pwndbg ~/.pwndbg 2>/dev/null || true
  [ -d ~/.pwndbg ] && (cd ~/.pwndbg && ./setup.sh) || true
fi

echo "[*] verifikasi"
python3 -c "import pwn; print('pwntools', pwn.__version__)" || echo "[!] pwntools bermasalah"
command -v r2 >/dev/null && r2 -v | head -1
command -v ropper >/dev/null && echo "ropper OK"
command -v one_gadget >/dev/null && echo "one_gadget OK"
echo "[OK] toolkit pwn siap. mulai: gdb ./chall atau python3 exploit.py"
