#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rotate.py — egress rotator: Tor NEWNYM · WARP rekey · proxy pool.

Dibutuhkan buat lewatin lockout berbasis IP (Wordfence dsb) yang nge-lock
IP publik kita. Tiga jalur egress:

  tor    — kirim SIGNAL NEWNYM ke ControlPort Tor (circuit baru, IP baru)
  warp   — rekey/reconnect Cloudflare WARP (butuh warp-cli)
  pool   — rotasi daftar proxy dari file, cek egress IP tiap proxy

    python3 rotate.py tor --check                 # lihat egress IP via Tor
    python3 rotate.py tor --newnym --check        # rotate lalu verifikasi IP berubah
    python3 rotate.py pool --proxies pool.txt --check
    python3 rotate.py tor --exec "ffuf -u ... -w wl.txt"   # rotate → jalankan

ATURAN: tool ini cuma nyiapkan egress. Target yang diserang tetap wajib
ada izinnya (lihat scope gate di masing-masing tool pemakai).
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import pathlib
import re
import socket
import subprocess
import sys
import time

DEF_SOCKS = "127.0.0.1:9050"
DEF_CTRL = "127.0.0.1:9051"
IP_SVCS = ["https://check.torproject.org/api/ip",
           "https://api.ipify.org?format=json"]


# ───────────────────────── util: cek egress IP ─────────────────────────
def _proxy_args(proxy: str | None) -> list[str]:
    """Normalisasi 'socks5h://h:p' / 'h:p' → flag curl yang benar."""
    if not proxy:
        return []
    m = re.match(r"^([a-z0-9]+://)?(.+)$", proxy, re.I)
    scheme = (m.group(1) or "http://").rstrip(":/").lower()
    hostport = m.group(2).strip()
    if scheme.startswith("socks"):
        return ["--socks5-hostname", hostport]
    return ["--proxy", hostport]


def ip_via_curl(proxy: str | None, timeout: float = 20.0) -> str:
    """Cek IP publik lewat curl (murah, tanpa dependensi)."""
    for svc in IP_SVCS:
        cmd = ["curl", "-s", "-m", str(timeout)] + _proxy_args(proxy) + [svc]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=timeout + 5).stdout
        except Exception:
            continue
        m = re.search(r'"ip"\s*:\s*"([\d.]+)"', out) or re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", out)
        if m:
            return m.group(1)
    return ""


# ───────────────────────── jalur 1: Tor ─────────────────────────
class TorCtrl:
    def __init__(self, host: str, port: int, password: str = "",
                 cookie_file: str = ""):
        self.addr = (host, port)
        self.password = password
        self.cookie_file = cookie_file
        self.s = socket.create_connection(self.addr, timeout=10)
        self.s.settimeout(10)

    def _cmd(self, line: str) -> str:
        self.s.sendall((line + "\r\n").encode())
        buf = b""
        while not buf.endswith(b"250 OK\r\n"):
            chunk = self.s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"515" in buf or b"5xx" in buf:
                break
        return buf.decode("utf-8", "replace")

    def auth(self) -> str:
        info = self._cmd("PROTOCOLINFO 1")
        m = re.search(r'COOKIEFILE="([^"]+)"', info)
        cookie = self.cookie_file or (m.group(1) if m else "")
        if self.password:
            r = self._cmd(f'AUTHENTICATE "{self.password}"')
            return "password"
        if cookie and pathlib.Path(cookie).exists():
            raw = pathlib.Path(cookie).read_bytes()
            r = self._cmd("AUTHENTICATE " + binascii.hexlify(raw).decode())
            if "250 OK" in r:
                return f"cookie ({cookie})"
            # SAFECOOKIE: HMAC-SHA256(cookie, "AUTH0000000000000000")
            key = hashlib.sha256(raw + b"AUTH0000000000000000").digest()
            client = hashlib.sha256(key + raw).hexdigest().upper()
            self._cmd(f"AUTHCHALLENGE SAFECOOKIE {client}")
            server = re.search(r"SERVERHASH\s+([0-9A-F]+)", self._cmd(
                "AUTHENTICATE " + hashlib.sha256(
                    key + bytes.fromhex(client)).hexdigest().upper()))
            r = self._cmd("AUTHENTICATE " + hashlib.sha256(
                key + raw).hexdigest().upper())
            if "250 OK" in r:
                return f"safecookie ({cookie})"
        raise SystemExit(
            "[STOP] auth Tor gagal. Set `ControlPort 9051` + `HashedControlPassword` "
            "atau `CookieAuthentication 1` di torrc, lalu restart tor.")

    def newnym(self) -> str:
        return self._cmd("SIGNAL NEWNYM")

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


# ───────────────────────── jalur 2: WARP ─────────────────────────
def warp(args) -> int:
    if not shutil_which("warp-cli"):
        print("[STOP] warp-cli tidak ada. Install dulu (BlackArch/AUR: cloudflare-warp).")
        return 2
    def run(*c):
        return subprocess.run(["warp-cli", *c], capture_output=True,
                              text=True).stdout.strip()
    if args.rekey:
        if args.license:
            print(run("settings", "set", "license", args.license))
        print(run("registration", "delete"))
        print(run("connect"))
        time.sleep(6)
    else:
        print(run("disconnect"))
        time.sleep(2)
        print(run("connect"))
        time.sleep(6)
    ip = ip_via_curl(None)
    print(f"[✓] WARP egress → {ip or 'tak terbaca'}")
    return 0


def shutil_which(name: str) -> str | None:
    for p in pathlib.Path("/usr/bin").glob(name):
        return str(p)
    for p in pathlib.Path("/usr/local/bin").glob(name):
        return str(p)
    return None


# ───────────────────────── jalur 3: proxy pool ─────────────────────────
def load_pool(path: str) -> list[str]:
    p = pathlib.Path(path)
    if not p.exists():
        raise SystemExit(f"[STOP] file proxy tak ada: {path}")
    out = []
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line if "://" in line else f"http://{line}")
    return out


def pool_check(proxies: list[str], timeout: float) -> list[dict]:
    hidup = []
    for pr in proxies:
        ip = ip_via_curl(pr, timeout)
        print(f"    {'[✓]' if ip else '[✗]'} {pr:<38} {ip}")
        if ip:
            hidup.append({"proxy": pr, "ip": ip})
    return hidup


# ───────────────────────── main ─────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser(description="egress rotator (tor/warp/pool)")
    ap.add_argument("jalur", choices=["tor", "warp", "pool"])
    ap.add_argument("--socks", default=DEF_SOCKS, help="SOCKS Tor (cek IP)")
    ap.add_argument("--ctrl", default=DEF_CTRL, help="ControlPort Tor")
    ap.add_argument("--password", default="", help="HashedControlPassword (plaintext)")
    ap.add_argument("--cookie-file", default="", help="path control_auth_cookie")
    ap.add_argument("--proxies", help="file proxy per baris (untuk jalur pool)")
    ap.add_argument("--license", help="WARP+ license key")
    ap.add_argument("--rekey", action="store_true", help="WARP: hapus registrasi + ulang")
    ap.add_argument("--newnym", action="store_true", help="tor: kirim NEWNYM")
    ap.add_argument("--check", action="store_true", help="tampilkan egress IP")
    ap.add_argument("--exec", help="jalankan command ini setelah rotasi")
    ap.add_argument("--timeout", type=float, default=20.0)
    a = ap.parse_args()

    before = ip_via_curl(a.socks) if a.check else ""

    if a.jalur == "tor":
        if a.newnym:
            h, p = a.ctrl.rsplit(":", 1)
            try:
                c = TorCtrl(h, int(p), a.password, a.cookie_file)
                print(f"[tor] auth: {c.auth()}")
                print(f"[tor] {c.newnym().splitlines()[-1]}")
                c.close()
                time.sleep(8)          # Tor butuh waktu bikin circuit baru
            except SystemExit as e:
                print(e)
                return 2
            except Exception as e:
                print(f"[STOP] control port tak terjangkau ({e}). "
                      f"Cek `ControlPort {a.ctrl}` di torrc.")
                return 2
        if a.check:
            after = ip_via_curl(a.socks)
            if not a.newnym:            # sekadar cek → jangan bandingkan
                print(f"[tor] egress IP: {after or '?'}  (via {a.socks})")
                return 0 if after else 1
            print(f"[tor] egress sebelum: {before or '?'}")
            print(f"[tor] egress sesudah : {after or '?'}")
            if before and after and before == after:
                print("[!] IP sama — NEWNYM belum aktif, tunggu 10-30s lagi.")
                return 1
            if after:
                print("[✓] IP berubah ✓")
    elif a.jalur == "warp":
        return warp(a)
    elif a.jalur == "pool":
        pl = load_pool(a.proxies)
        print(f"[pool] {len(pl)} proxy")
        hidup = pool_check(pl, a.timeout)
        print(f"[✓] {len(hidup)}/{len(pl)} hidup")
        if hidup and a.check:
            print("[pool] egress pool:", ", ".join(x["ip"] for x in hidup))

    if a.exec:
        print(f"[exec] {a.exec}")
        return subprocess.run(a.exec, shell=True).returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
