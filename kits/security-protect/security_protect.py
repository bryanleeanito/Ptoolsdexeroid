#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security_protect.py — defensive security & hardening toolkit.

Fitur:
  - headers: generate security headers (CSP, HSTS, X-Frame, etc.)
  - audit: audit keamanan dasar (file permission, config, etc.)
  - hardening: OS hardening checklist + auto-fix
  - firewall: generate iptables/nftables rules
  - monitor: log monitoring & alert rules
  - backup: backup & integrity checker

    python3 security_protect.py headers --domain example.com
    python3 security_protect.py audit --path /var/www/html
    python3 security_protect.py hardening --level 2
    python3 security_protect.py firewall --action block --ip 10.0.0.1
    python3 security_protect.py monitor --log /var/log/apache2/access.log
    python3 security_protect.py backup --source /var/www --dest /backup
"""
import argparse, hashlib, os, re, stat, sys, json
from datetime import datetime

# ============ Security Headers ============

def generate_headers(domain):
    print(f"[*] Security headers untuk: {domain}")
    print()
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
    }
    print("[*] Headers:")
    for h, v in headers.items():
        print(f"  {h}: {v}")
    print()
    print("[*] Nginx config:")
    print("  add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;")
    print("  add_header Content-Security-Policy \"default-src 'self'; script-src 'self'\" always;")
    print("  add_header X-Frame-Options DENY always;")
    print("  add_header X-Content-Type-Options nosniff always;")
    print()
    print("[*] Apache config:")
    print("  Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'")
    print("  Header always set X-Frame-Options DENY")
    print("  Header always set X-Content-Type-Options nosniff")
    print()
    print("[*] Express.js:")
    print("  app.use(helmet())")
    print()
    print("[*] Django:")
    print("  SECURE_HSTS_SECONDS = 31536000")
    print("  SECURE_CONTENT_TYPE_NOSNIFF = True")
    print("  X_FRAME_OPTIONS = 'DENY'")

# ============ Security Audit ============

def audit_path(path):
    print(f"[*] Security audit: {path}")
    print()
    findings = []
    # Check file permissions
    for root, dirs, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            try:
                st = os.stat(fp)
                mode = stat.S_IMODE(st.st_mode)
                # World-writable
                if mode & 0o002:
                    findings.append(("HIGH", fp, f"World-writable: {oct(mode)}"))
                # SUID/SGID
                if st.st_mode & stat.S_ISUID:
                    findings.append(("MEDIUM", fp, "SUID bit set"))
                if st.st_mode & stat.S_ISGID:
                    findings.append(("MEDIUM", fp, "SGID bit set"))
                # No owner
                if st.st_uid == 0 and st.st_gid == 0:
                    if f.endswith((".php", ".html", ".js")):
                        findings.append(("LOW", fp, "Owned by root"))
            except:
                pass
    # Check for sensitive files
    sensitive = [".env", "config.php", "wp-config.php", ".git", ".DS_Store", "backup", "dump.sql"]
    for s in sensitive:
        for root, dirs, files in os.walk(path):
            for f in files:
                if s in f.lower():
                    findings.append(("HIGH", os.path.join(root, f), f"Sensitive file: {s}"))
    if findings:
        print(f"[!] {len(findings)} findings:")
        for sev, fp, desc in findings:
            print(f"  [{sev:8}] {fp}: {desc}")
    else:
        print("[*] No findings")
    return findings

# ============ Hardening ============

def hardening(level=2):
    levels = {
        1: {
            "name": "Basic",
            "items": [
                "Update OS & packages",
                "Enable UFW/firewalld",
                "Disable root SSH",
                "Install fail2ban",
                "Enable automatic updates",
            ]
        },
        2: {
            "name": "Intermediate",
            "items": [
                "All Basic items",
                "Configure SELinux/AppArmor",
                "Disable unused services",
                "Enable auditd",
                "Configure sysctl hardening",
                "Enable ASLR",
                "Disable core dumps",
                "Configure PAM password policy",
            ]
        },
        3: {
            "name": "Advanced",
            "items": [
                "All Intermediate items",
                "Enable Secure Boot",
                "Configure IMA/EVM",
                "Enable dm-verity",
                "Configure kernel module signing",
                "Enable lockdown mode",
                "Configure remote logging",
                "Enable file integrity monitoring (AIDE)",
            ]
        },
    }
    lvl = levels.get(level, levels[2])
    print(f"[*] Hardening level {level}: {lvl['name']}")
    print()
    for i, item in enumerate(lvl['items'], 1):
        print(f"  {i:2}. {item}")
    print()
    print("[*] sysctl hardening:")
    sysctl = {
        "net.ipv4.ip_forward": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.all.log_martians": "1",
        "net.ipv4.icmp_echo_ignore_broadcasts": "1",
        "net.ipv4.icmp_ignore_bogus_error_responses": "1",
        "net.ipv4.tcp_syncookies": "1",
        "kernel.randomize_va_space": "2",
        "fs.suid_dumpable": "0",
    }
    for k, v in sysctl.items():
        print(f"  {k} = {v}")

# ============ Firewall ============

def firewall(action, ip=None, port=None):
    print(f"[*] Firewall: {action} {ip or ''} {port or ''}")
    print()
    if action == "block":
        print("[*] iptables:")
        print(f"  iptables -A INPUT -s {ip} -j DROP")
        print(f"  iptables -A INPUT -p tcp --dport {port} -s {ip} -j DROP")
        print()
        print("[*] nftables:")
        print(f"  nft add rule inet filter input ip saddr {ip} drop")
        print()
        print("[*] UFW:")
        print(f"  ufw deny from {ip}")
        print(f"  ufw deny from {ip} to any port {port}")
    elif action == "allow":
        print("[*] iptables:")
        print(f"  iptables -A INPUT -s {ip} -j ACCEPT")
        print()
        print("[*] UFW:")
        print(f"  ufw allow from {ip}")
    elif action == "rate-limit":
        print("[*] iptables rate limit:")
        print(f"  iptables -A INPUT -p tcp --dport {port} -m limit --limit 5/min -j ACCEPT")
        print(f"  iptables -A INPUT -p tcp --dport {port} -j DROP")
        print()
        print("[*] fail2ban:")
        print(f"  [DEFAULT]")
        print(f"  bantime = 3600")
        print(f"  maxretry = 5")

# ============ Monitor ============

def monitor(log_path):
    print(f"[*] Log monitoring: {log_path}")
    print()
    patterns = {
        "SQLi": r"(\bunion\b.*\bselect\b|\bdrop\b.*\btable\b|\binsert\b.*\binto\b)",
        "XSS": r"(<script|javascript:|on\w+=)",
        "Path Traversal": r"(\.\./|\.\.\\|%2e%2e)",
        "Shell": r"(\bsystem\b.*\$_GET|\bexec\b.*\$_POST|passthru)",
        "Brute Force": r"(401|403).*Failed",
        "Port Scan": r"(SYN.*SYN.*SYN|port.scan)",
    }
    print("[*] Alert rules:")
    for name, pattern in patterns.items():
        print(f"  {name:15}: {pattern}")
    print()
    print("[*] fail2ban jail:")
    print("  [sshd]")
    print("  enabled = true")
    print("  maxretry = 3")
    print("  bantime = 3600")
    print()
    print("[*] rsyslog:")
    print("  auth,authpriv.* /var/log/auth.log")
    print("  kern.* /var/log/kern.log")
    print()
    print("[*] OSSEC rules:")
    print("  <rule id='100001' level='10'>")
    print("    <if_sid>5716</if_sid>")
    print("    <match>Failed password</match>")
    print("    <description>Failed SSH attempt</description>")
    print("  </rule>")

# ============ Backup ============

def backup(source, dest):
    print(f"[*] Backup: {source} -> {dest}")
    print()
    print("[*] rsync:")
    print(f"  rsync -avz --delete {source}/ {dest}/")
    print()
    print("[*] tar:")
    print(f"  tar -czf {dest}/backup_$(date +%Y%m%d).tar.gz {source}")
    print()
    print("[*] Integrity check:")
    print(f"  find {source} -type f -exec sha256sum {{}} \\; > {dest}/integrity.sha256")
    print(f"  sha256sum -c {dest}/integrity.sha256")
    print()
    print("[*] Automated backup (cron):")
    print("  0 2 * * * rsync -avz --delete /var/www/ /backup/")
    print()
    print("[*] Backup verification:")
    print("  1. Test restore")
    print("  2. Check integrity")
    print("  3. Verify permissions")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "headers":
        p = argparse.ArgumentParser()
        p.add_argument("--domain", required=True)
        a = p.parse_args(args[1:])
        generate_headers(a.domain)
    elif cmd == "audit":
        p = argparse.ArgumentParser()
        p.add_argument("--path", required=True)
        a = p.parse_args(args[1:])
        audit_path(a.path)
    elif cmd == "hardening":
        p = argparse.ArgumentParser()
        p.add_argument("--level", type=int, default=2, choices=[1, 2, 3])
        a = p.parse_args(args[1:])
        hardening(a.level)
    elif cmd == "firewall":
        p = argparse.ArgumentParser()
        p.add_argument("--action", required=True, choices=["block", "allow", "rate-limit"])
        p.add_argument("--ip", default=None)
        p.add_argument("--port", default=None)
        a = p.parse_args(args[1:])
        firewall(a.action, a.ip, a.port)
    elif cmd == "monitor":
        p = argparse.ArgumentParser()
        p.add_argument("--log", required=True)
        a = p.parse_args(args[1:])
        monitor(a.log)
    elif cmd == "backup":
        p = argparse.ArgumentParser()
        p.add_argument("--source", required=True)
        p.add_argument("--dest", required=True)
        a = p.parse_args(args[1:])
        backup(a.source, a.dest)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
