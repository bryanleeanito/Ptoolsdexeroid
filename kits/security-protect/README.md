# security-protect v1.0

Defensive security & hardening toolkit.

## Perintah

```bash
python3 security_protect.py headers --domain example.com
python3 security_protect.py audit --path /var/www/html
python3 security_protect.py hardening --level 2
python3 security_protect.py firewall --action block --ip 10.0.0.1
python3 security_protect.py monitor --log /var/log/apache2/access.log
python3 security_protect.py backup --source /var/www --dest /backup
```

## Fitur

| Perintah | Fungsi |
|---|---|
| `headers` | Generate security headers (CSP, HSTS, X-Frame, etc.) |
| `audit` | Audit keamanan dasar (file permission, sensitive files) |
| `hardening` | OS hardening checklist (3 level) |
| `firewall` | Generate iptables/nftables/UFW rules |
| `monitor` | Log monitoring & alert rules |
| `backup` | Backup & integrity checker |

## Hardening Levels

| Level | Name | Items |
|---|---|---|
| 1 | Basic | Update, firewall, SSH, fail2ban, auto-update |
| 2 | Intermediate | + SELinux, auditd, sysctl, ASLR, PAM |
| 3 | Advanced | + Secure Boot, IMA/EVM, dm-verity, AIDE |

## Security Headers

- HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- Referrer-Policy, Permissions-Policy
- Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy

## Aturan pakai

- Gunakan untuk defensive security
- Audit = cari vulnerability di sistem sendiri
- Hardening = tingkatkan keamanan
- Backup = protect data
