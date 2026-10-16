# webshell-manager v1.0

Webshell detection, obfuscation & management toolkit.

## Perintah

```bash
python3 webshell_manager.py detect --path /var/www/html
python3 webshell_manager.py obfuscate --file shell.php --method base64
python3 webshell_manager.py generate --type php --method command
python3 webshell_manager.py manage --url https://target.com/shell.php --pass password
python3 webshell_manager.py clean --url https://target.com/shell.php --pass password
```

## Fitur

| Perintah | Fungsi |
|---|---|
| `detect` | Scan file/directory buat webshell signature |
| `obfuscate` | Obfuscate webshell (base64, hex, rot13, gzip) |
| `generate` | Generate webshell template (PHP, ASPX, JSP, Python) |
| `manage` | Upload, execute, manage webshell |
| `clean` | Cleanup webshell & logs |

## Webshell Types

- **PHP**: command, eval, base64, shell, file, backdoor
- **ASPX**: command, eval
- **JSP**: command, eval
- **Python**: command, eval

## Detection Signatures

- PHP: eval, base64_decode, shell_exec, system, passthru, exec, popen, assert
- ASPX: eval, Response.Write, Process.Start
- JSP: Runtime.exec, ProcessBuilder
- Python: os.system, subprocess, eval, exec

## Aturan pakai

- **Wajib** otorisasi tertulis / CTF scope
- Jangan produksi tanpa izin
- Cleanup wajib setelah testing
- Output = attack artifact
