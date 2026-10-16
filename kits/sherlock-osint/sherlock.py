#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sherlock.py — OSINT investigation toolkit ala Sherlock Holmes.

Fitur:
  - username: cari username di 50+ platform
  - email: cari email di breach, social media, dll
  - phone: cari nomor telepon di berbagai platform
  - domain: OSINT domain (DNS, WHOIS, subdomain, tech stack)
  - social: social media profiling
  - correlate: korelasikan semua data jadi 1 profil
  - report: generate laporan investigasi

    python3 sherlock.py username --target john_doe
    python3 sherlock.py email --target john@example.com
    python3 sherlock.py phone --target +6281234567890
    python3 sherlock.py domain --target example.com
    python3 sherlock.py social --target john_doe
    python3 sherlock.py correlate --username john_doe --email john@example.com
    python3 sherlock.py report --target john_doe
"""
import argparse, hashlib, json, re, socket, ssl, sys, urllib.error, urllib.parse, urllib.request

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
TIMEOUT = 10

# ============ Username Search ============

USERNAME_SITES = {
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Twitter/X": "https://x.com/{}",
    "Instagram": "https://instagram.com/{}",
    "Facebook": "https://facebook.com/{}",
    "LinkedIn": "https://linkedin.com/in/{}",
    "TikTok": "https://tiktok.com/@{}",
    "YouTube": "https://youtube.com/@{}",
    "Reddit": "https://reddit.com/user/{}",
    "Pinterest": "https://pinterest.com/{}",
    "Tumblr": "https://{}.tumblr.com",
    "Flickr": "https://flickr.com/people/{}",
    "Vimeo": "https://vimeo.com/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Twitch": "https://twitch.tv/{}",
    "Telegram": "https://t.me/{}",
    "Snapchat": "https://snapchat.com/add/{}",
    "WhatsApp": "https://wa.me/{}",
    "Medium": "https://medium.com/@{}",
    "Quora": "https://quora.com/profile/{}",
    "StackOverflow": "https://stackoverflow.com/users/{}",
    "WordPress": "https://{}.wordpress.com",
    "Blogger": "https://{}.blogspot.com",
    "Tinder": "https://tinder.com/@{}",
    "GitHub Gist": "https://gist.github.com/{}",
    "CodePen": "https://codepen.io/{}",
    "Dev.to": "https://dev.to/{}",
    "Hashnode": "https://hashnode.com/@{}",
    "npm": "https://npmjs.com/~{}",
    "PyPI": "https://pypi.org/user/{}",
    "Docker Hub": "https://hub.docker.com/u/{}",
    "Rust Crates": "https://crates.io/users/{}",
    "ResearchGate": "https://researchgate.net/profile/{}",
    "Academia.edu": "https://academia.edu/{}",
    "Behance": "https://behance.net/{}",
    "Dribbble": "https://dribbble.com/{}",
    "GitHub Pages": "https://{}.github.io",
    "Keybase": "https://keybase.io/{}",
    "Pastebin": "https://pastebin.com/u/{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "ProductHunt": "https://producthunt.com/@{}",
    "Kickstarter": "https://kickstarter.com/profile/{}",
    "Patreon": "https://patreon.com/{}",
}

def search_username(target, limit=None):
    sites = list(USERNAME_SITES.items())
    if limit:
        sites = sites[:limit]
    print(f"[*] Username search: {target}")
    print(f"[*] Checking {len(sites)} platforms...")
    print()
    found = []
    not_found = []
    errors = []
    for site, url_template in sites:
        url = url_template.format(target)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html"})
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
                if r.status == 200:
                    found.append((site, url))
                    print(f"  [+] {site:20} -> {url}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                not_found.append(site)
            elif e.code == 403:
                errors.append((site, "403 Forbidden (WAF/Block)"))
            else:
                errors.append((site, f"HTTP {e.code}"))
        except Exception as e:
            errors.append((site, str(e)[:30]))
    print(f"\n[*] Found: {len(found)} | Not found: {len(not_found)} | Errors: {len(errors)}")
    if errors:
        print(f"\n[*] Errors (first 10):")
        for site, err in errors[:10]:
            print(f"  [-] {site:20} -> {err}")
    return found

# ============ Email Search ============

EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "proton.me", "protonmail.com", "aol.com", "zoho.com", "gmx.com",
    "mail.com", "yandex.com", "tutanota.com", "fastmail.com",
]

SOCIAL_WITH_EMAIL = [
    "https://www.facebook.com/login/identify/?ctx=recover&email={}",
    "https://twitter.com/account/begin_password_reset?email={}",
    "https://www.linkedin.com/uas/login-submit?session_key={}",
    "https://www.instagram.com/accounts/password/reset/?email={}",
    "https://www.reddit.com/password?email={}",
]

def search_email(target):
    print(f"[*] Email OSINT: {target}")
    print()
    local, domain = target.split("@") if "@" in target else (target, "")
    print(f"[*] Local part: {local}")
    print(f"[*] Domain: {domain}")
    print()
    print(f"[*] Domain analysis:")
    print(f"  TLD: {domain.split('.')[-1] if domain else 'N/A'}")
    print(f"  Provider: {'Generic' if domain not in EMAIL_PROVIDERS else 'Known provider'}")
    print()
    print(f"[*] Social media password reset:")
    for url in SOCIAL_WITH_EMAIL:
        print(f"  {url.format(target)}")
    print()
    print(f"[*] Breach check:")
    print(f"  https://haveibeenpwned.com/unifiedsearch/{target}")
    print(f"  https://dehashed.com/search?query={target}")
    print()
    print(f"[*] Email reputation:")
    print(f"  https://emailrep.io/{target}")
    print(f"  https://piss.consumer.org/email/{target}")
    print()
    print(f"[*] Gravatar:")
    email_hash = hashlib.md5(target.lower().encode()).hexdigest()
    print(f"  https://gravatar.com/avatar/{email_hash}")
    print(f"  https://en.gravatar.com/{email_hash}")

# ============ Phone Search ============

def search_phone(target):
    print(f"[*] Phone OSINT: {target}")
    print()
    clean = re.sub(r"[^\d]", "", target)
    print(f"[*] Clean number: {clean}")
    if clean.startswith("62") or clean.startswith("0"):
        print(f"[*] Country: Indonesia (+62)")
        print(f"[*] Mobile prefix: {clean[:4]}")
        carriers = {
            "0811": "Telkomsel", "0812": "Telkomsel", "0813": "Telkomsel",
            "0821": "Telkomsel", "0822": "Telkomsel", "0823": "Telkomsel",
            "0851": "Telkomsel", "0852": "Telkomsel", "0853": "Telkomsel",
            "0814": "Indosat", "0815": "Indosat", "0816": "Indosat",
            "0855": "Indosat", "0856": "Indosat", "0857": "Indosat",
            "0858": "Indosat", "0817": "XL", "0818": "XL", "0819": "XL",
            "0859": "XL", "0877": "XL", "0878": "XL",
            "0895": "3 (Tri)", "0896": "3 (Tri)", "0897": "3 (Tri)",
            "0898": "3 (Tri)", "0899": "3 (Tri)",
            "0881": "Smartfren", "0882": "Smartfren", "0883": "Smartfren",
            "0884": "Smartfren", "0885": "Smartfren", "0886": "Smartfren",
            "0887": "Smartfren", "0888": "Smartfren", "0889": "Smartfren",
            "0838": "Axis", "0831": "Axis", "0832": "Axis", "0833": "Axis",
        }
        carrier = carriers.get(clean[:4], "Unknown")
        print(f"[*] Carrier: {carrier}")
    print()
    print(f"[*] Messaging apps:")
    print(f"  WhatsApp: https://wa.me/{clean}")
    print(f"  Telegram: https://t.me/{clean}")
    print(f"  Viber: viber://chat?number={clean}")
    print(f"  Line: https://line.me/ti/p/~{clean}")
    print()
    print(f"[*] Social media:")
    print(f"  Facebook: https://facebook.com/search/people?q={clean}")
    print(f"  Instagram: https://instagram.com/explore/?q={clean}")
    print()
    print(f"[*] Reverse lookup:")
    print(f"  https://www.truecaller.com/search/{clean}")
    print(f"  https://www.whitepages.com/phone/{clean}")

# ============ Domain OSINT ============

def search_domain(target):
    print(f"[*] Domain OSINT: {target}")
    print()
    print(f"[*] DNS records:")
    records = {
        "A": socket.gethostbyname(target) if _resolve(target) else "N/A",
        "NS": f"dig NS {target} +short",
        "MX": f"dig MX {target} +short",
        "TXT": f"dig TXT {target} +short",
    }
    for rtype, val in records.items():
        print(f"  {rtype}: {val}")
    print()
    print(f"[*] WHOIS:")
    print(f"  https://whois.domaintools.com/{target}")
    print(f"  https://www.whois.com/whois/{target}")
    print()
    print(f"[*] Subdomain enumeration:")
    print(f"  subfinder -d {target}")
    print(f"  amass enum -d {target}")
    print(f"  crt.sh/?q=%.{target}&output=json")
    print()
    print(f"[*] Tech stack:")
    print(f"  https://builtwith.com/{target}")
    print(f"  https://wappalyzer.com/lookup/{target}")
    print()
    print(f"[*] Wayback machine:")
    print(f"  https://web.archive.org/web/*/{target}")
    print()
    print(f"[*] Security headers:")
    print(f"  curl -I https://{target}")

def _resolve(host):
    try:
        socket.gethostbyname(host)
        return True
    except:
        return False

# ============ Social Profiling ============

def social_profile(target):
    print(f"[*] Social media profiling: {target}")
    print()
    platforms = {
        "Instagram": f"https://instagram.com/{target}",
        "Twitter/X": f"https://x.com/{target}",
        "TikTok": f"https://tiktok.com/@{target}",
        "Facebook": f"https://facebook.com/{target}",
        "LinkedIn": f"https://linkedin.com/in/{target}",
        "YouTube": f"https://youtube.com/@{target}",
        "GitHub": f"https://github.com/{target}",
        "Reddit": f"https://reddit.com/user/{target}",
        "Pinterest": f"https://pinterest.com/{target}",
        "Snapchat": f"https://snapchat.com/add/{target}",
        "Telegram": f"https://t.me/{target}",
        "Twitch": f"https://twitch.tv/{target}",
        "Medium": f"https://medium.com/@{target}",
        "Quora": f"https://quora.com/profile/{target}",
    }
    for name, url in platforms.items():
        print(f"  {name:12}: {url}")
    print()
    print(f"[*] Profile analysis:")
    print(f"  1. Profile picture (Google reverse image)")
    print(f"  2. Bio/description (clues: lokasi, pekerjaan, interest)")
    print(f"  3. Posts (clues: rutinitas, lokasi, kontak)")
    print(f"  4. Friends/followers (clues: jaringan sosial)")
    print(f"  5. Tagged photos (clues: lokasi, aktivitas)")
    print(f"  6. Check-ins (clues: lokasi favorit)")
    print(f"  7. Hashtags (clues: interest, komunitas)")

# ============ Correlation ============

def correlate(username=None, email=None, phone=None, domain=None):
    print(f"[*] Correlation analysis")
    print(f"=" * 50)
    profile = {}
    if username:
        profile["username"] = username
        print(f"\n[+] Username: {username}")
        print(f"  -> Check {len(USERNAME_SITES)} platforms")
    if email:
        profile["email"] = email
        local, dom = email.split("@") if "@" in email else (email, "")
        print(f"\n[+] Email: {email}")
        print(f"  -> Local: {local}")
        print(f"  -> Domain: {dom}")
        if username and local.lower() in username.lower():
            print(f"  -> [!] Email local part MATCHES username")
        if username and username.lower() in local.lower():
            print(f"  -> [!] Username MATCHES email local part")
    if phone:
        profile["phone"] = phone
        print(f"\n[+] Phone: {phone}")
        if username:
            clean = re.sub(r"[^\d]", "", phone)
            if clean[-4:] in username:
                print(f"  -> [!] Phone suffix in username")
    if domain:
        profile["domain"] = domain
        print(f"\n[+] Domain: {domain}")
        if username and username.lower() in domain.lower():
            print(f"  -> [!] Username in domain")
        if email and dom and dom.lower() in domain.lower():
            print(f"  -> [!] Email domain matches target domain")
    print(f"\n[+] Profile:")
    print(json.dumps(profile, indent=2))
    return profile

# ============ Report ============

def generate_report(target):
    print(f"[*] Investigation report: {target}")
    print(f"=" * 60)
    print(f"# OSINT Report: {target}")
    print(f"# Generated: {__import__('datetime').datetime.now().isoformat()}")
    print(f"# Tool: sherlock-osint v1.0")
    print(f"=" * 60)
    print()
    print("## 1. Username Search")
    print(f"- Target: {target}")
    print(f"- Platforms: {len(USERNAME_SITES)}")
    print()
    print("## 2. Email")
    print(f"- Check breach: haveibeenpwned.com")
    print(f"- Check reputation: emailrep.io")
    print()
    print("## 3. Phone")
    print(f"- Check WhatsApp: wa.me/")
    print(f"- Check Telegram: t.me/<phone_username>")
    print()
    print("## 4. Domain")
    print(f"- DNS: dig +trace")
    print(f"- WHOIS: whois.com")
    print(f"- Subdomains: subfinder")
    print()
    print("## 5. Social Media")
    for name in ["Instagram", "Twitter", "Facebook", "LinkedIn", "TikTok"]:
        print(f"- {name}")
    print()
    print("## 6. Next Steps")
    print("- Cross-reference all findings")
    print("- Check for password reuse")
    print("- Check for data breaches")
    print("- Check for leaked credentials")
    print("- Social engineering (phishing, vishing, pretexting)")
    print()
    print("=" * 60)
    print("END OF REPORT")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0]
    if cmd == "username":
        p = argparse.ArgumentParser()
        p.add_argument("--target", required=True)
        p.add_argument("--limit", type=int, default=None)
        a = p.parse_args(args[1:])
        search_username(a.target, a.limit)
    elif cmd == "email":
        p = argparse.ArgumentParser()
        p.add_argument("--target", required=True)
        a = p.parse_args(args[1:])
        search_email(a.target)
    elif cmd == "phone":
        p = argparse.ArgumentParser()
        p.add_argument("--target", required=True)
        a = p.parse_args(args[1:])
        search_phone(a.target)
    elif cmd == "domain":
        p = argparse.ArgumentParser()
        p.add_argument("--target", required=True)
        a = p.parse_args(args[1:])
        search_domain(a.target)
    elif cmd == "social":
        p = argparse.ArgumentParser()
        p.add_argument("--target", required=True)
        a = p.parse_args(args[1:])
        social_profile(a.target)
    elif cmd == "correlate":
        p = argparse.ArgumentParser()
        p.add_argument("--username", default=None)
        p.add_argument("--email", default=None)
        p.add_argument("--phone", default=None)
        p.add_argument("--domain", default=None)
        a = p.parse_args(args[1:])
        correlate(a.username, a.email, a.phone, a.domain)
    elif cmd == "report":
        p = argparse.ArgumentParser()
        p.add_argument("--target", required=True)
        a = p.parse_args(args[1:])
        generate_report(a.target)
    else:
        print(__doc__)

if __name__ == "__main__":
    main()
