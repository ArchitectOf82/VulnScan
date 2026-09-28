# -*- coding: utf-8 -*-
"""
VulnScan - Module 17: Subdomain Takeover Detection (READ-ONLY).

Enumerates common subdomains, resolves each CNAME record, and flags any
subdomain whose CNAME points at an unclaimed third-party service (Heroku,
GitHub Pages, S3, Azure, CloudFront, Netlify, ReadTheDocs, ...) - a classic
subdomain-takeover candidate. DNS query + passive banner check only.

Usage:  python subdomain_takeover.py <domain> [--out report.html]
"""

import sys
import os
import re
import socket
import ssl
import urllib.request
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

VERSION = "1.0.0"
PRODUCT = "VulnScan"
TIMEOUT = 3
DNS = "8.8.8.8"

DEFAULT_SUBDOMAINS = [
    "www", "mail", "blog", "api", "app", "dev", "test", "staging", "demo",
    "m", "shop", "docs", "support", "status", "cdn", "img", "assets", "static",
    "portal", "admin", "intranet", "vpn", "ftp", "remote", "git", "jenkins",
    "grafana", "kibana", "nexus", "gitlab", "auth", "login", "sso", "ws",
    "websocket", "graphql", "gateway", "proxy", "prod", "pre", "beta", "alpha",
    "release", "internal", "hr", "oa", "erp", "crm", "cms", "wiki",
    "confluence", "jira", "forum", "bbs", "news", "media", "video", "download",
    "upload", "backup", "db", "database", "redis", "mq", "kafka", "es", "log",
    "monitor", "zabbix", "nagios", "waf", "iot", "edge", "mf", "app1", "app2",
]

# cname suffix -> service label
TAKEOVER_SERVICES = {
    "herokudns.com": "Heroku", "herokussl.com": "Heroku",
    "github.io": "GitHub Pages", "githubusercontent.com": "GitHub Pages",
    "gitlab.io": "GitLab Pages",
    "amazonaws.com": "AWS S3/Elastic Beanstalk",
    "cloudfront.net": "AWS CloudFront",
    "azurewebsites.net": "Azure App Service",
    "azureedge.net": "Azure CDN", "cloudapp.azure.com": "Azure",
    "trafficmanager.net": "Azure",
    "netlify.app": "Netlify", "netlify.com": "Netlify",
    "surge.sh": "Surge.sh",
    "readthedocs.io": "Read the Docs", "readthedocs.org": "Read the Docs",
    "gitbook.io": "GitBook",
    "bitbucket.io": "Bitbucket",
    "myshopify.com": "Shopify",
    "zendesk.com": "Zendesk", "shopifycloud.com": "Shopify",
    "ghost.io": "Ghost",
    "fastly.net": "Fastly", "global.fastly.net": "Fastly",
    "wpengine.com": "WP Engine",
    "pantheon.io": "Pantheon",
    "statuspage.io": "StatusPage (Atlassian)",
    "tumblr.com": "Tumblr", "wordpress.com": "WordPress.com",
    "uservoice.com": "UserVoice", "helpscoutdocs.com": "Help Scout",
    "cargo.site": "Cargo", "webflow.io": "Webflow", "strato.de": "Strato",
    "pantheon-sites.io": "Pantheon", "web.app": "Firebase",
    "firebaseapp.com": "Firebase", "web.appspot.com": "AppSpot",
}

# banner markers of an unclaimed/available takeover target
_CLAIM_MARKERS = re.compile(
    r"(?i)(heroku\s*\|.*no\s+such\s+app|there\s+isn'?t\s+a\s+github\s+pages\s+site"
    r"|no\s+app\s+is\s+configured|404\s+.*(?:not\s+found|error)|no\s+such\s+app"
    r"|repository\s+not\s+found|page\s+doesn'?t\s+exist|account\s+not\s+found"
    r"|site\s+not\s+found|domain\s+not\s+claimed|something\s+went\s+wrong)")

socket.setdefaulttimeout(TIMEOUT)


def _resolve(name):
    try:
        socket.gethostbyname(name)
        return True
    except Exception:
        return False


def enumerate_subdomains(domain, timeout_total=90):
    names = [domain, "www." + domain]
    names += [f"{s}.{domain}" for s in DEFAULT_SUBDOMAINS]
    alive = []
    with ThreadPoolExecutor(max_workers=32) as ex:
        futs = {ex.submit(_resolve, n): n for n in dict.fromkeys(names)}
        for f in as_completed(futs, timeout=timeout_total):
            n = futs[f]
            try:
                if f.result():
                    alive.append(n)
            except Exception:
                pass
    return sorted(set(alive))


def _cname(name):
    """Resolve the CNAME chain for a name via system nslookup. Returns first CNAME host or ''."""
    try:
        out = subprocess.run(
            ["nslookup", "-type=CNAME", name, DNS],
            capture_output=True, text=True, timeout=6, errors="replace").stdout
    except Exception:
        return ""
    m = re.search(r"canonical\s+name\s*=\s*(\S+)", out, re.I)
    return m.group(1).rstrip(".") if m else ""


def _banner(url):
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Mozilla/5.0 VulnScanTakeover (read-only)")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=6) as r:
            return r.getcode(), r.read(60000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, ""


def scan_domain(domain, timeout_total=90):
    domain = (domain or "").strip().lower()
    domain = re.sub(r"^https?://", "", domain).rstrip("/")
    subdomains = enumerate_subdomains(domain, timeout_total)
    results = []
    scanned = 0
    for sd in subdomains:
        cname = _cname(sd)
        if not cname:
            continue
        service = None
        cl = cname.lower()
        for suffix, label in TAKEOVER_SERVICES.items():
            if cl == suffix or cl.endswith("." + suffix):
                service = label
                break
        if service is None:
            continue
        # passive banner check
        banner = _banner("https://" + sd)
        marker = False
        if banner[0] is not None:
            marker = bool(_CLAIM_MARKERS.search(banner[1] or ""))
        scanned += 1
        results.append({
            "subdomain": sd, "cname": cname, "service": service,
            "status": banner[0], "marker": marker,
            "candidate": marker,
        })
    # top-level domain itself
    tc = _cname(domain)
    if tc:
        service = None
        cl = tc.lower()
        for suffix, label in TAKEOVER_SERVICES.items():
            if cl == suffix or cl.endswith("." + suffix):
                service = label
                break
        if service:
            banner = _banner("https://" + domain)
            marker = bool(banner[0] is not None and _CLAIM_MARKERS.search(banner[1] or ""))
            results.insert(0, {"subdomain": domain, "cname": tc, "service": service,
                               "status": banner[0], "marker": marker, "candidate": marker})
    info = {"domain": domain, "subdomain_count": len(subdomains), "checked": scanned}
    return results, info


def generate_report(results, info, out_path, scanned_at=None):
    scanned_at = scanned_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    disclaimer = ("免责声明：本子域接管检测由 VulnScan 生成，仅用于你有权测试的资产；"
                  "仅做 DNS 查询与被动 banner 探测，未做任何接管/利用动作，命中为候选需人工确认。")
    total = len(results)
    candidates = [r for r in results if r["candidate"]]
    head = (f'<div style="display:flex;flex-wrap:wrap;gap:10px;margin:14px 0;">'
            f'<div style="flex:1;min-width:110px;background:#2f9e57;border-radius:10px;padding:12px;color:#fff;'
            f'text-align:center;"><div style="font-size:24px;font-weight:700;">{total}</div>'
            f'<div style="font-size:12px;opacity:.9;">CNAME 指向第三方</div></div>'
            f'<div style="flex:1;min-width:110px;background:#d64545;border-radius:10px;padding:12px;color:#fff;'
            f'text-align:center;"><div style="font-size:24px;font-weight:700;">{len(candidates)}</div>'
            f'<div style="font-size:12px;opacity:.9;">疑似可接管</div></div></div>')
    if results:
        rows = "".join(
            f'<tr><td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#6b7280;">{i}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:13px;font-weight:600;">{r["subdomain"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#6b7280;word-break:break-all;">{r["cname"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#374151;">{r["service"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#6b7280;">{r["status"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;">'
            f'{"<span style=background:#d64545;color:#fff;border-radius:4px;padding:1px 6px;font-size:12px;>疑似可接管</span>" if r["candidate"] else "<span style=color:#2f9e57>已配置</span>"}</td></tr>'
            for i, r in enumerate(results, 1))
        table = (f'<table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e3e6ec;'
                 f'border-radius:10px;overflow:hidden;"><thead><tr style="background:#f6f8fb;">'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">#</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">子域名</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">CNAME</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">第三方服务</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">状态码</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">判定</th>'
                 f'</tr></thead><tbody>{rows}</tbody></table>')
    else:
        table = ('<div style="background:#eef7ee;border:1px solid #c9e4cf;border-radius:10px;padding:16px;'
                 'color:#2f6f4f;font-size:14px;">未发现 CNAME 指向第三方服务的子域名。</div>')
    doc = (f'<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">'
           f'<title>子域接管检测报告</title></head>'
           f'<body style="margin:0;background:#f6f8fb;font-family:\'Microsoft YaHei\',sans-serif;">'
           f'<div style="max-width:1080px;margin:0 auto;padding:24px;">'
           f'<div style="display:flex;justify-content:space-between;align-items:baseline;">'
           f'<h1 style="font-size:22px;margin:0;">子域接管检测报告</h1>'
           f'<span style="color:#8a93a6;font-size:12px;">{PRODUCT} v{VERSION}</span></div>'
           f'<div style="color:#8a93a6;font-size:13px;margin:6px 0 8px;">'
           f'域名：{info.get("domain","")} · 枚举子域 {info.get("subdomain_count",0)} · CNAME 检查 {info.get("checked",0)} · {scanned_at}</div>'
           f'{head}{table}'
           f'<div style="margin-top:20px;padding:12px;border-top:1px solid #e3e6ec;color:#9aa3b2;'
           f'font-size:12px;">{disclaimer}</div></div></body></html>')
    with open(out_path, "w", encoding="utf-8") as fp:
        fp.write(doc)
    return out_path


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    domain = args[0]
    out = None
    if "--out" in args:
        out = args[args.index("--out") + 1]
    results, info = scan_domain(domain)
    print(f"域名: {info.get('domain')}  枚举子域 {info.get('subdomain_count')} 个, CNAME 检查 {info.get('checked')} 个")
    for r in results:
        tag = "疑似可接管!" if r["candidate"] else "已配置"
        print(f"  {r['subdomain']} -> {r['cname']} [{r['service']}] {r['status']} {tag}")
    if out:
        generate_report(results, info, out)
        print(f"报告已生成: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
