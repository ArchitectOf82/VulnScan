# -*- coding: utf-8 -*-
"""
VulnScan - Module 15: Web Tech-Stack Fingerprinting (READ-ONLY).

Sends a single harmless GET to a target and identifies the web technologies in
use (server / framework / CMS / language / frontend / CDN-WAF) by matching
response headers and page markers. Identification only; no injection.

Usage:  python web_fingerprint.py <url> [--out report.html]
"""

import sys
import os
import re
import ssl
import urllib.request
import urllib.error
from datetime import datetime

VERSION = "1.0.0"
PRODUCT = "VulnScan"
UA = ("Mozilla/5.0 (compatible; VulnScanFp/1.0; read-only; "
      "authorized-target-only)")
TIMEOUT = 8

# rules: (name, type, [(field, pattern)], confidence)
# field: "header:<name>"  |  "body"
FINGERPRINTS = [
    # ---- servers / middleware ----
    ("nginx", "服务器", [("header:server", r"nginx")], 3),
    ("openresty", "服务器", [("header:server", r"openresty")], 3),
    ("Apache", "服务器", [("header:server", r"apache")], 3),
    ("Microsoft IIS", "服务器", [("header:server", r"(iis|microsoft-iis)")], 3),
    ("Apache Tomcat", "中间件", [("header:server", r"tomcat"), ("body", r"apache tomcat")], 3),
    ("Jetty", "中间件", [("header:server", r"jetty")], 3),
    ("Tengine", "服务器", [("header:server", r"tengine")], 3),
    ("gunicorn", "服务器", [("header:server", r"gunicorn")], 3),
    ("Werkzeug", "服务器", [("header:server", r"werkzeug")], 3),
    ("OpenResty/Lua", "服务器", [("header:server", r"openresty")], 2),
    # ---- languages / platforms ----
    ("PHP", "语言", [("header:x-powered-by", r"php"), ("body", r"\bphp\b")], 2),
    ("Python", "语言", [("header:x-powered-by", r"python"), ("header:server", r"python"), ("body", r"python(?:/[\d.]+)?")], 2),
    ("Node.js", "语言", [("header:x-powered-by", r"node"), ("header:server", r"express|node")], 2),
    ("Java", "语言", [("header:x-powered-by", r"java|jsp"), ("body", r"(javax\.faces|jsp|servlet)")], 2),
    ("Ruby", "语言", [("header:server", r"passenger|puma|unicorn|ruby")], 2),
    ("Go", "语言", [("header:x-powered-by", r"go"), ("body", r"(go-echo|gin-|beego)")], 2),
    ("ASP.NET", "语言", [("header:x-aspnet-version", r".+"), ("body", r"__viewstate|__requestverificationtoken")], 2),
    # ---- frameworks ----
    ("ThinkPHP", "框架", [("header:x-powered-by", r"thinkphp"), ("body", r"(thinkphp|/index\.php\?s=)")], 3),
    ("Laravel", "框架", [("header:x-powered-by", r"laravel"), ("body", r"laravel_session")], 3),
    ("Spring", "框架", [("header:x-application-context", r".+"), ("body", r"whitelabel error page|spring[ -]?framework")], 3),
    ("Apache Struts2", "框架", [("body", r"struts"), ("header:server", r"struts")], 3),
    ("Apache Shiro", "框架", [("header:set-cookie", r"rememberMe=")], 3),
    ("Django", "框架", [("header:server", r"django"), ("body", r"csrfmiddlewaretoken|django\.contrib")], 3),
    ("Flask", "框架", [("header:x-powered-by", r"flask"), ("header:server", r"werkzeug"), ("body", r"flask")], 2),
    ("Express", "框架", [("header:x-powered-by", r"express")], 2),
    ("Ruby on Rails", "框架", [("header:x-powered-by", r"rails"), ("header:server", r"passenger"), ("body", r"rails")], 3),
    ("CodeIgniter", "框架", [("header:set-cookie", r"ci_session")], 3),
    ("Yii", "框架", [("header:set-cookie", r"yii"), ("body", r"yii")], 2),
    # ---- CMS ----
    ("WordPress", "CMS", [("body", r"/wp-content/|/wp-includes/|wp-json|wordpress")], 3),
    ("Drupal", "CMS", [("body", r"/sites/default/files|drupal|generator[^>]*drupal")], 3),
    ("Joomla", "CMS", [("body", r"/media/system/js|joomla|generator[^>]*joomla")], 3),
    ("Discuz!", "CMS", [("body", r"discuz!|powered by discuz")], 3),
    ("DedeCMS(织梦)", "CMS", [("body", r"dedecms|powered by dedecms")], 3),
    ("帝国CMS", "CMS", [("body", r"ecms|powered by ecms")], 2),
    ("PHPCMS", "CMS", [("body", r"phpcms")], 2),
    ("Z-Blog", "CMS", [("body", r"z-blog|zbp|zcms")], 2),
    # ---- frontend ----
    ("Vue.js", "前端", [("body", r"vue(?:\.min)?\.js|_vue|<div\s+id=\"app\"")], 2),
    ("React", "前端", [("body", r"react(?:\.production)?\.min\.js|_reactrootcontainer|create-react-app")], 2),
    ("jQuery", "前端", [("body", r"jquery(?:\.min)?\.js")], 2),
    ("Angular", "前端", [("body", r"angular(?:\.min)?\.js|ng-app=")], 2),
    ("Bootstrap", "前端", [("body", r"bootstrap(?:\.min)?\.(?:css|js)")], 2),
    ("Element UI", "前端", [("body", r"element-ui|element\.js")], 2),
    # ---- CDN / WAF / cloud ----
    ("Cloudflare", "CDN/WAF", [("header:server", r"cloudflare"), ("header:cf-ray", r".+")], 3),
    ("阿里云 WAF/Tengine", "CDN/WAF", [("header:server", r"tengine"), ("header:x-cache", r"(Aliyun|M[0-9a-f])"), ("body", r"alicdn|aliyun")], 2),
    ("腾讯云", "CDN/WAF", [("body", r"cloud\.tencent\.com|tencent")], 2),
    ("七牛云", "CDN/WAF", [("header:server", r"qiniu"), ("body", r"qiniu")], 2),
    ("AWS CloudFront", "CDN/WAF", [("header:x-amz-cf-id", r".+"), ("header:server", r"cloudfront")], 3),
    ("百度云加速", "CDN/WAF", [("header:server", r"bce|baiducdn|yunjiasu"), ("header:x-cache", r"yun")], 2),
]


def _get(url):
    req = urllib.request.Request(url)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "text/html,application/xhtml+xml,*/*")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            data = r.read(1_000_000)
            headers = {k.lower(): v for k, v in r.headers.items()}
            text = data.decode("utf-8", errors="replace")
            return {"ok": True, "status": r.getcode(), "headers": headers, "text": text}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "headers": {}, "text": "", "error": str(e)}
    except Exception as e:
        return {"ok": False, "status": None, "headers": {}, "text": "", "error": str(e)}


def probe(url):
    url = (url or "").strip()
    if "://" not in url:
        url = "https://" + url
    r = _get(url)
    info = {"url": url, "ok": r["ok"], "status": r["status"]}
    found = []
    if not r["ok"]:
        return found, info
    headers, text = r["headers"], r["text"]
    seen = set()
    for name, ftype, rules, conf in FINGERPRINTS:
        evidence = None
        for field, pattern in rules:
            rx = re.compile(pattern, re.I)
            if field.startswith("header:"):
                hname = field.split(":", 1)[1]
                val = headers.get(hname)
                if val and rx.search(val):
                    evidence = f"{hname}: {val.strip()[:60]}"
                    break
            else:
                m = rx.search(text)
                if m:
                    evidence = m.group(0)[:60]
                    break
        if evidence and name not in seen:
            seen.add(name)
            found.append({"name": name, "type": ftype, "evidence": evidence,
                          "confidence": conf})
    return found, info


def generate_report(found, info, out_path, scanned_at=None):
    scanned_at = scanned_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    disclaimer = ("免责声明：本指纹识别由 VulnScan 生成，仅用于你有权测试的资产；"
                  "仅发送无害 GET 识别技术栈，未发送任何攻击载荷。")
    if found:
        types = {}
        for f in found:
            types[f["type"]] = types.get(f["type"], 0) + 1
        tcards = "".join(
            f'<div style="flex:1;min-width:110px;background:#fff;border:1px solid #e3e6ec;'
            f'border-radius:10px;padding:12px;text-align:center;"><div style="font-size:22px;'
            f'font-weight:700;color:#2f9e57;">{n}</div><div style="font-size:12px;color:#8a93a6;">'
            f'{t}</div></div>' for t, n in sorted(types.items(), key=lambda x: -x[1]))
        head = (f'<div style="display:flex;flex-wrap:wrap;gap:10px;margin:14px 0;">'
                f'<div style="flex:1;min-width:110px;background:#2f9e57;border-radius:10px;padding:12px;'
                f'color:#fff;text-align:center;"><div style="font-size:24px;font-weight:700;">{len(found)}</div>'
                f'<div style="font-size:12px;opacity:.9;">识别技术栈</div></div>{tcards}</div>')
        rows = "".join(
            f'<tr><td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#6b7280;">{i}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:13px;font-weight:600;">{f["name"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#6b7280;">{f["type"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#374151;word-break:break-all;">{f["evidence"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;">'
            f'{"<span style=color:#2f9e57>高</span>" if f["confidence"]==3 else "<span style=color:#e0872a>中</span>" if f["confidence"]==2 else "<span style=color:#9aa3b2>低</span>"}</td></tr>'
            for i, f in enumerate(found, 1))
        table = (f'<table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e3e6ec;'
                 f'border-radius:10px;overflow:hidden;"><thead><tr style="background:#f6f8fb;">'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">#</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">技术栈</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">类型</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">命中依据</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">置信</th>'
                 f'</tr></thead><tbody>{rows}</tbody></table>')
    else:
        head = ('<div style="background:#eef7ee;border:1px solid #c9e4cf;border-radius:10px;padding:16px;'
                'color:#2f6f4f;font-size:14px;margin:14px 0;">未识别到明确技术栈（目标不可达、或页面特征不明显）。</div>')
        table = ""
    doc = (f'<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">'
           f'<title>Web 技术栈指纹识别报告</title></head>'
           f'<body style="margin:0;background:#f6f8fb;font-family:\'Microsoft YaHei\',sans-serif;">'
           f'<div style="max-width:1080px;margin:0 auto;padding:24px;">'
           f'<div style="display:flex;justify-content:space-between;align-items:baseline;">'
           f'<h1 style="font-size:22px;margin:0;">Web 技术栈指纹识别报告</h1>'
           f'<span style="color:#8a93a6;font-size:12px;">{PRODUCT} v{VERSION}</span></div>'
           f'<div style="color:#8a93a6;font-size:13px;margin:6px 0 8px;">'
           f'目标：{info.get("url","")} · 状态 {info.get("status","")} · 扫描时间 {scanned_at}</div>'
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
    url = args[0]
    out = None
    if "--out" in args:
        out = args[args.index("--out") + 1]
    found, info = probe(url)
    print(f"目标: {info.get('url')}  状态: {info.get('status')}")
    for f in found:
        print(f"  [{f['type']}] {f['name']}  ←  {f['evidence']}")
    if out:
        generate_report(found, info, out)
        print(f"报告已生成: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
