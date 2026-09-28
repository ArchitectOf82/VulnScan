# -*- coding: utf-8 -*-
"""
VulnScan - Module 16: JS Sensitive-Info & Endpoint Extraction (READ-ONLY).

Fetches the target page, discovers its JavaScript files, and scans them for
leaked secrets (cloud keys / tokens), internal addresses, cloud/OSS assets and
API endpoints. Passive read of scripts only; no execution, no payloads.

Usage:  python js_extract.py <url> [--out report.html] [--max-js N]
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
UA = ("Mozilla/5.0 (compatible; VulnScanJs/1.0; read-only; "
      "authorized-target-only)")
TIMEOUT = 8
MAX_JS = 8

# (category, risk, regex)
_PATTERNS = [
    ("云厂商密钥", "high",
     re.compile(r"(?i)(AKIA[0-9A-Z]{16}|aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{20,}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36}|sk-[a-zA-Z0-9]{20,})")),
    ("Token/访问凭证", "high",
     re.compile(r"(?i)(access_token|auth_token|refresh_token|client_secret|secret_key|api[_-]?key|apikey|token)\s*[:=]\s*['\"](?!(?:xxx|xxx=|your|placeholder|undefined|null|token)\b)[^'\"\s]{8,}")),
    ("授权头/口令", "high",
     re.compile(r"(?i)(authorization|password|passwd)\s*[:=]\s*['\"](?!(?:xxx|placeholder)\b)[^'\"\s]{6,}")),
    ("内网地址", "medium",
     re.compile(r"\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b|localhost|127\.0\.0\.1")),
    ("内网域名", "medium",
     re.compile(r"\b[\w-]+\.(?:internal|corp|local|intranet|lan)(?::\d+)?\b")),
    ("云/OSS 资源", "medium",
     re.compile(r"(?i)([\w-]+\.oss[-cn]{2}[\w.-]*\.aliyuncs\.com|[\w-]+\.s3[.-][\w.-]*amazonaws\.com|[\w-]+\.blob\.core\.windows\.net|[\w-]+\.(?:qiniucdn|clouddn|b0\.upaiyun)\.com|[\w-]+\.firebaseio\.com|[\w-]+\.cloudfront\.net)")),
    ("API 端点", "low",
     re.compile(r"['\"`]((?:/api/|/v\d+/|/graphql|/rest/|/auth/|/upload|/download|/admin|/manage|/debug|/console|/swagger|/ws)[\w\-/{}.?&=]*)['\"`]")),
]


def _get(url):
    req = urllib.request.Request(url)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "*/*")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            data = r.read(3_000_000)
            return {"ok": True, "status": r.getcode(), "text": data.decode("utf-8", errors="replace")}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "text": ""}
    except Exception as e:
        return {"ok": False, "status": None, "text": "", "error": str(e)}


def _abs(base, src):
    if src.startswith("//"):
        return "https:" + src
    if src.startswith("http"):
        return src
    if src.startswith("/"):
        m = re.match(r"https?://[^/]+", base)
        return (m.group(0) if m else base) + src
    return base.rstrip("/") + "/" + src


def scan_js(text, url):
    findings = []
    for cat, risk, rx in _PATTERNS:
        seen = set()
        for m in rx.finditer(text):
            hit = m.group(0).strip()
            if len(hit) > 120:
                hit = hit[:120] + "..."
            if hit in seen:
                continue
            seen.add(hit)
            findings.append({"category": cat, "risk": risk, "url": url, "detail": hit})
    return findings


def scan_url(target, max_js=MAX_JS):
    target = (target or "").strip()
    if "://" not in target:
        target = "https://" + target
    r = _get(target)
    info = {"url": target, "ok": r["ok"], "status": r.get("status")}
    findings = []
    if not r["ok"]:
        return findings, info
    # discover js links
    page = r["text"]
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', page, re.I)
    srcs = [s for s in srcs if s.strip()]
    seen_src, js_urls = set(), []
    for s in srcs:
        u = _abs(target, s)
        if u not in seen_src:
            seen_src.add(u)
            js_urls.append(u)
    # inline scripts
    inline = " ".join(re.findall(r'<script(?![^>]*src)[^>]*>(.*?)</script>', page, re.S))
    if inline.strip():
        findings += scan_js(inline, target)
    # fetch js files (bounded)
    fetched = 0
    for u in js_urls:
        if fetched >= max_js:
            break
        jr = _get(u)
        if jr.get("ok"):
            findings += scan_js(jr["text"], u)
            fetched += 1
    info["js_count"] = len(js_urls)
    info["js_fetched"] = fetched
    return findings, info


def _risk_cn(r):
    return {"high": "高危", "medium": "中危", "low": "低危"}.get(r, r)


def generate_report(findings, info, out_path, scanned_at=None):
    scanned_at = scanned_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    disclaimer = ("免责声明：本 JS 提取由 VulnScan 生成，仅用于你有权测试的资产；"
                  "只读抓取脚本内容，未执行代码、未发送攻击载荷，命中为候选需人工核验。")
    total = len(findings)
    by = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        by[f["risk"]] = by.get(f["risk"], 0) + 1
    cards = "".join(
        f'<div style="flex:1;min-width:110px;background:#fff;border:1px solid #e3e6ec;border-radius:10px;'
        f'padding:12px;text-align:center;"><div style="font-size:24px;font-weight:700;'
        f'color:{"#d64545" if r=="high" else ("#e0872a" if r=="medium" else "#9aa3b2")};">{by.get(r,0)}</div>'
        f'<div style="font-size:12px;color:#8a93a6;">{_risk_cn(r)}</div></div>' for r in ("high", "medium", "low"))
    head = (f'<div style="display:flex;flex-wrap:wrap;gap:10px;margin:14px 0;">'
            f'<div style="flex:1;min-width:110px;background:#2f9e57;border-radius:10px;padding:12px;color:#fff;'
            f'text-align:center;"><div style="font-size:24px;font-weight:700;">{total}</div>'
            f'<div style="font-size:12px;opacity:.9;">候选命中</div></div>{cards}</div>')
    if findings:
        rows = "".join(
            f'<tr><td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#6b7280;">{i}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:13px;">'
            f'<span style="background:{"#d64545" if f["risk"]=="high" else ("#e0872a" if f["risk"]=="medium" else "#9aa3b2")};'
            f'color:#fff;border-radius:4px;padding:1px 6px;font-size:12px;">{_risk_cn(f["risk"])}</span> {f["category"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#8a93a6;word-break:break-all;">{f["url"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#374151;word-break:break-all;">{f["detail"]}</td></tr>'
            for i, f in enumerate(findings, 1))
        table = (f'<table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e3e6ec;'
                 f'border-radius:10px;overflow:hidden;"><thead><tr style="background:#f6f8fb;">'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">#</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">级别/类别</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">来源</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">命中内容</th>'
                 f'</tr></thead><tbody>{rows}</tbody></table>')
    else:
        table = ('<div style="background:#eef7ee;border:1px solid #c9e4cf;border-radius:10px;padding:16px;'
                 'color:#2f6f4f;font-size:14px;">未发现敏感信息（或目标不可达/无 JS）。</div>')
    doc = (f'<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">'
           f'<title>JS 敏感信息与端点提取报告</title></head>'
           f'<body style="margin:0;background:#f6f8fb;font-family:\'Microsoft YaHei\',sans-serif;">'
           f'<div style="max-width:1080px;margin:0 auto;padding:24px;">'
           f'<div style="display:flex;justify-content:space-between;align-items:baseline;">'
           f'<h1 style="font-size:22px;margin:0;">JS 敏感信息与端点提取报告</h1>'
           f'<span style="color:#8a93a6;font-size:12px;">{PRODUCT} v{VERSION}</span></div>'
           f'<div style="color:#8a93a6;font-size:13px;margin:6px 0 8px;">'
           f'目标：{info.get("url","")} · 状态 {info.get("status","")} · JS 文件 {info.get("js_count",0)} 个（抓取 {info.get("js_fetched",0)}）· {scanned_at}</div>'
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
    max_js = MAX_JS
    if "--out" in args:
        out = args[args.index("--out") + 1]
    if "--max-js" in args:
        try:
            max_js = int(args[args.index("--max-js") + 1])
        except Exception:
            pass
    findings, info = scan_url(url, max_js=max_js)
    print(f"目标: {info.get('url')}  状态: {info.get('status')}  候选命中 {len(findings)} 项")
    for f in findings[:15]:
        print(f"  [{_risk_cn(f['risk'])}] {f['category']} :: {f['detail'][:80]}")
    if out:
        generate_report(findings, info, out)
        print(f"报告已生成: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
