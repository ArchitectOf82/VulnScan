# -*- coding: utf-8 -*-
"""
VulnScan - Module 14: Online Sensitive-Info Leak Scan (READ-ONLY).

Fetches a target web page (harmless GET, direct connect, no proxy) and scans the
returned text with regex for leaked sensitive data: emails, internal IPs, cloud
tokens, private keys, connection strings, hardcoded passwords, API keys.
Detection only; no exploitation, no payloads. Authorized targets only.

Usage:  python online_leak.py <url> [--out report.html] [--depth N]
"""

import sys
import os
import json
import re
import ssl
import urllib.request
import urllib.error
from datetime import datetime

VERSION = "1.0.0"
PRODUCT = "VulnScan"
UA = ("Mozilla/5.0 (compatible; VulnScanLeak/1.0; read-only; "
      "authorized-target-only)")
TIMEOUT = 8

# (category, risk, regex) — tuned to avoid obvious placeholder hits
_PATTERNS = [
    ("私钥/证书泄露", "high",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("云厂商密钥(AWS)", "high",
     re.compile(r"(?i)\b(AKIA[0-9A-Z]{16}|aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{20,})")),
    ("GitHub Token", "high",
     re.compile(r"\b(ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{50,}|gho_[0-9A-Za-z]{36})")),
    ("数据库连接串", "high",
     re.compile(r"(?i)(mysql|postgres(?:ql)?|redis|mongodb|mssql|jdbc)\://[^\s\"'<>]{3,}")),
    ("硬编码口令", "medium",
     re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key|apikey)\s*[=:]\s*['\"](?!(?:xxx|changeme|your|placeholder|redacted|password|replaceme|example)\b)[^'\"\s]{6,}")),
    ("邮箱地址", "low",
     re.compile(r"[\w.+-]+@(?!\d{1,3}\.)[\w-]+(\.[a-zA-Z]{2,})+")),
    ("内网IP泄露", "medium",
     re.compile(r"\b(?:10\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")),
]

_HIGH = {"high", "medium"}


def _get(url):
    req = urllib.request.Request(url)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "text/html,application/xhtml+xml,*/*")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=TIMEOUT, context=ctx) as r:
            data = r.read(2_000_000)
            ctype = (r.headers.get("Content-Type") or "").lower()
            text = data.decode("utf-8", errors="replace")
            return {"ok": True, "status": r.getcode(), "ctype": ctype, "text": text}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "text": "", "ctype": ""}
    except Exception as e:
        return {"ok": False, "status": None, "text": "", "ctype": "", "error": str(e)}


def scan_text(text, url):
    findings = []
    for cat, risk, rx in _PATTERNS:
        seen = set()
        for m in rx.finditer(text):
            hit = m.group(0).strip()
            if len(hit) > 160:
                hit = hit[:160] + "..."
            if hit in seen:
                continue
            seen.add(hit)
            findings.append({"category": cat, "risk": risk, "url": url, "detail": hit,
                             "suggestion": "确认该信息是否应公开；若为真实密钥/口令请立即轮换并移出源码/页面。"})
    return findings


def scan_url(target, depth=1):
    target = (target or "").strip()
    if not target:
        return [], {"url": target, "ok": False}
    if "://" not in target:
        target = "https://" + target
    findings = []
    r = _get(target)
    info = {"url": target, "ok": r.get("ok"), "status": r.get("status")}
    if not r.get("ok"):
        return findings, info
    if "html" in r.get("ctype", ""):
        findings += scan_text(r["text"], target)
        # shallow same-origin crawl (depth 1, max 5 links, read-only)
        if depth > 0:
            links = re.findall(r'href=["\'](https?://[^"\']+)["\']', r["text"])
            seen = {target}
            grabbed = 0
            base = target.split("//", 1)[1]
            for link in links:
                if grabbed >= 5:
                    break
                try:
                    lu = urllib.request.urlparse(link)
                    lhost = lu.netloc.split(":")[0]
                    if lhost != base.split("/")[0].split(":")[0]:
                        continue
                except Exception:
                    continue
                if link in seen:
                    continue
                seen.add(link)
                lr = _get(link)
                if lr.get("ok") and "html" in lr.get("ctype", ""):
                    findings += scan_text(lr["text"], link)
                    grabbed += 1
    return findings, info


def _risk_cn(r):
    return {"high": "高危", "medium": "中危", "low": "低危"}.get(r, r)


def generate_report(findings, info, out_path, scanned_at=None):
    scanned_at = scanned_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    disclaimer = ("免责声明：本报告由 VulnScan 生成，仅用于你有权测试的资产。"
                  "检测为只读页面抓取 + 正则启发式，命中为候选，是否真泄露需人工核验。")
    total = len(findings)
    by = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        by[f["risk"]] = by.get(f["risk"], 0) + 1
    cards = "".join(
        f'<div style="flex:1;min-width:110px;background:#fff;border:1px solid #e3e6ec;'
        f'border-radius:10px;padding:12px;text-align:center;"><div style="font-size:24px;'
        f'font-weight:700;color:{"#d64545" if r=="high" else ("#e0872a" if r=="medium" else "#9aa3b2")};">{by.get(r,0)}</div>'
        f'<div style="font-size:12px;color:#8a93a6;">{_risk_cn(r)}</div></div>' for r in ("high", "medium", "low"))
    head = (f'<div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px;">'
            f'<div style="flex:1;min-width:110px;background:#2f9e57;border-radius:10px;padding:12px;'
            f'color:#fff;text-align:center;"><div style="font-size:24px;font-weight:700;">{total}</div>'
            f'<div style="font-size:12px;opacity:.9;">候选命中</div></div>{cards}</div>')
    if findings:
        rows = "".join(
            f'<tr><td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#6b7280;">{i}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:13px;">'
            f'<span style="background:{"#d64545" if f["risk"]=="high" else ("#e0872a" if f["risk"]=="medium" else "#9aa3b2")};'
            f'color:#fff;border-radius:4px;padding:1px 6px;font-size:12px;">{_risk_cn(f["risk"])}</span> {f["category"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#374151;word-break:break-all;">{f["url"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#374151;word-break:break-all;">{f["detail"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#8a93a6;">{f["suggestion"]}</td></tr>'
            for i, f in enumerate(findings, 1))
        table = (f'<table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e3e6ec;'
                 f'border-radius:10px;overflow:hidden;"><thead><tr style="background:#f6f8fb;">'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">#</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">级别/类别</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">来源页面</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">命中内容</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">处置建议</th>'
                 f'</tr></thead><tbody>{rows}</tbody></table>')
    else:
        table = ('<div style="background:#eef7ee;border:1px solid #c9e4cf;border-radius:10px;padding:16px;'
                 'color:#2f6f4f;font-size:14px;">未发现敏感信息候选（或目标不可达/非 HTML）。</div>')
    doc = (f'<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">'
           f'<title>在线敏感信息泄露扫描报告</title></head>'
           f'<body style="margin:0;background:#f6f8fb;font-family:\'Microsoft YaHei\',sans-serif;">'
           f'<div style="max-width:1080px;margin:0 auto;padding:24px;">'
           f'<div style="display:flex;justify-content:space-between;align-items:baseline;">'
           f'<h1 style="font-size:22px;margin:0;">在线敏感信息泄露扫描报告</h1>'
           f'<span style="color:#8a93a6;font-size:12px;">{PRODUCT} v{VERSION}</span></div>'
           f'<div style="color:#8a93a6;font-size:13px;margin:6px 0 16px;">'
           f'目标：{info.get("url","")} · 状态 {info.get("status","")} · 扫描时间 {scanned_at} · 方式：只读页面抓取</div>'
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
    target = args[0]
    out = None
    depth = 1
    if "--out" in args:
        out = args[args.index("--out") + 1]
    if "--depth" in args:
        try:
            depth = int(args[args.index("--depth") + 1])
        except Exception:
            depth = 1
    findings, info = scan_url(target, depth=depth)
    print(f"目标: {info.get('url')}  可达: {info.get('ok')}  状态: {info.get('status')}")
    print(f"候选命中 {len(findings)} 项")
    for f in findings[:15]:
        print(f"  [{_risk_cn(f['risk'])}] {f['category']} :: {f['detail'][:80]}")
    if out:
        generate_report(findings, info, out)
        print(f"报告已生成: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
