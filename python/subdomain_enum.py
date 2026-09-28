# -*- coding: utf-8 -*-
"""
VulnScan - Module 11: Subdomain Enumeration (READ-ONLY, DNS-based).

Enumerates common subdomains of an authorized domain via DNS A/AAAA lookups,
reports resolved hostnames + IPs. Pure passive DNS query, no payload, no
exploitation. Only for domains you are authorized to test.

Usage:  python subdomain_enum.py <domain> [--out report.html] [--wordlist file]
"""

import sys
import os
import json
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

VERSION = "1.0.0"
PRODUCT = "VulnScan"

socket.setdefaulttimeout(3)  # apply to all socket ops (connect etc.)

# Common subdomain dictionary (extendable via --wordlist)
DEFAULT_SUBDOMAINS = [
    "www", "mail", "smtp", "pop", "imap", "ftp", "sftp", "ns1", "ns2", "mx",
    "api", "api1", "api2", "dev", "test", "stage", "staging", "qa", "uat",
    "beta", "demo", "pre", "preview", "internal", "intranet", "private",
    "admin", "manage", "manager", "portal", "web", "www2", "app", "apps",
    "m", "mobile", "shop", "store", "order", "pay", "payment", "billing",
    "login", "auth", "sso", "account", "accounts", "user", "users",
    "blog", "news", "forum", "community", "help", "support", "docs", "wiki",
    "cdn", "static", "assets", "img", "images", "media", "download",
    "vpn", "remote", "webmail", "owa", "exchange", "git", "jenkins",
    "ci", "build", "deploy", "monitor", "grafana", "prometheus", "kibana",
    "status", "health", "metrics", "log", "logs", "trace", "debug",
    "db", "database", "mysql", "redis", "mq", "rabbitmq", "kafka",
    "elastic", "es", "search", "solr", "cache", "memcached",
    "files", "upload", "download", "backup", "archive", "old", "new",
    "game", "games", "chat", "im", "video", "live", "stream", "vr",
]

_TIMEOUT = 3


def resolve(sub, domain):
    """Return first A-record IP(s) for sub.domain, or None."""
    host = f"{sub}.{domain}" if sub else domain
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        addrs = []
        for i in infos:
            ip = i[4][0]
            if ip not in addrs:
                addrs.append(ip)
        return host, addrs
    except socket.gaierror:
        return host, []
    except Exception:
        return host, []


def _load_wordlist(path):
    words = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fp:
        for line in fp:
            w = line.strip().lower()
            if w and not w.startswith("#"):
                words.append(w)
    return words


def enumerate_subdomains(domain, wordlist=None):
    domain = (domain or "").strip().lower().lstrip(".")
    if not domain:
        return [], {}
    words = _load_wordlist(wordlist) if wordlist else DEFAULT_SUBDOMAINS
    meta = {"domain": domain, "wordlist_size": len(words)}
    found = []
    # concurrent DNS resolve with an overall cap so slow/unreachable DNS
    # never hangs the scan
    with ThreadPoolExecutor(max_workers=32) as ex:
        futs = {ex.submit(resolve, sub, domain): sub for sub in words}
        for fut in as_completed(futs, timeout=90):
            try:
                host, ips = fut.result(timeout=4)
            except Exception:
                continue
            if ips:
                found.append({"host": host, "ips": ips})
    # also the apex itself
    apex, apex_ips = resolve("", domain)
    if apex_ips:
        found.append({"host": apex, "ips": apex_ips, "apex": True})
    return found, meta


def _page(title, scanned_at, meta, rows_html, disclaimer):
    return (f'<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">'
            f'<title>{title}</title></head>'
            f'<body style="margin:0;background:#f6f8fb;font-family:\'Microsoft YaHei\',sans-serif;">'
            f'<div style="max-width:1080px;margin:0 auto;padding:24px;">'
            f'<div style="display:flex;justify-content:space-between;align-items:baseline;">'
            f'<h1 style="font-size:22px;margin:0;">{title}</h1>'
            f'<span style="color:#8a93a6;font-size:12px;">{PRODUCT} v{VERSION}</span></div>'
            f'<div style="color:#8a93a6;font-size:13px;margin:6px 0 16px;">'
            f'目标域名：{meta.get("domain","")} · 字典 {meta.get("wordlist_size","")} 条 · 扫描时间 {scanned_at} · 方式：DNS A/AAAA 只读查询</div>'
            f'{rows_html}'
            f'<div style="margin-top:20px;padding:12px;border-top:1px solid #e3e6ec;'
            f'color:#9aa3b2;font-size:12px;">{disclaimer}</div>'
            f'</div></body></html>')


def generate_report(found, meta, out_path, scanned_at=None):
    scanned_at = scanned_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    disclaimer = ("免责声明：本报告由 VulnScan 生成，仅用于你有权测试的资产（自有、SRC/CNVD 授权范围）。"
                  "子域枚举为被动 DNS 查询，未发送任何攻击载荷。未授权使用后果自负。")
    if not found:
        body = ('<div style="background:#eef7ee;border:1px solid #c9e4cf;border-radius:10px;'
                'padding:16px;color:#2f6f4f;font-size:14px;">未发现可解析的子域（或 DNS 解析被限制）。'
                '可换更大字典或用 --wordlist 扩充。</div>')
    else:
        rows = []
        for i, f in enumerate(found, 1):
            ips = "、".join(f["ips"])
            tag = ' <span style="color:#8a93a6;font-size:12px;">(主域)</span>' if f.get("apex") else ""
            rows.append(
                f'<tr><td style="padding:8px 10px;border-bottom:1px solid #eef1f5;font-size:12px;'
                f'color:#6b7280;">{i}</td>'
                f'<td style="padding:8px 10px;border-bottom:1px solid #eef1f5;font-size:13px;">'
                f'<code>{f["host"]}</code>{tag}</td>'
                f'<td style="padding:8px 10px;border-bottom:1px solid #eef1f5;font-size:12px;'
                f'color:#374151;word-break:break-all;">{ips}</td></tr>')
        body = (f'<div style="display:flex;gap:10px;margin-bottom:14px;">'
                f'<div style="flex:1;background:#2f9e57;border-radius:10px;padding:14px;color:#fff;">'
                f'<div style="font-size:28px;font-weight:700;">{len(found)}</div>'
                f'<div style="font-size:13px;opacity:.9;">发现子域</div></div>'
                f'<div style="flex:1;background:#fff;border:1px solid #e3e6ec;border-radius:10px;padding:14px;color:#6b7280;">'
                f'<div style="font-size:28px;font-weight:700;">{meta.get("wordlist_size","")}</div>'
                f'<div style="font-size:13px;">探测字典</div></div></div>'
                f'<table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e3e6ec;'
                f'border-radius:10px;overflow:hidden;"><thead><tr style="background:#f6f8fb;">'
                f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">#</th>'
                f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">主机名</th>'
                f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">解析 IP</th>'
                f'</tr></thead><tbody>{"".join(rows)}</tbody></table>')
    doc = _page("子域名枚举报告", scanned_at, meta, body, disclaimer)
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
    wordlist = None
    if "--out" in args:
        out = args[args.index("--out") + 1]
    if "--wordlist" in args:
        wordlist = args[args.index("--wordlist") + 1]
    found, meta = enumerate_subdomains(domain, wordlist)
    print(f"域名: {domain}  字典: {meta['wordlist_size']}  发现子域: {len(found)}")
    for f in found:
        print(f"  {f['host']}  ->  {'、'.join(f['ips'])}")
    if out:
        generate_report(found, meta, out)
        print(f"报告已生成: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
