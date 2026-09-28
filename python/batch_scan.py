# -*- coding: utf-8 -*-
"""
VulnScan - Batch multi-target scan (READ-ONLY, online modules only).

Runs subdomain / TLS / online-leak (and optionally web-probe) against a list of
authorized targets and produces one consolidated report. No payloads, no
exploitation; authorized targets only.

Usage:
  python batch_scan.py --targets example.com,test.com [--mods subdomain,tls,onleak] [--out batch_report.html]
  python batch_scan.py --file targets.txt [--mods subdomain,tls,onleak] [--out batch_report.html]
  (default mods: subdomain,tls)
"""

import os
import re
import sys
from datetime import datetime

VERSION = "1.0.0"
PRODUCT = "VulnScan"


def _host_of(t):
    t = (t or "").strip().lower()
    t = re.sub(r"^[a-z]+://", "", t).split("/")[0]
    t = t.split(":")[0]
    return t


def parse_targets(inline, file):
    out = []
    if inline:
        out += [x.strip() for x in inline.split(",") if x.strip()]
    if file and os.path.isfile(file):
        with open(file, encoding="utf-8") as fp:
            out += [x.strip() for x in fp if x.strip() and not x.startswith("#")]
    seen = []
    for t in out:
        if t not in seen:
            seen.append(t)
    return seen


def scan_one(target, mods):
    host = _host_of(target)
    res = {"target": target, "host": host}
    if "subdomain" in mods:
        import subdomain_enum
        try:
            found, _ = subdomain_enum.enumerate_subdomains(host)
            res["subdomains"] = [x["host"] for x in found]
        except Exception as e:
            res["subdomains"] = []
            res["subdomain_error"] = str(e)[:120]
    if "tls" in mods:
        import tls_check
        try:
            fi, info = tls_check.check_tls(host)
            res["tls"] = {"proto": info.get("proto"), "cn": info.get("cn"),
                          "issuer": info.get("issuer_cn"),
                          "days_left": info.get("days_left"),
                          "reachable": bool(info.get("reachable")),
                          "findings": fi}
        except Exception as e:
            res["tls"] = {"reachable": False, "error": str(e)[:120], "findings": []}
    if "onleak" in mods:
        import online_leak
        url = target if "://" in target else "https://" + target
        try:
            f, info = online_leak.scan_url(url)
            res["leaks"] = f
        except Exception as e:
            res["leaks"] = []
            res["leak_error"] = str(e)[:120]
    if "webprobe" in mods:
        import web_probe, report_probe
        url = target if "://" in target else "https://" + target
        try:
            f, info = web_probe.probe(url)
            res["webprobe"] = f
        except Exception as e:
            res["webprobe"] = []
            res["webprobe_error"] = str(e)[:120]
    return res


def _risk_cn(r):
    return {"high": "高危", "medium": "中危", "low": "低危", "info": "信息"}.get(str(r).lower(), str(r))


def generate_report(results, mods, out_path):
    disclaimer = ("免责声明：本批量扫描由 VulnScan 生成，仅用于你有权测试的资产；"
                  "所有检测为只读（DNS/握手/页面抓取），未发送任何攻击载荷，未授权使用后果自负。")
    blocks = []
    total_find = 0
    for r in results:
        rows = []
        if r.get("subdomains"):
            sub = "、".join(r["subdomains"])
            rows.append(f'<tr><td style="padding:7px 10px;border-bottom:1px solid #eef1f5;">子域名枚举</td>'
                        f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;color:#2f9e57;">发现 {len(r["subdomains"])} 个</td>'
                        f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;color:#374151;word-break:break-all;">{sub}</td></tr>')
        elif "subdomain_error" in r:
            rows.append(f'<tr><td style="padding:7px 10px;border-bottom:1px solid #eef1f5;">子域名枚举</td>'
                        f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;color:#8a93a6;">未发现</td>'
                        f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;color:#8a93a6;">{r["subdomain_error"]}</td></tr>')
        else:
            rows.append(f'<tr><td style="padding:7px 10px;border-bottom:1px solid #eef1f5;">子域名枚举</td>'
                        f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;color:#8a93a6;">未发现</td>'
                        f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;color:#8a93a6;">-</td></tr>')
        if r.get("tls"):
            t = r["tls"]
            if t.get("reachable"):
                rows.append(f'<tr><td style="padding:7px 10px;border-bottom:1px solid #eef1f5;">TLS/证书</td>'
                            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;color:#2f9e57;">协议 {t.get("proto")} · 剩余 {t.get("days_left")} 天</td>'
                            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;color:#374151;">{t.get("cn")}（{t.get("issuer")}）发现 {len(t.get("findings") or [])} 项</td></tr>')
            else:
                rows.append(f'<tr><td style="padding:7px 10px;border-bottom:1px solid #eef1f5;">TLS/证书</td>'
                            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;color:#8a93a6;">不可达</td>'
                            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;color:#8a93a6;">{t.get("error","")}</td></tr>')
        if r.get("leaks"):
            for f in r["leaks"]:
                total_find += 1
                rows.append(f'<tr><td style="padding:7px 10px;border-bottom:1px solid #eef1f5;">敏感信息</td>'
                            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;"><span style="background:{"#d64545" if f["risk"]=="high" else ("#e0872a" if f["risk"]=="medium" else "#9aa3b2")};color:#fff;border-radius:4px;padding:1px 6px;">{_risk_cn(f["risk"])}</span> {f["category"]}</td>'
                            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;color:#374151;word-break:break-all;">{f["detail"][:90]}</td></tr>')
        if r.get("webprobe"):
            for f in r["webprobe"]:
                total_find += 1
                rows.append(f'<tr><td style="padding:7px 10px;border-bottom:1px solid #eef1f5;">Web探测</td>'
                            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;"><span style="background:{"#d64545" if f["risk"]=="high" else ("#e0872a" if f["risk"]=="medium" else "#9aa3b2")};color:#fff;border-radius:4px;padding:1px 6px;">{_risk_cn(f["risk"])}</span> {f["category"]}</td>'
                            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;color:#374151;word-break:break-all;">{f.get("detail","")[:90]}</td></tr>')
        if not rows:
            rows.append(f'<tr><td style="padding:7px 10px;border-bottom:1px solid #eef1f5;">-</td>'
                        f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;color:#8a93a6;">无异常发现</td>'
                        f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;color:#8a93a6;">-</td></tr>')
        blocks.append(
            f'<div style="background:#fff;border:1px solid #e3e6ec;border-radius:10px;margin-bottom:14px;overflow:hidden;">'
            f'<div style="padding:10px 14px;background:#f6f8fb;font-weight:700;font-size:14px;">{r["target"]}</div>'
            f'<table style="width:100%;border-collapse:collapse;"><tbody>{"".join(rows)}</tbody></table></div>')
    head = (f'<div style="display:flex;flex-wrap:wrap;gap:10px;margin:14px 0;">'
            f'<div style="flex:1;min-width:120px;background:#2f9e57;border-radius:10px;padding:12px;color:#fff;'
            f'text-align:center;"><div style="font-size:24px;font-weight:700;">{len(results)}</div>'
            f'<div style="font-size:12px;opacity:.9;">目标数</div></div>'
            f'<div style="flex:1;min-width:120px;background:#5b8def;border-radius:10px;padding:12px;color:#fff;'
            f'text-align:center;"><div style="font-size:24px;font-weight:700;">{total_find}</div>'
            f'<div style="font-size:12px;opacity:.9;">发现条目</div></div>'
            f'<div style="flex:1;min-width:120px;background:#8a93a6;border-radius:10px;padding:12px;color:#fff;'
            f'text-align:center;"><div style="font-size:24px;font-weight:700;">{"、".join(mods)}</div>'
            f'<div style="font-size:12px;opacity:.9;">启用模块</div></div></div>')
    doc = (f'<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">'
           f'<title>批量多目标扫描报告</title></head>'
           f'<body style="margin:0;background:#f6f8fb;font-family:\'Microsoft YaHei\',sans-serif;">'
           f'<div style="max-width:1080px;margin:0 auto;padding:24px;">'
           f'<div style="display:flex;justify-content:space-between;align-items:baseline;">'
           f'<h1 style="font-size:22px;margin:0;">批量多目标扫描报告</h1>'
           f'<span style="color:#8a93a6;font-size:12px;">{PRODUCT} v{VERSION}</span></div>'
           f'<div style="color:#8a93a6;font-size:13px;margin:6px 0 8px;">扫描时间 '
           f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>'
           f'{head}{"".join(blocks)}'
           f'<div style="margin-top:20px;padding:12px;border-top:1px solid #e3e6ec;color:#9aa3b2;'
           f'font-size:12px;">{disclaimer}</div></div></body></html>')
    with open(out_path, "w", encoding="utf-8") as fp:
        fp.write(doc)
    return out_path


def main():
    args = sys.argv[1:]
    if not args or ("--targets" not in args and "--file" not in args):
        print(__doc__)
        return 1
    inline = None
    file = None
    out = None
    mods = ["subdomain", "tls"]
    if "--targets" in args:
        inline = args[args.index("--targets") + 1]
    if "--file" in args:
        file = args[args.index("--file") + 1]
    if "--mods" in args:
        mods = [m.strip() for m in args[args.index("--mods") + 1].split(",") if m.strip()]
    if "--out" in args:
        out = args[args.index("--out") + 1]
    targets = parse_targets(inline, file)
    if not targets:
        print("[错误] 没有目标")
        return 1
    print(f"目标 {len(targets)} 个 · 模块 {mods}")
    results = []
    for t in targets:
        print(f"  → {t} ...")
        r = scan_one(t, mods)
        results.append(r)
    if out:
        generate_report(results, mods, out)
        print(f"批量报告已生成: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
