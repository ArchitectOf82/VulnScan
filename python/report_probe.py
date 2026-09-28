# -*- coding: utf-8 -*-
"""
VulnScan - Module 10 report generator.
Reads probe results (dict with url/findings) and writes an HTML report:
stat card + grouped issue list with severity + fix suggestions.

Usage:  python report_probe.py <findings.json> <out.html> [--url URL]
"""

import sys
import json
from datetime import datetime

_RISK_CN = {"high": "高危", "medium": "中危", "low": "低危"}
_RISK_COLOR = {"high": "#d64545", "medium": "#e0872a", "low": "#9aa3b2"}


def _stat_card(total, by, scanned_at, url):
    cards = ""
    for r in ("high", "medium", "low"):
        n = by.get(r, 0)
        color = _RISK_COLOR[r]
        cards += (f'<div style="flex:1;background:#fff;border:1px solid #e3e6ec;'
                  f'border-radius:10px;padding:14px;text-align:center;min-width:120px;">'
                  f'<div style="font-size:28px;font-weight:700;color:{color};">{n}</div>'
                  f'<div style="font-size:13px;color:#8a93a6;">{_RISK_CN[r]}</div></div>')
    return (f'<div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px;">'
            f'<div style="flex:1;background:#2f9e57;border-radius:10px;padding:14px;color:#fff;min-width:120px;">'
            f'<div style="font-size:28px;font-weight:700;">{total}</div>'
            f'<div style="font-size:13px;opacity:.9;">可报告项</div></div>'
            f'{cards}</div>'
            f'<div style="color:#8a93a6;font-size:13px;margin-bottom:8px;">'
            f'目标：{url} · {scanned_at} · 只读探测，不含任何利用</div>')


def _issue_rows(findings):
    rows = []
    for i, f in enumerate(findings, 1):
        color = _RISK_COLOR.get(f["risk"], "#9aa3b2")
        rows.append(
            f'<tr><td style="padding:8px 10px;border-bottom:1px solid #eef1f5;'
            f'font-size:12px;color:#6b7280;">{i}</td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid #eef1f5;font-size:13px;">'
            f'<span style="background:{color};color:#fff;border-radius:4px;'
            f'padding:1px 6px;font-size:12px;">{_RISK_CN.get(f["risk"], f["risk"])}</span>'
            f' {f["category"]}</td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid #eef1f5;font-size:12px;'
            f'color:#374151;word-break:break-all;">{f["url"]}</td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid #eef1f5;font-size:13px;">'
            f'{f["detail"]}<div style="font-size:12px;color:#8a93a6;margin-top:3px;">'
            f'修复：{f["suggestion"]}</div></td></tr>')
    return "".join(rows)


def generate_probe_report(payload, out_path, url=None, scanned_at=None):
    findings = payload.get("findings", []) if isinstance(payload, dict) else payload
    target = (payload.get("url") if isinstance(payload, dict) else url) or url or ""
    scanned_at = scanned_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    by = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        by[f["risk"]] = by.get(f["risk"], 0) + 1
    total = len(findings)
    body = _stat_card(total, by, scanned_at, target)
    if not findings:
        body += ('<div style="background:#eef7ee;border:1px solid #c9e4cf;border-radius:10px;'
                 'padding:16px;color:#2f6f4f;font-size:14px;">未发现可报告项。'
                 '（若目标有反爬/需登录，可先确认可达性后再评估）</div>')
    else:
        body += (f'<table style="width:100%;border-collapse:collapse;background:#fff;'
                 f'border:1px solid #e3e6ec;border-radius:10px;overflow:hidden;">'
                 f'<thead><tr style="background:#f6f8fb;">'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">#</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">级别/类别</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">URL</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">问题与修复建议</th>'
                 f'</tr></thead><tbody>{_issue_rows(findings)}</tbody></table>')
    doc = (f'<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">'
           f'<title>Web 在线业务探测报告</title></head>'
           f'<body style="margin:0;background:#f6f8fb;font-family:\'Microsoft YaHei\',sans-serif;">'
           f'<div style="max-width:1080px;margin:0 auto;padding:24px;">'
           f'<h1 style="font-size:24px;margin:0 0 4px;">Web 在线业务探测报告</h1>'
           f'<div style="color:#8a93a6;font-size:13px;margin-bottom:16px;">'
           f'VulnScan 模块10 · 只读探测（不含利用）</div>{body}</div></body></html>')
    with open(out_path, "w", encoding="utf-8") as fp:
        fp.write(doc)
    return out_path


def main():
    args = sys.argv[1:]
    if len(args) < 2:
        print(__doc__)
        return 1
    src, out = args[0], args[1]
    url = None
    if "--url" in args:
        url = args[args.index("--url") + 1]
    with open(src, "r", encoding="utf-8") as fp:
        payload = json.load(fp)
    generate_probe_report(payload, out, url=url)
    print(f"报告已生成: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
