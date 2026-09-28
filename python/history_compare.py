# -*- coding: utf-8 -*-
"""
VulnScan - History Diff: compare two scan snapshots.

VulnScan saves a snapshot JSON (output/history/<stamp>_snapshot.json) after each
scan. This tool diffs two snapshots and reports what was ADDED (new findings),
FIXED (disappeared), and KEPT (still present) per module.

Usage:
  python history_compare.py --base <snapshot.json> --cur <snapshot.json> [--out report.html]
  python history_compare.py --list            # list available snapshots
"""

import os
import re
import sys
import json
from datetime import datetime

VERSION = "1.0.0"
PRODUCT = "VulnScan"

_FIND_KEYS = ("risk", "severity", "level", "detail", "vuln", "cve", "cve_id",
              "name", "port", "rule", "check", "pattern", "host", "category",
              "package", "version")


def collect_entries(results):
    """Return {module: {entry_key: (risk, desc)}} via generic recursion."""
    out = {}
    for mod, data in (results or {}).items():
        if not isinstance(data, (dict, list)):
            continue
        es = {}
        _collect(data, es)
        if es:
            out[mod] = es
    return out


def _leaf_key(obj):
    parts = []
    for k, v in sorted(obj.items()):
        if isinstance(v, (dict, list)):
            continue
        parts.append(f"{k}={v}")
    return " | ".join(parts)[:500]


def _collect(obj, es):
    if isinstance(obj, dict):
        if any(k in obj for k in _FIND_KEYS):
            key = _leaf_key(obj)
            if key:
                risk = obj.get("risk") or obj.get("severity") or obj.get("level") or "info"
                desc = (obj.get("detail") or obj.get("name") or obj.get("rule")
                        or obj.get("check") or obj.get("pattern") or obj.get("package")
                        or obj.get("host") or obj.get("category") or key[:120])
                es[key] = (str(risk), str(desc)[:160])
        for v in obj.values():
            if isinstance(v, (dict, list)):
                _collect(v, es)
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, (dict, list)):
                _collect(v, es)


def diff(base, cur):
    added, fixed, kept = {}, {}, {}
    for mod in set(base) | set(cur):
        b, c = base.get(mod, {}), cur.get(mod, {})
        a = {k: v for k, v in c.items() if k not in b}
        f = {k: v for k, v in b.items() if k not in c}
        kp = {k: v for k, v in c.items() if k in b}
        if a:
            added[mod] = a
        if f:
            fixed[mod] = f
        if kp:
            kept[mod] = kp
    return added, fixed, kept


def _risk_cn(r):
    return {"high": "高危", "medium": "中危", "low": "低危", "info": "信息"}.get(str(r).lower(), str(r))


def _table(title, color, mods):
    if not mods:
        return ""
    rows = []
    for mod, es in mods.items():
        for key, (risk, desc) in sorted(es.items()):
            rows.append(
                f'<tr><td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;'
                f'color:#6b7280;">{mod}</td>'
                f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;">'
                f'<span style="background:{color};color:#fff;border-radius:4px;padding:1px 6px;">{_risk_cn(risk)}</span></td>'
                f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;'
                f'color:#374151;word-break:break-all;">{desc}</td></tr>')
    return (f'<h2 style="font-size:16px;margin:18px 0 8px;color:{color};">{title}（{len(rows)}）</h2>'
            f'<table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e3e6ec;'
            f'border-radius:10px;overflow:hidden;"><thead><tr style="background:#f6f8fb;">'
            f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">模块</th>'
            f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">级别</th>'
            f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">条目</th>'
            f'</tr></thead><tbody>{"".join(rows)}</tbody></table>')


def generate_report(base_meta, cur_meta, added, fixed, kept, out_path):
    n_add = sum(len(v) for v in added.values())
    n_fix = sum(len(v) for v in fixed.values())
    n_keep = sum(len(v) for v in kept.values())
    cards = (f'<div style="display:flex;flex-wrap:wrap;gap:10px;margin:14px 0;">'
             f'<div style="flex:1;min-width:120px;background:#d64545;border-radius:10px;padding:12px;color:#fff;'
             f'text-align:center;"><div style="font-size:24px;font-weight:700;">{n_add}</div>'
             f'<div style="font-size:12px;opacity:.9;">新增</div></div>'
             f'<div style="flex:1;min-width:120px;background:#2f9e57;border-radius:10px;padding:12px;color:#fff;'
             f'text-align:center;"><div style="font-size:24px;font-weight:700;">{n_fix}</div>'
             f'<div style="font-size:12px;opacity:.9;">已修复/消失</div></div>'
             f'<div style="flex:1;min-width:120px;background:#5b8def;border-radius:10px;padding:12px;color:#fff;'
             f'text-align:center;"><div style="font-size:24px;font-weight:700;">{n_keep}</div>'
             f'<div style="font-size:12px;opacity:.9;">仍存在</div></div></div>')
    meta = (f'<div style="color:#8a93a6;font-size:13px;margin:6px 0 10px;">'
            f'基线：{base_meta.get("scanned_at","?")} · {base_meta.get("dir","")}<br>'
            f'当前：{cur_meta.get("scanned_at","?")} · {cur_meta.get("dir","")}</div>')
    doc = (f'<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">'
           f'<title>扫描历史对比报告</title></head>'
           f'<body style="margin:0;background:#f6f8fb;font-family:\'Microsoft YaHei\',sans-serif;">'
           f'<div style="max-width:1080px;margin:0 auto;padding:24px;">'
           f'<div style="display:flex;justify-content:space-between;align-items:baseline;">'
           f'<h1 style="font-size:22px;margin:0;">扫描历史对比报告</h1>'
           f'<span style="color:#8a93a6;font-size:12px;">{PRODUCT} v{VERSION}</span></div>'
           f'{meta}{cards}'
           f'{_table("新增发现（本次新增 / 新出现问题）", "#d64545", added)}'
           f'{_table("已修复 / 消失（上次存在，本次已无）", "#2f9e57", fixed)}'
           f'{_table("仍存在", "#5b8def", kept)}'
           f'<div style="margin-top:20px;padding:12px;border-top:1px solid #e3e6ec;color:#9aa3b2;'
           f'font-size:12px;">免责声明：本对比由 VulnScan 生成，条目为启发式提取，重要结论请人工核验。'
           f'仅用于你有权测试的资产。</div></div></body></html>')
    with open(out_path, "w", encoding="utf-8") as fp:
        fp.write(doc)
    return out_path


def list_snapshots(hist_dir):
    if not os.path.isdir(hist_dir):
        return []
    files = sorted([f for f in os.listdir(hist_dir) if f.endswith("_snapshot.json")])
    return [os.path.join(hist_dir, f) for f in files]


def main():
    args = sys.argv[1:]
    hist_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output", "history")
    if "--list" in args:
        for p in list_snapshots(hist_dir):
            print(p)
        return 0
    if "--base" not in args or "--cur" not in args:
        print(__doc__)
        return 1
    base_path = args[args.index("--base") + 1]
    cur_path = args[args.index("--cur") + 1]
    out = None
    if "--out" in args:
        out = args[args.index("--out") + 1]
    if not (os.path.isfile(base_path) and os.path.isfile(cur_path)):
        print("[错误] 快照文件不存在（先跑一次扫描生成快照）")
        return 1
    with open(base_path, encoding="utf-8") as fp:
        base_snap = json.load(fp)
    with open(cur_path, encoding="utf-8") as fp:
        cur_snap = json.load(fp)
    be = collect_entries(base_snap.get("results"))
    ce = collect_entries(cur_snap.get("results"))
    added, fixed, kept = diff(be, ce)
    n_add = sum(len(v) for v in added.values())
    n_fix = sum(len(v) for v in fixed.values())
    n_keep = sum(len(v) for v in kept.values())
    print(f"基线模块 {len(be)} · 当前模块 {len(ce)}")
    print(f"新增 {n_add} · 修复 {n_fix} · 仍存在 {n_keep}")
    for mod, es in added.items():
        print(f"  新增[{mod}] {len(es)} 条")
    if out:
        generate_report(base_snap, cur_snap, added, fixed, kept, out)
        print(f"对比报告已生成: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
