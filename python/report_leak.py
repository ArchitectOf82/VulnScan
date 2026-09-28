# -*- coding: utf-8 -*-
"""VulnScan - Module 3 leak report (HTML with inline SVG charts + audit list)."""

import os
import html
from datetime import datetime

import info_leak

_CAT_COLOR = {
    "backup": "#f0a202", "vcs": "#8e44ad", "config": "#2980b9",
    "key": "#27ae60", "database": "#16a085", "logdump": "#7f8c8d",
    "source": "#c0392b", "credential": "#d64541",
}
_CAT_ORDER = ["backup", "vcs", "config", "key", "database",
              "logdump", "source", "credential"]


def _pie_svg(by_cat, total):
    """Inline SVG donut chart of leak-category distribution."""
    if total == 0:
        return ""
    cx, cy, r, ir = 150, 130, 100, 55
    start = -90.0
    paths = []
    labels = []
    for c in _CAT_ORDER:
        n = len(by_cat.get(c, []))
        if n == 0:
            continue
        frac = n / total
        ang = frac * 360.0
        end = start + ang
        color = _CAT_COLOR[c]
        large = 1 if ang > 180 else 0
        a0, a1 = start * 3.14159 / 180, end * 3.14159 / 180
        x0, y0 = cx + r * __import__("math").cos(a0), cy + r * __import__("math").sin(a0)
        x1, y1 = cx + r * __import__("math").cos(a1), cy + r * __import__("math").sin(a1)
        ix0, iy0 = cx + ir * __import__("math").cos(a1), cy + ir * __import__("math").sin(a1)
        ix1, iy1 = cx + ir * __import__("math").cos(a0), cy + ir * __import__("math").sin(a0)
        d = (f"M {cx} {cy} L {x0:.1f} {y0:.1f} A {r} {r} 0 {large} 1 {x1:.1f} {y1:.1f} "
             f"L {ix0:.1f} {iy0:.1f} A {ir} {ir} 0 {large} 0 {ix1:.1f} {iy1:.1f} Z")
        paths.append(f'<path d="{d}" fill="{color}"/>')
        labels.append(
            f'<rect x="8" y="{14 + len(labels) * 22}" width="12" height="12" rx="3" fill="{color}"/>'
            f'<text x="26" y="{24 + len(labels) * 22}" font-size="12" fill="#34495e">'
            f'{info_leak.CATS.get(c, c)} · {n}（{frac * 100:.1f}%）</text>')
    center = (f'<text x="{cx}" y="{cy - 2}" text-anchor="middle" font-size="26" '
              f'font-weight="700" fill="#34495e">{total}</text>'
              f'<text x="{cx}" y="{cy + 18}" text-anchor="middle" font-size="12" '
              f'fill="#8a93a6">发现总数</text>')
    return (f'<svg viewBox="0 0 300 260" style="width:100%;max-width:360px;">'
            f'{"".join(paths)}{center}{"".join(labels)}</svg>')


def _bar_svg(by_cat):
    """Inline SVG horizontal bar chart of counts per category."""
    items = [(c, len(by_cat.get(c, []))) for c in _CAT_ORDER if by_cat.get(c)]
    if not items:
        return ""
    maxn = max(n for _, n in items)
    bw = maxn or 1
    rows = []
    y = 8
    for c, n in items:
        w = max(8, (n / bw) * 240)
        rows.append(
            f'<text x="0" y="{y + 14}" font-size="12" fill="#34495e">{info_leak.CATS.get(c, c)}</text>'
            f'<rect x="150" y="{y}" width="{w:.1f}" height="16" rx="4" fill="{_CAT_COLOR[c]}"/>'
            f'<text x="{156 + w:.1f}" y="{y + 13}" font-size="12" fill="#5c6773">{n}</text>')
        y += 24
    return f'<svg viewBox="0 0 420 {y + 6}" style="width:100%;max-width:420px;">{"".join(rows)}</svg>'


def _file_row(f):
    cat = f["cat"]
    if cat is None:
        cat = "credential"
    color = _CAT_COLOR.get(cat, "#95a5a6")
    label = info_leak.CATS.get(cat, cat)
    name = html.escape(f["name"])
    path = html.escape(f["path"])
    size = f["size"] / 1024
    cred = ""
    if f["cred_hits"]:
        lines = "<br>".join(html.escape(h[0] + " → " + h[1]) for h in f["cred_hits"][:8])
        cred = (f'<div style="margin-top:6px;color:#c0392b;font-size:12px;">'
                f'<b>内容命中:</b><br>{lines}</div>')
    return f"""
    <tr>
      <td style="padding:8px;border-bottom:1px solid #eef1f5;white-space:nowrap;">
        <span style="background:{color};color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;">{label}</span>
      </td>
      <td style="padding:8px;border-bottom:1px solid #eef1f5;">
        <b>{name}</b><br>
        <span style="color:#8a93a6;font-size:12px;">{path}</span>
        <span style="color:#8a93a6;font-size:11px;"> · {size:.1f} KB</span>
        {cred}
      </td>
    </tr>
    """


def generate_leak_report(findings, target_dir, out_path, scanned_at=None):
    if scanned_at is None:
        scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    by_cat = info_leak.summarize(findings)
    total = len(findings)
    cred_files = sum(1 for f in findings if f["cred_hits"])
    n_cats = len(by_cat)

    cards = [
        ("发现泄露项", total, "#d64541"),
        ("涉及类别", n_cats, "#2980b9"),
        ("含硬编码凭证的文件", cred_files, "#f0a202"),
    ]
    card_html = "".join(
        f'<div style="flex:1;min-width:150px;background:#fff;border:1px solid #e3e6ec;'
        f'border-radius:10px;padding:14px;text-align:center;">'
        f'<div style="font-size:26px;font-weight:700;color:{color};">{v}</div>'
        f'<div style="color:#8a93a6;font-size:13px;margin-top:4px;">{k}</div></div>'
        for k, v, color in cards)

    rows = "".join(_file_row(f) for f in findings)

    doc = f"""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<title>信息泄露扫描报告</title>
<meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;background:#f6f8fb;font-family:'Microsoft YaHei',sans-serif;">
<div style="max-width:1080px;margin:0 auto;padding:24px;">
  <h1 style="font-size:24px;margin:0 0 4px;">信息泄露扫描报告</h1>
  <div style="color:#8a93a6;font-size:13px;margin-bottom:18px;">
    扫描目录: {html.escape(target_dir)} · 生成时间: {scanned_at}
  </div>
  <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:22px;">{card_html}</div>

  <h2 style="font-size:18px;margin:20px 0 10px;">泄露类别分布（图解）</h2>
  <div style="display:flex;flex-wrap:wrap;gap:20px;background:#fff;border:1px solid #e3e6ec;border-radius:10px;padding:16px;">
    <div style="flex:1;min-width:300px;">{_pie_svg(by_cat, total)}</div>
    <div style="flex:1;min-width:300px;">{_bar_svg(by_cat)}</div>
  </div>

  <h2 style="font-size:18px;margin:24px 0 10px;">审计列表（{total} 项）</h2>
  <div style="background:#fff;border:1px solid #e3e6ec;border-radius:10px;overflow:hidden;">
    <table style="width:100%;border-collapse:collapse;font-size:14px;">
      {rows}
    </table>
  </div>

  <div style="color:#8a93a6;font-size:12px;margin-top:20px;border-top:1px solid #e3e6ec;padding-top:10px;">
    说明: 本报告为<b>静态信息泄露识别</b>，用于授权资产内的安全评估。文件名规则与内容正则均为启发式——
    "数据库/数据文件"多为程序正常运行产物、"敏感配置"与"硬编码凭证"需人工核验是否为真实密钥/敏感数据。
    不含任何复现 / 利用内容。
  </div>
</div></body></html>"""
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return out_path
