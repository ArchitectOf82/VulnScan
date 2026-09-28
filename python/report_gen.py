# -*- coding: utf-8 -*-
"""
VulnScan - HTML report generation.
"""

import html
from collections import Counter


_CSS = """
<style>
:root { --good:#2e7d32; --warn:#ef6c00; --bad:#c62828; --bg:#f5f6f8; --card:#fff; }
* { box-sizing:border-box; }
body { font-family:'Segoe UI',system-ui,sans-serif; margin:0; background:var(--bg); color:#222; }
.wrap { max-width:1200px; margin:0 auto; padding:24px; }
h1 { font-size:22px; margin:0 0 4px; }
.sub { color:#666; margin-bottom:20px; }
.stats { display:flex; gap:16px; flex-wrap:wrap; margin:16px 0 24px; }
.stat { background:var(--card); border:1px solid #e2e5ea; border-radius:10px; padding:14px 20px; min-width:120px; }
.stat .n { font-size:26px; font-weight:700; }
.stat .l { color:#777; font-size:12px; margin-top:2px; }
.cve { background:var(--card); border:1px solid #e2e5ea; border-left:5px solid var(--good); border-radius:10px;
       padding:14px 18px; margin-bottom:12px; }
.cve.hi { border-left-color:var(--bad); }
.cve.md { border-left-color:var(--warn); }
.cve .head { display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; }
.cve .id { font-weight:700; font-size:15px; }
.cve .prod { font-size:12px; color:#555; }
.cve .desc { margin:8px 0 6px; font-size:14px; }
.cve .meta { display:flex; gap:14px; flex-wrap:wrap; font-size:12px; color:#555; }
.cve .meta b { color:#222; }
.badge { display:inline-block; padding:2px 8px; border-radius:12px; font-size:12px; font-weight:600; color:#fff; }
.badge.raw { background:#555; }
.badge.high { background:var(--bad); }
.badge.medium { background:var(--warn); }
.badge.low { background:var(--good); }
.cve .path { font-family:Consolas,monospace; font-size:11px; color:#888; word-break:break-all; margin-top:8px; }
.empty { background:var(--card); border:1px solid #e2e5ea; border-radius:10px; padding:30px; text-align:center; color:#888; }
footer { margin-top:30px; color:#999; font-size:12px; text-align:center; }
</style>
"""


def _cvss_badge(cvss):
    if not cvss:
        return "", "raw"
    if cvss >= 9.0:
        return "CRITICAL", "high"
    if cvss >= 7.0:
        return "HIGH", "high"
    if cvss >= 4.0:
        return "MEDIUM", "medium"
    return "LOW", "low"


def generate_report(entries, matches, identified, out_path, target_dir, scanned_at=""):
    """entries: all scanned dicts; matches: list of {entry, product, version, matches:[cve,...]};
    identified: list of {name, product, version, cve_count, top_cvss} (every identified lib)."""
    total_files = len(entries)
    matched_libs = len(matches)
    identified_libs = len(identified)

    cve_rows = []
    for m in matches:
        for c in m["matches"]:
            cve_rows.append((m["entry"], m["product"], m["version"], c))

    total_cve = len(cve_rows)

    # sort by cvss desc
    def _key(r):
        cv = r[3].get("cvss") or 0
        return (-cv, r[2] or "")

    cve_rows.sort(key=_key)

    # distinct CVE ids
    distinct_ids = len({r[3]["id"] for r in cve_rows})

    # group by severity for clearer display
    def _group(r):
        cv = r[3].get("cvss") or 0
        if cv >= 9.0: return 0, "CRITICAL 严重"
        if cv >= 7.0: return 1, "HIGH 高危"
        if cv >= 4.0: return 2, "MEDIUM 中危"
        if cv > 0: return 3, "LOW 低危"
        return 4, "UNVERIFIED 待核实"

    groups = {}
    for r in cve_rows:
        key, label = _group(r)
        groups.setdefault(key, (label, []))[1].append(r)

    card_html = ""
    if not cve_rows:
        card_html = '<div class="empty">未发现匹配到已知 CVE 的第三方库（或未识别到带版本的库）。</div>'
    for key in sorted(groups):
        label, rows = groups[key]
        card_html += f'<h2 style="font-size:17px;margin:22px 0 10px;color:#444;">{label} ({len(rows)})</h2>'
        for entry, product, version, cve in rows:
            cvss = cve.get("cvss") or 0
            _, badge = _cvss_badge(cvss)
            remote = cve.get("remote")
            fixed = cve.get("fixed_in") or "未知"
            path = entry.get("path", "")
            name = entry.get("name", "")
            sev_cls = "hi" if badge == "high" else ("md" if badge == "medium" else "")
            card_html += (
                f'<div class="cve {sev_cls}">'
                f'<div class="head"><span class="id">{html.escape(cve["id"])}</span>'
                f'<span class="badge {badge}">{label.split(" ")[0]}</span></div>'
                f'<div class="prod">{html.escape(product)} {html.escape(version)}  &middot; {html.escape(name)}</div>'
                f'<div class="desc">{html.escape(cve.get("desc",""))}</div>'
                f'<div class="meta">'
                f'<span>CVSS: <b>{cvss}</b></span>'
                f'<span>类型: <b>{html.escape(cve.get("type",""))}</b></span>'
                f'<span>可远程触发: <b>{"是" if remote else "否/未知"}</b></span>'
                f'<span>修复版本: <b>{html.escape(str(fixed))}</b></span>'
                f'</div>'
                f'<div class="path">{html.escape(path)}</div>'
                f'</div>'
            )

    stats = (
        f'<div class="stats">'
        f'<div class="stat"><div class="n">{total_files}</div><div class="l">扫描文件</div></div>'
        f'<div class="stat"><div class="n">{identified_libs}</div><div class="l">识别到库</div></div>'
        f'<div class="stat"><div class="n">{matched_libs}</div><div class="l">命中 CVE 的库</div></div>'
        f'<div class="stat"><div class="n">{total_cve}</div><div class="l">CVE 命中数</div></div>'
        f'<div class="stat"><div class="n">{distinct_ids}</div><div class="l">去重 CVE 数</div></div>'
        f'</div>'
    )

    # every identified lib (new/old, with/without CVEs)
    lib_rows = sorted(identified, key=lambda x: -x["cve_count"])
    lib_table_html = '<div style="margin:0 0 20px;"><h2 style="font-size:18px;margin:0 0 14px;">已识别第三方库（新老版本都列出，0 命中也显示）</h2>'
    if not lib_rows:
        lib_table_html += '<div class="empty">未识别到带版本的第三方库。</div>'
    else:
        lib_table_html += '<table style="border-collapse:collapse;width:100%;font-size:13px;background:#fff;border:1px solid #e2e5ea;border-radius:10px;overflow:hidden;">'
        lib_table_html += ('<tr style="background:#f0f1f4;"><th style="padding:8px 12px;text-align:left;">库</th>'
                           '<th style="padding:8px 12px;text-align:left;">版本</th>'
                           '<th style="padding:8px 12px;text-align:center;">已知 CVE</th>'
                           '<th style="padding:8px 12px;text-align:left;">状态</th></tr>')
        for lib in lib_rows:
            if lib["cve_count"]:
                status = f'<span style="color:#c62828;font-weight:700;">命中 {lib["cve_count"]} 个已知 CVE（最高 CVSS {lib["top_cvss"]}）</span>'
            else:
                status = '<span style="color:#2e7d32;">无已知命中（较新版本或已修复）</span>'
            lib_table_html += (
                f'<tr style="border-top:1px solid #eee;">'
                f'<td style="padding:8px 12px;font-weight:600;">{html.escape(lib["product"])}</td>'
                f'<td style="padding:8px 12px;font-family:Consolas,monospace;">{html.escape(lib["version"])}</td>'
                f'<td style="padding:8px 12px;text-align:center;">{lib["cve_count"]}</td>'
                f'<td style="padding:8px 12px;">{status}</td></tr>')
        lib_table_html += '</table>'
    lib_table_html += '</div>'

    title = html.escape(f"VulnScan 报告 - {target_dir}")
    t = scanned_at or "未知时间"

    doc = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>{title}</title>{_CSS}</head>
<body><div class="wrap">
<h1>{title}</h1>
<div class="sub">扫描时间: {t}</div>
{stats}
{lib_table_html}
<h2 style="font-size:18px;margin:0 0 14px;">命中 CVE</h2>
{card_html}
<footer>VulnScan 自研漏洞扫描器 &middot; 结果仅供授权测试参考，提交漏洞前请以 NVD 官方为准核对版本范围</footer>
</div></body></html>
"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return out_path
