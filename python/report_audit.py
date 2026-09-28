# -*- coding: utf-8 -*-
"""VulnScan - Module 2 audit report (HTML).

Renders the binary-security-audit results (from pe_audit.audit_directory)
into a grouped HTML report: capability stats, per-file capability map,
risky API list and hardcoded-key samples.
"""

import os
import html
from datetime import datetime

CAT_LABELS = {
    "cmd_exec":     ("命令执行", "CreateProcess / ShellExecute / system"),
    "file_write":   ("文件写入", "CreateFileW / WriteFile / 删除 / 临时文件"),
    "reg_modify":   ("注册表",   "RegSetValueEx / RegCreateKey 等持久化"),
    "mem_exec":     ("内存操作", "VirtualAlloc / VirtualProtect / 进程内存"),
    "net":          ("网络",     "socket / HttpSendRequest / curl 拉流"),
    "crypto":       ("加密",     "BCrypt / Crypt* 密钥运算"),
    "thread_inject":("线程/注入","CreateRemoteThread / SetWindowsHook 等"),
    "dyn_load":     ("动态加载", "LoadLibrary / GetProcAddress"),
}
CAT_ORDER = ["cmd_exec", "file_write", "reg_modify", "mem_exec",
             "net", "crypto", "thread_inject", "dyn_load"]
_CAT_COLOR = {
    "cmd_exec": "#d64541", "file_write": "#f0a202", "reg_modify": "#8e44ad",
    "mem_exec": "#16a085", "net": "#2980b9", "crypto": "#27ae60",
    "thread_inject": "#c0392b", "dyn_load": "#7f8c8d",
}


def _agg_stats(results):
    total = len(results)
    cat_total = {c: 0 for c in CAT_ORDER}
    files_with_cat = {c: 0 for c in CAT_ORDER}
    key_total = 0
    files_with_keys = 0
    risky_total = 0
    for r in results:
        risky_total += len(r["risky_calls"])
        key_total += len(r["key_strings"])
        if r["key_strings"]:
            files_with_keys += 1
        for c in CAT_ORDER:
            n = r["cats"].get(c, 0)
            cat_total[c] += n
            if n:
                files_with_cat[c] += 1
    return (cat_total, files_with_cat, key_total, files_with_keys, risky_total)


def _file_card(r):
    name = html.escape(r["name"])
    path = html.escape(r["path"])
    size = r["size"] / 1024 / 1024
    caps = r["cats"]
    cap_chips = []
    for c in CAT_ORDER:
        n = caps.get(c, 0)
        if n:
            label = CAT_LABELS[c][0]
            color = _CAT_COLOR[c]
            cap_chips.append(
                f'<span style="background:{color};color:#fff;padding:2px 8px;'
                f'border-radius:10px;font-size:12px;margin-right:4px;">{label} {n}</span>')
    risky = ", ".join(html.escape(x) for x in r["risky_calls"][:20])
    keys = ""
    if r["key_strings"]:
        klines = "<br>".join(html.escape(x) for x in r["key_strings"][:6])
        keys = (f'<div style="margin-top:6px;color:#c0392b;font-size:12px;">'
                f'<b>硬编码密钥/敏感串候选:</b><br>{klines}</div>')
    return f"""
    <div style="border:1px solid #e3e6ec;border-radius:10px;padding:12px 14px;margin-bottom:10px;background:#fff;">
      <div style="display:flex;justify-content:space-between;align-items:baseline;">
        <b style="font-size:15px;">{name}</b>
        <span style="color:#8a93a6;font-size:12px;">{size:.2f} MB · 风险点 {len(r['risky_calls'])} · 密钥/敏感串 {len(r['key_strings'])}</span>
      </div>
      <div style="color:#8a93a6;font-size:12px;margin:2px 0 8px;">{path}</div>
      <div>{''.join(cap_chips) or '<span style="color:#999;">无高危能力分类</span>'}</div>
      <div style="margin-top:6px;color:#34495e;font-size:12px;"><b>危险 API:</b> {risky or '无'}</div>
      {keys}
    </div>
    """


def generate_audit_report(results, target_dir, out_path, scanned_at=None):
    if scanned_at is None:
        scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    (cat_total, files_with_cat, key_total, files_with_keys, risky_total) = _agg_stats(results)
    risky_files = sum(1 for r in results if r["risky_calls"])

    # stats cards
    cards = [
        ("审计的 PE 文件", len(results), "#2980b9"),
        ("含危险 API 的模块", risky_files, "#16a085"),
        ("危险 API 调用总数", risky_total, "#c0392b"),
        ("含敏感串的模块", files_with_keys, "#f0a202"),
    ]
    card_html = "".join(
        f'<div style="flex:1;min-width:150px;background:#fff;border:1px solid #e3e6ec;'
        f'border-radius:10px;padding:14px;text-align:center;">'
        f'<div style="font-size:26px;font-weight:700;color:{color};">{v}</div>'
        f'<div style="color:#8a93a6;font-size:13px;margin-top:4px;">{k}</div></div>'
        for k, v, color in cards)

    # capability summary table
    rows = []
    for c in CAT_ORDER:
        label, desc = CAT_LABELS[c]
        color = _CAT_COLOR[c]
        rows.append(
            f'<tr><td><span style="color:{color};font-weight:600;">{label}</span></td>'
            f'<td style="color:#8a93a6;">{desc}</td>'
            f'<td style="text-align:center;">{cat_total[c]}</td>'
            f'<td style="text-align:center;">{files_with_cat[c]}</td></tr>')
    summary_table = f"""
    <table style="width:100%;border-collapse:collapse;font-size:14px;background:#fff;">
      <tr style="background:#f6f8fb;color:#5c6773;">
        <th style="text-align:left;padding:8px;">能力类别</th><th style="text-align:left;">含义</th>
        <th>调用总数</th><th>涉及模块数</th></tr>
      {''.join(rows)}
    </table>
    """

    file_cards = "\n".join(_file_card(r) for r in results[:60])

    doc = f"""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<title>二进制安全审计报告</title>
<meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;background:#f6f8fb;font-family:'Microsoft YaHei',sans-serif;">
<div style="max-width:1080px;margin:0 auto;padding:24px;">
  <h1 style="font-size:24px;margin:0 0 4px;">二进制安全审计报告</h1>
  <div style="color:#8a93a6;font-size:13px;margin-bottom:18px;">
    扫描目录: {html.escape(target_dir)} · 生成时间: {scanned_at}
  </div>
  <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:22px;">{card_html}</div>

  <h2 style="font-size:18px;margin:20px 0 10px;">危险能力分类汇总</h2>
  <div style="border:1px solid #e3e6ec;border-radius:10px;overflow:hidden;">{summary_table}</div>

  <h2 style="font-size:18px;margin:24px 0 10px;">模块能力图（按风险排序，前 {min(len(results), 60)} 个）</h2>
  {file_cards}

  <div style="color:#8a93a6;font-size:12px;margin-top:20px;border-top:1px solid #e3e6ec;padding-top:10px;">
    说明: 本报告为<b>进攻面定位与审计探雷</b>用途——识别二进制所具备的危险能力与硬编码密钥候选，
    仅用于授权资产内的安全评估，不包含任何复现 / 武器化内容。敏感字符串仅作候选提示，需人工核验是否为真实密钥。
  </div>
</div></body></html>"""
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return out_path
