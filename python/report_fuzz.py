# -*- coding: utf-8 -*-
"""
report_fuzz.py - VulnScan 模块9 报告生成（fuzzing / 0day 崩溃报告）
输入 fuzz_result.json（fuzzer.py 生成），输出 HTML 报告。
"""

import os
import json
import sys
from datetime import datetime


def _esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _crash_rows(crashes):
    if not crashes:
        return '<tr><td colspan="4" style="text-align:center;color:#8a93a6;">未发现崩溃 —— 本次 fuzzing 未触发异常</td></tr>'
    rows = []
    for i, c in enumerate(crashes, 1):
        rows.append(
            "<tr>"
            f"<td>{i}</td>"
            f"<td><b>{_esc(c.get('code_hex','-'))}</b><br><span style='color:#8a93a6'>{_esc(c.get('code_name',''))}</span></td>"
            f"<td>{c.get('size','-')} B<br><code style='font-size:11px;color:#7a5a1a'>{_esc(os.path.basename(c.get('input','')))}</code></td>"
            f"<td style='word-break:break-all;font-size:11px;color:#5b6472'>{_esc(c.get('input',''))}</td>"
            "</tr>"
        )
    return "".join(rows)


def _severity_hint(crashes):
    """按崩溃码给一个报送危害提示。"""
    if not crashes:
        return '<span style="color:#2e7d32">未触发崩溃，继续扩大样本 / 换目标</span>'
    codes = {c.get("code_hex", "") for c in crashes}
    serious = {"0xC0000005", "0xC0000374", "0xC00000FD", "0xC0000409"}
    if codes & serious:
        return ('<span style="color:#b00020">命中内存破坏类崩溃（访问冲突/堆损坏/栈溢出），'
                '具备报送 CNVD 的原始素材，建议按流程报送</span>')
    return ('<span style="color:#f0a202">命中异常退出，但暂未见内存破坏类崩溃；'
            '可增加样本量或换种子再测</span>')


def generate_fuzz_report(res, out_path, scanned_at=""):
    stats = res.get("stats", {})
    crashes = res.get("crashes", [])
    target = res.get("target", "")
    scan = scanned_at or res.get("scanned_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    dedup = {}
    for c in crashes:
        dedup[c.get("code_hex", "?")] = dedup.get(c.get("code_hex", "?"), 0) + 1
    code_summary = "".join(
        f"<span style='display:inline-block;background:#fdecea;color:#b00020;border-radius:4px;"
        f"padding:2px 8px;margin:2px;font-size:12px'>{k} ×{v}</span>"
        for k, v in dedup.items()
    ) or '<span style="color:#8a93a6">—</span>'

    html = f"""<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8">
<title>VulnScan 模块9 - 二进制 fuzzing 崩溃报告</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{{margin:0;background:#f6f8fb;font-family:'Microsoft YaHei',sans-serif;}}
.wrap{{max-width:1080px;margin:0 auto;padding:24px;}}
h1{{font-size:22px;margin:0 0 6px;}}
.sub{{color:#8a93a6;font-size:13px;margin-bottom:16px;}}
.card{{background:#fff;border:1px solid #e3e6ec;border-radius:10px;padding:16px;margin-bottom:16px;}}
.kv{{display:flex;gap:8px;font-size:13px;color:#5b6472;margin:3px 0;}}
.kv b{{min-width:90px;color:#1f2d3d;}}
.grid{{display:flex;gap:12px;flex-wrap:wrap;margin:10px 0;}}
.stat{{flex:1;min-width:100px;background:#f0f3f8;border-radius:8px;padding:10px 14px;text-align:center;}}
.stat .n{{font-size:22px;font-weight:bold;color:#1f2d3d;}}
.stat .l{{font-size:12px;color:#8a93a6;}}
table{{border-collapse:collapse;width:100%;font-size:13px;}}
th,td{{border:1px solid #e3e6ec;padding:7px 9px;text-align:left;vertical-align:top;}}
th{{background:#f0f3f8;}}
.notice{{background:#eaf4ec;border:1px solid #bfe3c6;border-radius:8px;padding:12px 14px;font-size:13px;color:#1c5b2d;}}
</style></head><body><div class="wrap">
<h1>VulnScan 模块9 · 二进制 fuzzing 崩溃报告</h1>
<div class="sub">目标: {_esc(target)} · 扫描时间: {_esc(scan)}</div>

<div class="notice">
<b>合规边界：</b>本报告仅对<b>授权/本地目标</b>做输入健壮性测试与崩溃采集，不包含利用、不做武器化。
命中崩溃后请按 CNVD/CNNVD 报送流程提交<b>原始崩溃输入</b>（报告末尾说明），勿在未授权目标上使用本工具。
</div>

<div class="card">
<div class="kv"><b>目标二进制</b>{_esc(target)}</div>
<div class="kv"><b>崩溃保存目录</b>{_esc(res.get('crashes_dir',''))}</div>
<div class="grid">
  <div class="stat"><div class="n">{stats.get('samples',0)}</div><div class="l">执行样本</div></div>
  <div class="stat"><div class="n">{stats.get('crash',0)}</div><div class="l">触发崩溃</div></div>
  <div class="stat"><div class="n">{len(crashes)}</div><div class="l">去重崩溃</div></div>
  <div class="stat"><div class="n">{stats.get('timeout',0)}</div><div class="l">超时样本</div></div>
  <div class="stat"><div class="n">{stats.get('elapsed_s',0)}s</div><div class="l">耗时</div></div>
</div>
<div style="margin-top:10px;font-size:13px;"><b>危害研判：</b>{_severity_hint(crashes)}</div>
</div>

<div class="card">
<h2 style="font-size:16px;margin:0 0 10px;">崩溃类型分布</h2>
{code_summary or '<span style="color:#8a93a6">无</span>'}
</div>

<div class="card">
<h2 style="font-size:16px;margin:0 0 10px;">崩溃明细（{len(crashes)} 条）</h2>
<table>
<tr><th style="width:34px">#</th><th style="width:150px">崩溃码</th><th style="width:120px">输入大小</th><th>原始输入文件（报送附件）</th></tr>
{_crash_rows(crashes)}
</table>
</div>

<div class="card">
<h2 style="font-size:16px;margin:0 0 10px;">CNVD 报送建议</h2>
<ol style="font-size:13px;color:#1f2d3d;margin:0;padding-left:20px;line-height:1.9">
<li>上表 <b>「原始输入文件」</b> 即每个崩溃的<b>最小复现输入</b>，报送时作为附件上传，无需额外构造 PoC。</li>
<li>报送时在 CNVD 选择「事件型漏洞 / 应用软件漏洞」，危害等级参考崩溃码：<b>访问冲突 / 堆损坏 / 栈溢出</b> 通常可按高危或以上评估。</li>
<li>若目标属于某开源组件，请在报送备注中写明组件名与版本，便于 CNVD 收录与复验。</li>
<li>同一崩溃码的多个输入视为同一疑似漏洞，报送前先去重（本报告已去重）。</li>
<li>仅针对<b>授权 / 自有 / 开源</b>目标使用，切勿对未授权商业目标执行。</li>
</ol>
</div>

</div></body></html>"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path


def main():
    if len(sys.argv) < 2:
        print("用法: python report_fuzz.py <fuzz_result.json> [输出HTML]")
        return 1
    src = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output", "fuzz_report.html")
    with open(src, "r", encoding="utf-8") as f:
        res = json.load(f)
    path = generate_fuzz_report(res, out)
    print("报告已生成:", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
