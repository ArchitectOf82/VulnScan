# -*- coding: utf-8 -*-
"""VulnScan - Module 7: unified report engine.

Aggregates all module results into a single HTML report with an overview
stat card bar, per-module sections and anchor navigation.
"""

import os
import html
from datetime import datetime

import cve_match


def _esc(s):
    return html.escape(str(s))


def _risk_color(risk):
    return {"high": "#d64541", "medium": "#f0a202", "low": "#27ae60",
            "warn": "#f0a202", "pass": "#27ae60", "fail": "#d64541",
            "info": "#2980b9", "n/a": "#95a5a6"}.get(risk, "#95a5a6")


def _cve_table(matches, identified):
    rows = []
    for lib in sorted(identified, key=lambda x: -x["cve_count"]):
        tag = f"{lib['cve_count']} 个CVE" if lib["cve_count"] else "无已知命中"
        rows.append(f"<tr><td>{_esc(lib['name'])}</td><td>{_esc(lib['product'])} "
                    f"{_esc(lib['version'])}</td><td>{tag}</td></tr>")
    top_rows = []
    for m in sorted(matches, key=lambda x: -(max(c.get('cvss') or 0 for c in x['matches']))):
        top = sorted(m["matches"], key=lambda c: -(c.get("cvss") or 0))[0]
        cvss = top.get("cvss") or 0
        ids = ", ".join(c["id"] for c in sorted(m["matches"], key=lambda c: -(c.get("cvss") or 0))[:3])
        top_rows.append(
            f"<tr><td>{_esc(m['entry']['name'])}</td><td>{_esc(m['product'])} {_esc(m['version'])}</td>"
            f"<td style='color:{_risk_color('high') if cvss >= 7 else ('#f0a202' if cvss >= 4 else '#27ae60')};'>"
            f"{cvss}</td><td>{_esc(ids)}</td></tr>")
    return (f"<b>已识别第三方库（{len(identified)}）</b>"
            f"<table style='width:100%;border-collapse:collapse;font-size:13px;'>"
            f"<tr style='background:#f0f3f8;'><th style='text-align:left;padding:6px;'>文件</th>"
            f"<th style='text-align:left;'>库/版本</th><th>命中</th></tr>{''.join(rows)}</table>"
            f"<br><b>CVE 命中明细（{len(matches)}）</b>"
            f"<table style='width:100%;border-collapse:collapse;font-size:13px;'>"
            f"<tr style='background:#f0f3f8;'><th style='text-align:left;padding:6px;'>文件</th>"
            f"<th style='text-align:left;'>库</th><th>CVSS</th><th style='text-align:left;'>Top CVE</th></tr>"
            f"{''.join(top_rows)}</table>")


def _audit_table(results, limit=25):
    rows = []
    for r in results[:limit]:
        caps = " ".join(f"<span style='font-size:11px;'>{_esc(k)}:{v}</span>"
                        for k, v in sorted(r["cats"].items(), key=lambda x: -x[1]))
        rows.append(f"<tr><td>{_esc(r['name'])}</td><td>{caps}</td>"
                    f"<td style='text-align:center;'>{len(r['risky_calls'])}</td>"
                    f"<td style='text-align:center;'>{len(r['key_strings'])}</td>"
                    f"<td style='text-align:center;'>{r['score']}</td></tr>")
    tail = f"…（共 {len(results)} 个有发现模块，完整见二进制审计报告）" if len(results) > limit else ""
    return (f"<b>模块能力图（前 {min(len(results), limit)} 个）</b>{tail}"
            f"<table style='width:100%;border-collapse:collapse;font-size:13px;'>"
            f"<tr style='background:#f0f3f8;'><th style='text-align:left;padding:6px;'>模块</th>"
            f"<th style='text-align:left;'>危险能力</th><th>风险点</th><th>密钥/敏感串</th><th>风险分</th></tr>"
            f"{''.join(rows)}</table>")


def _leak_table(findings):
    rows = []
    for f in findings:
        cat = f["cat"] or "credential"
        cred = "⚠" if f["cred_hits"] else ""
        rows.append(f"<tr><td>{_esc(cat)}</td><td>{_esc(f['name'])}</td>"
                    f"<td style='color:#8a93a6;font-size:12px;'>{_esc(f['path'])}</td><td>{cred}</td></tr>")
    return (f"<b>泄露项（{len(findings)}）</b>"
            f"<table style='width:100%;border-collapse:collapse;font-size:13px;'>"
            f"<tr style='background:#f0f3f8;'><th style='text-align:left;padding:6px;'>类别</th>"
            f"<th style='text-align:left;'>文件</th><th style='text-align:left;'>路径</th><th>凭证命中</th></tr>"
            f"{''.join(rows)}</table>")


def _web_table(findings):
    rows = []
    for f in findings:
        color = _risk_color(f["risk"])
        rows.append(f"<tr><td><span style='color:{color};'>[{_esc(f['risk'])}]</span></td>"
                    f"<td>{_esc(f['name'])}</td><td>{_esc(f['label'])} (L{f['line']})</td>"
                    f"<td style='color:#8a93a6;font-size:12px;'>{_esc(f['snippet'])}</td></tr>")
    return (f"<b>Web 弱配置（{len(findings)}）</b>"
            f"<table style='width:100%;border-collapse:collapse;font-size:13px;'>"
            f"<tr style='background:#f0f3f8;'><th style='text-align:left;padding:6px;'>风险</th>"
            f"<th style='text-align:left;'>文件</th><th style='text-align:left;'>问题</th>"
            f"<th style='text-align:left;'>内容</th></tr>{''.join(rows)}</table>")


def _baseline_table(checks):
    rows = []
    for c in checks:
        color = _risk_color(c["status"])
        rows.append(f"<tr><td><span style='color:{color};'>[{_esc(c['status'])}]</span></td>"
                    f"<td>{_esc(c['item'])}</td><td>{_esc(c['value'])}</td>"
                    f"<td style='color:#8a93a6;font-size:12px;'>{_esc(c.get('detail', ''))}</td></tr>")
    return (f"<b>系统安全基线（{len(checks)} 项）</b>"
            f"<table style='width:100%;border-collapse:collapse;font-size:13px;'>"
            f"<tr style='background:#f0f3f8;'><th style='text-align:left;padding:6px;'>状态</th>"
            f"<th style='text-align:left;'>检查项</th><th style='text-align:left;'>当前值</th>"
            f"<th style='text-align:left;'>说明</th></tr>{''.join(rows)}</table>")


def _port_table(results):
    rows = []
    for r in results:
        risk = r.get("risk", "")
        color = _risk_color("high" if risk else "low")
        banner = f"<span style='color:#8a93a6;font-size:12px;'>{_esc(r['banner'])}</span>" if r.get("banner") else ""
        rows.append(f"<tr><td>{r['port']}</td><td>{_esc(r['service'])}</td>"
                    f"<td>{banner}</td><td><span style='color:{color};'>{_esc(risk)}</span></td></tr>")
    return (f"<b>开放端口与服务（{len(results)}）</b>"
            f"<table style='width:100%;border-collapse:collapse;font-size:13px;'>"
            f"<tr style='background:#f0f3f8;'><th style='padding:6px;'>端口</th>"
            f"<th style='text-align:left;'>服务</th><th style='text-align:left;'>Banner</th>"
            f"<th style='text-align:left;'>风险</th></tr>{''.join(rows)}</table>")


def _dep_table(dep_res):
    if not dep_res:
        return "<p>未扫描依赖清单</p>"
    vuln_deps = [d for d in dep_res.get("deps", []) if d.get("vulns")]
    rows = ""
    for d in vuln_deps:
        ids = "、".join(f"<code>{_esc(v['id'])}</code>" for v in d["vulns"])
        fix = "、".join(dict.fromkeys([v["fixed"] or "?" for v in d["vulns"] if v["fixed"]]))
        sev = max((v["cvss"] for v in d["vulns"]), default=0)
        sev_txt = f"{sev:.1f}" if sev else "N/A"
        rows += (f"<tr><td>{_esc(d['ecosystem'])}</td><td><b>{_esc(d['package'])}</b></td>"
                 f"<td>{_esc(d['version'])}</td><td>{len(d['vulns'])}</td><td>{sev_txt}</td>"
                 f"<td>{ids}</td><td>{fix}</td></tr>")
    if not rows:
        rows = "<tr><td colspan='7' style='color:#666'>未发现已知漏洞依赖</td></tr>"
    head = ("<table style='border-collapse:collapse;width:100%;font-size:13px'>"
            "<tr><th>生态</th><th>包</th><th>版本</th><th>漏洞数</th><th>最高CVSS</th><th>漏洞ID</th><th>修复版本</th></tr>")
    return head + rows + "</table>"


def generate_all_report(data, out_path, scanned_at=None):
    if scanned_at is None:
        scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target = data.get("dir", "")

    cve_matches = data.get("cve_matches", [])
    identified = data.get("identified", [])
    audit_res = data.get("audit_results", [])
    leak_res = data.get("leak_results", [])
    web_res = data.get("web_results", [])
    baseline_checks = data.get("baseline_checks", [])
    port_res = data.get("port_results", [])
    dep_res = data.get("dep_results", {}) or {}

    n_cve = len(cve_matches)
    n_audit = len(audit_res)
    n_leak = len(leak_res)
    n_web = len(web_res)
    n_baseline_fail = sum(1 for c in baseline_checks if c["status"] in ("fail", "warn"))
    n_port = len(port_res)
    n_dep = dep_res.get("vuln_count", 0) if dep_res else 0

    cards = [
        ("CVE 命中", n_cve, "#d64541"),
        ("审计模块", n_audit, "#16a085"),
        ("信息泄露", n_leak, "#f0a202"),
        ("Web 弱配置", n_web, "#8e44ad"),
        ("基线异常", n_baseline_fail, "#c0392b"),
        ("开放端口", n_port, "#2980b9"),
        ("依赖漏洞", n_dep, "#1e8449"),
    ]
    cards_html = "".join(
        f'<div style="flex:1;min-width:120px;background:#fff;border:1px solid #e3e6ec;'
        f'border-radius:10px;padding:12px;text-align:center;">'
        f'<div style="font-size:26px;font-weight:700;color:{color};">{v}</div>'
        f'<div style="color:#8a93a6;font-size:12px;margin-top:4px;">{k}</div></div>'
        for k, v, color in cards)

    nav = f"""
    <div style="display:flex;flex-wrap:wrap;gap:8px;margin:16px 0;padding:10px;background:#fff;
                border:1px solid #e3e6ec;border-radius:10px;">
      <a href="#sec-cve" style="color:#d64541;text-decoration:none;font-size:13px;padding:4px 10px;">① CVE 扫描</a>
      <a href="#sec-audit" style="color:#16a085;text-decoration:none;font-size:13px;padding:4px 10px;">② 二进制审计</a>
      <a href="#sec-leak" style="color:#f0a202;text-decoration:none;font-size:13px;padding:4px 10px;">③ 信息泄露</a>
      <a href="#sec-web" style="color:#8e44ad;text-decoration:none;font-size:13px;padding:4px 10px;">④ Web 弱配置</a>
      <a href="#sec-base" style="color:#c0392b;text-decoration:none;font-size:13px;padding:4px 10px;">⑤ 基线配置</a>
      <a href="#sec-port" style="color:#2980b9;text-decoration:none;font-size:13px;padding:4px 10px;">⑥ 端口服务</a>
      <a href="#sec-dep" style="color:#1e8449;text-decoration:none;font-size:13px;padding:4px 10px;">⑦ 依赖清单</a>
    </div>"""

    def section(anchor, title, color, body, show=True):
        if not show:
            return ""
        return (f'<div id="{anchor}" style="background:#fff;border:1px solid #e3e6ec;'
                f'border-radius:10px;padding:16px;margin-bottom:16px;">'
                f'<h2 style="font-size:17px;margin:0 0 10px;color:{color};border-left:4px solid {color};'
                f'padding-left:10px;">{title}</h2>{body}</div>')

    secs = ""
    secs += section("sec-cve", "① 第三方库 CVE 扫描", "#d64541", _cve_table(cve_matches, identified), n_cve or identified)
    secs += section("sec-audit", "② 二进制安全审计", "#16a085", _audit_table(audit_res), n_audit)
    secs += section("sec-leak", "③ 信息泄露扫描", "#f0a202", _leak_table(leak_res), n_leak)
    secs += section("sec-web", "④ Web 弱配置", "#8e44ad", _web_table(web_res), n_web)
    secs += section("sec-base", "⑤ 系统安全基线", "#c0392b", _baseline_table(baseline_checks), baseline_checks)
    secs += section("sec-port", "⑥ 端口 & 服务识别", "#2980b9", _port_table(port_res), n_port)
    secs += section("sec-dep", "⑦ 依赖清单扫描（全语言生态）", "#1e8449", _dep_table(dep_res), n_dep)

    doc = f"""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<title>VulnScan 统一安全扫描报告</title>
<meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;background:#f6f8fb;font-family:'Microsoft YaHei',sans-serif;">
<div style="max-width:1080px;margin:0 auto;padding:24px;">
  <h1 style="font-size:24px;margin:0 0 4px;">VulnScan 统一安全扫描报告</h1>
  <div style="color:#8a93a6;font-size:13px;margin-bottom:8px;">
    扫描目录: {_esc(target)} · 生成时间: {scanned_at}
  </div>
  <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:4px;">{cards_html}</div>
  {nav}
  {secs}
  <div style="color:#8a93a6;font-size:12px;margin-top:16px;border-top:1px solid #e3e6ec;padding-top:10px;">
    说明: 统一报告聚合各模块结果。本工具用于授权资产内的安全评估，识别 + 报告，不含复现 / 武器化内容。
    文件名规则 / 内容命中为启发式，重要结论请人工核验。各模块完整报告见 VulnScan\\output 下对应 HTML。
  </div>
</div></body></html>"""
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return out_path
