# -*- coding: utf-8 -*-
"""
VulnScan - Module 13: SBOM (Software Bill of Materials) generation.

Reuses the dependency-manifest parsers to inventory all third-party components
(name/version/ecosystem) of a project, and emits:
  - a standard CycloneDX JSON document (sbom.json)
  - a human-readable HTML report (sbom_report.html)
Read-only; no network required (unlike module 8 which queries OSV).

Usage:  python sbom_gen.py <dir> [--out report.html] [--json out.json]
"""

import os
import sys
import json
import uuid
from datetime import datetime

VERSION = "1.0.0"
PRODUCT = "VulnScan"

PURL_TYPE = {
    "npm": "npm", "pypi": "pypi", "maven": "maven", "go": "golang",
    "golang": "golang", "rubygems": "gem", "gem": "gem", "cargo": "cargo",
    "crates.io": "cargo", "composer": "composer", "packagist": "composer",
    "nuget": "nuget", "pub": "pub",
}


def _load_dep_scan():
    import dep_scan
    return dep_scan


def build_sbom(root):
    dep_scan = _load_dep_scan()
    manifests = dep_scan.find_manifests(root)
    seen, comps = set(), []
    by_eco = {}
    for path, eco, kind in manifests:
        try:
            parsed = dep_scan.parse_manifest(path, eco, kind)
        except Exception:
            parsed = []
        for eco2, name, ver in parsed:
            key = (eco2, name, ver)
            if key in seen:
                continue
            seen.add(key)
            ptype = PURL_TYPE.get(eco2.lower(), "generic")
            name_safe = name.replace("@", "").replace("/", ":")
            purl = f"pkg:{ptype}/{name_safe}@{ver}"
            comps.append({"type": "library", "name": name, "version": ver,
                          "ecosystem": eco2, "purl": purl})
            by_eco[eco2] = by_eco.get(eco2, 0) + 1
    comps.sort(key=lambda c: (c["ecosystem"], c["name"]))
    return comps, manifests, by_eco


def cyclone_dx(comps, root, scanned_at=None):
    scanned_at = scanned_at or datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {"timestamp": scanned_at,
                     "tools": [{"vendor": PRODUCT, "name": "VulnScan SBOM", "version": VERSION}],
                     "component": {"type": "application", "name": os.path.basename(root or "project")}},
        "components": comps,
    }


def generate_report(comps, by_eco, root, out_path, scanned_at=None):
    scanned_at = scanned_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    disclaimer = ("免责声明：本 SBOM 由 VulnScan 生成，仅用于你有权评估的资产。"
                  "组件清单来自工程依赖清单的启发式解析，重要结论请人工核验。")
    total = len(comps)
    # stat cards
    eco_cards = "".join(
        f'<div style="flex:1;min-width:120px;background:#fff;border:1px solid #e3e6ec;'
        f'border-radius:10px;padding:12px;text-align:center;"><div style="font-size:22px;'
        f'font-weight:700;color:#2f9e57;">{n}</div><div style="font-size:12px;color:#8a93a6;">'
        f'{e}</div></div>' for e, n in sorted(by_eco.items(), key=lambda x: -x[1]))
    cards = (f'<div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px;">'
             f'<div style="flex:1;min-width:120px;background:#2f9e57;border-radius:10px;padding:12px;'
             f'color:#fff;text-align:center;"><div style="font-size:22px;font-weight:700;">{total}</div>'
             f'<div style="font-size:12px;opacity:.9;">组件总数</div></div>{eco_cards}</div>')
    # table
    if comps:
        rows = "".join(
            f'<tr><td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;'
            f'color:#6b7280;">{i}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:13px;">{c["name"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;'
            f'color:#374151;">{c["version"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;">{c["ecosystem"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:11px;'
            f'color:#8a93a6;word-break:break-all;">{c["purl"]}</td></tr>'
            for i, c in enumerate(comps, 1))
        table = (f'<table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e3e6ec;'
                 f'border-radius:10px;overflow:hidden;"><thead><tr style="background:#f6f8fb;">'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">#</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">组件</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">版本</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">生态</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">PURL</th>'
                 f'</tr></thead><tbody>{rows}</tbody></table>')
    else:
        table = ('<div style="background:#eef7ee;border:1px solid #c9e4cf;border-radius:10px;padding:16px;'
                 'color:#2f6f4f;font-size:14px;">未发现依赖清单（package.json / requirements.txt / go.mod 等）。</div>')
    doc = (f'<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">'
           f'<title>SBOM 供应链清单报告</title></head>'
           f'<body style="margin:0;background:#f6f8fb;font-family:\'Microsoft YaHei\',sans-serif;">'
           f'<div style="max-width:1080px;margin:0 auto;padding:24px;">'
           f'<div style="display:flex;justify-content:space-between;align-items:baseline;">'
           f'<h1 style="font-size:22px;margin:0;">SBOM 供应链清单报告</h1>'
           f'<span style="color:#8a93a6;font-size:12px;">{PRODUCT} v{VERSION}</span></div>'
           f'<div style="color:#8a93a6;font-size:13px;margin:6px 0 16px;">'
           f'目标：{root} · 扫描时间 {scanned_at} · 格式：CycloneDX 1.5</div>'
           f'{cards}{table}'
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
    root = args[0]
    out = None
    json_out = None
    if "--out" in args:
        out = args[args.index("--out") + 1]
    if "--json" in args:
        json_out = args[args.index("--json") + 1]
    if not os.path.isdir(root):
        print(f"[错误] 不是有效目录: {root}")
        return 1
    comps, manifests, by_eco = build_sbom(root)
    print(f"清单文件 {len(manifests)} 个，组件 {len(comps)} 个：{dict(sorted(by_eco.items(), key=lambda x:-x[1]))}")
    if json_out:
        doc = cyclone_dx(comps, root)
        with open(json_out, "w", encoding="utf-8") as fp:
            json.dump(doc, fp, ensure_ascii=False, indent=2)
        print(f"CycloneDX JSON 已生成: {json_out}")
    if out:
        generate_report(comps, by_eco, root, out)
        print(f"SBOM 报告已生成: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
