# -*- coding: utf-8 -*-
"""
VulnScan - Module 18: API Asset Discovery (READ-ONLY).

Probes a set of common API / OpenAPI / framework endpoints on a target and
reports which are present (200/3xx/401/403 = reachable, with content-type and
openapi/swagger/actuator markers). Passive GETs only.

Usage:  python api_discover.py <url> [--out report.html]
"""

import sys
import os
import re
import ssl
import urllib.request
import urllib.error
from datetime import datetime

VERSION = "1.0.0"
PRODUCT = "VulnScan"
UA = "Mozilla/5.0 (compatible; VulnScanApi/1.0; read-only; authorized-target-only)"
TIMEOUT = 6

# path -> (category, note)
API_PATHS = [
    ("/swagger", "OpenAPI", "Swagger UI 根路径"),
    ("/swagger-ui.html", "OpenAPI", "Swagger UI 页面"),
    ("/swagger/index.html", "OpenAPI", "Swagger UI 页面"),
    ("/swagger-ui/index.html", "OpenAPI", "Swagger UI 页面"),
    ("/swagger.json", "OpenAPI", "Swagger JSON 文档"),
    ("/v2/api-docs", "OpenAPI", "Swagger v2 文档"),
    ("/v3/api-docs", "OpenAPI", "OpenAPI v3 文档"),
    ("/openapi.json", "OpenAPI", "OpenAPI JSON 文档"),
    ("/openapi.yaml", "OpenAPI", "OpenAPI YAML 文档"),
    ("/api-docs", "OpenAPI", "通用 API 文档"),
    ("/api/swagger-ui.html", "OpenAPI", "Swagger UI（/api 前缀）"),
    ("/actuator", "Spring Actuator", "Actuator 根端点"),
    ("/actuator/health", "Spring Actuator", "健康检查（未授权风险）"),
    ("/actuator/env", "Spring Actuator", "环境变量（敏感，未授权风险）"),
    ("/actuator/beans", "Spring Actuator", "Bean 列表（未授权风险）"),
    ("/actuator/mappings", "Spring Actuator", "路由映射（未授权风险）"),
    ("/graphql", "GraphQL", "GraphQL 端点"),
    ("/api", "REST API", "API 根路径"),
    ("/api/v1", "REST API", "API v1"),
    ("/api/v2", "REST API", "API v2"),
    ("/api/version", "REST API", "API 版本端点"),
    ("/api/health", "REST API", "API 健康检查"),
    ("/api/user", "REST API", "API 用户端点"),
    ("/health", "健康检查", "通用健康检查"),
    ("/version", "版本信息", "版本端点"),
    ("/status", "状态", "状态端点"),
    ("/robots.txt", "信息暴露", "爬虫协议（常暴露路径）"),
    ("/sitemap.xml", "信息暴露", "站点地图（常暴露端点）"),
    ("/server-info", "信息暴露", "服务器信息"),
]

_OPENAPI_MARK = re.compile(r'(?i)(swagger\s*:\s*["\']?2|"?openapi["\']?\s*:|["\']?paths["\']?\s*[:{])')
_ACTUATOR_MARK = re.compile(r'(?i)(["\']?status["\']?\s*:\s*"?UP|_links|self\s*:\s*"|"health")')


def _get(base, path):
    url = base.rstrip("/") + path
    req = urllib.request.Request(url)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "application/json,text/html,*/*")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            data = r.read(200_000)
            ct = r.headers.get("Content-Type", "")
            return r.getcode(), ct, data.decode("utf-8", errors="replace")[:2000]
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), ""
    except Exception:
        return None, "", ""


def scan_base(target):
    target = (target or "").strip()
    if "://" not in target:
        target = "https://" + target
    found = []
    for path, cat, note in API_PATHS:
        code, ct, body = _get(target, path)
        if code is None:
            continue
        if code in (200, 201, 204, 301, 302, 307, 308, 401, 403, 405):
            is_openapi = bool(_OPENAPI_MARK.search(body)) if cat == "OpenAPI" else False
            is_actuator = bool(_ACTUATOR_MARK.search(body)) if cat == "Spring Actuator" else False
            found.append({
                "path": path, "category": cat, "note": note, "status": code,
                "content_type": ct.split(";")[0][:40], "openapi": is_openapi,
                "actuator": is_actuator,
            })
    info = {"url": target, "found": len(found)}
    return found, info


def generate_report(found, info, out_path, scanned_at=None):
    scanned_at = scanned_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    disclaimer = ("免责声明：本 API 发现由 VulnScan 生成，仅用于你有权测试的资产；"
                  "仅对常见路径发起无害 GET 探测，未做任何未授权访问或利用，命中为候选需人工核验。")
    total = len(found)
    openapi = [f for f in found if f["openapi"]]
    actu = [f for f in found if f["actuator"]]
    head = (f'<div style="display:flex;flex-wrap:wrap;gap:10px;margin:14px 0;">'
            f'<div style="flex:1;min-width:110px;background:#2f9e57;border-radius:10px;padding:12px;color:#fff;'
            f'text-align:center;"><div style="font-size:24px;font-weight:700;">{total}</div>'
            f'<div style="font-size:12px;opacity:.9;">可访问端点</div></div>'
            f'<div style="flex:1;min-width:110px;background:#e0872a;border-radius:10px;padding:12px;color:#fff;'
            f'text-align:center;"><div style="font-size:24px;font-weight:700;">{len(openapi)}</div>'
            f'<div style="font-size:12px;opacity:.9;">OpenAPI 文档</div></div>'
            f'<div style="flex:1;min-width:110px;background:#d64545;border-radius:10px;padding:12px;color:#fff;'
            f'text-align:center;"><div style="font-size:24px;font-weight:700;">{len(actu)}</div>'
            f'<div style="font-size:12px;opacity:.9;">Actuator 端点</div></div></div>')
    if found:
        rows = "".join(
            f'<tr><td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#6b7280;">{i}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:13px;font-weight:600;">{f["path"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#6b7280;">{f["category"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#6b7280;">{f["status"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;color:#6b7280;">{f["content_type"]}</td>'
            f'<td style="padding:7px 10px;border-bottom:1px solid #eef1f5;font-size:12px;">'
            f'{"<span style=background:#e0872a;color:#fff;border-radius:4px;padding:1px 6px;font-size:12px;>OpenAPI</span> " if f["openapi"] else ""}'
            f'{"<span style=background:#d64545;color:#fff;border-radius:4px;padding:1px 6px;font-size:12px;>Actuator</span>" if f["actuator"] else ""}</td></tr>'
            for i, f in enumerate(found, 1))
        table = (f'<table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e3e6ec;'
                 f'border-radius:10px;overflow:hidden;"><thead><tr style="background:#f6f8fb;">'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">#</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">路径</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">类别</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">状态</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">类型</th>'
                 f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">标记</th>'
                 f'</tr></thead><tbody>{rows}</tbody></table>')
    else:
        table = ('<div style="background:#eef7ee;border:1px solid #c9e4cf;border-radius:10px;padding:16px;'
                 'color:#2f6f4f;font-size:14px;">未发现常见 API/OpenAPI/Actuator 端点（目标不可达或均返回不可用状态）。</div>')
    doc = (f'<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">'
           f'<title>API 资产发现报告</title></head>'
           f'<body style="margin:0;background:#f6f8fb;font-family:\'Microsoft YaHei\',sans-serif;">'
           f'<div style="max-width:1080px;margin:0 auto;padding:24px;">'
           f'<div style="display:flex;justify-content:space-between;align-items:baseline;">'
           f'<h1 style="font-size:22px;margin:0;">API 资产发现报告</h1>'
           f'<span style="color:#8a93a6;font-size:12px;">{PRODUCT} v{VERSION}</span></div>'
           f'<div style="color:#8a93a6;font-size:13px;margin:6px 0 8px;">'
           f'目标：{info.get("url","")} · 探测路径 {len(API_PATHS)} · 扫描时间 {scanned_at}</div>'
           f'{head}{table}'
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
    url = args[0]
    out = None
    if "--out" in args:
        out = args[args.index("--out") + 1]
    found, info = scan_base(url)
    print(f"目标: {info.get('url')}  发现可访问端点 {len(found)} 个")
    for f in found:
        print(f"  [{f['status']}] {f['path']}  {f['category']}"
              + ("  <OpenAPI>" if f["openapi"] else "") + ("  <Actuator>" if f["actuator"] else ""))
    if out:
        generate_report(found, info, out)
        print(f"报告已生成: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
