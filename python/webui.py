# -*- coding: utf-8 -*-
"""
VulnScan - local Web UI (no third-party deps, stdlib only).

Usage:
    python webui.py [--port 8000]
Then open http://localhost:8000 in a browser.
"""

import os
import sys
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCANNER = os.path.join(ROOT, "build", "pe_scanner.exe")
OUT = os.path.join(ROOT, "output")

import cve_match
import report_gen


_SYSTEM_PREFIX = ("api-ms-win-", "msvcp", "vcruntime", "ucrtbase", "vcomp")
_SYSTEM_NAMES = {"kernel32.dll", "user32.dll", "ntdll.dll", "ole32.dll", "ws2_32.dll",
                 "advapi32.dll", "shell32.dll", "gdi32.dll", "comctl32.dll", "crypt32.dll"}


def is_system_lib(entry):
    name = (entry.get("name") or "").lower()
    return name.startswith(_SYSTEM_PREFIX) or name in _SYSTEM_NAMES


def run_scanner(target_dir, maxdepth):
    cmd = [SCANNER, target_dir]
    if maxdepth is not None:
        cmd += ["--maxdepth", str(maxdepth)]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    entries = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except Exception:
                pass
    return entries, proc.stderr.strip()


def scan_and_render(target_dir, maxdepth=None, use_nvd=False):
    """Run scan+match and produce a rendered result page body."""
    if not os.path.isdir(target_dir):
        return f'<div class="msg err">目录无效: {html_escape(target_dir)}</div>'
    if not os.path.isfile(SCANNER):
        return '<div class="msg err">未找到 pe_scanner.exe，请先运行 scripts\\build_cpp.bat</div>'

    entries, stderr = run_scanner(target_dir, maxdepth)
    real = [e for e in entries if not is_system_lib(e)]
    matches = cve_match.match_entries(real, use_nvd=use_nvd)

    # write report file
    os.makedirs(OUT, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    rep_path = os.path.join(OUT, f"vulnscan_report_{stamp}.html")
    report_gen.generate_report(real, matches, rep_path, target_dir,
                               scanned_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # inline cards
    rows = []
    for m in matches:
        for c in m["matches"]:
            rows.append((m["entry"], m["product"], m["version"], c))
    rows.sort(key=lambda r: -((r[3].get("cvss") or 0)))

    def badge(cvss):
        if not cvss: return "raw", "未知"
        if cvss >= 7.0: return "high", f"{cvss} 高危"
        if cvss >= 4.0: return "medium", f"{cvss} 中危"
        return "low", f"{cvss} 低危"

    cards = ""
    if not rows:
        cards = '<div class="msg">未匹配到已知 CVE。</div>'
    for e, prod, ver, c in rows:
        cls, label = badge(c.get("cvss") or 0)
        remote = "是" if c.get("remote") else "否/未知"
        fixed = c.get("fixed_in") or "未知"
        cards += (
            f'<div class="cve {cls}">'
            f'<div class="head"><b>{html_escape(c["id"])}</b>'
            f'<span class="badge {cls}">{label}</span></div>'
            f'<div class="prod">{html_escape(prod)} {html_escape(ver)} &middot; {html_escape(e.get("name",""))}</div>'
            f'<div class="desc">{html_escape(c.get("desc",""))}</div>'
            f'<div class="meta">类型 {html_escape(c.get("type",""))} &middot; 远程触发 {remote} &middot; 修复 {fixed}</div>'
            f'<div class="path">{html_escape(e.get("path",""))}</div></div>'
        )

    distinct = len({r[3]["id"] for r in rows})
    html_escape_local = html_escape
    return (
        f'<div class="stats">'
        f'<div class="stat"><div class="n">{len(entries)}</div><div class="l">扫描文件</div></div>'
        f'<div class="stat"><div class="n">{len(matches)}</div><div class="l">匹配库</div></div>'
        f'<div class="stat"><div class="n">{len(rows)}</div><div class="l">CVE 命中</div></div>'
        f'<div class="stat"><div class="n">{distinct}</div><div class="l">去重 CVE</div></div>'
        f'</div>'
        f'<div class="msg">完整报告已生成：<span class="path">{html_escape_local(rep_path)}</span></div>'
        f'{cards}'
    )


def html_escape(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>VulnScan - 第三方库漏洞扫描器</title>
<style>
*{box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#f5f6f8;margin:0;color:#222}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 6px}
.sub{color:#666;margin-bottom:18px}
.form{background:#fff;border:1px solid #e2e5ea;border-radius:10px;padding:18px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:20px}
input[type=text]{flex:1;min-width:260px;padding:9px 12px;border:1px solid #cfd4db;border-radius:8px;font-size:14px}
button{padding:9px 20px;background:#1a73e8;color:#fff;border:0;border-radius:8px;font-size:14px;cursor:pointer}
button:hover{background:#1666cc}
.stats{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:18px}
.stat{background:#fff;border:1px solid #e2e5ea;border-radius:10px;padding:12px 18px;min-width:110px}
.stat .n{font-size:24px;font-weight:700}
.stat .l{color:#777;font-size:12px}
.cve{background:#fff;border:1px solid #e2e5ea;border-left:5px solid #2e7d32;border-radius:10px;padding:12px 16px;margin-bottom:10px}
.cve.high{border-left-color:#c62828}
.cve.medium{border-left-color:#ef6c00}
.cve .head{display:flex;justify-content:space-between;align-items:center}
.cve .prod{font-size:12px;color:#555;margin:4px 0}
.cve .desc{font-size:14px;margin:6px 0}
.cve .meta{font-size:12px;color:#555}
.cve .path{font-family:Consolas,monospace;font-size:11px;color:#888;word-break:break-all;margin-top:6px}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:12px;font-weight:600;color:#fff}
.badge.high{background:#c62828}.badge.medium{background:#ef6c00}.badge.low{background:#2e7d32}.badge.raw{background:#555}
.msg{background:#eef3fb;border:1px solid #d0e0f5;border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:14px}
.msg.err{background:#fdeeec;border-color:#f0c9c4}
.loading{color:#888}
</style></head>
<body><div class="wrap">
<h1>VulnScan 第三方库漏洞扫描器</h1>
<div class="sub">输入要扫描的目录，自动识别 DLL 库 + 版本，匹配已知 CVE，生成报告。仅用于授权范围内的安全测试。</div>
<div class="form">
  <form method="post" action="/scan" id="f">
    <input type="text" name="dir" id="dir" placeholder="例如：E:\\Program Files\\QQ" required>
    <button type="submit">开始扫描</button>
  </form>
</div>
<div id="res"><div class="msg loading">输入目录后点击「开始扫描」。</div></div>
<script>
document.getElementById('f').onsubmit=async function(e){
  e.preventDefault();
  var d=document.getElementById('dir').value;
  document.getElementById('res').innerHTML='<div class="msg loading">扫描中，请稍候…（大型目录可能需要一些时间）</div>';
  var r=await fetch('/scan',{method:'POST',body:new URLSearchParams({dir:d})});
  var t=await r.text();
  document.getElementById('res').innerHTML=t;
};
</script>
</div></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, body, code=200):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._send(PAGE)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "replace")
        qs = parse_qs(body)
        target = (qs.get("dir") or [""])[0].strip()
        result = scan_and_render(target, use_nvd=False)
        self._send(result)

    def log_message(self, *a):
        pass


def main():
    import argparse
    import webbrowser
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    args = ap.parse_args()
    if not os.path.isfile(SCANNER):
        print(f"[错误] 未找到 {SCANNER}，请先运行 scripts\\build_cpp.bat")
        return 1
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"VulnScan Web UI 已启动: http://127.0.0.1:{args.port}")
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://127.0.0.1:{args.port}")).start()
    print("关闭此窗口即可停止服务。")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    return 0


if __name__ == "__main__":
    sys.exit(main())
