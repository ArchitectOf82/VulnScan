# -*- coding: utf-8 -*-
"""
VulnScan - CLI entry point.

Usage:
    python vulnscan.py <directory> [--maxdepth N] [--out DIR] [--json FILE] [--no-nvd]

Pipeline: run C++ pe_scanner -> identify libs+versions -> match CVEs -> HTML report.
"""

import os
import sys
import json
import time
import argparse
import subprocess
from datetime import datetime

# 强制 stdout/stderr 用 UTF-8，配合 .bat 里的 chcp 65001，避免 cmd 终端中文乱码(????)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCANNER = os.path.join(ROOT, "build", "pe_scanner.exe")

import cve_match
import report_gen


# System / compiler runtime DLLs to skip (not third-party, never CVE-matched)
_SYSTEM_PREFIX = (
    "api-ms-win-", "msvcp", "vcruntime", "ucrtbase", "vcomp",
)
_SYSTEM_NAMES = {"kernel32.dll", "user32.dll", "ntdll.dll", "ole32.dll", "ws2_32.dll",
                 "advapi32.dll", "shell32.dll", "gdi32.dll", "comctl32.dll", "crypt32.dll"}


def run_scanner(target_dir, maxdepth):
    if not os.path.isdir(target_dir):
        return [], ""
    cmd = [SCANNER, target_dir]
    if maxdepth is not None:
        cmd += ["--maxdepth", str(maxdepth)]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    entries = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except Exception:
            continue
    return entries, proc.stderr.strip()


def is_system_lib(entry):
    name = (entry.get("name") or "").lower()
    return name.startswith(_SYSTEM_PREFIX) or name in _SYSTEM_NAMES


def _simple_html(title, body_html, out_path, scanned_at=""):
    doc = (f'<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">'
           f'<title>{title}</title></head>'
           f'<body style="margin:0;background:#f6f8fb;font-family:\'Microsoft YaHei\',sans-serif;">'
           f'<div style="max-width:1080px;margin:0 auto;padding:24px;">'
           f'<h1 style="font-size:24px;margin:0 0 4px;">{title}</h1>'
           f'<div style="color:#8a93a6;font-size:13px;margin-bottom:16px;">{scanned_at}</div>'
           f'<div style="background:#fff;border:1px solid #e3e6ec;border-radius:10px;padding:16px;">'
           f'{body_html}</div></div></body></html>')
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return out_path


def main():
    ap = argparse.ArgumentParser(description="VulnScan 第三方库漏洞扫描器")
    ap.add_argument("directory", help="要扫描的目录")
    ap.add_argument("--maxdepth", type=int, default=None, help="最大递归深度")
    ap.add_argument("--out", default=None, help="HTML 报告输出目录（默认 output/）")
    ap.add_argument("--json", default=None, help="额外保存原始扫描结果为 JSON 文件")
    ap.add_argument("--no-nvd", action="store_true", help="关闭 NVD 联网增强（只用内置库）")
    ap.add_argument("--audit", action="store_true", help="同时执行二进制安全审计（模块2）")
    ap.add_argument("--leak", action="store_true", help="同时执行信息泄露扫描（模块3）")
    ap.add_argument("--web", action="store_true", help="同时执行 Web 弱配置识别（模块5）")
    ap.add_argument("--baseline", action="store_true", help="同时执行系统安全基线核查（模块6）")
    ap.add_argument("--port", default=None, help="端口&服务识别目标主机（模块4，如 127.0.0.1）")
    ap.add_argument("--dep", action="store_true", help="同时执行依赖清单扫描（模块8，全语言生态）")
    ap.add_argument("--fuzz", action="store_true", help="同时执行二进制 fuzzing（模块9，0day 挖掘）")
    ap.add_argument("--fuzz-bin", default=None, help="fuzzing 指定具体 exe 文件名（目录模式）")
    ap.add_argument("--fuzz-iters", type=int, default=None, help="fuzzing 变异样本数（默认 3000）")
    ap.add_argument("--fuzz-mode", default="file", choices=["file", "stdin", "dll"],
                    help="fuzzing 输入模式：file=文件路径参数；stdin=标准输入；dll=DLL导出函数harness")
    ap.add_argument("--fuzz-dll", default=None, help="fuzzing dll 模式：DLL 路径")
    ap.add_argument("--fuzz-func", default=None, help="fuzzing dll 模式：导出函数名（默认签名 func(const void*, size_t)）")
    ap.add_argument("--webprobe", action="store_true", help="同时执行 Web 在线业务探测（模块10，只读非破坏）")
    ap.add_argument("--weburl", default=None, help="模块10 目标 URL（如 https://example.com）")
    ap.add_argument("--subdomain", default=None, help="模块11：子域名枚举（授权域名，被动 DNS）")
    ap.add_argument("--tls", default=None, help="模块12：TLS/证书检查（host[:port]，默认 443）")
    ap.add_argument("--sbom", action="store_true", help="模块13：生成 SBOM 供应链清单（基于扫描目录）")
    ap.add_argument("--onleak", default=None, help="模块14：在线敏感信息爬取（目标 URL，只读）")
    ap.add_argument("--fingerprint", action="store_true", help="模块15：Web 技术栈指纹识别（URL 取 --weburl，只读）")
    ap.add_argument("--jsextract", action="store_true", help="模块16：JS 敏感信息/端点提取（URL 取 --weburl，只读）")
    ap.add_argument("--takeover", default=None, help="模块17：子域接管检测（授权域名，被动 DNS+仅 banner 探测）")
    ap.add_argument("--apidiscover", action="store_true", help="模块18：API 资产发现（URL 取 --weburl，只读）")
    ap.add_argument("--all", action="store_true", help="执行全部模块并生成统一报告（模块7）")
    args = ap.parse_args()

    if not os.path.isdir(args.directory):
        if not (args.webprobe or args.subdomain or args.tls or args.onleak
                or args.fingerprint or args.jsextract or args.takeover or args.apidiscover):
            print(f"[错误] 不是有效目录: {args.directory}")
            return 1
    if not os.path.isfile(SCANNER):
        print(f"[错误] 找不到扫描引擎: {SCANNER}\n请先运行 scripts\\build_cpp.bat 编译")
        return 1

    print(f"[*] 扫描目录: {args.directory}")
    entries, stderr = run_scanner(args.directory, args.maxdepth)
    if stderr:
        print(f"[*] 引擎提示: {stderr}")

    # filter system libs
    real = [e for e in entries if not is_system_lib(e)]
    print(f"[*] 扫描到 {len(entries)} 个文件，剔除系统库后 {len(real)} 个待匹配")

    # optional raw json dump
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(real, f, ensure_ascii=False, indent=2)
        print(f"[*] 原始扫描结果已存: {args.json}")

    identified = cve_match.identified_libraries(real)
    matches = cve_match.match_entries(real, use_nvd=not args.no_nvd)

    # console summary: every identified lib (new/old, with/without CVEs)
    print("\n===== 识别到的第三方库 =====")
    print(f"共识别 {len(identified)} 个第三方库（含未命中 CVE 的新版/已修复库）")
    for lib in sorted(identified, key=lambda x: -x["cve_count"]):
        tag = f"{lib['cve_count']} 个CVE" if lib["cve_count"] else "无已知命中"
        print(f"  [{lib['product']} {lib['version']}] {tag}   ({lib['name']})")

    print("\n===== 命中 CVE 明细 =====")
    if not matches:
        print("无。")
    for m in matches:
        top = sorted(m["matches"], key=lambda c: -(c.get("cvss") or 0))[0]
        cvss = top.get("cvss") or 0
        n = len(m["matches"])
        print(f"  [{m['product']} {m['version']}] {m['entry']['name']}")
        print(f"     命中 {n} 个 CVE，最高 CVSS={cvss} -> {top['id']} ({top.get('type','')})")

    # report
    out_dir = args.out or os.path.join(ROOT, "output")
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fixed_path = os.path.join(out_dir, "vulnscan_report.html")   # 固定名，供一键打开
    stamp_path = os.path.join(out_dir, f"vulnscan_report_{stamp}.html")  # 历史保留
    report_gen.generate_report(real, matches, identified, fixed_path, args.directory, scanned_at=scanned_at)
    report_gen.generate_report(real, matches, identified, stamp_path, args.directory, scanned_at=scanned_at)
    print(f"[*] 报告已生成: {fixed_path}")

    # Module 2: binary security audit
    results = {"dir": args.directory, "identified": identified, "cve_matches": matches}
    if args.audit or args.all:
        import pe_audit
        import report_audit
        print("\n[*] 模块2: 二进制安全审计 ...")
        audit_res = pe_audit.audit_directory(args.directory, args.maxdepth)
        print(f"[*] 审计到 {len(audit_res)} 个有发现的 PE 文件")
        results["audit_results"] = audit_res
        audit_fixed = os.path.join(out_dir, "binary_audit_report.html")
        audit_stamp = os.path.join(out_dir, f"binary_audit_report_{stamp}.html")
        report_audit.generate_audit_report(audit_res, args.directory, audit_fixed, scanned_at=scanned_at)
        report_audit.generate_audit_report(audit_res, args.directory, audit_stamp, scanned_at=scanned_at)
        print(f"[*] 二进制审计报告已生成: {audit_fixed}")

    # Module 3: information leakage scan
    if args.leak or args.all:
        import info_leak
        import report_leak
        print("\n[*] 模块3: 信息泄露扫描 ...")
        leak_res = info_leak.scan_directory(args.directory)
        print(f"[*] 发现 {len(leak_res)} 项泄露")
        results["leak_results"] = leak_res
        leak_fixed = os.path.join(out_dir, "info_leak_report.html")
        leak_stamp = os.path.join(out_dir, f"info_leak_report_{stamp}.html")
        report_leak.generate_leak_report(leak_res, args.directory, leak_fixed, scanned_at=scanned_at)
        report_leak.generate_leak_report(leak_res, args.directory, leak_stamp, scanned_at=scanned_at)
        print(f"[*] 信息泄露报告已生成: {leak_fixed}")

    # Module 5: web weak-config identification
    if args.web or args.all:
        import web_weak
        import report_all
        print("\n[*] 模块5: Web 弱配置识别 ...")
        web_res = web_weak.scan_directory(args.directory)
        print(f"[*] 发现 {len(web_res)} 项 Web 弱配置")
        results["web_results"] = web_res
        web_fixed = os.path.join(out_dir, "web_weak_report.html")
        _simple_html("Web 弱配置报告", report_all._web_table(web_res), web_fixed, scanned_at=scanned_at)
        print(f"[*] Web 弱配置报告已生成: {web_fixed}")

    # Module 6: baseline configuration check
    if args.baseline or args.all:
        import baseline
        import report_all
        print("\n[*] 模块6: 系统安全基线核查 ...")
        base_checks = baseline.run_baseline()
        n_fail = sum(1 for c in base_checks if c["status"] in ("fail", "warn"))
        print(f"[*] 基线核查完成，异常 {n_fail} 项")
        results["baseline_checks"] = base_checks
        base_fixed = os.path.join(out_dir, "baseline_report.html")
        _simple_html("系统安全基线报告", report_all._baseline_table(base_checks), base_fixed, scanned_at=scanned_at)
        print(f"[*] 基线报告已生成: {base_fixed}")

    # Module 4: port & service identification (needs a target host)
    if args.port:
        import port_scan
        import report_all
        print(f"\n[*] 模块4: 端口 & 服务识别 ({args.port}) ...")
        port_res = port_scan.scan_host(args.port, port_scan.parse_ports("1-1000"))
        print(f"[*] 开放端口 {len(port_res)} 个")
        results["port_results"] = port_res
        port_fixed = os.path.join(out_dir, "port_scan_report.html")
        _simple_html("端口与服务识别报告", report_all._port_table(port_res), port_fixed, scanned_at=scanned_at)
        print(f"[*] 端口报告已生成: {port_fixed}")

    # Module 8: dependency manifest scan (all language ecosystems)
    if args.dep or args.all:
        import dep_scan
        print("\n[*] 模块8: 依赖清单扫描（全语言生态）...")
        dep_res = dep_scan.run_dep_scan(args.directory)
        print(f"[*] 清单文件 {dep_res['manifests_count']} 个，依赖 {dep_res['total_deps']} 项，已知漏洞 {dep_res['vuln_count']} 条")
        results["dep_results"] = dep_res
        dep_fixed = os.path.join(out_dir, "dep_scan_report.html")
        with open(dep_fixed, "w", encoding="utf-8") as f:
            f.write(dep_scan._html(dep_res))
        print(f"[*] 依赖清单报告已生成: {dep_fixed}")

    # Module 9: binary fuzzing (0day mining)
    if args.fuzz or args.all:
        import fuzzer
        import report_fuzz
        fmode = getattr(args, "fuzz_mode", "file")
        print(f"\n[*] 模块9: 二进制 fuzzing（0day 挖掘，模式 {fmode}）...")
        fuzz_res = None
        iters = args.fuzz_iters or 3000
        if fmode == "dll":
            if not getattr(args, "fuzz_dll", None):
                print("[!] dll 模式需提供 --fuzz-dll，跳过")
            else:
                fuzz_res = fuzzer.fuzz(args.directory, mode="dll", iters=iters,
                                       dll=args.fuzz_dll, func=args.fuzz_func)
        else:
            if not os.path.isdir(args.directory):
                print("[!] fuzzing 需要目录，跳过")
            else:
                exes = fuzzer._find_executables(args.directory)
                if not exes:
                    print("[!] 目录下未找到 .exe 可执行文件，跳过 fuzzing")
                else:
                    if args.fuzz_bin:
                        m = [e for e in exes if os.path.basename(e).lower() == args.fuzz_bin.lower()]
                        tgt = m[0] if m else max(exes, key=os.path.getsize)
                    else:
                        tgt = max(exes, key=os.path.getsize)
                    print(f"[*] fuzzing 目标: {tgt}（样本 {iters}）")
                    fuzz_res = fuzzer.fuzz(tgt, mode=fmode, iters=iters)
        if fuzz_res is not None:
            print(f"[*] 去重崩溃 {len(fuzz_res['crashes'])} 个，已存: {fuzz_res['crashes_dir']}")
            results["fuzz_results"] = fuzz_res
            fuzz_fixed = os.path.join(out_dir, "fuzz_report.html")
            fuzz_stamp = os.path.join(out_dir, f"fuzz_report_{stamp}.html")
            report_fuzz.generate_fuzz_report(fuzz_res, fuzz_fixed, scanned_at=scanned_at)
            report_fuzz.generate_fuzz_report(fuzz_res, fuzz_stamp, scanned_at=scanned_at)
            print(f"[*] fuzzing 报告已生成: {fuzz_fixed}")

    # Module 10: online web-business probe (read-only, non-destructive)
    if args.webprobe:
        import web_probe
        import report_probe
        wurl = args.weburl or (args.port or "")
        if not wurl:
            print("[!] 模块10 需提供目标 URL（--weburl），跳过")
        else:
            print(f"\n[*] 模块10: Web 在线业务探测（只读，{wurl}）...")
            wfind, winfo = web_probe.probe(wurl)
            print(f"[*] 目标可达: {winfo['reachable']}，发现 {len(wfind)} 个可报告项")
            results["webprobe"] = {"url": winfo["url"], "reachable": winfo["reachable"],
                                   "findings": wfind}
            wfixed = os.path.join(out_dir, "web_probe_report.html")
            wstamp = os.path.join(out_dir, f"web_probe_report_{stamp}.html")
            report_probe.generate_probe_report(results["webprobe"], wfixed, scanned_at=scanned_at)
            report_probe.generate_probe_report(results["webprobe"], wstamp, scanned_at=scanned_at)
            print(f"[*] Web 在线业务探测报告已生成: {wfixed}")

    # Module 11: subdomain enumeration (passive DNS, read-only)
    if args.subdomain:
        import subdomain_enum
        print(f"\n[*] 模块11: 子域名枚举（{args.subdomain}，被动 DNS）...")
        sub_found, sub_meta = subdomain_enum.enumerate_subdomains(args.subdomain)
        print(f"[*] 发现 {len(sub_found)} 个子域")
        results["subdomain"] = {"found": sub_found, "meta": sub_meta}
        sub_fixed = os.path.join(out_dir, "subdomain_report.html")
        sub_stamp = os.path.join(out_dir, f"subdomain_report_{stamp}.html")
        subdomain_enum.generate_report(sub_found, sub_meta, sub_fixed, scanned_at=scanned_at)
        subdomain_enum.generate_report(sub_found, sub_meta, sub_stamp, scanned_at=scanned_at)
        print(f"[*] 子域枚举报告已生成: {sub_fixed}")

    # Module 12: TLS / certificate check (read-only handshake)
    if args.tls:
        import tls_check
        print(f"\n[*] 模块12: TLS/证书检查（{args.tls}，只读握手）...")
        tls_find, tls_info = tls_check.check_tls(args.tls)
        if tls_info.get("reachable"):
            print(f"[*] 协议 {tls_info.get('proto')}，证书 {tls_info.get('cn')}，"
                  f"剩余 {tls_info.get('days_left')} 天，发现 {len(tls_find)} 项")
        else:
            print("[!] TLS 目标不可达")
        results["tls"] = {"info": tls_info, "findings": tls_find}
        tls_fixed = os.path.join(out_dir, "tls_report.html")
        tls_stamp = os.path.join(out_dir, f"tls_report_{stamp}.html")
        tls_check.generate_report(tls_info, tls_find, tls_fixed, scanned_at=scanned_at)
        tls_check.generate_report(tls_info, tls_find, tls_stamp, scanned_at=scanned_at)
        print(f"[*] TLS/证书检查报告已生成: {tls_fixed}")

    # Module 13: SBOM supply-chain inventory (read-only)
    if args.sbom:
        import sbom_gen
        print(f"\n[*] 模块13: 生成 SBOM 供应链清单（{args.directory}）...")
        sb_comps, sb_manifests, sb_by_eco = sbom_gen.build_sbom(args.directory)
        print(f"[*] 清单 {len(sb_manifests)} 个，组件 {len(sb_comps)} 个："
              f"{dict(sorted(sb_by_eco.items(), key=lambda x: -x[1]))}")
        results["sbom"] = {"components": len(sb_comps), "manifests": len(sb_manifests),
                           "components_list": sb_comps}
        sb_json = os.path.join(out_dir, "sbom.json")
        sb_fixed = os.path.join(out_dir, "sbom_report.html")
        sb_stamp = os.path.join(out_dir, f"sbom_report_{stamp}.html")
        doc = sbom_gen.cyclone_dx(sb_comps, args.directory)
        with open(sb_json, "w", encoding="utf-8") as fp:
            json.dump(doc, fp, ensure_ascii=False, indent=2)
        sbom_gen.generate_report(sb_comps, sb_by_eco, args.directory, sb_fixed, scanned_at=scanned_at)
        sbom_gen.generate_report(sb_comps, sb_by_eco, args.directory, sb_stamp, scanned_at=scanned_at)
        print(f"[*] SBOM 已生成: {sb_json}  /  {sb_fixed}")

    # Module 14: online sensitive-info leak scan (read-only)
    if args.onleak:
        import online_leak
        print(f"\n[*] 模块14: 在线敏感信息爬取（{args.onleak}，只读页面抓取）...")
        leak_f, leak_i = online_leak.scan_url(args.onleak)
        print(f"[*] 可达 {leak_i.get('ok')}，候选命中 {len(leak_f)} 项")
        results["onleak"] = {"findings": len(leak_f), "info": leak_i}
        leak_fixed = os.path.join(out_dir, "online_leak_report.html")
        leak_stamp = os.path.join(out_dir, f"online_leak_report_{stamp}.html")
        online_leak.generate_report(leak_f, leak_i, leak_fixed, scanned_at=scanned_at)
        online_leak.generate_report(leak_f, leak_i, leak_stamp, scanned_at=scanned_at)
        print(f"[*] 在线敏感信息报告已生成: {leak_fixed}")

    # Module 15: web tech-stack fingerprint (read-only)
    if args.fingerprint:
        import web_fingerprint
        wurl = args.weburl
        if not wurl:
            print("[!] 模块15 需提供目标 URL（--weburl），跳过")
        else:
            print(f"\n[*] 模块15: Web 技术栈指纹识别（{wurl}，只读）...")
            fp_find, fp_info = web_fingerprint.probe(wurl)
            print(f"[*] 识别到 {len(fp_find)} 项技术栈")
            results["fingerprint"] = {"findings": fp_find, "info": fp_info}
            fp_fixed = os.path.join(out_dir, "fingerprint_report.html")
            fp_stamp = os.path.join(out_dir, f"fingerprint_report_{stamp}.html")
            web_fingerprint.generate_report(fp_find, fp_info, fp_fixed, scanned_at=scanned_at)
            web_fingerprint.generate_report(fp_find, fp_info, fp_stamp, scanned_at=scanned_at)
            print(f"[*] 技术栈指纹报告已生成: {fp_fixed}")

    # Module 16: JS sensitive-info & endpoint extraction (read-only)
    if args.jsextract:
        import js_extract
        wurl = args.weburl
        if not wurl:
            print("[!] 模块16 需提供目标 URL（--weburl），跳过")
        else:
            print(f"\n[*] 模块16: JS 敏感信息/端点提取（{wurl}，只读）...")
            js_find, js_info = js_extract.scan_url(wurl)
            print(f"[*] 候选命中 {len(js_find)} 项")
            results["jsextract"] = {"findings": len(js_find), "info": js_info}
            js_fixed = os.path.join(out_dir, "js_extract_report.html")
            js_stamp = os.path.join(out_dir, f"js_extract_report_{stamp}.html")
            js_extract.generate_report(js_find, js_info, js_fixed, scanned_at=scanned_at)
            js_extract.generate_report(js_find, js_info, js_stamp, scanned_at=scanned_at)
            print(f"[*] JS 提取报告已生成: {js_fixed}")

    # Module 17: subdomain takeover detection (passive DNS, read-only)
    if args.takeover:
        import subdomain_takeover
        dom = args.takeover
        print(f"\n[*] 模块17: 子域接管检测（{dom}，被动 DNS）...")
        tk_res, tk_info = subdomain_takeover.scan_domain(dom)
        print(f"[*] CNAME 指向第三方 {len(tk_res)} 个")
        results["takeover"] = {"findings": tk_res, "info": tk_info}
        tk_fixed = os.path.join(out_dir, "subdomain_takeover_report.html")
        tk_stamp = os.path.join(out_dir, f"subdomain_takeover_report_{stamp}.html")
        subdomain_takeover.generate_report(tk_res, tk_info, tk_fixed, scanned_at=scanned_at)
        subdomain_takeover.generate_report(tk_res, tk_info, tk_stamp, scanned_at=scanned_at)
        print(f"[*] 子域接管报告已生成: {tk_fixed}")

    # Module 18: API asset discovery (read-only)
    if args.apidiscover:
        import api_discover
        wurl = args.weburl
        if not wurl:
            print("[!] 模块18 需提供目标 URL（--weburl），跳过")
        else:
            print(f"\n[*] 模块18: API 资产发现（{wurl}，只读）...")
            ap_find, ap_info = api_discover.scan_base(wurl)
            print(f"[*] 可访问端点 {len(ap_find)} 个")
            results["apidiscover"] = {"findings": ap_find, "info": ap_info}
            ap_fixed = os.path.join(out_dir, "api_discover_report.html")
            ap_stamp = os.path.join(out_dir, f"api_discover_report_{stamp}.html")
            api_discover.generate_report(ap_find, ap_info, ap_fixed, scanned_at=scanned_at)
            api_discover.generate_report(ap_find, ap_info, ap_stamp, scanned_at=scanned_at)
            print(f"[*] API 资产发现报告已生成: {ap_fixed}")

    # Module 7: unified report engine
    if args.all:
        import report_all
        unified = os.path.join(out_dir, "unified_report.html")
        report_all.generate_all_report(results, unified, scanned_at=scanned_at)

    # history snapshot for later diff (history_compare.py)
    try:
        hdir = os.path.join(out_dir, "history")
        os.makedirs(hdir, exist_ok=True)
        snap = {"stamp": stamp, "scanned_at": scanned_at,
                "dir": args.directory, "results": results}
        with open(os.path.join(hdir, f"{stamp}_snapshot.json"), "w",
                  encoding="utf-8") as fp:
            json.dump(snap, fp, ensure_ascii=False, default=str)
        print(f"[*] 历史快照已保存: {os.path.join(hdir, stamp + '_snapshot.json')}")
    except Exception as e:
        print(f"[!] 历史快照保存失败: {e}")
        print(f"[*] 统一报告已生成: {unified}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
