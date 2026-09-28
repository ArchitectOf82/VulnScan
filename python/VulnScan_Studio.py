# -*- coding: utf-8 -*-
"""
VulnScan Studio - unified product UI (tkinter, no browser / no HTTP server).

Opens a window with all 7 capabilities. Pick a target directory (or host),
choose module(s), scan, then open the generated HTML report.

Run:  python VulnScan_Studio.py   (or double-click  VulnScan Studio.bat)
"""

import os
import sys
import json
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PYTHON = sys.executable
OUT = os.path.join(ROOT, "output")
REPORTS = {
    "cve":       ("vulnscan_report.html", "① 第三方库 CVE 扫描"),
    "audit":     ("binary_audit_report.html", "② 二进制安全审计"),
    "leak":      ("info_leak_report.html", "③ 信息泄露扫描"),
    "web":       ("web_weak_report.html", "④ Web 弱配置"),
    "baseline":  ("baseline_report.html", "⑤ 系统安全基线"),
    "port":      ("port_scan_report.html", "⑥ 端口 & 服务识别"),
    "dep":       ("dep_scan_report.html", "⑧ 依赖清单扫描(全语言)"),
    "fuzz":      ("fuzz_report.html", "⑨ Fuzzer 二进制0day"),
    "webprobe":  ("web_probe_report.html", "⑩ Web 在线业务探测(只读)"),
    "subdomain": ("subdomain_report.html", "⑪ 子域名枚举(被动DNS)"),
    "tls":       ("tls_report.html", "⑫ TLS/证书检查"),
    "sbom":      ("sbom_report.html", "⑬ SBOM 供应链清单"),
    "onleak":    ("online_leak_report.html", "⑭ 在线敏感信息爬取(只读)"),
    "fingerprint": ("fingerprint_report.html", "⑮ Web 技术栈指纹(只读)"),
    "jsextract":   ("js_extract_report.html", "⑯ JS 敏感信息/端点提取(只读)"),
    "takeover":    ("subdomain_takeover_report.html", "⑰ 子域接管检测(被动DNS)"),
    "apidiscover": ("api_discover_report.html", "⑱ API 资产发现(只读)"),
    "all":       ("unified_report.html", "⑦ 统一报告（全部模块）"),
}

report_choice = {v[1]: k for k, v in REPORTS.items()}


class VulnScanStudio:
    def __init__(self, root):
        self.root = root
        root.title("VulnScan Studio — 多功能漏洞扫描产品")
        root.geometry("780x760")
        root.minsize(700, 700)

        self.dir_var = tk.StringVar(value="")
        self.host_var = tk.StringVar(value="127.0.0.1")
        self.weburl_var = tk.StringVar(value="")
        self.add_name_var = tk.StringVar(value="")
        self.add_needle_var = tk.StringVar(value="")
        self.fuzz_mode_var = tk.StringVar(value="file")
        self.fuzz_dll_var = tk.StringVar(value="")
        self.fuzz_func_var = tk.StringVar(value="")
        self.cron_freq_var = tk.StringVar(value="每天")
        self.cron_hour_var = tk.StringVar(value="10")
        self.cron_min_var = tk.StringVar(value="00")
        self.cron_targets_var = tk.StringVar(value="")
        self.cron_mod_var = tk.StringVar(value="在线批量扫描(subdomain+tls+onleak)")
        self.status_var = tk.StringVar(value="就绪。选择目录与模块后点击扫描。")
        self.log = []

        self._build()
        self._log("VulnScan Studio 已启动。仅用于授权资产内的安全评估（识别+报告，不含利用）。")

    def _build(self):
        pad = {"padx": 12, "pady": 6}
        frm = ttk.Frame(self.root, padding=14)
        frm.pack(fill="both", expand=True)

        # Target
        tk.Label(frm, text="扫描目录（本地文件类模块）", font=("Microsoft YaHei", 10)).pack(anchor="w", **pad)
        row = ttk.Frame(frm)
        row.pack(fill="x", padx=12)
        self.dir_entry = ttk.Entry(row, textvariable=self.dir_var, width=70)
        self.dir_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="浏览…", command=self._browse).pack(side="left", padx=6)

        tk.Label(frm, text="端口扫描目标主机（仅授权资产，默认本机）", font=("Microsoft YaHei", 10)).pack(anchor="w", **pad)
        row2 = ttk.Frame(frm)
        row2.pack(fill="x", padx=12)
        ttk.Entry(row2, textvariable=self.host_var, width=30).pack(side="left")

        tk.Label(frm, text="Web 在线探测目标 URL（模块10，只读非破坏，如 https://example.com）",
                 font=("Microsoft YaHei", 10)).pack(anchor="w", **pad)
        row3 = ttk.Frame(frm)
        row3.pack(fill="x", padx=12)
        ttk.Entry(row3, textvariable=self.weburl_var, width=70).pack(side="left", fill="x", expand=True)

        # Modules
        tk.Label(frm, text="选择要执行的模块", font=("Microsoft YaHei", 10)).pack(anchor="w", **pad)
        self.vars = {}
        grid = ttk.Frame(frm)
        grid.pack(fill="x", padx=12)
        mods = [
            ("cve", "① 第三方库 CVE 扫描", True),
            ("audit", "② 二进制安全审计", False),
            ("leak", "③ 信息泄露扫描", False),
            ("web", "④ Web 弱配置", False),
            ("baseline", "⑤ 系统安全基线(本机)", False),
            ("port", "⑥ 端口 & 服务识别(主机)", False),
            ("dep", "⑧ 依赖清单扫描(全语言)", False),
            ("fuzz", "⑨ Fuzzer 二进制0day", False),
            ("webprobe", "⑩ Web 在线业务探测(只读)", False),
            ("subdomain", "⑪ 子域名枚举(被动DNS)", False),
            ("tls", "⑫ TLS/证书检查", False),
            ("sbom", "⑬ SBOM 供应链清单", False),
            ("onleak", "⑭ 在线敏感信息爬取(只读)", False),
            ("fingerprint", "⑮ Web 技术栈指纹(只读)", False),
            ("jsextract", "⑯ JS 敏感信息/端点提取(只读)", False),
            ("takeover", "⑰ 子域接管检测(被动DNS)", False),
            ("apidiscover", "⑱ API 资产发现(只读)", False),
        ]
        for i, (key, label, default) in enumerate(mods):
            var = tk.BooleanVar(value=default)
            self.vars[key] = var
            tk.Checkbutton(grid, text=label, variable=var,
                           font=("Microsoft YaHei", 10)).grid(row=i // 2, column=i % 2, sticky="w", padx=4, pady=3)

        # Fuzzer config (module 9)
        fz = ttk.Frame(frm)
        fz.pack(fill="x", padx=12, pady=(2, 2))
        tk.Label(fz, text="Fuzzer模式", font=("Microsoft YaHei", 9)).pack(side="left")
        ttk.Combobox(fz, textvariable=self.fuzz_mode_var, values=["file", "stdin", "dll"],
                     width=7, state="readonly").pack(side="left", padx=4)
        tk.Label(fz, text="DLL路径(dll模式)", font=("Microsoft YaHei", 9)).pack(side="left")
        ttk.Entry(fz, textvariable=self.fuzz_dll_var, width=28).pack(side="left", padx=4)
        tk.Label(fz, text="函数", font=("Microsoft YaHei", 9)).pack(side="left")
        ttk.Entry(fz, textvariable=self.fuzz_func_var, width=14).pack(side="left", padx=4)

        # Actions
        bar = ttk.Frame(frm)
        bar.pack(fill="x", padx=12, pady=10)
        ttk.Button(bar, text="扫描所选模块", command=self._scan_selected, width=20).pack(side="left", padx=4)
        ttk.Button(bar, text="扫描全部（⑦ 统一报告）", command=self._scan_all, width=24).pack(side="left", padx=4)
        ttk.Button(bar, text="打开最近报告", command=self._open_recent, width=16).pack(side="left", padx=4)
        tk.Label(bar, text="报告", font=("Microsoft YaHei", 9)).pack(side="left", padx=(8, 2))
        self.report_choice_var = tk.StringVar(value="⑦ 统一报告（全部模块）")
        ttk.Combobox(bar, textvariable=self.report_choice_var,
                     values=list(report_choice.keys()), state="readonly",
                     width=26).pack(side="left", padx=2)
        ttk.Button(bar, text="导出 PDF", command=lambda: self._export("pdf"),
                   width=9).pack(side="left", padx=2)
        ttk.Button(bar, text="导出 Word", command=lambda: self._export("docx"),
                   width=10).pack(side="left", padx=2)

        # Scheduled scan (platform-level cron)
        cron_title = ttk.Frame(frm)
        cron_title.pack(fill="x", padx=12, pady=(8, 2))
        tk.Label(cron_title, text="定时扫描（自定义频率+时间，保存配置后我为你创建平台级定时任务）",
                 font=("Microsoft YaHei", 10)).pack(side="left")
        crow = ttk.Frame(frm)
        crow.pack(fill="x", padx=12, pady=2)
        tk.Label(crow, text="频率", font=("Microsoft YaHei", 9)).pack(side="left")
        ttk.Combobox(crow, textvariable=self.cron_freq_var, state="readonly", width=10,
                     values=["每天", "每周一", "每周二", "每周三", "每周四", "每周五",
                             "每周六", "每周日", "工作日(周一至周五)"]).pack(side="left", padx=4)
        tk.Label(crow, text="时", font=("Microsoft YaHei", 9)).pack(side="left")
        ttk.Combobox(crow, textvariable=self.cron_hour_var, state="readonly", width=4,
                     values=[f"{h:02d}" for h in range(24)]).pack(side="left", padx=2)
        tk.Label(crow, text="分", font=("Microsoft YaHei", 9)).pack(side="left")
        ttk.Combobox(crow, textvariable=self.cron_min_var, state="readonly", width=4,
                     values=[f"{m:02d}" for m in range(60)]).pack(side="left", padx=2)
        tk.Label(crow, text="模块", font=("Microsoft YaHei", 9)).pack(side="left", padx=(8, 2))
        ttk.Combobox(crow, textvariable=self.cron_mod_var, state="readonly", width=30,
                     values=["在线批量扫描(subdomain+tls+onleak)", "依赖清单+SBOM",
                             "系统安全基线(本机)", "全模块统一报告"]).pack(side="left", padx=2)
        crow2 = ttk.Frame(frm)
        crow2.pack(fill="x", padx=12, pady=2)
        tk.Label(crow2, text="目标(在线批量用，逗号分隔)", font=("Microsoft YaHei", 9)).pack(side="left")
        ttk.Entry(crow2, textvariable=self.cron_targets_var, width=46).pack(side="left", padx=4)
        ttk.Button(crow2, text="从文件导入目标", command=self._import_targets,
                   width=14).pack(side="left", padx=2)
        ttk.Button(crow2, text="生成并保存配置", command=self._save_cron_config,
                   width=16).pack(side="left", padx=4)

        # Auto library add
        tk.Label(frm, text="自动加库（扫新产品自动补 CVE，写入 data/extra_products.py）",
                 font=("Microsoft YaHei", 10)).pack(anchor="w", padx=12, pady=(8, 0))
        arow = ttk.Frame(frm)
        arow.pack(fill="x", padx=12, pady=4)
        tk.Label(arow, text="库名", font=("Microsoft YaHei", 9)).pack(side="left")
        ttk.Entry(arow, textvariable=self.add_name_var, width=16).pack(side="left", padx=4)
        tk.Label(arow, text="匹配标识(空格分隔)", font=("Microsoft YaHei", 9)).pack(side="left")
        ttk.Entry(arow, textvariable=self.add_needle_var, width=26).pack(side="left", padx=4)
        ttk.Button(arow, text="自动加库", command=self._auto_add).pack(side="left", padx=4)
        ttk.Button(arow, text="发现新库(当前目录)", command=self._discover).pack(side="left", padx=4)

        # Log
        tk.Label(frm, text="执行日志", font=("Microsoft YaHei", 11)).pack(anchor="w", **pad)
        self.txt = tk.Text(frm, height=14, font=("Microsoft YaHei", 11), wrap="word", state="disabled")
        self.txt.pack(fill="both", expand=True, padx=12, pady=(0, 6))
        tk.Label(frm, textvariable=self.status_var, fg="#34495e",
                 font=("Microsoft YaHei", 10)).pack(anchor="w", padx=12, pady=(0, 4))

    def _browse(self):
        d = filedialog.askdirectory()
        if d:
            self.dir_var.set(d)

    def _log(self, msg):
        self.log.append(msg)
        self.txt.configure(state="normal")
        self.txt.insert("end", msg + "\n")
        self.txt.see("end")
        self.txt.configure(state="disabled")

    def _run(self, cmd):
        self._log("$ " + " ".join(cmd))
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               encoding="utf-8", errors="replace",
                               timeout=600)
            out = (p.stdout or "").strip()
            if out:
                for line in out.splitlines()[-8:]:
                    self._log("   " + line)
            if p.returncode != 0 and (p.stderr or "").strip():
                self._log("   [stderr] " + p.stderr.strip()[-200:])
        except Exception as e:
            self._log(f"   [错误] {e}")

    def _open_report(self, key):
        fname = REPORTS[key][0]
        path = os.path.join(OUT, fname)
        if os.path.isfile(path):
            os.startfile(path)
            self._log(f"已打开: {path}")
        else:
            messagebox.showinfo("提示", f"尚未生成报告: {path}")

    def _export(self, fmt):
        key = report_choice[self.report_choice_var.get()]
        fname = REPORTS[key][0]
        path = os.path.join(OUT, fname)
        if not os.path.isfile(path):
            messagebox.showinfo("提示", f"尚未生成报告: {path}")
            return
        try:
            import report_export
            out = os.path.splitext(path)[0] + (".pdf" if fmt == "pdf" else ".docx")
            if fmt == "pdf":
                report_export.export_pdf(path, out)
            else:
                report_export.export_docx(path, out)
            self._log(f"已导出 {fmt.upper()}: {out}")
            os.startfile(out)
            messagebox.showinfo("完成", f"已导出 {os.path.basename(out)}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}")

    def _scan_selected(self):
        d = self.dir_var.get().strip()
        host = self.host_var.get().strip() or "127.0.0.1"
        wurl = self.weburl_var.get().strip()
        keys = [k for k, v in self.vars.items() if v.get()]
        if not keys:
            messagebox.showinfo("提示", "请至少勾选一个模块")
            return
        need_dir = [k for k in keys if k not in ("webprobe", "subdomain", "tls", "onleak",
                                                 "fingerprint", "jsextract", "takeover", "apidiscover")]
        if need_dir and not os.path.isdir(d):
            messagebox.showerror("错误", "扫描目录不存在或未填写（本地文件类模块需要目录）")
            return
        if ("webprobe" in keys or "onleak" in keys or "fingerprint" in keys
                or "jsextract" in keys or "apidiscover" in keys) and not wurl:
            messagebox.showerror("错误", "请填写 Web 探测目标 URL（http:// 或 https:// 开头）")
            return
        sub_domain = ""
        if wurl:
            sd = wurl.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            sub_domain = sd
        if ("subdomain" in keys or "takeover" in keys) and not sub_domain:
            messagebox.showerror("错误", "请填写 Web 探测目标 URL 里的域名（模块11/17 用于子域枚举/接管检测）")
            return
        if "tls" in keys and not host:
            messagebox.showerror("错误", "请填写端口扫描目标主机（模块12 用于 TLS 检测）")
            return

        flagmap = {
            "cve": [],
            "audit": ["--audit"],
            "leak": ["--leak"],
            "web": ["--web"],
            "baseline": ["--baseline"],
            "port": ["--port", host],
            "dep": ["--dep"],
            "fuzz": ["--fuzz", "--fuzz-mode", self.fuzz_mode_var.get().strip() or "file"],
            "webprobe": ["--webprobe", "--weburl", wurl],
            "subdomain": ["--subdomain", sub_domain],
            "tls": ["--tls", host],
            "sbom": ["--sbom"],
            "onleak": ["--onleak", wurl],
            "fingerprint": ["--fingerprint", "--weburl", wurl],
            "jsextract": ["--jsextract", "--weburl", wurl],
            "takeover": ["--takeover", sub_domain],
            "apidiscover": ["--apidiscover", "--weburl", wurl],
        }
        if "fuzz" in keys:
            _d = self.fuzz_dll_var.get().strip()
            _fn = self.fuzz_func_var.get().strip()
            if _d:
                flagmap["fuzz"] += ["--fuzz-dll", _d]
            if _fn:
                flagmap["fuzz"] += ["--fuzz-func", _fn]
        vscan = os.path.join(HERE, "vulnscan.py")

        def job():
            self._log(f"\n===== 开始扫描（勾选 {len(keys)} 个模块）=====")
            self._log(f"目录: {d} | 主机: {host}")
            for key in keys:
                tdir = d if d else os.path.dirname(HERE)
                cmd = [PYTHON, vscan, tdir] + flagmap[key] + ["--out", OUT, "--no-nvd"]
                self._log(f"--- 模块: {REPORTS[key][1]} ---")
                self._run(cmd)
                self._open_report(key)
            self.status_var.set("扫描完成。已打开各模块报告。")
            self._log("===== 完成 =====\n")

        threading.Thread(target=job, daemon=True).start()
        self.status_var.set("扫描中…")

    def _scan_all(self):
        d = self.dir_var.get().strip()
        if not os.path.isdir(d):
            messagebox.showerror("错误", "扫描目录不存在或未填写")
            return
        host = self.host_var.get().strip() or "127.0.0.1"

        def job():
            self._log("\n===== 扫描全部模块 → 统一报告 =====")
            cmd = [PYTHON, os.path.join(HERE, "vulnscan.py"), d,
                   "--audit", "--leak", "--web", "--baseline", "--dep",
                   "--port", host, "--all", "--out", OUT, "--no-nvd"]
            self._run(cmd)
            self.status_var.set("全部模块完成。打开统一报告。")
            self._open_report("all")
            self._log("===== 完成 =====\n")

        threading.Thread(target=job, daemon=True).start()
        self.status_var.set("全模块扫描中…")

    def _open_recent(self):
        # offer the unified report, else cve report
        for key in ("all", "cve"):
            fname = REPORTS[key][0]
            p = os.path.join(OUT, fname)
            if os.path.isfile(p):
                os.startfile(p)
                return
        messagebox.showinfo("提示", "尚未生成任何报告")

    def _auto_add(self):
        name = self.add_name_var.get().strip()
        needle = self.add_needle_var.get().strip()
        if not name or not needle:
            messagebox.showinfo("提示", "请填库名和匹配标识。\n例：库名 libvips，匹配标识 libvips vips")
            return
        cmd = [PYTHON, os.path.join(HERE, "add_library.py"), "add", name] + needle.split()

        def job():
            self._log(f"\n===== 自动加库: {name} =====")
            self._run(cmd)
            self.status_var.set("加库完成（识别规则 + CVE 已写入 data/extra_products.py）")
            self._log("===== 完成 =====\n")

        threading.Thread(target=job, daemon=True).start()
        self.status_var.set("加库中（从 NVD 拉 CVE，可能需等待）…")

    def _discover(self):
        d = self.dir_var.get().strip()
        if not os.path.isdir(d):
            messagebox.showerror("错误", "请先填写有效扫描目录")
            return
        cmd = [PYTHON, os.path.join(HERE, "add_library.py"), "discover", d]

        def job():
            self._log("\n===== 发现未识别第三方库（当前目录）=====")
            self._run(cmd)
            self._log("看到候选库名后，在上方填库名+标识点【自动加库】即可。\n")
            self.status_var.set("发现完成。见日志中的候选库列表。")

        threading.Thread(target=job, daemon=True).start()
        self.status_var.set("发现中…")

    def _import_targets(self):
        """Import authorized targets from a txt file (one target per line, # = comment)."""
        path = filedialog.askopenfilename(title="选择目标清单(txt)",
                                          filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as fp:
                lines = [l.strip() for l in fp if l.strip() and not l.strip().startswith("#")]
            if not lines:
                messagebox.showinfo("提示", "文件中没有有效目标（每行一个，可用 # 注释）")
                return
            self.cron_targets_var.set(", ".join(lines))
            self._log(f"已从文件导入 {len(lines)} 个目标: {path}")
            self._log("   " + "、".join(lines[:10]) + (" …" if len(lines) > 10 else ""))
            messagebox.showinfo("导入完成", f"已导入 {len(lines)} 个目标到目标框，可点【生成并保存配置】。")
        except Exception as e:
            messagebox.showerror("错误", f"读取文件失败: {e}")

    def _gen_cron(self):
        """Build a cron expression from the user's frequency/time selection."""
        freq = self.cron_freq_var.get().strip()
        hour = self.cron_hour_var.get().strip().zfill(2) or "10"
        minute = self.cron_min_var.get().strip().zfill(2) or "00"
        dow_map = {"每天": "*", "每周一": "1", "每周二": "2", "每周三": "3",
                   "每周四": "4", "每周五": "5", "每周六": "6", "每周日": "0",
                   "工作日(周一至周五)": "1-5"}
        dow = dow_map.get(freq, "*")
        return f"{minute} {hour} * * {dow}"

    def _save_cron_config(self):
        freq = self.cron_freq_var.get().strip()
        time_str = f"{self.cron_hour_var.get().strip().zfill(2) or '10'}:{self.cron_min_var.get().strip().zfill(2) or '00'}"
        cron = self._gen_cron()
        mod = self.cron_mod_var.get().strip()
        targets = self.cron_targets_var.get().strip()
        if mod.startswith("在线批量") and not targets:
            messagebox.showinfo("提示", "在线批量模式需要填目标列表（逗号分隔的授权域名/IP/URL）")
            return
        cfg = {"title": "VulnScan 定时扫描", "cron": cron, "schedule_type": "cron",
               "freq": freq, "time": time_str, "module": mod, "targets": targets}
        path = os.path.join(ROOT, "cron_config.json")
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(cfg, fp, ensure_ascii=False, indent=2)
        self._log(f"定时配置已保存: {path}")
        self._log(f"  频率 {freq} · 时间 {time_str} · cron 表达式: {cron}")
        self._log(f"  模块 {mod}" + (f" · 目标 {targets}" if targets else ""))
        self.status_var.set(f"定时配置已保存（cron: {cron}）。把目标发给我即可创建平台级定时任务。")
        messagebox.showinfo("定时配置", f"已保存到 cron_config.json\ncron 表达式: {cron}\n\n"
                             f"把目标列表发给我（或让我读取配置），我就创建平台级定时任务，到点自动扫描并出报告。")


def main():
    try:
        import tkinter  # noqa
    except Exception as e:
        print(f"[错误] 当前 Python 没有 tkinter: {e}\n请换用带 tkinter 的 Python 运行")
        return 1
    root = tk.Tk()
    VulnScanStudio(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
