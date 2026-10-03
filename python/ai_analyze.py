# -*- coding: utf-8 -*-
"""
ai_analyze.py - VulnScan AI 分析模块（LLM 双模式）

对扫描结果做 AI 解读：
  1) 每个命中漏洞的解释（是什么、危害、CVSS 级别）
  2) 误报筛查（判断哪些更可能是真问题）
  3) 修复建议
  4) 整体结论（适合放进报告）

模型接入（双模式，自动降级）：
  - 优先：本地 Ollama（默认 http://127.0.0.1:11434，可经 AI_OLLAMA_HOST 改）
  - 退用：OpenAI 兼容 API（经 AI_API_URL + AI_API_KEY + AI_MODEL 配置）
  - 都没有：降级为规则化总结（仍能出报告，只是没有 LLM 解读）

用法：
  python ai_analyze.py <snapshot.json> [--out report.html]   # 独立分析
  python vulnscan.py <dir> --ai                              # 集成模式（见 vulnscan.py）
"""

import os
import sys
import json
import argparse
import urllib.request
import urllib.error
from datetime import datetime

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))

# ---- 模型配置（环境变量可覆盖）----
OLLAMA_HOST = os.environ.get("AI_OLLAMA_HOST", "http://127.0.0.1:11434")
AI_API_URL = os.environ.get("AI_API_URL", "")
AI_API_KEY = os.environ.get("AI_API_KEY", "")
AI_MODEL = os.environ.get("AI_MODEL", "")          # 优先用的模型名（ollama 或 api 共用）
OLLAMA_MODEL = AI_MODEL or "qwen2.5"                # ollama 默认模型
API_MODEL = AI_MODEL or "deepseek-chat"              # api 默认模型（OpenAI 兼容）

SYSTEM_PROMPT = (
    "你是资深安全审计分析师。基于扫描工具给出的漏洞命中列表，逐项输出："
    "①问题说明(是什么/危害/风险等级) ②误报判断(可能是真问题/可能是误报/不确定，并给依据) "
    "③修复建议(具体可操作)。最后给一段整体结论。保持简洁、专业、实事求是，"
    "不要编造扫描结果里不存在的内容。用中文输出。"
)


def _check_ollama() -> bool:
    """探测本地 Ollama 是否可用（只读）。"""
    try:
        req = urllib.request.Request(f"{OLLAMA_HOST}/api/tags", timeout=2)
        with urllib.request.urlopen(req) as r:
            return r.status == 200
    except Exception:
        return False


def _chat(prompt: str, system: str = "") -> str:
    """优先 Ollama，退 OpenAI 兼容 API；全失败返回 None。"""
    # 1) Ollama 本地
    if _check_ollama():
        try:
            msgs = []
            if system:
                msgs.append({"role": "system", "content": system})
            msgs.append({"role": "user", "content": prompt})
            body = json.dumps({
                "model": OLLAMA_MODEL,
                "messages": msgs,
                "stream": False,
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{OLLAMA_HOST}/api/chat", data=body,
                headers={"Content-Type": "application/json"}, timeout=120)
            with urllib.request.urlopen(req) as r:
                data = json.loads(r.read().decode("utf-8"))
                return (data.get("message") or {}).get("content") or ""
        except Exception as e:
            print(f"[ai] Ollama 调用失败: {e}，尝试 API")

    # 2) OpenAI 兼容 API
    if AI_API_URL and AI_API_KEY:
        try:
            msgs = []
            if system:
                msgs.append({"role": "system", "content": system})
            msgs.append({"role": "user", "content": prompt})
            body = json.dumps({
                "model": API_MODEL,
                "messages": msgs,
                "stream": False,
            }).encode("utf-8")
            req = urllib.request.Request(
                AI_API_URL, data=body,
                headers={"Content-Type": "application/json",
                         "Authorization": f"Bearer {AI_API_KEY}"}, timeout=120)
            with urllib.request.urlopen(req) as r:
                data = json.loads(r.read().decode("utf-8"))
                return (data["choices"][0]["message"]["content"]) or ""
        except Exception as e:
            print(f"[ai] API 调用失败: {e}")

    return None


def detect_engine() -> str:
    """返回当前可用的引擎：ollama / api / none。"""
    if _check_ollama():
        return "ollama"
    if AI_API_URL and AI_API_KEY:
        return "api"
    return "none"


def _compact_matches(matches) -> str:
    """把 CVE 命中结果压缩成给 LLM 的输入文本。"""
    lines = []
    for m in matches:
        entry = m.get("entry") or {}
        product = m.get("product", "?")
        version = m.get("version", "?")
        name = entry.get("name", "")
        cves = sorted(m.get("matches", []), key=lambda c: -(c.get("cvss") or 0))
        line = f"- [{product} {version}] ({name})"
        for c in cves[:8]:
            line += f"\n    CVE {c.get('id')} CVSS={c.get('cvss')} {c.get('type')}: {c.get('desc')}"
        if len(cves) > 8:
            line += f"\n    ...另有 {len(cves)-8} 条"
        lines.append(line)
    return "\n".join(lines)


def _rule_summary(matches) -> dict:
    """无模型时的规则化降级总结（保证报告不空）。"""
    total_cves = 0
    max_cvss = 0.0
    by_type = {}
    items = []
    for m in matches:
        cves = sorted(m.get("matches", []), key=lambda c: -(c.get("cvss") or 0))
        if not cves:
            continue
        total_cves += len(cves)
        top = cves[0]
        cvss = float(top.get("cvss") or 0)
        if cvss > max_cvss:
            max_cvss = cvss
        by_type[top.get("type", "未知")] = by_type.get(top.get("type", "未知"), 0) + 1
        items.append({
            "product": m.get("product", "?"), "version": m.get("version", "?"),
            "cves": len(cves), "max_cvss": cvss,
            "top_cve": top.get("id"), "top_desc": top.get("desc", ""),
        })
    items.sort(key=lambda x: -x["max_cvss"])
    summary = {
        "libs_affected": len(items),
        "total_cves": total_cves,
        "max_cvss": max_cvss,
        "by_type": by_type,
        "items": items[:20],
    }
    return summary


def analyze(matches, extra_context: str = "") -> dict:
    """主入口：分析 CVE 命中结果，返回结构化结果。"""
    engine = detect_engine()
    result = {"engine": engine, "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

    if engine == "none":
        result["summary"] = _rule_summary(matches)
        result["note"] = "未配置 LLM（未检测到本地 Ollama，且未设 AI_API_URL/AI_API_KEY），已用规则化总结替代。"
        result["llm_text"] = None
        return result

    compact = _compact_matches(matches)
    if not compact.strip():
        compact = "本次扫描未发现命中的已知 CVE。"
    prompt = (
        f"以下是漏洞扫描工具对目标软件/目录的已知漏洞命中列表：\n\n{compact}\n\n"
        f"额外上下文：{extra_context if extra_context else '无'}\n\n"
        f"请按要求逐项分析并输出：\n"
        f"【整体结论】3-5句话概括整体风险水平、最值得优先处理的问题。\n"
        f"【逐项分析】对每个 [产品 版本]：风险等级 / 是否可能误报及依据 / 修复建议。\n"
        f"只分析列表里存在的内容，不要编造。"
    )
    ai_text = _chat(prompt, SYSTEM_PROMPT)
    if not ai_text:
        result["engine"] = "none"
        result["summary"] = _rule_summary(matches)
        result["note"] = "LLM 调用失败，已降级为规则化总结。"
        result["llm_text"] = None
        return result

    result["llm_text"] = ai_text
    result["summary"] = _rule_summary(matches)  # 附带结构化摘要供报告表格用
    result["note"] = f"AI 分析完成（引擎: {engine}）。"
    return result


def _render_html(result, target) -> str:
    engine = result.get("engine", "none")
    parts = []
    if result.get("llm_text"):
        parts.append(f"<h2>🤖 AI 分析结论（引擎: {engine}）</h2>"
                     f"<div style='white-space:pre-wrap;line-height:1.7;'>{result['llm_text']}</div>")
    else:
        parts.append(f"<h2>📊 规则化总结（无 LLM，引擎: {engine}）</h2>"
                     f"<div style='color:#8a93a6;font-size:13px;'>{result.get('note','')}</div>")
    s = result.get("summary") or {}
    if s:
        parts.append("<h3>结构化摘要</h3>")
        parts.append(f"<p>受影响库 <b>{s.get('libs_affected',0)}</b> 个 · 已知 CVE <b>{s.get('total_cves',0)}</b> 条 · "
                     f"最高 CVSS <b style='color:#c0392b;'>{s.get('max_cvss',0)}</b></p>")
        bt = s.get("by_type") or {}
        if bt:
            parts.append("<p>类型分布：" + "，".join(f"{k}({v})" for k, v in bt.items()) + "</p>")
        items = s.get("items") or []
        if items:
            rows = "".join(
                f"<tr><td>{it.get('product')} {it.get('version')}</td>"
                f"<td>{it.get('cves')}</td>"
                f"<td><b>{it.get('max_cvss')}</b></td>"
                f"<td>{it.get('top_cve')}</td></tr>" for it in items)
            parts.append("<table border='1' cellspacing='0' cellpadding='6' "
                         "style='border-collapse:collapse;width:100%;font-size:13px;'>"
                         "<tr style='background:#f0f2f5;'><th>产品 版本</th><th>CVE数</th>"
                         "<th>最高CVSS</th><th>首要CVE</th></tr>" + rows + "</table>")
    doc = (f'<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">'
           f'<title>VulnScan AI 分析报告</title></head>'
           f'<body style="margin:0;background:#f6f8fb;font-family:\'Microsoft YaHei\',sans-serif;">'
           f'<div style="max-width:1080px;margin:0 auto;padding:24px;">'
           f'<h1 style="font-size:24px;margin:0 0 4px;">AI 分析报告</h1>'
           f'<div style="color:#8a93a6;font-size:13px;margin-bottom:16px;">{result.get("scanned_at","")}</div>'
           f'<div style="background:#fff;border:1px solid #e3e6ec;border-radius:10px;padding:20px;">'
           f'{"".join(parts)}</div></div></body></html>')
    with open(target, "w", encoding="utf-8") as f:
        f.write(doc)
    return target


def main():
    ap = argparse.ArgumentParser(description="VulnScan AI 分析（LLM 双模式）")
    ap.add_argument("snapshot", help="扫描结果快照 JSON（vulnscan.py --all 生成）或 CVE 命中 JSON")
    ap.add_argument("--out", default=None, help="报告输出路径（默认 output/ai_report.html）")
    args = ap.parse_args()

    with open(args.snapshot, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 支持两种输入：整体快照 / 纯 cve_matches
    matches = data.get("cve_matches", data if isinstance(data, list) else [])
    out_dir = args.out or os.path.join(os.path.dirname(HERE), "output")
    os.makedirs(out_dir, exist_ok=True)
    target = args.out or os.path.join(out_dir, "ai_report.html")

    result = analyze(matches)
    _render_html(result, target)
    print(f"[*] 引擎: {result['engine']}")
    print(f"[*] AI 分析报告已生成: {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
