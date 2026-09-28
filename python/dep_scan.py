# -*- coding: utf-8 -*-
"""
VulnScan - module 8: dependency manifest scanner (scan ALL language ecosystems).

Walks a directory for every language's dependency manifest (package.json /
requirements.txt / pom.xml / go.mod / Cargo.lock / Gemfile.lock / composer.lock /
packages.config ...), extracts (ecosystem, package, version), then queries OSV
(free, no key) which covers PyPI / npm / Maven / Go / RubyGems / crates.io /
Packagist / NuGet / Pub and returns exact vulns for that version with real CVSS.

Usage:
    python dep_scan.py <dir> [--out report.html]
"""

import os
import re
import json
import sys
import math
import time
import argparse
import urllib.request

OSV_QUERY = "https://api.osv.dev/v1/query"

# manifest filename (lower) -> (ecosystem, parser kind)
MANIFESTS = [
    ("package-lock.json", "npm", "npm_lock"),
    ("package.json", "npm", "npm"),
    ("yarn.lock", "npm", "yarn"),
    ("pnpm-lock.yaml", "npm", "pnpm"),
    ("pipfile.lock", "PyPI", "pipfile_lock"),
    ("poetry.lock", "PyPI", "poetry"),
    ("requirements.txt", "PyPI", "requirements"),
    ("requirements-dev.txt", "PyPI", "requirements"),
    ("go.mod", "Go", "go_mod"),
    ("go.sum", "Go", "go_sum"),
    ("cargo.lock", "crates.io", "cargo_lock"),
    ("cargo.toml", "crates.io", "cargo_toml"),
    ("gemfile.lock", "RubyGems", "gemfile_lock"),
    ("composer.lock", "Packagist", "composer_lock"),
    ("pom.xml", "Maven", "pom"),
    ("packages.config", "NuGet", "packages_config"),
    ("pubspec.lock", "Pub", "pubspec_lock"),
]


def _norm(v):
    v = (v or "").strip()
    m = re.match(r"^[=~>^]+\s*(\d[\w.\-]*)", v)
    return m.group(1) if m else v


# ---------------------------------------------------------------- CVSS 3.1 base
def cvss3_base(vec):
    """Convert a CVSS:3.1 vector string to its numeric base score (0.0-10.0)."""
    if not vec or "CVSS:3" not in vec:
        return 0.0
    try:
        parts = dict(p.split(":", 1) for p in vec.split("/")[1:])
    except Exception:
        return 0.0
    AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(parts.get("AV", "N"), 0.85)
    AC = {"L": 0.77, "H": 0.44}.get(parts.get("AC", "L"), 0.77)
    UI = {"N": 0.85, "R": 0.62}.get(parts.get("UI", "N"), 0.85)
    C = {"H": 0.56, "L": 0.22, "N": 0}.get(parts.get("C", "N"), 0)
    I = {"H": 0.56, "L": 0.22, "N": 0}.get(parts.get("I", "N"), 0)
    A = {"H": 0.56, "L": 0.22, "N": 0}.get(parts.get("A", "N"), 0)
    S = parts.get("S", "U")
    if S == "C":
        PR = {"N": 0.85, "L": 0.68, "H": 0.5}.get(parts.get("PR", "N"), 0.85)
    else:
        PR = {"N": 0.85, "L": 0.62, "H": 0.27}.get(parts.get("PR", "N"), 0.85)
    ISS = 1 - (1 - C) * (1 - I) * (1 - A)
    if S == "C":
        imp = 7.52 * (ISS - 0.029) - 3.25 * ((ISS - 0.02) ** 15)
    else:
        imp = 6.42 * ISS
    exp = 8.22 * AV * AC * PR * UI
    return min(math.ceil(min(imp + exp, 10.0) * 10) / 10.0, 10.0)


# ---------------------------------------------------------------- parsers
def _parse_npm_lock(txt):
    try:
        data = json.loads(txt)
    except Exception:
        return []
    deps = []
    pk = data.get("packages", {})
    for path, info in pk.items():
        if not path or info is None:
            continue
        name = info.get("name")
        ver = info.get("version")
        if name and ver:
            deps.append((name, _norm(ver)))
    if not deps:
        for name, info in data.get("dependencies", {}).items():
            ver = info.get("version") if isinstance(info, dict) else None
            if ver:
                deps.append((name, _norm(ver)))
    return deps


def _parse_npm(txt):
    try:
        data = json.loads(txt)
    except Exception:
        return []
    deps = []
    for name, ver in {**(data.get("dependencies") or {}),
                      **(data.get("devDependencies") or {})}.items():
        v = _norm(ver) if isinstance(ver, str) else ""
        if v:
            deps.append((name, v))
    return deps


def _parse_yarn(txt):
    deps = []
    for m in re.finditer(r'^"?([\w@.\-/_]+)"?@(?:"?[^"]*?"?@)?\^?~?([0-9][\w.\-]*)', txt, re.M):
        deps.append((m.group(1).split("@")[-1], m.group(2)))
    return deps


def _parse_pnpm(txt):
    deps = []
    for m in re.finditer(r"^\s{2}([\w@.\-/]+)@([0-9][\w.\-]*):", txt, re.M):
        deps.append((m.group(1).split("@")[-1], m.group(2)))
    return deps


def _parse_pipfile_lock(txt):
    try:
        data = json.loads(txt)
    except Exception:
        return []
    deps = []
    for sec in ("default", "develop"):
        for name, info in (data.get(sec) or {}).items():
            ver = (info.get("version") if isinstance(info, dict) else None) or ""
            v = re.sub(r"^[=~<>!]+", "", ver).strip()
            if v:
                deps.append((name, v))
    return deps


def _parse_poetry(txt):
    deps, cur = [], {}
    for line in txt.splitlines():
        m = re.match(r'name\s*=\s*"([^"]+)"', line)
        if m:
            cur["name"] = m.group(1)
        m = re.match(r'version\s*=\s*"([^"]+)"', line)
        if m:
            cur["version"] = m.group(1)
        if cur.get("name") and cur.get("version"):
            deps.append((cur["name"], cur["version"]))
            cur = {}
    return deps


def _parse_requirements(txt):
    deps = []
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = re.split(r"\s*#", line, 1)[0].strip()
        m = re.match(r"([A-Za-z0-9_.\-]+)\s*==\s*([0-9][\w.\-]*)", line)
        if m:
            deps.append((m.group(1), m.group(2)))
    return deps


def _parse_go_mod(txt):
    deps, in_req = [], False
    for line in txt.splitlines():
        s = line.strip()
        if s.startswith("require"):
            rest = s[len("require"):].strip()
            if rest.startswith("("):
                in_req = True
                continue
            m = re.match(r"([\w./\-]+)\s+v?([0-9][\w.\-]*)", rest)
            if m:
                deps.append((m.group(1), m.group(2)))
        elif in_req:
            if s == ")":
                in_req = False
                continue
            m = re.match(r"([\w./\-]+)\s+v?([0-9][\w.\-]*)", s)
            if m and not s.startswith("//"):
                deps.append((m.group(1), m.group(2)))
    return deps


def _parse_go_sum(txt):
    deps, seen = [], set()
    for line in txt.splitlines():
        m = re.match(r"^([\w./\-]+)\s+v?([0-9][\w.\-]*)\s", line)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            deps.append((m.group(1), m.group(2)))
    return deps


def _parse_cargo_lock(txt):
    deps, cur = [], {}
    for line in txt.splitlines():
        m = re.match(r'name\s*=\s*"([^"]+)"', line)
        if m:
            cur["name"] = m.group(1)
        m = re.match(r'version\s*=\s*"([^"]+)"', line)
        if m:
            cur["version"] = m.group(1)
        if cur.get("name") and cur.get("version"):
            deps.append((cur["name"], cur["version"]))
            cur = {}
    return deps


def _parse_cargo_toml(txt):
    deps = []
    for m in re.finditer(r"^\s*([\w\-]+)\s*=\s*\{\s*version\s*=\s*\"([0-9][\w.\-]*)\"", txt, re.M):
        deps.append((m.group(1), m.group(2)))
    for m in re.finditer(r"^\s*([\w\-]+)\s*=\s*\"([0-9][\w.\-]*)\"", txt, re.M):
        deps.append((m.group(1), m.group(2)))
    return deps


def _parse_gemfile_lock(txt):
    deps = []
    for line in txt.splitlines():
        m = re.match(r"^\s+([\w.\-]+)\s+\(([0-9][\w.\-]*)\)", line)
        if m:
            deps.append((m.group(1), m.group(2)))
    return deps


def _parse_composer_lock(txt):
    try:
        data = json.loads(txt)
    except Exception:
        return []
    deps = []
    for p in data.get("packages") or []:
        name = p.get("name")
        ver = p.get("version")
        if name and ver:
            deps.append((name.split("/")[-1], re.sub(r"^v", "", ver)))
    return deps


def _parse_pom(txt):
    deps = []
    for b in re.findall(r"<dependency>(.*?)</dependency>", txt, re.S):
        g = re.search(r"<groupId>([^<]+)</groupId>", b)
        a = re.search(r"<artifactId>([^<]+)</artifactId>", b)
        v = re.search(r"<version>([^<]+)</version>", b)
        if g and a and v and not v.group(1).startswith("${"):
            deps.append((f"{g.group(1)}:{a.group(1)}", v.group(1)))
    return deps


def _parse_packages_config(txt):
    deps = []
    for m in re.finditer(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', txt):
        deps.append((m.group(1), m.group(2)))
    return deps


def _parse_pubspec_lock(txt):
    deps, cur = [], {}
    for line in txt.splitlines():
        m = re.match(r"^  ([\w_]+):", line)
        if m:
            cur["name"] = m.group(1)
        m = re.match(r"^\s+version:\s*\"([0-9][\w.\-]*)\"", line)
        if m and cur.get("name"):
            deps.append((cur["name"], m.group(1)))
            cur = {}
    return deps


_PARSERS = {
    "npm_lock": _parse_npm_lock, "npm": _parse_npm, "yarn": _parse_yarn,
    "pnpm": _parse_pnpm, "pipfile_lock": _parse_pipfile_lock, "poetry": _parse_poetry,
    "requirements": _parse_requirements, "go_mod": _parse_go_mod, "go_sum": _parse_go_sum,
    "cargo_lock": _parse_cargo_lock, "cargo_toml": _parse_cargo_toml,
    "gemfile_lock": _parse_gemfile_lock, "composer_lock": _parse_composer_lock,
    "pom": _parse_pom, "packages_config": _parse_packages_config,
    "pubspec_lock": _parse_pubspec_lock,
}


def find_manifests(root):
    found = []
    for dp, dn, fn in os.walk(root):
        for f in fn:
            low = f.lower()
            for mf, eco, kind in MANIFESTS:
                if low == mf:
                    found.append((os.path.join(dp, f), eco, kind))
                    break
    return found


def parse_manifest(path, eco, kind):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            txt = f.read()
    except Exception:
        return []
    parser = _PARSERS.get(kind)
    return [(eco, name, ver) for name, ver in (parser(txt) if parser else []) if ver]


def _cvss_of(vuln):
    for sev in vuln.get("severity") or []:
        if sev.get("type") == "CVSS_V3":
            return cvss3_base(sev.get("score", ""))
    return 0.0


def _fixed_of(vuln):
    for aff in vuln.get("affected") or []:
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    return ev["fixed"]
    return None


def query_osv(deps):
    """deps: list of (ecosystem, name, version). Full per-package query."""
    results = []
    for i, d in enumerate(deps):
        body = json.dumps({"package": {"ecosystem": d[0], "name": d[1]},
                           "version": d[2]}).encode("utf-8")
        req = urllib.request.Request(OSV_QUERY, data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=40) as r:
                data = json.loads(r.read().decode("utf-8"))
        except Exception as e:
            results.append({"status": "error", "vulns": [], "reason": str(e)})
            continue
        items = []
        for v in data.get("vulns") or []:
            items.append({"id": v.get("id", ""),
                          "summary": (v.get("summary") or "")[:180],
                          "cvss": _cvss_of(v),
                          "fixed": _fixed_of(v),
                          "aliases": (v.get("aliases") or [])[:5]})
        results.append({"status": "ok", "vulns": items})
        if i % 5 == 4:
            time.sleep(0.6)
    return results


def run_dep_scan(root):
    manifests = find_manifests(root)
    result = {"manifests": [], "deps": [], "vuln_count": 0, "ok": True,
              "total_deps": 0, "manifests_count": len(manifests)}
    deps_flat = []
    for path, eco, kind in manifests:
        parsed = parse_manifest(path, eco, kind)
        result["manifests"].append({"file": path, "ecosystem": eco, "count": len(parsed)})
        for eco2, name, ver in parsed:
            deps_flat.append((eco2, name, ver))
    seen, uniq = set(), []
    for d in deps_flat:
        k = (d[0], d[1], d[2])
        if k not in seen:
            seen.add(k)
            uniq.append(d)
    result["total_deps"] = len(uniq)
    if uniq:
        res = query_osv(uniq)
        for d, r in zip(uniq, res):
            item = {"ecosystem": d[0], "package": d[1], "version": d[2],
                    "status": r.get("status"), "vulns": r.get("vulns") or []}
            result["deps"].append(item)
            if r.get("status") == "ok":
                result["vuln_count"] += len(r.get("vulns") or [])
            if r.get("status") == "error":
                result["ok"] = False
    return result


def _html(res):
    vuln_deps = [d for d in res["deps"] if d["vulns"]]
    cards = f"""
    <div class='card'><b>{res['manifests_count']}</b><span>清单文件</span></div>
    <div class='card'><b>{res['total_deps']}</b><span>依赖项</span></div>
    <div class='card'><b>{res['vuln_count']}</b><span>已知漏洞</span></div>
    <div class='card'><b>{len(vuln_deps)}</b><span>含漏洞依赖</span></div>"""
    rows = ""
    for d in res["deps"]:
        if not d["vulns"]:
            continue
        id_tags = "、".join(f"<code>{v['id']}</code>" for v in d["vulns"])
        fix_tags = "、".join(dict.fromkeys([v["fixed"] or "?" for v in d["vulns"] if v["fixed"]]))
        sev = max((v["cvss"] for v in d["vulns"]), default=0)
        sev_txt = f"{sev:.1f}" if sev else "N/A"
        rows += (f"<tr><td>{d['ecosystem']}</td><td><b>{d['package']}</b></td>"
                 f"<td>{d['version']}</td><td>{len(d['vulns'])}</td><td>{sev_txt}</td>"
                 f"<td>{id_tags}</td><td>{fix_tags}</td></tr>")
    if not rows:
        rows = "<tr><td colspan='7' style='color:#666'>未发现已知漏洞依赖</td></tr>"
    return f"""<html><head><meta charset='utf-8'><title>依赖清单扫描报告</title>
<style>body{{font-family:Microsoft YaHei;margin:24px}} .cards{{display:flex;gap:12px;margin:16px 0}}
.card{{background:#1f2d3d;color:#fff;padding:14px 18px;border-radius:10px;flex:1}}
.card b{{font-size:26px;display:block}} .card span{{font-size:12px;color:#bcd}}
table{{border-collapse:collapse;width:100%;font-size:13px}} td,th{{border:1px solid #ddd;padding:6px 8px;text-align:left}}
th{{background:#eef2f7}} code{{background:#f3f4f6;padding:1px 4px;border-radius:4px}}</style></head><body>
<h2>模块 8 · 依赖清单扫描（全语言生态）</h2>
<div class='cards'>{cards}</div>
<h3>漏洞依赖明细</h3>
<table><tr><th>生态</th><th>包</th><th>版本</th><th>漏洞数</th><th>最高CVSS</th><th>漏洞ID</th><th>修复版本</th></tr>{rows}</table>
<h3>清单文件</h3><table><tr><th>文件</th><th>生态</th><th>依赖数</th></tr>""" + \
    "".join(f"<tr><td>{m['file']}</td><td>{m['ecosystem']}</td><td>{m['count']}</td></tr>"
            for m in res["manifests"]) + "</table></body></html>"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    res = run_dep_scan(args.dir)
    print(f"清单文件 {res['manifests_count']} 个，依赖 {res['total_deps']} 项，已知漏洞 {res['vuln_count']} 条")
    for d in res["deps"]:
        if d["vulns"]:
            sev = max((v["cvss"] for v in d["vulns"]), default=0)
            print(f"  [{d['ecosystem']}] {d['package']} {d['version']} -> {len(d['vulns'])} vulns (max cvss {sev:.1f})")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(_html(res))
        print("报告已写:", args.out)


if __name__ == "__main__":
    sys.exit(main())
