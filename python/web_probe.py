# -*- coding: utf-8 -*-
"""
VulnScan - Module 10: Online Web-business probe (READ-ONLY, NON-DESTRUCTIVE).

Probes a live web target with harmless requests (GET / HEAD / OPTIONS, no
payloads, no exploitation) and REPORTS potential issues only:
  - missing security headers
  - sensitive path / source-leak exposure (existence probes only)
  - server / tech fingerprint leak
  - lax CORS
  - TRACE method enabled
  - plaintext HTTP without HTTPS redirect

Only for targets you are authorized to test. No exploitation, no destructive
actions. Detection only, never sends attack payloads.

Usage:  python web_probe.py <url> [--out report.json]
"""

import sys
import json
import ssl
import urllib.request
import urllib.error

UA = ("Mozilla/5.0 (compatible; VulnScanProbe/1.0; read-only; "
      "authorized-target-only)")
TIMEOUT = 6

# Sensitive / interesting paths (existence probes, harmless GET/HEAD).
# Grouped by class; returning 200/301/302 on these is a candidate exposure.
SENSITIVE_PATHS = [
    # --- version control / source / CI ---
    "/.git/HEAD", "/.git/config", "/.gitignore", "/.git/objects/info/packs",
    "/.svn/entries", "/.svn/wc.db", "/.hg/hgrc", "/.hg/store",
    "/.bzr/README", "/.bzr/branch/branch.conf",
    "/.gitlab-ci.yml", "/.github/workflows/deploy.yml", "/Jenkinsfile",
    "/.travis.yml", "/build.gradle", "/pom.xml", "/composer.json",
    # --- env / config / credentials ---
    "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.flaskenv",
    "/.npmrc", "/.netrc", "/.aws/credentials", "/.ssh/id_rsa", "/.ssh/id_rsa.pub",
    "/.pem", "/.key", "/config.php", "/config.php.bak", "/config.php.old",
    "/config.yml", "/settings.py", "/settings.py.bak", "/application.properties",
    "/application.yml", "/appsettings.json", "/web.config.bak", "/web.config.old",
    "/wp-config.php.bak", "/wp-config.php.old",
    # --- backup / dump / logs ---
    "/backup.sql", "/backup.sql.gz", "/db.sql", "/dump.sql", "/database.sql",
    "/data.sql", "/.sql", "/backup.zip", "/backup.tar.gz", "/www.zip",
    "/site.tar.gz", "/app.rar", "/.DS_Store", "/Thumbs.db",
    "/error.log", "/access.log", "/debug.log", "/syslog", "/messages",
    "/var/log", "/server.log", "/info.php", "/phpinfo.php", "/phpinfo.php.bak",
    "/test.php", "/shell.php",
    # --- admin / management consoles ---
    "/admin/", "/admin", "/manager/", "/manager/html", "/console/",
    "/phpmyadmin/", "/pma/", "/webmail/", "/cpanel/", "/jenkins/",
    "/sonar/", "/nexus/", "/artifactory/", "/grafana/", "/prometheus/",
    "/kibana/", "/zabbix/", "/rabbitmq/", "/activemq/", "/hadoop/",
    # --- framework / runtime sensitive endpoints ---
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump",
    "/actuator/mappings", "/actuator/beans", "/actuator/configprops",
    "/actuator/gateway/routes", "/actuator/httptrace", "/actuator/loggers",
    "/actuator/conditions", "/actuator/scheduledtasks", "/actuator/logfile",
    "/env", "/heapdump", "/jolokia", "/jolokia/list", "/trace", "/mappings",
    "/beans", "/configprops", "/metrics", "/dump",
    "/debug/pprof", "/debug/pprof/heap", "/debug/pprof/goroutine",
    "/debug/vars", "/metrics", "/healthz", "/readyz",
    "/api/", "/api/swagger.json", "/swagger-ui.html", "/swagger/index.html",
    "/v2/api-docs", "/v3/api-docs", "/graphql", "/gql",
    "/rails/info", "/rails/info/routes", "/assets/", "/telescope", "/horizon",
    "/elmah.axd", "/trace.axd", "/glimpse.axd", "/_profiler/",
    "/__debug/", "/status", "/server-status", "/server-info",
    # --- generic leak / discovery ---
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/.well-known/security.txt", "/debug", "/test", "/phpunit.xml",
]

# Security headers that SHOULD exist on a public web service
SECURITY_HEADERS = {
    "X-Frame-Options": "点击劫持防护(X-Frame-Options)",
    "Content-Security-Policy": "内容安全策略(CSP)",
    "Strict-Transport-Security": "HSTS(强制 HTTPS)",
    "X-Content-Type-Options": "MIME 嗅探防护",
    "Referrer-Policy": "来源策略(Referrer-Policy)",
    "Permissions-Policy": "功能权限策略",
}

# Headers that leak fingerprint when present
LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]

# Path suffixes that are high-signal data/source leaks when they return 200
_HIGH_LEAK = (".git", "config", ".env", ".bak", ".old", "backup", ".sql", ".pem",
              ".key", "entries", "id_rsa", "credentials", ".aws", ".ssh", "password",
              ".yml", ".yaml", "properties", "settings", "appsettings", "dump",
              "log", "trace", "heapdump", "jolokia", "pprof", "credential", "secret")


def normalize_url(target):
    target = (target or "").strip()
    if not target:
        return None
    if "://" not in target:
        target = "https://" + target
    return target.rstrip("/")


def _request(url, method="GET"):
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "*/*")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=TIMEOUT, context=ctx) as resp:
            return {"status": resp.getcode(), "headers": dict(resp.headers),
                    "final_url": resp.geturl(), "reason": "ok"}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "headers": dict(e.headers),
                "final_url": getattr(e, "url", url), "reason": "http-error"}
    except Exception as e:
        return {"status": None, "headers": {}, "final_url": url, "reason": str(e)}


def probe(target):
    """Probe a target, return (findings, info)."""
    findings = []
    base = normalize_url(target)
    if not base:
        return findings, {"url": "", "reachable": False}

    info = {"url": base, "reachable": False}
    r = _request(base)
    if r["status"] is not None:
        info["reachable"] = True
    else:
        # fallback http
        alt = base.replace("https://", "http://", 1)
        r2 = _request(alt)
        if r2["status"] is not None:
            base, r, info["url"] = alt, r2, alt
            info["reachable"] = True
    if not info["reachable"]:
        return findings, info

    headers = {k.lower(): v for k, v in r["headers"].items()}

    # 1) missing security headers
    for h, desc in SECURITY_HEADERS.items():
        if h.lower() not in headers:
            findings.append({
                "category": "安全响应头缺失", "url": base, "risk": "medium",
                "detail": f"缺少 {desc}",
                "suggestion": f"在服务端/反向代理统一添加响应头 {h}（按业务需要配置）。"})

    # 2) fingerprint leak
    for h in LEAK_HEADERS:
        v = (headers.get(h.lower()) or "").strip()
        if v:
            findings.append({
                "category": "技术栈/版本指纹泄露", "url": base, "risk": "low",
                "detail": f"响应头 {h}: {v[:120]}",
                "suggestion": "隐藏或移除版本指纹响应头，降低针对性攻击面。"})

    # 3) lax CORS
    acao = (headers.get("access-control-allow-origin") or "").strip().strip('"')
    if acao == "*":
        findings.append({
            "category": "宽松 CORS", "url": base, "risk": "medium",
            "detail": "Access-Control-Allow-Origin: *（允许任意源跨域读取）",
            "suggestion": "按业务只对可信源开放，或用白名单反射受信任 Origin。"})

    # 4) TRACE enabled (XST risk)
    try:
        opt = _request(base, method="OPTIONS")
        oh = {k.lower(): v for k, v in (opt.get("headers") or {}).items()}
        allow = (oh.get("allow") or "")
        if "TRACE" in allow.upper():
            findings.append({
                "category": "TRACE 方法开启", "url": base, "risk": "low",
                "detail": f"OPTIONS 响应 Allow 含 TRACE（跨站追踪/XST 风险）",
                "suggestion": "在 Web 服务器禁用 TRACE 方法（如 Apache 关闭 TraceEnable）。"})
    except Exception:
        pass

    # 5) plaintext HTTP without HTTPS redirect
    if base.startswith("http://"):
        https_base = "https://" + base[len("http://"):]
        rh = _request(https_base)
        if rh["status"] is not None and rh["status"] < 400:
            findings.append({
                "category": "未强制 HTTPS", "url": base, "risk": "medium",
                "detail": "HTTP 明文可访问且未自动 301 跳转 HTTPS",
                "suggestion": "配置全站 301 重定向到 HTTPS 并启用 HSTS。"})

    # 6) sensitive-path existence probes (harmless GET)
    for path in SENSITIVE_PATHS:
        pr = _request(base + path)
        st = pr["status"]
        if st is None:
            continue
        if st in (200, 301, 302):
            last = path.split("/")[-1].lower()
            if st == 200 and last not in ("admin", "phpinfo.php"):
                pl = path.lower()
                risk = "high" if any(tok in pl for tok in _HIGH_LEAK) else "medium"
                findings.append({
                    "category": "敏感路径可访问", "url": base + path, "risk": risk,
                    "detail": f"路径 {path} 返回 HTTP 200（可能存在文件/目录/源码泄露）",
                    "suggestion": "移除或保护该资源；确认无需对外后禁止外网访问。"})
            # 301/302 typically redirect to a login/normal page - not reported

    return findings, info


def _risk_cn(r):
    return {"high": "高危", "medium": "中危", "low": "低危"}.get(r, r)


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    target = args[0]
    out = None
    if "--out" in args:
        out = args[args.index("--out") + 1]
    findings, info = probe(target)
    print(f"目标: {info['url']}  可达: {info['reachable']}")
    if not info["reachable"]:
        print("目标不可达或超时。")
        return 1
    print(f"发现 {len(findings)} 个可报告项")
    by = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        by[f["risk"]] += 1
        print(f"  [{_risk_cn(f['risk'])}] {f['category']} - {f['detail']}")
    print(f"  高危 {by['high']} / 中危 {by['medium']} / 低危 {by['low']}")
    if out:
        with open(out, "w", encoding="utf-8") as fp:
            json.dump({"url": info["url"], "reachable": info["reachable"],
                       "findings": findings}, fp, ensure_ascii=False, indent=2)
        print(f"JSON 已存: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
