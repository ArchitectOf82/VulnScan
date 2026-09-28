# -*- coding: utf-8 -*-
"""
VulnScan - Module 5: Web weak-configuration identification.

Static scan of web-related config files (web.config, .htaccess, nginx/apache
conf, appsettings, properties, ini, yaml) for weak-configuration signals:
debug mode, weak/default credentials, plaintext HTTP, directory listing,
server-version leak, weak crypto protocols, insecure cookies.

Read-only identification, no exploitation.
Usage:  python web_weak.py <dir>
"""

import os
import re

_RISK_LABEL = {"high": "高危", "medium": "中危", "low": "低危"}

# Weak-config patterns: (label, risk, regex)
_WEAK_PATTERNS = [
    ("debug 模式开启", "medium",
     re.compile(r"(?i)(debug[\"']?\s*[=:]\s*(true|1|on)|development[\"']?\s*[=:]\s*(true|1|on))")),
    ("默认/弱口令", "high",
     re.compile(r"(?i)(password|passwd|pwd)[\"']?\s*[=:]\s*['\"]?(123456|admin|password|"
                r"1234|12345|0000|test|root|qwerty|letmein)['\"]?")),
    ("管理员默认账号", "high",
     re.compile(r"(?i)admin\s*/\s*admin|(username|user|account)[\"']?\s*[=:]\s*['\"]?admin\b")),
    ("明文 HTTP 地址", "medium",
     re.compile(r"(?i)http://(?!localhost|127\.0\.0\.1)[^\s'\"]+")),
    ("目录列表开启", "medium",
     re.compile(r"(?i)(autoindex\s+on|Options\s+.*Indexes)")),
    ("服务器版本泄露", "medium",
     re.compile(r"(?i)ServerTokens|server(?:-signature)?\s+.*(apache|nginx|iis|php)[/\s]+\d")),
    ("弱加密协议(SSLv3/TLS1.0/RC4/DES)", "high",
     re.compile(r"(?i)(sslprotocol[^\n]*(sslv3|tlsv1\.0|tlsv1\.1)|"
                r"(sslcipherlist|ciphers|sslciphersuites)[^\n]*(RC4|DES|3DES))")),
    ("Cookie 缺 Secure/HttpOnly", "medium",
     re.compile(r"(?i)Set-Cookie[^\n]*(?<!secure)(?<!httponly)")),
    ("宽松跨域配置", "low",
     re.compile(r"(?i)(Access-Control-Allow-Origin\s*[:=]\s*['\"]?\*)")),
    ("禁用的 TLS(明文)", "low",
     re.compile(r"(?i)(ssl\s+off|sslenable\s+0|https\s*[=:]\s*false)")),
]

# Web-related config text files to scan
_WEB_EXT = (".conf", ".config", ".properties", ".ini", ".yaml", ".yml",
            ".json", ".xml", ".env", ".cfg")
_WEB_NAMES = ("web.config", ".htaccess", ".htpasswd", "nginx.conf", "httpd.conf",
              "apache.conf", "appsettings.json", "application.properties",
              "docker-compose.yml", "docker-compose.yaml", "haproxy.cfg", "php.ini",
              ".user.ini", "server.xml", "tomcat-users.xml")

_MAX = 512 * 1024

# Files/dirs that LOOK like configs but are build/cache artifacts, never web configs.
# e.g. CMake IntelliSense cache (codemodel-v2-*.json) contains "directoryIndexes",
# which would false-positive on directory-listing. Skip them.
_SKIP_DIR_NAMES = {".vs", ".git", "node_modules", "cmake-build-debug",
                   "cmake-build-release", "venv", ".venv", "__pycache__", "cache"}
_SKIP_FILE_PREFIX = ("codemodel-v2-", "ctest", "browse.vc", "slnx.")
_SKIP_FILE_NAMES = {"cmakecache.txt", "compile_commands.json", "link.txt",
                    "depend.internal", "depend.make", "flags.make"}


def _is_web_server_conf(name):
    """True only for files where DirectoryIndex / autoindex have real meaning
    (Apache/nginx/IIS-style server config), not for data/config JSON/XML."""
    n = name.lower()
    return (n.endswith(".conf") or n.endswith(".htaccess") or n.endswith(".htpasswd")
            or n in ("httpd.conf", "nginx.conf", "apache.conf", "haproxy.cfg",
                     "php.ini", ".user.ini", "server.xml", "tomcat-users.xml",
                     "web.config", "appsettings.json"))


def scan_file(path, name):
    """Return list of weak-config findings in a file."""
    hits = []
    try:
        if os.path.getsize(path) > _MAX:
            return hits
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                if len(line) > 4096:
                    line = line[:4096]
                for label, risk, rx in _WEAK_PATTERNS:
                    m = rx.search(line)
                    if m:
                        snippet = line.strip()
                        if len(snippet) > 100:
                            snippet = snippet[:100] + "..."
                        hits.append({"label": label, "risk": risk,
                                     "line": lineno, "snippet": snippet})
                        break
        # DirectoryIndex (Apache directive) is only meaningful in real web-server
        # config files; checked separately so CMake/JSON caches never trigger it.
        if _is_web_server_conf(name):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for lineno, line in enumerate(f, 1):
                    if re.search(r"(?i)(DirectoryIndex\b)", line):
                        hits.append({"label": "目录列表开启", "risk": "medium",
                                     "line": lineno,
                                     "snippet": line.strip()[:100] + "..."})
                        break
    except Exception:
        pass
    return hits


def scan_directory(target_dir):
    findings = []
    for dp, dn, fn in os.walk(target_dir):
        # skip build/cache directories entirely
        base = os.path.basename(os.path.normpath(dp))
        if base in _SKIP_DIR_NAMES or any(s in base for s in ("cmake-build", ".vs")):
            dn[:] = [d for d in dn if d not in _SKIP_DIR_NAMES]
            continue
        for f in fn:
            lower = f.lower()
            if lower in _SKIP_FILE_NAMES or lower.startswith(_SKIP_FILE_PREFIX):
                continue
            is_web = lower.endswith(_WEB_EXT) or lower in _WEB_NAMES
            if not is_web:
                continue
            p = os.path.join(dp, f)
            try:
                hits = scan_file(p, f)
                for h in hits:
                    findings.append({"file": p, "name": f, **h})
            except Exception:
                pass
    return findings


def summarize(findings):
    by_risk = {"high": [], "medium": [], "low": []}
    for f in findings:
        by_risk[f["risk"]].append(f)
    return by_risk


def main():
    import sys
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    res = scan_directory(d)
    by = summarize(res)
    total = len(res)
    print(f"total weak-config findings: {total}")
    for risk in ("high", "medium", "low"):
        print(f"  {_RISK_LABEL[risk]}: {len(by[risk])}")
    for f in res[:20]:
        print(f"  [{_RISK_LABEL[f['risk']]}] {f['name']}: {f['label']} (L{f['line']})")
    return res


if __name__ == "__main__":
    main()
