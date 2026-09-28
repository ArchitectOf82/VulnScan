# -*- coding: utf-8 -*-
"""
VulnScan - Module 3: Information leakage scan.

Two layers over a target directory:
  1) Filename/extension rules -> leaked file classes
     (backups, VCS leftovers, sensitive configs, keys/certs, DB files,
      logs/dumps, source/doc accidentally shipped)
  2) Content scan on text files -> hardcoded credentials / internal IPs /
     emails / connection strings

Static detection only, no exploitation.
Usage:  python info_leak.py <dir>
"""

import os
import re

# --- Category display ---
CATS = {
    "backup":    "备份/临时文件",
    "vcs":       "版本控制残留",
    "config":    "敏感配置",
    "key":       "密钥/证书",
    "database":  "数据库/数据文件",
    "logdump":   "日志/转储",
    "source":    "源码/文档分发",
    "credential":"内容硬编码凭证",
}

# --- Filename / extension rules ---
_FILENAME_RULES = []
def _add(cat, names=(), exts=(), base=(), suffixes=()):
    _FILENAME_RULES.append((cat, names, exts, base, suffixes))

_add("backup", exts=(".bak", ".backup", ".old", ".orig", ".swp", ".swo",
                    ".tmp", ".temp", ".part", ".rej", ".original"),
     suffixes=("~",))
_add("backup", names=())
# Word/office lock files
_add("backup", suffixes=("$",))  # ~$xxx.docx

_add("vcs", names=(".git", ".svn", ".hg", "CVS", ".gitignore",
                   ".gitconfig", ".gitmodules", ".svnignore", ".hgignore", ".bzr"))
_add("vcs", exts=(".git", ".svn"))

_add("config", names=(".env", ".env.local", ".env.production", "config.php",
                      "config.py", "config.js", "config.json", "web.config",
                      "appsettings.json", "appsettings.Development.json",
                      "settings.py", "settings.json", "global.json",
                      ".npmrc", ".pypirc", ".netrc", ".htpasswd", ".htaccess",
                      "hosts", "passwd", "shadow", "credentials", ".dockercfg",
                      "docker-compose.yml", "docker-compose.yaml", "package.json"),
     exts=(".env", ".conf", ".cfg", ".ini", ".properties"))
_add("config", base=("web.config", "appsettings", "settings", "config"))

_add("key", exts=(".pem", ".key", ".p12", ".pfx", ".jks", ".keystore",
                 ".crt", ".cer", ".der", ".csr", ".p7b", ".pub", ".asc",
                 ".gpg", ".ppk", ".keychain"))
_add("key", names=("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "known_hosts",
                   "authorized_keys", "ca.key", "server.key", "keystore.jks"))

_add("database", exts=(".sqlite", ".sqlite3", ".db", ".sqlitedb", ".dump",
                      ".dmp", ".mdb", ".accdb", ".sql", ".backupdb", ".db3"))
_add("database", base=("data", "database", "app", "userdata"))

_add("logdump", exts=(".log", ".minidump", ".core", ".crash", ".dmp",
                     ".dmp.tmp", ".etl", ".evtx", ".trace", ".mdmp"))
_add("logdump", names=("crash.log", "error.log", "debug.log", "access.log"))

_add("source", exts=(".cs", ".cpp", ".c", ".h", ".hpp", ".py", ".java",
                    ".js", ".ts", ".go", ".rs", ".rb", ".php", ".asp",
                    ".aspx", ".jsp", ".vue", ".sql.txt"))
_add("source", base=("src", "source"))

# --- Text extensions for content scan ---
_TEXT_EXT = (".txt", ".log", ".conf", ".cfg", ".ini", ".properties", ".json",
             ".xml", ".yml", ".yaml", ".env", ".config", ".js", ".ts", ".json5",
             ".html", ".htm", ".csv", ".bat", ".cmd", ".ps1", ".sh", ".py",
             ".cs", ".cpp", ".c", ".h", ".hpp", ".java", ".php", ".md", ".sql",
             ".rc", ".manifest")

_CONTENT_MAX = 512 * 1024  # only scan text files up to 512KB

# --- Content credential patterns ---
_CONTENT_PATTERNS = [
    ("aws_key",    re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("credential", re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|"
                              r"client[_-]?secret|access[_-]?token|auth[_-]?token|"
                              r"session[_-]?key|encrypt[_-]?key)\b\s*[:=]\s*"
                              r"['\"]?([^'\"\s,;]{6,})['\"]?")),
    ("connstr",    re.compile(r"(?i)(jdbc:|mongodb(\+srv)?://|postgres(ql)?://|"
                              r"mysql://|redis://|Server\s*=|Data\s+Source\s*=|"
                              r"Driver\s*=)")),
    ("internal_ip",re.compile(r"\b(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)"
                              r"\d{1,3}\.\d{1,3}\b")),
    ("localhost",  re.compile(r"(?i)https?://(localhost|127\.0\.0\.1|10\.|192\.168\.)")),
    ("email",      re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    ("hwid_mac",   re.compile(r"(?i)(mac[_-]?addr(ess)?|machine[_-]?id|device[_-]?id|"
                              r"hardware[_-]?id)\b\s*[:=]")),
]


def _match_filename(name, path):
    lower = name.lower()
    base = os.path.basename(path)
    base_lower = base.lower()
    for cat, names, exts, bases, suffixes in _FILENAME_RULES:
        for n in names:
            if lower == n or lower.startswith(n + "."):
                return cat
        for e in exts:
            if lower.endswith(e):
                return cat
        for b in bases:
            if base_lower == b or base_lower.startswith(b + "."):
                return cat
        for sfx in suffixes:
            if lower.endswith(sfx):
                return cat
    return None


def _scan_content(path):
    """Return list of (pattern_label, line_snippet) for a text file."""
    hits = []
    try:
        size = os.path.getsize(path)
        if size > _CONTENT_MAX:
            return hits
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                if len(line) > 4096:
                    line = line[:4096]
                for label, rx in _CONTENT_PATTERNS:
                    m = rx.search(line)
                    if m:
                        snippet = line.strip()
                        if len(snippet) > 90:
                            snippet = snippet[:90] + "..."
                        hits.append((label, f"L{lineno}: {snippet}"))
                        break  # one hit per line is enough
                if len(hits) >= 20:
                    break
    except Exception:
        pass
    return hits


def scan_file(path, name):
    """Return a finding dict or None."""
    cat = _match_filename(name, path)
    cred_hits = []
    if name.lower().endswith(_TEXT_EXT):
        cred_hits = _scan_content(path)
    if cat is None and not cred_hits:
        return None
    size = 0
    try:
        size = os.path.getsize(path)
    except Exception:
        pass
    return {"path": path, "name": name, "size": size,
            "cat": cat, "cred_hits": cred_hits}


def scan_directory(target_dir, maxdepth=None):
    findings = []
    for dp, dn, fn in os.walk(target_dir):
        # skip .git/.svn/... contents to avoid huge noise
        dn[:] = [d for d in dn if d not in (".git", ".svn", ".hg", ".bzr", "CVS",
                                            "node_modules", ".idea", ".vscode", "__pycache__")]
        for f in fn:
            if f.lower() in (".git", ".svn", ".hg"):
                continue
            p = os.path.join(dp, f)
            try:
                r = scan_file(p, f)
                if r:
                    findings.append(r)
            except Exception:
                pass
    return findings


def summarize(findings):
    by_cat = {}
    for f in findings:
        c = f["cat"] or "credential"
        by_cat.setdefault(c, []).append(f)
    return by_cat


if __name__ == "__main__":
    import sys
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    res = scan_directory(d)
    by = summarize(res)
    print(f"total findings: {len(res)}")
    for cat in by:
        print(f"  {CATS.get(cat, cat)}: {len(by[cat])}")
