# -*- coding: utf-8 -*-
"""
VulnScan - Module 6: Windows security baseline check (read-only).

Queries read-only system state (firewall, Defender, password policy, accounts,
RDP, autologon credentials, shares, UAC, patches) and compares against a sane
baseline. No modification of any kind.

Usage:  python baseline.py
"""

import subprocess

_STATUS = {"pass": "通过", "warn": "警告", "fail": "未通过", "info": "信息", "n/a": "无法读取"}


def _ps(script, timeout=20):
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout)
        return p.stdout.strip()
    except Exception as e:
        return f"<err {e}>"


def _int(s):
    import re
    m = re.search(r"\d+", s or "")
    return int(m.group(0)) if m else None


# --- individual checks ---
def check_firewall():
    out = _ps("Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { \"$($_.Name)=$($_.Enabled)\" }")
    if not out or out.startswith("<err"):
        return {"item": "防火墙（Domain/Private/Public）", "value": out or "无法读取",
                "status": "n/a", "risk": "低", "detail": "需管理员权限读取"}
    vals = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            vals[k.strip()] = v.strip()
    off = [k for k, v in vals.items() if v.lower() != "true"]
    if off:
        return {"item": "防火墙", "value": f"{'、'.join(off)} 关闭", "status": "fail",
                "risk": "高", "detail": "这些网络配置文件的防火墙被关闭，暴露面增大"}
    return {"item": "防火墙（Domain/Private/Public）", "value": "全部启用", "status": "pass",
            "risk": "低", "detail": "三个配置文件防火墙均开启"}


def check_defender():
    out = _ps("(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled")
    if out.lower() == "true":
        return {"item": "Defender 实时保护", "value": "开启", "status": "pass", "risk": "低",
                "detail": "Windows Defender 实时防护运行中"}
    if out.lower() == "false":
        return {"item": "Defender 实时保护", "value": "关闭", "status": "fail", "risk": "高",
                "detail": "实时防护已关闭，可能被第三方安全软件接管或已禁用"}
    return {"item": "Defender 实时保护", "value": out or "无法读取", "status": "n/a",
            "risk": "中", "detail": "Get-MpComputerStatus 不可用（可能未启用 Defender 或需权限）"}


def check_patch():
    out = _ps("(Get-HotFix -ErrorAction SilentlyContinue).Count")
    n = _int(out)
    if n is None:
        return {"item": "系统补丁", "value": out or "无法读取", "status": "n/a", "risk": "中",
                "detail": "无法枚举已安装补丁"}
    return {"item": "已装系统补丁数", "value": str(n), "status": "info", "risk": "低",
            "detail": "补丁数量低不代表未打齐，建议以 Windows Update 提示为准"}


def _net_accounts():
    out = _ps("net accounts")
    return out.splitlines() if out else []


def check_pw_len(lines):
    for ln in lines:
        if "length" in ln.lower() or "长度" in ln:
            n = _int(ln)
            if n is not None:
                return {"item": "密码最小长度", "value": str(n), "status": "fail" if n < 8 else "pass",
                        "risk": "高" if n < 8 else "低",
                        "detail": "建议最小 8 位及以上" if n >= 8 else "低于 8 位，易被暴力破解"}
    return {"item": "密码最小长度", "value": "无法解析", "status": "n/a", "risk": "中", "detail": ""}


def check_pw_complex(lines):
    for ln in lines:
        l = ln.lower()
        if "complex" in l or "复杂" in l:
            if "require" in l or "必须" in l:
                return {"item": "密码复杂度要求", "value": "已启用", "status": "pass", "risk": "低", "detail": ""}
            if "disable" in l or "禁用" in l:
                return {"item": "密码复杂度要求", "value": "未启用", "status": "fail", "risk": "高",
                        "detail": "允许纯简单密码"}
    return {"item": "密码复杂度要求", "value": "无法解析", "status": "n/a", "risk": "中", "detail": ""}


def check_lockout(lines):
    for ln in lines:
        l = ln.lower()
        if ("lockout" in l or "锁定" in l) and ("threshold" in l or "次数" in l):
            n = _int(ln)
            if n is not None:
                return {"item": "账户锁定阈值", "value": str(n), "status": "fail" if n == 0 else "pass",
                        "risk": "高" if n == 0 else "低",
                        "detail": "锁定阈值为 0，允许无限次尝试，易被暴力破解" if n == 0 else ""}
    return {"item": "账户锁定阈值", "value": "无法解析", "status": "n/a", "risk": "中", "detail": ""}


def check_guest():
    out = _ps("(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled")
    if out.lower() == "true":
        return {"item": "Guest 账户", "value": "已启用", "status": "fail", "risk": "高",
                "detail": "Guest 账户启用存在风险，建议禁用"}
    if out.lower() == "false":
        return {"item": "Guest 账户", "value": "已禁用", "status": "pass", "risk": "低", "detail": ""}
    return {"item": "Guest 账户", "value": "无法读取", "status": "n/a", "risk": "中",
            "detail": "Get-LocalUser 不可用（旧系统）"}


def check_admins():
    out = _ps("Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }")
    names = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return {"item": "Administrators 组成员", "value": "、".join(names[:6]) if names else "无法读取",
            "status": "info", "risk": "中",
            "detail": "管理员账户越多，被攻破面越大，建议最小化"}


def check_rdp():
    out = _ps("(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections")
    if out == "0":
        return {"item": "远程桌面 (RDP)", "value": "已开启", "status": "warn", "risk": "高",
                "detail": "RDP 开启且暴露公网时风险高；确认有强口令与防火墙限制"}
    if out == "1":
        return {"item": "远程桌面 (RDP)", "value": "已关闭", "status": "pass", "risk": "低", "detail": ""}
    return {"item": "远程桌面 (RDP)", "value": "无法读取", "status": "n/a", "risk": "中", "detail": ""}


def check_autologon():
    out = _ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction SilentlyContinue).DefaultPassword")
    if out and not out.startswith("<err"):
        return {"item": "自动登录明文凭据", "value": "存在 DefaultPassword", "status": "fail", "risk": "高",
                "detail": "注册表 Winlogon 存在明文密码（自动登录），本地可读"}
    return {"item": "自动登录明文凭据", "value": "未发现", "status": "pass", "risk": "低", "detail": ""}


def check_shares():
    out = _ps("Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^\\\\(IPC\\$|ADMIN\\$|C\\$)' } | ForEach-Object { $_.Name }")
    names = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if names:
        return {"item": "非默认共享", "value": "、".join(names[:6]), "status": "warn", "risk": "中",
                "detail": "检测到自定义共享，确认是否需要；共享目录是攻击面"}
    return {"item": "非默认共享", "value": "无（或无法读取）", "status": "pass", "risk": "低", "detail": ""}


def check_uac():
    out = _ps("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction SilentlyContinue).EnableLUA")
    if out == "1":
        return {"item": "UAC", "value": "启用", "status": "pass", "risk": "低", "detail": ""}
    if out == "0":
        return {"item": "UAC", "value": "已关闭", "status": "fail", "risk": "高",
                "detail": "UAC 关闭后提权门槛大降"}
    return {"item": "UAC", "value": "无法读取", "status": "n/a", "risk": "中", "detail": ""}


def run_baseline():
    lines = _net_accounts()
    checks = [
        check_firewall(),
        check_defender(),
        check_patch(),
        check_pw_len(lines),
        check_pw_complex(lines),
        check_lockout(lines),
        check_guest(),
        check_admins(),
        check_rdp(),
        check_autologon(),
        check_shares(),
        check_uac(),
    ]
    return checks


def main():
    checks = run_baseline()
    n_pass = sum(1 for c in checks if c["status"] == "pass")
    n_fail = sum(1 for c in checks if c["status"] == "fail")
    n_warn = sum(1 for c in checks if c["status"] == "warn")
    print(f"基线核查: 共 {len(checks)} 项 | 通过 {n_pass} | 未通过 {n_fail} | 警告 {n_warn}")
    for c in checks:
        extra = f" - {c['detail']}" if c.get("detail") else ""
        print(f"  [{_STATUS[c['status']]}] {c['item']}: {c['value']}{extra}")
    return checks


if __name__ == "__main__":
    main()
