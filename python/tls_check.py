# -*- coding: utf-8 -*-
"""
VulnScan - Module 12: TLS / Certificate Check (READ-ONLY).

Performs TLS handshake to fetch the server certificate and checks:
  - certificate validity (expired / expiring soon)
  - weak TLS versions (TLSv1.0 / TLSv1.1 accepted)
  - negotiated protocol + cipher
Read-only handshake, no exploitation. Only authorized targets.

Usage:  python tls_check.py <host[:port]> [--out report.html]
"""

import sys
import os
import json
import socket
import ssl
from datetime import datetime, timezone

VERSION = "1.0.0"
PRODUCT = "VulnScan"

_PROTO_LABEL = {
    "TLSv1": "TLSv1.0", "TLSv1.1": "TLSv1.1", "TLSv1.2": "TLSv1.2",
    "TLSv1.3": "TLSv1.3", "SSLv3": "SSLv3",
}
_WEAK_PROTOS = ["SSLv3", "TLSv1", "TLSv1.1"]


def _parse_host(target):
    target = (target or "").strip()
    if not target:
        return None, None
    if "://" in target:
        target = target.split("://", 1)[1]
    target = target.rstrip("/")
    if target.count(":") == 1:
        host, port = target.rsplit(":", 1)
        return host, int(port)
    return target, 443


def _connect(host, port, protocol, timeout=5):
    ctx = ssl.SSLContext(protocol)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                ver = tls.version()
                ciph = tls.cipher()
                try:
                    der = tls.getpeercert(binary_form=True)
                except Exception:
                    der = None
                return {"ok": True, "proto": ver, "cipher": ciph[0] if ciph else None,
                        "bits": ciph[1] if ciph else None, "der": der}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _cert_field(cert, key):
    """Extract a field from getpeercert() dict."""
    if not cert:
        return None
    return cert.get(key)


def _cn(subject):
    """Recursively extract commonName / organization fields from a cert dict."""
    if not subject:
        return ""
    found = []

    def walk(v):
        if isinstance(v, str):
            return
        if isinstance(v, (tuple, list)):
            for item in v:
                if isinstance(item, tuple) and len(item) == 2:
                    if item[0] == "commonName":
                        found.append(item[1])
                    walk(item[1]) if not isinstance(item[1], str) else None
                elif isinstance(item, (tuple, list)):
                    walk(item)
    walk(subject)
    return "、".join(dict.fromkeys(found))


def _san(cert):
    san = (cert or {}).get("subjectAltName")
    if not san:
        return []
    out = []
    for item in san:
        if isinstance(item, tuple) and len(item) == 2:
            out.append(item[1])
    return out


def _decode_cert(der):
    """Decode DER cert bytes into a dict (subject/issuer/validity/SAN)."""
    if not der:
        return {}
    import tempfile
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False,
                                         encoding="utf-8") as tf:
            tf.write(pem)
            path = tf.name
        try:
            return ssl._ssl._test_decode_cert(path)
        finally:
            os.unlink(path)
    except Exception:
        return {}


def check_tls(target):
    """Return (findings, info)."""
    findings = []
    host, port = _parse_host(target)
    if not host:
        return findings, {"host": target, "ok": False}
    info = {"host": host, "port": port}

    # modern handshake
    r = _connect(host, port, ssl.PROTOCOL_TLS_CLIENT, timeout=5)
    # note: PROTOCOL_TLS_CLIENT requires cert validation; use PROTOCOL_TLS for raw
    r = _connect(host, port, ssl.PROTOCOL_TLS)
    info["reachable"] = r["ok"]
    if not r["ok"]:
        info["error"] = r["error"]
        return findings, info

    info["proto"] = r["proto"]
    info["cipher"] = r["cipher"]
    info["bits"] = r["bits"]
    cert = _decode_cert(r.get("der"))
    info["cn"] = _cn(cert.get("subject") if cert else None)
    info["issuer_cn"] = _cn(cert.get("issuer") if cert else None)
    info["san"] = _san(cert)

    # certificate validity
    if cert:
        not_after = _cert_field(cert, "notAfter")
        not_before = _cert_field(cert, "notBefore")
        info["not_after"] = not_after
        info["not_before"] = not_before
        try:
            from email.utils import parsedate_to_datetime
            exp = parsedate_to_datetime(not_after)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days = (exp - now).days
            info["days_left"] = days
            if days < 0:
                findings.append({
                    "category": "证书已过期", "risk": "high",
                    "detail": f"证书已于 {not_after} 过期（{abs(days)} 天前）",
                    "suggestion": "立即续期并部署新证书。"})
            elif days <= 30:
                findings.append({
                    "category": "证书即将过期", "risk": "medium",
                    "detail": f"证书将于 {not_after} 过期（剩 {days} 天）",
                    "suggestion": "在过期前续期，避免服务中断与信任告警。"})
        except Exception:
            pass

    # weak protocol accepted
    weak = []
    for p in (ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1):
        try:
            wr = _connect(host, port, p, timeout=5)
            if wr["ok"]:
                weak.append(_PROTO_LABEL.get(wr["proto"], wr["proto"]))
        except Exception:
            pass
    if weak:
        findings.append({
            "category": "弱 TLS 协议可协商", "risk": "high" if "SSLv3" in weak else "medium",
            "detail": f"服务端接受弱协议: {'、'.join(sorted(set(weak)))}",
            "suggestion": "在服务端禁用 SSLv3 / TLSv1.0 / TLSv1.1，仅启用 TLS1.2+。"})

    return findings, info


def _page(title, scanned_at, info, rows_html, disclaimer):
    return (f'<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">'
            f'<title>{title}</title></head>'
            f'<body style="margin:0;background:#f6f8fb;font-family:\'Microsoft YaHei\',sans-serif;">'
            f'<div style="max-width:1080px;margin:0 auto;padding:24px;">'
            f'<div style="display:flex;justify-content:space-between;align-items:baseline;">'
            f'<h1 style="font-size:22px;margin:0;">{title}</h1>'
            f'<span style="color:#8a93a6;font-size:12px;">{PRODUCT} v{VERSION}</span></div>'
            f'<div style="color:#8a93a6;font-size:13px;margin:6px 0 16px;">'
            f'目标：{info.get("host","")}:{info.get("port","443")} · 扫描时间 {scanned_at} · 方式：TLS 只读握手</div>'
            f'{rows_html}'
            f'<div style="margin-top:20px;padding:12px;border-top:1px solid #e3e6ec;'
            f'color:#9aa3b2;font-size:12px;">{disclaimer}</div>'
            f'</div></body></html>')


def generate_report(info, findings, out_path, scanned_at=None):
    scanned_at = scanned_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    disclaimer = ("免责声明：本报告由 VulnScan 生成，仅用于你有权测试的资产。TLS 检测为被动/只读握手，"
                  "未发送任何攻击载荷。未授权使用后果自负。")
    # overview card
    cert = info.get("cn") or "—"
    issuer = info.get("issuer_cn") or "—"
    days = info.get("days_left")
    days_txt = f"{days} 天" if days is not None else "—"
    overview = (f'<div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px;">'
                f'<div style="flex:1 1 200px;background:#fff;border:1px solid #e3e6ec;border-radius:10px;padding:12px;">'
                f'<div style="font-size:12px;color:#8a93a6;">主机</div><div style="font-size:15px;'
                f'font-weight:700;">{info.get("host","")}</div></div>'
                f'<div style="flex:1 1 200px;background:#fff;border:1px solid #e3e6ec;border-radius:10px;padding:12px;">'
                f'<div style="font-size:12px;color:#8a93a6;">证书 CN</div><div style="font-size:15px;">{cert}</div></div>'
                f'<div style="flex:1 1 200px;background:#fff;border:1px solid #e3e6ec;border-radius:10px;padding:12px;">'
                f'<div style="font-size:12px;color:#8a93a6;">协商协议</div><div style="font-size:15px;">'
                f'{info.get("proto","—")}</div></div>'
                f'<div style="flex:1 1 200px;background:#fff;border:1px solid #e3e6ec;border-radius:10px;padding:12px;">'
                f'<div style="font-size:12px;color:#8a93a6;">证书剩余</div><div style="font-size:15px;">{days_txt}</div></div>'
                f'</div>')
    # findings
    if findings:
        rows = []
        for i, f in enumerate(findings, 1):
            color = "#d64545" if f["risk"] == "high" else ("#e0872a" if f["risk"] == "medium" else "#9aa3b2")
            rows.append(f'<tr><td style="padding:8px 10px;border-bottom:1px solid #eef1f5;font-size:12px;">{i}</td>'
                        f'<td style="padding:8px 10px;border-bottom:1px solid #eef1f5;font-size:13px;">'
                        f'<span style="background:{color};color:#fff;border-radius:4px;padding:1px 6px;font-size:12px;">'
                        f'{"高危" if f["risk"]=="high" else ("中危" if f["risk"]=="medium" else "低危")}</span>'
                        f' {f["category"]}</td>'
                        f'<td style="padding:8px 10px;border-bottom:1px solid #eef1f5;font-size:13px;">{f["detail"]}'
                        f'<div style="font-size:12px;color:#8a93a6;margin-top:3px;">修复：{f["suggestion"]}</div></td></tr>')
        find_html = (f'<table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e3e6ec;'
                     f'border-radius:10px;overflow:hidden;"><thead><tr style="background:#f6f8fb;">'
                     f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">#</th>'
                     f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">级别/类别</th>'
                     f'<th style="padding:8px 10px;text-align:left;font-size:12px;color:#6b7280;">问题与修复</th>'
                     f'</tr></thead><tbody>{"".join(rows)}</tbody></table>')
    else:
        find_html = ('<div style="background:#eef7ee;border:1px solid #c9e4cf;border-radius:10px;padding:16px;'
                     'color:#2f6f4f;font-size:14px;">未发现证书/TLS 问题。</div>')
    doc = _page("TLS / 证书检查报告", scanned_at, info, overview + find_html, disclaimer)
    with open(out_path, "w", encoding="utf-8") as fp:
        fp.write(doc)
    return out_path


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    target = args[0]
    out = None
    if "--out" in args:
        out = args[args.index("--out") + 1]
    findings, info = check_tls(target)
    print(f"目标: {info.get('host')}:{info.get('port')}  可达: {info.get('reachable')}")
    if not info.get("reachable"):
        print("目标不可达或握手失败:", info.get("error"))
        return 1
    print(f"协议: {info.get('proto')}  证书CN: {info.get('cn')}  剩余: {info.get('days_left')} 天")
    for f in findings:
        print(f"  [{f['risk']}] {f['category']} - {f['detail']}")
    if out:
        generate_report(info, findings, out)
        print(f"报告已生成: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
