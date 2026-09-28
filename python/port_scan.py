# -*- coding: utf-8 -*-
"""
VulnScan - Module 4: Port & service identification.

Passive-ish TCP connect probe against an authorized target host, then banner
grab to identify services. Read-only detection, no exploitation.

Usage:  python port_scan.py [host] [--ports 1-1000] [--timeout ms]
"""

import socket
import threading
import time
import argparse

# Common service ports -> name
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    81: "HTTP-Alt", 110: "POP3", 111: "RPC", 135: "MS-RPC", 137: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-Sub", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM", 5986: "WinRM-HTTPS", 6379: "Redis",
    7001: "WebLogic", 8000: "HTTP-Alt", 8009: "AJP", 8080: "HTTP-Proxy",
    8081: "HTTP-Alt", 8082: "HTTP-Alt", 8083: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9000: "HTTP-Alt", 9200: "Elasticsearch", 9090: "HTTP-Alt",
    9092: "Kafka", 11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB-Shard",
}
# Services whose exposure is high-risk for a host
RISK_HIGH = {
    21: "FTP 明文口令", 23: "Telnet 明文", 445: "SMB 暴露", 1433: "MSSQL 暴露",
    3306: "MySQL 暴露", 3389: "RDP 远程桌面暴露", 5432: "PostgreSQL 暴露",
    6379: "Redis 未授权风险", 9200: "Elasticsearch 未授权", 27017: "MongoDB 未授权",
    5900: "VNC 弱口令风险", 1080: "SOCKS 代理", 5985: "WinRM 远程管理",
}


def _probe(host, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((host, port)) == 0:
            return True
    finally:
        s.close()
    return False


def _banner(host, port, timeout):
    """Try to read a small banner to identify the service."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        # some services wait for client; try a couple of probes
        for data in (b"", b"\r\n", b"HEAD / HTTP/1.0\r\n\r\n"):
            try:
                s.sendall(data)
            except Exception:
                pass
            try:
                resp = s.recv(256)
                if resp:
                    txt = resp.decode("utf-8", errors="ignore").strip()
                    if txt:
                        return txt[:64]
            except Exception:
                pass
    except Exception:
        pass
    finally:
        s.close()
    return ""


def scan_host(host, ports, timeout=0.8, threads=200):
    """Return list of open {port, service, banner, risk}."""
    results = []
    open_lock = threading.Lock()
    port_list = list(ports)

    def work(p):
        if _probe(host, p, timeout):
            banner = ""
            # only banner-grab if likely textual service (skip huge ranges cost)
            if p in COMMON_PORTS or p < 1024:
                banner = _banner(host, p, timeout)
            with open_lock:
                results.append({"port": p,
                                "service": COMMON_PORTS.get(p, "unknown"),
                                "banner": banner,
                                "risk": RISK_HIGH.get(p, "")})

    sem = threading.Semaphore(threads)
    def guarded(p):
        sem.acquire()
        try:
            work(p)
        finally:
            sem.release()

    workers = [threading.Thread(target=guarded, args=(p,)) for p in port_list]
    for w in workers:
        w.start()
    for w in workers:
        w.join()

    results.sort(key=lambda x: x["port"])
    return results


def parse_ports(spec):
    """Parse '1-1000' or '22,80,443' into a set of ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            lo, hi = int(a), int(b)
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    return ports


def main():
    ap = argparse.ArgumentParser(description="VulnScan 模块4: 端口与服务识别")
    ap.add_argument("host", nargs="?", default="127.0.0.1", help="目标主机（仅授权资产）")
    ap.add_argument("--ports", default="1-1000", help="端口范围，如 1-1000 或 22,80,443")
    ap.add_argument("--timeout", type=float, default=0.8, help="连接超时（秒）")
    args = ap.parse_args()

    ports = parse_ports(args.ports)
    print(f"[*] 探测 {args.host} 端口 {args.ports} ...")
    t0 = time.time()
    res = scan_host(args.host, ports, timeout=args.timeout)
    dt = time.time() - t0
    print(f"[*] 用时 {dt:.1f}s，开放端口 {len(res)} 个")
    for r in res:
        risk = f"  ⚠ {r['risk']}" if r["risk"] else ""
        banner = f"  [{r['banner']}]" if r["banner"] else ""
        print(f"  {r['port']:<6} {r['service']:<16}{banner}{risk}")
    if not res:
        print("  无开放端口。")
    return res


if __name__ == "__main__":
    main()
