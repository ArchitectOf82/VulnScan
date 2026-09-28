# -*- coding: utf-8 -*-
"""
VulnScan - Module 2: Binary security audit.

For each PE (dll/exe/sys/ocx) in a directory:
  - parse the import table -> per-DLL imported functions
  - classify risky API calls into capability categories
  - scan for hardcoded keys / sensitive strings

Output is a structured list that feeds the unified report.
Usage (standalone test):
    python pe_audit.py <dir>
"""

import os
import re
import struct

# Risky API -> capability category
_API_CATS = {
    "cmd_exec":     ["WinExec", "ShellExecuteW", "ShellExecuteA", "ShellExecuteExW",
                     "CreateProcessW", "CreateProcessA", "system"],
    "file_write":   ["CreateFileW", "CreateFileA", "WriteFile", "DeleteFileW", "DeleteFileA",
                     "MoveFileW", "MoveFileA", "GetTempPathW", "GetTempPathA",
                     "CreateDirectoryW", "RemoveDirectoryW", "ReplaceFileW"],
    "reg_modify":   ["RegOpenKeyExW", "RegOpenKeyExA", "RegSetValueExW", "RegSetValueExA",
                     "RegCreateKeyExW", "RegCreateKeyExA", "RegDeleteKeyW", "RegDeleteValueW",
                     "RegSetKeyValueW"],
    "mem_exec":     ["VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
                     "WriteProcessMemory", "ReadProcessMemory", "VirtualAlloc2",
                     "MapViewOfFile", "VirtualAllocExNuma"],
    "net":          ["InternetOpenW", "InternetOpenUrlW", "HttpSendRequestW", "HttpSendRequestA",
                     "WinHttpOpen", "WSAStartup", "socket", "connect", "accept", "send", "recv",
                     "URLDownloadToFileW", "URLDownloadToFileA", "WinHttpConnect", "WinHttpSendRequest"],
    "crypto":       ["BCryptEncrypt", "BCryptDecrypt", "BCryptHashData", "CryptEncrypt", "CryptDecrypt",
                     "CryptAcquireContextW", "CryptAcquireContextA", "CryptProtectData",
                     "BCryptGenRandom", "CryptGenKey"],
    "thread_inject":["CreateThread", "CreateRemoteThread", "SetWindowsHookExW", "SetWindowsHookExA",
                     "QueueUserAPC", "NtCreateThreadEx", "RtlCreateUserThread"],
    "dyn_load":     ["LoadLibraryW", "LoadLibraryA", "LoadLibraryExW", "GetProcAddress",
                     "LdrLoadDll", "LoadPackagedLibrary"],
}

# Sensitive string patterns (hardcoded key / credential candidates)
_SENS_PATTERNS = [
    ("hex_key",     re.compile(rb"\b[0-9a-fA-F]{32,64}\b")),
    ("secret",      re.compile(rb"(?i)\b(?:secret|password|passwd|api[_-]?key|appkey|"
                                rb"access[_-]?token|private[_-]?key|signkey|client[_-]?secret|"
                                rb"token|authcode)\b\s*[:=]")),
    ("pem_key",     re.compile(rb"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
    ("connstr",     re.compile(rb"(?i)(?:Server\s*=|Data\s*Source\s*=|jdbc:|mongodb://)")),
]

_PE_EXT = (".dll", ".exe", ".sys", ".ocx")


def parse_imports(path):
    """Parse the import table of a PE file -> {dll_name: [funcs]}. Robust for 32/64-bit."""
    try:
        data = open(path, "rb").read()
    except Exception:
        return {}
    if len(data) < 0x40 or data[0:2] != b"MZ":
        return {}
    pe = struct.unpack("<I", data[0x3c:0x40])[0]
    if pe + 0x18 + 4 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        return {}
    nsec = struct.unpack("<H", data[pe + 0x06:pe + 0x08])[0]
    opt_size = struct.unpack("<H", data[pe + 0x14:pe + 0x16])[0]
    sh = pe + 0x18 + opt_size
    sects = []
    for i in range(nsec):
        o = sh + i * 40
        if o + 40 > len(data):
            break
        vsz, vaddr, rawsz, rawptr = struct.unpack("<IIII", data[o + 8:o + 24])
        sects.append((vaddr, vaddr + max(vsz, rawsz), rawptr))

    def r2o(rva):
        for va0, va1, raw in sects:
            if va0 <= rva < va1 and raw < len(data):
                return raw + (rva - va0)
        return None

    magic = struct.unpack("<H", data[pe + 0x18:pe + 0x1a])[0]
    is64 = (magic == 0x20b)
    dd = pe + 0x18 + (0x70 if is64 else 0x60)
    imp_rva = struct.unpack("<I", data[dd + 8:dd + 12])[0]
    step = 8 if is64 else 4
    ordflag = 0x8000000000000000 if is64 else 0x80000000
    mask = 0x7fffffffffffffff if is64 else 0x7fffffff

    dlls = {}
    d = imp_rva
    for _ in range(200):
        off = r2o(d)
        if off is None or off + 20 > len(data):
            break
        oft, ts, _, name_rva, first_thunk = struct.unpack("<IIIII", data[off:off + 20])
        if oft == 0 and name_rva == 0:
            break
        noff = r2o(name_rva)
        dllname = ""
        if noff is not None:
            end = data.find(b"\x00", noff)
            if end != -1:
                dllname = data[noff:end].decode("utf-8", errors="ignore")
        funcs = []
        thunk = oft or first_thunk
        toff = r2o(thunk)
        guard = 0
        while toff is not None and toff + step <= len(data) and guard < 3000:
            val = struct.unpack("<Q" if is64 else "<I", data[toff:toff + step])[0]
            if val == 0:
                break
            if val & ordflag:
                funcs.append("ord" + str(val & 0xffff))
            else:
                noff2 = r2o(val & mask)
                if noff2 is not None and noff2 + 2 <= len(data):
                    end2 = data.find(b"\x00", noff2 + 2)
                    if end2 != -1:
                        funcs.append(data[noff2 + 2:end2].decode("utf-8", errors="ignore"))
            toff += step
            guard += 1
        if dllname:
            dlls[dllname] = funcs
        d += 20
    return dlls


def classify_calls(dlls):
    """Return (cats, risky_calls): capability->count and sorted risky call strings."""
    cats = {}
    risky = []
    for dll, funcs in dlls.items():
        for f in funcs:
            for cat, names in _API_CATS.items():
                if f in names:
                    risky.append(f"{f} ({dll})")
                    cats[cat] = cats.get(cat, 0) + 1
    return cats, sorted(set(risky))


def scan_sensitive_strings(data):
    """Return a sample list of hardcoded-key / credential candidate strings."""
    out = []
    for label, pat in _SENS_PATTERNS:
        m = pat.search(data)
        if m:
            g = m.group(0)
            try:
                gs = g.decode("utf-8", errors="ignore")
            except Exception:
                gs = repr(g)
            out.append(f"{label}: {gs[:48]}")
    return out


def audit_file(path):
    res = {"path": path, "name": os.path.basename(path),
           "size": os.path.getsize(path), "imports": {},
           "cats": {}, "risky_calls": [], "key_strings": [], "score": 0}
    try:
        data = open(path, "rb").read()
    except Exception:
        return res
    dlls = parse_imports(path)
    res["imports"] = dlls
    cats, risky = classify_calls(dlls)
    res["cats"] = cats
    res["risky_calls"] = risky
    res["key_strings"] = scan_sensitive_strings(data)
    res["score"] = sum(cats.values()) + len(res["key_strings"])
    return res


def audit_directory(target_dir, maxdepth=None):
    results = []
    for dp, dn, fn in os.walk(target_dir):
        for f in fn:
            if os.path.splitext(f)[1].lower() not in _PE_EXT:
                continue
            p = os.path.join(dp, f)
            try:
                r = audit_file(p)
                if r["risky_calls"] or r["key_strings"]:
                    results.append(r)
            except Exception:
                pass
    return sorted(results, key=lambda x: -x["score"])


if __name__ == "__main__":
    import sys
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    res = audit_directory(d)
    print(f"audited files with findings: {len(res)}")
    for r in res[:20]:
        caps = ",".join(f"{k}:{v}" for k, v in r["cats"].items())
        print(f"\n[{r['score']}] {r['name']}")
        print(f"   caps: {caps or '-'}")
        print(f"   risky: {len(r['risky_calls'])} | keys: {len(r['key_strings'])}")
        if r["key_strings"]:
            print("   key samples:", r["key_strings"][:3])
