# -*- coding: utf-8 -*-
"""
fuzzer.py - VulnScan Module 9: 二进制 0day 模糊测试（fuzzing）· 升级版

支持三种输入模式：
  file   把变异数据写成临时文件，作为"文件路径参数"喂给目标（原版）
  stdin  把变异数据通过管道(stdin)喂给读标准输入的目标
  dll    对指定 DLL 的导出函数建轻量 harness（ctypes 子进程隔离调用）

变异引擎：
  通用变异（bit/byte/magic/截断/追加/块复制）
  + 格式感知变异（按 JPEG/PNG/GIF/ZIP/PE/WAV 等模板篡改长度字段）
  + 反馈引导（以执行时长/输出量为粗糙路径深度信号，保留"触达更深路径"的
    样本进 corpus，使变异朝更深执行进化，命中率高于纯随机）

【边界声明】本模块仅对用户指定的授权/本地目标做"输入健壮性测试+崩溃采集"，
不包含利用、不做武器化；命中崩溃请按 CNVD/CNNVD 流程报送原始输入，勿用于未授权目标。

用法:
  python fuzzer.py <target> [--mode file|stdin|dll] [--dll PATH] [--func NAME]
                   [--seeds DIR] [--iters N] [--timeout MS] [--crashes DIR]
"""

import os
import sys
import json
import time
import random
import tempfile
import subprocess
import hashlib
from datetime import datetime

# 抑制 Windows 崩溃弹窗(WER)：崩溃进程不弹框、不挂起，快速返回崩溃码
import ctypes
try:
    _SEM = 0x0001 | 0x0002 | 0x8000  # FAILCRITICALERRORS | NOGPFAULTERRORBOX | NOOPENFILEERRORBOX
    ctypes.windll.kernel32.SetErrorMode(_SEM)
except Exception:
    pass

CRASH_CODES = {
    -1073741819: ("0xC0000005", "访问冲突(ACCESS_VIOLATION)"),
    -1073740684: ("0xC0000374", "堆损坏(HEAP_CORRUPTION)"),
    -1073741571: ("0xC00000FD", "栈溢出(STACK_OVERFLOW)"),
    -1073740791: ("0xC0000409", "安全校验失败(STACK_BUFFER_OVERRUN)"),
    -1073741676: ("0xC0000094", "整数除零(INT_DIVIDE_BY_ZERO)"),
    -1073741701: ("0xC0000096", "特权指令(PRIVILEGED_INSTRUCTION)"),
    -2147483645: ("0x80000003", "断点(BREAKPOINT)"),
}
_MAGIC32 = [0x00000000, 0xFFFFFFFF, 0x41414141, 0x42424242, 0xCCCCCCCC,
            0xDEADBEEF, 0x7FFFFFFF, 0x80000000]
_MAGIC64 = [0x4141414141414141, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
            0x8000000000000000, 0xDEADBEEFDEADBEEF]


def _crash_name(code):
    if code in CRASH_CODES:
        hx, name = CRASH_CODES[code]
        return hx, name
    if code < 0:
        return "0x%08X" % (code & 0xFFFFFFFF), "未知异常(%d)" % code
    return "0x%08X" % code, "异常退出(%d)" % code


# ---------- 格式感知：常见文件格式模板 + 关键长度/尺寸字段偏移 ----------
def _fmt_templates():
    return {
        "jpeg":      b"\xFF\xD8\xFF\xE0" + b"\x00" * 20,
        "png":       b"\x89PNG\r\n\x1a\n" + b"\x00" * 40,
        "gif":       b"GIF89a" + b"\x00" * 20,
        "bmp":       b"BM" + b"\x00" * 60,
        "zip":       b"PK\x03\x04" + b"\x00" * 40,
        "pe":        b"MZ" + b"\x00" * 64,
        "riff_wav":  b"RIFF" + b"\x00" * 4 + b"WAVE" + b"\x00" * 30,
        "flv":       b"FLV" + b"\x00" * 16,
        "text":      b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
        "json":      b'{"id":0,"data":"' + b"A" * 32 + b'"}',
        "sql":       b"SELECT * FROM t WHERE id=" + b"1" * 16,
        "browser":   b"{\"url\":\"http://a\",\"len\":" + b"0" * 8 + b"}",
    }
_FMT_FIELDS = {
    "jpeg":     [4, 6, 8, 10],
    "png":      [8, 12, 16, 20, 24],
    "gif":      [6, 8, 10],
    "bmp":      [2, 6, 10, 14, 18],
    "zip":      [4, 8, 12],
    "pe":       [4, 8, 12, 20],
    "riff_wav": [4, 8, 12],
    "flv":      [4, 8, 12],
    "text":     [0],
    "json":     [0],
    "sql":      [0],
    "browser":  [0],
}


def _base_seeds():
    return [b"", b"\x00", b"\xff" * 64, b"A" * 64, b"\x00" * 4096,
            b"id=1&name=test", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, b"\xff\xd8\xff\xe0" + b"\x00" * 64,
            b"\x1f\x8b" + b"\x00" * 64, b"RIFF" + b"\x00" * 60]


def _load_seeds(seeds_dir):
    seeds = _base_seeds()
    if seeds_dir and os.path.isdir(seeds_dir):
        for name in os.listdir(seeds_dir):
            p = os.path.join(seeds_dir, name)
            if os.path.isfile(p):
                try:
                    with open(p, "rb") as f:
                        seeds.append(f.read())
                except Exception:
                    pass
    return seeds


def _mutate(data, rng):
    """通用单步变异。"""
    if not data:
        data = b"\x00"
    buf = bytearray(data)
    op = rng.randint(0, 6)
    if op == 0 and buf:
        i = rng.randrange(len(buf)); buf[i] ^= (1 << rng.randint(0, 7))
    elif op == 1 and buf:
        i = rng.randrange(len(buf)); buf[i] = rng.randrange(256)
    elif op == 2 and buf:
        i = rng.randrange(len(buf))
        m = rng.choice(_MAGIC32 + _MAGIC64)
        for k in range(min(4, len(buf) - i)):
            buf[i + k] = (m >> (8 * k)) & 0xFF
    elif op == 3 and buf:
        buf = buf[: rng.randrange(1, len(buf) + 1)]
    elif op == 4:
        buf += bytes(rng.randrange(256) for _ in range(rng.randint(1, 64)))
    elif op == 5 and buf:
        i = rng.randrange(len(buf)); n = rng.randint(1, min(64, len(buf) - i)); buf[i:i] = buf[i:i + n]
    else:
        buf += b"A" * rng.randint(64, 512)
    return bytes(buf[: 1 << 20])


def _fmt_mutate(rng):
    """格式感知变异：取模板，篡改长度字段/尺寸 + 追加 payload。"""
    name, tmpl = rng.choice(list(_fmt_templates().items()))
    buf = bytearray(tmpl)
    fields = _FMT_FIELDS.get(name, [])
    for _ in range(rng.randint(1, 3)):
        if fields:
            off = rng.choice(fields)
            m = rng.choice([0x00000000, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000,
                           0x41414141, 0x10000000, 0x0000FFFF])
            for k in range(min(4, max(0, len(buf) - off))):
                buf[off + k] = (m >> (8 * k)) & 0xFF
    r = rng.random()
    if r < 0.4:
        buf += bytes(rng.randrange(256) for _ in range(rng.randint(1, 256)))
    elif r < 0.6 and len(buf) > 8:
        buf = buf[: rng.randint(8, len(buf))]
    elif r < 0.7:
        buf += b"\x00" * rng.randint(8, 128)
    elif r < 0.8:
        buf += b"\xff" * rng.randint(8, 128)
    return name, bytes(buf[: 1 << 20])


# ---------- 三种输入模式执行器（返回 code, elapsed, out_len） ----------
def _exec_file(target, data_path, timeout_s):
    t0 = time.time()
    p = subprocess.run([target, data_path], capture_output=True, timeout=timeout_s)
    out = len(p.stdout or b"") + len(p.stderr or b"")
    return p.returncode, time.time() - t0, out


def _exec_stdin(target, sample, timeout_s):
    t0 = time.time()
    p = subprocess.run([target], input=sample, capture_output=True, timeout=timeout_s)
    out = len(p.stdout or b"") + len(p.stderr or b"")
    return p.returncode, time.time() - t0, out


def _run_harness_worker(argv):
    """DLL harness worker：在子进程加载 DLL 调导出函数，崩溃则进程退出非0。
    参数: __harness__ <dll> <func> <input_file>"""
    dll_path, func_name, data_file = argv[2], argv[3], argv[4]
    with open(data_file, "rb") as f:
        data = f.read()
    lib = ctypes.CDLL(dll_path)
    fn = getattr(lib, func_name)
    # 常见解析签名: func(const void* buf, size_t len)
    fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    buf = ctypes.create_string_buffer(data)
    t0 = time.time()
    fn(ctypes.cast(buf, ctypes.c_void_p), len(data))
    print("OK %.4f" % (time.time() - t0))
    return 0


def _exec_dll(sys_exe, fuzzer_path, dll, func, data_path, timeout_s):
    cmd = [sys_exe, fuzzer_path, "__harness__", dll, func, data_path]
    p = subprocess.run(cmd, capture_output=True, timeout=timeout_s)
    elapsed = 0.0
    try:
        elapsed = float((p.stdout or b"").decode("utf-8", "replace").split("OK ")[1].split()[0])
    except Exception:
        pass
    return p.returncode, elapsed, 0


# ---------- 主 fuzz 循环 ----------
def fuzz(target, mode="file", seeds_dir=None, iters=3000, timeout_ms=1500,
         crashes_dir=None, dll=None, func=None):
    if mode == "file" and not os.path.isfile(target):
        raise FileNotFoundError(f"目标不存在: {target}")
    if mode == "dll" and (not dll or not func):
        raise ValueError("dll 模式必须提供 --dll 与 --func")
    if mode == "dll" and not os.path.isfile(dll):
        raise FileNotFoundError(f"DLL 不存在: {dll}")

    seeds = _load_seeds(seeds_dir)
    rng = random.Random(0xC0FFEE)
    corpus = list(seeds)
    corpus_time = [0.0] * len(corpus)     # 父代执行时长，作粗糙路径深度信号
    crashes = []
    seen_hash = set()
    stats = {"samples": 0, "timeout": 0, "crash": 0, "exec_s": 0.0,
             "fmt_hit": 0, "corpus": len(corpus), "guided_hit": 0, "modes": mode}

    crash_root = os.path.abspath(crashes_dir) if crashes_dir else os.path.abspath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "output", "crashes"))
    os.makedirs(crash_root, exist_ok=True)

    sys_exe = sys.executable
    fuzzer_path = os.path.abspath(__file__)
    timeout_s = timeout_ms / 1000.0
    t_start = time.time()
    tmp_path = None
    if mode == "file" or mode == "dll":
        fd, tmp_path = tempfile.mkstemp(suffix=".bin"); os.close(fd)

    try:
        for i in range(iters):
            base_idx = None
            # 混合：格式感知变异(约30%) + 通用变异
            if rng.random() < 0.30:
                _, sample = _fmt_mutate(rng)
                stats["fmt_hit"] += 1
            else:
                base_idx = rng.randrange(len(corpus))
                sample = _mutate(corpus[base_idx], rng)

            try:
                if mode == "file":
                    with open(tmp_path, "wb") as f: f.write(sample)
                    code, el, outlen = _exec_file(target, tmp_path, timeout_s)
                elif mode == "stdin":
                    code, el, outlen = _exec_stdin(target, sample, timeout_s)
                else:
                    with open(tmp_path, "wb") as f: f.write(sample)
                    code, el, outlen = _exec_dll(sys_exe, fuzzer_path, dll, func, tmp_path, timeout_s)
                stats["samples"] += 1
                stats["exec_s"] = round(time.time() - t_start, 2)
            except subprocess.TimeoutExpired:
                stats["timeout"] += 1
                continue

            if code != 0:
                hx, name = _crash_name(code)
                h = hashlib.md5(sample).hexdigest()
                if h not in seen_hash:
                    seen_hash.add(h)
                    cname = f"crash_{i:06d}_{hx}.bin"
                    cpath = os.path.join(crash_root, cname)
                    try:
                        with open(cpath, "wb") as f: f.write(sample)
                    except Exception:
                        pass
                    crashes.append({
                        "id": i, "code_hex": hx, "code_name": name,
                        "returncode": code, "input": cpath,
                        "size": len(sample), "md5": h,
                    })
                stats["crash"] += 1
            else:
                # 反馈引导：执行更久 / 有输出 → 疑似触达更深路径 → 高概率保留
                deeper = False
                if base_idx is not None:
                    deeper = (el > corpus_time[base_idx] + 0.0005) or outlen > 0
                if deeper:
                    stats["guided_hit"] += 1
                if deeper or rng.random() < 0.03:
                    corpus.append(sample)
                    corpus_time.append(el)
                    if len(corpus) > 300:
                        corpus = corpus[-300:]
                        corpus_time = corpus_time[-300:]
    finally:
        if tmp_path:
            try: os.remove(tmp_path)
            except Exception: pass

    stats["elapsed_s"] = round(time.time() - t_start, 2)
    stats["corpus"] = len(corpus)
    return {
        "target": target, "mode": mode, "dll": dll, "func": func,
        "stats": stats, "crashes": crashes,
        "crashes_dir": crash_root,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _find_executables(directory, maxdepth=2):
    exes = []
    base = os.path.abspath(directory)
    for root, dirs, files in os.walk(directory):
        rel = os.path.relpath(root, base)
        cur = 0 if rel == "." else rel.count(os.sep) + 1
        if cur > maxdepth:
            dirs[:] = []; continue
        for f in files:
            if f.lower().endswith((".exe", ".scr")):
                exes.append(os.path.join(root, f))
    return exes


def main():
    # DLL harness worker 子命令（内部使用，勿直接调用）
    if len(sys.argv) > 1 and sys.argv[1] == "__harness__":
        return _run_harness_worker(sys.argv)

    import argparse
    ap = argparse.ArgumentParser(description="VulnScan 模块9: 二进制 fuzzing（0day 挖掘）·升级版")
    ap.add_argument("target", help="目标二进制(.exe) 或目录（file 模式）")
    ap.add_argument("--mode", default="file", choices=["file", "stdin", "dll"],
                    help="输入模式：file=文件路径参数(默认)；stdin=标准输入管道；dll=DLL导出函数harness")
    ap.add_argument("--dll", default=None, help="dll 模式：DLL 路径")
    ap.add_argument("--func", default=None, help="dll 模式：导出函数名（默认签名 func(const void*, size_t)）")
    ap.add_argument("--seeds", default=None, help="种子目录")
    ap.add_argument("--iters", type=int, default=3000, help="变异样本数")
    ap.add_argument("--timeout", type=int, default=1500, help="单样本超时 ms")
    ap.add_argument("--crashes", default=None, help="崩溃输入保存目录")
    ap.add_argument("--bin", default=None, help="目录模式下指定具体 exe 文件名")
    args = ap.parse_args()

    target = args.target
    if args.mode == "file" and os.path.isdir(target):
        exes = _find_executables(target)
        if not exes:
            print("[错误] 目录下未找到 .exe 可执行文件"); return 1
        if args.bin:
            m = [e for e in exes if os.path.basename(e).lower() == args.bin.lower()]
            target = m[0] if m else max(exes, key=os.path.getsize)
        else:
            target = max(exes, key=os.path.getsize)
        print(f"[*] 目录模式，自动选择目标: {target}")

    print(f"[*] 目标: {target}  模式: {args.mode}" + (f"  DLL={args.dll} func={args.func}" if args.mode == "dll" else ""))
    print(f"[*] 变异样本: {args.iters}，单样本超时: {args.timeout}ms（格式感知 + 反馈引导）")

    res = fuzz(target, mode=args.mode, seeds_dir=args.seeds, iters=args.iters,
               timeout_ms=args.timeout, crashes_dir=args.crashes,
               dll=args.dll, func=args.func)

    s = res["stats"]
    print(f"\n===== Fuzzing 结果 =====")
    print(f"执行样本: {s['samples']} | 超时: {s['timeout']} | 崩溃: {s['crash']} | "
          f"格式感知变异: {s['fmt_hit']} | 反馈引导保留: {s['guided_hit']} | 耗时: {s['elapsed_s']}s")
    print(f"corpus 规模: {s['corpus']} | 去重崩溃: {len(res['crashes'])} 个，已保存至: {res['crashes_dir']}")
    for c in res["crashes"][:8]:
        print(f"  [{c['code_hex']}] {c['code_name']}  size={c['size']}  {os.path.basename(c['input'])}")
    if len(res["crashes"]) > 8:
        print(f"  ... 共 {len(res['crashes'])} 个")

    json_path = os.path.join(res["crashes_dir"], "fuzz_result.json")
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=2)
        print(f"[*] 结果 JSON: {json_path}")
    except Exception as e:
        print(f"[!] 写 JSON 失败: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
