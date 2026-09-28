# VulnScan — Third-Party Library & Binary Vulnerability Scanner

> A 18-module, read-only vulnerability scanner that detects known CVEs in third-party libraries, audits binary attack surfaces, finds information leaks, and probes online services for weak configurations — all from a single tool. Authorized-asset focused, designed for security researchers, CTF teams, and product security QA.

[中文说明 · Chinese README](README_zh.md)

---

## Highlights

- **18 built-in modules** — CVE matching, binary audit, info-leak scan, port scan, web weak-config, Windows baseline, SBOM, dependency (OSV) scan, fuzzing, online probe, subdomain enum, TLS check, fingerprint, JS extraction, subdomain takeover, API discovery, and more.
- **Offline-first** — large built-in CVE database (46+ libraries / 114+ CVEs), optional NVD enrichment via `NVD_API_KEY`.
- **Read-only & compliant** — all online modules perform harmless GET / DNS queries only. No exploitation, no weaponization.
- **Product-grade output** — unified HTML report, PDF/Word export, historical comparison, batch multi-target, scheduled runs, auto library-add.
- **GUI + CLI + Web UI** — pick your entry point.

---

## Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | CVE Scan | Scan DLL/EXE in a directory, identify 3rd-party libs & versions, match known CVEs (offline DB + optional NVD) |
| 2 | Binary Audit | Per-PE static capability audit: import tables, dangerous-API classification (8 categories), hardcoded key scan |
| 3 | Info Leak | Filename rules (backup/VCS/sensitive config/key/db/log) + content scan for credentials/tokens/private keys/internal IPs |
| 4 | Port Scan | TCP connect probe + banner grabbing for host/service fingerprinting |
| 5 | Web Weak Config | Detect debug mode / weak auth / plaintext / weak crypto, etc. (read-only) |
| 6 | Windows Baseline | Read-only security baseline check of the local machine |
| 7 | Unified Report | Aggregates all selected modules into one report with a summary dashboard |
| 8 | Dependency Scan | Parse manifests across all ecosystems (npm/pip/Go/Maven/RubyGems/crates.io/…) and query **OSV** for real CVSS + fix versions |
| 9 | Fuzzer | Binary fuzzing (file / stdin / dll) for 0day hunting; crashes reported to CNVD/CNNVD as raw input |
| 10 | Web Probe | Security headers / sensitive paths / fingerprint / CORS / TRACE / HTTPS checks (read-only GET) |
| 11 | Subdomain Enum | Passive DNS enumeration, 32-thread concurrency |
| 12 | TLS Check | Protocol versions / cert chain / expiry / weak crypto (read-only handshake) |
| 13 | SBOM | Generate a standard CycloneDX 1.5 JSON supply-chain manifest |
| 14 | Online Leak | Depth-1 crawl for key/Token/internal-IP/OSS candidates (read-only) |
| 15 | Web Fingerprint | 50+ fingerprint rules to identify servers / frameworks / CMS / languages / CDN (read-only GET) |
| 16 | JS Extract | Grab page JS and scan for cloud keys / tokens / internal endpoints / API endpoints (read-only) |
| 17 | Subdomain Takeover | Check whether a CNAME points to an unclaimed third-party service (passive DNS + banner) |
| 18 | API Discovery | Probe swagger / OpenAPI / Actuator / REST endpoints (read-only GET) |

---

## Quick Start

### Requirements
- Python 3.8+
- VS compiler only if you rebuild the C++ engine (optional — a prebuilt `pe_scanner.exe` is included)
- Optional: `pip install reportlab python-docx` for PDF/Word export
- Optional: set `NVD_API_KEY` for online CVE enrichment

### CLI scan (recommended)
```bash
python python\vulnscan.py <target-dir> --out output
```

Run everything at once:
```bash
python python\vulnscan.py <target-dir> --audit --leak --web --baseline --dep --all --out output
```

### GUI — VulnScan Studio
Double-click `VulnScan Studio.bat`. A tkinter window with all module entry points: choose a directory (or host for port scan), tick modules, and run.

### Web UI (optional)
Double-click `启动扫描器.bat` → browser opens `http://127.0.0.1:8000`.
> If your security software blocks localhost access, whitelist `python.exe` or use the CLI.

---

## Command Reference

```bash
python python\vulnscan.py <dir> --out output                 # ① CVE
python python\vulnscan.py <dir> --audit --out output         # ② Binary audit (+CVE)
python python\vulnscan.py <dir> --leak --out output          # ③ Info leak (+CVE)
python python\vulnscan.py <dir> --web --out output           # ④ Web weak config (+CVE)
python python\vulnscan.py <dir> --baseline --out output      # ⑤ Windows baseline (+CVE)
python python\vulnscan.py <dir> --port 127.0.0.1 --out output # ⑥ Port scan (+CVE)
python python\vulnscan.py <dir> --dep --out output           # ⑧ Dependency scan (OSV)
python vulnscan.py <dir> --all --out output                  # all modules + unified report
```

### Auto library-add (scan new products, auto-extend the CVE DB)
```bash
python add_library.py discover <dir>                         # find unrecognized 3rd-party libs
python add_library.py add <libname> <ident> [--limit 60]     # add recognition + auto-fetch CVEs from NVD
python add_library.py fetch <libname> [--min-cvss 7]         # fetch CVEs only
```

---

## Built-in CVE Coverage (46+ libraries / 114+ CVEs)

- **Network/Crypto**: curl, OpenSSL, c-ares, nghttp2, libssh2, wolfSSL, mbedTLS, libevent, libsodium
- **Media/Image**: FFmpeg, libpng, libjpeg, libwebp, libtiff, openjpeg, giflib, libheif, libsndfile, libvpx, libmp3lame
- **Font/Text**: freetype, harfbuzz, ICU
- **Archive/Compression**: zlib, zlib-ng, libarchive, libzip, zstd, lz4, brotli, liblzma(xz)
- **Graphics/Window**: SDL2, GLEW, GLFW, freeglut
- **Game audio**: libvorbis, libogg, libtheora, OpenAL, FMOD
- **Game engines (recognition)**: Unity, Unreal, Godot, Cocos2D, PhysX
- **Parsing/Data**: libxml2, expat, libyaml, json-c, rapidjson, protobuf, hiredis, leveldb
- **Other**: sqlite, lua, luajit, libsass, assimp, bullet

Includes recent 2023–2024 CVEs (e.g. curl CVE-2023-38545 SOCKS5, libwebp CVE-2023-4863, xz CVE-2024-3094 backdoor).

---

## Compliance & Disclaimer

This tool is intended for **assets you are authorized to test** (your own software, SRC/CNVD authorized scope). All online modules are **read-only identification** (harmless GET / DNS queries) — no reproduction, exploitation, or weaponization. Findings are candidates; verify against official sources before submitting. **Misuse against unauthorized targets is your own responsibility.**

---

## License

[MIT](LICENSE). Please keep the attribution notice when redistributing.
