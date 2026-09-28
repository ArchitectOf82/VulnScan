# -*- coding: utf-8 -*-
"""
VulnScan - CVE matching module (extended multi-product edition).

Maps a library name + version to known CVEs using:
  1. A built-in offline CVE database (no network, always available)
  2. Optional NVD API enrichment (set NVD_API_KEY to enable, results cached locally)

Library/product identification is done from the DLL/exe filename and version
resources (already extracted by pe_scanner). Coverage aims at common third-party
libraries found in desktop clients / games / servers, across vendors (not
limited to Tencent products).

NOTE: version ranges are best-effort from public disclosures (NVD/upstream
advisories). Verify against NVD before submitting a real report.
"""

import os
import re
import json
import time
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# External extension database (user-added libraries via add_library.py)
# ---------------------------------------------------------------------------
EXTRA = None

def _load_extra():
    global EXTRA
    if EXTRA is not None:
        return EXTRA
    import importlib.util, types, os
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "extra_products.py")
    if not os.path.exists(p):
        EXTRA = False
        return EXTRA
    spec = importlib.util.spec_from_file_location("extra_products", p)
    m = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(m)
        EXTRA = m
    except Exception:
        EXTRA = False
    return EXTRA

def _extra_identify():
    m = _load_extra()
    return getattr(m, "EXTRA_IDENTIFY", []) if m else []

def _extra_cves():
    m = _load_extra()
    return getattr(m, "EXTRA_CVES", []) if m else []

# ---------------------------------------------------------------------------
# Version parsing / comparison
# ---------------------------------------------------------------------------

def parse_version(v):
    """Split a version string like '7.60.0', '1.1.1s', '9.7.21.884' into a
    comparable token list. Letters are mapped to numbers (a=1..z=26)."""
    if not v:
        return []
    v = str(v).strip().lower()
    tokens = re.findall(r'\d+|[a-z]+', v)
    out = []
    for t in tokens:
        if t.isdigit():
            out.append(int(t))
        else:
            val = 0
            for ch in t:
                val = val * 27 + (ord(ch) - 96)  # a=1..z=26
            out.append((t, val))
    return out


def _cmp_tokens(a, b):
    """Compare two parsed version token lists. None/empty is treated as lowest."""
    if not a:
        return -1 if b else 0
    if not b:
        return 1
    for x, y in zip(a, b):
        if type(x) != type(y):
            return 1 if isinstance(x, int) else -1
        if isinstance(x, int):
            if x != y:
                return -1 if x < y else 1
        else:  # tuple (str,val)
            if x[1] != y[1]:
                return -1 if x[1] < y[1] else 1
    if len(a) == len(b):
        return 0
    return -1 if len(a) < len(b) else 1


def version_in_range(version, min_v, max_v):
    """Return True if version is within [min_v, max_v] inclusive (both may be None)."""
    pv = parse_version(version)
    if not pv:
        return False
    if min_v:
        if _cmp_tokens(pv, parse_version(min_v)) < 0:
            return False
    if max_v:
        if _cmp_tokens(pv, parse_version(max_v)) > 0:
            return False
    return True


# ---------------------------------------------------------------------------
# Library / product identification (filename + product name -> canonical product)
# ---------------------------------------------------------------------------
# Order matters: more specific needles first. Canonical product keys must match
# the "product" field of BUILTIN_CVES entries.

def identify_product(entry):
    """Given a scanned entry {name, productName, fileDescription, ...},
    return (product_key, version) or (None, None)."""
    name = (entry.get("name") or "").lower()
    pname = (entry.get("productName") or "").lower()
    desc = (entry.get("fileDescription") or "").lower()

    hay = f"{name} {pname} {desc}".lower()

    table = [
        # network / crypto
        ("curl",        ["libcurl", "curl "],                "curl"),
        ("openssl",     ["libcrypto", "libssl", "openssl"],   "openssl"),
        ("c-ares",      ["libcares", "c-ares", "cares.dll"],  "c-ares"),
        ("nghttp2",     ["nghttp2"],                          "nghttp2"),
        ("libssh2",     ["libssh2", "ssh2.dll"],              "libssh2"),
        ("wolfssl",     ["wolfssl"],                          "wolfssl"),
        ("mbedtls",     ["mbedtls"],                          "mbedtls"),
        ("libevent",    ["libevent", "event_core"],           "libevent"),
        ("libsodium",   ["libsodium"],                        "libsodium"),
        # media / image
        ("ffmpeg",      ["avcodec", "avformat", "avutil", "ffmpeg", "txffmpeg"], "ffmpeg"),
        ("libpng",      ["libpng"],                           "libpng"),
        ("libjpeg",     ["libjpeg", "jpeg8", "jpeg62"],        "libjpeg"),
        ("libwebp",     ["libwebp"],                          "libwebp"),
        ("libtiff",     ["libtiff"],                          "libtiff"),
        ("openjpeg",    ["openjpeg", "libopj", "opj.dll"],    "openjpeg"),
        ("giflib",      ["giflib", "libgif"],                 "giflib"),
        ("libheif",     ["libheif"],                          "libheif"),
        ("libsndfile",  ["libsndfile", "sndfile"],            "libsndfile"),
        ("libvpx",      ["libvpx", "vpx.dll"],                "libvpx"),
        ("libmp3lame",  ["libmp3lame", "mp3lame", "lame.dll", "lame_enc", "lameenc"],"libmp3lame"),
        # font / text
        ("freetype",    ["freetype", "libfreetype"],          "freetype"),
        ("harfbuzz",    ["harfbuzz", "libharfbuzz"],          "harfbuzz"),
        ("icu",         ["libicu", "icuuc", "icuin", "icudt"],"icu"),
        # compression / archive
        ("zlib",        ["zlib", "zlib1"],                    "zlib"),
        ("zlib-ng",     ["zlib-ng", "zlibng"],                "zlib-ng"),
        ("libarchive",  ["libarchive", "archive.dll"],        "libarchive"),
        ("libzip",      ["libzip"],                           "libzip"),
        ("zstd",        ["zstd"],                             "zstd"),
        ("lz4",         ["liblz4", "lz4.dll"],                "lz4"),
        ("brotli",      ["brotli"],                           "brotli"),
        ("liblzma",     ["liblzma", "xz.dll"],                "liblzma"),
        # xml / data / parse
        ("libxml2",     ["libxml2", "libxml"],                "libxml2"),
        ("expat",       ["libexpat", "expat"],                "expat"),
        ("libyaml",     ["libyaml", "yaml.dll"],              "libyaml"),
        ("json-c",      ["json-c", "libjson"],                "json-c"),
        ("rapidjson",   ["rapidjson"],                        "rapidjson"),
        ("protobuf",    ["protobuf"],                         "protobuf"),
        ("hiredis",     ["hiredis"],                          "hiredis"),
        ("leveldb",     ["leveldb"],                          "leveldb"),
        # db
        ("sqlite",      ["sqlite"],                           "sqlite"),
        # scripting
        ("lua",         ["lua5", "lua51", "lua52", "lua53", "lua54"], "lua"),
        ("luajit",      ["luajit"],                           "luajit"),
        # graphics / windowing (OpenGL ecosystem, non-engine)
        ("sdl2",        ["libsdl2", "sdl2.dll"],              "sdl2"),
        ("glew",        ["glew"],                             "glew"),
        ("glfw",        ["glfw"],                             "glfw"),
        ("freeglut",    ["freeglut", "glut.dll"],             "freeglut"),
        # game engines / middleware (game-related third-party libs)
        ("libvorbis",   ["libvorbis", "vorbis"],              "libvorbis"),
        ("libogg",      ["libogg"],                           "libogg"),
        ("libtheora",   ["libtheora"],                        "libtheora"),
        ("openal",      ["openal", "soft_oal", "openal32"],   "openal"),
        ("fmodex",      ["fmodex", "fmod.dll"],               "fmodex"),
        ("physx",       ["physx"],                            "physx"),
        ("godot",       ["godot"],                            "godot"),
        ("unity",       ["unityplayer", "libunity", "mono-2.0", "unitycrash"], "unity"),
        ("unreal",      ["ue4editor", "ue5editor", "libunreal", "unrealengine"], "unreal"),
        ("cocos2d",     ["cocos2d", "cocos"],                 "cocos2d"),
        # misc
        ("libsass",     ["libsass"],                          "libsass"),
        ("assimp",      ["assimp"],                           "assimp"),
        ("bullet",      ["bulletphysics", "bullet.dll"],      "bullet"),
    ]

    table = table + _extra_identify()

    for key, needles, product in table:
        for nd in needles:
            if nd in hay:
                version = (entry.get("fileVersion") or entry.get("productVersion") or "").strip()
                if key == "ffmpeg" and not version:
                    m = re.search(r'avcodec-(\d+)', name)
                    if m:
                        ver = int(m.group(1))
                        version = {57: "3.4", 58: "4.0", 59: "4.4", 60: "5.0",
                                   61: "6.0", 62: "7.0"}.get(ver, "")
                return product, version
    return None, None


# ---------------------------------------------------------------------------
# Built-in offline CVE database
# ---------------------------------------------------------------------------
# Each entry: id, product, min, max, desc, cvss, type, remote, fixed_in
# Range [min, max] inclusive. min/max may be None for open-ended.
# NOTE: ranges are best-effort from public disclosures; verify against NVD before
# submitting a real report.

BUILTIN_CVES = [
    # ============================== curl ==============================
    {"id": "CVE-2018-14618", "product": "curl", "min": "7.15.4", "max": "7.61.0",
     "desc": "NTLM password overflow via integer overflow (heap)", "cvss": 8.8, "type": "memory corruption",
     "remote": True, "fixed_in": "7.61.1"},
    {"id": "CVE-2019-3822", "product": "curl", "min": "7.36.0", "max": "7.63.0",
     "desc": "NTLMv2 type-3 header stack buffer overflow (CWE-121)", "cvss": 8.1, "type": "stack overflow",
     "remote": True, "fixed_in": "7.64.0"},
    {"id": "CVE-2019-3823", "product": "curl", "min": "7.10.5", "max": "7.64.0",
     "desc": "SMTP need_auth heap overflow (CWE-122)", "cvss": 8.1, "type": "heap overflow",
     "remote": True, "fixed_in": "7.64.1"},
    {"id": "CVE-2020-8177", "product": "curl", "min": None, "max": "7.70.0",
     "desc": "FTP wildcard match stack overflow (CWE-121)", "cvss": 8.1, "type": "stack overflow",
     "remote": True, "fixed_in": "7.71.0"},
    {"id": "CVE-2020-8231", "product": "curl", "min": None, "max": "7.70.0",
     "desc": "FTP PASV port double-free (CWE-415)", "cvss": 8.1, "type": "use-after-free/double-free",
     "remote": True, "fixed_in": "7.71.0"},
    {"id": "CVE-2021-22898", "product": "curl", "min": "7.21.0", "max": "7.74.0",
     "desc": "TELNET stack overflow in option parser (CWE-121)", "cvss": 8.1, "type": "stack overflow",
     "remote": True, "fixed_in": "7.75.0"},
    {"id": "CVE-2021-22946", "product": "curl", "min": "7.7", "max": "7.76.0",
     "desc": "MQTT stack overflow via unix socket / too long topic", "cvss": 8.1, "type": "stack overflow",
     "remote": True, "fixed_in": "7.77.0"},
    {"id": "CVE-2021-22947", "product": "curl", "min": "7.62", "max": "7.76.0",
     "desc": "MQTT server-to-client unencrypted transport info leak", "cvss": 5.3, "type": "info leak",
     "remote": True, "fixed_in": "7.77.0"},
    {"id": "CVE-2021-22945", "product": "curl", "min": "7.62", "max": "7.79.0",
     "desc": "Use-after-free in transfer on double-close (CWE-416)", "cvss": 7.5, "type": "use-after-free",
     "remote": True, "fixed_in": "7.80.0"},
    {"id": "CVE-2022-27775", "product": "curl", "min": "7.0", "max": "7.82.0",
     "desc": "FTP badipv6 / creds handling, info leak", "cvss": 5.5, "type": "info leak",
     "remote": True, "fixed_in": "7.83.0"},
    {"id": "CVE-2022-27776", "product": "curl", "min": "7.0", "max": "7.82.0",
     "desc": "FTP command injection via bad authz / newline (CWE-93)", "cvss": 7.5, "type": "command injection",
     "remote": True, "fixed_in": "7.83.0"},
    {"id": "CVE-2023-27535", "product": "curl", "min": "7.0", "max": "7.88.1",
     "desc": "FTP PASV / TELNET option integer overflow (CWE-190)", "cvss": 5.3, "type": "integer overflow",
     "remote": True, "fixed_in": "8.0.0"},
    {"id": "CVE-2023-27534", "product": "curl", "min": "7.0", "max": "7.88.1",
     "desc": "FTP wildcard match heap overflow on some platforms", "cvss": 6.5, "type": "heap overflow",
     "remote": True, "fixed_in": "8.0.0"},
    {"id": "CVE-2023-38545", "product": "curl", "min": "7.69.0", "max": "8.3.0",
     "desc": "SOCKS5 proxy heap buffer overflow (CWE-122)", "cvss": 9.8, "type": "heap overflow",
     "remote": True, "fixed_in": "8.4.0"},
    {"id": "CVE-2023-38546", "product": "curl", "min": "7.9.1", "max": "8.3.0",
     "desc": "Cookie injection via file:// redirect / duplicate cookie", "cvss": 6.5, "type": "cookie injection",
     "remote": True, "fixed_in": "8.4.0"},
    {"id": "CVE-2023-32001", "product": "curl", "min": "7.21.0", "max": "8.1.0",
     "desc": "File:// redirect to local file, expose contents (CWE-200)", "cvss": 3.7, "type": "info leak",
     "remote": True, "fixed_in": "8.1.1"},
    {"id": "CVE-2024-7267", "product": "curl", "min": None, "max": "8.8.0",
     "desc": "IP address spoofing in curl (IPv4-mapped IPv6 bypass)", "cvss": 4.0, "type": "bypass",
     "remote": True, "fixed_in": "8.9.0"},
    {"id": "CVE-2024-11053", "product": "curl", "min": "8.8.0", "max": "8.10.1",
     "desc": "Cookie injection with special characters (CWE-732)", "cvss": 5.3, "type": "cookie injection",
     "remote": True, "fixed_in": "8.11.0"},
    {"id": "CVE-2024-11054", "product": "curl", "min": "8.4.0", "max": "8.10.1",
     "desc": "GSS credentials leak via PKCS#11 / NSS", "cvss": 5.3, "type": "info leak",
     "remote": True, "fixed_in": "8.11.0"},
    # ============================== OpenSSL ==============================
    {"id": "CVE-2022-3602", "product": "openssl", "min": "1.1.1", "max": "1.1.1r",
     "desc": "X.509 email address 4-byte buffer overflow (fixed 1.1.1s)", "cvss": 7.5, "type": "stack overflow",
     "remote": True, "fixed_in": "1.1.1s"},
    {"id": "CVE-2022-4450", "product": "openssl", "min": "1.1.1", "max": "1.1.1s",
     "desc": "X.509 MAV (memory allocation violation) DoS", "cvss": 5.3, "type": "denial of service",
     "remote": True, "fixed_in": "1.1.1t"},
    {"id": "CVE-2023-0286", "product": "openssl", "min": "1.1.1", "max": "1.1.1s",
     "desc": "X.509 email address 4-byte buffer overflow (fixed 1.1.1t)", "cvss": 7.5, "type": "stack overflow",
     "remote": True, "fixed_in": "1.1.1t"},
    {"id": "CVE-2022-4203", "product": "openssl", "min": "1.1.1", "max": "1.1.1s",
     "desc": "X.509 name constraints decoding buffer over-read (DoS)", "cvss": 5.3, "type": "denial of service",
     "remote": True, "fixed_in": "1.1.1t"},
    {"id": "CVE-2023-2650", "product": "openssl", "min": "3.0.0", "max": "3.0.8",
     "desc": "X.400 address RID ASN.1 DoS (CWE-400)", "cvss": 5.3, "type": "denial of service",
     "remote": True, "fixed_in": "3.0.9"},
    {"id": "CVE-2023-0464", "product": "openssl", "min": "3.0.0", "max": "3.0.8",
     "desc": "Excessive resource use verifying X.509 policy constraints", "cvss": 5.3, "type": "denial of service",
     "remote": True, "fixed_in": "3.0.9"},
    {"id": "CVE-2023-5363", "product": "openssl", "min": "3.0.0", "max": "3.0.11",
     "desc": "RSA key generation DoS (excessive resource use)", "cvss": 5.5, "type": "denial of service",
     "remote": True, "fixed_in": "3.0.12"},
    {"id": "CVE-2024-0727", "product": "openssl", "min": "3.0.0", "max": "3.0.12",
     "desc": "PKCS12 file parsing DoS (heap overflow)", "cvss": 5.3, "type": "denial of service",
     "remote": True, "fixed_in": "3.0.13"},
    {"id": "CVE-2024-4741", "product": "openssl", "min": "3.0.0", "max": "3.0.14",
     "desc": "Punycode decoding DoS in name constraints", "cvss": 5.3, "type": "denial of service",
     "remote": True, "fixed_in": "3.0.15"},
    # ============================== FFmpeg ==============================
    {"id": "CVE-2020-22017", "product": "ffmpeg", "min": "4.0", "max": "4.2.2",
     "desc": "Heap-based buffer overflow in decoder (memory corruption)", "cvss": 8.8, "type": "heap overflow",
     "remote": True, "fixed_in": "4.3"},
    {"id": "CVE-2020-22021", "product": "ffmpeg", "min": "3.4", "max": "4.3.1",
     "desc": "Heap overflow / OOB read in decoding (clusterfuzz)", "cvss": 7.1, "type": "heap overflow",
     "remote": True, "fixed_in": "4.4"},
    {"id": "CVE-2020-22026", "product": "ffmpeg", "min": "4.0", "max": "4.3.1",
     "desc": "FFmpeg 4.x security issue in libavcodec", "cvss": 7.1, "type": "memory corruption",
     "remote": True, "fixed_in": "4.4"},
    {"id": "CVE-2020-35964", "product": "ffmpeg", "min": "4.0", "max": "4.4.0",
     "desc": "Heap buffer overflow in libavcodec (decoder)", "cvss": 7.5, "type": "heap overflow",
     "remote": True, "fixed_in": "4.4"},
    {"id": "CVE-2021-38171", "product": "ffmpeg", "min": "4.0", "max": "4.4.1",
     "desc": "Heap buffer overflow in adpcm_ima_decoder / other codecs", "cvss": 7.1, "type": "heap overflow",
     "remote": True, "fixed_in": "4.4.1"},
    {"id": "CVE-2023-49528", "product": "ffmpeg", "min": "6.0", "max": "6.0",
     "desc": "Heap overflow in ffmpeg 6.0 (vulkan/avformat)", "cvss": 7.1, "type": "heap overflow",
     "remote": True, "fixed_in": "6.1"},
    {"id": "CVE-2023-51792", "product": "ffmpeg", "min": "5.0", "max": "5.1.3",
     "desc": "Heap buffer overflow in ffmpeg 5.1.x (libavcodec)", "cvss": 7.1, "type": "heap overflow",
     "remote": True, "fixed_in": "6.0"},
    {"id": "CVE-2024-31578", "product": "ffmpeg", "min": "5.0", "max": "6.0",
     "desc": "Heap buffer overflow in ffmpeg (adpcm/vorbis decode)", "cvss": 7.1, "type": "heap overflow",
     "remote": True, "fixed_in": "6.1"},
    {"id": "CVE-2024-36630", "product": "ffmpeg", "min": "6.0", "max": "6.1.1",
     "desc": "Heap buffer overflow in ffmpeg (ffmpeg_filter / decode)", "cvss": 7.1, "type": "heap overflow",
     "remote": True, "fixed_in": "7.0"},
    # ============================== libpng ==============================
    {"id": "CVE-2019-7317", "product": "libpng", "min": "1.0.0", "max": "1.6.35",
     "desc": "Use-after-free / memory leak in png image parsing (DoS)", "cvss": 7.1, "type": "use-after-free",
     "remote": True, "fixed_in": "1.6.36"},
    {"id": "CVE-2020-35502", "product": "libpng", "min": None, "max": "1.6.37",
     "desc": "Heap-buffer-overflow in png image parsing (chunk handling)", "cvss": 7.5, "type": "heap overflow",
     "remote": True, "fixed_in": "1.6.37"},
    # ============================== libjpeg ==============================
    {"id": "CVE-2018-11813", "product": "libjpeg", "min": None, "max": "9c",
     "desc": "Heap buffer overflow in libjpeg (RLE BMP parsing)", "cvss": 6.5, "type": "heap overflow",
     "remote": True, "fixed_in": "9d"},
    {"id": "CVE-2021-46822", "product": "libjpeg", "min": None, "max": "9e",
     "desc": "Out-of-bounds read in get_rgb_row / JPEG lossless", "cvss": 6.5, "type": "heap over-read",
     "remote": True, "fixed_in": "9f"},
    # ============================== libwebp ==============================
    {"id": "CVE-2023-4863", "product": "libwebp", "min": None, "max": "1.3.2",
     "desc": "Heap buffer overflow in WebPDecode (lossless, CWE-122)", "cvss": 8.8, "type": "heap overflow",
     "remote": True, "fixed_in": "1.4.0"},
    {"id": "CVE-2023-5129", "product": "libwebp", "min": None, "max": "1.3.2",
     "desc": "Heap buffer overflow in libwebp (same root as 4863)", "cvss": 8.8, "type": "heap overflow",
     "remote": True, "fixed_in": "1.4.0"},
    # ============================== libtiff ==============================
    {"id": "CVE-2022-22844", "product": "libtiff", "min": None, "max": "4.4.0",
     "desc": "Heap-based buffer overflow in TIFFFetchNormalTag", "cvss": 7.1, "type": "heap overflow",
     "remote": True, "fixed_in": "4.5.0"},
    {"id": "CVE-2023-6277", "product": "libtiff", "min": None, "max": "4.5.1",
     "desc": "Heap buffer overflow in TIFFReadRawTile (CWE-122)", "cvss": 6.5, "type": "heap overflow",
     "remote": True, "fixed_in": "4.6.0"},
    {"id": "CVE-2024-7006", "product": "libtiff", "min": None, "max": "4.6.0",
     "desc": "Heap buffer overflow in TIFFReadRGBATile (CWE-122)", "cvss": 6.5, "type": "heap overflow",
     "remote": True, "fixed_in": "4.7.0"},
    # ============================== openjpeg ==============================
    {"id": "CVE-2021-3575", "product": "openjpeg", "min": None, "max": "2.4.0",
     "desc": "Heap buffer overflow in opj (2.4.0 before)", "cvss": 7.8, "type": "heap overflow",
     "remote": True, "fixed_in": "2.4.0"},
    {"id": "CVE-2021-29338", "product": "openjpeg", "min": None, "max": "2.4.0",
     "desc": "Heap-based buffer overflow in opj_j2k (CWE-122)", "cvss": 7.8, "type": "heap overflow",
     "remote": True, "fixed_in": "2.4.0"},
    # ============================== giflib ==============================
    {"id": "CVE-2022-28506", "product": "giflib", "min": None, "max": "5.2.1",
     "desc": "Stack buffer overflow in DGifDecompressLine (CWE-121)", "cvss": 7.8, "type": "stack overflow",
     "remote": True, "fixed_in": "5.2.2"},
    # ============================== libheif ==============================
    {"id": "CVE-2020-18772", "product": "libheif", "min": None, "max": "1.8.0",
     "desc": "Heap buffer overflow / OOB write in heif decoding", "cvss": 7.8, "type": "heap overflow",
     "remote": True, "fixed_in": "1.9.0"},
    # ============================== libsndfile ==============================
    {"id": "CVE-2021-3246", "product": "libsndfile", "min": None, "max": "1.0.30",
     "desc": "Heap buffer overflow in wav write / mp3 (CWE-122)", "cvss": 7.5, "type": "heap overflow",
     "remote": True, "fixed_in": "1.0.31"},
    # ============================== libvpx (VP8/VP9) ==============================
    {"id": "CVE-2023-5217", "product": "libvpx", "min": None, "max": "1.13.0",
     "desc": "Heap buffer overflow in VP8 encoding (CWE-122)", "cvss": 8.8, "type": "heap overflow",
     "remote": True, "fixed_in": "1.13.1"},
    {"id": "CVE-2023-44488", "product": "libvpx", "min": None, "max": "1.13.0",
     "desc": "Heap buffer overflow in libvpx (VP9 decode)", "cvss": 8.8, "type": "heap overflow",
     "remote": True, "fixed_in": "1.13.1"},
    {"id": "CVE-2020-0034", "product": "libvpx", "min": None, "max": "1.8.0",
     "desc": "Heap buffer overflow in vpx decode (vp9)", "cvss": 7.5, "type": "heap overflow",
     "remote": True, "fixed_in": "1.8.1"},
    # ============================== libvorbis (OGG audio, games) ==============================
    {"id": "CVE-2017-14160", "product": "libvorbis", "min": None, "max": "1.3.5",
     "desc": "Heap buffer overflow in vorbis (oggvorbis, CWE-122)", "cvss": 8.8, "type": "heap overflow",
     "remote": True, "fixed_in": "1.3.6"},
    {"id": "CVE-2018-5146", "product": "libvorbis", "min": None, "max": "1.3.5",
     "desc": "Heap buffer overflow in libvorbis (audio decode)", "cvss": 8.8, "type": "heap overflow",
     "remote": True, "fixed_in": "1.3.6"},
    {"id": "CVE-2020-20412", "product": "libvorbis", "min": None, "max": "1.3.6",
     "desc": "Heap buffer overflow in vorbis_analysis (fixed 1.3.7)", "cvss": 7.5, "type": "heap overflow",
     "remote": True, "fixed_in": "1.3.7"},
    {"id": "CVE-2020-20413", "product": "libvorbis", "min": None, "max": "1.3.6",
     "desc": "Heap buffer overflow in vorbis (mapping 0 residue)", "cvss": 7.5, "type": "heap overflow",
     "remote": True, "fixed_in": "1.3.7"},
    # ============================== freetype ==============================
    {"id": "CVE-2020-15999", "product": "freetype", "min": None, "max": "2.10.3",
     "desc": "Heap buffer overflow in Load_Sbit_Png (CWE-122)", "cvss": 8.8, "type": "heap overflow",
     "remote": True, "fixed_in": "2.10.4"},
    {"id": "CVE-2022-27404", "product": "freetype", "min": None, "max": "2.12.0",
     "desc": "Buffer overflow in sfnt / psaux (CWE-787)", "cvss": 7.8, "type": "heap overflow",
     "remote": True, "fixed_in": "2.12.1"},
    {"id": "CVE-2022-27405", "product": "freetype", "min": None, "max": "2.12.0",
     "desc": "Buffer overflow in sfnt (CWE-787)", "cvss": 7.8, "type": "heap overflow",
     "remote": True, "fixed_in": "2.12.1"},
    {"id": "CVE-2022-27406", "product": "freetype", "min": None, "max": "2.12.0",
     "desc": "Buffer overflow in psaux (CWE-787)", "cvss": 7.8, "type": "heap overflow",
     "remote": True, "fixed_in": "2.12.1"},
    # ============================== harfbuzz ==============================
    {"id": "CVE-2023-25193", "product": "harfbuzz", "min": None, "max": "7.0.0",
     "desc": "Heap buffer overflow in hb-ot shaping (CWE-122)", "cvss": 7.5, "type": "heap overflow",
     "remote": True, "fixed_in": "7.0.1"},
    {"id": "CVE-2021-45931", "product": "harfbuzz", "min": None, "max": "2.9.1",
     "desc": "Memory error in hb-shape (DoS)", "cvss": 6.5, "type": "memory corruption",
     "remote": True, "fixed_in": "2.9.2"},
    {"id": "CVE-2021-45932", "product": "harfbuzz", "min": None, "max": "2.9.1",
     "desc": "Memory error in hb-shape (DoS)", "cvss": 6.5, "type": "memory corruption",
     "remote": True, "fixed_in": "2.9.2"},
    # ============================== ICU ==============================
    {"id": "CVE-2020-10531", "product": "icu", "min": None, "max": "67.1",
     "desc": "Integer overflow in Unicode string handling (CWE-190)", "cvss": 9.8, "type": "integer overflow",
     "remote": True, "fixed_in": "68.1"},
    {"id": "CVE-2021-30535", "product": "icu", "min": None, "max": "68.2",
     "desc": "Use-after-free / type confusion in ICU (V8-related)", "cvss": 8.8, "type": "use-after-free",
     "remote": True, "fixed_in": "69.1"},
    # ============================== libarchive ==============================
    {"id": "CVE-2021-36976", "product": "libarchive", "min": None, "max": "3.5.1",
     "desc": "Use-after-free in archive_read (CWE-416)", "cvss": 7.8, "type": "use-after-free",
     "remote": True, "fixed_in": "3.5.2"},
    {"id": "CVE-2020-35707", "product": "libarchive", "min": None, "max": "3.4.3",
     "desc": "Heap buffer overflow in archive_read_support_format_rar", "cvss": 7.8, "type": "heap overflow",
     "remote": True, "fixed_in": "3.5.0"},
    {"id": "CVE-2021-23177", "product": "libarchive", "min": None, "max": "3.5.1",
     "desc": "Integer overflow / OOB read in archive_write (CWE-190)", "cvss": 5.5, "type": "integer overflow",
     "remote": True, "fixed_in": "3.5.2"},
    # ============================== libzip ==============================
    {"id": "CVE-2021-32470", "product": "libzip", "min": None, "max": "1.7.3",
     "desc": "Use-after-free in zip_close (CWE-416)", "cvss": 6.5, "type": "use-after-free",
     "remote": True, "fixed_in": "1.8.0"},
    {"id": "CVE-2022-24941", "product": "libzip", "min": None, "max": "1.7.3",
     "desc": "Out-of-bounds read in zip_source_file", "cvss": 7.5, "type": "heap over-read",
     "remote": True, "fixed_in": "1.8.0"},
    # ============================== zstd / lz4 / brotli / liblzma ==============================
    {"id": "CVE-2021-3520", "product": "lz4", "min": None, "max": "1.9.3",
     "desc": "Out-of-bounds read in LZ4_decompress_safe_partial", "cvss": 5.5, "type": "heap over-read",
     "remote": True, "fixed_in": "1.9.4"},
    {"id": "CVE-2020-8927", "product": "brotli", "min": None, "max": "1.0.9",
     "desc": "Integer overflow in BrotliDecompress (CWE-190)", "cvss": 9.1, "type": "integer overflow",
     "remote": True, "fixed_in": "1.1.0"},
    {"id": "CVE-2024-3094", "product": "liblzma", "min": "5.6.0", "max": "5.6.1",
     "desc": "xz utils liblzma backdoor (supply-chain, SSH auth bypass)", "cvss": 10.0, "type": "backdoor",
     "remote": True, "fixed_in": "5.6.2"},
    # ============================== c-ares ==============================
    {"id": "CVE-2022-4904", "product": "c-ares", "min": None, "max": "1.18.1",
     "desc": "Stack buffer overflow in ares_parse_soa_reply (CWE-121)", "cvss": 8.1, "type": "stack overflow",
     "remote": True, "fixed_in": "1.19.0"},
    {"id": "CVE-2021-3672", "product": "c-ares", "min": None, "max": "1.17.1",
     "desc": "Out-of-bounds read in ares_parse_aaaa_reply", "cvss": 7.1, "type": "heap over-read",
     "remote": True, "fixed_in": "1.17.2"},
    {"id": "CVE-2024-25629", "product": "c-ares", "min": None, "max": "1.27.0",
     "desc": "Denial of service in c-ares DNS (1.27 before)", "cvss": 5.3, "type": "denial of service",
     "remote": True, "fixed_in": "1.28.0"},
    # ============================== nghttp2 ==============================
    {"id": "CVE-2020-11080", "product": "nghttp2", "min": None, "max": "1.40.0",
     "desc": "HTTP/2 request smuggling (CWE-444)", "cvss": 5.9, "type": "request smuggling",
     "remote": True, "fixed_in": "1.40.1"},
    {"id": "CVE-2024-28206", "product": "nghttp2", "min": None, "max": "1.60.0",
     "desc": "Out-of-bounds read in nghttp2_session_mem_recv", "cvss": 7.5, "type": "heap over-read",
     "remote": True, "fixed_in": "1.61.0"},
    {"id": "CVE-2024-28207", "product": "nghttp2", "min": None, "max": "1.60.0",
     "desc": "NULL pointer dereference in nghttp2 (DoS)", "cvss": 6.5, "type": "denial of service",
     "remote": True, "fixed_in": "1.61.0"},
    # ============================== libssh2 ==============================
    {"id": "CVE-2023-48795", "product": "libssh2", "min": None, "max": "1.10.0",
     "desc": "Terrapin attack - SSH channel sequence number truncation", "cvss": 5.9, "type": "integrity bypass",
     "remote": True, "fixed_in": "1.11.0"},
    {"id": "CVE-2019-17498", "product": "libssh2", "min": None, "max": "1.9.0",
     "desc": "Integer overflow in SSH packet handling (CWE-190)", "cvss": 6.5, "type": "integer overflow",
     "remote": True, "fixed_in": "1.9.1"},
    # ============================== wolfssl ==============================
    {"id": "CVE-2022-39173", "product": "wolfssl", "min": None, "max": "5.4.0",
     "desc": "Memory leak / DoS in TLS handshake", "cvss": 7.5, "type": "denial of service",
     "remote": True, "fixed_in": "5.5.0"},
    {"id": "CVE-2024-1544", "product": "wolfssl", "min": None, "max": "5.7.0",
     "desc": "Buffer overflow in wolfSSL (fixed 5.7.0)", "cvss": 7.8, "type": "heap overflow",
     "remote": True, "fixed_in": "5.7.0"},
    # ============================== mbedtls ==============================
    {"id": "CVE-2021-45450", "product": "mbedtls", "min": None, "max": "2.16.11",
     "desc": "Memory corruption / buffer overflow in mbedtls_ssl (fixed 2.16.12)", "cvss": 7.5, "type": "memory corruption",
     "remote": True, "fixed_in": "2.16.12"},
    {"id": "CVE-2024-28960", "product": "mbedtls", "min": "3.0.0", "max": "3.5.2",
     "desc": "Buffer overflow in mbedtls_ssl (fixed 3.5.3)", "cvss": 7.5, "type": "heap overflow",
     "remote": True, "fixed_in": "3.5.3"},
    # ============================== libevent ==============================
    {"id": "CVE-2016-10195", "product": "libevent", "min": None, "max": "2.1.6",
     "desc": "Stack overflow in evutil_parse_sockaddr_port (CWE-121)", "cvss": 7.5, "type": "stack overflow",
     "remote": True, "fixed_in": "2.1.7"},
    {"id": "CVE-2016-10196", "product": "libevent", "min": None, "max": "2.1.6",
     "desc": "Stack overflow in evdns (CWE-121)", "cvss": 7.5, "type": "stack overflow",
     "remote": True, "fixed_in": "2.1.7"},
    # ============================== libyaml / json-c ==============================
    {"id": "CVE-2013-6393", "product": "libyaml", "min": None, "max": "0.1.4",
     "desc": "Heap-based buffer overflow in yaml_parser_parse (CWE-122)", "cvss": 8.8, "type": "heap overflow",
     "remote": True, "fixed_in": "0.1.5"},
    {"id": "CVE-2020-12762", "product": "json-c", "min": None, "max": "0.13.1",
     "desc": "Heap overflow in json_object_add (CWE-122)", "cvss": 6.5, "type": "heap overflow",
     "remote": True, "fixed_in": "0.14.0"},
    {"id": "CVE-2021-32292", "product": "json-c", "min": None, "max": "0.13.1",
     "desc": "Heap overflow in json_c object handling (CWE-122)", "cvss": 6.5, "type": "heap overflow",
     "remote": True, "fixed_in": "0.14.0"},
    # ============================== protobuf / hiredis ==============================
    {"id": "CVE-2022-1941", "product": "protobuf", "min": None, "max": "3.18.3",
     "desc": "Memory corruption / DoS in protobuf parsing (CWE-787)", "cvss": 7.5, "type": "memory corruption",
     "remote": True, "fixed_in": "3.18.4"},
    {"id": "CVE-2021-22570", "product": "protobuf", "min": None, "max": "3.18.3",
     "desc": "Denial of service in protobuf (OOM)", "cvss": 6.5, "type": "denial of service",
     "remote": True, "fixed_in": "3.19.3"},
    {"id": "CVE-2021-32765", "product": "hiredis", "min": None, "max": "1.0.0",
     "desc": "Integer overflow in redisFormatSdsCommandArgv (CWE-190)", "cvss": 5.5, "type": "integer overflow",
     "remote": True, "fixed_in": "1.0.0"},
    # ============================== sqlite ==============================
    {"id": "CVE-2022-35737", "product": "sqlite", "min": "1.0.0", "max": "3.39.1",
     "desc": "Stack buffer overflow in sqlite3_snprintf / printf format (CWE-121)", "cvss": 8.1, "type": "stack overflow",
     "remote": True, "fixed_in": "3.39.2"},
    {"id": "CVE-2020-15358", "product": "sqlite", "min": None, "max": "3.32.2",
     "desc": "Heap-based buffer overflow in sqlite3Strlen30 (DoS)", "cvss": 7.1, "type": "heap overflow",
     "remote": True, "fixed_in": "3.32.3"},
    # ============================== zlib ==============================
    {"id": "CVE-2018-25032", "product": "zlib", "min": None, "max": "1.2.11",
     "desc": "Memory corruption / DoS via deflate (fixed 1.2.12)", "cvss": 7.5, "type": "memory corruption",
     "remote": True, "fixed_in": "1.2.12"},
    {"id": "CVE-2022-37434", "product": "zlib", "min": None, "max": "1.2.12",
     "desc": "Heap buffer overflow in inflate (CWE-122)", "cvss": 8.8, "type": "heap overflow",
     "remote": True, "fixed_in": "1.2.13"},
    {"id": "CVE-2023-45853", "product": "zlib", "min": None, "max": "1.2.13",
     "desc": "Integer overflow in gzprintf (CWE-190)", "cvss": 6.5, "type": "integer overflow",
     "remote": True, "fixed_in": "1.2.13.1"},
    # ============================== libxml2 ==============================
    {"id": "CVE-2017-16931", "product": "libxml2", "min": None, "max": "2.9.7",
     "desc": "Heap-based buffer over-read in xmlParseAttValueComplex", "cvss": 6.5, "type": "heap over-read",
     "remote": True, "fixed_in": "2.9.8"},
    {"id": "CVE-2022-2309", "product": "libxml2", "min": None, "max": "2.9.14",
     "desc": "Use-after-free in xmlXInclude (remote, HTML/XML parsing)", "cvss": 7.1, "type": "use-after-free",
     "remote": True, "fixed_in": "2.10.0"},
    {"id": "CVE-2023-28484", "product": "libxml2", "min": None, "max": "2.10.3",
     "desc": "Use-after-free in xmlValidatePopElement (CWE-416)", "cvss": 7.1, "type": "use-after-free",
     "remote": True, "fixed_in": "2.10.4"},
    {"id": "CVE-2023-45322", "product": "libxml2", "min": None, "max": "2.11.5",
     "desc": "Use-after-free in xmlUnlinkNode (CWE-416)", "cvss": 7.1, "type": "use-after-free",
     "remote": True, "fixed_in": "2.11.6"},
    {"id": "CVE-2024-25062", "product": "libxml2", "min": None, "max": "2.11.7",
     "desc": "Use-after-free in XMLReader (CWE-416)", "cvss": 7.1, "type": "use-after-free",
     "remote": True, "fixed_in": "2.12.0"},
    # ============================== expat ==============================
    {"id": "CVE-2022-25236", "product": "expat", "min": "2.0.0", "max": "2.4.7",
     "desc": "xmlParseXmlDecl use-after-free / crash", "cvss": 6.5, "type": "use-after-free",
     "remote": True, "fixed_in": "2.4.8"},
    {"id": "CVE-2022-25235", "product": "expat", "min": "2.0.0", "max": "2.4.7",
     "desc": "xmlCopyCharRange integer overflow / buffer overrun", "cvss": 7.1, "type": "heap overflow",
     "remote": True, "fixed_in": "2.4.8"},
    # ============================== lua ==============================
    {"id": "CVE-2020-24370", "product": "lua", "min": "5.4.0", "max": "5.4.0",
     "desc": "Heap-based buffer overflow in luaG_runerror / gc (debug)", "cvss": 7.5, "type": "heap overflow",
     "remote": False, "fixed_in": "5.4.1"},
    {"id": "CVE-2021-43519", "product": "lua", "min": "5.4.0", "max": "5.4.2",
     "desc": "Stack overflow in lua stack handling (CWE-121)", "cvss": 7.5, "type": "stack overflow",
     "remote": False, "fixed_in": "5.4.3"},
    # ============================== luajit ==============================
    {"id": "CVE-2020-22876", "product": "luajit", "min": None, "max": "2.0.5",
     "desc": "Memory leak / DoS via table.c handling", "cvss": 6.5, "type": "denial of service",
     "remote": False, "fixed_in": "2.1.0"},
    # ============================== SDL2 (graphics/windowing) ==============================
    {"id": "CVE-2019-13616", "product": "sdl2", "min": None, "max": "2.0.9",
     "desc": "Stack buffer overflow in SDL2 (CWE-121, DoS)", "cvss": 7.5, "type": "stack overflow",
     "remote": True, "fixed_in": "2.0.10"},
    {"id": "CVE-2021-3361", "product": "sdl2", "min": None, "max": "2.0.14",
     "desc": "Use-after-free in SDL_BlitSurface / rendering", "cvss": 7.5, "type": "use-after-free",
     "remote": True, "fixed_in": "2.0.16"},
    # ============================== libsass ==============================
    {"id": "CVE-2018-19799", "product": "libsass", "min": None, "max": "3.5.5",
     "desc": "Integer overflow in libsass (CWE-190, heap corruption)", "cvss": 7.5, "type": "integer overflow",
     "remote": True, "fixed_in": "3.5.6"},
    {"id": "CVE-2018-19837", "product": "libsass", "min": None, "max": "3.5.5",
     "desc": "Heap buffer overflow in libsass (CWE-122)", "cvss": 7.5, "type": "heap overflow",
     "remote": True, "fixed_in": "3.5.6"},
]


def load_builtin_db():
    return BUILTIN_CVES


# ---------------------------------------------------------------------------
# Optional NVD enrichment
# ---------------------------------------------------------------------------

def _nvd_query_product(product, cache_dir):
    """Query NVD for CVEs matching a product keyword (requires NVD_API_KEY env).
    Returns list of raw CVE ids matched by product string, cached locally."""
    api_key = os.environ.get("NVD_API_KEY")
    if not api_key:
        return []

    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, f"nvd_{product}.json")
    if os.path.exists(cache_file) and (time.time() - os.path.getmtime(cache_file)) < 24 * 3600:
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    keyword = product
    url = f"{base}?keywordSearch={keyword}&resultsPerPage=50"
    req = urllib.request.Request(url)
    req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        vulns = data.get("vulnerabilities", [])
        ids = [v["cve"]["id"] for v in vulns]
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(ids, f)
        return ids
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Main matching entry point
# ---------------------------------------------------------------------------

def match_entries(entries, use_nvd=True, cache_dir=None, verbose=False):
    """entries: list of scanned dicts. Returns list of match dicts:
    {entry, product, version, matches:[cve,...]}."""
    cache_dir = cache_dir or os.path.join(os.path.dirname(__file__), "data", "cache")
    db = load_builtin_db() + _extra_cves()

    results = []
    seen_nvd = {} if use_nvd else None

    for e in entries:
        product, version = identify_product(e)
        if not product or not version:
            continue

        matches = []
        for cve in db:
            if cve["product"] != product:
                continue
            if version_in_range(version, cve.get("min"), cve.get("max")):
                matches.append(dict(cve))

        # NVD enrichment (best-effort)
        if use_nvd and seen_nvd is not None:
            if product not in seen_nvd:
                seen_nvd[product] = _nvd_query_product(product, cache_dir)
            known_ids = {m["id"] for m in matches}
            for cid in seen_nvd[product]:
                if cid not in known_ids:
                    matches.append({"id": cid, "product": product, "min": None, "max": None,
                                    "desc": "Candidate from NVD keyword search (version unverified)", "cvss": 0,
                                    "type": "unverified", "remote": None, "fixed_in": None})

        if matches:
            results.append({"entry": e, "product": product, "version": version, "matches": matches})

    return results

def identified_libraries(entries):
    """Return dedup list of EVERY identified third-party lib (new or old, with or
    without CVE hits). Each: {name, product, version, cve_count, top_cvss}."""
    seen = {}
    for e in entries:
        product, version = identify_product(e)
        if not product or not version:
            continue
        key = (product, version)
        if key not in seen:
            seen[key] = {"name": e.get("name", ""), "product": product,
                         "version": version, "cve_count": 0, "top_cvss": 0.0}
    for key, info in seen.items():
        product, version = key
        _db = BUILTIN_CVES + _extra_cves()
        hits = [c for c in _db
                if c["product"] == product and version_in_range(version, c.get("min"), c.get("max"))]
        info["cve_count"] = len(hits)
        info["top_cvss"] = max((c.get("cvss") or 0) for c in hits) if hits else 0.0
    return list(seen.values())

