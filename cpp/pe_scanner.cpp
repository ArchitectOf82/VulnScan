// VulnScan - C++ PE scanner
// Scans a directory recursively for .dll/.exe/.sys, extracts library name,
// version resource, SHA-256 and architecture, outputs JSON to stdout.
//
// Build (VS x64 native):
//   cl /std:c++17 /O2 /EHsc pe_scanner.cpp /link version.lib bcrypt.lib
//
// Usage:
//   pe_scanner.exe <directory> [--maxdepth N]
//   Output: one JSON object per line: {"path":...,"name":...,"size":...}

#include <windows.h>
#include <bcrypt.h>
#include <versionhelpers.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>

#pragma comment(lib, "version.lib")
#pragma comment(lib, "bcrypt.lib")

namespace fs = std::filesystem;

static std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string out(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &out[0], size, nullptr, nullptr);
    return out;
}

static std::string JsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s)
    {
        switch (c)
        {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if ((unsigned char)c < 0x20) { char buf[8]; sprintf(buf, "\\u%04x", c); out += buf; }
            else out += c;
        }
    }
    return out;
}

// Read version resource fields via VerQueryValue
static bool GetVersionInfo(const std::wstring& path,
                           std::string& fileVersion,
                           std::string& productVersion,
                           std::string& productName,
                           std::string& fileDescription)
{
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (size == 0) return false;

    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(path.c_str(), handle, size, data.data())) return false;

    // Get translation (language/codepage)
    WORD* trans = nullptr;
    UINT transLen = 0;
    if (!VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation", (void**)&trans, &transLen) || transLen < 4)
        return false;

    wchar_t sub[64];
    swprintf(sub, 64, L"\\StringFileInfo\\%04x%04x\\", trans[0], trans[1]);

    auto query = [&](const wchar_t* key, std::string& out) -> bool
    {
        std::wstring full = sub; full += key;
        void* buf = nullptr; UINT len = 0;
        if (!VerQueryValueW(data.data(), full.c_str(), &buf, &len) || !buf || len == 0) return false;
        std::wstring raw((wchar_t*)buf, len);
        // strip trailing nulls
        while (!raw.empty() && raw.back() == L'\0') raw.pop_back();
        out = WideToUtf8(raw);
        return true;
    };

    query(L"FileVersion", fileVersion);
    query(L"ProductVersion", productVersion);
    query(L"ProductName", productName);
    query(L"FileDescription", fileDescription);
    return true;
}

// SHA-256 via BCrypt
static std::string Sha256Hex(const std::wstring& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) return "";
    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0))) { BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }

    char buf[65536];
    while (f.read(buf, sizeof(buf))) { BCryptHashData(hHash, (PUCHAR)buf, (ULONG)f.gcount(), 0); }
    if (f.gcount() > 0) BCryptHashData(hHash, (PUCHAR)buf, (ULONG)f.gcount(), 0);
    f.close();

    UCHAR digest[32];
    if (!NT_SUCCESS(BCryptFinishHash(hHash, digest, 32, 0))) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return ""; }
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (int i = 0; i < 32; ++i) { out += hex[digest[i] >> 4]; out += hex[digest[i] & 0xF]; }
    return out;
}

// Detect PE arch from DOS header + optional header magic
static std::string PeArch(const std::wstring& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) return "unknown";
    char dos[64] = {0}; f.read(dos, 64);
    if (f.gcount() < 64 || dos[0] != 'M' || dos[1] != 'Z') return "unknown";
    long peOff = *(long*)(dos + 0x3C);
    f.clear();
    f.seekg(peOff);
    char pe[26] = {0}; f.read(pe, 26);
    if (f.gcount() < 26 || pe[0] != 'P' || pe[1] != 'E') return "unknown";
    // magic sits at peOff+24: 4-byte "PE\0\0" + 20-byte COFF header
    unsigned short magic = *(unsigned short*)(pe + 24);
    if (magic == 0x10b) return "x86";
    if (magic == 0x20b) return "x64";
    return "unknown";
}

static bool IsTargetExt(const fs::path& p)
{
    std::string ext = p.extension().string();
    for (auto& c : ext) c = (char)tolower((unsigned char)c);
    return ext == ".dll" || ext == ".exe" || ext == ".sys" || ext == ".ocx";
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2)
    {
        fwprintf(stderr, L"usage: %s <directory> [--maxdepth N]\n", argv[0]);
        return 1;
    }

    fs::path root(argv[1]);
    if (!fs::exists(root) || !fs::is_directory(root))
    {
        fwprintf(stderr, L"error: not a directory: %s\n", argv[1]);
        return 1;
    }

    int maxDepth = -1;
    for (int i = 2; i < argc; ++i)
    {
        if (wcscmp(argv[i], L"--maxdepth") == 0 && i + 1 < argc)
            maxDepth = _wtoi(argv[i + 1]);
    }

    fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied);
    fs::recursive_directory_iterator end;
    size_t count = 0;

    for (; it != end; ++it)
    {
        if (maxDepth >= 0 && it.depth() > maxDepth) { it.disable_recursion_pending(); continue; }
        if (!it->is_regular_file()) continue;
        const fs::path& p = it->path();
        if (!IsTargetExt(p)) continue;

        std::wstring wpath = p.wstring();
        std::string fv, pv, pn, fd;
        GetVersionInfo(wpath, fv, pv, pn, fd);

        char sizeBuf[32];
        std::error_code ec;
        uintmax_t sz = fs::file_size(p, ec);
        sprintf(sizeBuf, "%llu", (unsigned long long)sz);

        std::string sha = Sha256Hex(wpath);
        std::string arch = PeArch(wpath);

        // JSON line
        printf("{\"path\":\"%s\",\"name\":\"%s\",\"size\":%s,\"fileVersion\":\"%s\",\"productVersion\":\"%s\",\"productName\":\"%s\",\"fileDescription\":\"%s\",\"sha256\":\"%s\",\"arch\":\"%s\"}\n",
               JsonEscape(WideToUtf8(wpath)).c_str(),
               JsonEscape(WideToUtf8(p.filename().wstring())).c_str(),
               sizeBuf,
               JsonEscape(fv).c_str(),
               JsonEscape(pv).c_str(),
               JsonEscape(pn).c_str(),
               JsonEscape(fd).c_str(),
               sha.c_str(),
               arch.c_str());
        ++count;
    }

    fwprintf(stderr, L"scanned %zu files\n", count);
    return 0;
}
