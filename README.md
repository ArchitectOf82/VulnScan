# VulnScan 第三方库漏洞扫描器

[English README](README_en.md)

自动扫描指定目录里的 DLL/EXE，识别第三方库和版本，匹配已知 CVE，生成报告。

## 目录结构
```
VulnScan/
├── cpp/pe_scanner.cpp      C++ 扫描引擎（PE 解析、版本资源、SHA256、架构）
├── python/vulnscan.py      CLI 主程序
├── python/cve_match.py     CVE 匹配（内置离线库 + 可选 NVD 增强）
├── python/report_gen.py    HTML 报告生成
├── python/pe_audit.py      模块2：二进制安全审计（PE 导入解析/危险 API 分类/密钥扫描）
├── python/report_audit.py  模块2：审计 HTML 报告生成
├── python/info_leak.py     模块3：信息泄露扫描（文件名规则 + 内容凭证扫描）
├── python/report_leak.py   模块3：泄露报告生成（含 SVG 图解 + 审计列表）
├── python/port_scan.py     模块4：端口 & 服务识别（TCP 探测 + banner）
├── python/web_weak.py      模块5：Web 弱配置识别（debug/弱口令/明文/弱加密等）
├── python/baseline.py      模块6：Windows 安全基线核查（只读）
├── python/report_all.py    模块7：统一报告引擎（聚合全部模块）
├── python/VulnScan_Studio.py  产品主界面（tkinter 图形窗口，7 功能入口）
├── python/webui.py         本地 Web UI（可选）
├── build/pe_scanner.exe    已编译扫描引擎
├── scripts/build_cpp.bat   重编译引擎
├── output/                 报告输出目录
├── 扫描.bat                CLI 一键扫描（推荐，无需本地服务）
├── 审计.bat                模块2：一键二进制安全审计（推荐）
├── 泄露.bat                模块3：一键信息泄露扫描（推荐）
├── VulnScan Studio.bat      产品主界面一键启动（推荐）
└── 启动扫描器.bat          Web UI 一键启动（依赖本地 HTTP 服务）
```

## 用法

### 方式 A：CLI 一键扫描（推荐，肯定能用）
双击 `扫描.bat`，输入要扫描的目录（如 `C:\Program Files\MyApp`），回车。
扫描完成后自动打开 `output\` 文件夹，内含 HTML 报告。
命令行等价：
```
python python\vulnscan.py <目录> --out output
```

### 方式 B：Web UI（图形界面，可选）
双击 `启动扫描器.bat`，浏览器自动打开 http://127.0.0.1:8000。
**注意**：Web UI 依赖本机 HTTP 服务。如果你的安全软件
拦截了本地回环访问，页面会一直"加载中/无法访问"。此时请在安全软件里给
python.exe 放行本地访问，或改用 CLI 方式。

## 重建扫描引擎（改了 C++ 代码后）
双击 `scripts\build_cpp.bat`（需要 VS 编译器）。

## 内置 CVE 库覆盖（46+ 库 / 114+ 条 CVE）
覆盖主流通用第三方库（任何软件目录都能扫）：
- **网络/加密**：curl、OpenSSL、c-ares、nghttp2、libssh2、wolfSSL、mbedTLS、libevent、libsodium
- **媒体/图像**：FFmpeg、libpng、libjpeg、libwebp、libtiff、openjpeg、giflib、libheif、libsndfile、libvpx、libmp3lame
- **字体/文本**：freetype、harfbuzz、ICU
- **压缩/存档**：zlib、zlib-ng、libarchive、libzip、zstd、lz4、brotli、liblzma(xz)
- **图形/窗口**：SDL2、GLEW、GLFW、freeglut
- **游戏音频**：libvorbis、libogg、libtheora、OpenAL、FMOD
- **游戏引擎(识别)**：Unity、Unreal、Godot、Cocos2D、PhysX
- **解析/数据**：libxml2、expat、libyaml、json-c、rapidjson、protobuf、hiredis、leveldb
- **其他**：sqlite、lua、luajit、libsass、assimp、bullet
含 2023-2024 较新 CVE（如 curl CVE-2023-38545 SOCKS5、libwebp CVE-2023-4863、xz CVE-2024-3094 后门等）。
设环境变量 `NVD_API_KEY` 可联网扩展匹配（结果缓存于 python/data/cache）。

## 模块 2：二进制安全审计（新）
对目录内每个 PE（dll/exe/sys/ocx）做**静态能力审计**：
- 解析导入表 → 列出每个模块导入的 DLL 与函数
- 把危险 API 归类为 8 类能力（命令执行/文件写入/注册表/内存操作/网络/加密/线程注入/动态加载）
- 扫描硬编码密钥 / 敏感字符串候选（hex 密钥、private key、连接串等）
- 生成「二进制安全审计报告.html」：统计卡 + 能力分类汇总表 + 每个模块的能力图与危险 API 明细

### 用法
双击 `审计.bat`，输入要审计的目录，回车；或命令行：
```
python python\vulnscan.py <目录> --audit --out output
```
`--audit` 会**同时**出 CVE 扫描报告（vulnscan_report.html）和二进制审计报告（binary_audit_report.html）。
审计较大目录较慢（如大型应用资源目录约 40 秒），属正常。

**说明**：本模块是进攻面定位 / 审计探雷用途——识别二进制"具备什么危险能力、藏了什么密钥"，只做静态识别，不含任何复现或武器化内容。

## 模块 3：信息泄露扫描（新）
对目标目录做**静态信息泄露识别**，两层检测：
- **文件名/扩展名规则**：备份/临时文件（*.bak/*.old/*.swp 等）、版本控制残留（.git/.svn/.hg）、敏感配置（.env/web.config/appsettings/.npmrc/.netrc 等）、密钥证书（*.pem/*.key/*.p12/*.pfx 等）、数据库文件（*.sqlite/*.db/*.sql 等）、日志/转储（*.log/*.dmp/*.core 等）、源码/文档分发
- **文件内容扫描**（仅文本文件 ≤512KB）：硬编码凭证、AWS/GitHub token、私钥块、连接串、内网 IP、邮箱等

### 用法
双击 `泄露.bat`，输入要审计的目录；或命令行：
```
python python\vulnscan.py <目录> --leak --out output
```
报告 `info_leak_report.html` 带**泄露类别分布图解（饼图/条形图）+ 审计列表**。
三个模块可叠加：`vulnscan.py <目录> --audit --leak --out output` 一次出三份报告。
**说明**：文件规则与内容正则为启发式——数据库/数据文件等多为程序正常运行产物，"敏感配置/凭证"需人工核验。

## 安全声明
仅用于你有权测试的资产（自有软件、SRC 授权范围）。报告中的版本区间为
内置库推断，提交漏洞前请以 NVD 官方为准核对。

## 统一产品界面：VulnScan Studio（推荐入口）
双击 `VulnScan Studio.bat`，打开图形窗口，内置 **7 个功能入口**：
1. ① 第三方库 CVE 扫描
2. ② 二进制安全审计
3. ③ 信息泄露扫描
4. ④ Web 弱配置
5. ⑤ 系统安全基线（本机）
6. ⑥ 端口 & 服务识别（目标主机，仅授权资产）
7. ⑦ 统一报告（一次跑全部模块）

用法：填扫描目录（端口填目标主机）→ 勾选模块 → 点「扫描所选模块」或「扫描全部（统一报告）」。
每个模块跑完自动打开对应 HTML 报告；「扫描全部」生成 `unified_report.html` 聚合总览 + 各模块分区。

## 命令行汇总
```
python python\vulnscan.py <目录> --out output        # ① CVE
python python\vulnscan.py <目录> --audit --out output # ② 二进制审计（+CVE）
python python\vulnscan.py <目录> --leak --out output  # ③ 信息泄露（+CVE）
python python\vulnscan.py <目录> --web --out output   # ④ Web 弱配置（+CVE）
python python\vulnscan.py <目录> --baseline --out output  # ⑤ 基线（+CVE）
python python\vulnscan.py <目录> --port 127.0.0.1 --out output  # ⑥ 端口（+CVE）
python python\vulnscan.py <目录> --audit --leak --web --baseline --port 127.0.0.1 --all --out output  # ⑦ 全部+统一报告
```


## 模块 8 · 依赖清单扫描（全语言生态）

不只扫 DLL/EXE——遍历目录里**所有语言**的依赖清单，提取依赖名+版本，调 **OSV**（免费、免 key，覆盖 PyPI/npm/Maven/Go/RubyGems/crates.io/Packagist/NuGet/Pub）按版本精确查漏洞，返回真实 CVSS（自带 CVSS 3.1 计算器）与修复版本。

支持的清单：package.json / package-lock.json / yarn.lock / pnpm-lock.yaml / requirements.txt / Pipfile.lock / poetry.lock / go.mod / go.sum / Cargo.lock / Cargo.toml / Gemfile.lock / composer.lock / pom.xml / packages.config / pubspec.lock

```
python vulnscan.py <目录> --dep             # 只跑依赖清单扫描
python vulnscan.py <目录> --all            # 全部模块，统一报告含模块8分区
python dep_scan.py <目录> --out 报告.html   # 独立运行
```

## 自动加库（扫新产品自动补 CVE）

扫到不认识的第三方库时，可一键加库：自动加识别规则 + 从 **NVD**（免 key）拉该库真实 CVE，追加进 `python\data\extra_products.py`（不动内置库），下次扫描自动生效。

```
python add_library.py discover <目录>               # 发现未识别第三方库候选
python add_library.py add <库名> <匹配标识> [--limit 60]   # 加识别 + 自动拉 CVE
python add_library.py fetch <库名> [--min-cvss 7]   # 只拉 CVE
```

> 说明：CVE 命中为启发式（版本推断），重要结论请人工核验。本工具仅用于授权资产内的识别与报告，不含复现 / 武器化内容。

## 模块 9-18（新增，全部只读识别）
- ⑨ Fuzzer：file/stdin/dll 三模式二进制 fuzzing（0day 挖掘，崩溃按 CNVD/CNNVD 报送原始输入）
- ⑩ Web 在线业务探测：安全头/敏感路径/指纹/CORS/TRACE/HTTPS（只读 GET）
- ⑪ 子域名枚举：被动 DNS，并发 32 线程
- ⑫ TLS/证书检查：协议版本/证书链/过期/弱加密（只读握手）
- ⑬ SBOM：生成标准 CycloneDX 1.5 JSON 供应链清单
- ⑭ 在线敏感信息爬取：页面深度 1，密钥/Token/内网/OSS 候选提取（只读）
- ⑮ Web 技术栈指纹：50+ 指纹识别服务器/框架/CMS/语言/CDN（只读 GET）
- ⑯ JS 敏感信息/端点提取：抓页面 JS 扫云密钥/Token/内网/OSS/API 端点（只读）
- ⑰ 子域接管检测：查 CNAME 是否指向无人认领第三方服务（被动 DNS + banner）
- ⑱ API 资产发现：探测 swagger/OpenAPI/Actuator/REST 端点（只读 GET）

## 模块 19 · AI 分析（LLM，双模式）

把扫描结果交给大模型做 AI 解读，让 VulnScan 从「能扫」变「能判断」：
- **漏洞解读**：逐项说明是什么、危害、风险等级（CVSS）
- **误报筛查**：判断哪些更可能是真问题 / 疑似误报 / 不确定，并给依据
- **修复建议**：每项附具体可操作的修复方向
- **整体结论**：3-5 句概括整体风险与优先处理项，生成 `ai_report.html`

**双模式模型接入（自动降级）**：
- **本地 Ollama（优先，离线免费）**：默认 `http://127.0.0.1:11434`，模型默认 `qwen2.5`（可经 `AI_MODEL` 改）。装好 Ollama 并 `ollama pull qwen2.5` 即可用。
- **OpenAI 兼容 API（兜底）**：设环境变量 `AI_API_URL` + `AI_API_KEY` + `AI_MODEL`（如 DeepSeek/Kimi/豆包等）。
- **都没配置**：自动降级为规则化总结（结构化摘要 + 类型分布 + 最高 CVSS），不影响扫描。

```
python vulnscan.py <目录> --ai               # 只加 AI 分析（配合上面任一扫描）
python vulnscan.py <目录> --all              # 全部模块，统一报告含模块19分区
python ai_analyze.py <snapshot.json>         # 独立分析已有快照
```

环境变量示例（OpenAI 兼容 API）：
```
AI_API_URL=https://api.deepseek.com/v1/chat/completions
AI_API_KEY=你的key
AI_MODEL=deepseek-chat
```

## 产品化能力
统一报告、PDF/Word 导出、历史对比、批量多目标、定时配置、自动加库。

## 依赖
Python 3.8+；本地 CVE 模块需先运行 `scripts\build_cpp.bat` 编译 `pe_scanner.exe`（需 VS 编译器）；
在线模块仅用标准库。PDF/Word 导出需 `reportlab`、`python-docx`；可选设 `NVD_API_KEY` 联网增强。

## 合规与免责声明
本工具仅用于**你有权测试的资产**（自有软件、SRC/CNVD 授权范围）。所有在线模块均为**只读识别**
（无害 GET / DNS 查询），不含复现、利用或武器化内容。命中为候选，提交漏洞前请以官方信息人工核验。
违规使用（未授权目标、复现/利用）责任自负。

## 许可证
MIT License，见 [LICENSE](LICENSE)。
