---
name: android-apk-reverse-analysis
description: >-
  Windows 上从零搭建 Android APK 静态逆向分析环境（无 Java / 无 binutils）并产出带证据链的
  五分册分析报告。当用户要求"逆向 APK / 分析 APK 实现 / 提取硬编码域名密钥 / 还原 MDM 或
  恶意行为逻辑 / 分析 .so 原生层"，或需要对 APK 做只读合规审计时使用。
agent_created: true
---

# Android APK 静态逆向分析（Windows / 无管理员权限）

## 何时使用

- 用户给出 `.apk` 并要求逆向、审计、梳理实现、提取 IOC/密钥、分析原生库。
- 需要先说明：**只读分析，不修改、不重打包、不重签名**原文件。

## 0. 环境与产出约定

- 产出目录：`<工作目录>/analysis/`，下分 `_raw/`（解出的原始件）、`_tools/`（工具）、`apktool_out/`、`jadx_out/`。
- 先记录原文件 `size` + `sha256`，报告完成后**复核一次哈希**，证明未被改动。
- 报告分五册 + 总览：`01_basic_info.md`、`02_code_structure.md`、`03_detection_logic.md`、
  `04_data_security.md`、`05_native_layer.md`、`summary.md`。
- **每条结论必须带证据**：`文件路径 + 类名/方法名 + 行号`。信息缺失明确写"未发现"+原因，禁止推测填充。

## 1. 环境搭建（本机通常既无 Java 也无 readelf/objdump）

### Java
`winget install EclipseAdoptium.Temurin.21.JDK` 常失败（"No applicable installer found"）。直接下 zip：

```bash
curl -sL -o _tools/jdk21.zip \
  "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse"
python -c "import zipfile; zipfile.ZipFile('_tools/jdk21.zip').extractall('_tools/jdk')"
export PATH="/d/<abs>/_tools/jdk/jdk-<ip>+1/bin:$PATH"   # 必须是 /d/... 形式，不能用 D:\\ 形式赋 PATH
java -version
```

### 反编译工具

```bash
# 查最新版
curl -sL "https://api.github.com/repos/iBotPeaches/Apktool/releases/latest" | python -c "..."
curl -sL "https://api.github.com/repos/skylot/jadx/releases/latest"        | python -c "..."

curl -sL -o _tools/apktool_<ver>.jar "<apktool jar url>"

# GitHub release 经常 HTTP=000 中断，必须断点续传 + 循环重试
for i in 1 2 3 4 5; do
  curl -sL -C - --retry 2 --retry-all-errors -m 240 -o _tools/jadx.zip "<jadx zip url>"
  s=$(stat -c%s _tools/jadx.zip 2>/dev/null || echo 0); [ "$s" -gt 38000000 ] && break
done
python -c "import zipfile; zipfile.ZipFile('_tools/jadx.zip').extractall('_tools/jadx')"
```

> 若 GitHub 持续不通，maven 中央 / `https://maven.aliyun.com/repository/public/...` 通常稳定（cfr、vineflower 都有）。
> 但 dex→java 仍需 jadx，不要轻易降级方案。

### 反编译执行

```bash
java -jar _tools/apktool_<ver>.jar d -f -o analysis/apktool_out <target.apk>
_tools/jadx/bin/jadx -d analysis/jadx_out --no-res -j 8 --show-bad-code <target.apk>
```

- jadx **没有 `--package-filter`**（1.5.x），用 `--include/--exclude` 或直接全量跑（4k 类约 30 秒）。
- jadx 报 `finished with errors, count: N` 属正常（Kotlin 协程状态机类）。

### 清单解析（无需 aapt）
`python -m pip install pyaxmlparser` →
```python
from pyaxmlparser import APK
a = APK(path)
a.package, a.version_name, a.version_code
a.get_min_sdk_version(), a.get_target_sdk_version()
a.get_permissions(), a.get_activities(), a.get_services(), a.get_receivers(), a.get_providers()
a.get_attribute_value('application', 'name' / 'allowBackup' / 'usesCleartextTraffic' / 'networkSecurityConfig')
```

## 2. 签名分析（无需 apksigner）

```bash
openssl pkcs7 -inform DER -in META-INF__CERT.RSA -print_certs -out v1cert.pem
openssl x509 -in v1cert.pem -outform DER -out v1cert.der
openssl x509 -in v1cert.pem -noout -fingerprint -sha256 -subject -issuer -dates -text
```
> `-print_certs -outform DER` 会出错，必须先出 PEM 再 `x509 -outform DER` 转换。

APK Signing Block 手工解析（判断 v1/v2/v3/v3.1）：
- 定位 EOCD `PK\x05\x06` → 取 `cd_off`；在 `[0, cd_off)` 反向找 magic `APK Sig Block 42`。
- 块起始 `start = cd_off - blk_size - 8`；ID-value 对循环：
  `length = u64(pos)`，`id = u32(pos+8)`，**value = data[pos+12 : pos+8+length]**，`pos += 8 + length`。
  （注意：length 只覆盖 id+value，不含自身 8 字节 —— 用 `pos+length` 会错位 8 字节。）
- 块 ID：`0x7109871a`=v2、`0xf05368c0`=v3、`0x1b93ad61`=v3.1、`0x42726577`=verity padding、
  `0x504b4453`=dependency-info、`0x6dff800d`=source stamp。
- v2 块内结构：`signers序列长度(u32)` → `signer长度(u32)` → `signed data(长度前缀)` →
  `minSdk(u32) maxSdk(u32)` → `signatures(长度前缀)` → `public key(长度前缀)`。
  证书在 signed data 尾部，可直接 `b.find(v1cert_der)` 比对 v1/v2 是否同一证书。

## 3. 原生层（本机无 readelf/objdump/nm）

用自写纯 Python 解析器（见本 skill 目录 `elfinfo.py`），能力：
ELF32/64 头、`e_machine` 映射、节表、`.dynamic` 的 NEEDED/SONAME/RUNPATH、
`.dynsym` 导出/导入符号（`st_shndx==0` 为导入）、`.rodata`/`.data`/`.data.rel.ro` 可打印串。

要点：
- 32 位 ELF 的 `e_entry`/`e_shoff` 是 `u32` 不是 `u64`，否则解出垃圾值。
- **混淆字符串多为逐串单字节 XOR**：对每条串遍历 256 个密钥，按"合法字符占比 + 常见字母频率"打分取最优。
  JNI 签名串常命中 `0x02`（如 `Nhctc-ncle-Qvpkle9` → `Ljava/lang/String;`）。
- 导出名形如 `tencent<数字>` / 单字母 = 符号名混淆；无 `Java_*` 导出但有 `JNI_OnLoad` ⇒ 动态注册。
- 用 `openssl rsa` 实测验证从 `.rodata` 抠出的 PEM/Base64 密钥，不要只靠肉眼。

## 4. 扫描脚本（放在 analysis/ 下复用）

- `scan_urls.py <dir>` —— 遍历 `*.smali`，只取 `const-string` 行，正则抽 `https?://...`，输出 URL + 文件:行号。
- `scan_secrets.py <dir>` —— 先收集本文件 `.field` 名，若含 key/secret/token/aes/rsa/iv/salt… 则把该文件所有 `const-string` 视为候选。噪声较大，需人工复核。
- `scan_zh.py <dir>` —— **smali 里的中文是 `\uXXXX` 转义**，必须先 `re.sub(r'\\u([0-9a-fA-F]{4})', ...)` 解码再匹配，否则 `grep` 搜中文零命中。中文日志串是最快定位业务逻辑的入口。

> 正则含 `\\`/`\]` 时**不要**写在 `bash -c "..."` 或 heredoc 里（会被 shell 吃掉反斜杠），一律落成 `.py` 文件再执行。

## 5. 阅读 jadx 输出的速查

R8 混淆后的短名（尤其是被塞进 SDK 包的自有代码）：

| 短名 | 含义 |
|---|---|
| `py.f/e/c/v` | Kotlin `Intrinsics.checkNotNullParameter` 等 |
| `l11.a` | `Unit` |
| `yl.b()` / `yl.c()` | `Dispatchers.Default` / `Dispatchers.IO` |
| `oa.d(scope, ctx, start, block, n, null)` | `BuildersKt.launch/async` |
| `rk.a(ms, cont)` | `delay(ms)` |
| `be.b(x)` / `ce.h(x,y)` / `d7.v(arr)` / `d7.w(arr)` / `d7.k(arr,v)` | `listOf` / `arrayOf` / `toList` / `toMutableList` / `contains` |
| `xv0.y(s,a,b,...)` / `yv0.J(s,sub,...)` | `String.replace` / `StringsKt.contains` |
| `z10` / `pw0` / `js` / `xs` | `SuspendLambda` / 2 参 lambda / `Function1` / `Function2` |
| `com.umeng.analytics.pro.f.aC/.M/.X` | 友盟常量类被当字符串池复用：`"session"` / `"provider"` / `"context"` |

遇到超长 `GuardService`/`Activity`，用脚本按缩进提取内部类方法 + 每个方法内的
`LogUtils.INSTANCE.s(...)` 字符串和委派调用，几行代码就能还原"混淆方法名 → 真实能力"映射表。

## 6. 交付 Word 版报告（pandoc 3.10 + python-docx）

标杆脚本：`D:\Claw\analysis\build_docx.py`、`_build\polish_docx.py`、`_build\insert_toc.py`。

```bash
pandoc report.md -f gfm -t docx --reference-doc=ref.docx --toc --toc-depth=3 -o out.docx
```

必知陷阱：

1. **gfm 不识别 `\newpage`**（会原样排成正文文字）。分页必须用 raw block：
   ````
   ```{=openxml}
   <w:p><w:r><w:br w:type="page"/></w:r></w:p>
   ```
   ````
2. **目录默认是空域**，且被包在 `w:sdt` 内 —— `Document.paragraphs` 遍历不到。
   要用 lxml 遍历 `document.element.body` 的子元素，`etree.tostring(child)` 中同时含
   `instrText` 与 `TOC` 才是锚点，再 `anchor.addnext(p)` 插静态目录段落；
   否则用户打开 Word 是空白目录，还要手动 F9 更新域。
3. **中文字体必须写 `w:rFonts/@w:eastAsia`**，python-docx 的 `style.font.name` 只设 ascii/hAnsi。
   推荐：正文等线 10.5pt、标题微软雅黑、代码 Consolas(+eastAsia 等线) 8.5pt + 底纹 F2F4F7、
   表内 8.5pt（宽表否则折行失控）、页脚 `PAGE`/`NUMPAGES` 域。
4. reference doc 若未预定义 `Source Code` / `VerbatimStringTok`，pandoc 会自建默认字体；
   更简单是转换后用 python-docx 回填这两个样式的 `rFonts` + 底纹。
5. `lang: zh-CN` 会刷 "The term Table has no translation defined" 警告，无表题时无害。
6. 合并多个 md 时，先把 `[x](x.md)` 相对链接 `re.sub` 成加粗文本（Word 里无意义）。

## 7. 常见高价值检查项

1. 是否真含 ArkTS/Harmony：找 `.abc`、`config.json`/`module.json5`、`ohos.app.Ability`。
   多数"xxx_harmony.apk"只是 Gradle flavor + 反射探测 `ohos.system.Parameters`。
2. 业务代码是否被塞进第三方 SDK 包名（反分析）：`grep -rl "<自有包>" jadx_out/sources/<sdk包> | wc -l`。
3. release 包是否残留测试环境域名：搜 `test-`、`10.x.x.x`、`localhost`、`:8080`。
4. `network_security_config.xml` / `usesCleartextTraffic` / https→http 降级 / 证书固定缺失。
5. OkHttp `HttpLoggingInterceptor` 级别是否为 `BODY`。
6. 对象存储直传路径、SharedPreferences 名与键、secret 是否硬编码。
7. 原生库里的 Base64 PEM（搜 `MII`、`MFww`、`MIGf`）。
8. 声明了但未实际使用的危险权限（声明 ≠ 调用，报告中要区分）。
