# android-apk-reverse-analysis

Windows 上从零搭建 Android APK 静态逆向分析环境（无 Java / 无 binutils）并产出带证据链的五分册分析报告。用于逆向 APK、提取硬编码域名密钥、还原 MDM 或恶意行为逻辑、分析 .so 原生层，或对 APK 做只读合规审计。

## Install

```bash
git clone https://github.com/longhai-lanxin/android-apk-reverse-analysis.git ~/.workbuddy/skills/android-apk-reverse-analysis
```

Or copy the whole folder into your skills directory.

## Contents

```
android-apk-reverse-analysis/
  SKILL.md
  elfinfo.py
```

## Usage

See [`SKILL.md`](SKILL.md) — that file is the entry point the agent reads.

## License

MIT
