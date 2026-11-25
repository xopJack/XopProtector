# XopProtector（XOP 加固平台）

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[English](README.en.md)

Android APK 加固 monorepo：构建期打包引擎（JVM CLI + Windows 桌面端）与设备端原生壳
（`libprotector.so`），提供 DEX 加密、双 VMP、SO 保护与 RASP。

> **免责声明：** 加固只能提高逆向成本，**不能**保证应用不可破解。请仅用于保护您有权分发的软件，
> 禁止用于隐藏恶意软件。

**安全联系邮箱：** `xopJack@163.com` — 详见 [SECURITY.md](SECURITY.md)。  
快速解决问题可加V:<span style="color:#000000">wnchjy168</span>

## 快速开始

### 先试用 Windows 桌面端（推荐）

若不打算改源码，可直接从 GitHub **[Releases](https://github.com/xopJack/XopProtector/releases)** 下载最新的 Windows 包（如 `XopProtector-*-win-x64.zip` 或 Setup 安装包）：

1. 下载，解压后运行 `XopProtector.exe`

桌面端已自带加固引擎；无需自行配置 Android SDK / NDK / .NET。

需要从源码编译、改功能或参与贡献时，再按下面步骤操作。

### 0）配置 Android SDK（必做）

打开仓库根目录的 `local.properties`，把 `sdk.dir` 改成**你本机** Android SDK 路径后再编译：

```properties
# Windows 示例（反斜杠需转义）
sdk.dir=D\:\\Android\\Sdk
```

也可不改该文件，改用环境变量 `ANDROID_HOME` / `ANDROID_SDK_ROOT`。

### 环境要求

| 工具 | 用途 |
|------|------|
| JDK 17+ | Packer / Gradle |
| Android SDK + NDK | `:native`、`:demo`、`exportShellFiles` |
| .NET SDK 7+（可选） | Windows 桌面端 |

请设置 `ANDROID_HOME` 或 `ANDROID_SDK_ROOT`（或按上面写好 `local.properties`）。Windows 下推荐使用 `gradlew.bat`。

### 1）编译 packer 与壳文件

```bat
gradlew.bat :packer:jar
gradlew.bat exportShellFiles
```

壳产物输出到 `executable/shell-files/`（已被 gitignore，需本地生成）。

### 2）加固 demo APK

```bat
gradlew.bat :demo:assembleRelease
gradlew.bat protectDemo
```

或对任意 APK 调用 CLI：

```bat
java -jar packer\build\libs\protector-packer-*.jar app.apk -o out.apk ^
  --shell-dir executable\shell-files
```

### 3）Windows 桌面端（可选）

```bat
cd desktop
dotnet run --project Protector.Desktop
```

生成便携目录 / 安装包：

```bat
powershell -ExecutionPolicy Bypass -File scripts\release-desktop.ps1
```

更多说明见英文 README 的 [Windows desktop](README.en.md#windows-desktop-xoprotector) 与 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 模块

| 模块 | 说明 |
|------|------|
| `:native` | C++ 运行时（hook / 还原 / PVM2 解释）+ Java 壳 |
| `:demo` | 示例应用 + `libdemo_biz.so`（SO 保护冒烟） |
| `:packer` | JVM 打包库与 CLI jar（非 Android AAR） |
| `desktop/` | Windows WPF 界面，子进程调用 packer |

| 层级 | 运行位置 | 作用 |
|------|----------|------|
| Packer / Desktop | Windows / CI | 发布前加固 APK |
| Native shell | Android 设备 | 解密 / 还原 / 解释执行 / RASP |

## 能力概览

| 里程碑 | 能力 |
|--------|------|
| M1 | PDX1 DEX 加密、明文窗口收缩、可配置 RASP |
| M2 | SO 自守护、Frida/Hook 扫描、威胁上报 |
| M3 | PVM1 方法打包、业务 SO `.text` RC4（默认开） |
| PVM2 | 真 VMP（morph + 多 ISA + 浮点/monitor 等） |
| Perf | 冷启动解密管线、预修补、SO 异步解密等 |

**VMP 含义：**

- `--vmp-prefix` → **PVM1**（解码后写回 Dalvik，不是解释器）
- `--true-vmp-prefix` → **PVM2**（JNI 跳板 + 原生解释，不写回 DEX）

默认策略偏「加密优先」：全量 DEX 加密，不全包抽空；支付 / 行业可自动 True-VMP。
详见 `doc/industry-profile.md`、`doc/auto-true-vmp-contract.md`。

## 常用 CLI

完整参数列表见 [README.en.md — Packer options](README.en.md#packer-options)。常用示例：

```bat
java -jar packer\build\libs\protector-packer-*.jar app.apk -o out.apk ^
  --shell-dir executable\shell-files ^
  --profile balanced ^
  --protect-so
```

SO 冷启动解密时机（默认 eager）：`--so-decrypt-mode eager|lazy`。
lazy：跳过全量 materialize；preload 只 pin 已有 `so_plain`；其余 dlopen 按需解密；
后台补齐剩余 keyed 并写 `so_plain_ready`，二次启动走 warm reuse。

行业 / 工具类应用可试：

```bat
  --profile industry
```

## 桌面端

- 语言：英文（默认资源）/ 简体中文；跟随系统，设置里可改（需重启）
- 主题：深色（默认）/ 浅色
- 配置目录：`%AppData%\XopProtector\`（旧版 `XOP Protector` / `AppShield` 会在首次启动迁移）

发版模板：[.github/RELEASE_TEMPLATE.md](.github/RELEASE_TEMPLATE.md)

## 许可证与贡献

- 许可证：[Apache License 2.0](LICENSE) · [NOTICE](NOTICE)
- 贡献：[CONTRIBUTING.md](CONTRIBUTING.md)
- 安全漏洞：**勿公开提 Issue**，走 [SECURITY.md](SECURITY.md) 或邮件 `xopJack@163.com`

## 文档索引

- 英文完整文档：[README.en.md](README.en.md)
- 变更记录：[CHANGELOG.md](CHANGELOG.md)
- 设计文档：`doc/`（PVM2、assets、渠道、NetGuard、LLVM 混淆等）
