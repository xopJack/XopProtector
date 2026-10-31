# XopProtector

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[中文说明](README.zh-CN.md)

Monorepo for an Android APK protector: build-time packer (JVM + Windows desktop) and
on-device native shell (`libprotector.so`) with DEX encryption, dual VMP, SO protect, and RASP.

> **Disclaimer:** Protection raises the cost of reverse engineering; it does **not** make
> an app unbreakable. Use only to protect software you are authorized to distribute.
> Do not use this project to conceal malware.

**Security contact:** `xopJack@163.com` — see [SECURITY.md](SECURITY.md).

## Quick start

### Try the Windows desktop build first (recommended)

If you only want to use the tool, download the latest Windows package from
**[Releases](https://github.com/xopJack/XopProtector/releases)**
(e.g. `XopProtector-*-win-x64.zip` or the Setup installer):

1. Download, extract, then run `XopProtector.exe`

The desktop build ships with the packer engine; no Android SDK / NDK / .NET setup is required.

Build from source only if you need to modify the code or contribute — see below.

### 0) Configure Android SDK (required)

Edit `local.properties` at the repo root and set `sdk.dir` to **your** Android SDK path before building:

```properties
# Windows example (escape backslashes)
sdk.dir=D\:\\Android\\Sdk
```

You may skip editing the file and use `ANDROID_HOME` / `ANDROID_SDK_ROOT` instead.

### Prerequisites

| Tool | Purpose |
|------|---------|
| JDK 17+ | Packer jar / Gradle |
| Android SDK + NDK | `:native`, `:demo`, `exportShellFiles` |
| .NET SDK 7+ (optional) | Windows desktop UI |

Set `ANDROID_HOME` or `ANDROID_SDK_ROOT` (or edit `local.properties` as above). On Windows, prefer `gradlew.bat`.

### 1) Build packer + shell

```bat
gradlew.bat :packer:jar
gradlew.bat exportShellFiles
```

Shell files land under `executable/shell-files/` (gitignored; generated locally).

### 2) Protect the demo APK

```bat
gradlew.bat :demo:assembleRelease
gradlew.bat protectDemo
```

Or run the packer CLI against any APK:

```bat
java -jar packer\build\libs\protector-packer-*.jar app.apk -o out.apk ^
  --shell-dir executable\shell-files
```

### 3) Windows desktop (optional)

```bat
cd desktop
dotnet run --project Protector.Desktop
```

Portable release folder + optional installer:

```bat
powershell -ExecutionPolicy Bypass -File scripts\release-desktop.ps1
```

More detail: [Windows desktop](#windows-desktop-xoprotector) · [CONTRIBUTING.md](CONTRIBUTING.md)

## Modules
- `:native` — C++ runtime (hook/patch/PVM2 interpret) + thin Java shell (`ProxyApplication`)
- `:demo` — sample app + `libdemo_biz.so` for `--protect-so` smoke
- `:packer` — JVM packer library + CLI jar (build-time; **not** an Android AAR)
- `desktop/` — Windows WPF UI that runs the packer as a **subprocess**

| Layer | Runs on | Role |
|-------|---------|------|
| Packer / Desktop | Windows / CI (JVM + .NET) | Protect an APK before release |
| Native shell | Android device (inside protected APK) | Decrypt / restore / interpret / RASP |

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md) (`xopJack@163.com`).

## Capability summary
| Milestone | Capability |
|-----------|------------|
| M1 | PDX1 dexes.zip, plaintext-window shrink, configurable RASP |
| M2 | SO self-guard, Frida/Hook scans, threat reports |
| M3 | **PVM1 method packing** (`--vmp-prefix`), optional business SO `.text` RC4 (`--protect-so`) |
| PVM2 | **True VMP** (`--true-vmp-prefix`): morph + multi-ISA + float/double/monitor ISA (v4) + RASP gate + interpret cache |
| Perf P0 | Class-batch hollow restore + startup DEX RW hold (done) |
| Perf P1 | Parallel file prepatch before ART map (done) |
| Perf P2 | Cold-start decrypt→extract pipeline (no plaintext zip); warm skip code.bin re-copy; async SO decrypt |

> **Note on “VMP”:**
> - `--vmp-prefix` = **PVM1** virtualized packing (unpack → write Dalvik). Not an interpreter.
> - `--true-vmp-prefix` = **PVM2** true VMP (JNI trampoline + native interpret).

## Docs
- `doc/pvm2-mvp.md` / `doc/pvm2-phase2.md` / `doc/pvm2-phase3.md` / `doc/pvm2-phase4.md`
- `doc/industry-profile.md` — `--profile industry` (tools / industrial apps)
- `CHANGELOG.md`
- [README.zh-CN.md](README.zh-CN.md) — Chinese overview + quick start
- [.github/RELEASE_TEMPLATE.md](.github/RELEASE_TEMPLATE.md) — GitHub Release body template

## Library API (packer)
Programmatic entry (same code as the CLI):

```java
ProtectOptions opts = new ProtectOptions();
opts.inputApk = new File("app.apk");
opts.outputApk = new File("out.apk");
opts.shellDir = new File("executable/shell-files");
ProtectResult result = new Protector().protect(opts);
```

CLI adds `--json-progress` for NDJSON phase/log/done/error events (used by the desktop UI).

## Windows desktop (XopProtector)

Windows WPF client that drives the packer as a local subprocess. End users run a self-contained
`XopProtector.exe` (or the Setup installer); no system .NET runtime or JDK is required when the
release is built with the bundled jlink JRE.

UI languages: **English** (default resource) and **Simplified Chinese**. Follows the OS language unless
overridden under **Settings → Language** (restart required). Themes: **Dark** (default) and **Light**.
Preferences are stored in `%AppData%\XopProtector\settings.json` (legacy `%AppData%\XOP Protector` / `AppShield` is migrated on first launch).

### Prerequisites (build from source)

| Dependency | Purpose |
|------------|---------|
| [.NET SDK 7+](https://dotnet.microsoft.com/download) | Build / publish the WPF app |
| JDK 17+ (`JAVA_HOME`, with `jlink`) | Packer jar + optional bundled runtime |
| Android NDK (via Gradle) | Native shell (`exportShellFiles`) |
| [Inno Setup 6](https://jrsoftware.org/isdl.php) (optional) | Windows Setup `.exe` installer |

### Development

```bat
gradlew.bat :packer:jar
gradlew.bat exportShellFiles
cd desktop
dotnet run --project Protector.Desktop
```

Release configuration:

```bat
cd desktop
dotnet run --project Protector.Desktop -c Release
```

At runtime the UI resolves the packer engine in this order:

1. `PROTECTOR_ENGINE_HOME`
2. `engine\` next to `XopProtector.exe`
3. Repository `packer\build\libs` + `executable\shell-files` (requires `java` on `PATH`)

### Build portable `.exe` (recommended)

Produces a self-contained folder under `dist\XopProtector\` including `XopProtector.exe` and the
local packer engine. From the repository root:

```bat
powershell -ExecutionPolicy Bypass -File scripts\release-desktop.ps1
```

This script:

1. Builds `protector-packer-*.jar`
2. Exports shell files (`exportShellFiles`)
3. Publishes the WPF app (`dotnet publish`, `win-x64`, self-contained)
4. Assembles `dist\XopProtector\`
5. Bundles a minimal JRE via `jlink` into `engine\runtime\`
6. Builds the Inno Setup installer when ISCC is available

**Optional flags**

| Flag | Effect |
|------|--------|
| `-SkipNativeShell` | Reuse existing `executable\shell-files` |
| `-SkipJlink` | Do not bundle JRE (machine must have JDK at runtime) |
| `-SkipInstaller` | Skip Setup `.exe`; only emit the portable folder |

Example (portable folder only, no installer):

```bat
powershell -ExecutionPolicy Bypass -File scripts\release-desktop.ps1 -SkipInstaller
```

**Output layout**

```
dist/XopProtector/
  XopProtector.exe           # main application
  *.dll / *.json / …         # .NET self-contained runtime
  engine/
    runtime/                 # jlink JRE (omit if -SkipJlink)
    protector-packer.jar
    shell-files/
dist/XopProtector-Setup-<ver>.exe   # Windows installer (if Inno Setup is installed)
```

Ship either the whole `dist\XopProtector\` folder (portable) or the Setup executable.

### Build Windows installer (Setup `.exe`)

Prerequisite: [Inno Setup 6](https://jrsoftware.org/isdl.php) and an assembled `dist\XopProtector\`.

```bat
powershell -ExecutionPolicy Bypass -File scripts\release-desktop.ps1
```

Or build the installer alone after a prior release:

```bat
powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1
```

Alternatively open `installer\XOP-Protector.iss` in the Inno Setup Compiler and choose **Build**.

Installer defaults:

- Wizard languages: English and Simplified Chinese
- Install directory: `C:\Program Files\XopProtector\`
- Desktop shortcut enabled by default
- Start Menu entry and uninstaller
- Bundled `engine\` (JRE + packer + shell); end users do not need a system JDK

See also `installer\README.md`.

## `--true-vmp-prefix` (Phase 4)
- Phase 3 ISA + parsed-image cache; demo covers invoke/field/array/catch + `soProbe` → protected SO.

## `--protect-so` / `--no-protect-so` / `--protect-so-mode`
- **Default ON** (0.6.8+): RC4-encrypt safe business `lib/*.so` `.text`.
- Pass `--no-protect-so` to disable. `--protect-so` remains as an explicit enable.
- **`--protect-so-mode safe`** (default, 0.6.12+): industry/reloc skips **plus** a
  size budget (default 12MB extra / skip files &gt;8MB unpacked) so large engines
  do not inflate the APK by tens of MB.
- **`--protect-so-mode aggressive`**: only shell + text-reloc skips; still applies
  soft size-budget truncate with WARN.
- **`--protect-so-mode max`**: industry skips, **no** size budget (encrypt every eligible SO).
- `--protect-so-budget-mb` / `--protect-so-max-file-mb` / `--protect-so-abi` override defaults.
- **`--so-decrypt-mode eager|lazy`** (default **eager**): cold-start decrypt timing.
  Eager = full `so_plain` materialize + preload all keyed. Lazy = skip full
  materialize; preload only mirrors already in `so_plain`; decrypt on first
  `dlopen` (keyed `DT_NEEDED` closure); background-fill remaining keyed SOs and
  write `so_plain_ready` for the next warm start.
  Missing `so_decrypt_mode` in old `config.json` → eager.
- Prefer `System.loadLibrary` **after** `Application` / shell bootstrap.
- Early `dlopen` hooks are installed in the SO constructor; loads before `sokeys.bin` are queued and decrypted when keys arrive.
- Packer **skips** SOs whose dynamic relocs patch `.text` (would break after encrypt).
- Runtime uses ELF `load_bias = map_start - first_PT_LOAD.p_vaddr` for decrypt.
- Demo: `libdemo_biz.so` (`Business.nativeAddRaw` / `soProbe`).
- After pack: `size_report` on stdout and `<outDir>/Log/<out>-size_report.json`.

## Build / release
```bat
gradlew.bat protectDemo
powershell -File scripts\release-demo.ps1 -Serial <deviceSerial>
```

```bat
java -jar packer/build/libs/protector-packer-*.jar app.apk -o out.apk ^
  --shell-dir executable/shell-files ^
  --true-vmp-prefix Lcom/yqsh/protectordemo/Business; ^
  --protect-so
```

## Packer options
```
--profile <name>           hollow/VMP: balanced (default) | industry | aggressive | perf | max
--hollow-prefix <desc>     allowlist type prefix (repeatable; disables auto include)
--vmp-prefix <desc>        PVM1-pack methods under type prefix (repeatable)
--true-vmp-prefix <desc>   PVM2 true VMP under type prefix (repeatable)
--protect-so               RC4-encrypt safe business lib/*.so .text (default ON)
--no-protect-so            disable business SO .text encryption
--encrypt-assets           PAS1+AES-GCM encrypt assets/** → protector/aenc (default OFF)
--no-encrypt-assets        disable assets encryption
--enable-res-protect       shorten res/ paths + rewrite resources.arsc (default OFF)
--detect-proxy             enable NetGuard proxy/VPN heuristics (default OFF)
--pin-certs <file>         leaf cert SHA-256 pins for NetGuard TrustManager wrapper
--channel <name>           stamp Walle-compatible channel after sign (needs --keystore)
--channels <file>          batch stamp → <out>-<channel>.apk (needs --keystore)
--protect-so-mode <m>      safe (default) | aggressive | max
--protect-so-budget-mb <n> SO protect size budget MB (default 12; max ignores)
--protect-so-max-file-mb <n> skip SO if unpacked >N MB (default 8; max ignores)
--protect-so-abi <abi>|all only select basenames present under ABI (default all)
--so-decrypt-mode <m>      eager (default)=full SO materialize+preload at cold start;
                           lazy=on-demand + background fill → so_plain_ready warm reuse
--json-progress            NDJSON progress on stdout (desktop UI)
--risk-flags / --rasp-action / --report-enabled
```

### Hollow policy (production default)
Without `--hollow-prefix`, packer uses a **unified** auto policy (same for every APK):
- **balanced** / **perf** (default): hollow only the manifest `applicationId` package (skip `*Activity`/…); keeps most code AOT-friendly
- **aggressive**: skip major SDKs/components; hollow remaining business types
- **max**: near legacy hollow-all (still skips `Landroid/` + `Landroidx/`)

Pass `--hollow-prefix` to restrict to an allowlist (still skips framework + components under balanced/perf).
Never hard-codes a single customer package name.

## Assets
- `code.bin` v4, `dexes.zip` (PDX1), `config.json`, optional `sokeys.bin` / `assets.map` / `netguard.json`
- Optional `--encrypt-assets`: `protector/aenc/*` (PAS1); read via `ProtectorAssets`
- Optional `--enable-res-protect`: shorten `res/` paths (see `doc/res-protect.md`)
- Optional `--detect-proxy` / `--pin-certs`: `NetGuard` (see `doc/netguard.md`)
- Optional `--channel` / `--channels`: signing-block channel (see `doc/channel.md`)
- Phase 7 native CFF/BCF: source-level default; LLVM via `-Pprotector.llvmObf` (see `doc/llvm-obfuscation.md`)
- `libprotector.so` keys: INSN / DEX / ASSETS / UNKNOWN / HMAC
