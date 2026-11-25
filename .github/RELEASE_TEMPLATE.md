<!--
  Copy this body into the GitHub "Release" description when tagging.
  Replace placeholders: VERSION, DATE, and attach artifacts as needed.
-->

## XopProtector v{{VERSION}}

**Date:** {{YYYY-MM-DD}}

Apache-2.0 Android APK protector (packer CLI + native shell + Windows desktop).

### Highlights

- …
- …

### Artifacts (optional)

| File | Notes |
|------|--------|
| `XopProtector-Setup-{{VERSION}}.exe` | Windows installer (Inno) |
| `XopProtector-{{VERSION}}-win-x64.zip` | Portable folder (`dist/XopProtector`) |
| `protector-packer-{{VERSION}}.jar` | CLI packer only (needs JDK + shell-files) |

> Do **not** attach customer APKs, keystores, or internal logs.

### Build from source

```bat
gradlew.bat :packer:jar
gradlew.bat exportShellFiles
powershell -ExecutionPolicy Bypass -File scripts\release-desktop.ps1 -SkipInstaller
```

See [README.md](../README.md#快速开始) / [README.en.md](../README.en.md#quick-start).

### Compatibility

| Item | Support |
|------|---------|
| Host | Windows 10+ (desktop); JDK 17+ (packer) |
| Device ABI | `armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64` |
| minSdk | 24 |

### Security

Report vulnerabilities privately — see [SECURITY.md](../SECURITY.md).
Do not file public issues for bypass PoCs.

### Checksums

```
SHA256  {{hash}}  XopProtector-Setup-{{VERSION}}.exe
SHA256  {{hash}}  XopProtector-{{VERSION}}-win-x64.zip
```

### Full changelog

See [CHANGELOG.md](../CHANGELOG.md).
