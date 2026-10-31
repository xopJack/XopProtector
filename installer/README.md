# XopProtector — Windows installer

Official Inno Setup packaging for **XopProtector** (desktop client).

## Artifacts

| Item | Path |
|------|------|
| Script | `XOP-Protector.iss` |
| Simplified Chinese UI | `Languages\ChineseSimplified.isl` (vendored) |
| Output | `../dist/XopProtector-Setup-<version>.exe` |

## Prerequisites

1. [Inno Setup 6](https://jrsoftware.org/isdl.php)
2. Assembled portable app at `../dist/XopProtector/` (from `scripts\release-desktop.ps1`)

## Build

From the repository root:

```bat
powershell -ExecutionPolicy Bypass -File scripts\release-desktop.ps1
```

Portable folder only, then installer:

```bat
powershell -ExecutionPolicy Bypass -File scripts\release-desktop.ps1 -SkipInstaller
powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1
```

Or open `XOP-Protector.iss` in the Inno Setup Compiler and choose **Build**.

## Installer behavior

- Wizard languages: **English** and **Simplified Chinese**
- Default directory: `C:\Program Files\XopProtector\` (first install); upgrades reuse the previous folder (`DisableDirPage=auto`)
- In-place upgrade: closes a running UI / bundled engine Java; main binary is `XopProtectorApp.exe` (avoids locked legacy `XopProtector.exe`); Start Menu / desktop shortcuts point at the App exe
- Desktop shortcut checked by default
- Start Menu entry and Add/Remove Programs uninstaller
- Bundled `engine\` (optional jlink JRE + packer + shell); end users do not need a system JDK when jlink was used
