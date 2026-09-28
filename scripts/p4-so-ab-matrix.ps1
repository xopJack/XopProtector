# P4 A/B matrix for business-SO SIGILL diagnosis (pack + optional device smoke).
#
# Variants:
#   A  --no-protect-so
#   B  --protect-so --protect-so-mode safe  --so-decrypt-mode eager  (+ --so-diag)
#   C  --protect-so --protect-so-mode safe  --so-decrypt-mode lazy   (+ --so-diag)
#   D  --protect-so --protect-so-mode max   --so-decrypt-mode eager  (+ --so-diag)
#   E  --protect-so --protect-so-mode max   --so-decrypt-mode lazy   (+ --so-diag)
#
# Examples:
#   .\scripts\p4-so-ab-matrix.ps1 -InputApk .\app.apk -PackageName com.torhang.microapp.v5
#   .\scripts\p4-so-ab-matrix.ps1 -UseDemo -InstallId B
#   .\scripts\p4-so-ab-matrix.ps1 -InputApk .\app.apk -PackOnly
#
param(
    [string]$InputApk = "",
    [switch]$UseDemo,
    [string]$PackageName = "",
    [string]$LaunchComponent = "",
    [string]$Serial = "",
    [string]$WatchSo = "libDJIProtobuf.so",
    [string]$OutDir = "",
    [string]$InstallId = "",
    [switch]$PackOnly,
    [int]$WarmSeconds = 8
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Resolve-PackerJar {
    $dir = Join-Path $Root "packer\build\libs"
    $jar = Get-ChildItem $dir -Filter "protector-packer*.jar" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($null -eq $jar) { throw "packer jar missing — run: gradlew.bat :packer:jar" }
    return $jar.FullName
}

function Resolve-ShellDir {
    $shell = Join-Path $Root "executable\shell-files"
    if (!(Test-Path (Join-Path $shell "lib"))) {
        Write-Host "==> exportShellFiles"
        & .\gradlew.bat exportShellFiles
        if ($LASTEXITCODE -ne 0) { throw "exportShellFiles failed" }
    }
    return $shell
}

function Resolve-DebugKeystore {
    $ks = Join-Path $env:USERPROFILE ".android\debug.keystore"
    if (!(Test-Path $ks)) { throw "debug keystore not found: $ks" }
    return $ks
}

function Resolve-Adb {
    foreach ($envName in @("ANDROID_HOME", "ANDROID_SDK_ROOT")) {
        $v = [Environment]::GetEnvironmentVariable($envName)
        if (![string]::IsNullOrWhiteSpace($v)) {
            $adb = Join-Path $v "platform-tools\adb.exe"
            if (Test-Path $adb) { return $adb }
        }
    }
    $localProps = Join-Path $Root "local.properties"
    if (Test-Path $localProps) {
        foreach ($line in Get-Content $localProps) {
            if ($line -match '^\s*sdk\.dir\s*=\s*(.+)\s*$') {
                $raw = $Matches[1].Trim()
                # Gradle uses C\:\\Users\\... or C:\\Users\\...
                $path = $raw -replace '\\\\', '\'
                $path = $path -replace '^([A-Za-z])\\:', '$1:'
                if (Test-Path $path) {
                    $adb = Join-Path $path "platform-tools\adb.exe"
                    if (Test-Path $adb) { return $adb }
                }
            }
        }
    }
    $cmd = Get-Command adb -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw "adb not found"
}

function Get-XopPackHits {
    param([string]$LogPath, [string]$SoName)
    if (!(Test-Path $LogPath)) { return @() }
    $pat = '\[XOP-PACK\].*' + [regex]::Escape($SoName)
    Select-String -Path $LogPath -Pattern $pat -ErrorAction SilentlyContinue |
        ForEach-Object { $_.Line.Trim() }
}

function Summarize-DiagJson {
    param([string]$DiagPath, [string]$SoName)
    if (!(Test-Path $DiagPath)) { return "diag=missing" }
    $text = Get-Content $DiagPath -Raw
    if ($text -notmatch [regex]::Escape($SoName)) {
        return "not in so_text_diag (SKIP or absent)"
    }
    $m = [regex]::Match(
        $text,
        '"name"\s*:\s*"' + [regex]::Escape($SoName) + '"[\s\S]{0,400}?"text_sha256"\s*:\s*"([0-9a-fA-F]*)"'
    )
    if ($m.Success) {
        $sha = $m.Groups[1].Value
        $short = if ($sha.Length -ge 16) { $sha.Substring(0, 16) + "..." } else { $sha }
        return ("ENCRYPT sha=" + $short)
    }
    return "ENCRYPT (in diag)"
}

if ($UseDemo) {
    Write-Host "==> gradlew :demo:assembleRelease exportShellFiles :packer:jar"
    & .\gradlew.bat :demo:assembleRelease exportShellFiles :packer:jar
    if ($LASTEXITCODE -ne 0) { throw "demo/shell/packer build failed" }
    $demoApk = Get-ChildItem (Join-Path $Root "demo\build\outputs\apk\release") -Filter "*.apk" |
        Select-Object -First 1
    if ($null -eq $demoApk) { throw "demo release apk not found" }
    $InputApk = $demoApk.FullName
    if ([string]::IsNullOrWhiteSpace($PackageName)) {
        $PackageName = "com.yqsh.protectordemo"
    }
    if ([string]::IsNullOrWhiteSpace($LaunchComponent)) {
        $LaunchComponent = "com.yqsh.protectordemo/.MainActivity"
    }
    if ($WatchSo -eq "libDJIProtobuf.so") {
        $WatchSo = "libdemo_biz.so"
    }
}

if ([string]::IsNullOrWhiteSpace($InputApk) -or !(Test-Path $InputApk)) {
    throw "Provide -InputApk path or -UseDemo. Customer APK with libDJIProtobuf.so required for crash A/B."
}

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutDir = Join-Path $Root ("executable\p4-matrix-" + $stamp)
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$packerJar = Resolve-PackerJar
$shellDir = Resolve-ShellDir
$ks = Resolve-DebugKeystore
$adb = $null
$adbArgs = @()
if (-not $PackOnly) {
    $adb = Resolve-Adb
    if ($Serial -ne "") { $adbArgs += @("-s", $Serial) }
}

$variants = @(
    @{ Id = "A"; Args = @("--no-protect-so") },
    @{ Id = "B"; Args = @("--protect-so", "--protect-so-mode", "safe", "--so-decrypt-mode", "eager", "--so-diag") },
    @{ Id = "C"; Args = @("--protect-so", "--protect-so-mode", "safe", "--so-decrypt-mode", "lazy", "--so-diag") },
    @{ Id = "D"; Args = @("--protect-so", "--protect-so-mode", "max", "--so-decrypt-mode", "eager", "--so-diag") },
    @{ Id = "E"; Args = @("--protect-so", "--protect-so-mode", "max", "--so-decrypt-mode", "lazy", "--so-diag") }
)

$baseName = [IO.Path]::GetFileNameWithoutExtension($InputApk)
$results = New-Object System.Collections.Generic.List[object]

Write-Host ("==> P4 pack matrix input=" + $InputApk)
Write-Host ("    watch_so=" + $WatchSo + " out=" + $OutDir)

foreach ($v in $variants) {
    $id = $v.Id
    $outApk = Join-Path $OutDir ($baseName + "-P4" + $id + ".apk")
    $packLog = Join-Path $OutDir ($baseName + "-P4" + $id + "-pack.log")
    Write-Host ""
    Write-Host ("==> Pack " + $id + " -> " + $outApk)

    $allArgs = @(
        "-jar", $packerJar,
        (Resolve-Path $InputApk).Path,
        "-o", $outApk,
        "--shell-dir", $shellDir,
        "--no-encrypt-assets",
        "--no-res-protect",
        "--keystore", $ks,
        "--alias", "androiddebugkey",
        "--storepass", "android",
        "--keypass", "android"
    ) + $v.Args

    & java @allArgs 2>&1 | Tee-Object -FilePath $packLog
    if ($LASTEXITCODE -ne 0) {
        Write-Warning ("Pack " + $id + " failed (exit " + $LASTEXITCODE + ")")
        $results.Add([pscustomobject]@{
            Id = $id
            PackOk = $false
            Apk = $outApk
            WatchDecision = "pack_failed"
            Diag = ""
            Runtime = "n/a"
            Crash = "n/a"
        }) | Out-Null
        continue
    }

    $diagBeside = $outApk -replace '\.apk$', '-so_text_diag.json'
    $sizeBeside = $outApk -replace '\.apk$', '-size_report.json'
    $packHits = @(Get-XopPackHits -LogPath $packLog -SoName $WatchSo)
    $decision = if ($packHits.Count -gt 0) { $packHits[-1] } else { ("no XOP-PACK line for " + $WatchSo) }
    $diagSum = Summarize-DiagJson -DiagPath $diagBeside -SoName $WatchSo

    $results.Add([pscustomobject]@{
        Id = $id
        PackOk = $true
        Apk = $outApk
        WatchDecision = $decision
        Diag = $diagSum
        SizeReport = $sizeBeside
        DiagJson = $diagBeside
        PackLog = $packLog
        Runtime = "pending"
        Crash = "pending"
    }) | Out-Null
}

function Invoke-DeviceSmoke {
    param(
        [string]$Id,
        [string]$ApkPath
    )
    if ([string]::IsNullOrWhiteSpace($PackageName)) {
        Write-Warning ("Skip device smoke " + $Id + " — set -PackageName")
        return @{ Runtime = "no_package"; Crash = "skipped" }
    }
    $runLog = Join-Path $OutDir ($baseName + "-P4" + $Id + "-logcat.txt")
    Write-Host ("==> Device smoke " + $Id + " install+launch " + $PackageName)
    & $adb @adbArgs install -r --no-incremental $ApkPath
    if ($LASTEXITCODE -ne 0) {
        return @{ Runtime = "install_failed"; Crash = "install_failed" }
    }
    & $adb @adbArgs shell setprop debug.protector.so_diag 1 | Out-Null
    & $adb @adbArgs logcat -c | Out-Null
    if (![string]::IsNullOrWhiteSpace($LaunchComponent)) {
        & $adb @adbArgs shell am start -n $LaunchComponent | Out-Null
    } else {
        & $adb @adbArgs shell monkey -p $PackageName -c android.intent.category.LAUNCHER 1 | Out-Null
    }
    Start-Sleep -Seconds $WarmSeconds
    & $adb @adbArgs logcat -d -s "protector:I" "protector:E" "AndroidRuntime:E" "libc:F" "DEBUG:I" |
        Out-File -FilePath $runLog -Encoding utf8

    $xopPat = '\[XOP-SO\].*' + [regex]::Escape($WatchSo)
    $fatalPat = '\[XOP-SO\] FATAL.*' + [regex]::Escape($WatchSo)
    $xop = @(Select-String -Path $runLog -Pattern $xopPat -ErrorAction SilentlyContinue)
    $fatal = @(Select-String -Path $runLog -Pattern $fatalPat -ErrorAction SilentlyContinue)
    $sigill = @(Select-String -Path $runLog -Pattern "SIGILL|Fatal signal 4|libDJIProtobuf|tombstone" -ErrorAction SilentlyContinue)

    $runtime = if ($xop.Count -gt 0) {
        (($xop | Select-Object -Last 3 | ForEach-Object { $_.Line.Trim() }) -join " ;; ")
    } else {
        ("no XOP-SO for " + $WatchSo)
    }
    $crash = if ($fatal.Count -gt 0) { "FATAL_gate" }
             elseif ($sigill.Count -gt 0) { "SIGILL_or_tombstone" }
             else { "no_crash_seen" }
    return @{ Runtime = $runtime; Crash = $crash; Log = $runLog }
}

if (-not $PackOnly) {
    $toInstall = @()
    if (![string]::IsNullOrWhiteSpace($InstallId)) {
        $toInstall = @($InstallId.ToUpperInvariant())
    } else {
        $toInstall = @("B", "D")
    }
    foreach ($id in $toInstall) {
        $row = $results | Where-Object { $_.Id -eq $id -and $_.PackOk } | Select-Object -First 1
        if ($null -eq $row) { continue }
        $smoke = Invoke-DeviceSmoke -Id $id -ApkPath $row.Apk
        $row.Runtime = $smoke.Runtime
        $row.Crash = $smoke.Crash
    }
}

$tablePath = Join-Path $OutDir "P4-RESULTS.md"
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# P4 SO A/B results") | Out-Null
$lines.Add("") | Out-Null
$lines.Add(("- Input: " + $InputApk)) | Out-Null
$lines.Add(("- Watch SO: " + $WatchSo)) | Out-Null
$lines.Add(("- Package: " + $PackageName)) | Out-Null
$lines.Add(("- Generated: " + (Get-Date -Format o))) | Out-Null
$lines.Add("") | Out-Null
$lines.Add("| ID | Pack | Watch decision / diag | Runtime | Crash |") | Out-Null
$lines.Add("|----|------|------------------------|---------|-------|") | Out-Null
foreach ($r in $results) {
    $pack = if ($r.PackOk) { "OK" } else { "FAIL" }
    $dec = [string]$r.WatchDecision
    if ($dec.Length -gt 100) { $dec = $dec.Substring(0, 97) + "..." }
    $dec = $dec -replace '\|', '/'
    $rt = [string]$r.Runtime
    if ($rt.Length -gt 100) { $rt = $rt.Substring(0, 97) + "..." }
    $rt = $rt -replace '\|', '/'
    $lines.Add(("| {0} | {1} | {2} / {3} | {4} | {5} |" -f $r.Id, $pack, $dec, $r.Diag, $rt, $r.Crash)) | Out-Null
}
$lines.Add("") | Out-Null
$lines.Add("## Decision tree") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("A crash -> unrelated to protect") | Out-Null
$lines.Add("A OK, B crash + text hash MISMATCH -> materialize/double-RC4/partial-write (P5)") | Out-Null
$lines.Add("A OK, B crash + text hash OK -> reloc/IFUNC/ISA (new phase)") | Out-Null
$lines.Add("A OK, B OK, C crash -> lazy timing / background fill") | Out-Null
$lines.Add("A/B OK, D/E crash -> max selected a risky SO / same bug on large libs") | Out-Null
$lines.Add("") | Out-Null
$lines.Add(("Artifacts under " + $OutDir)) | Out-Null
$lines | Set-Content -Path $tablePath -Encoding utf8

Write-Host ""
Write-Host ("==> Wrote " + $tablePath)
Get-Content $tablePath
Write-Host ""
Write-Host "Next (customer APK):"
Write-Host "  .\scripts\p4-so-ab-matrix.ps1 -InputApk C:\path\app.apk -PackageName com.torhang.microapp.v5 -WatchSo libDJIProtobuf.so -InstallId B"
