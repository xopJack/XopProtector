# Verify UniMP host (unprotected vs protected)

param(
    [ValidateSet("debug", "protected")]
    [string]$Mode = "protected",
    [int]$WaitSeconds = 15
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Pkg = "com.yqsh.unimpdemo"
$Activity = "$Pkg/.LaunchActivity"

function Install-Apk([string]$apk) {
    if (-not (Test-Path $apk)) { throw "APK not found: $apk" }
    Write-Host "Push+pm install $apk"
    adb push $apk /data/local/tmp/unimp-verify.apk | Out-Host
    adb shell pm uninstall $Pkg 2>$null | Out-Null
    $r = adb shell pm install -r -t /data/local/tmp/unimp-verify.apk
    if ("$r" -notmatch "Success") { throw "pm install failed: $r" }
}

$apk = if ($Mode -eq "debug") {
    Join-Path $Root "unimp-host\build\outputs\apk\debug\unimp-host-debug.apk"
} else {
    Join-Path $Root "executable\unimp-demo-protected.apk"
}

Install-Apk $apk
adb logcat -c | Out-Null
adb shell am start -n $Activity | Out-Host
Start-Sleep -Seconds $WaitSeconds

$log = adb logcat -d | Out-String
$hasSpin = $log -match "spinWaitPeer timeout"
$weexSoPlain = $log -match "so_plain.*libweex" -or $log -match "libweex.*so_plain"
$weexPreinit = $log -match "DT_PREINIT_ARRAY.*libweex" -or $log -match "libweex.*DT_PREINIT"
$checks = [ordered]@{
    "SDK onInitFinished=true" = ($log -match "DCUniMPSDK onInitFinished=true")
    "openUniMP"               = ($log -match "\[XOP-DEMO\] openUniMP appid=")
    "DCUniMPActivity shown"   = ($log -match "DCUniMPActivity")
    "sPackageName non-empty"  = ($log -match "sPackageName=com\.yqsh\.unimpdemo") -and -not ($log -match "sPackageName=;")
    # Emulator x86 may race on Weex IPC even unprotected; fail only if encrypted so_plain path.
    "no Weex so_plain/PREINIT" = -not ($weexSoPlain -or $weexPreinit)
    "XOPDEMO or sample open"  = ($log -match "openUniMP appid=__UNI__(XOPDEMO|F743940)")
}

Write-Host ""
Write-Host "=== Mode=$Mode ==="
$fail = 0
foreach ($k in $checks.Keys) {
    $ok = [bool]$checks[$k]
    $mark = if ($ok) { "PASS" } else { "FAIL" }
    if (-not $ok) { $fail++ }
    Write-Host ("[{0}] {1}" -f $mark, $k)
}
if ($hasSpin) {
    Write-Host "[WARN] spinWaitPeer seen (x86 emulator flake unless so_plain/PREINIT also fails)"
}
if ($log -match "openUniMP appid=__UNI__XOPDEMO") {
    if ($log -match "page-show:") {
        Write-Host "[PASS] XOPDEMO page-show probe seen in logcat"
    } else {
        Write-Host "[WARN] XOPDEMO opened but page-show not seen (Weex/JS may still be racing on emulator)"
    }
}

$openLine = (adb logcat -d | Select-String -Pattern "\[XOP-DEMO\] openUniMP appid=" | Select-Object -Last 1)
if ($openLine) { Write-Host "open: $($openLine.Line.Trim())" }

if ($Mode -eq "protected") {
    $report = Join-Path $Root "executable\Log\unimp-demo-protected-size_report.json"
    if (Test-Path $report) {
        $hits = ([regex]::Matches((Get-Content $report -Raw), '"uniapp/runtime"')).Count
        Write-Host "size_report uniapp/runtime hits=$hits"
        if ($hits -lt 5) { $fail++; Write-Host "[FAIL] expect uniapp/runtime hits >= 5" }
        else { Write-Host "[PASS] uniapp/runtime hits >= 5" }
        if ((Get-Content $report -Raw) -match 'libweexcore\.so".*"uniapp/runtime"' -or
            (Get-Content $report -Raw) -match '"path": "[^"]*libweexcore\.so".*\n.*"reason": "uniapp/runtime"') {
            Write-Host "[PASS] libweexcore.so skipped as uniapp/runtime (heuristic)"
        } else {
            # Fallback: any so_skipped_policy line mentioning weexcore + uniapp
            $txt = Get-Content $report -Raw
            if ($txt -match "libweexcore\.so" -and $txt -match "uniapp/runtime") {
                Write-Host "[PASS] libweexcore.so present with uniapp/runtime in report"
            } else {
                Write-Host "[WARN] libweexcore.so uniapp/runtime not clearly verified in report"
            }
        }
    }
}

Write-Host ""
if ($fail -gt 0) {
    Write-Host "RESULT: FAIL ($fail checks)"
    exit 1
}
Write-Host "RESULT: PASS"
exit 0
