@echo off
setlocal
cd /d "%~dp0\.."

echo === assemble :unimp-host:assembleRelease ===
call gradlew.bat :unimp-host:assembleRelease
if errorlevel 1 exit /b 1

echo === protectUnimpDemo ===
call gradlew.bat protectUnimpDemo
if errorlevel 1 exit /b 1

echo.
echo Protected APK: executable\unimp-demo-protected.apk
echo size_report:   executable\Log\unimp-demo-protected-size_report.json
echo.
echo Install (prefer pm; adb install-incremental may fail):
echo   adb push executable\unimp-demo-protected.apk /data/local/tmp/unimp.apk
echo   adb shell pm install -r -t /data/local/tmp/unimp.apk
echo Verify:
echo   powershell -File scripts\verify-unimp-demo.ps1 -Mode protected
echo Log filter:
echo   adb logcat ^| findstr /i "XOP-DEMO WeexCore spinWaitPeer UTSKeyIterable protector.SoDir"
endlocal

