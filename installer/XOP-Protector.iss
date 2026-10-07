; XopProtector — Inno Setup 6 script
; Build: ISCC installer\XOP-Protector.iss
; Or:    powershell -File scripts\build-installer.ps1
;
; Requires: dist\XopProtector\ from scripts\release-desktop.ps1

#define MyAppName "XopProtector"
#define MyAppVersion "0.7.2"
#define MyAppPublisher "XOP"
#define MyAppExeName "XopProtector.exe"
#define MyAppId "{{A7C3E91B-4D2F-4E8A-9B1C-6F0D8E2A5B74}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=
OutputDir=..\dist
OutputBaseFilename=XopProtector-Setup-{#MyAppVersion}
SetupIconFile=..\desktop\Protector.Desktop\Assets\app.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=XopProtector Setup
VersionInfoProductName={#MyAppName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "chinesesimplified"; MessagesFile: "Languages\ChineseSimplified.isl"

[CustomMessages]
english.CreateDesktopIcon=Create a desktop shortcut
english.AdditionalIcons=Additional icons:
english.UninstallApp=Uninstall {#MyAppName}
english.LaunchApp=Launch {#MyAppName}
chinesesimplified.CreateDesktopIcon=创建桌面快捷方式
chinesesimplified.AdditionalIcons=附加图标:
chinesesimplified.UninstallApp=卸载 {#MyAppName}
chinesesimplified.LaunchApp=立即运行 {#MyAppName}

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce

[Files]
; Full self-contained layout (exe + engine\runtime + jar + shell-files)
Source: "..\dist\XopProtector\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{group}\{cm:UninstallApp}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchApp}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Leave %AppData%\XopProtector (settings/history) intact on uninstall
; (legacy %AppData%\XOP Protector / AppShield is migrated on first launch)
Type: filesandordirs; Name: "{app}\engine\runtime\*.tmp"
