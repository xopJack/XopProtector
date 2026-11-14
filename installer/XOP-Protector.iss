; XopProtector — Inno Setup 6 script
; Build: ISCC installer\XOP-Protector.iss
; Or:    powershell -File scripts\build-installer.ps1
;
; Requires: dist\XopProtector\ from scripts\release-desktop.ps1
;
; Upgrade note: never require an in-place MoveFile replace of a possibly
; delete-pending or AV-locked "XopProtector.exe". The real apphost is installed
; as XopProtectorApp.exe; shortcuts launch that. Legacy XopProtector.exe is
; best-effort synced afterward (restartreplace if still locked).

#define MyAppName "XopProtector"
#define MyAppVersion "0.8.1"
#define MyAppPublisher "XOP"
#define MyAppExeName "XopProtectorApp.exe"
#define MyAppLegacyExeName "XopProtector.exe"
#define MyAppId "{{A7C3E91B-4D2F-4E8A-9B1C-6F0D8E2A5B74}"
; Must match desktop App.xaml.cs named mutex (session + Global).
#define MyAppMutex "XopProtector.SingleInstance.Mutex"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
DisableDirPage=auto
UsePreviousAppDir=yes
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
AppMutex={#MyAppMutex},Global\{#MyAppMutex}
CloseApplications=force
CloseApplicationsFilter=*.*
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "chinesesimplified"; MessagesFile: "Languages\ChineseSimplified.isl"

[CustomMessages]
english.CreateDesktopIcon=Create a desktop shortcut
english.AdditionalIcons=Additional icons:
english.UninstallApp=Uninstall {#MyAppName}
english.LaunchApp=Launch {#MyAppName}
english.ClosingApp=Closing {#MyAppName} so files can be updated…
chinesesimplified.CreateDesktopIcon=创建桌面快捷方式
chinesesimplified.AdditionalIcons=附加图标:
chinesesimplified.UninstallApp=卸载 {#MyAppName}
chinesesimplified.LaunchApp=立即运行 {#MyAppName}
chinesesimplified.ClosingApp=正在关闭 {#MyAppName} 以便更新文件…

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce

[InstallDelete]
Type: files; Name: "{app}\is-*.tmp"
Type: files; Name: "{app}\*.upgrade-old"

[Files]
; Primary apphost under a name that older installs never locked as XopProtector.exe.
; Do NOT also install legacy XopProtector.exe here — MoveFile error 5 on that name
; aborts Setup even with restartreplace when the failure is ACCESS_DENIED.
Source: "..\dist\XopProtector\XopProtector.exe"; DestDir: "{app}"; DestName: "{#MyAppExeName}"; Flags: ignoreversion
; Remainder of the published tree (exclude apphost — installed above).
Source: "..\dist\XopProtector\*"; Excludes: "XopProtector.exe"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{group}\{cm:UninstallApp}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchApp}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\engine\runtime\*.tmp"
Type: files; Name: "{app}\is-*.tmp"
Type: files; Name: "{app}\*.upgrade-old"

[Code]
procedure TaskKillImage(const ImageName: String);
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'),
    '/F /T /IM ' + ImageName, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure TaskKillEngineJava;
var
  ResultCode: Integer;
  Cmd: String;
begin
  Cmd :=
    'Get-CimInstance Win32_Process -Filter "Name=''java.exe''" | ' +
    'Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -like ''*\XopProtector\engine\*'') } | ' +
    'ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }';
  Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -ExecutionPolicy Bypass -Command "' + Cmd + '"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure CleanupStaleSetupTemps;
var
  AppDir: String;
  FindRec: TFindRec;
begin
  AppDir := ExpandConstant('{app}');
  if (AppDir = '') or not DirExists(AppDir) then
    Exit;
  if FindFirst(AppDir + '\is-*.tmp', FindRec) then
  try
    repeat
      DeleteFile(AppDir + '\' + FindRec.Name);
    until not FindNext(FindRec);
  finally
    FindClose(FindRec);
  end;
end;

procedure TrySyncLegacyExe;
var
  AppDir, Src, Dst: String;
begin
  (* Best-effort: copy App exe to legacy name for old Start Menu pins. Ignore failures. *)
  AppDir := ExpandConstant('{app}');
  Src := AppDir + '\{#MyAppExeName}';
  Dst := AppDir + '\{#MyAppLegacyExeName}';
  if not FileExists(Src) then
    Exit;
  DeleteFile(Dst);
  if not FileCopy(Src, Dst, False) then
    Log('TrySyncLegacyExe: could not update legacy XopProtector.exe (ignored)');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  NeedsRestart := False;
  Log('PrepareToInstall: close running app; install as XopProtectorApp.exe');
  WizardForm.StatusLabel.Caption := CustomMessage('ClosingApp');
  TaskKillImage('{#MyAppLegacyExeName}');
  TaskKillImage('{#MyAppExeName}');
  TaskKillEngineJava;
  Sleep(1500);
  CleanupStaleSetupTemps;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    TrySyncLegacyExe;
end;
