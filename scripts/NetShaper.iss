; NetShaper GUI installer (Inno Setup 6)
; Build: powershell -File scripts\build-installer.ps1
; Compiles published dist\NetShaper-win-x64 into a single Setup.exe wizard.

#define MyAppName "NetShaper"
#ifndef MyAppVersion
  #define MyAppVersion "0.4.2"
#endif
#define MyAppPublisher "NetShaper contributors"
#define MyAppURL "https://github.com/ksanjeev284/NetShaper"
#define MyAppExeName "NetShaper.exe"
#define PublishDir "..\dist\NetShaper-win-x64"

[Setup]
AppId={{A7B2C3D4-E5F6-7890-ABCD-NETSHAPER0001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
InfoBeforeFile=installer-welcome.txt
InfoAfterFile=installer-finish.txt
OutputDir=..\dist
OutputBaseFilename=NetShaper-Setup-{#MyAppVersion}
SetupIconFile=..\assets\NetShaper.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardSizePercent=120
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
DisableWelcomePage=no
AllowNoIcons=yes
CloseApplications=yes
RestartApplications=no
ChangesEnvironment=yes
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Setup - free Windows bandwidth limiter
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
VersionInfoCopyright=Copyright (c) 2026 {#MyAppPublisher}
AppMutex=NetShaper.Gui.SingleInstance
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel1=Welcome to NetShaper Setup
WelcomeLabel2=This will install [name/ver] on your computer.%n%nNetShaper is a free open-source bandwidth limiter and traffic controller for Windows.%n%nIt is recommended that you close all other applications before continuing.
FinishedHeadingLabel=Completing NetShaper Setup
FinishedLabelNoIcons=Setup has finished installing NetShaper on your computer.%n%nRun as Administrator for full limits, firewall, and precise rates.
ClickFinish=Click Finish to exit Setup.

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: checkedonce
Name: "addpath"; Description: "Add &CLI (NetShaper.Cli.exe) to system PATH"; GroupDescription: "Options:"; Flags: unchecked
Name: "startmenu"; Description: "Create Start Menu shortcuts"; GroupDescription: "Shortcuts:"; Flags: checkedonce

[Files]
; Full self-contained app (GUI + CLI + runtimes + easy-install helpers)
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Ensure full uninstall helper is present even if publish skipped it
Source: "uninstall-app.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\NetShaper.ico"; Comment: "Free bandwidth limiter"; Tasks: startmenu
Name: "{group}\{#MyAppName} CLI"; Filename: "{app}\cli\NetShaper.Cli.exe"; IconFilename: "{app}\NetShaper.ico"; Comment: "NetShaper command line"; Tasks: startmenu
Name: "{group}\Getting Started"; Filename: "{app}\GETTING-STARTED.txt"; Tasks: startmenu
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"; Tasks: startmenu
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\NetShaper.ico"; Comment: "Free bandwidth limiter"; Tasks: desktopicon

[Registry]
; Apps & Features display polish (Inno also writes uninstall key)
Root: HKLM; Subkey: "Software\NetShaper"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\NetShaper"; ValueType: string; ValueName: "Version"; ValueData: "{#MyAppVersion}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch NetShaper now"; Flags: nowait postinstall skipifsilent shellexec
Filename: "{app}\GETTING-STARTED.txt"; Description: "Open Getting Started guide"; Flags: nowait postinstall skipifsilent shellexec unchecked

[UninstallDelete]
Type: filesandordirs; Name: "{app}\cli"
Type: files; Name: "{app}\*.log"

[Code]
const
  EnvironmentKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function GetCliDir: string;
begin
  Result := ExpandConstant('{app}\cli');
end;

function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  { Path is semicolon-separated; look for exact segment }
  Result := Pos(';' + UpperCase(Param) + ';', ';' + UpperCase(OrigPath) + ';') = 0;
end;

procedure EnvAddPath(Path: string);
var
  OrigPath: string;
begin
  if not NeedsAddPath(Path) then
    exit;
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', OrigPath) then
    OrigPath := '';
  if (Length(OrigPath) > 0) and (OrigPath[Length(OrigPath)] <> ';') then
    OrigPath := OrigPath + ';';
  RegWriteExpandStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', OrigPath + Path);
  Log('Added to PATH: ' + Path);
end;

procedure EnvRemovePath(Path: string);
var
  OrigPath, P, Left, Right: string;
  PPos: Integer;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', OrigPath) then
    exit;
  P := ';' + UpperCase(OrigPath) + ';';
  PPos := Pos(';' + UpperCase(Path) + ';', P);
  if PPos = 0 then
    exit;
  { Rebuild without the segment }
  Left := Copy(OrigPath, 1, PPos - 1);
  Right := Copy(OrigPath, PPos + Length(Path) + 1, MaxInt);
  if (Length(Left) > 0) and (Left[Length(Left)] = ';') then
    Delete(Left, Length(Left), 1);
  if (Length(Right) > 0) and (Right[1] = ';') then
    Delete(Right, 1, 1);
  if (Left <> '') and (Right <> '') then
    OrigPath := Left + ';' + Right
  else
    OrigPath := Left + Right;
  RegWriteExpandStringValue(HKEY_LOCAL_MACHINE, EnvironmentKey, 'Path', OrigPath);
  Log('Removed from PATH: ' + Path);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if WizardIsTaskSelected('addpath') then
      EnvAddPath(GetCliDir);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    EnvRemovePath(ExpandConstant('{app}\cli'));
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not FileExists(ExpandConstant('{#PublishDir}\{#MyAppExeName}')) then
  begin
    { Compile-time PublishDir is relative to the .iss file when building;
      at runtime we only install packaged files — this check is for builder mistakes. }
  end;
end;
