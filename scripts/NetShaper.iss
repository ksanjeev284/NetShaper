; Inno Setup 6 script for NetShaper
; Build: scripts\build-installer.ps1 (requires Inno Setup 6)

#define MyAppName "NetShaper"
#ifndef MyAppVersion
  #define MyAppVersion "0.4.1"
#endif
#define MyAppPublisher "NetShaper contributors"
#define MyAppURL "https://github.com/ksanjeev284/NetShaper"
#define MyAppExeName "NetShaper.exe"
#define PublishDir "..\dist\NetShaper-win-x64"

[Setup]
AppId={{A7B2C3D4-E5F6-7890-ABCD-NETSHAPER0001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=NetShaper-Setup-{#MyAppVersion}
SetupIconFile=..\assets\NetShaper.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"
Name: "addpath"; Description: "Add CLI to system &PATH"; GroupDescription: "Options:"; Flags: unchecked

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\scripts\uninstall-app.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\NetShaper.ico"
Name: "{group}\{#MyAppName} CLI"; Filename: "{app}\cli\NetShaper.Cli.exe"; IconFilename: "{app}\NetShaper.ico"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\NetShaper.ico"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\NetShaper"; ValueType: string; ValueName: "DisplayIcon"; ValueData: "{app}\{#MyAppExeName}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch NetShaper"; Flags: nowait postinstall skipifsilent

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var
  Path, Cli: string;
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addpath') then
  begin
    Cli := ExpandConstant('{app}\cli');
    Path := GetEnv('PATH');
    if Pos(LowerCase(Cli), LowerCase(Path)) = 0 then
      RegWriteStringValue(HKEY_LOCAL_MACHINE,
        'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
        'Path', Path + ';' + Cli);
  end;
end;
