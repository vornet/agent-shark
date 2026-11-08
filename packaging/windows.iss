#define AppVersion "@VERSION@"
#define Payload "@PAYLOAD@"
[Setup]
AppId={{4D113420-E17E-4EF4-AD16-6ED71F8FE92D}
AppName=AgentShark
AppVersion={#AppVersion}
AppPublisher=Vorn Mom
AppPublisherURL=https://github.com/vornet/agent-shark
AppSupportURL=https://github.com/vornet/agent-shark/issues
DefaultDirName={localappdata}\Programs\AgentShark
PrivilegesRequired=lowest
ArchitecturesAllowed=@ARCH@
ArchitecturesInstallIn64BitMode=@ARCH@
OutputDir=@OUTPUT@
OutputBaseFilename=AgentShark-{#AppVersion}-@RID@-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
LicenseFile={#Payload}\LICENSE
UninstallDisplayIcon={app}\server\AgentShark.Server.exe
CloseApplications=no
RestartApplications=no
SetupLogging=yes

[Files]
Source: "{#Payload}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Tasks]
Name: connect; Description: "Connect detected AI client profiles (Codex, Claude, Cursor, VS Code, Windsurf)"; Flags: checkedonce

[UninstallDelete]
Type: files; Name: "{app}\installer-profile.ini"

[Code]
function ProfileArguments(Home: String): String;
begin
  Result := '';
  if Home <> '' then Result := ' --home "' + Home + '"';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var ResultCode: Integer; Home: String;
begin
  if CurStep = ssPostInstall then
  begin
    Home := ExpandConstant('{param:PROFILEHOME|}');
    SetIniString('setup', 'profileHome', Home, ExpandConstant('{app}\installer-profile.ini'));
    if WizardIsTaskSelected('connect') then
    begin
      if (not Exec(ExpandConstant('{app}\setup\AgentShark.Setup.exe'), 'integrate --clients detected' + ProfileArguments(Home), '', SW_HIDE, ewWaitUntilTerminated, ResultCode)) or (ResultCode <> 0) then
        SuppressibleMsgBox('AgentShark is installed. Some client profiles could not be configured. Review the setup report in your AgentShark application-data folder. Existing conflicting settings were preserved.', mbInformation, MB_OK, IDOK);
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var ResultCode: Integer; Home: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    Home := GetIniString('setup', 'profileHome', '', ExpandConstant('{app}\installer-profile.ini'));
    if FileExists(ExpandConstant('{app}\setup\AgentShark.Setup.exe')) then
      Exec(ExpandConstant('{app}\setup\AgentShark.Setup.exe'), 'remove --clients all' + ProfileArguments(Home), '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
