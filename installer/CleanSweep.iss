; CleanSweep 安装器（Inno Setup 6）。
; 前提：已运行 tools/publish.ps1 生成 publish\win-x64（自包含，含签名清单）。
; 编译：iscc installer\CleanSweep.iss  → installer\output\FatalCleaner-Setup-<版本>.exe
; 发布构建须对 CleanSweep.exe、CleanSweep.Service.exe、CleanSweep.Core.dll 与安装器本身做代码签名（SignTool），
; 否则提权服务的 RequireSignedClient 会在安装时被 --install 自动关闭。

#define AppName "FatalCleaner"
#define AppVersion GetVersionNumbersString("..\publish\win-x64\CleanSweep.exe")
#define Publisher "FatalCleaner"

[Setup]
AppId={{6F0C2A1E-8B7D-4E2B-9C61-3A5D7E9F1B24}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#Publisher}
DefaultDirName={autopf}\CleanSweep
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=output
OutputBaseFilename={#AppName}-Setup-{#AppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
MinVersion=10.0.17763
UninstallDisplayIcon={app}\CleanSweep.exe
SetupIconFile=..\src\CleanSweep.App\Assets\FatalCleaner.ico
WizardStyle=modern
CloseApplications=yes
; SignTool=signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a $f

[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
Name: "service"; Description: "安装提权服务（界面以普通权限运行，系统目录的清理经服务执行，无需每次 UAC）"; Flags: checkedonce
Name: "desktopicon"; Description: "创建桌面快捷方式"; Flags: unchecked

[Files]
Source: "..\publish\win-x64\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
Name: "{commonappdata}\CleanSweep"

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\CleanSweep.exe"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\CleanSweep.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\CleanSweep.Service.exe"; Parameters: "--install"; Flags: runhidden waituntilterminated; Tasks: service; StatusMsg: "正在安装提权服务…"
Filename: "{app}\CleanSweep.exe"; Description: "启动 {#AppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\CleanSweep.Service.exe"; Parameters: "--uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "svc"

[UninstallDelete]
; 数据目录默认保留（隔离区索引、注册表备份）；各卷根下的 $CleanSweep.Quarantine 也保留，用户仍可手动恢复
Type: filesandordirs; Name: "{app}"
