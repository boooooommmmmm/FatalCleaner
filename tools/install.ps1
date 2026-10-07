# CleanSweep 安装脚本（需要管理员权限）。Inno Setup 安装器（installer/CleanSweep.iss）内部也调用同样的步骤。
#   1. 把发布目录复制到 %ProgramFiles%\CleanSweep（自包含发布，目标机无需 .NET 运行时）
#   2. 创建 %ProgramData%\CleanSweep 数据目录（提权服务与界面共用；ACL 由程序首次提权运行时收紧）
#   3. 安装提权服务 CleanSweep.Service --install（登记安装者 SID 与 CleanSweep.exe 路径）
#   4. 开始菜单快捷方式、"应用和功能"卸载项
# 用法：powershell -ExecutionPolicy Bypass -File tools/install.ps1 [-Source publish/win-x64] [-Target "C:\Program Files\CleanSweep"] [-NoService]
param(
    [string]$Source = "",
    [string]$Target = (Join-Path $env:ProgramFiles "CleanSweep"),
    [switch]$NoService
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if ($Source -eq "") { $Source = Join-Path $root "publish\win-x64" }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "需要以管理员身份运行" }
if (-not (Test-Path (Join-Path $Source "CleanSweep.exe"))) { throw "发布目录里没有 CleanSweep.exe：$Source（先运行 tools/publish.ps1）" }
foreach ($kind in "rules", "fingerprints", "popups") {
    if (-not (Test-Path (Join-Path $Source "$kind\manifest.json"))) { throw "$kind 缺少签名清单 manifest.json，拒绝安装" }
}

# 停止正在运行的实例与旧服务（服务进程占用着文件，必须先停再复制）
Get-Process CleanSweep -ErrorAction SilentlyContinue | Stop-Process -Force
if (Get-Service CleanSweepElevation -ErrorAction SilentlyContinue) {
    Stop-Service CleanSweepElevation -Force -ErrorAction SilentlyContinue
    (Get-Service CleanSweepElevation).WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    $oldSvc = Join-Path $Target "CleanSweep.Service.exe"
    if (Test-Path $oldSvc) { & $oldSvc --uninstall | Out-Null } else { sc.exe delete CleanSweepElevation | Out-Null }
}
Get-Process CleanSweep.Service -ErrorAction SilentlyContinue | Stop-Process -Force

New-Item -ItemType Directory -Force -Path $Target | Out-Null
robocopy $Source $Target /MIR /NJH /NJS /NFL /NDL | Out-Null
if ($LASTEXITCODE -ge 8) { throw "复制文件失败（robocopy $LASTEXITCODE）" }

$data = Join-Path $env:ProgramData "CleanSweep"
New-Item -ItemType Directory -Force -Path $data | Out-Null

if (-not $NoService) {
    & (Join-Path $Target "CleanSweep.Service.exe") --install
    if ($LASTEXITCODE -ne 0) { Write-Warning "提权服务安装失败（$LASTEXITCODE），程序仍可用“以管理员身份重新启动”方式工作" }
}

# 快捷方式
$shell = New-Object -ComObject WScript.Shell
$programs = [Environment]::GetFolderPath("CommonPrograms")
$lnk = $shell.CreateShortcut((Join-Path $programs "FatalCleaner.lnk"))
$lnk.TargetPath = Join-Path $Target "CleanSweep.exe"
$lnk.WorkingDirectory = $Target
$lnk.Description = "FatalCleaner · 安全优先的 Windows 系统清理"
$lnk.Save()

# 应用和功能
$version = (Get-Item (Join-Path $Target "CleanSweep.exe")).VersionInfo.ProductVersion
$key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CleanSweep"
New-Item -Path $key -Force | Out-Null
Set-ItemProperty $key DisplayName "FatalCleaner"
Set-ItemProperty $key DisplayVersion "$version"
Set-ItemProperty $key Publisher "FatalCleaner"
Set-ItemProperty $key InstallLocation $Target
Set-ItemProperty $key DisplayIcon (Join-Path $Target "CleanSweep.exe")
Set-ItemProperty $key UninstallString "powershell.exe -ExecutionPolicy Bypass -File `"$Target\tools\uninstall.ps1`" -Target `"$Target`""
Set-ItemProperty $key NoModify 1 -Type DWord
Set-ItemProperty $key NoRepair 1 -Type DWord
New-Item -ItemType Directory -Force -Path (Join-Path $Target "tools") | Out-Null
Copy-Item (Join-Path $PSScriptRoot "uninstall.ps1") (Join-Path $Target "tools\uninstall.ps1") -Force

Write-Host "已安装到 $Target；数据目录 $data；提权服务：$(if ($NoService) { '未安装' } else { 'CleanSweepElevation' })"
