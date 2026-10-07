# CleanSweep 卸载脚本（需要管理员权限）。默认保留 %ProgramData%\CleanSweep（隔离区索引、注册表备份、历史）；加 -RemoveData 一并删除。
# 各卷根下的 $CleanSweep.Quarantine 目录里是用户仍可恢复的文件，脚本不删除，需要时在程序的隔离区页面处理后再手动删除。
param(
    [string]$Target = "",
    [switch]$RemoveData
)
$ErrorActionPreference = "Continue"
# 安装目录默认从脚本自身位置推导（<安装目录>\tools\uninstall.ps1），不再假定 Program Files；删除前核对目录里确实是本程序
if ($Target -eq "") { $Target = Split-Path -Parent $PSScriptRoot }
$Target = [IO.Path]::GetFullPath($Target).TrimEnd('\\')
if (-not (Test-Path (Join-Path $Target "CleanSweep.exe"))) { throw "目录 $Target 里没有 CleanSweep.exe，拒绝卸载" }
if ($Target.Length -le 3) { throw "安装目录不能是卷根" }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "需要以管理员身份运行" }

Get-Process CleanSweep -ErrorAction SilentlyContinue | Stop-Process -Force
if (Get-Service CleanSweepElevation -ErrorAction SilentlyContinue) {
    Stop-Service CleanSweepElevation -Force -ErrorAction SilentlyContinue
    (Get-Service CleanSweepElevation).WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
}
$svc = Join-Path $Target "CleanSweep.Service.exe"
if (Test-Path $svc) { & $svc --uninstall | Out-Null } else { sc.exe delete CleanSweepElevation | Out-Null }
Get-Process CleanSweep.Service -ErrorAction SilentlyContinue | Stop-Process -Force

Remove-Item (Join-Path ([Environment]::GetFolderPath("CommonPrograms")) "CleanSweep.lnk") -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path ([Environment]::GetFolderPath("CommonPrograms")) "FatalCleaner.lnk") -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CleanSweep" -Recurse -Force -ErrorAction SilentlyContinue

if ($RemoveData) { Remove-Item (Join-Path $env:ProgramData "CleanSweep") -Recurse -Force -ErrorAction SilentlyContinue }

# 脚本自身在 $Target\tools 下：延迟删除目录
Start-Process powershell -ArgumentList "-NoProfile -Command Start-Sleep 2; Remove-Item -LiteralPath '$Target' -Recurse -Force" -WindowStyle Hidden
Write-Host "已卸载。$(if (-not $RemoveData) { "数据目录 $env:ProgramData\CleanSweep 已保留。" })"
