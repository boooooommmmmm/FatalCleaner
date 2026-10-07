# 本地与 CI 共用的只读验收入口：构建、测试、公开签名和可选发布产物核对。
# 不签名、不安装服务、不上传发布。结果写入 artifacts/verification/<配置>/。
param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [string]$PackageDir = '',
    [string]$ReleaseZip = '',
    [string]$ResultsDirectory = ''
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $repoRoot
$steps = [System.Collections.Generic.List[string]]::new()
$failure = $null
$appVersion = ''
function Invoke-DotNet {
    param([string[]]$Arguments)
    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet $($Arguments -join ' ') 失败（$LASTEXITCODE）" }
}
try {
    if ($ResultsDirectory -eq '') { $ResultsDirectory = "artifacts/verification/$Configuration" }
    $ResultsDirectory = [IO.Path]::GetFullPath($ResultsDirectory)
    New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null
    [xml]$appProject = Get-Content src/CleanSweep.App/CleanSweep.App.csproj -Raw -Encoding UTF8
    [xml]$serviceProject = Get-Content src/CleanSweep.Service/CleanSweep.Service.csproj -Raw -Encoding UTF8
    [xml]$appManifest = Get-Content src/CleanSweep.App/app.manifest -Raw -Encoding UTF8
    $appVersion = [string]$appProject.Project.PropertyGroup.Version
    if ([version]$appVersion -ne [version]([string]$serviceProject.Project.PropertyGroup.Version)) { throw '界面与服务项目版本不一致' }
    $manifestVersion = [version]$appManifest.assembly.assemblyIdentity.version
    if ($manifestVersion.ToString(3) -ne ([version]$appVersion).ToString(3)) { throw '应用清单版本与项目版本不一致' }
    $steps.Add('项目与应用清单版本一致')

    Invoke-DotNet @('restore', 'CleanSweep.slnx', '--nologo')
    Invoke-DotNet @('build', 'CleanSweep.slnx', '-c', $Configuration, '--no-restore', '--nologo', '-warnaserror')
    $steps.Add('解决方案构建通过，无警告')
    foreach ($testProject in @('CleanSweep.Core.Tests', 'CleanSweep.App.Tests')) {
        Invoke-DotNet @('test', "tests/$testProject", '-c', $Configuration, '--no-build', '--no-restore', '--nologo',
            '--logger', "trx;LogFileName=$testProject.trx", '--results-directory', $ResultsDirectory)
        $steps.Add("$testProject 通过")
    }
    $cli = "tools/CleanSweep.SignData/bin/$Configuration/net10.0-windows/CleanSweep.SignData.dll"
    foreach ($kind in @('rules', 'fingerprints', 'popups')) {
        Invoke-DotNet @($cli, 'verify', $kind, $kind)
    }
    Invoke-DotNet @($cli, 'verify-release', 'release/latest.json')
    $steps.Add('内置数据集与发布信息签名通过')

    if ($PackageDir -ne '') {
        $packageRoot = (Resolve-Path -LiteralPath $PackageDir).Path.TrimEnd('\')
        $prefix = $packageRoot + '\'
        if ((Get-Item -LiteralPath $packageRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw '发布根目录是重解析点' }
        $expectedFiles = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($line in Get-Content -Encoding UTF8 -LiteralPath (Join-Path $packageRoot 'install-files.txt')) {
            $relative = $line.Trim()
            if ($relative -eq '' -or $relative.StartsWith('#')) { continue }
            if ([IO.Path]::IsPathRooted($relative) -or $relative.Contains(':') -or ($relative -split '[/\\]') -contains '..') { throw "安装清单路径非法：$relative" }
            if (-not $expectedFiles.Add($relative.Replace('/', '\'))) { throw "安装清单含重复项：$relative" }
            $full = [IO.Path]::GetFullPath((Join-Path $packageRoot $relative))
            if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "安装清单文件缺失或越界：$relative" }
        }
        $pending = [System.Collections.Generic.Stack[string]]::new()
        $pending.Push($packageRoot)
        while ($pending.Count -gt 0) {
            foreach ($entry in Get-ChildItem -LiteralPath $pending.Pop() -Force) {
                if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "发布产物含重解析点：$($entry.Name)" }
                if ($entry.PSIsContainer) { $pending.Push($entry.FullName); continue }
                $relative = $entry.FullName.Substring($prefix.Length)
                if ($relative -ne 'install-files.txt' -and -not $expectedFiles.Contains($relative)) { throw "文件未列入安装清单：$relative" }
            }
        }
        foreach ($file in @('CleanSweep.exe', 'CleanSweep.Service.exe', 'CleanSweep.Service.dll')) {
            if (-not $expectedFiles.Contains($file)) { throw "发布产物缺少必要文件：$file" }
        }
        foreach ($file in @('CleanSweep.exe', 'CleanSweep.Service.dll')) {
            $binaryVersion = ([Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $packageRoot $file)).ProductVersion -split '\+')[0]
            if ([version]$binaryVersion -ne [version]$appVersion) { throw "$file 的版本与当前源码不一致" }
        }
        foreach ($kind in @('rules', 'fingerprints', 'popups')) { Invoke-DotNet @($cli, 'verify', (Join-Path $packageRoot $kind), $kind) }
        $steps.Add('发布目录：安装清单、必要文件、二进制版本、数据集签名通过')
    }
    if ($ReleaseZip -ne '') {
        $metadata = Get-Content release/latest.json -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([version]$metadata.version -ne [version]$appVersion) { throw '发布信息版本与当前项目版本不一致' }
        Invoke-DotNet @($cli, 'verify-release', 'release/latest.json', $ReleaseZip)
        $steps.Add('发布 ZIP：名称、大小、哈希、签名和版本通过')
    }
    Write-Host "验证完成：$Configuration，版本 $appVersion"
}
catch {
    $failure = $_.Exception.Message
    throw
}
finally {
    if ($ResultsDirectory -ne '' -and (Test-Path -LiteralPath $ResultsDirectory)) {
        [ordered]@{
            CheckedAtUtc = [DateTime]::UtcNow.ToString('o')
            Commit = (git rev-parse HEAD)
            Configuration = $Configuration
            Version = $appVersion
            Passed = ($null -eq $failure)
            Checks = @($steps)
            Failure = $failure
            Limitation = '不包含真实管理员/SYSTEM 服务、安装卸载和断电验收'
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'summary.json') -Encoding UTF8
    }
    Pop-Location
}
