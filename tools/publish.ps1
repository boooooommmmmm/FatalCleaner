# 发布自包含版本（目标机不需要安装 .NET 运行时）。
# 用法：powershell -File tools/publish.ps1 [-Rid win-x64|win-arm64] [-Out publish/win-x64]
param(
    [string]$Rid = "win-x64",
    [string]$Out = "",
    [string]$PortableOut = ""
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if ($Out -eq "") { $Out = "publish/$Rid" }
if ($PortableOut -eq "") { $PortableOut = "publish/portable-$Rid" }
Push-Location $root
try {
    # 禁止混入上次构建的 DLL 或用户文件；调用方先归档旧目录，不能在原地覆盖打包。
    foreach ($dir in @($Out, $PortableOut)) {
        if ((Test-Path -LiteralPath $dir) -and (Get-ChildItem -LiteralPath $dir -Force | Select-Object -First 1)) {
            throw "输出目录非空，请先归档或指定新的输出目录：$dir"
        }
    }
    $compatRoot = [IO.Path]::GetFullPath($Out).TrimEnd('\')
    $portableRoot = [IO.Path]::GetFullPath($PortableOut).TrimEnd('\')
    if ($compatRoot -eq $portableRoot -or $portableRoot.StartsWith($compatRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or $compatRoot.StartsWith($portableRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw '兼容包与单文件输出目录必须不同，且不能相互嵌套'
    }
    foreach ($proj in "src/CleanSweep.App", "src/CleanSweep.Service") {
        $extra = @()
        if ($proj -eq 'src/CleanSweep.App') {
            $extra = @('-p:PublishSingleFile=true', '-p:IncludeNativeLibrariesForSelfExtract=true', '-p:EnableCompressionInSingleFile=true', '-p:DebugType=embedded')
        }
        dotnet publish $proj -c Release -r $Rid --self-contained true -p:PublishReadyToRun=true @extra -o $Out --nologo -v q
        if ($LASTEXITCODE -ne 0) { throw "publish $proj failed" }
    }
    # 发布前自检：三个数据集的签名必须通过
    foreach ($kind in "rules", "fingerprints", "popups") {
        dotnet run --project tools/CleanSweep.SignData -c Release -- verify (Join-Path $Out $kind) $kind
        if ($LASTEXITCODE -ne 0) { throw "$kind manifest verification failed" }
    }
    # 安装清单：自更新时只替换 / 删除这里列出的文件，安装目录里用户放的其他文件不动
    $outFull = (Resolve-Path $Out).Path.TrimEnd('\')
    $manifest = Join-Path $outFull "install-files.txt"
    $files = Get-ChildItem -Path $outFull -Recurse -File -Attributes !ReparsePoint |
        Where-Object { $_.Name -ne "install-files.txt" } |
        ForEach-Object { $_.FullName.Substring($outFull.Length + 1) } | Sort-Object
    $lines = @("# CleanSweep 安装清单：本程序拥有的文件。更新时只替换 / 删除这里列出的文件。") + $files
    [System.IO.File]::WriteAllLines($manifest, $lines, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "已发布到 $Out（$($files.Count) 个文件，安装清单 install-files.txt）"
    New-Item -ItemType Directory -Path $PortableOut -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $outFull 'CleanSweep.exe') -Destination (Join-Path $PortableOut 'FatalCleaner.exe')
    # 只能在本机体系结构上运行；跨架构产物需在目标机器执行同一自检。
    if ($Rid -eq ('win-' + [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant())) {
        & (Join-Path $PSScriptRoot 'verify-portable.ps1') -Exe (Join-Path $PortableOut 'FatalCleaner.exe')
    }
    Write-Host "单文件免安装版：$PortableOut/FatalCleaner.exe；旧版自动更新继续使用兼容目录的 ZIP。"
}
finally {
    Pop-Location
}
