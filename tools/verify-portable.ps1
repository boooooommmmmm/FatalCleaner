# 只运行发布包的自检入口，不启动主界面、不访问用户数据或服务。
param([Parameter(Mandatory = $true)][string]$Exe)
$ErrorActionPreference = 'Stop'
$exePath = (Resolve-Path -LiteralPath $Exe).Path
$info = [Diagnostics.ProcessStartInfo]::new($exePath, '--verify-portable')
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
$info.RedirectStandardOutput = $true
$info.RedirectStandardError = $true
$info.WorkingDirectory = Split-Path -Parent $exePath
$process = [Diagnostics.Process]::Start($info)
try {
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(60000)) { $process.Kill(); throw '单文件自检 60 秒内未完成' }
    $output = $stdout.GetAwaiter().GetResult()
    $errorText = $stderr.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) { throw "单文件自检失败：$errorText" }
    $result = $output | ConvertFrom-Json
    if (-not $result.Ok -or $result.DataSets.Count -ne 3) { throw '自检未返回完整结果' }
    if ($result.BaseDirectory.TrimEnd('\') -ne $info.WorkingDirectory.TrimEnd('\')) { throw '程序基目录指向解压缓存，更新路径不安全' }
    $output
}
finally { $process.Dispose() }
