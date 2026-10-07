# 打一个可自动更新的发布：publish → zip → 用数据签名密钥生成 release/latest.json。
# 用法：powershell -File tools/release.ps1 -Repo owner/CleanSweep [-Version 0.17.0] [-Notes "..."] [-Key <私钥.pem>] [-KeyId release-2026-09]
# 私钥默认读 %USERPROFILE%\.cleansweep\keys\release-signing-key.pem，不在仓库里。
# 之后：
#   1. git add release/latest.json && git commit && git push          （程序从 raw.githubusercontent.com/<repo>/main/release/latest.json 读发布信息）
#   2. 在 GitHub 上创建 tag v<版本> 的 Release，把 publish/FatalCleaner-win-x64-<版本>.zip 作为附件上传（地址必须与 latest.json 里的 url 一致）
#   或者加 -Publish：脚本用 %USERPROFILE%\.cleansweep\github-token.txt 里的细粒度令牌（Contents: Read and write）直接创建 Release、上传 zip、
#   匿名重新下载核对哈希。前提是当前提交已推送（脚本会 fetch 核对），之后只剩提交并推送 release/latest.json。令牌用完请吊销。
param(
    [Parameter(Mandatory = $true)][string]$Repo,
    [string]$Version = "",
    [string]$Notes = "",
    [string]$Key = (Join-Path $env:USERPROFILE ".cleansweep\keys\release-signing-key.pem"),
    [string]$KeyId = "release-2026-09",
    [string]$Rid = "win-x64",
    [switch]$Publish,
    [string]$Branch = "main",
    [string]$TokenFile = (Join-Path $env:USERPROFILE ".cleansweep\github-token.txt")
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $releaseCommit = $null
    if ($Publish) { $releaseCommit = & (Join-Path $PSScriptRoot 'verify-release-source.ps1') }
    & (Join-Path $PSScriptRoot "publish.ps1") -Rid $Rid
    if ($LASTEXITCODE -ne 0) { throw "publish failed" }
    $exe = "publish/$Rid/CleanSweep.exe"
    $builtVersion = ((Get-Item $exe).VersionInfo.ProductVersion -split "\+")[0]
    if ($Version -eq "") { $Version = $builtVersion }
    if ([version]$Version -ne [version]$builtVersion) { throw "发布版本 $Version 与程序版本 $builtVersion 不一致" }
    $asset = "FatalCleaner-$Rid-$Version.zip"
    $zip = "publish/$asset"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path "publish/$Rid/*" -DestinationPath $zip -CompressionLevel Optimal
    $url = "https://github.com/$Repo/releases/download/v$Version/$asset"
    dotnet run --project tools/CleanSweep.SignData -c Release -- sign-release $Version $zip $url release/latest.json $Key $KeyId $Notes
    if ($LASTEXITCODE -ne 0) { throw "sign-release failed" }
    dotnet run --project tools/CleanSweep.SignData -c Release --no-build -- verify-release release/latest.json $zip
    if ($LASTEXITCODE -ne 0) { throw "release verification failed" }
    Write-Host ""
    Write-Host "已生成 $zip 与 release/latest.json。"

    if (-not $Publish) {
        Write-Host "接下来："
        Write-Host "  git add release/latest.json; git commit -m 'release v$Version'; git push"
        Write-Host "  在 GitHub 创建 Release v$Version 并上传 $zip（下载地址须为 $url），或改用 -Publish 让脚本完成这一步"
        return
    }

    # ---- -Publish：通过 GitHub REST API 创建 Release 并上传附件 ----
    # 发布信息里的下载地址指向 tag v<版本>，tag 必须打在已经推送的提交上，否则用户看得到新版本却下载不到
    $sha = & (Join-Path $PSScriptRoot 'verify-release-source.ps1')
    if ($sha -ne $releaseCommit) { throw '构建期间 HEAD 发生变化，请重新发布' }
    # git 把进度信息写到 stderr，$ErrorActionPreference = Stop 下会被当成错误终止，临时放宽并只看退出码
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    git fetch --quiet origin $Branch 2>$null
    $fetchExit = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    if ($fetchExit -ne 0) { throw "git fetch origin $Branch 失败（退出码 $fetchExit）" }
    $remote = (git rev-parse "origin/$Branch").Trim()
    if ($sha -ne $remote) { throw "HEAD（$sha）与 origin/$Branch（$remote）不一致：先把代码推送到 GitHub 再发布" }
    if (-not (Test-Path -LiteralPath $TokenFile)) { throw "找不到令牌文件 $TokenFile" }
    $token = (Get-Content -LiteralPath $TokenFile -Raw).Trim()
    if ($token -eq "") { throw "令牌文件为空" }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $headers = @{
        Authorization          = "Bearer $token"
        Accept                 = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
        "User-Agent"           = "CleanSweep-release-script"
    }
    $payload = @{ tag_name = "v$Version"; target_commitish = $sha; name = "FatalCleaner v$Version"; body = $Notes; draft = $false; prerelease = $false } | ConvertTo-Json -Compress
    Write-Host "创建 Release v$Version（$sha）…"
    $rel = Invoke-RestMethod -Method Post -Uri "https://api.github.com/repos/$Repo/releases" -Headers $headers -ContentType "application/json; charset=utf-8" -Body ([Text.Encoding]::UTF8.GetBytes($payload))
    $uploadUrl = ($rel.upload_url -replace '\{.*$', '') + "?name=$([Uri]::EscapeDataString($asset))"
    Write-Host "上传 $asset（$([math]::Round((Get-Item $zip).Length / 1MB)) MB）…"
    $assetInfo = Invoke-RestMethod -Method Post -Uri $uploadUrl -Headers $headers -ContentType "application/zip" -InFile $zip
    if ($assetInfo.browser_download_url -ne $url) { throw "附件地址 $($assetInfo.browser_download_url) 与 latest.json 里的 $url 不一致" }

    # 匿名重新下载核对哈希（附件刚上传后 CDN 可能要几秒才可用）
    $expected = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    $tmp = Join-Path $env:TEMP "cleansweep-verify-$Version.zip"
    $actual = ""
    for ($i = 1; $i -le 6; $i++) {
        try {
            Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing -Headers @{ "User-Agent" = "CleanSweep-release-script" }
            $actual = (Get-FileHash $tmp -Algorithm SHA256).Hash.ToLowerInvariant()
            break
        }
        catch { if ($i -eq 6) { throw }; Start-Sleep -Seconds 5 }
    }
    if (Test-Path $tmp) { Remove-Item $tmp -Force }
    if ($actual -ne $expected) { throw "匿名下载的哈希 $actual 与本地 $expected 不一致，请到 GitHub 检查该 Release" }
    Write-Host "Release 已发布并核对哈希：$($rel.html_url)"
    Write-Host "最后一步：git add release/latest.json; git commit -m 'release v$Version'; git push（推送后自更新才能看到这个版本）。用完请吊销令牌并删除 $TokenFile。"
}
finally {
    Pop-Location
}
