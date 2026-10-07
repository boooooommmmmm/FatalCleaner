using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using CleanSweep.Core.Integrity;

namespace CleanSweep.Core.Tests;

/// <summary>
/// 程序自更新：发布信息签名、来源解析、下载核对、安装目录里的可信程序复验与解压（N13）、
/// 事务式替换与回滚、提权服务协调（N12）、不跟随重解析点且只动安装清单里的文件（N11）。
/// </summary>
public sealed class AppUpdateTests : IDisposable
{
    private readonly TestEnv _t = new();

    public void Dispose() => _t.Dispose();

    private static (ECDsa Key, Dictionary<string, byte[]> Trusted) NewKey(string id = "test")
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = SignedManifest.PublicKeyFromBase64(Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
        return (key, new Dictionary<string, byte[]>(StringComparer.Ordinal) { [id] = pub });
    }

    /// <summary>造一个带签名数据集的发布包目录。</summary>
    private string MakePackage(string name, ECDsa key, string exeContent = "exe", bool signData = true, params (string Rel, string Content)[] extra)
    {
        var src = _t.Dir($"{name}/CleanSweep");
        File.WriteAllText(Path.Combine(src, "CleanSweep.exe"), exeContent);
        foreach (var kind in new[] { "rules", "fingerprints", "popups" })
        {
            var d = Path.Combine(src, kind);
            Directory.CreateDirectory(d);
            File.WriteAllText(Path.Combine(d, "a.json"), "{}");
            if (signData) SignedManifest.Sign(d, kind, 1, key, "test");
        }
        foreach (var (rel, content) in extra)
        {
            var p = Path.Combine(src, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(p)!);
            File.WriteAllText(p, content);
        }
        return src;
    }

    /// <summary>把包目录压成 zip，并在旁边写签名的发布信息。</summary>
    private string MakeSignedZip(string packageParent, string version, ECDsa key, string? zipName = null)
    {
        var zip = Path.Combine(_t.Root, zipName ?? $"CleanSweep-win-x64-{version}.zip");
        if (File.Exists(zip)) File.Delete(zip);
        ZipFile.CreateFromDirectory(packageParent, zip);
        var dto = ReleaseManifest.Sign(version, zip, $"https://github.com/o/r/releases/download/v{version}/{Path.GetFileName(zip)}", "notes", key, "test");
        File.WriteAllText(zip + AppUpdater.ReleaseInfoSuffix, ReleaseManifest.ToJson(dto));
        return zip;
    }

    private sealed class FakeService : IUpdateServiceControl
    {
        public bool IsInstalled { get; set; } = true;
        public bool IsRunning { get; set; } = true;
        public List<string> Calls { get; } = new();
        public void Stop(TimeSpan timeout) { Calls.Add("stop"); IsRunning = false; }
        public void Start(TimeSpan timeout) { Calls.Add("start"); IsRunning = true; }
    }

    [Fact]
    public void Update_source_resolves_github_repo_or_https_root_only()
    {
        var gh = UpdateSources.Resolve("someone/CleanSweep");
        Assert.NotNull(gh);
        Assert.Equal("https://raw.githubusercontent.com/someone/CleanSweep/main", gh!.DataBaseUrl);
        Assert.Equal("https://raw.githubusercontent.com/someone/CleanSweep/main/release/latest.json", gh.ReleaseInfoUrl);
        Assert.Equal("https://raw.githubusercontent.com/someone/CleanSweep/dev", UpdateSources.Resolve("someone/CleanSweep@dev")!.DataBaseUrl);
        Assert.Equal("https://updates.example.com/cs", UpdateSources.Resolve("https://updates.example.com/cs/")!.DataBaseUrl);
        Assert.Equal("https://raw.githubusercontent.com/boooooommmmmm/FatalCleaner/main", UpdateSources.Resolve("")!.DataBaseUrl); // 空 = 官方仓库
        Assert.Null(UpdateSources.Resolve("http://updates.example.com/cs"));
        Assert.Null(UpdateSources.Resolve("a/b/c"));
        Assert.Null(UpdateSources.Resolve("some one/repo"));
        Assert.Null(UpdateSources.Resolve("owner/repo@br anch"));
    }

    [Fact]
    public void Release_info_roundtrip_and_rejections()
    {
        var (key, trusted) = NewKey();
        var zip = _t.File("out/CleanSweep-win-x64-0.15.0.zip", "zipbytes");
        var dto = ReleaseManifest.Sign("0.15.0", zip, "https://github.com/o/r/releases/download/v0.15.0/CleanSweep-win-x64-0.15.0.zip", "修复若干问题", key, "test");
        var json = ReleaseManifest.ToJson(dto);
        var back = JsonSerializer.Deserialize<ReleaseInfoDto>(json);

        var info = ReleaseManifest.Verify(back, trusted, out var error);
        Assert.NotNull(info);
        Assert.Null(error);
        Assert.Equal(new Version(0, 15, 0), info!.Version);
        Assert.Equal(8, info.Size);
        Assert.Equal(SignedManifest.HashFile(zip), info.Sha256);
        Assert.Same(back, info.Source);

        back!.Url = "https://evil.example.com/x.zip";
        Assert.Null(ReleaseManifest.Verify(back, trusted, out error));
        Assert.Contains("签名验证失败", error);

        back = JsonSerializer.Deserialize<ReleaseInfoDto>(json)!;
        back.Version = "0.99.0";
        Assert.Contains("签名验证失败", ReleaseManifest.Verify(back, trusted, out error) is null ? error : "");

        Assert.Null(ReleaseManifest.Verify(JsonSerializer.Deserialize<ReleaseInfoDto>(json), new Dictionary<string, byte[]>(), out error));
        Assert.Contains("不受信任", error);

        var http = ReleaseManifest.Sign("0.15.0", zip, "http://mirror.example.com/x.zip", "", key, "test");
        Assert.Null(ReleaseManifest.Verify(http, trusted, out error));
        Assert.Contains("https", error);

        Assert.Throws<ArgumentException>(() => ReleaseManifest.Sign("v1", zip, "https://x/y.zip", "", key, "test"));
    }

    [Fact]
    public void Newer_compares_first_three_parts()
    {
        Assert.True(ReleaseManifest.IsNewer(new Version(0, 15, 0), new Version(0, 14, 0)));
        Assert.False(ReleaseManifest.IsNewer(new Version(0, 14, 0), new Version(0, 14, 0)));
        Assert.False(ReleaseManifest.IsNewer(new Version(0, 14, 0, 5), new Version(0, 14, 0)));
        Assert.True(ReleaseManifest.IsNewer(new Version(1, 0), new Version(0, 99, 99)));
    }

    // ------------------------------------------------------------------ N13：安装阶段在可信位置独立复验

    [Fact]
    public void Verify_and_extract_accepts_only_signed_matching_newer_package()
    {
        var (key, trusted) = NewKey();
        var updater = new AppUpdater(new HttpClient(), trusted);
        MakePackage("pkg", key, extra: ("lib/x.dll", "x"));
        var zip = MakeSignedZip(Path.Combine(_t.Root, "pkg"), "0.15.0", key);
        var stage = Path.Combine(_t.Root, "install", AppUpdater.StageDirName);

        var root = updater.VerifyAndExtract(zip, stage, new Version(0, 14, 0), out var error);
        Assert.NotNull(root);
        Assert.Null(error);
        Assert.Equal("exe", File.ReadAllText(Path.Combine(root!, "CleanSweep.exe")));
        Assert.Equal("x", File.ReadAllText(Path.Combine(root, "lib", "x.dll")));

        // 版本不高于当前：拒绝（防止用旧的真实发布包降级）
        Assert.Null(updater.VerifyAndExtract(zip, stage, new Version(0, 15, 0), out error));
        Assert.Contains("不高于当前版本", error);

        // 压缩包在验签之后被替换：哈希不符
        var bytes = File.ReadAllBytes(zip);
        bytes[^1] ^= 0xFF;
        File.WriteAllBytes(zip, bytes);
        Assert.Null(updater.VerifyAndExtract(zip, stage, new Version(0, 14, 0), out error));
        Assert.Contains("哈希", error);
        Assert.False(Directory.Exists(stage), "拒绝时不应留下暂存目录");

        // 发布信息被改（版本抬高）：签名失败
        MakeSignedZip(Path.Combine(_t.Root, "pkg"), "0.15.0", key);
        var dto = JsonSerializer.Deserialize<ReleaseInfoDto>(File.ReadAllText(zip + AppUpdater.ReleaseInfoSuffix))!;
        dto.Version = "9.0.0";
        File.WriteAllText(zip + AppUpdater.ReleaseInfoSuffix, ReleaseManifest.ToJson(dto));
        Assert.Null(updater.VerifyAndExtract(zip, stage, new Version(0, 14, 0), out error));
        Assert.Contains("发布信息无效", error);

        // 发布信息用不受信任的密钥签
        var (otherKey, _) = NewKey("other");
        var dto2 = ReleaseManifest.Sign("0.15.0", zip, "https://x/y.zip", "", otherKey, "other");
        File.WriteAllText(zip + AppUpdater.ReleaseInfoSuffix, ReleaseManifest.ToJson(dto2));
        Assert.Null(updater.VerifyAndExtract(zip, stage, new Version(0, 14, 0), out error));
        Assert.Contains("不受信任", error);
    }

    [Fact]
    public void Verify_and_extract_rejects_traversal_missing_exe_and_unsigned_data()
    {
        var (key, trusted) = NewKey();
        var updater = new AppUpdater(new HttpClient(), trusted);
        var stage = Path.Combine(_t.Root, "install2", AppUpdater.StageDirName);

        var traversal = Path.Combine(_t.Root, "traversal.zip");
        using (var z = ZipFile.Open(traversal, ZipArchiveMode.Create))
        {
            using (var w = new StreamWriter(z.CreateEntry("CleanSweep.exe").Open())) w.Write("x");
            using (var w2 = new StreamWriter(z.CreateEntry("../evil.txt").Open())) w2.Write("x");
        }
        File.WriteAllText(traversal + AppUpdater.ReleaseInfoSuffix, ReleaseManifest.ToJson(ReleaseManifest.Sign("0.15.0", traversal, "https://x/t.zip", "", key, "test")));
        Assert.Null(updater.VerifyAndExtract(traversal, stage, new Version(0, 14, 0), out var error));
        Assert.Contains("路径非法", error);
        Assert.False(File.Exists(Path.Combine(_t.Root, "install2", "evil.txt")));

        var noExe = Path.Combine(_t.Root, "noexe.zip");
        using (var z = ZipFile.Open(noExe, ZipArchiveMode.Create)) z.CreateEntry("readme.txt");
        File.WriteAllText(noExe + AppUpdater.ReleaseInfoSuffix, ReleaseManifest.ToJson(ReleaseManifest.Sign("0.15.0", noExe, "https://x/n.zip", "", key, "test")));
        Assert.Null(updater.VerifyAndExtract(noExe, stage, new Version(0, 14, 0), out error));
        Assert.Contains("没有 CleanSweep.exe", error);

        MakePackage("unsigned", key, signData: false);
        var unsigned = MakeSignedZip(Path.Combine(_t.Root, "unsigned"), "0.15.0", key, "unsigned.zip");
        Assert.Null(updater.VerifyAndExtract(unsigned, stage, new Version(0, 14, 0), out error));
        Assert.Contains("rules 签名校验失败", error);

        Assert.Null(updater.VerifyAndExtract(Path.Combine(_t.Root, "missing.zip"), stage, new Version(0, 14, 0), out error));
        Assert.Contains("读取发布信息失败", error);
    }

    [Fact]
    public void Launch_apply_requires_installed_exe_and_downloaded_release_info()
    {
        var install = _t.Dir("launch-install");
        Assert.Contains("安装目录里没有", AppUpdater.LaunchApply(install, Path.Combine(_t.Root, "x.zip")));
        File.WriteAllText(Path.Combine(install, "CleanSweep.exe"), "exe");
        Assert.Contains("不存在", AppUpdater.LaunchApply(install, Path.Combine(_t.Root, "x.zip")));
    }

    // ------------------------------------------------------------------ N11：不跟随重解析点，只动安装清单里的文件

    [Fact]
    public void Apply_replaces_owned_files_keeps_foreign_files_and_never_follows_junctions()
    {
        var install = _t.Dir("install3");
        File.WriteAllText(Path.Combine(install, "CleanSweep.exe"), "old");
        File.WriteAllText(Path.Combine(install, "old.dll"), "old-only");
        File.WriteAllText(Path.Combine(install, "stale.dll"), "stale");
        File.WriteAllText(Path.Combine(install, "notes.txt"), "user's own file");
        Directory.CreateDirectory(Path.Combine(install, "rules"));
        File.WriteAllText(Path.Combine(install, "rules", "a.json"), "old-rules");
        AppUpdater.WriteInstallManifest(Path.Combine(install, AppUpdater.InstallManifestName), new[] { "CleanSweep.exe", "old.dll", "stale.dll", @"rules\a.json" });

        var external = _t.Dir("external-data");
        File.WriteAllText(Path.Combine(external, "user-data.txt"), "keep me");
        var junction = Path.Combine(install, "data");
        var hasJunction = TestEnv.TryCreateJunction(junction, external);

        var source = _t.Dir("source3");
        File.WriteAllText(Path.Combine(source, "CleanSweep.exe"), "new");
        File.WriteAllText(Path.Combine(source, "new.dll"), "new-only");
        Directory.CreateDirectory(Path.Combine(source, "rules"));
        File.WriteAllText(Path.Combine(source, "rules", "a.json"), "new-rules");

        var svc = new FakeService();
        var log = new List<string>();
        Assert.Null(AppUpdater.ApplyStaged(source, install, svc, log.Add));

        Assert.Equal("new", File.ReadAllText(Path.Combine(install, "CleanSweep.exe")));
        Assert.Equal("new-only", File.ReadAllText(Path.Combine(install, "new.dll")));
        Assert.Equal("new-rules", File.ReadAllText(Path.Combine(install, "rules", "a.json")));
        Assert.False(File.Exists(Path.Combine(install, "old.dll")), "旧版本拥有且新版本没有的文件应删除");
        Assert.False(File.Exists(Path.Combine(install, "stale.dll")));
        Assert.Equal("user's own file", File.ReadAllText(Path.Combine(install, "notes.txt")));
        Assert.False(Directory.Exists(Path.Combine(install, AppUpdater.BackupDirName)));
        Assert.Equal(new[] { "stop", "start" }, svc.Calls);

        var manifest = AppUpdater.ReadInstallManifest(Path.Combine(install, AppUpdater.InstallManifestName))!;
        Assert.Contains("new.dll", manifest);
        Assert.Contains(@"rules\a.json", manifest);
        Assert.DoesNotContain("old.dll", manifest);
        Assert.DoesNotContain("notes.txt", manifest);

        if (hasJunction)
        {
            Assert.Equal("keep me", File.ReadAllText(Path.Combine(external, "user-data.txt")));
            Assert.True(Directory.Exists(junction) && Core.Safety.PathGuard.IsReparsePoint(junction), "Junction 本身应原样保留");
        }
    }

    [Fact]
    public void Apply_refuses_to_write_through_a_junction_and_rolls_back()
    {
        var install = _t.Dir("install4");
        File.WriteAllText(Path.Combine(install, "CleanSweep.exe"), "old");
        AppUpdater.WriteInstallManifest(Path.Combine(install, AppUpdater.InstallManifestName), new[] { "CleanSweep.exe" });
        var external = _t.Dir("external4");
        File.WriteAllText(Path.Combine(external, "user-data.txt"), "keep me");
        if (!TestEnv.TryCreateJunction(Path.Combine(install, "rules"), external)) return;

        var source = _t.Dir("source4");
        File.WriteAllText(Path.Combine(source, "CleanSweep.exe"), "new");
        Directory.CreateDirectory(Path.Combine(source, "rules"));
        File.WriteAllText(Path.Combine(source, "rules", "a.json"), "new-rules");

        var svc = new FakeService();
        var error = AppUpdater.ApplyStaged(source, install, svc);
        Assert.NotNull(error);
        Assert.Contains("重解析点", error);
        Assert.Contains("已恢复原文件", error);
        Assert.Equal("old", File.ReadAllText(Path.Combine(install, "CleanSweep.exe")));
        Assert.False(File.Exists(Path.Combine(external, "a.json")), "不得穿过 Junction 写到外部目录");
        Assert.Equal("keep me", File.ReadAllText(Path.Combine(external, "user-data.txt")));
        Assert.Equal(new[] { "stop", "start" }, svc.Calls);
    }

    [Fact]
    public void First_upgrade_without_manifest_treats_every_file_as_owned()
    {
        var install = _t.Dir("install5");
        File.WriteAllText(Path.Combine(install, "CleanSweep.exe"), "old");
        File.WriteAllText(Path.Combine(install, "stale.dll"), "stale");
        var source = _t.Dir("source5");
        File.WriteAllText(Path.Combine(source, "CleanSweep.exe"), "new");

        Assert.Null(AppUpdater.ApplyStaged(source, install, new FakeService { IsInstalled = false }));
        Assert.Equal("new", File.ReadAllText(Path.Combine(install, "CleanSweep.exe")));
        Assert.False(File.Exists(Path.Combine(install, "stale.dll")));
        Assert.True(File.Exists(Path.Combine(install, AppUpdater.InstallManifestName)));
    }

    // ------------------------------------------------------------------ N12：失败回滚与服务协调

    [Fact]
    public void Apply_rolls_back_everything_when_a_file_cannot_be_replaced()
    {
        var install = _t.Dir("install6");
        File.WriteAllText(Path.Combine(install, "CleanSweep.exe"), "old");
        File.WriteAllText(Path.Combine(install, "a.dll"), "old-a");
        File.WriteAllText(Path.Combine(install, "z.dll"), "old-z");
        AppUpdater.WriteInstallManifest(Path.Combine(install, AppUpdater.InstallManifestName), new[] { "CleanSweep.exe", "a.dll", "z.dll" });
        var source = _t.Dir("source6");
        File.WriteAllText(Path.Combine(source, "CleanSweep.exe"), "new");
        File.WriteAllText(Path.Combine(source, "a.dll"), "new-a");
        File.WriteAllText(Path.Combine(source, "z.dll"), "new-z");

        var oldRetries = AppUpdater.RetryCount;
        AppUpdater.RetryCount = 2;
        try
        {
            var svc = new FakeService();
            string? error;
            // 枚举顺序靠后的 z.dll 被占用（不带 FILE_SHARE_DELETE 打开，改名失败）
            using (new FileStream(Path.Combine(install, "z.dll"), FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                error = AppUpdater.ApplyStaged(source, install, svc);
            }
            Assert.NotNull(error);
            Assert.Contains("已恢复原文件", error);
            Assert.Equal("old", File.ReadAllText(Path.Combine(install, "CleanSweep.exe")));
            Assert.Equal("old-a", File.ReadAllText(Path.Combine(install, "a.dll")));
            Assert.Equal("old-z", File.ReadAllText(Path.Combine(install, "z.dll")));
            Assert.False(Directory.Exists(Path.Combine(install, AppUpdater.BackupDirName)));
            Assert.Equal(new[] { "stop", "start" }, svc.Calls);
            Assert.Equal(new[] { "CleanSweep.exe", "a.dll", "z.dll" }.Order(StringComparer.OrdinalIgnoreCase),
                AppUpdater.ReadInstallManifest(Path.Combine(install, AppUpdater.InstallManifestName))!.Where(f => f != AppUpdater.InstallManifestName).Order(StringComparer.OrdinalIgnoreCase));
        }
        finally
        {
            AppUpdater.RetryCount = oldRetries;
        }
    }

    [Fact]
    public void Service_is_not_touched_when_absent_or_stopped()
    {
        var install = _t.Dir("install7");
        File.WriteAllText(Path.Combine(install, "CleanSweep.exe"), "old");
        var source = _t.Dir("source7");
        File.WriteAllText(Path.Combine(source, "CleanSweep.exe"), "new");

        var absent = new FakeService { IsInstalled = false };
        Assert.Null(AppUpdater.ApplyStaged(source, install, absent));
        Assert.Empty(absent.Calls);

        File.WriteAllText(Path.Combine(source, "CleanSweep.exe"), "newer");
        var stopped = new FakeService { IsRunning = false };
        Assert.Null(AppUpdater.ApplyStaged(source, install, stopped));
        Assert.Empty(stopped.Calls);
        Assert.Equal("newer", File.ReadAllText(Path.Combine(install, "CleanSweep.exe")));
    }

    [Fact]
    public void Cleanup_removes_stage_and_backup_leftovers_including_links()
    {
        var install = _t.Dir("install8");
        Directory.CreateDirectory(Path.Combine(install, AppUpdater.StageDirName, "pkg"));
        File.WriteAllText(Path.Combine(install, AppUpdater.StageDirName, "pkg", "CleanSweep.exe"), "x");
        var external = _t.Dir("external8");
        File.WriteAllText(Path.Combine(external, "keep.txt"), "keep");
        var link = Path.Combine(install, AppUpdater.BackupDirName);
        var hasJunction = TestEnv.TryCreateJunction(link, external);
        if (!hasJunction) Directory.CreateDirectory(link);

        Assert.True(AppUpdater.CleanupLeftovers(install));
        Assert.False(Directory.Exists(Path.Combine(install, AppUpdater.StageDirName)));
        Assert.False(Directory.Exists(link));
        Assert.Equal("keep", File.ReadAllText(Path.Combine(external, "keep.txt")));
    }

    private static (HttpListener Listener, string BaseUrl, Task Serving) Serve(Dictionary<string, byte[]> files, CancellationToken ct)
    {
        var (listener, baseUrl) = TestHttpListener.Start();
        var serving = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try { ctx = await listener.GetContextAsync(); }
                catch { break; }
                var rel = ctx.Request.Url!.AbsolutePath.TrimStart('/');
                if (files.TryGetValue(rel, out var bytes))
                {
                    ctx.Response.ContentLength64 = bytes.Length;
                    await ctx.Response.OutputStream.WriteAsync(bytes);
                }
                else ctx.Response.StatusCode = 404;
                ctx.Response.Close();
            }
        });
        return (listener, baseUrl, serving);
    }

    [Fact]
    public async Task Check_and_download_verify_version_size_and_hash_and_keep_signed_release_info()
    {
        var (key, trusted) = NewKey();
        var zipBytes = new byte[100_000];
        Random.Shared.NextBytes(zipBytes);
        var zipPath = Path.Combine(_t.Root, "CleanSweep-win-x64-0.15.0.zip");
        File.WriteAllBytes(zipPath, zipBytes);

        using var cts = new CancellationTokenSource();
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var (listener, baseUrl, serving) = Serve(files, cts.Token);
        try
        {
            var url = baseUrl + "/dl/CleanSweep-win-x64-0.15.0.zip";
            var dto = ReleaseManifest.Sign("0.15.0", zipPath, url, "notes", key, "test");
            files["release/latest.json"] = System.Text.Encoding.UTF8.GetBytes(ReleaseManifest.ToJson(dto));
            files["dl/CleanSweep-win-x64-0.15.0.zip"] = zipBytes;
            var updater = new AppUpdater(new HttpClient(), trusted);

            var same = await updater.CheckAsync(baseUrl + "/release/latest.json", new Version(0, 15, 0));
            Assert.False(same.Available);
            Assert.Contains("已是最新", same.Message);

            var check = await updater.CheckAsync(baseUrl + "/release/latest.json", new Version(0, 14, 0));
            Assert.True(check.Available, check.Message);
            Assert.NotNull(check.Release);

            var missing = await updater.CheckAsync(baseUrl + "/nope/latest.json", new Version(0, 14, 0));
            Assert.False(missing.Available);
            Assert.Contains("还没有发布信息", missing.Message);

            var staging = Path.Combine(_t.Root, "staging");
            var downloaded = await updater.DownloadAsync(check.Release!, staging);
            Assert.Equal(zipBytes, File.ReadAllBytes(downloaded));
            Assert.Empty(Directory.EnumerateFiles(staging, "*.part"));
            // 签名的发布信息原样存在压缩包旁，安装阶段据此独立复验
            var saved = JsonSerializer.Deserialize<ReleaseInfoDto>(File.ReadAllText(downloaded + AppUpdater.ReleaseInfoSuffix));
            Assert.NotNull(ReleaseManifest.Verify(saved, trusted, out _));
            Assert.Equal(dto.Signature, saved!.Signature);

            // 服务器上的包被换掉：大小相同但内容不同 → 哈希不符；大小不同 → 直接拒绝
            var swapped = (byte[])zipBytes.Clone();
            swapped[10] ^= 0xFF;
            files["dl/CleanSweep-win-x64-0.15.0.zip"] = swapped;
            var ex = await Assert.ThrowsAsync<InvalidDataException>(() => updater.DownloadAsync(check.Release!, staging));
            Assert.Contains("哈希", ex.Message);
            files["dl/CleanSweep-win-x64-0.15.0.zip"] = zipBytes.Take(50_000).ToArray();
            ex = await Assert.ThrowsAsync<InvalidDataException>(() => updater.DownloadAsync(check.Release!, staging));
            Assert.Contains("大小", ex.Message);
            Assert.Empty(Directory.EnumerateFiles(staging, "*.part"));
        }
        finally
        {
            cts.Cancel();
            listener.Stop();
            try { await serving; } catch { }
        }
    }
}
