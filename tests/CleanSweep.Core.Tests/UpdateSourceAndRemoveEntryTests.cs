using CleanSweep.Core.Backup;
using CleanSweep.Core.Integrity;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.RegistryCleaning;
using CleanSweep.Core.Storage;
using CleanSweep.Core.Uninstall;
using Microsoft.Win32;

namespace CleanSweep.Core.Tests;

/// <summary>
/// 2026-09-30 真机反馈："自动更新不生效"（更新来源默认为空，从不检查）与"卸载程序不存在怎么办"（登记项无法移除）。
/// </summary>
public sealed class UpdateSourceAndRemoveEntryTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();

    public void Dispose()
    {
        _db.Dispose();
        _t.Dispose();
    }

    [Fact]
    public void Empty_setting_resolves_to_official_repo_with_mirror_fallback()
    {
        foreach (var setting in new[] { null, "", "   " })
        {
            var s = UpdateSources.Resolve(setting);
            Assert.NotNull(s);
            Assert.Equal("https://raw.githubusercontent.com/boooooommmmmm/FatalCleaner/main", s!.DataBaseUrl);
            Assert.Equal("https://raw.githubusercontent.com/boooooommmmmm/FatalCleaner/main/release/latest.json", s.ReleaseInfoUrl);
            Assert.Equal("https://cdn.jsdelivr.net/gh/boooooommmmmm/FatalCleaner@main", s.FallbackDataBaseUrl);
            Assert.Equal("https://cdn.jsdelivr.net/gh/boooooommmmmm/FatalCleaner@main/release/latest.json", s.FallbackReleaseInfoUrl);
        }
        var branch = UpdateSources.Resolve("someone/Fork@dev")!;
        Assert.Equal("https://cdn.jsdelivr.net/gh/someone/Fork@dev", branch.FallbackDataBaseUrl);
        Assert.Equal("github.com/someone/Fork@dev", branch.Display);

        var https = UpdateSources.Resolve("https://example.com/cleansweep/")!;
        Assert.Equal("https://example.com/cleansweep", https.DataBaseUrl);
        Assert.Null(https.FallbackDataBaseUrl);
        Assert.Null(https.FallbackReleaseInfoUrl);

        Assert.Null(UpdateSources.Resolve("not a repo"));
        Assert.Null(UpdateSources.Resolve("a/b/c"));
    }

    [Theory]
    [InlineData("boooooommmmmm/Cleaner", "main")]
    [InlineData(" boooooommmmmm/cleaner/ ", "main")]
    [InlineData("boooooommmmmm/Cleaner@dev", "dev")]
    public void Legacy_official_repository_resolves_to_renamed_repository(string setting, string branch)
    {
        var source = UpdateSources.Resolve(setting)!;
        Assert.Equal($"https://raw.githubusercontent.com/boooooommmmmm/FatalCleaner/{branch}", source.DataBaseUrl);
        Assert.Equal($"https://cdn.jsdelivr.net/gh/boooooommmmmm/FatalCleaner@{branch}/release/latest.json", source.FallbackReleaseInfoUrl);
        Assert.Equal("https://raw.githubusercontent.com/someone/Cleaner/main", UpdateSources.Resolve("someone/Cleaner")!.DataBaseUrl);
        Assert.Equal("https://example.com/Cleaner", UpdateSources.Resolve("https://example.com/Cleaner")!.DataBaseUrl);
    }

    [Theory]
    [InlineData("获取发布信息失败：No such host is known", true)]
    [InlineData("获取发布信息超时", true)]
    [InlineData("下载清单失败：连接被拒绝", true)]
    [InlineData("更新超时（超过 5 分钟）", true)]
    [InlineData("发布信息无效：签名不匹配", false)]
    [InlineData("更新来源里还没有发布信息（release/latest.json）", false)]
    [InlineData("已是最新版本（当前 0.16.0，发布 0.16.0）", false)]
    [InlineData("远端清单：签名无效", false)]
    public void Only_network_failures_trigger_mirror_retry(string message, bool network)
    {
        Assert.Equal(network, UpdateSources.IsNetworkFailure(message));
    }

    private static InstalledApp RegistryApp(string key, string uninstall, string? location = null) => new()
    {
        Id = "app", Name = "Gone App", Source = AppSource.Registry, RegistryKey = key, View = RegistryView.Registry64,
        UninstallString = uninstall, InstallLocation = location,
    };

    [Fact]
    public void UninstallerMissing_only_for_registry_entries_whose_absolute_exe_is_gone()
    {
        var present = _t.File(Path.Combine(_t.Root, "app", "unins000.exe"), "x");
        var gone = Path.Combine(_t.Root, "app", "nope.exe");
        const string key = @"HKCU\Software\CleanSweepTests\Uninstall\GoneApp";

        Assert.True(Uninstaller.UninstallerMissing(RegistryApp(key, $"\"{gone}\" /SILENT"), out var exe));
        Assert.Equal(gone, exe, ignoreCase: true);
        Assert.False(Uninstaller.UninstallerMissing(RegistryApp(key, $"\"{present}\" /SILENT"), out _));
        Assert.False(Uninstaller.UninstallerMissing(RegistryApp(key, "MsiExec.exe /X{11111111-2222-3333-4444-555555555555}"), out _));
        Assert.False(Uninstaller.UninstallerMissing(RegistryApp(key, "unins000.exe"), out _)); // 相对路径：无法判断
        Assert.False(Uninstaller.UninstallerMissing(RegistryApp(key, ""), out _));
        Assert.False(Uninstaller.UninstallerMissing(new InstalledApp { Id = "p", Name = "Portable", Source = AppSource.Portable, UninstallString = $"\"{gone}\"" }, out _));
        Assert.False(Uninstaller.UninstallerMissing(new InstalledApp { Id = "u", Name = "Uwp", Source = AppSource.Uwp, PackageFullName = "A.B_1.0.0.0_x64__abcdefghijklm", UninstallString = $"\"{gone}\"" }, out _));

        // 卸载页：卸载命令构造失败且卸载程序缺失 → 才允许移除登记项
        Assert.Null(Uninstaller.BuildCommand(RegistryApp(key, $"\"{gone}\""), quiet: false, out var error));
        Assert.Contains("卸载程序不存在", error);
    }

    [Fact]
    public void RemoveEntry_deletes_only_that_uninstall_key_with_backup_and_records_history()
    {
        const string testRoot = @"Software\CleanSweepTests\RemoveEntry";
        using var root = Registry.CurrentUser.CreateSubKey(testRoot)!;
        try
        {
            var gone = Path.Combine(_t.Root, "app", "nope.exe");
            using (var k = root.CreateSubKey(@"Uninstall\GoneApp")!) { k.SetValue("DisplayName", "Gone App"); k.SetValue("UninstallString", $"\"{gone}\" /S"); }
            using (var k = root.CreateSubKey(@"Uninstall\OtherApp")!) { k.SetValue("DisplayName", "Other"); }

            var keyPath = $@"HKCU\{testRoot}\Uninstall\GoneApp";
            var history = new UninstallHistory(_db);
            var log = new OperationLog(_db);
            var uninstaller = new Uninstaller(new AppInventory(_t.Env), history, log);
            var ops = new RegistryOps(new RegistryBackup(_db, Path.Combine(_t.Root, "Backups")));

            var backup = uninstaller.RemoveEntry(RegistryApp(keyPath, $"\"{gone}\" /S"), ops);

            Assert.False(string.IsNullOrEmpty(backup));
            Assert.True(File.Exists(Path.Combine(_t.Root, "Backups", backup)));
            Assert.Null(root.OpenSubKey(@"Uninstall\GoneApp"));
            Assert.NotNull(root.OpenSubKey(@"Uninstall\OtherApp"));
            Assert.Contains(history.List(), r => r.Name == "Gone App" && r.DetectedBy == "entry-removed");
            Assert.Contains(log.GetOperations(), o => o.Action == "remove-entry" && o.Success && o.Target == keyPath);

            // 卸载程序还在的条目拒绝移除
            var present = _t.File(Path.Combine(_t.Root, "app", "unins000.exe"), "x");
            Assert.Throws<InvalidOperationException>(() => uninstaller.RemoveEntry(RegistryApp($@"HKCU\{testRoot}\Uninstall\OtherApp", $"\"{present}\""), ops));
            Assert.NotNull(root.OpenSubKey(@"Uninstall\OtherApp"));
        }
        finally
        {
            Registry.CurrentUser.DeleteSubKeyTree(testRoot, throwOnMissingSubKey: false);
        }
    }
}
