using CleanSweep.Core.Inventory;
using CleanSweep.Core.Model;
using CleanSweep.Core.Residue;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;
using CleanSweep.Core.Uninstall;

namespace CleanSweep.Core.Tests;

public sealed class NameKeyTests
{
    [Theory]
    [InlineData("Visual Studio Code", "visualstudiocode")]
    [InlineData("IntelliJ IDEA 2023.1", "intellijidea")]
    [InlineData("7-Zip 23.01 (x64)", "7zip")]
    [InlineData("Google Chrome", "googlechrome")]
    [InlineData("Gradle Inc.", "gradle")]
    [InlineData("Python 3.12.1 (64-bit)", "python")]
    [InlineData("", "")]
    public void Normalizes(string input, string expected) => Assert.Equal(expected, NameKey.Normalize(input));

    [Fact]
    public void Matches_prefix_only_when_long_enough()
    {
        Assert.True(NameKey.Matches("IntelliJIdea2023.1", "IntelliJ IDEA"));
        Assert.True(NameKey.Matches("JetBrains", "JetBrains s.r.o."));
        Assert.False(NameKey.Matches("Code", "Visual Studio Code"));
        Assert.False(NameKey.Matches("Foo", "Foobar"));
        Assert.False(NameKey.Matches("", "x"));
    }
}

public sealed class FingerprintTests : IDisposable
{
    private readonly TestEnv _t = new();
    public void Dispose() => _t.Dispose();

    [Fact]
    public void Loads_valid_and_rejects_invalid()
    {
        var db = AppFingerprintDb.FromJson("""
            { "fingerprints": [
              { "id": "ok", "app": "Ok", "paths": ["%UserProfile%\\.ok"], "flags": ["devCache"], "cachePaths": ["%UserProfile%\\.ok\\cache"] },
              { "id": "badflag", "app": "B", "paths": ["%UserProfile%\\.b"], "flags": ["nope"] },
              { "id": "badcache", "app": "C", "paths": ["%UserProfile%\\.c"], "cachePaths": ["%UserProfile%\\.other"] },
              { "id": "badpath", "app": "D", "paths": ["C:\\Windows\\System32"] },
              { "id": "dotdot", "app": "E", "paths": ["%UserProfile%\\..\\x"] },
              { "id": "baddetect", "app": "F", "paths": ["%UserProfile%\\.f"], "detect": { "anyOf": [ { "command": "a b" } ] } },
              { "id": "ok", "app": "Dup", "paths": ["%UserProfile%\\.dup"] }
            ] }
            """, "t.json", _t.Guard);

        Assert.Single(db.Fingerprints);
        Assert.Equal(6, db.Rejected.Count);
        Assert.Contains(db.Rejected, r => r.RuleId == "badflag" && r.Reason.Contains("flag"));
        Assert.Contains(db.Rejected, r => r.RuleId == "badcache" && r.Reason.Contains("paths 之下"));
        Assert.Contains(db.Rejected, r => r.RuleId == "badpath");
        Assert.Contains(db.Rejected, r => r.RuleId == "dotdot");
        Assert.Contains(db.Rejected, r => r.RuleId == "baddetect");
        Assert.Contains(db.Rejected, r => r.Reason.Contains("重复"));
    }

    [Fact]
    public void Bundled_fingerprints_all_load()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "fingerprints");
        var db = AppFingerprintDb.LoadDirectory(dir, _t.Guard);
        Assert.Empty(db.Rejected);
        Assert.True(db.Fingerprints.Count >= 40);
    }

    [Fact]
    public void Detect_uses_inventory_and_environment()
    {
        var db = AppFingerprintDb.FromJson("""
            { "fingerprints": [
              { "id": "byname", "app": "A", "paths": ["%UserProfile%\\.a"], "detect": { "anyOf": [ { "installedName": "Alpha Tool" } ] } },
              { "id": "bydir", "app": "B", "paths": ["%UserProfile%\\.b"], "detect": { "anyOf": [ { "directory": "%LocalAppData%\\BetaHome" } ] } },
              { "id": "nodetect", "app": "C", "paths": ["%UserProfile%\\.c"] }
            ] }
            """, "t.json", _t.Guard);
        var inv = Snapshot(new InstalledApp { Id = "1", Name = "Alpha Tool 2.0", Source = AppSource.Registry });

        Assert.True(AppFingerprintDb.IsInstalled(db.Fingerprints[0], inv, _t.Env));
        Assert.False(AppFingerprintDb.IsInstalled(db.Fingerprints[1], inv, _t.Env));
        _t.Dir(Path.Combine(_t.Vars["LocalAppData"], "BetaHome"));
        Assert.True(AppFingerprintDb.IsInstalled(db.Fingerprints[1], inv, _t.Env));
        Assert.Null(AppFingerprintDb.IsInstalled(db.Fingerprints[2], inv, _t.Env));
    }

    [Fact]
    public void Publisher_match_is_not_reverse_prefix()
    {
        var inv = Snapshot(new InstalledApp { Id = "1", Name = "Unity Hub", Publisher = "Unity Technologies", Source = AppSource.Registry },
            new InstalledApp { Id = "2", Name = "IntelliJ IDEA", Publisher = "JetBrains s.r.o.", Source = AppSource.Registry });
        Assert.True(inv.IsPublisher("JetBrains"));
        Assert.True(inv.IsPublisher("Unity"));
        Assert.False(inv.IsPublisher("UnityHubWebGLHost"));
        Assert.False(inv.IsPublisher("Uni"));
    }

    internal static InventorySnapshot Snapshot(params InstalledApp[] apps) => new()
    {
        Apps = apps,
        TakenUtc = DateTime.UtcNow,
        RegistryCount = 50,
        UwpCount = apps.Count(a => a.Source == AppSource.Uwp),
        RunningExecutables = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
    };
}

public sealed class ResidueScannerTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();

    public void Dispose()
    {
        _db.Dispose();
        _t.Dispose();
    }

    private static readonly DateTime Old = DateTime.UtcNow.AddDays(-200);
    private static readonly DateTime Mid = DateTime.UtcNow.AddDays(-100);

    private string Dir(string relativeToRoot, DateTime? lastWrite = null, bool withFile = true)
    {
        var d = _t.Dir(relativeToRoot);
        if (withFile)
        {
            var f = _t.File(Path.Combine(d, "data.bin"), "1234");
            if (lastWrite is not null) File.SetLastWriteTimeUtc(f, lastWrite.Value);
        }
        if (lastWrite is not null) Directory.SetLastWriteTimeUtc(d, lastWrite.Value);
        return d;
    }

    private async Task<IReadOnlyList<ScanItem>> Scan(InventorySnapshot inv, AppFingerprintDb? fps = null, UninstallHistory? history = null, ResidueOptions? opts = null, IReadOnlyList<CleanRule>? rules = null)
    {
        var inventory = new AppInventory(_t.Env);
        inventory.UseSnapshot(inv);
        var scanner = new ResidueScanner(inventory, fps ?? AppFingerprintDb.Empty(), history, opts ?? new ResidueOptions());
        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist(), Rules = rules ?? Array.Empty<CleanRule>() };
        return await scanner.ScanAsync(ctx, null, default);
    }

    [Fact]
    public async Task Installed_app_directory_is_active()
    {
        Dir(Path.Combine(_t.Vars["AppData"], "Alpha Tool"), Old);
        var items = await Scan(FingerprintTests.Snapshot(new InstalledApp { Id = "1", Name = "Alpha Tool", Source = AppSource.Registry }));
        Assert.Empty(items);
    }

    [Fact]
    public async Task Uninstall_history_marks_directory_confirmed_even_if_recent()
    {
        var dir = Dir(Path.Combine(_t.Vars["AppData"], "GoneApp"));
        var history = new UninstallHistory(_db);
        history.Record(new InstalledApp { Id = "x", Name = "GoneApp 3.1", Source = AppSource.Registry }, "test");

        var items = await Scan(FingerprintTests.Snapshot(), history: history);

        var item = Assert.Single(items);
        Assert.Equal(dir, item.Path, ignoreCase: true);
        Assert.Equal(RiskLevel.Safe, item.Risk);
        Assert.Equal(ItemKind.Directory, item.Kind);
        Assert.Contains("卸载记录", item.Description);
        Assert.NotNull(item.DirectoryFingerprint);
        Assert.StartsWith("GoneApp", item.Group);
    }

    [Fact]
    public async Task Unattributed_directories_are_classified_by_age()
    {
        var old = Dir(Path.Combine(_t.Vars["LocalAppData"], "OldThing"), Old);
        var mid = Dir(Path.Combine(_t.Vars["LocalAppData"], "MidThing"), Mid);
        Dir(Path.Combine(_t.Vars["LocalAppData"], "FreshThing"));

        var items = await Scan(FingerprintTests.Snapshot());

        Assert.Equal(2, items.Count);
        var oldItem = items.Single(i => i.Path!.Equals(old, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(RiskLevel.Confirm, oldItem.Risk);
        Assert.False(oldItem.DefaultSelected);
        var midItem = items.Single(i => i.Path!.Equals(mid, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(RiskLevel.NotRecommended, midItem.Risk);
    }

    [Fact]
    public async Task Empty_old_directory_is_safe_residue()
    {
        var dir = Dir(Path.Combine(_t.Vars["LocalAppData"], "EmptyOld"), DateTime.UtcNow.AddDays(-40), withFile: false);
        var items = await Scan(FingerprintTests.Snapshot());
        var item = Assert.Single(items);
        Assert.Equal(dir, item.Path, ignoreCase: true);
        Assert.Equal(RiskLevel.Safe, item.Risk);
        Assert.Equal(0, item.SizeBytes);
    }

    [Fact]
    public async Task System_and_excluded_directories_are_never_listed()
    {
        Dir(Path.Combine(_t.Vars["LocalAppData"], "Microsoft", "Windows", "Explorer"), Old);
        Dir(Path.Combine(_t.Vars["LocalAppData"], "Microsoft", "SomeOldThing"), Old);
        Dir(Path.Combine(_t.Vars["LocalAppData"], "Temp", "x"), Old);
        Dir(Path.Combine(_t.Vars["LocalAppData"], "ConnectedDevicesPlatform"), Old);
        Dir(Path.Combine(_t.Vars["AppData"], "Microsoft", "Crypto"), Old);
        Dir(Path.Combine(_t.Vars["UserProfile"], ".ssh"), Old);

        var items = await Scan(FingerprintTests.Snapshot());
        Assert.Empty(items);
    }

    [Fact]
    public async Task Junction_under_appdata_is_skipped()
    {
        var target = _t.Dir("elsewhere");
        _t.File(Path.Combine(target, "secret.txt"));
        var link = Path.Combine(_t.Vars["LocalAppData"], "LinkedOld");
        if (!TestEnv.TryCreateJunction(link, target)) return;
        try
        {
            Directory.SetLastWriteTimeUtc(target, Old);
            var items = await Scan(FingerprintTests.Snapshot());
            Assert.Empty(items);
        }
        finally
        {
            Directory.Delete(link);
        }
    }

    [Fact]
    public async Task Fingerprint_not_installed_is_confirmed_with_flag_risk()
    {
        var gradle = Dir(Path.Combine(_t.Vars["UserProfile"], ".gradle"));
        var jb = Dir(Path.Combine(_t.Vars["AppData"], "JetBrains"));
        var fps = AppFingerprintDb.FromJson("""
            { "fingerprints": [
              { "id": "gradle", "app": "Gradle", "paths": ["%UserProfile%\\.gradle"], "detect": { "anyOf": [ { "command": "cleansweep-no-such-command-xyz" } ] } },
              { "id": "jetbrains", "app": "JetBrains IDE", "paths": ["%AppData%\\JetBrains"], "flags": ["license"], "detect": { "anyOf": [ { "installedPublisher": "JetBrains" } ] } }
            ] }
            """, "t.json", _t.Guard);

        var items = await Scan(FingerprintTests.Snapshot(), fps);

        Assert.Single(items);
        Assert.DoesNotContain(items, i => i.Path!.Equals(gradle, StringComparison.OrdinalIgnoreCase));
        var j = items.Single(i => i.Path!.Equals(jb, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(RiskLevel.Confirm, j.Risk);
        Assert.Contains("许可证", j.Description);
    }

    [Fact]
    public async Task Fingerprint_installed_is_not_listed()
    {
        Dir(Path.Combine(_t.Vars["AppData"], "JetBrains"), Old);
        var fps = AppFingerprintDb.FromJson("""
            { "fingerprints": [ { "id": "jetbrains", "app": "JetBrains IDE", "paths": ["%AppData%\\JetBrains"], "detect": { "anyOf": [ { "installedPublisher": "JetBrains" } ] } } ] }
            """, "t.json", _t.Guard);
        var inv = FingerprintTests.Snapshot(new InstalledApp { Id = "1", Name = "IntelliJ IDEA 2024.1", Publisher = "JetBrains s.r.o.", Source = AppSource.Registry });

        Assert.Empty(await Scan(inv, fps));
    }

    [Fact]
    public async Task Vendor_directory_descends_to_products()
    {
        var vendor = Path.Combine(_t.Vars["AppData"], "JetBrains");
        var oldProduct = Dir(Path.Combine(vendor, "PyCharm2021.3"), Old);
        Dir(Path.Combine(vendor, "IntelliJIdea2024.1"));
        var inv = FingerprintTests.Snapshot(new InstalledApp { Id = "1", Name = "IntelliJ IDEA 2024.1", Publisher = "JetBrains s.r.o.", Source = AppSource.Registry });

        var items = await Scan(inv);

        var item = Assert.Single(items);
        Assert.Equal(oldProduct, item.Path, ignoreCase: true);
        Assert.Equal(RiskLevel.Confirm, item.Risk);
    }

    [Fact]
    public async Task Packages_use_uwp_inventory_and_skip_system_packages()
    {
        var pk = Path.Combine(_t.Vars["LocalAppData"], "Packages");
        var gone = Dir(Path.Combine(pk, "SomeVendor.GoneApp_abcdefghijklm"));
        Dir(Path.Combine(pk, "SomeVendor.LiveApp_abcdefghijklm"));
        Dir(Path.Combine(pk, "Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy"), Old);
        Dir(Path.Combine(pk, "MicrosoftWindows.Client.CBS_cw5n1h2txyewy"), Old);

        var live = new InstalledApp { Id = "uwp:live", Name = "Live", Source = AppSource.Uwp, PackageFamilyName = "SomeVendor.LiveApp_abcdefghijklm", PackageFullName = "SomeVendor.LiveApp_1.0.0.0_x64__abcdefghijklm" };
        var items = await Scan(FingerprintTests.Snapshot(live));

        var item = Assert.Single(items);
        Assert.Equal(gone, item.Path, ignoreCase: true);
        Assert.Equal(RiskLevel.Safe, item.Risk);
        Assert.Contains("应用商店包", item.Description);
    }

    [Fact]
    public async Task Packages_are_skipped_when_uwp_inventory_is_empty()
    {
        Dir(Path.Combine(_t.Vars["LocalAppData"], "Packages", "SomeVendor.GoneApp_abcdefghijklm"));
        var items = await Scan(FingerprintTests.Snapshot());
        Assert.Empty(items);
    }

    [Fact]
    public async Task Rule_covered_paths_are_left_to_rules()
    {
        Dir(Path.Combine(_t.Vars["AppData"], "discord"), Old);
        var rules = new RuleLoader(_t.Guard).LoadJson("""
            { "rules": [ { "id": "discord", "app": "Discord", "category": "app", "detect": { "anyOf": [ { "directory": "%LocalAppData%\\Discord" } ] },
              "targets": [ { "path": "%AppData%\\discord", "kind": "directory", "risk": "high", "when": "uninstalled", "description": "d" } ] } ] }
            """, "t.json").Rules;

        var heuristics = await Scan(FingerprintTests.Snapshot(), rules: rules);
        Assert.Empty(heuristics);

        // 规则扫描器接手：应用未安装 → 高风险条目
        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist(), Rules = rules };
        var fromRules = await RuleScanner.Residue().ScanAsync(ctx, null, default);
        var item = Assert.Single(fromRules);
        Assert.Equal(RiskLevel.High, item.Risk);
        Assert.NotNull(item.DirectoryFingerprint);
    }

    [Fact]
    public async Task Whitelisted_directory_is_skipped()
    {
        var dir = Dir(Path.Combine(_t.Vars["LocalAppData"], "OldThing"), Old);
        var inventory = new AppInventory(_t.Env);
        inventory.UseSnapshot(FingerprintTests.Snapshot());
        var wl = new Whitelist();
        wl.AddPath(dir);
        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = wl };
        var items = await new ResidueScanner(inventory, AppFingerprintDb.Empty(), null, new ResidueOptions()).ScanAsync(ctx, null, default);
        Assert.Empty(items);
    }

    [Fact]
    public async Task Programs_directory_is_only_judged_by_activity()
    {
        var programs = Path.Combine(_t.Vars["LocalAppData"], "Programs");
        var stale = Dir(Path.Combine(programs, "OldPortable"), Old);
        Dir(Path.Combine(programs, "FreshPortable"));
        var items = await Scan(FingerprintTests.Snapshot());
        var item = Assert.Single(items);
        Assert.Equal(stale, item.Path, ignoreCase: true);
        Assert.Equal(RiskLevel.Confirm, item.Risk);
    }

    [Fact]
    public async Task Targeted_scan_filters_to_one_app()
    {
        Dir(Path.Combine(_t.Vars["AppData"], "GoneApp"));
        Dir(Path.Combine(_t.Vars["AppData"], "OtherOld"), Old);
        var history = new UninstallHistory(_db);
        history.Record(new InstalledApp { Id = "x", Name = "GoneApp", Source = AppSource.Registry }, "test");

        var items = await Scan(FingerprintTests.Snapshot(), history: history, opts: new ResidueOptions { OnlyAppName = "GoneApp" });
        var item = Assert.Single(items);
        Assert.EndsWith("GoneApp", item.Path, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Documents_fingerprint_is_high_risk_only()
    {
        var saves = Dir(Path.Combine(_t.Vars["UserProfile"], "Documents", "My Games"), Old);
        var fps = AppFingerprintDb.FromJson("""
            { "fingerprints": [ { "id": "my-games", "app": "游戏存档", "paths": ["%UserProfile%\\Documents\\My Games"], "flags": ["gameSaves"] } ] }
            """, "t.json", _t.Guard);
        var items = await Scan(FingerprintTests.Snapshot(), fps);
        var item = Assert.Single(items);
        Assert.Equal(saves, item.Path, ignoreCase: true);
        Assert.Equal(RiskLevel.High, item.Risk);
        Assert.False(item.DefaultSelected);
        Assert.Contains("存档", item.Description);
    }

    [Fact]
    public async Task Residue_items_clean_through_engine_as_directories()
    {
        var dir = Dir(Path.Combine(_t.Vars["AppData"], "GoneApp"));
        var history = new UninstallHistory(_db);
        history.Record(new InstalledApp { Id = "x", Name = "GoneApp", Source = AppSource.Registry }, "test");
        var items = await Scan(FingerprintTests.Snapshot(), history: history);

        var q = new Cleaning.Quarantine(_db, null, _ => Path.Combine(_t.Root, "Q"), _t.Guard);
        var report = await new Cleaning.CleanEngine(_t.Guard, q, new OperationLog(_db), new Cleaning.NullPreActionRunner()).CleanAsync(items, null, default);

        Assert.Empty(report.Failures);
        Assert.Equal(1, report.DirectoriesQuarantined);
        Assert.False(Directory.Exists(dir));
        var entry = Assert.Single(q.ListActive());
        q.Restore(entry.Id);
        Assert.True(Directory.Exists(dir));
    }
}

public sealed class DevCacheScannerTests : IDisposable
{
    private readonly TestEnv _t = new();
    public void Dispose() => _t.Dispose();

    [Fact]
    public async Task Protects_dependency_caches_but_lists_stale_node_modules_for_confirmation()
    {
        var caches = _t.Dir(Path.Combine(_t.Vars["UserProfile"], ".gradle", "caches"));
        _t.File(Path.Combine(caches, "a.jar"), "12345");
        _t.File(Path.Combine(_t.Vars["UserProfile"], ".gradle", "gradle.properties"), "cfg");

        var project = _t.Dir("proj");
        var nm = _t.Dir(Path.Combine(project, "node_modules", "left-pad"));
        _t.File(Path.Combine(nm, "index.js"), "x");
        _t.File(Path.Combine(project, "package.json"), "{}");
        foreach (var f in Directory.EnumerateFiles(project, "*", SearchOption.AllDirectories)) File.SetLastWriteTimeUtc(f, DateTime.UtcNow.AddDays(-90));
        Directory.SetLastWriteTimeUtc(project, DateTime.UtcNow.AddDays(-90));

        var fresh = _t.Dir("fresh");
        _t.File(Path.Combine(fresh, "node_modules", "x", "i.js"), "x");
        _t.File(Path.Combine(fresh, "index.js"), "x");

        var fps = AppFingerprintDb.FromJson("""
            { "fingerprints": [ { "id": "gradle", "app": "Gradle", "paths": ["%UserProfile%\\.gradle"], "flags": ["devCache"], "cachePaths": ["%UserProfile%\\.gradle\\caches"] } ] }
            """, "t.json", _t.Guard);
        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist() };
        var items = await new DevCacheScanner(fps, new[] { project, fresh }, 30).ScanAsync(ctx, null, default);

        Assert.Single(items);
        Assert.DoesNotContain(items, i => i.Group == "Gradle");
        var node = items.Single(i => i.Group.Contains("node_modules"));
        Assert.Equal(Path.Combine(project, "node_modules"), node.Path, ignoreCase: true);
        Assert.Equal(RiskLevel.Confirm, node.Risk);
    }
}

public sealed class UninstallerTests
{
    private static InstalledApp Reg(string? uninstall, string? quiet = null) => new()
    {
        Id = "reg:x", Name = "X", Source = AppSource.Registry, UninstallString = uninstall, QuietUninstallString = quiet,
    };

    [Theory]
    [InlineData("MsiExec.exe /I{6F2E2D1B-9F1C-4A3E-8A1D-1234567890AB}")]
    [InlineData("msiexec /x {6F2E2D1B-9F1C-4A3E-8A1D-1234567890AB} /qn REBOOT=ReallySuppress")]
    [InlineData("\"C:\\Windows\\System32\\msiexec.exe\" /X{6F2E2D1B-9F1C-4A3E-8A1D-1234567890AB}")]
    public void Msi_is_rewritten_to_fixed_form(string raw)
    {
        var cmd = Uninstaller.BuildCommand(Reg(raw), quiet: false, out var error);
        Assert.NotNull(cmd);
        Assert.Null(error);
        Assert.Equal("msi", cmd!.Kind);
        Assert.EndsWith("msiexec.exe", cmd.Exe, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("/x {6F2E2D1B-9F1C-4A3E-8A1D-1234567890AB}", cmd.Args);

        var quiet = Uninstaller.BuildCommand(Reg(raw), quiet: true, out _)!;
        Assert.Contains("/qb-", quiet.Args);
    }

    [Fact]
    public void Msi_without_product_code_is_rejected()
    {
        Assert.Null(Uninstaller.BuildCommand(Reg("msiexec.exe /x SomethingElse"), false, out var error));
        Assert.Contains("产品代码", error);
    }

    [Fact]
    public void Missing_uninstaller_is_rejected()
    {
        Assert.Null(Uninstaller.BuildCommand(Reg(@"""C:\Program Files\Nope\unins000.exe"" /SILENT"), false, out var error));
        Assert.Contains("不存在", error);
        Assert.Null(Uninstaller.BuildCommand(Reg(null), false, out error));
        Assert.Contains("没有卸载命令", error);
    }

    [Fact]
    public void Existing_exe_is_used_with_its_arguments()
    {
        var cmd = System.Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\cmd.exe");
        var result = Uninstaller.BuildCommand(Reg($"\"{cmd}\" /c echo uninstall"), false, out _);
        Assert.NotNull(result);
        Assert.Equal(cmd, result!.Exe, ignoreCase: true);
        Assert.Equal("/c echo uninstall", result.Args);
        Assert.Equal("exe", result.Kind);
    }

    [Fact]
    public void Quiet_prefers_quiet_string()
    {
        var cmd = System.Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\cmd.exe");
        var result = Uninstaller.BuildCommand(Reg($"\"{cmd}\" /c loud", $"\"{cmd}\" /c quiet"), quiet: true, out _)!;
        Assert.Equal("/c quiet", result.Args);
    }

    [Fact]
    public void Uwp_requires_valid_full_name_and_non_system()
    {
        var ok = new InstalledApp { Id = "uwp:a", Name = "A", Source = AppSource.Uwp, PackageFullName = "SpotifyAB.SpotifyMusic_1.245.0.0_x64__zpdnekdrzrea0", PackageFamilyName = "SpotifyAB.SpotifyMusic_zpdnekdrzrea0" };
        var cmd = Uninstaller.BuildCommand(ok, false, out _);
        Assert.NotNull(cmd);
        Assert.Equal("uwp", cmd!.Kind);
        Assert.Contains("Remove-AppxPackage -Package 'SpotifyAB.SpotifyMusic_1.245.0.0_x64__zpdnekdrzrea0'", cmd.Args);

        var bad = ok with { PackageFullName = "Evil_1.0_x64__abc'; Remove-Item C:\\ -Recurse #" };
        Assert.Null(Uninstaller.BuildCommand(bad, false, out var error));
        Assert.Contains("格式无效", error);

        var sys = ok with { IsSystemComponent = true };
        Assert.Null(Uninstaller.BuildCommand(sys, false, out error));
        Assert.Contains("系统组件", error);
    }

    [Fact]
    public void Portable_has_no_uninstaller()
    {
        var p = new InstalledApp { Id = "portable:x", Name = "X", Source = AppSource.Portable, InstallLocation = @"C:\x" };
        Assert.Null(Uninstaller.BuildCommand(p, false, out var error));
        Assert.Contains("便携", error);
    }

    [Fact]
    public void Bloatware_detection()
    {
        Assert.True(Bloatware.IsKnown(new InstalledApp { Id = "u", Name = "Solitaire", Source = AppSource.Uwp, PackageFamilyName = "Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe" }));
        Assert.False(Bloatware.IsKnown(new InstalledApp { Id = "u", Name = "Terminal", Source = AppSource.Uwp, PackageFamilyName = "Microsoft.WindowsTerminal_8wekyb3d8bbwe" }));
        Assert.True(Bloatware.IsKnown(new InstalledApp { Id = "r", Name = "McAfee LiveSafe", Source = AppSource.Registry }));
    }
}

public sealed class InstallMonitorTests
{
    [Fact]
    public void Diff_reports_new_apps_dirs_services_and_run_entries()
    {
        var before = new MonitorSnapshot { TakenUtc = DateTime.UtcNow.AddMinutes(-5) };
        before.Apps["a"] = "A";
        before.Directories[@"C:\Program Files\A"] = DateTime.UtcNow.AddDays(-1);
        before.Services.Add("svcA");
        before.RunEntries["HKCU\\Run|Registry64|A"] = "a.exe";

        var after = new MonitorSnapshot { TakenUtc = DateTime.UtcNow };
        after.Apps["b"] = "B";
        after.Directories[@"C:\Program Files\A"] = DateTime.UtcNow;
        after.Directories[@"C:\Program Files\B"] = DateTime.UtcNow;
        after.Services.Add("svcA");
        after.Services.Add("svcB");
        after.RunEntries["HKCU\\Run|Registry64|A"] = "a.exe";
        after.RunEntries["HKCU\\Run|Registry64|B"] = "b.exe";

        var diff = InstallMonitor.Diff(before, after);
        Assert.Equal(new[] { "B" }, diff.NewApps);
        Assert.Equal(new[] { "A" }, diff.RemovedApps);
        Assert.Equal(new[] { @"C:\Program Files\B" }, diff.NewDirectories);
        Assert.Equal(new[] { @"C:\Program Files\A" }, diff.ModifiedDirectories);
        Assert.Equal(new[] { "svcB" }, diff.NewServices);
        Assert.Single(diff.NewRunEntries);
        Assert.Equal("B", diff.NewRunEntries[0].Name);
        Assert.False(diff.IsEmpty);
    }
}

public sealed class InventoryRealEnvironmentTests
{
    [Fact]
    public void Scans_real_machine_read_only()
    {
        var errors = new List<string>();
        var inv = new AppInventory(new Core.Environment.CurrentUserEnvironmentResolver()) { OnSourceError = (s, e) => errors.Add(s + ": " + e.Message) };
        var snap = inv.Scan();
        Assert.True(snap.RegistryReliable, "注册表卸载项应能读到；错误：" + string.Join("; ", errors));
        Assert.All(snap.Apps, a => Assert.False(string.IsNullOrWhiteSpace(a.Name)));
        Assert.Equal(snap.Apps.Count, snap.Apps.Select(a => a.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        // 至少能认出一个微软应用
        Assert.Contains(snap.Apps, a => a.IsMicrosoft);
    }

    [Fact]
    public void Parses_install_date_formats()
    {
        Assert.Equal(new DateTime(2024, 3, 5), AppInventory.ParseInstallDate("20240305")!.Value.Date);
        Assert.Null(AppInventory.ParseInstallDate(""));
        Assert.Null(AppInventory.ParseInstallDate("garbage"));
        Assert.Equal("Foo_pub", AppInventory.ToFamilyName("Foo_1.0.0.0_x64__pub"));
        Assert.Equal("SpotifyAB", AppInventory.PublisherFromPackageName("SpotifyAB.SpotifyMusic"));
    }
}
