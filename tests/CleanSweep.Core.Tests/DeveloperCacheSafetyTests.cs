using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Environment;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Model;
using CleanSweep.Core.Residue;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Tests;

public sealed class DeveloperCacheSafetyTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly CleanSweepDb _db = CleanSweepDb.InMemory();
    private string Package => Path.Combine(_t.Vars["UserProfile"], @".nuget\packages\microsoft.netcore.app.ref\6.0.13\ref\net6.0\System.Runtime.dll");
    private string QuarantineRoot => Path.Combine(_t.Root, "Quarantine");
    private ScanContext Context(IReadOnlyList<CleanRule>? rules = null) =>
        new() { Env = _t.Env, Guard = _t.Guard, Whitelist = new Whitelist(), Rules = rules ?? [] };

    [Theory]
    [InlineData("UserProfile", @".nuget\packages")]
    [InlineData("UserProfile", @".m2\repository")]
    [InlineData("UserProfile", @".gradle\caches")]
    [InlineData("UserProfile", @".gradle\wrapper\dists")]
    [InlineData("UserProfile", @".cargo\registry\src")]
    [InlineData("UserProfile", @".cargo\git\checkouts")]
    [InlineData("UserProfile", @"go\pkg\mod")]
    [InlineData("UserProfile", @".templateengine\packages")]
    [InlineData("UserProfile", @".dotnet\tools")]
    [InlineData("UserProfile", @".rustup\toolchains")]
    [InlineData("UserProfile", @"miniconda3\pkgs")]
    [InlineData("UserProfile", @".conda\envs")]
    [InlineData("LocalAppData", @"pnpm\store")]
    [InlineData("LocalAppData", @"Pub\Cache")]
    [InlineData("LocalAppData", @"deno\npm")]
    [InlineData("LocalAppData", @"pypoetry\Cache\virtualenvs")]
    [InlineData("LocalAppData", @"uv\cache")]
    [InlineData("LocalAppData", @"Cypress\Cache")]
    [InlineData("LocalAppData", @"Android\Sdk")]
    public void Dependency_roots_children_and_parents_are_protected_but_restore_is_allowed(string variable, string relative)
    {
        var root = Path.Combine(_t.Vars[variable], relative);
        Assert.False(_t.Guard.Check(root).Allowed);
        Assert.False(_t.Guard.Check(Path.Combine(root, "package", "input.dll")).Allowed);
        Assert.False(_t.Guard.Check(Path.GetDirectoryName(root)!).Allowed);
        Assert.True(_t.Guard.CheckRestoreTarget(Path.Combine(root, "package", "input.dll")).Allowed);
    }

    [Fact]
    public void Similar_names_and_nuget_http_cache_remain_available()
    {
        Assert.True(_t.Guard.Check(Path.Combine(_t.Vars["UserProfile"], @".nuget\packages-backup\note.txt")).Allowed);
        Assert.True(_t.Guard.Check(Path.Combine(_t.Vars["LocalAppData"], @"NuGet\v3-cache\download.dat")).Allowed);
    }

    [Theory]
    [InlineData("NUGET_PACKAGES")]
    [InlineData("GRADLE_USER_HOME")]
    [InlineData("CARGO_HOME")]
    [InlineData("GOMODCACHE")]
    [InlineData("UV_CACHE_DIR")]
    public void Configured_dependency_locations_are_also_protected(string variable)
    {
        var custom = Path.Combine(_t.Root, "CustomDependencies");
        var vars = _t.Vars.ToDictionary(p => p.Key, p => p.Value);
        vars[variable] = custom;
        var guard = new PathGuard(new CurrentUserEnvironmentResolver(vars));
        Assert.False(guard.Check(Path.Combine(custom, "library.dll")).Allowed);
    }

    [Fact]
    public async Task Legacy_fingerprint_and_safe_rule_cannot_reintroduce_nuget_packages()
    {
        _t.File(Package, "reference assembly");
        var db = AppFingerprintDb.FromJson("""
            {"fingerprints":[{"id":"nuget","app":"NuGet","paths":["%UserProfile%\\.nuget"],
            "flags":["devCache"],"cachePaths":["%UserProfile%\\.nuget\\packages"]}]}
            """, "old.json", _t.Guard);
        Assert.Empty(db.Rejected);
        Assert.Empty(await new DevCacheScanner(db, []).ScanAsync(Context(), null, default));
        var loaded = new RuleLoader(_t.Guard).LoadJson("""
            {"rules":[{"id":"dev.nuget","app":"NuGet","category":"dev","targets":[
            {"path":"%UserProfile%\\.nuget\\packages","risk":"safe","when":"always","recurse":true}]}]}
            """, "old.json");
        Assert.Empty(loaded.Rejected);
        Assert.Empty(await RuleScanner.AppCache().ScanAsync(Context(loaded.Rules), null, default));
        Assert.True(File.Exists(Package));
    }

    [Fact]
    public async Task Unknown_fingerprint_cache_and_safe_developer_rule_require_confirmation()
    {
        _t.File(Path.Combine(_t.Vars["LocalAppData"], "NewTool", "Cache", "input.bin"));
        var db = AppFingerprintDb.FromJson("""
            {"fingerprints":[{"id":"new-tool","app":"New tool","paths":["%LocalAppData%\\NewTool"],
            "flags":["devCache"],"cachePaths":["%LocalAppData%\\NewTool\\Cache"]}]}
            """, "new.json", _t.Guard);
        var loaded = new RuleLoader(_t.Guard).LoadJson("""
            {"rules":[{"id":"new-tool-without-prefix","app":"New tool","category":"dev","targets":[
            {"path":"%LocalAppData%\\NewTool\\Cache","risk":"safe","when":"always","recurse":true}]}]}
            """, "new.json");
        Assert.Empty(loaded.Rejected);
        var fp = Assert.Single(await new DevCacheScanner(db, []).ScanAsync(Context(), null, default));
        var rule = Assert.Single(await RuleScanner.AppCache().ScanAsync(Context(loaded.Rules), null, default));
        Assert.True(rule.RequiresFreshSelection);
        foreach (var item in new[] { fp, rule })
        {
            Assert.Equal(RiskLevel.Confirm, item.Risk);
            Assert.False(item.DefaultSelected);
            Assert.Contains("影响构建", item.Description);
        }
    }

    [Theory]
    [InlineData("dev-cache", RiskLevel.Safe)]
    [InlineData("dev-cache", RiskLevel.Confirm)]
    [InlineData("app-cache", RiskLevel.Safe)]
    [InlineData("duplicates", RiskLevel.Confirm)]
    public async Task Engine_rejects_old_or_cross_module_items_for_the_incident_file(string module, RiskLevel risk)
    {
        var path = _t.File(Package, "reference assembly");
        var fi = new FileInfo(path);
        var item = new ScanItem { Id = "legacy", ModuleId = module, Group = "legacy", DisplayName = "dependency", Kind = ItemKind.FileSet, Risk = risk,
            Path = Path.GetDirectoryName(path), Files = [new(path, fi.Length, fi.LastWriteTimeUtc)] };
        var q = new Quarantine(_db, null, _ => QuarantineRoot, _t.Guard);
        var engine = new CleanEngine(_t.Guard, q, new OperationLog(_db), new NullPreActionRunner());
        var report = await engine.CleanAsync([item], null, default);
        Assert.Equal(0, report.FilesQuarantined);
        Assert.True(report.Skipped > 0 || report.Failures.Count > 0);
        Assert.Equal("reference assembly", File.ReadAllText(path));
        Assert.Empty(q.ListActive());
    }

    [Fact]
    public void Quarantine_direct_entry_is_blocked()
    {
        _t.File(Package, "dependency");
        var q = new Quarantine(_db, null, _ => QuarantineRoot, _t.Guard);
        Assert.Throws<IOException>(() => q.MoveIn(Package, false, 10, "any", "new", "dependency"));
        Assert.True(File.Exists(Package));
    }

    [Fact]
    public async Task Cleaning_a_parent_directory_cannot_move_the_dependency_repository()
    {
        _t.File(Package, "dependency");
        var parent = Path.Combine(_t.Vars["UserProfile"], ".nuget");
        var (_, count, _, fingerprint) = _t.Guard.FingerprintDirectory(parent, default);
        var item = new ScanItem { Id = "parent", ModuleId = "residue", Group = "test", DisplayName = "parent",
            Kind = ItemKind.Directory, Risk = RiskLevel.High, Path = parent,
            DirectoryFileCount = count, DirectoryFingerprint = fingerprint };
        var q = new Quarantine(_db, null, _ => QuarantineRoot, _t.Guard);
        var engine = new CleanEngine(_t.Guard, q, new OperationLog(_db), new NullPreActionRunner());
        var result = await engine.CleanAsync([item], null, default);
        Assert.Equal(0, result.DirectoriesQuarantined);
        Assert.NotEmpty(result.Failures);
        Assert.True(File.Exists(Package));
    }

    [Theory]
    [InlineData("dev-cache", false)]
    [InlineData("app-cache", true)]
    public void Old_dependencies_survive_automatic_purge_and_can_be_restored(string module, bool knownPath)
    {
        var path = _t.File(knownPath ? Package : Path.Combine(_t.Root, "OldCustomRepo", "dependency.dll"), "dependency");
        var options = new QuarantineOptions { RetentionDays = -1, MaxBytesAbsolute = 0 };
        // Model an entry created by the old version before the new protection existed.
        var old = new Quarantine(_db, options, _ => QuarantineRoot);
        var entry = old.MoveIn(path, false, 10, module, "old", "dependency");
        var q = new Quarantine(_db, options, _ => QuarantineRoot, _t.Guard);
        Assert.Equal(0, q.PurgeExpired());
        Assert.Equal(0, q.EnforceSizeLimit());
        Assert.True(File.Exists(entry.QuarantinePath));
        Assert.Equal(path, q.Restore(entry.Id));
        Assert.Equal("dependency", File.ReadAllText(path));
    }

    public void Dispose() { _db.Dispose(); _t.Dispose(); }
}
