using CleanSweep.Core.Inventory;
using CleanSweep.Core.Model;
using CleanSweep.Core.Residue;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;

namespace CleanSweep.Core.Tests;

public sealed class JetBrainsCacheTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly Whitelist _whitelist = new();
    private string Vendor => Path.Combine(_t.Vars["LocalAppData"], "JetBrains");
    private AppFingerprintDb Legacy => AppFingerprintDb.FromJson("""
        { "fingerprints": [{ "id": "jetbrains", "app": "JetBrains IDE",
          "paths": ["%LocalAppData%\\JetBrains"], "flags": ["devCache"],
          "cachePaths": ["%LocalAppData%\\JetBrains"] }] }
        """, "legacy.json", _t.Guard);

    private IReadOnlyList<CleanRule> Rules()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "CleanSweep.slnx"))) dir = dir.Parent;
        Assert.NotNull(dir);
        var loaded = new RuleLoader(_t.Guard).LoadJson(File.ReadAllText(Path.Combine(dir!.FullName, "rules", "apps.json")), "apps.json");
        Assert.Empty(loaded.Rejected);
        return loaded.Rules.Where(r => r.Id == "jetbrains.ide").ToArray();
    }

    [Fact]
    public async Task Legacy_whole_root_fingerprint_cannot_select_local_history_or_configuration()
    {
        _t.File(Path.Combine(Vendor, "IntelliJIdea2026.2", "LocalHistory", "history.dat"));
        _t.File(Path.Combine(Vendor, "IntelliJIdea2026.2", "caches", "index.dat"));
        _t.File(Path.Combine(Vendor, "Toolbox", "apps", "idea.exe"));
        Assert.Empty(Legacy.Fingerprints.Single().ExpandCachePaths(_t.Env));
        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = _whitelist };
        Assert.Empty(await new DevCacheScanner(Legacy, []).ScanAsync(ctx, null, default));
    }

    [Fact]
    public async Task Developer_and_application_cache_share_scope_risk_age_cutoffs_and_ids()
    {
        _t.Dir(Path.Combine(Vendor, "Toolbox")); // Existing installation detection in the shipped rule.
        var ide = Path.Combine(Vendor, "IntelliJIdea2026.2");
        foreach (var name in new[] { "caches", "index", "log", "tmp", "LocalHistory", "plugins", "options" })
        {
            var path = _t.File(Path.Combine(ide, name, "old.dat"));
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddDays(-30));
        }
        _t.File(Path.Combine(ide, "log", "current.log"));
        _t.File(Path.Combine(ide, "tmp", "current.tmp"));
        var ctx = new ScanContext { Env = _t.Env, Guard = _t.Guard, Whitelist = _whitelist, Rules = Rules() };
        var dev = await new DevCacheScanner(Legacy, []).ScanAsync(ctx, null, default);
        var app = await RuleScanner.AppCache().ScanAsync(ctx, null, default);
        Assert.Equal(4, dev.Count);
        Assert.Equal(app.Select(i => (i.Id, i.Risk, i.ContentSnapshot())), dev.Select(i => (i.Id, i.Risk, i.ContentSnapshot())));
        foreach (var item in dev)
        {
            var leaf = Path.GetFileName(item.Path!);
            Assert.Contains(leaf, new[] { "caches", "index", "log", "tmp" });
            Assert.Equal(leaf is "caches" or "index" ? RiskLevel.Confirm : RiskLevel.Safe, item.Risk);
            Assert.DoesNotContain(item.Files, f => Path.GetFileName(f.Path).StartsWith("current"));
        }
        _whitelist.AddRule("jetbrains.ide");
        Assert.Empty(await new DevCacheScanner(Legacy, []).ScanAsync(ctx, null, default));
    }

    public void Dispose() => _t.Dispose();
}
