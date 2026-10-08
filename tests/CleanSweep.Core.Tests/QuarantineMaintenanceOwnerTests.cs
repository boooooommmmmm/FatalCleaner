using System.Text.Json.Nodes;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Environment;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Tests;

public sealed class QuarantineMaintenanceOwnerTests
{
    private const string UserA = "S-1-5-21-1-2-3-1001";
    private const string UserB = "S-1-5-21-1-2-3-1002";

    [Theory]
    [InlineData(UserA, UserB, false)]
    [InlineData(UserA, UserB, true)]
    [InlineData(UserA, "S-1-5-18", false)]
    [InlineData(UserA, "S-1-5-18", true)]
    [InlineData(null, UserB, false)]
    [InlineData(null, UserB, true)]
    [InlineData(UserA, null, false)]
    [InlineData(UserA, null, true)]
    [InlineData("S-1-5-18", "S-1-5-18", false)]
    [InlineData("S-1-5-18", "S-1-5-18", true)]
    public void Reconciled_foreign_or_unknown_dependencies_survive_automatic_maintenance(
        string? owner, string? maintainer, bool sizeLimit)
    {
        using var t = new TestEnv();
        var root = t.Dir("Quarantine");
        var path = t.File(Path.Combine(t.Vars["UserProfile"], @".cargo\registry\src\pkg\input.rs"), "dependency");
        var opts = new QuarantineOptions { RetentionDays = -1, MaxBytesAbsolute = 0 };
        QuarantineEntry original;
        using (var oldDb = CleanSweepDb.InMemory())
            original = new Quarantine(oldDb, opts, _ => root).MoveIn(path, false, 10, "app-cache", "old", "dependency");
        // Model an old sidecar, including versions without an owner field; rebuild a fresh index.
        var metaPath = original.QuarantinePath + Quarantine.MetaSuffix;
        var meta = JsonNode.Parse(File.ReadAllText(metaPath))!.AsObject();
        if (owner is null) meta.Remove("OwnerSid"); else meta["OwnerSid"] = owner;
        File.WriteAllText(metaPath, meta.ToJsonString());
        var vars = t.Vars.ToDictionary(p => p.Key, p => p.Value);
        vars["UserProfile"] = t.Dir(@"Users\other");
        vars["LocalAppData"] = t.Dir(@"Users\other\AppData\Local");
        vars["AppData"] = t.Dir(@"Users\other\AppData\Roaming");
        var guard = new PathGuard(new CurrentUserEnvironmentResolver(vars));
        Assert.True(t.Guard.IsDeveloperDataProtected(path));
        Assert.False(guard.IsDeveloperDataProtected(path));
        using var db = CleanSweepDb.InMemory();
        var q = new Quarantine(db, opts, _ => root, guard) { AutomaticMaintenanceSid = maintainer };
        Assert.Equal(1, q.Reconcile([root]));
        var entry = Assert.Single(q.ListActive());
        Assert.Equal(owner, entry.OwnerSid);
        Assert.Equal(0, sizeLimit ? q.EnforceSizeLimit() : q.PurgeExpired());
        Assert.True(File.Exists(entry.QuarantinePath));
        Assert.Single(q.ListActive());
        Assert.Equal(path, q.Restore(entry.Id));
        Assert.Equal("dependency", File.ReadAllText(path));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Current_users_ordinary_cache_still_expires(bool sizeLimit)
    {
        using var t = new TestEnv();
        using var db = CleanSweepDb.InMemory();
        var opts = new QuarantineOptions { RetentionDays = -1, MaxBytesAbsolute = 0 };
        var q = new Quarantine(db, opts, _ => t.Dir("Quarantine"), t.Guard);
        var entry = q.MoveIn(t.File("cache.tmp"), false, 5, "app-cache", "current", "cache");
        Assert.Equal(1, sizeLimit ? q.EnforceSizeLimit() : q.PurgeExpired());
        Assert.False(File.Exists(entry.QuarantinePath));
        Assert.Empty(q.ListActive());
    }
}
