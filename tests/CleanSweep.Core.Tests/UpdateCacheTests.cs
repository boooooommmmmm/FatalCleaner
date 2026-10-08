using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Integrity;
using CleanSweep.Core.Model;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Tests;

public sealed class UpdateCacheTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly Whitelist _whitelist = new();
    private string Root => Path.Combine(_t.Root, "updates");
    private IReadOnlyDictionary<string, byte[]> Keys => new Dictionary<string, byte[]> { ["test"] = _key.ExportSubjectPublicKeyInfo() };
    private ScanContext Context => new() { Env = _t.Env, Guard = _t.Guard, Whitelist = _whitelist };
    private UpdateCacheInventory Inventory => new(Root, new Version(0, 24, 0), Context, Keys);
    private string Old(string name, string content = "cache")
    {
        var path = _t.File(Path.Combine(Root, name), content);
        File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddDays(-10));
        return path;
    }
    private string Package(string version = "0.23.0")
    {
        var path = Old($"FatalCleaner-win-x64-{version}.zip");
        var dto = ReleaseManifest.Sign(version, path, "https://example.com/" + Path.GetFileName(path), "", _key, "test");
        Old(Path.GetFileName(path) + AppUpdater.ReleaseInfoSuffix, ReleaseManifest.ToJson(dto));
        return path;
    }
    private string Index(string asset) => Old("prepared-update.json", JsonSerializer.Serialize(new { Source = "https://example.com/latest.json", Asset = asset }));
    private CleanEngine Engine(CleanSweepDb db, Quarantine quarantine) => new(_t.Guard, quarantine, new OperationLog(db), new NullPreActionRunner(), _whitelist);

    [Fact]
    public void Lists_old_signed_packages_parts_and_index_temporaries_only()
    {
        var zip = Package();
        Index(Path.GetFileName(zip));
        Old("CleanSweep-win-x64-0.22.0.zip.part");
        Old("prepared-update.json." + Guid.NewGuid().ToString("N") + ".tmp");
        Old("unknown.zip"); Old("cleansweep.db"); Old("recovery.json");
        Old("backup/FatalCleaner-win-x64-0.20.0.zip.part");
        var fresh = Old("FatalCleaner-win-x64-0.24.0.zip.part");
        File.SetLastWriteTimeUtc(fresh, DateTime.UtcNow);
        var result = Inventory.Preview(null);
        Assert.Equal(5, result.Items.Count);
        Assert.All(result.Items, i => { Assert.Equal(RiskLevel.Confirm, i.Risk); Assert.False(i.DefaultSelected); });
        Assert.DoesNotContain(result.Items, i => i.Path == fresh || i.DisplayName == "recovery.json");
    }

    [Theory]
    [InlineData("future")]
    [InlineData("ready")]
    [InlineData("bad-signature")]
    [InlineData("bad-index")]
    [InlineData("unsafe-index")]
    [InlineData("unknown-key")]
    [InlineData("missing-signature")]
    public void Keeps_pending_or_unverifiable_packages(string condition)
    {
        var zip = Package(condition == "future" ? "0.25.0" : "0.23.0");
        if (condition == "bad-signature") Old(Path.GetFileName(zip) + AppUpdater.ReleaseInfoSuffix, "{}");
        if (condition == "bad-index") Old("prepared-update.json", "broken");
        if (condition == "unsafe-index") Index("../outside.zip");
        if (condition == "missing-signature") File.Delete(zip + AppUpdater.ReleaseInfoSuffix);
        var inventory = condition == "unknown-key" ? new UpdateCacheInventory(Root, new Version(0,24,0), Context, new Dictionary<string,byte[]>()) : Inventory;
        Assert.Empty(inventory.Preview(condition == "ready" ? Path.GetFileName(zip) : null).Items);
    }

    [Fact]
    public void Missing_package_index_is_eligible_but_in_memory_ready_state_protects_it()
    {
        const string asset = "FatalCleaner-win-x64-0.25.0.zip";
        Index(asset);
        Assert.Equal("prepared-update.json", Assert.Single(Inventory.Preview(null).Items).DisplayName);
        Assert.Empty(Inventory.Preview(asset).Items);
    }

    [Fact]
    public async Task Selected_files_are_quarantined_and_restorable_without_expanding_selection()
    {
        var zip = Package();
        var index = Index(Path.GetFileName(zip));
        var selected = Inventory.Preview(null).Items.Where(i => i.Path == zip).ToArray();
        using var db = CleanSweepDb.InMemory();
        var quarantine = new Quarantine(db, null, _ => Path.Combine(_t.Root, "Q"));
        var report = await Inventory.CleanAsync(selected, null, Engine(db, quarantine));
        Assert.Equal(1, report.FilesQuarantined);
        Assert.Equal(0, report.FreedBytes);
        Assert.True(File.Exists(index)); Assert.True(File.Exists(zip + AppUpdater.ReleaseInfoSuffix));
        Assert.False(File.Exists(zip));
        quarantine.Restore(Assert.Single(quarantine.ListActive()).Id);
        Assert.Equal("cache", File.ReadAllText(zip));
    }

    [Theory]
    [InlineData("file")]
    [InlineData("index")]
    [InlineData("ready")]
    [InlineData("whitelist")]
    public async Task Execution_rechecks_changes_and_preserves_files(string change)
    {
        var zip = Package();
        var selected = Inventory.Preview(null).Items;
        if (change == "file") File.AppendAllText(zip, "changed");
        if (change == "index") Index("FatalCleaner-win-x64-0.30.0.zip");
        if (change == "whitelist") _whitelist.AddPath(zip);
        using var db = CleanSweepDb.InMemory();
        var quarantine = new Quarantine(db, null, _ => Path.Combine(_t.Root, "Q"));
        await Assert.ThrowsAsync<IOException>(() => Inventory.CleanAsync(selected, change == "ready" ? Path.GetFileName(zip) : null, Engine(db, quarantine)));
        Assert.True(File.Exists(zip));
        Assert.Empty(quarantine.ListActive());
    }

    [Fact]
    public void Cache_lock_excludes_other_operations_and_releases_after_disposal()
    {
        Package();
        using (UpdateCacheLock.Acquire(Root)) Assert.Throws<IOException>(() => Inventory.Preview(null));
        Assert.Equal(2, Inventory.Preview(null).Items.Count);
    }

    [Fact]
    public void Directory_links_and_linked_files_are_preserved()
    {
        var elsewhere = _t.Dir("other");
        Assert.True(TestEnv.TryCreateJunction(Root, elsewhere));
        Assert.Throws<IOException>(() => Inventory.Preview(null));
    }

    [Fact]
    public async Task Active_download_holds_cache_lock_even_before_first_byte()
    {
        var zip = Package();
        var dto = JsonSerializer.Deserialize<ReleaseInfoDto>(File.ReadAllText(zip + AppUpdater.ReleaseInfoSuffix));
        var release = ReleaseManifest.Verify(dto, Keys, out _)!;
        var gate = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var http = new HttpClient(new Handler(() => gate.Task));
        var work = new AppUpdater(http, Keys).DownloadAsync(release, Root);
        Assert.Throws<IOException>(() => Inventory.Preview(null));
        gate.SetResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("cache") });
        await work;
        using var lease = UpdateCacheLock.Acquire(Root);
    }

    private sealed class Handler(Func<Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => respond();
    }

    public void Dispose() { _key.Dispose(); _t.Dispose(); }
}
