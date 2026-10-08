using System.Text.Json;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Model;
using CleanSweep.Core.Residue;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Tests;

public sealed class BuildOutputTests : IDisposable
{
    private readonly TestEnv _t = new();
    private readonly Whitelist _whitelist = new();
    private BuildActivity _activity = new(false, []);
    private string Project => Path.Combine(_t.Root, "repo", "App");
    private string Manifest => Path.Combine(Project, "obj", "Release", "net10.0", "App.csproj.FileListAbsolute.txt");
    private string Output => Path.Combine(Project, "bin", "Release", "net10.0", "App.dll");
    private ScanContext Context => new() { Env = _t.Env, Guard = _t.Guard, Whitelist = _whitelist };
    private BuildOutputScanner Scanner(params string[] roots) => new(roots.Length == 0 ? [Path.GetDirectoryName(Project)!] : roots)
        { ReadActivity = () => _activity };

    private void Setup()
    {
        _t.File(Path.Combine(Project, "App.csproj"), "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>");
        _t.File(Path.Combine(Project, "obj", "project.assets.json"), JsonSerializer.Serialize(new
            { project = new { restore = new { projectPath = Path.Combine(Project, "App.csproj") } } }));
        _t.File(Output, "assembly");
        _t.File(Manifest, Output);
        AgeFiles();
    }

    private void AgeFiles()
    {
        foreach (var path in Directory.GetFiles(Project, "*", SearchOption.AllDirectories))
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddDays(-10));
    }

    [Fact]
    public async Task Only_confirmed_generated_files_are_selected_and_duplicate_roots_are_deduplicated()
    {
        Setup();
        var source = _t.File(Path.Combine(Project, "Program.cs"));
        var config = _t.File(Path.Combine(Project, "bin", "settings.json"));
        var manual = _t.File(Path.Combine(Project, "bin", "manual.dll"));
        var outside = _t.File("outside.dll");
        var generated = _t.File(Path.Combine(Project, "obj", "Release", "App.AssemblyInfo.cs"));
        File.WriteAllLines(Manifest, [Output, Output, source, config, outside, "obj/Release/App.AssemblyInfo.cs"]);
        AgeFiles();
        var item = Assert.Single(await Scanner(Path.GetDirectoryName(Project)!, Project).ScanAsync(Context, null, default));
        Assert.Equal(ItemKind.FileSet, item.Kind);
        Assert.Equal(RiskLevel.Confirm, item.Risk);
        Assert.False(item.DefaultSelected);
        Assert.Equal(2, item.Files.Count);
        Assert.Contains(item.Files, f => f.Path == Output);
        Assert.Contains(item.Files, f => f.Path == generated);
        Assert.DoesNotContain(item.Files, f => f.Path == manual || f.Path == config || f.Path == source || f.Path == outside);
    }

    [Theory]
    [InlineData("project")]
    [InlineData("assets")]
    [InlineData("manifest")]
    [InlineData("wrong-owner")]
    [InlineData("xml")]
    [InlineData("multiple-projects")]
    [InlineData("fresh-output")]
    [InlineData("fresh-manifest")]
    public async Task Missing_ambiguous_or_recent_evidence_is_not_cleanable(string condition)
    {
        Setup();
        switch (condition)
        {
            case "project": File.Delete(Path.Combine(Project, "App.csproj")); break;
            case "assets": File.Delete(Path.Combine(Project, "obj", "project.assets.json")); break;
            case "manifest": File.Delete(Manifest); break;
            case "wrong-owner": File.WriteAllText(Path.Combine(Project, "obj", "project.assets.json"), "{\"project\":{\"restore\":{\"projectPath\":\"C:/Other.csproj\"}}}"); break;
            case "xml": File.WriteAllText(Path.Combine(Project, "App.csproj"), "<!DOCTYPE Project [<!ENTITY x SYSTEM 'file:///C:/x'>]><Project>&x;</Project>"); break;
            case "multiple-projects": _t.File(Path.Combine(Project, "Other.csproj"), "<Project/>"); break;
            case "fresh-output": File.SetLastWriteTimeUtc(Output, DateTime.UtcNow); break;
            case "fresh-manifest": File.SetLastWriteTimeUtc(Manifest, DateTime.UtcNow); break;
        }
        Assert.Empty(await Scanner().ScanAsync(Context, null, default));
    }

    [Fact]
    public async Task Whitelist_applies_to_files_projects_and_items()
    {
        Setup();
        _whitelist.AddPath(Output);
        Assert.Empty(await Scanner().ScanAsync(Context, null, default));
        _whitelist.RemovePath(Output);
        var item = Assert.Single(await Scanner().ScanAsync(Context, null, default));
        _whitelist.AddItem(item.Id);
        Assert.Empty(await Scanner().ScanAsync(Context, null, default));
        _whitelist.RemoveItem(item.Id);
        _whitelist.AddPath(Project);
        Assert.Empty(await Scanner().ScanAsync(Context, null, default));
    }

    [Fact]
    public async Task Build_hosts_and_running_project_outputs_block_scan()
    {
        Setup();
        _activity = new(true, []);
        var blockedScanner = Scanner();
        Assert.Empty(await blockedScanner.ScanAsync(Context, null, default));
        Assert.Contains("本次已跳过", blockedScanner.Note);
        _activity = new(false, [Path.Combine(Project, "bin", "App.exe")]);
        Assert.Empty(await Scanner().ScanAsync(Context, null, default));
        _activity = new(false, [Path.Combine(_t.Root, "unrelated.exe")]);
        Assert.Single(await Scanner().ScanAsync(Context, null, default));
    }

    [Fact]
    public async Task Reparse_roots_and_output_subdirectories_are_not_followed()
    {
        Setup();
        var link = Path.Combine(_t.Root, "linked");
        Assert.True(TestEnv.TryCreateJunction(link, Project));
        Assert.Empty(await Scanner(link).ScanAsync(Context, null, default));
        var external = _t.Dir("external");
        _t.File(Path.Combine(external, "external.dll"));
        var outputLink = Path.Combine(Project, "bin", "linked");
        Assert.True(TestEnv.TryCreateJunction(outputLink, external));
        File.AppendAllText(Manifest, "\n" + Path.Combine(outputLink, "external.dll"));
        File.SetLastWriteTimeUtc(Manifest, DateTime.UtcNow.AddDays(-10));
        Assert.Equal(Output, Assert.Single(Assert.Single(await Scanner().ScanAsync(Context, null, default)).Files).Path);
    }

    [Theory]
    [InlineData("process")]
    [InlineData("project")]
    [InlineData("manifest")]
    [InlineData("scope")]
    [InlineData("file")]
    [InlineData("missing-recheck")]
    [InlineData("failed-recheck")]
    public async Task Engine_preserves_outputs_when_execution_recheck_cannot_confirm(string change)
    {
        Setup();
        var scanner = Scanner();
        var item = Assert.Single(await scanner.ScanAsync(Context, null, default));
        Func<ScanItem, CancellationToken, Task<bool>>? recheck = (i, ct) => scanner.StillEligibleAsync(i, Context, ct);
        switch (change)
        {
            case "process": _activity = new(true, []); break;
            case "project": File.AppendAllText(Path.Combine(Project, "App.csproj"), "<!--changed-->"); break;
            case "manifest": File.AppendAllText(Manifest, "\n"); AgeFiles(); break;
            case "scope": recheck = (i, ct) => Scanner(_t.Dir("other")).StillEligibleAsync(i, Context, ct); break;
            case "file": File.AppendAllText(Output, "changed"); break;
            case "missing-recheck": recheck = null; break;
            case "failed-recheck": recheck = (_, _) => throw new IOException("test"); break;
        }
        using var db = CleanSweepDb.InMemory();
        var engine = new CleanEngine(_t.Guard, new Quarantine(db, null, _ => Path.Combine(_t.Root, "Q")),
            new OperationLog(db), new NullPreActionRunner(), _whitelist, buildOutputRecheck: recheck);
        var report = await engine.CleanAsync([item], null, default);
        Assert.Equal(0, report.FilesQuarantined);
        Assert.Equal(1, report.Skipped);
        Assert.True(File.Exists(Output));
    }

    [Fact]
    public async Task Confirmed_files_are_quarantined_and_restorable_while_unknown_data_stays()
    {
        Setup();
        var keep = _t.File(Path.Combine(Project, "bin", "user-data.db"), "userdata");
        var scanner = Scanner();
        var item = Assert.Single(await scanner.ScanAsync(Context, null, default));
        using var db = CleanSweepDb.InMemory();
        var quarantine = new Quarantine(db, null, _ => Path.Combine(_t.Root, "Q"));
        var engine = new CleanEngine(_t.Guard, quarantine, new OperationLog(db), new NullPreActionRunner(), _whitelist,
            buildOutputRecheck: (i, ct) => scanner.StillEligibleAsync(i, Context, ct));
        var report = await engine.CleanAsync([item], null, default);
        Assert.Equal(1, report.FilesQuarantined);
        Assert.Equal(0, report.FreedBytes);
        Assert.False(File.Exists(Output));
        Assert.True(File.Exists(keep));
        Assert.True(File.Exists(Manifest));
        var entry = Assert.Single(quarantine.ListActive());
        quarantine.Restore(entry.Id);
        Assert.Equal("assembly", File.ReadAllText(Output));
    }

    [Fact]
    public async Task User_selected_subset_does_not_expand_to_other_manifest_entries()
    {
        Setup();
        var second = _t.File(Path.Combine(Project, "bin", "App.pdb"));
        File.AppendAllText(Manifest, "\n" + second);
        AgeFiles();
        var scanner = Scanner();
        var item = Assert.Single(await scanner.ScanAsync(Context, null, default));
        var selected = item with { Files = item.Files.Where(f => f.Path == Output).ToArray(), SizeBytes = new FileInfo(Output).Length };
        using var db = CleanSweepDb.InMemory();
        var engine = new CleanEngine(_t.Guard, new Quarantine(db, null, _ => Path.Combine(_t.Root, "Q")),
            new OperationLog(db), new NullPreActionRunner(), _whitelist,
            buildOutputRecheck: (i, ct) => scanner.StillEligibleAsync(i, Context, ct));
        var report = await engine.CleanAsync([selected], null, default);
        Assert.Equal(1, report.FilesQuarantined);
        Assert.True(File.Exists(second));
    }

    [Fact]
    public async Task Empty_roots_and_bad_settings_paths_are_handled_without_scanning_other_locations()
    {
        Setup();
        var empty = new BuildOutputScanner([]) { ReadActivity = () => throw new Exception("must not inspect processes") };
        Assert.Empty(await empty.ScanAsync(Context, null, default));
        Assert.Contains("添加项目根目录", empty.Note);
        Assert.Empty(await Scanner("missing-project", "\0").ScanAsync(Context, null, default));
    }

    [Fact]
    public async Task Cancellation_is_propagated()
    {
        Setup();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Scanner().ScanAsync(Context, null, cts.Token));
    }

    public void Dispose() => _t.Dispose();
}
