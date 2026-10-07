using CleanSweep.Core.Integrity;

namespace CleanSweep.Core.Tests;

public sealed class PortableUpdateTests : IDisposable
{
    private readonly TestEnv _t = new();
    public void Dispose() => _t.Dispose();

    [Fact]
    public void Portable_upgrade_replaces_only_itself_even_beside_a_legacy_install()
    {
        var install = _t.Dir("Downloads");
        var source = _t.Dir("stage");
        _t.File("Downloads/FatalCleaner.exe", "portable-old");
        _t.File("Downloads/CleanSweep.exe", "legacy-old");
        _t.File("Downloads/CleanSweep.Service.exe", "service-old");
        _t.File("Downloads/install-files.txt", "CleanSweep.exe\nnotes.txt");
        _t.File("Downloads/notes.txt", "my notes");
        _t.File("Downloads/settings.json", "settings");
        _t.File("stage/CleanSweep.exe", "new-bundle");
        _t.File("stage/CleanSweep.Service.exe", "service-new");
        _t.File("stage/rules/manifest.json", "external signed data");

        Assert.Null(AppUpdater.ApplyStaged(source, install, new UnexpectedService(), executableName: AppUpdater.PortableExeName));
        Assert.Equal("new-bundle", File.ReadAllText(Path.Combine(install, "FatalCleaner.exe")));
        Assert.Equal("legacy-old", File.ReadAllText(Path.Combine(install, "CleanSweep.exe")));
        Assert.Equal("service-old", File.ReadAllText(Path.Combine(install, "CleanSweep.Service.exe")));
        Assert.Equal("my notes", File.ReadAllText(Path.Combine(install, "notes.txt")));
        Assert.Equal("settings", File.ReadAllText(Path.Combine(install, "settings.json")));
        Assert.Equal("CleanSweep.exe\nnotes.txt", File.ReadAllText(Path.Combine(install, "install-files.txt")));
        Assert.False(Directory.Exists(Path.Combine(install, "rules")));
    }

    [Fact]
    public void Portable_upgrade_does_not_write_an_install_manifest()
    {
        var install = _t.Dir("standalone");
        var source = _t.Dir("package");
        _t.File("standalone/FatalCleaner.exe", "old");
        _t.File("package/CleanSweep.exe", "new");
        Assert.Null(AppUpdater.ApplyStaged(source, install, null, executableName: AppUpdater.PortableExeName));
        Assert.Equal(new[] { "FatalCleaner.exe" }, Directory.GetFiles(install).Select(Path.GetFileName));
    }

    [Fact]
    public void Portable_upgrade_preserves_the_old_exe_when_replacement_fails()
    {
        var install = _t.Dir("locked");
        var source = _t.Dir("new");
        var old = _t.File("locked/FatalCleaner.exe", "old");
        var next = _t.File("new/CleanSweep.exe", "new");
        var retries = AppUpdater.RetryCount;
        AppUpdater.RetryCount = 1;
        try
        {
            // 旧文件已移入备份之后，新文件无法读取，必须恢复旧文件。
            using var locked = new FileStream(next, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            var error = AppUpdater.ApplyStaged(source, install, null, executableName: AppUpdater.PortableExeName);
            Assert.Contains("已恢复原文件", error);
            Assert.Equal("old", File.ReadAllText(old));
            Assert.False(Directory.Exists(Path.Combine(install, AppUpdater.BackupDirName)));
        }
        finally { AppUpdater.RetryCount = retries; }
    }

    [Theory]
    [InlineData("../outside.exe")]
    [InlineData("C:\\outside.exe")]
    [InlineData("other.exe")]
    public void Update_rejects_arbitrary_target_names(string name)
    {
        Assert.NotNull(AppUpdater.ApplyStaged(_t.Root, _t.Root, null, executableName: name));
        Assert.False(AppUpdater.IsSupportedExeName(name));
    }

    [Theory]
    [InlineData(DataKind.Rules)]
    [InlineData(DataKind.Fingerprints)]
    [InlineData(DataKind.Popups)]
    public void Embedded_data_verifies_without_external_files_and_rejects_unsigned_updates(DataKind kind)
    {
        var builtin = DataSets.LocateInstalled(kind, null);
        Assert.True(builtin.Verdict.Ok, builtin.Verdict.Reason);
        Assert.NotEmpty(builtin.Contents);
        var update = _t.Dir("unsigned");
        _t.File("unsigned/manifest.json", "{\"version\":2147483647}");
        var located = DataSets.LocateInstalled(kind, update);
        Assert.False(located.FromUpdate);
        Assert.Equal(builtin.Verdict.Version, located.Verdict.Version);
        Assert.Equal(builtin.Contents, located.Contents);
    }

    private sealed class UnexpectedService : IUpdateServiceControl
    {
        public bool IsInstalled => throw new InvalidOperationException("Portable update must not query a legacy service");
        public bool IsRunning => throw new InvalidOperationException();
        public void Stop(TimeSpan timeout) => throw new InvalidOperationException();
        public void Start(TimeSpan timeout) => throw new InvalidOperationException();
    }
}
