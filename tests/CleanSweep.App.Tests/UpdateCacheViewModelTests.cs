using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using CleanSweep.App.Services;
using CleanSweep.App.ViewModels;
using CleanSweep.App.Views;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Integrity;
using CleanSweep.Core.Model;

namespace CleanSweep.App.Tests;

public sealed class UpdateCacheViewModelTests
{
    private static readonly ReleaseInfo Release = new(new Version(0, 25, 0), "FatalCleaner-win-x64-0.25.0.zip", "https://example.com/a.zip", "hash", 10, "", "test");
    private static AppUpdateCoordinator Coordinator(Action? check = null) => new(
        _ => { check?.Invoke(); return Task.FromResult(new AppUpdateCheck(true, Release, "")); },
        (_, _, _) => Task.FromResult("a.zip"), (_, _) => Task.FromResult(false), _ => null, () => { }, (_, _) => Task.FromResult(true));
    private static ScanItem Item(string id) => new()
    {
        Id = id, ModuleId = "update-cache", Group = "程序更新缓存", DisplayName = id,
        Kind = ItemKind.FileSet, Risk = RiskLevel.Confirm, SizeBytes = 10,
    };

    [Fact]
    public async Task Confirmation_and_cleanup_block_updates_and_pass_only_selected_rows()
    {
        var checks = 0;
        var updates = Coordinator(() => checks++);
        IReadOnlyList<ScanItem>? cleaned = null;
        var vm = new UpdateCacheViewModel(updates, _ => Task.FromResult(new UpdateCachePreview([Item("first"), Item("second")], "预览完成")),
            (items, _) => { cleaned = items; return Task.FromResult(new CleanReport { FilesQuarantined = items.Count, QuarantinedBytes = 10 }); },
            async (count, bytes) =>
            {
                Assert.True(updates.IsBusy);
                Assert.False(updates.CanCancel);
                Assert.Equal(1, count); Assert.Equal(10, bytes);
                await updates.CheckAndPrepareAsync();
                Assert.Equal(0, checks);
                return true;
            });
        await vm.PreviewCommand.ExecuteAsync(null);
        Assert.All(vm.Rows, r => Assert.False(r.IsSelected));
        Assert.False(vm.CleanCommand.CanExecute(null));
        vm.Rows[1].IsSelected = true;
        Assert.True(vm.CleanCommand.CanExecute(null));
        await vm.CleanCommand.ExecuteAsync(null);
        Assert.Equal("second", Assert.Single(cleaned!).Id);
        Assert.Contains("隔离区", vm.Status);
        Assert.False(updates.IsBusy);
    }

    [Fact]
    public async Task Declining_confirmation_preserves_selection_and_does_not_clean()
    {
        var updates = Coordinator();
        var vm = new UpdateCacheViewModel(updates, _ => Task.FromResult(new UpdateCachePreview([Item("a")], "")),
            (_, _) => throw new Exception("must not clean"), (_, _) => Task.FromResult(false));
        await vm.PreviewCommand.ExecuteAsync(null);
        vm.Rows[0].IsSelected = true;
        await vm.CleanCommand.ExecuteAsync(null);
        Assert.True(Assert.Single(vm.Rows).IsSelected);
        Assert.False(updates.IsBusy);
    }

    [Fact]
    public async Task Ready_package_is_passed_as_protected_and_failures_release_coordinator()
    {
        var updates = Coordinator();
        await updates.CheckAndPrepareAsync();
        var vm = new UpdateCacheViewModel(updates, asset =>
        {
            Assert.Equal(Release.Asset, asset);
            throw new System.IO.IOException("busy cache");
        }, (_, _) => throw new Exception(), (_, _) => Task.FromResult(true));
        await vm.PreviewCommand.ExecuteAsync(null);
        Assert.Contains("busy cache", vm.Status);
        Assert.Same(Release, updates.ReadyRelease);
        Assert.False(updates.IsBusy);
        Assert.True(vm.PreviewCommand.CanExecute(null));
    }

    [Fact]
    public async Task Maintenance_rejects_concurrent_work_and_releases_gate_on_exception()
    {
        var updates = Coordinator();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var work = updates.MaintainCacheAsync(_ => gate.Task);
        Assert.False(await updates.MaintainCacheAsync(_ => throw new Exception("must not run")));
        gate.SetResult();
        Assert.True(await work);
        await Assert.ThrowsAsync<System.IO.IOException>(() => updates.MaintainCacheAsync(_ => throw new System.IO.IOException("test")));
        Assert.False(updates.IsBusy);
    }

    [Fact]
    public void Settings_cache_expander_binds_selection_and_actions_at_narrow_width() => WpfTestHost.Run(() =>
    {
        var vm = new UpdateCacheViewModel(Coordinator(), _ => Task.FromResult(new UpdateCachePreview([Item("FatalCleaner-win-x64-0.23.0.zip.release.json")], "可清理缓存")),
            (_, _) => Task.FromResult(new CleanReport()), (_, _) => Task.FromResult(false));
        var page = new SettingsPage { DataContext = new { UpdateCache = vm } };
        ((TabControl)page.FindName("SettingsSections")).SelectedIndex = 2;
        void Layout()
        {
            page.Measure(new Size(740, 600)); page.Arrange(new Rect(0, 0, 740, 600)); page.UpdateLayout(); WpfTestHost.Drain();
        }
        Layout();
        var expander = Assert.Single(Descendants(page).OfType<Expander>(), e => Equals(e.Header, "程序更新缓存"));
        expander.IsExpanded = true;
        vm.PreviewCommand.ExecuteAsync(null).GetAwaiter().GetResult();
        Layout();
        var preview = Assert.Single(Descendants(expander).OfType<Button>(), b => Equals(b.Content, "预览可清理缓存"));
        var clean = Assert.Single(Descendants(expander).OfType<Button>(), b => Equals(b.Content, "将选中项移入隔离区"));
        Assert.Same(vm.PreviewCommand, preview.Command);
        Assert.Same(vm.CleanCommand, clean.Command);
        Assert.False(clean.IsEnabled);
        var choice = Assert.Single(Descendants(expander).OfType<CheckBox>());
        choice.IsChecked = true;
        WpfTestHost.Drain();
        Assert.True(vm.Rows[0].IsSelected);
        Assert.True(clean.IsEnabled);
        foreach (var button in new[] { preview, clean })
        {
            var point = button.TransformToAncestor(page).Transform(new Point());
            Assert.True(point.X >= 0 && point.X + button.ActualWidth <= page.ActualWidth);
        }
    });

    private static IEnumerable<DependencyObject> Descendants(DependencyObject root)
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            yield return child;
            foreach (var item in Descendants(child)) yield return item;
        }
    }
}
