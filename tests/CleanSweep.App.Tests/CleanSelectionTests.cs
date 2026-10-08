using System.IO;
using CleanSweep.App.Services;
using CleanSweep.App.ViewModels;
using CleanSweep.Core.Model;

namespace CleanSweep.App.Tests;

public sealed class CleanSelectionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "CleanSweep-selection-" + Guid.NewGuid().ToString("N"));
    private string SettingsFile => Path.Combine(_root, "settings.json");

    private static ScanItemViewModel Row(string id, RiskLevel risk = RiskLevel.Safe, bool allowed = true, string module = "cache") =>
        new(new ScanItem { Id = id, ModuleId = module, Group = "test", DisplayName = id, Risk = risk, Path = @"C:\cache\" + id }, allowed, "");

    private static CleanPageViewModel Page(AppSettings settings, params ScanItemViewModel[] rows)
    {
        var page = new CleanPageViewModel(null!, "test", "", () => [], selectionSettings: settings);
        page.Groups.Add(new ScanGroupViewModel("test", rows));
        page.HasResults = true;
        return page;
    }

    [Fact]
    public void Selected_and_deselected_items_survive_restart_and_changed_file_contents()
    {
        var safe = Row("safe");
        var confirm = Row("confirm", RiskLevel.Confirm);
        var page = Page(AppSettings.Load(SettingsFile), safe, confirm);
        safe.IsSelected = false;
        confirm.IsSelected = true;
        Assert.Null(page.SelectionSaveError);

        var safeAgain = Row("safe");
        var confirmAgain = new ScanItemViewModel(confirm.Item with { SizeBytes = 900, Files = [new(@"C:\cache\new.tmp", 900, DateTime.UtcNow)] });
        Page(AppSettings.Load(SettingsFile), safeAgain, confirmAgain);
        Assert.False(safeAgain.IsSelected);
        Assert.True(confirmAgain.IsSelected);
    }

    [Theory]
    [InlineData("dev-cache", null)]
    [InlineData("app-cache", "dev.pip")]
    [InlineData("app-cache", "new-tool-without-prefix")]
    public void Developer_caches_require_a_fresh_choice_even_after_a_saved_confirmation(string module, string? rule)
    {
        var settings = AppSettings.Load(SettingsFile);
        var item = Row("dependency", RiskLevel.Confirm, module: module).Item with
            { RuleId = rule, RequiresFreshSelection = rule == "new-tool-without-prefix" };
        settings.RememberCleaningSelection(item, true);
        settings.Save();
        var row = new ScanItemViewModel(item);
        Page(AppSettings.Load(SettingsFile), row);
        Assert.False(row.IsSelected);
        row.IsSelected = true;
        Assert.True(row.IsSelected);
        var nextScan = new ScanItemViewModel(item);
        Page(AppSettings.Load(SettingsFile), nextScan);
        Assert.False(nextScan.IsSelected);
    }

    [Fact]
    public void Rebuilt_project_with_new_outputs_does_not_reuse_old_confirmation()
    {
        var settings = AppSettings.Load(SettingsFile);
        var old = Row("project", RiskLevel.Confirm, module: "build-output").Item with
        {
            TargetSnapshot = "old-evidence", Files = [new(@"C:\repo\bin\App.dll", 10, DateTime.UtcNow.AddDays(-10))]
        };
        // Persist a v0.25.0 choice, which did not carry RequiresFreshSelection.
        settings.RememberCleaningSelection(old, true);
        settings.Save();
        var current = old with
        {
            RequiresFreshSelection = true, TargetSnapshot = "new-evidence",
            Files = [new(@"C:\repo\bin\App.dll", 20, DateTime.UtcNow.AddDays(-2)),
                new(@"C:\repo\bin\New.dll", 30, DateTime.UtcNow.AddDays(-2))]
        };
        var row = new ScanItemViewModel(current);
        Page(AppSettings.Load(SettingsFile), row);
        Assert.False(row.IsSelected);
        row.IsSelected = true;
        Assert.True(row.IsSelected);
        var nextScan = new ScanItemViewModel(current);
        Page(AppSettings.Load(SettingsFile), nextScan);
        Assert.False(nextScan.IsSelected);
    }

    [Fact]
    public void Risk_filter_and_sort_preserve_saved_selection_without_rewriting_settings()
    {
        var safe = Row("safe");
        var high = Row("high", RiskLevel.High);
        var page = Page(AppSettings.Load(SettingsFile), safe, high);
        high.IsSelected = true;
        safe.IsSelected = false;
        var saved = File.ReadAllText(SettingsFile);
        page.RiskFilter = CleanRiskFilter.High;
        page.SortOrder = CleanSortOrder.RiskAscending;
        page.SortOrder = CleanSortOrder.NameAscending;
        page.ClearFilterCommand.Execute(null);
        Assert.Equal(saved, File.ReadAllText(SettingsFile));
        var settings = AppSettings.Load(SettingsFile);
        Assert.True(settings.CleaningSelectionFor(high.Item));
        Assert.False(settings.CleaningSelectionFor(safe.Item));
    }

    [Fact]
    public void Filtered_bulk_selection_remembers_only_changed_visible_items()
    {
        var chrome = Row("Chrome");
        var edge = Row("Edge", RiskLevel.Confirm);
        var page = Page(AppSettings.Load(SettingsFile), chrome, edge);
        edge.IsSelected = true;
        page.FilterText = "Chrome";
        page.SelectNoneCommand.Execute(null);
        var settings = AppSettings.Load(SettingsFile);
        Assert.False(settings.CleaningSelectionFor(chrome.Item));
        Assert.True(settings.CleaningSelectionFor(edge.Item));
        page.SelectSafeOnlyCommand.Execute(null);
        settings = AppSettings.Load(SettingsFile);
        Assert.True(settings.CleaningSelectionFor(chrome.Item));
        Assert.True(settings.CleaningSelectionFor(edge.Item));
    }

    [Fact]
    public void Group_checkbox_and_safe_only_selection_are_persisted()
    {
        var safe = Row("safe");
        var confirm = Row("confirm", RiskLevel.Confirm);
        var page = Page(AppSettings.Load(SettingsFile), safe, confirm);
        page.Groups[0].IsChecked = false;
        page.Groups[0].IsChecked = true;
        Assert.True(AppSettings.Load(SettingsFile).CleaningSelectionFor(confirm.Item));
        page.SelectSafeOnlyCommand.Execute(null);
        var reloaded = AppSettings.Load(SettingsFile);
        Assert.True(reloaded.CleaningSelectionFor(safe.Item));
        Assert.False(reloaded.CleaningSelectionFor(confirm.Item));
    }

    [Fact]
    public void Disabled_items_do_not_erase_the_selection_saved_with_permission()
    {
        var settings = AppSettings.Load(SettingsFile);
        var original = Row("admin", RiskLevel.Confirm);
        Page(settings, original);
        original.IsSelected = true;
        var disabled = Row("admin", RiskLevel.Confirm, allowed: false);
        var page = Page(AppSettings.Load(SettingsFile), disabled, Row("other"));
        Assert.False(disabled.IsSelected);
        page.Groups[0].IsChecked = false;
        Assert.True(AppSettings.Load(SettingsFile).CleaningSelectionFor(original.Item));
    }

    [Fact]
    public void Automatic_deselection_during_cleanup_and_later_filtering_preserve_user_choice()
    {
        var row = Row("confirm", RiskLevel.Confirm);
        var page = Page(AppSettings.Load(SettingsFile), row);
        row.IsSelected = true;
        page.IsBusy = true;
        Assert.False(page.SelectNoneCommand.CanExecute(null));
        Assert.False(page.SelectSafeOnlyCommand.CanExecute(null));
        row.IsSelected = false;
        page.IsBusy = false;
        page.FilterText = "confirm";
        Assert.True(AppSettings.Load(SettingsFile).CleaningSelectionFor(row.Item));
    }

    [Fact]
    public void New_identity_or_changed_risk_or_kind_uses_defaults()
    {
        var settings = AppSettings.Load(SettingsFile);
        var row = Row("shared", RiskLevel.Confirm);
        Page(settings, row);
        row.IsSelected = true;
        var reloaded = AppSettings.Load(SettingsFile);
        Assert.False(reloaded.CleaningSelectionFor(row.Item with { Risk = RiskLevel.High }));
        Assert.False(reloaded.CleaningSelectionFor(row.Item with { Kind = ItemKind.Command }));
        Assert.False(reloaded.CleaningSelectionFor(row.Item with { ModuleId = "other" }));
        Assert.False(reloaded.CleaningSelectionFor(row.Item with { Id = "new" }));
        Assert.True(reloaded.CleaningSelectionFor(Row("new-safe").Item));
    }

    [Fact]
    public void Rescan_disposes_old_subscriptions_and_does_not_forget_absent_items()
    {
        var settings = AppSettings.Load(SettingsFile);
        var old = Row("cache");
        var page = Page(settings, old);
        old.IsSelected = false;
        page.Groups.Clear();
        old.IsSelected = true;
        page.Groups.Add(new ScanGroupViewModel("test", [Row("other")]));
        page.SelectNoneCommand.Execute(null);
        var returned = Row("cache");
        Page(AppSettings.Load(SettingsFile), returned);
        Assert.False(returned.IsSelected);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"CleaningSelections\":null}")]
    [InlineData("{\"CleaningSelections\":{\"invalid\":null}}")]
    public void Older_settings_and_null_entries_keep_default_selection(string json)
    {
        Directory.CreateDirectory(_root);
        File.WriteAllText(SettingsFile, json);
        var settings = AppSettings.Load(SettingsFile);
        Assert.Empty(settings.CleaningSelections);
        Assert.True(settings.CleaningSelectionFor(Row("safe").Item));
        Assert.False(settings.CleaningSelectionFor(Row("confirm", RiskLevel.Confirm).Item));
    }

    [Fact]
    public void Save_failure_is_visible_and_a_later_change_retries()
    {
        Directory.CreateDirectory(SettingsFile); // A directory blocks the atomic file replacement.
        var row = Row("safe");
        var page = Page(AppSettings.Load(SettingsFile), row);
        row.IsSelected = false;
        Assert.Contains("未能保存", page.SelectionSaveError);
        Directory.Delete(SettingsFile);
        page.FilterText = "safe";
        Assert.Null(page.SelectionSaveError);
        Assert.False(AppSettings.Load(SettingsFile).CleaningSelectionFor(row.Item));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
