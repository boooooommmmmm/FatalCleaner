using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Data;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.App.Views;
using CleanSweep.Core.Backup;
using CleanSweep.Core.Startup;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CleanSweep.App.ViewModels;

public sealed partial class StartupRow : ObservableObject
{
    private bool _suppress;

    public StartupRow(StartupItem item)
    {
        Item = item;
        _enabled = item.Enabled;
    }

    public StartupItem Item { get; }

    [ObservableProperty]
    private bool _enabled;

    /// <summary>用户切换开关时触发；程序回写状态时不触发。</summary>
    public event EventHandler<bool>? ToggleRequested;

    partial void OnEnabledChanged(bool value)
    {
        if (_suppress) return;
        ToggleRequested?.Invoke(this, value);
    }

    public void SetEnabledSilently(bool value)
    {
        _suppress = true;
        Enabled = value;
        _suppress = false;
    }

    public string Name => Item.Name;
    public string Publisher => Item.Publisher ?? "未知";
    public string Location => Item.Location;
    public string Command => Item.Command ?? "";
    public string? Note => Item.Note;
    public bool CanToggle => Item.CanToggle;
    public bool CanDelete => Item.CanDelete;
    public bool CanDelay => Item.CanDelay;
    public bool CanOpenLocation => Item.ExePath is not null && File.Exists(Item.ExePath);

    public int KindOrder => Item.Kind switch
    {
        StartupKind.RegistryRun => 0,
        StartupKind.RegistryRunOnce => 1,
        StartupKind.StartupFolder => 2,
        StartupKind.ScheduledTask => 3,
        StartupKind.Service => 4,
        StartupKind.UwpStartupTask => 5,
        _ => 9,
    };

    public string KindText => Item.Kind switch
    {
        StartupKind.RegistryRun => "注册表启动项",
        StartupKind.RegistryRunOnce => "注册表 RunOnce",
        StartupKind.StartupFolder => "启动文件夹",
        StartupKind.ScheduledTask => "计划任务",
        StartupKind.Service => "服务",
        StartupKind.UwpStartupTask => "应用商店应用",
        _ => Item.Kind.ToString(),
    };

    public string ScopeText => Item.Scope == StartupScope.AllUsers ? "所有用户" : "当前用户";

    public string SignatureText => Item.Signature switch
    {
        SignatureState.SignedMicrosoft => "微软签名",
        SignatureState.Signed => "已签名",
        SignatureState.Unsigned => "未签名",
        SignatureState.Invalid => "签名无效",
        _ => "—",
    };

    public string ImpactText => Item.Impact switch
    {
        StartupImpact.High => "高",
        StartupImpact.Medium => "中",
        StartupImpact.Low => "低",
        _ => "未测量",
    };

    public string ImpactDetail => Item.Impact == StartupImpact.NotMeasured
        ? "近几次开机没有该程序的耗时记录"
        : $"平均 CPU {Item.CpuMs:0} 毫秒，磁盘 {Format.Bytes(Item.DiskBytes)}（近几次开机平均）";

    public string SuggestionText => Item.Suggestion switch
    {
        StartupSuggestion.Keep => "保留",
        StartupSuggestion.RecommendDisable => "建议禁用",
        _ => "可禁用",
    };

    public string ToolTipText
    {
        get
        {
            var lines = new List<string> { Item.Location };
            if (Item.Command is not null) lines.Add(Item.Command);
            if (Item.Note is not null) lines.Add(Item.Note);
            lines.Add(ImpactDetail);
            return string.Join('\n', lines);
        }
    }
}

public sealed record BootBar(string DateText, double Seconds, double BarHeight, string ToolTip);

public sealed partial class StartupViewModel : ObservableObject
{
    private readonly AppServices _s;
    private bool _restorePointWarned;

    public ObservableCollection<StartupRow> Rows { get; } = new();
    public ICollectionView View { get; }
    public ObservableCollection<BootBar> Boots { get; } = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RefreshCommand), nameof(DeleteCommand), nameof(DelayCommand), nameof(DisableRecommendedCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _status = "点击“刷新”扫描开机启动项。";

    [ObservableProperty]
    private string _summary = "";

    [ObservableProperty]
    private string _bootSummary = "";

    [ObservableProperty]
    private bool _showMicrosoft;

    [ObservableProperty]
    private int _recommendCount;

    public bool HasScanned { get; private set; }

    public StartupViewModel(AppServices s)
    {
        _s = s;
        _showMicrosoft = s.Settings.ShowMicrosoftStartup;

        View = CollectionViewSource.GetDefaultView(Rows);
        View.GroupDescriptions.Add(new PropertyGroupDescription(nameof(StartupRow.KindText)));
        View.SortDescriptions.Add(new SortDescription(nameof(StartupRow.KindOrder), ListSortDirection.Ascending));
        View.SortDescriptions.Add(new SortDescription(nameof(StartupRow.Name), ListSortDirection.Ascending));
    }

    private bool NotBusy => !IsBusy;

    partial void OnShowMicrosoftChanged(bool value)
    {
        _s.Settings.ShowMicrosoftStartup = value;
        _s.Settings.Save();
        if (HasScanned && !IsBusy) RefreshCommand.Execute(null);
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task RefreshAsync()
    {
        IsBusy = true;
        Status = "正在扫描启动项…";
        try
        {
            var includeMs = ShowMicrosoft;
            // 刷新时丢掉签名缓存：同一路径的文件可能已被替换
            FileSignature.ClearCache();
            var (items, boots) = await Task.Run(() => (_s.Startup.Scan(includeMs), _s.Startup.GetBootHistory(12)));

            foreach (var r in Rows) r.ToggleRequested -= OnToggleRequested;
            Rows.Clear();
            foreach (var item in items)
            {
                var row = new StartupRow(item);
                row.ToggleRequested += OnToggleRequested;
                Rows.Add(row);
            }
            View.Refresh();

            var enabled = items.Count(i => i.Enabled);
            RecommendCount = items.Count(i => i.Enabled && i.CanToggle && i.Suggestion == StartupSuggestion.RecommendDisable);
            Summary = $"{items.Count} 项，其中 {enabled} 项已启用" + (RecommendCount > 0 ? $"，{RecommendCount} 项建议禁用" : "");
            Status = includeMs ? "已包含微软自带的服务与计划任务。" : "微软自带的服务与计划任务默认隐藏，可勾选“显示微软项”查看。";
            HasScanned = true;

            UpdateBoots(boots);
        }
        catch (Exception ex)
        {
            Status = $"扫描失败：{ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void UpdateBoots((IReadOnlyList<BootRecord> Boots, string? Error) history)
    {
        var boots = history.Boots;
        Boots.Clear();
        if (boots.Count == 0)
        {
            BootSummary = history.Error ?? "没有开机时间记录。";
            return;
        }

        var ordered = boots.OrderBy(b => b.TimeUtc).ToList();
        var max = Math.Max(1.0, ordered.Max(b => b.BootTimeMs) / 1000.0);
        foreach (var b in ordered)
        {
            var sec = b.BootTimeMs / 1000.0;
            Boots.Add(new BootBar(
                b.TimeUtc.ToLocalTime().ToString("MM-dd"),
                sec,
                Math.Max(3, 60 * sec / max),
                $"{b.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm}\n开机 {sec:0} 秒（系统 {b.MainPathMs / 1000.0:0} 秒 + 登录后 {b.PostBootMs / 1000.0:0} 秒）"));
        }

        var last = ordered[^1];
        var avg = ordered.Average(b => b.BootTimeMs) / 1000.0;
        BootSummary = $"最近一次开机 {last.BootTimeMs / 1000.0:0} 秒（{last.TimeUtc.ToLocalTime():MM-dd HH:mm}），近 {ordered.Count} 次平均 {avg:0} 秒。";
    }

    private async void OnToggleRequested(object? sender, bool enabled)
    {
        if (sender is not StartupRow row) return;

        // 扫描或另一项修改进行中时不接受新的切换，避免并发写注册表
        if (IsBusy)
        {
            row.SetEnabledSilently(!enabled);
            Status = "正在处理其他操作，请稍候再试。";
            return;
        }

        if (row.Item.Kind == StartupKind.Service && !enabled)
        {
            var ok = MessageBox.Show(
                $"将服务“{row.Name}”改为手动启动？\n\n服务本身不会被禁用，下次开机不再自动运行；需要时仍可由其他程序启动。修改前会备份注册表" +
                (_s.Settings.CreateRestorePoint ? "并尝试创建系统还原点。" : "。"),
                "开机加速", MessageBoxButton.OKCancel, MessageBoxImage.Question);
            if (ok != MessageBoxResult.OK)
            {
                row.SetEnabledSilently(!enabled);
                return;
            }
        }

        IsBusy = true;
        try
        {
            var result = await Task.Run(() => _s.Startup.SetEnabled(row.Item, enabled));
            if (!result.Success)
            {
                row.SetEnabledSilently(!enabled);
                MessageBox.Show(result.Message, "开机加速", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            Status = result.Message;
            WarnRestorePoint(result.RestorePoint);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void WarnRestorePoint(RestorePointOutcome? rp)
    {
        if (rp is null || rp.Protected || _restorePointWarned) return;
        _restorePointWarned = true;
        MessageBox.Show(rp.Message + "\n\n本次会话内不再重复提示。", "系统还原点", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task DeleteAsync(StartupRow? row)
    {
        if (row is null || !row.CanDelete) return;

        var hint = row.Item.Kind switch
        {
            StartupKind.StartupFolder => "文件将移入隔离区，可恢复。",
            StartupKind.ScheduledTask => "这是 FatalCleaner 创建的延迟启动任务，删除后请重新启用原启动项。",
            _ => "注册表键会先备份，可在“设置 → 注册表备份”中还原。通常只需“禁用”，无需删除。",
        };
        if (MessageBox.Show($"删除启动项“{row.Name}”？\n\n{hint}", "开机加速", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK)
            return;

        IsBusy = true;
        try
        {
            var result = await Task.Run(() => _s.Startup.Delete(row.Item));
            Status = result.Message;
            if (!result.Success)
                MessageBox.Show(result.Message, "开机加速", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsBusy = false;
        }
        await RefreshAsync();
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task DelayAsync(StartupRow? row)
    {
        if (row is null || !row.CanDelay) return;

        var dlg = new DelayDialog(row.Name) { Owner = Application.Current.MainWindow };
        if (dlg.ShowDialog() != true) return;

        IsBusy = true;
        try
        {
            var seconds = dlg.Seconds;
            var result = await Task.Run(() => _s.Startup.ConvertToDelayed(row.Item, seconds));
            Status = result.Message;
            if (!result.Success)
                MessageBox.Show(result.Message, "开机加速", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsBusy = false;
        }
        await RefreshAsync();
    }

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task DisableRecommendedAsync()
    {
        var targets = Rows.Where(r => r.Enabled && r.CanToggle && r.Item.Suggestion == StartupSuggestion.RecommendDisable
                                      && r.Item.Kind != StartupKind.Service).ToList();
        if (targets.Count == 0)
        {
            Status = "没有可一键禁用的“建议禁用”项（服务需逐项确认）。";
            return;
        }

        var names = string.Join("\n", targets.Take(12).Select(t => "· " + t.Name)) + (targets.Count > 12 ? $"\n… 共 {targets.Count} 项" : "");
        if (MessageBox.Show($"禁用以下 {targets.Count} 个启动项？原始项不会被删除，随时可重新启用。\n\n{names}",
                "开机加速", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK)
            return;

        IsBusy = true;
        int ok = 0, fail = 0;
        try
        {
            await Task.Run(() =>
            {
                foreach (var t in targets)
                {
                    var r = _s.Startup.SetEnabled(t.Item, false);
                    if (r.Success) ok++; else fail++;
                }
            });
            foreach (var t in targets) t.SetEnabledSilently(false);
            Status = $"已禁用 {ok} 项" + (fail > 0 ? $"，{fail} 项失败（详见清理历史）" : "") + "。";
        }
        finally
        {
            IsBusy = false;
        }
        await RefreshAsync();
    }

    [RelayCommand]
    private void OpenLocation(StartupRow? row)
    {
        var path = row?.Item.ExePath;
        if (path is null || !File.Exists(path)) return;
        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
        }
        catch
        {
        }
    }
}
