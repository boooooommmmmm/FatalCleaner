using System.Collections.ObjectModel;
using System.IO;
using Microsoft.Win32;
using System.Windows;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Model;
using CleanSweep.Core.Scanning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CleanSweep.App.ViewModels;

/// <summary>"扫描 → 勾选 → 清理"通用页面，系统清理与应用缓存共用。</summary>
public sealed partial class CleanPageViewModel : ObservableObject
{
    private readonly AppServices _s;
    private readonly Func<IScanner[]> _scanners;
    private Func<IScanner[]>? _scopedScanners;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasScanScope))]
    private string? _scanScopeText;
    public bool HasScanScope => _scopedScanners is not null;

    /// <summary>Only change scope while idle; clear old actionable rows immediately.</summary>
    public bool TrySetScanScope(Func<IScanner[]>? scanners, string? description)
    {
        if (IsBusy) return false;
        _scopedScanners = scanners;
        ScanScopeText = scanners is null ? null : description;
        OnPropertyChanged(nameof(HasScanScope));
        ClearGroups();
        HasResults = false;
        Note = null;
        FilterText = "";
        RiskFilter = CleanRiskFilter.All;
        Status = "扫描范围已更改，请开始扫描。";
        return true;
    }

    [RelayCommand(CanExecute = nameof(CanScan))]
    private void ScanAll()
    {
        if (TrySetScanScope(null, null)) ScanCommand.Execute(null);
    }
    private readonly Func<string?>? _postScanNote;
    private readonly Dictionary<ScanGroupViewModel, CleanSelectionTracker> _selectionTrackers = new();
    private readonly HashSet<ScanGroupViewModel> _observedGroups = new();
    private bool _applyingFilter;
    private long _operationId;
    private readonly Func<IProgress<ScanProgress>, CancellationToken, Task<IReadOnlyList<ScanItemViewModel>>> _scanRows;
    internal CleanExecutionReport? ExecutionReport { get; private set; }
    public ObservableCollection<CleanReportRow> ReportRows { get; } = new();
    public IReadOnlyList<CleanReportFilterOption> ReportFilters { get; } =
    [
        new("全部结果", null), new("未完成与跳过", null, true),
        new("正在使用", CleanIssueKind.InUse), new("权限不足", CleanIssueKind.Permission),
        new("扫描后变化", CleanIssueKind.Changed), new("备份失败", CleanIssueKind.BackupFailed),
        new("安全排除", CleanIssueKind.Excluded), new("已不存在", CleanIssueKind.AlreadyAbsent),
        new("未确认完成", CleanIssueKind.NotProcessed), new("其他失败", CleanIssueKind.Failure),
    ];
    [ObservableProperty] private CleanReportFilterOption _reportFilter = new("全部结果", null);
    [ObservableProperty] private bool _hasExecutionReport;
    [ObservableProperty] private string _reportCountText = "";
    [ObservableProperty] private string _reportActionStatus = "";

    partial void OnReportFilterChanged(CleanReportFilterOption value) => RefreshReportRows();

    private void RefreshReportRows()
    {
        ReportRows.Clear();
        if (ExecutionReport is null) return;
        foreach (var row in ExecutionReport.Rows.Where(r => ReportFilter.Kind is { } kind
            ? r.Kind == kind : !ReportFilter.ProblemsOnly || r.Kind is not null)) ReportRows.Add(row);
        ReportCountText = $"显示 {ReportRows.Count}/{ExecutionReport.Rows.Count} 条；导出包含全部结果，不受此筛选影响。";
    }

    internal void SetExecutionReport(CleanExecutionReport report)
    {
        ExecutionReport = report;
        LastReport = report.Summary;
        HasReportProblems = report.Cancelled || report.Items.Any(i => !i.Complete)
            || report.Rows.Any(r => r.Kind is not null and not CleanIssueKind.AlreadyAbsent);
        HasExecutionReport = true;
        ReportFilter = ReportFilters[0];
        RefreshReportRows();
        RescanIncompleteCommand.NotifyCanExecuteChanged();
        ExportReportCommand.NotifyCanExecuteChanged();
    }

    private bool CanRescanIncomplete => !IsBusy && ExecutionReport?.IncompleteIds.Count > 0;
    private bool CanExportReport => !IsBusy && ExecutionReport is not null;

    [RelayCommand(IncludeCancelCommand = true, CanExecute = nameof(CanRescanIncomplete))]
    private Task RescanIncompleteAsync(CancellationToken ct) => ScanCoreAsync(ct, ExecutionReport!.IncompleteIds);

    [RelayCommand(CanExecute = nameof(CanExportReport))]
    private void ExportReport()
    {
        var dialog = new SaveFileDialog { Title = "导出清理结果（包含本机路径）", Filter = "JSON 报告 (*.json)|*.json",
            FileName = $"FatalCleaner-result-{DateTime.Now:yyyyMMdd-HHmmss}.json", DefaultExt = ".json" };
        if (dialog.ShowDialog() != true) return;
        try
        {
            File.WriteAllText(dialog.FileName, ExecutionReport!.ToJson(), new System.Text.UTF8Encoding(false));
            ReportActionStatus = "结果已导出。报告包含本机路径，分享前请检查。";
        }
        catch (Exception ex) { ReportActionStatus = "导出失败：" + ex.Message; }
    }

    [ObservableProperty]
    private string? _selectionSaveError;

    public string Title { get; }
    public string Subtitle { get; }
    public ObservableCollection<ScanGroupViewModel> Groups { get; } = new();

    /// <summary>扫描结束后附加到状态栏的说明（如 Docker 虚拟磁盘体积）。</summary>
    [ObservableProperty]
    private string? _note;

    /// <summary>一次扫描结束（成功、取消或失败）。</summary>
    public event EventHandler? ScanCompleted;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ScanCommand), nameof(ScanAllCommand), nameof(CleanCommand), nameof(SelectSafeOnlyCommand), nameof(SelectNoneCommand), nameof(IgnoreItemCommand), nameof(RescanIncompleteCommand), nameof(ExportReportCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _status = "点击“开始扫描”查看可清理的内容。";

    [ObservableProperty]
    private string _progressDetail = "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CleanCommand))]
    private bool _hasResults;

    [ObservableProperty]
    private string _totalText = "";

    [ObservableProperty]
    private string _selectedText = "";

    [ObservableProperty]
    private string? _lastReport;

    [ObservableProperty]
    private bool _hasReportProblems;

    /// <summary>结果筛选关键字；本次清理只处理筛选后可见的已选项。</summary>
    [ObservableProperty]
    private string _filterText = "";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasActiveFilter))]
    private CleanRiskFilter _riskFilter;

    [ObservableProperty]
    private CleanSortOrder _sortOrder;

    [ObservableProperty]
    private string _visibleResultsText = "";

    [ObservableProperty]
    private bool _hasNoVisibleResults;

    public bool HasActiveFilter => !string.IsNullOrWhiteSpace(FilterText) || RiskFilter != CleanRiskFilter.All;

    public IReadOnlyList<CleanResultOption<CleanRiskFilter>> RiskFilters { get; } =
    [
        new(CleanRiskFilter.All, "全部风险"), new(CleanRiskFilter.Safe, "安全"),
        new(CleanRiskFilter.Confirm, "建议确认"), new(CleanRiskFilter.High, "高风险"),
        new(CleanRiskFilter.NotRecommended, "不建议清理"),
    ];

    public IReadOnlyList<CleanResultOption<CleanSortOrder>> SortOrders { get; } =
    [
        new(CleanSortOrder.ScanOrder, "扫描顺序"), new(CleanSortOrder.SizeDescending, "大小：从大到小"),
        new(CleanSortOrder.NameAscending, "名称"), new(CleanSortOrder.RiskAscending, "风险：从低到高"),
    ];

    /// <summary>风险分布："安全 12 · 建议确认 3 · 高风险 1"。</summary>
    [ObservableProperty]
    private string _riskSummary = "";

    public CleanPageViewModel(AppServices s, string title, string subtitle, Func<IScanner[]> scanners, Func<string?>? postScanNote = null,
        AppSettings? selectionSettings = null)
    {
        _s = s;
        _scanRows = ScanRowsAsync;
        Title = title;
        Subtitle = subtitle;
        _scanners = scanners;
        _postScanNote = postScanNote;
        var settings = selectionSettings ?? s?.Settings;
        Groups.CollectionChanged += (_, _) =>
        {
            foreach (var removed in _observedGroups.Where(g => !Groups.Contains(g)).ToArray())
            {
                if (_selectionTrackers.Remove(removed, out var tracker)) tracker.Dispose();
                removed.SelectionChanged -= OnGroupSelectionChanged;
                _observedGroups.Remove(removed);
            }
            foreach (var added in Groups.Where(g => !_observedGroups.Contains(g)))
            {
                if (settings is not null)
                    _selectionTrackers.Add(added, new CleanSelectionTracker(added, settings, () => !IsBusy,
                        error => SelectionSaveError = error));
                _observedGroups.Add(added);
                added.SelectionChanged += OnGroupSelectionChanged;
                added.ApplyFilter(FilterText, RiskFilter);
                added.SortItems(SortOrder);
            }
            UpdateTotals();
        };
    }

    internal CleanPageViewModel(string title,
        Func<IProgress<ScanProgress>, CancellationToken, Task<IReadOnlyList<ScanItemViewModel>>> scanRows,
        AppSettings? settings = null) : this(null!, title, "", () => [], selectionSettings: settings)
    {
        _scanRows = scanRows;
    }

    private async Task<IReadOnlyList<ScanItemViewModel>> ScanRowsAsync(IProgress<ScanProgress> progress, CancellationToken ct)
    {
        var items = await _s.Scheduler.RunAsync((_scopedScanners ?? _scanners)(), _s.CreateScanContext(), progress, ct);
        var elevation = _s.Elevation;
        if (!elevation.IsElevated) await elevation.ProbeServiceAsync();
        ct.ThrowIfCancellationRequested();
        return items.Select(i => new ScanItemViewModel(i, elevation.CanExecute(i), elevation.HintFor(i), Explain)).ToList();
    }

    private void OnGroupSelectionChanged(object? sender, EventArgs e)
    {
        if (!_applyingFilter) UpdateTotals();
    }

    private bool CanScan => !IsBusy;

    [RelayCommand(IncludeCancelCommand = true, CanExecute = nameof(CanScan))]
    private Task ScanAsync(CancellationToken ct) => ScanCoreAsync(ct);

    private async Task ScanCoreAsync(CancellationToken ct, IReadOnlySet<string>? scope = null)
    {
        IsBusy = true;
        var operationId = ++_operationId;
        HasResults = false;
        ReportActionStatus = "";
        ClearGroups();
        Status = "正在扫描…";

        var progress = new Progress<ScanProgress>(p =>
        {
            if (!IsBusy || operationId != _operationId) return;
            ProgressDetail = p.CurrentPath ?? "";
            Status = $"正在扫描… 已发现 {p.ItemsFound} 项，{Format.Bytes(p.BytesFound)}";
        });

        try
        {
            var rows = await _scanRows(progress, ct);
            ct.ThrowIfCancellationRequested();
            var matched = rows.Where(r => scope is null || scope.Contains(r.Item.Id)).ToList();
            int needAdmin = matched.Count(r => !r.CanSelect);
            int viaService = matched.Count(r => r.ElevationHint == "由提权服务执行");
            foreach (var g in matched.GroupBy(r => r.Item.Group))
            {
                var group = new ScanGroupViewModel(g.Key, g);
                // 条目很多的分组（如 MUI 缓存孤儿）默认折叠，避免淹没其他分组
                if (group.Items.Count > 30) group.IsExpanded = false;
                Groups.Add(group);
                // Tracker may restore saved choices during Groups.Add. Rescan is preview-only.
                if (scope is not null || HasScanScope) foreach (var row in group.Items) row.IsSelected = false;
            }

            HasResults = Groups.Count > 0;
            UpdateTotals();
            Status = HasResults
                ? $"扫描完成：{Groups.Sum(g => g.Items.Count)} 项，共 {TotalText}。"
                : "扫描完成，没有发现可清理的内容。";
            if (scope is not null)
                Status = $"重新扫描完成：找到 {matched.Count} 个原未完成项目，已全部取消勾选，请核对最新内容后选择。未再次检出的项目不代表此前删除成功。";
            else if (HasScanScope)
                Status = $"定向预览完成：找到 {matched.Count} 项，已全部取消勾选，请核对后选择。没有结果可能是缺少卸载依据或规则尚未覆盖。";
            if (needAdmin > 0) Status += $" 其中 {needAdmin} 项需要管理员权限，已禁用；点击左下角“以管理员身份重新启动”后可清理。";
            if (viaService > 0) Status += $" {viaService} 项将由提权服务执行。";
            try { Note = _postScanNote?.Invoke(); } catch { Note = null; }
        }
        catch (OperationCanceledException)
        {
            Status = "扫描已取消。";
        }
        catch (Exception ex)
        {
            Status = $"扫描出错：{ex.Message}";
        }
        finally
        {
            ProgressDetail = "";
            IsBusy = false;
            ScanCompleted?.Invoke(this, EventArgs.Empty);
        }
    }

    private bool CanClean => !IsBusy && HasResults && Groups.Any(g => g.SelectedCount > 0);

    private ItemExplanation.Text Explain(ScanItem item) => ItemExplanation.For(item, _s.Settings.RetentionDays, _s.Quarantine.GetQuarantineRoot);

    partial void OnFilterTextChanged(string value)
    {
        OnPropertyChanged(nameof(HasActiveFilter));
        ApplyResultFilter();
    }

    partial void OnRiskFilterChanged(CleanRiskFilter value) => ApplyResultFilter();

    partial void OnSortOrderChanged(CleanSortOrder value)
    {
        foreach (var g in Groups) g.SortItems(value);
    }

    private void ApplyResultFilter()
    {
        _applyingFilter = true;
        try { foreach (var g in Groups) g.ApplyFilter(FilterText, RiskFilter); }
        finally { _applyingFilter = false; }
        UpdateTotals();
    }

    [RelayCommand]
    private void ClearFilter()
    {
        FilterText = "";
        RiskFilter = CleanRiskFilter.All;
    }

    /// <summary>取消当前正在进行的扫描或清理。</summary>
    [RelayCommand]
    private void Cancel()
    {
        if (ScanCommand.IsRunning) ScanCancelCommand.Execute(null);
        if (CleanCommand.IsRunning) CleanCancelCommand.Execute(null);
        if (RescanIncompleteCommand.IsRunning) RescanIncompleteCancelCommand.Execute(null);
    }

    [RelayCommand(IncludeCancelCommand = true, CanExecute = nameof(CanClean))]
    private async Task CleanAsync(CancellationToken ct)
    {
        var selected = Groups.SelectMany(g => g.SelectedVisibleItems).ToList();
        if (selected.Count == 0) return;

        var serviceItems = selected.Where(i => _s.Elevation.ViaService(i.Item)).ToList();
        var localItems = selected.Except(serviceItems).ToList();

        var risky = selected.Count(i => i.Risk != RiskLevel.Safe);
        var recycle = selected.Any(i => i.Item.Kind == ItemKind.RecycleBin);
        var commands = selected.Count(i => i.Item.Kind == ItemKind.Command);
        var registryLike = selected.Count(i => i.Item.IsRegistryLike);
        var fileLike = selected.Count - registryLike - commands - (recycle ? 1 : 0);

        var msg = $"将清理 {selected.Count} 项，约 {Format.Bytes(selected.Sum(i => i.SizeBytes))}。";
        if (HasActiveFilter) msg += "\n\n仅处理当前筛选结果中的已选项目，隐藏项目本次不处理。";
        if (fileLike > 0) msg += $"\n\n文件会先移入隔离区，默认保留 {_s.Settings.RetentionDays} 天；超过容量上限可能提前淘汰，未永久删除前可恢复。";
        if (registryLike > 0) msg += $"\n\n{registryLike} 项为注册表值 / 键、服务或计划任务：不经过隔离区，删除前自动备份（.reg / 任务 XML），可在“设置 → 备份与还原”中还原。";
        if (risky > 0) msg += $"\n\n注意：其中 {risky} 项为“建议确认”或“高风险”级别，请确认已阅读说明。";
        if (recycle) msg += "\n\n注意：清空回收站不经过隔离区，不可恢复。";
        if (commands > 0) msg += $"\n\n注意：{commands} 项为系统命令（如 DISM），执行需要数分钟且不可撤销。";
        if (serviceItems.Count > 0) msg += $"\n\n{serviceItems.Count} 项位于系统目录，将交给提权服务执行（服务会按同样的规则重新核对后再移入隔离区）。";

        var icon = risky > 0 || recycle ? MessageBoxImage.Warning : MessageBoxImage.Question;
        if (MessageBox.Show(msg, "确认清理", MessageBoxButton.OKCancel, icon) != MessageBoxResult.OK) return;

        IsBusy = true;
        var operationId = ++_operationId;
        Status = "正在清理…";
        ReportActionStatus = "";
        var report = new CleanReport();
        var serviceOutcomes = new Dictionary<string, bool>(StringComparer.Ordinal);
        var serviceIssues = new List<CleanFailure>();
        try
        {
            var progress = new Progress<CleanProgress>(p =>
            {
                if (!IsBusy || operationId != _operationId) return;
                ProgressDetail = p.CurrentItem;
                Status = $"正在清理… {p.Done}/{p.Total}，已处理 {Format.Bytes(p.ProcessedBytes)}";
            });

            var incomplete = new HashSet<string>(StringComparer.Ordinal);
            var serviceMessages = new List<string>();
            long serviceBytes = 0;
            try
            {
                if (localItems.Count > 0)
                    report = await _s.Engine.CleanAsync(localItems.Select(i => i.Item).ToList(), progress, ct);
            }
            catch (CleanCancelledException ex) { report = ex.Report; }

            if (serviceItems.Count > 0 && !report.Cancelled)
            {
                Status = $"正在通过提权服务清理 {serviceItems.Count} 项…";
                var result = await _s.Elevation.RunViaServiceAsync(serviceItems.Select(i => i.Item).ToList(), ct);
                serviceMessages = result.Messages;
                serviceBytes = result.QuarantinedBytes;
                serviceOutcomes = result.Outcomes;
                serviceIssues = result.Issues;
                report.Cancelled |= result.Cancelled;
            }
            foreach (var vm in selected)
            {
                var complete = serviceItems.Contains(vm) ? serviceOutcomes.GetValueOrDefault(vm.Item.Id)
                    : report.Outcomes.TryGetValue(vm.Item.Id, out var outcome) && outcome.Complete && !outcome.Untouched;
                if (!complete) incomplete.Add(vm.Item.Id);
            }

            // 按引擎给出的逐条结果更新列表：只有全部文件都成功处理的条目才移除；有失败、有跳过（扫描后变化、白名单）
            // 或未处理的条目保留并取消勾选，让用户看到哪些没处理完。选择状态以发起时固定的 selected 为准，不读界面当前状态。
            foreach (var vm in selected)
            {
                if (incomplete.Contains(vm.Item.Id))
                {
                    vm.IsSelected = false;
                    continue;
                }
                var group = Groups.FirstOrDefault(g => g.Items.Contains(vm));
                group?.Remove(vm);
            }
            foreach (var empty in Groups.Where(g => g.Items.Count == 0).ToList()) Groups.Remove(empty);

            HasResults = Groups.Count > 0;
            UpdateTotals();

            var summary = $"{report.FilesQuarantined} 个文件与 {report.DirectoriesQuarantined} 个目录移入隔离区（{Format.Bytes(report.QuarantinedBytes)}，到期或永久删除后释放）";
            if (report.RegistryEntriesRemoved > 0) summary += $"，删除 {report.RegistryEntriesRemoved} 项注册表 / 服务 / 任务（已备份，可在设置中还原）";
            if (report.RegistryEntriesAlreadyAbsent > 0) summary += $"，{report.RegistryEntriesAlreadyAbsent} 项注册表目标已不存在，无需清理（已从列表移除）";
            if (report.FreedBytes > 0) summary += $"，直接释放 {Format.Bytes(report.FreedBytes)}";
            if (report.InUse > 0) summary += $"，{report.InUse} 个文件正在被其他程序使用，这次跳过（关闭相关程序后重新扫描即可）";
            if (report.Skipped > 0) summary += $"，跳过 {report.Skipped} 个已变化、已不存在或被安全排除的文件（所在项目保留在列表中）";
            if (report.Failures.Count > 0) summary += $"，{report.Failures.Count} 项失败（仍保留在列表中）";
            if (serviceItems.Count > 0) summary += $"；提权服务请求 {serviceItems.Count} 项（{Format.Bytes(serviceBytes)}）" + (serviceMessages.Count > 0 ? $"，{serviceMessages.Count} 条问题" : "");
            summary += $"。耗时 {report.Elapsed.TotalSeconds:0.#} 秒。";

            HasReportProblems = incomplete.Count > 0 || report.Failures.Count > 0 || serviceMessages.Count > 0;
            LastReport = summary;
            Status = incomplete.Count > 0 ? "清理完成，部分项目未完全处理。重新扫描可刷新这些项目的内容。" : "清理完成。";

            if (report.Cancelled)
            {
                summary = "清理已取消。" + summary;
                Status = "已取消，已返回的结果保留如下；未确认完成的项目请重新扫描。";
            }
            SetExecutionReport(CleanExecutionReport.Create(Title, selected.Select(v => v.Item).ToList(), report,
                serviceItems.Select(v => v.Item.Id).ToHashSet(StringComparer.Ordinal), serviceOutcomes, serviceIssues, summary));

        }
        catch (Exception ex)
        {
            Status = $"清理出错：{ex.Message}";
            foreach (var vm in selected) vm.IsSelected = false;
            UpdateTotals();
            // A fatal error may have interrupted a write before a report was returned. Keep uncertainty explicit.
            serviceIssues.Add(new("execution", "本次清理", null, ex.Message, CleanIssueKind.NotProcessed, ex.HResult));
            SetExecutionReport(CleanExecutionReport.Create(Title, selected.Select(v => v.Item).ToList(), report,
                serviceItems.Select(v => v.Item.Id).ToHashSet(StringComparer.Ordinal), serviceOutcomes, serviceIssues, Status));
        }
        finally
        {
            ProgressDetail = "";
            IsBusy = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanScan))]
    private void SelectSafeOnly()
    {
        foreach (var g in Groups) g.SelectSafeOnly();
        UpdateTotals();
    }

    [RelayCommand(CanExecute = nameof(CanScan))]
    private void SelectNone()
    {
        foreach (var g in Groups) g.IsChecked = false;
        UpdateTotals();
    }

    private bool CanIgnoreItem(ScanItemViewModel? item) => !IsBusy && item is not null && Groups.Any(g => g.Items.Contains(item));

    [RelayCommand(CanExecute = nameof(CanIgnoreItem))]
    private void IgnoreItem(ScanItemViewModel? item)
    {
        if (item is null || !CanIgnoreItem(item)) return;
        if (MessageBox.Show($"以后不再扫描“{item.Name}”？\n可在“设置”页面的白名单中恢复。", "加入白名单",
                MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;

        _s.Whitelist.AddItem(item.Item.Id);
        var group = Groups.FirstOrDefault(g => g.Items.Contains(item));
        group?.Remove(item);
        if (group is { Items.Count: 0 }) Groups.Remove(group);
        HasResults = Groups.Count > 0;
        UpdateTotals();
    }

    private void UpdateTotals()
    {
        TotalText = Format.Bytes(Groups.Sum(g => g.TotalBytes));
        var allRows = Groups.SelectMany(g => g.Items).ToArray();
        var visibleRows = allRows.Where(i => i.IsVisible).ToArray();
        VisibleResultsText = $"显示 {visibleRows.Length}/{allRows.Length} 项 · {Format.Bytes(visibleRows.Sum(i => i.SizeBytes))}";
        HasNoVisibleResults = allRows.Length > 0 && visibleRows.Length == 0;
        var count = Groups.Sum(g => g.SelectedCount);
        SelectedText = count == 0 ? "未选择任何项目" : $"已选择 {count} 项，{Format.Bytes(Groups.Sum(g => g.SelectedBytes))}";
        var hidden = Groups.Sum(g => g.Items.Count(i => !i.IsVisible && i.IsSelected && i.CanSelect));
        if (hidden > 0) SelectedText += $"（筛选外 {hidden} 项本次不处理）";
        var parts = new List<string>();
        foreach (var (risk, label) in new[] { (RiskLevel.Safe, "安全"), (RiskLevel.Confirm, "建议确认"), (RiskLevel.High, "高风险"), (RiskLevel.NotRecommended, "不建议") })
        {
            var n = Groups.Sum(g => g.CountByRisk(risk));
            if (n > 0) parts.Add($"{label} {n}");
        }
        RiskSummary = string.Join(" · ", parts);
        CleanCommand.NotifyCanExecuteChanged();
        IgnoreItemCommand.NotifyCanExecuteChanged();
    }

    private void ClearGroups()
    {
        Groups.Clear();
        TotalText = "";
        SelectedText = "";
        RiskSummary = "";
        FilterText = "";
        RiskFilter = CleanRiskFilter.All;
        VisibleResultsText = "";
        HasNoVisibleResults = false;
    }
}

public sealed record CleanReportFilterOption(string Label, CleanIssueKind? Kind, bool ProblemsOnly = false);
