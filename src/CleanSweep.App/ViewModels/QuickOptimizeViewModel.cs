using System.Collections.ObjectModel;
using System.Windows;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Scanning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CleanSweep.App.ViewModels;

public sealed partial class QuickOptimizeViewModel : ObservableObject
{
    private readonly Func<QuickOptimizeRequest, IProgress<QuickOptimizeProgress>, CancellationToken, Task<QuickOptimizeResult>> _run;
    private readonly Func<string?> _block;
    private readonly Action<string> _navigate;
    private readonly TimeProvider _clock;
    private readonly TimeSpan _minimumPresentation;
    private readonly Func<bool> _animationsEnabled;
    private readonly Func<TimeSpan, CancellationToken, Task> _presentationDelay;
    private long _generation;

    public QuickOptimizeViewModel(AppServices services, Func<string?> block, Action<string> navigate)
        : this(new QuickOptimizer(services).RunAsync, block, navigate, minimumPresentation: TimeSpan.FromSeconds(3)) { }

    internal QuickOptimizeViewModel(
        Func<QuickOptimizeRequest, IProgress<QuickOptimizeProgress>, CancellationToken, Task<QuickOptimizeResult>> run,
        Func<string?>? block = null, Action<string>? navigate = null,
        TimeSpan? minimumPresentation = null, Func<bool>? animationsEnabled = null,
        TimeProvider? clock = null, Func<TimeSpan, CancellationToken, Task>? presentationDelay = null)
    {
        _run = run;
        _block = block ?? (() => null);
        _navigate = navigate ?? (_ => { });
        _clock = clock ?? TimeProvider.System;
        _minimumPresentation = minimumPresentation ?? TimeSpan.Zero;
        _animationsEnabled = animationsEnabled ?? (() => SystemParameters.ClientAreaAnimation);
        _presentationDelay = presentationDelay ?? ((duration, token) => Task.Delay(duration, _clock, token));
    }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(OptimizeCommand), nameof(NavigateCommand))]
    [NotifyPropertyChangedFor(nameof(CanEditScope))]
    private bool _isBusy;
    public bool CanEditScope => !IsBusy;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(CancelButtonText))] private bool _isPresenting;
    public string CancelButtonText => IsPresenting ? "立即查看结果" : "停止优化";
    [ObservableProperty, NotifyPropertyChangedFor(nameof(ScopeSummary))] private bool _cleanTemp = true;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(ScopeSummary))] private bool _cleanCache = true;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(ScopeSummary))] private bool _cleanLogs = true;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(ScopeSummary))] private bool _releaseStandby;
    public string ScopeSummary => "本次范围：" + string.Join(" · ", new[]
    {
        CleanTemp ? "7 天以上临时文件" : null,
        CleanCache ? "7 天以上网页缓存" : null,
        CleanLogs ? "30 天以上 .NET 日志" : null,
        ReleaseStandby ? "低优先级待机缓存" : null,
    }.Where(s => s is not null));
    [ObservableProperty] private string _headline = "准备开始一键优化";
    [ObservableProperty] private string _stage = "准备就绪";
    [ObservableProperty] private string _detail = "按下按钮，扫描并整理下方勾选范围；文件先进入可恢复的隔离区。";
    [ObservableProperty] private double _progress;
    [ObservableProperty] private double _processedFiles = double.NaN;
    [ObservableProperty] private double _quarantinedBytes = double.NaN;
    [ObservableProperty] private double _freedBytes = double.NaN;
    [ObservableProperty] private double _memoryDelta = double.NaN;
    [ObservableProperty] private double _bootSeconds = double.NaN;
    [ObservableProperty] private string _memoryDetail = "可选处理低优先级待机缓存；默认只测量";
    [ObservableProperty] private string _resultSummary = "完成后显示本次实测结果";
    [ObservableProperty] private string _memoryMessage = "无需结束应用，也不修改系统服务";
    [ObservableProperty] private bool _hasResult;
    [ObservableProperty] private bool _showCompletionEffect;
    public ObservableCollection<CleanFailure> Issues { get; } = new();

    private bool NotBusy => !IsBusy;

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private void Navigate(string title) => _navigate(title);

    [RelayCommand(IncludeCancelCommand = true, CanExecute = nameof(NotBusy))]
    private async Task OptimizeAsync(CancellationToken ct)
    {
        if (IsBusy) return;
        if (_block() is { } reason) { Detail = reason + "，请等待完成后再开始。"; return; }
        if (!CleanTemp && !CleanCache && !CleanLogs && !ReleaseStandby) { Detail = "请至少勾选一个处理范围。"; return; }
        var request = new QuickOptimizeRequest(new QuickOptimizeScope(CleanTemp, CleanCache, CleanLogs), ReleaseStandby);
        var started = _clock.GetTimestamp();
        var animate = _animationsEnabled();
        IsBusy = true;
        var generation = ++_generation;
        HasResult = false;
        ShowCompletionEffect = false;
        Issues.Clear();
        ProcessedFiles = QuarantinedBytes = FreedBytes = MemoryDelta = BootSeconds = double.NaN;
        MemoryDetail = "正在采样";
        MemoryMessage = "内存变化受其他程序活动影响";
        ResultSummary = "正在处理，尚未生成本次结果";
        Headline = "正在为你整理";
        Stage = "开始检查";
        Progress = 0;
        var progress = new Progress<QuickOptimizeProgress>(p =>
        {
            if (!IsBusy || generation != _generation) return;
            Stage = p.Stage;
            Detail = p.Detail;
            Progress = Math.Clamp(p.Percent, 0, 100);
        });
        try
        {
            var result = await _run(request, progress, ct);
            var report = result.Report;
            ++_generation; // 实际任务已返回，排队中的阶段回调不得覆盖结果展示状态。
            var remaining = _minimumPresentation - _clock.GetElapsedTime(started);
            var completedNormally = !report.Cancelled && report.IncompleteItemIds.Count == 0 && report.Failures.Count == 0
                && (!request.ReleaseStandby || result.MemorySucceeded);
            if (animate && completedNormally && !ct.IsCancellationRequested && remaining > TimeSpan.Zero)
            {
                IsPresenting = true;
                Headline = "处理已结束，正在展示结果";
                Stage = "结果展示";
                Detail = "结果已就绪，可跳过动画直接查看。";
                ResultSummary = "操作已结束，正在播放完成动画";
                Progress = 100;
                try { await _presentationDelay(remaining, ct); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { /* 跳过展示不撤销已取得的结果。 */ }
                finally { IsPresenting = false; }
            }
            ProcessedFiles = report.FilesQuarantined;
            QuarantinedBytes = report.QuarantinedBytes;
            FreedBytes = report.FreedBytes;
            MemoryDelta = result.MemoryBefore.HasValue && result.MemoryAfter.HasValue ? result.MemoryAfter.Value - result.MemoryBefore.Value : double.NaN;
            BootSeconds = result.BootSeconds ?? double.NaN;
            MemoryDetail = $"可用内存：{(result.MemoryBefore is { } before ? Format.Bytes(before) : "未读取")} → {(result.MemoryAfter is { } after ? Format.Bytes(after) : "未读取")}";
            MemoryMessage = result.MemoryMessage;
            foreach (var issue in report.Failures.Concat(report.SkippedDetails).Concat(report.InUseFiles)) Issues.Add(issue);
            HasResult = true;
            ShowCompletionEffect = completedNormally && (report.FilesQuarantined > 0 || report.FreedBytes > 0 || result.MemorySucceeded);
            Headline = report.Cancelled ? "已停止，已处理的文件可恢复"
                : request.ReleaseStandby && !result.MemorySucceeded ? "处理结束，内存操作未完成"
                : report.IncompleteItemIds.Count > 0 ? "整理完成，部分项目已保留"
                : report.FilesQuarantined == 0 && !result.MemorySucceeded ? "检查完成，暂无需要处理的文件" : "整理完成";
            Stage = report.Cancelled ? "已取消" : "本次结果";
            Detail = "文件在隔离区保留至到期或手动永久删除；本次未自动调整启动项。";
            ResultSummary = $"候选 {result.Candidates:N0} 个文件 · 已隔离 {report.FilesQuarantined:N0} 个 · 问题记录 {Issues.Count:N0} 条";
            Progress = report.Cancelled ? Progress : 100;
        }
        catch (OperationCanceledException)
        {
            Headline = "已取消";
            Stage = "已停止";
            Detail = "扫描已停止，没有可展示的清理结果。";
            MemoryDetail = "未取得完整采样";
            ResultSummary = "本次已取消，未产生清理结果。";
        }
        catch (Exception ex)
        {
            Headline = "本次优化未完成";
            Stage = "需要检查";
            Detail = ex.Message;
            MemoryDetail = "结果不完整";
            ResultSummary = "未确认完成的操作不计为成功；如已开始处理，可到隔离区查看。";
        }
        finally { ++_generation; IsPresenting = false; IsBusy = false; }
    }
}
