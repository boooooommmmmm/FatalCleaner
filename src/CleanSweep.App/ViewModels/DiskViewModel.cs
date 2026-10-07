using System.Collections.ObjectModel;
using System.Windows;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.Core.Disk;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CleanSweep.App.ViewModels;

public sealed class DiskRow
{
    public required PhysicalDiskInfo Disk { get; init; }
    public SmartInfo? Smart { get; init; }
    public string Name => Disk.FriendlyName;
    public string MediaText => Disk.Media switch { MediaKind.Hdd => "机械盘", MediaKind.Ssd => "固态盘", MediaKind.Scm => "存储级内存", _ => "未知" };
    public string Bus => Disk.BusType;
    public string SizeText => Format.Bytes(Disk.SizeBytes);
    public string Health => Disk.HealthStatus;
    public string SmartText
    {
        get
        {
            if (Smart is null) return "";
            var parts = new List<string>();
            if (Smart.PredictFailure is { } p) parts.Add(p ? "S.M.A.R.T. 预测故障！" : "S.M.A.R.T. 正常");
            if (Smart.TemperatureCelsius is { } t) parts.Add($"{t} °C");
            if (Smart.WearPercent is { } w) parts.Add($"磨损 {w}%");
            if (Smart.PowerOnHours is { } h) parts.Add($"通电 {h} 小时");
            if (Smart.ReadErrorsTotal is { } r && r > 0) parts.Add($"读错误 {r}");
            return parts.Count == 0 ? (Smart.Note ?? "无 S.M.A.R.T. 数据") : string.Join(" · ", parts);
        }
    }
    public bool IsWarning => Smart?.PredictFailure == true || Disk.HealthStatus != "健康";
}

public sealed class VolumeRow
{
    public required VolumeInfo Volume { get; init; }
    public string Letter => Volume.Letter;
    // CommandParameter is object-typed; WPF StringFormat does not format it.
    public string AnalyzeParameter => $"{Letter}|Analyze";
    public string OptimizeParameter => $"{Letter}|Optimize";
    public string RetrimParameter => $"{Letter}|Retrim";
    public string DefragmentParameter => $"{Letter}|Defragment";
    public string ScheduleCheckDiskParameter => $"{Letter}|ScheduleCheckDisk";
    public string Label => string.IsNullOrEmpty(Volume.Label) ? "本地磁盘" : Volume.Label;
    public string FileSystem => Volume.FileSystem;
    public string SizeText => $"{Format.Bytes(Volume.SizeBytes - Volume.FreeBytes)} / {Format.Bytes(Volume.SizeBytes)}";
    public double UsedPercent => Volume.UsedFraction * 100;
    public string MediaText => Volume.Media switch { MediaKind.Hdd => "机械盘", MediaKind.Ssd => "固态盘", MediaKind.Scm => "存储级内存", _ => "未知" };
    public bool CanDefragment => Volume.Media == MediaKind.Hdd && Volume.Type == DriveType.Fixed;
    public bool CanRetrim => Volume.Media is MediaKind.Ssd or MediaKind.Scm;
    public bool IsFixed => Volume.Type == DriveType.Fixed;
    public bool IsNtfs => Volume.FileSystem.Equals("NTFS", StringComparison.OrdinalIgnoreCase);
}

/// <summary>磁盘健康与优化页（设计文档 4.2）。</summary>
public sealed partial class DiskViewModel : ObservableObject
{
    private readonly AppServices _s;

    public ObservableCollection<DiskRow> Disks { get; } = new();
    public ObservableCollection<VolumeRow> Volumes { get; } = new();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RefreshCommand), nameof(RunCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _status = "读取磁盘信息…";

    [ObservableProperty]
    private string _scheduleText = "";

    [ObservableProperty]
    private string _output = "";

    public bool HasLoaded { get; private set; }

    /// <summary>普通权限下的提示：defrag 与 chkntfs /C 都需要管理员身份。</summary>
    public string? ElevationHint => _s.Elevation.IsElevated ? null
        : "当前为普通权限运行：分析、优化、修剪、碎片整理与计划检查磁盘都需要管理员身份，点击时会提示以管理员身份重新启动。";

    public DiskViewModel(AppServices s)
    {
        _s = s;
    }

    private bool NotBusy => !IsBusy;

    [RelayCommand(CanExecute = nameof(NotBusy))]
    private async Task RefreshAsync()
    {
        IsBusy = true;
        try
        {
            var (disks, volumes, smart, schedule) = await Task.Run(() =>
            {
                var d = DiskHealth.GetPhysicalDisks();
                return (d, DiskHealth.GetVolumes(d), DiskHealth.GetSmart(d), DiskHealth.GetOptimizeSchedule());
            });
            Disks.Clear();
            foreach (var d in disks) Disks.Add(new DiskRow { Disk = d, Smart = smart.FirstOrDefault(x => x.DiskNumber == d.Number) });
            Volumes.Clear();
            foreach (var v in volumes) Volumes.Add(new VolumeRow { Volume = v });
            ScheduleText = schedule.TaskFound
                ? $"系统“优化驱动器”计划任务：{(schedule.Enabled ? "已启用" : "已禁用")}" +
                  (schedule.LastRun is { } lr ? $"，上次运行 {lr:yyyy-MM-dd HH:mm}" : "，尚未运行") +
                  (schedule.NextRun is { } nr ? $"，下次 {nr:yyyy-MM-dd HH:mm}" : "") +
                  (schedule.LastResult is { } r && r != 0 ? $"，上次结果代码 0x{r:X}" : "") +
                  "。Windows 每周自动对机械盘整理、对固态盘修剪，本程序不自研整理算法。"
                : "无法读取系统优化计划：" + schedule.Note;
            HasLoaded = true;
            Status = $"{disks.Count} 块物理磁盘，{volumes.Count} 个卷。" + (Disks.Any(d => d.IsWarning) ? " 有磁盘报告健康警告，请尽快备份数据。" : "");
        }
        catch (Exception ex)
        {
            Status = "读取失败：" + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>参数形如 "C:|Analyze"。</summary>
    [RelayCommand(IncludeCancelCommand = true, CanExecute = nameof(NotBusy))]
    private async Task RunAsync(string? parameter, CancellationToken ct)
    {
        var parts = parameter?.Split('|');
        if (parts is not { Length: 2 } || !Enum.TryParse<DiskHealth.DiskOperation>(parts[1], out var op) || !Enum.IsDefined(op))
        {
            Status = "无法执行：磁盘操作参数无效，请刷新磁盘信息后重试。";
            return;
        }
        var row = Volumes.FirstOrDefault(v => v.Letter == parts[0]);
        if (row is null)
        {
            Status = "无法执行：未找到所选卷，请刷新磁盘信息后重试。";
            return;
        }

        var cmd = DiskHealth.BuildCommand(op, row.Letter, row.Volume.Media, out var error);
        if (cmd is null)
        {
            MessageBox.Show(error, "无法执行", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        // defrag / chkntfs /C 在普通权限下不会执行（defrag 只打印 0x89000024 且退出码为 0），先问是否以管理员身份重新启动
        if (DiskHealth.RequiresElevation(op) && !_s.Elevation.IsElevated)
        {
            var choice = MessageBox.Show("磁盘优化与检查命令需要管理员身份，当前是普通权限运行。\n\n是否现在以管理员身份重新启动 FatalCleaner？重新启动后回到本页再执行。",
                "需要管理员身份", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (choice == MessageBoxResult.Yes)
            {
                var err = ElevationContext.RelaunchElevated();
                if (err is null) { Application.Current.Shutdown(0); return; }
                if (err != "已取消提权") MessageBox.Show($"无法以管理员身份重新启动：{err}", "FatalCleaner", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return;
        }

        string title = op switch
        {
            DiskHealth.DiskOperation.Analyze => "分析碎片（只读）",
            DiskHealth.DiskOperation.Optimize => "优化驱动器",
            DiskHealth.DiskOperation.Retrim => "重新修剪（TRIM）",
            DiskHealth.DiskOperation.Defragment => "碎片整理",
            DiskHealth.DiskOperation.ScheduleCheckDisk => "计划下次启动时检查磁盘",
            DiskHealth.DiskOperation.QueryCheckDisk => "查询磁盘检查状态",
            _ => op.ToString(),
        };
        if (op is not (DiskHealth.DiskOperation.Analyze or DiskHealth.DiskOperation.QueryCheckDisk))
        {
            var note = op == DiskHealth.DiskOperation.ScheduleCheckDisk
                ? "下次重启时会在登录前运行 chkdsk 检查并修复该卷，耗时几分钟到几十分钟。"
                : "过程可能持续较长时间，期间磁盘性能下降；一旦开始不会中途强杀，取消只停止等待。";
            if (MessageBox.Show($"{title} {row.Letter}？\n\n将执行：{cmd.Value.Exe} {cmd.Value.Args}\n\n{note}", title, MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        }

        IsBusy = true;
        Output = "";
        Status = $"正在执行 {title} {row.Letter}…";
        try
        {
            var progress = new Progress<string>(line => Output += line + "\n");
            var result = await DiskHealth.RunAsync(op, row.Letter, row.Volume.Media, ct, progress);
            _s.Log.Write(null, "disk", op.ToString(), row.Letter, 0, result.Success, result.TimedOut ? "超时" : $"退出码 {result.ExitCode}");
            Status = result.Success ? $"{title} 完成（{result.Elapsed.TotalSeconds:0} 秒）。"
                : result.TimedOut ? $"{title} 超时，已终止。"
                : DiskHealth.DescribeExitCode(result.ExitCode) is { } why ? $"{title} 未执行：{why}。"
                : $"{title} 退出码 0x{unchecked((uint)result.ExitCode):X8}，详见命令输出。";
            if (string.IsNullOrWhiteSpace(Output)) Output = result.Output;
        }
        catch (Exception ex)
        {
            Status = $"{title} 出错：{ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
