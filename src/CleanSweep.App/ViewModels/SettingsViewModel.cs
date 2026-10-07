using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Text;
using System.Windows;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.Core.Backup;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;

namespace CleanSweep.App.ViewModels;

public sealed class BatchRow
{
    public required BatchRecord Batch { get; init; }
    public string StartedText => Format.LocalTime(Batch.StartedUtc);
    public string Modules => Batch.ModuleIds;
    public string ItemsText => $"{Batch.ItemCount} 项";
    public string FreedText => Format.Bytes(Batch.FreedBytes);
    public string StateText => Batch.FinishedUtc is null ? "未完成" : "完成";
}

public sealed class RegistryBackupRow
{
    public required RegistryBackupRecord Record { get; init; }
    public string TimeText => Format.LocalTime(Record.TsUtc);
    public string KeyPath => Record.KeyPath + (Record.View == RegistryView.Registry32 ? "（32 位）" : "");
    public string Reason => Record.Reason;
    public string StateText => Record.RestoredUtc is null ? "" : $"已于 {Format.LocalTime(Record.RestoredUtc.Value)} 还原";
    public string FileName => Path.GetFileName(Record.File);
}

public sealed class TaskBackupRow
{
    public required CleanSweep.Core.RegistryCleaning.RegistryOps.TaskBackupRecord Record { get; init; }
    public string TimeText => Format.LocalTime(Record.TsUtc);
    public string TaskPath => Record.TaskPath;
    public string Reason => Record.Reason;
    public string StateText => Record.RestoredUtc is null ? "" : $"已于 {Format.LocalTime(Record.RestoredUtc.Value)} 恢复";
    public string FileName => Record.FileName;
}

public sealed partial class SettingsViewModel : ObservableObject
{
    private readonly AppServices _s;

    public ObservableCollection<string> WhitelistPaths { get; } = new();
    public ObservableCollection<string> WhitelistItems { get; } = new();
    public ObservableCollection<RuleRejection> RejectedRules { get; } = new();
    public ObservableCollection<BatchRow> RecentBatches { get; } = new();
    public ObservableCollection<RegistryBackupRow> RegistryBackups { get; } = new();
    public ObservableCollection<TaskBackupRow> TaskBackups { get; } = new();

    [ObservableProperty]
    private bool _advancedMode;

    [ObservableProperty]
    private int _retentionDays;

    [ObservableProperty]
    private bool _createRestorePoint;

    [ObservableProperty]
    private string _restorePointStatus = "";

    [ObservableProperty]
    private string _rulesSummary = "";

    /// <summary>三个数据集的签名与版本状态。</summary>
    [ObservableProperty]
    private string _dataSetSummary = "";

    [ObservableProperty]
    private string _updateSource = "";

    [ObservableProperty]
    private bool _checkUpdatesOnStartup;

    [ObservableProperty]
    private string _dataUpdateStatus = "";

    [ObservableProperty]
    private string _appUpdateStatus = "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CheckDataUpdatesCommand), nameof(CheckAppUpdateCommand), nameof(InstallAppUpdateCommand))]
    private bool _isUpdating;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(InstallAppUpdateCommand))]
    private Core.Integrity.ReleaseInfo? _availableRelease;

    public string AppVersionText => $"当前版本 {_s.CurrentVersion.ToString(3)}";
    public AppUpdateCoordinator Updates => _s.AppUpdates;

    [ObservableProperty]
    private string _backupSummary = "";

    [ObservableProperty]
    private string _dataDir = AppPaths.DataDir;

    [ObservableProperty]
    private string? _selectedWhitelistPath;

    // M3：残留清理与卸载监控
    public ObservableCollection<string> DevProjectRoots { get; } = new();

    [ObservableProperty]
    private bool _residueScanAllUsers;

    [ObservableProperty]
    private bool _watchUninstalls;

    [ObservableProperty]
    private string _watchStatus = "";

    public bool IsElevated => AppPaths.Elevated;

    public SettingsViewModel(AppServices s)
    {
        _s = s;
        _advancedMode = s.Settings.AdvancedMode;
        _retentionDays = s.Settings.RetentionDays;
        _createRestorePoint = s.Settings.CreateRestorePoint;
        _residueScanAllUsers = s.Settings.ResidueScanAllUsers;
        _watchUninstalls = s.Settings.WatchUninstalls;
        _updateSource = s.Settings.UpdateSource;
        _checkUpdatesOnStartup = s.Settings.CheckUpdatesOnStartup;
        s.AppUpdates.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(AppUpdateCoordinator.Status) or nameof(AppUpdateCoordinator.ReadyRelease)
                or nameof(AppUpdateCoordinator.IsBusy)) SyncAppUpdateState();
        };
        SyncAppUpdateState();
        foreach (var r in s.Settings.DevProjectRoots) DevProjectRoots.Add(r);
        Refresh();
    }

    partial void OnAdvancedModeChanged(bool value)
    {
        _s.Settings.AdvancedMode = value;
        _s.Settings.Save();
    }

    partial void OnResidueScanAllUsersChanged(bool value)
    {
        _s.Settings.ResidueScanAllUsers = value;
        _s.ResidueOptions.ScanAllUsers = value;
        _s.Settings.Save();
    }

    partial void OnWatchUninstallsChanged(bool value)
    {
        _s.Settings.WatchUninstalls = value;
        _s.Settings.Save();
        _s.ApplyUninstallWatching();
        UpdateWatchStatus();
    }

    private void UpdateWatchStatus()
    {
        WatchStatus = _s.UninstallWatcher.IsRunning
            ? "正在监听：程序运行期间，检测到软件被卸载后会提示扫描它的残留。关闭窗口即停止，本程序没有常驻后台进程。"
            : "关闭。开启后只在本程序运行期间生效（监视注册表卸载项、应用商店包仓库与 Windows Installer 事件）。";
    }

    [RelayCommand]
    private void AddDevRoot()
    {
        var dlg = new OpenFolderDialog { Title = "选择项目根目录（其下的 node_modules 会被查找）" };
        if (dlg.ShowDialog() != true) return;
        if (DevProjectRoots.Contains(dlg.FolderName, StringComparer.OrdinalIgnoreCase)) return;
        DevProjectRoots.Add(dlg.FolderName);
        _s.Settings.DevProjectRoots = DevProjectRoots.ToList();
        _s.Settings.Save();
    }

    [RelayCommand]
    private void RemoveDevRoot(string? root)
    {
        if (root is null) return;
        DevProjectRoots.Remove(root);
        _s.Settings.DevProjectRoots = DevProjectRoots.ToList();
        _s.Settings.Save();
    }

    partial void OnRetentionDaysChanged(int value)
    {
        if (value is < 1 or > 365) return;
        _s.Settings.RetentionDays = value;
        _s.Quarantine.Options.RetentionDays = value;
        _s.Settings.Save();
    }

    partial void OnCreateRestorePointChanged(bool value)
    {
        _s.Settings.CreateRestorePoint = value;
        _s.Startup.CreateRestorePointForServices = value;
        _s.Settings.Save();
    }

    [RelayCommand]
    private void Refresh()
    {
        UpdateWatchStatus();
        WhitelistPaths.Clear();
        foreach (var p in _s.Whitelist.Paths.OrderBy(p => p)) WhitelistPaths.Add(p);

        WhitelistItems.Clear();
        foreach (var i in _s.Whitelist.ItemIds) WhitelistItems.Add(i);

        RejectedRules.Clear();
        foreach (var r in _s.Rules.Rejected) RejectedRules.Add(r);

        var byCategory = _s.Rules.Rules.GroupBy(r => r.Category).Select(g => $"{CategoryName(g.Key)} {g.Count()}");
        RulesSummary = $"已加载 {_s.Rules.Rules.Count} 条规则（{string.Join("，", byCategory)}）" +
                       (_s.Rules.Rejected.Count > 0 ? $"，{_s.Rules.Rejected.Count} 条被拒绝" : "");
        DataSetSummary = string.Join("；", _s.DataSetStatus.Select(d =>
            $"{DataSetName(d.KindName)}：" + (d.Verdict.Ok ? $"版本 {d.Verdict.Version}（{(d.FromUpdate ? "在线更新" : "内置")}，签名 {d.Verdict.KeyId}）" : "签名校验失败，未加载：" + d.Verdict.Reason)));

        RecentBatches.Clear();
        foreach (var b in _s.Log.GetRecentBatches(30)) RecentBatches.Add(new BatchRow { Batch = b });

        RegistryBackups.Clear();
        var backups = _s.RegistryBackup.List(50);
        foreach (var b in backups) RegistryBackups.Add(new RegistryBackupRow { Record = b });
        BackupSummary = backups.Count == 0
            ? "还没有注册表备份。每次修改注册表（如禁用启动项）前会自动导出所改的键。"
            : $"最近 {backups.Count} 条，保留 {_s.Settings.RegistryBackupRetentionDays} 天。目录：{_s.RegistryBackup.BackupDir}";

        TaskBackups.Clear();
        try
        {
            foreach (var t in _s.RegistryOps.ListTaskBackups().Take(50)) TaskBackups.Add(new TaskBackupRow { Record = t });
        }
        catch { }

        RestorePointStatus = RestorePointService.IsProtectionEnabled()
            ? $"系统保护已启用。Windows 默认每 {RestorePointService.GetFrequencyMinutes() / 60} 小时最多创建一个还原点，间隔内复用已有的。"
            : "系统保护未启用：无法创建还原点，修改服务时只有注册表备份保护。可在“系统属性 → 系统保护”中开启。";
    }

    [RelayCommand]
    private void AddWhitelistPath()
    {
        var dlg = new OpenFolderDialog { Title = "选择要永久排除的文件夹" };
        if (dlg.ShowDialog() == true)
        {
            _s.Whitelist.AddPath(dlg.FolderName);
            Refresh();
        }
    }

    [RelayCommand]
    private void RemoveWhitelistPath(string? path)
    {
        if (path is null) return;
        _s.Whitelist.RemovePath(path);
        Refresh();
    }

    [RelayCommand]
    private void RemoveWhitelistItem(string? id)
    {
        if (id is null) return;
        _s.Whitelist.RemoveItem(id);
        Refresh();
    }

    [RelayCommand]
    private void ReloadRules()
    {
        _s.ReloadRules();
        Refresh();
    }

    private static string DataSetName(string kind) => kind switch { "rules" => "规则库", "fingerprints" => "指纹库", "popups" => "弹窗规则", _ => kind };

    private bool NotUpdating => !IsUpdating && !_s.AppUpdates.IsBusy;

    private void SyncAppUpdateState()
    {
        AvailableRelease = _s.AppUpdates.ReadyRelease;
        AppUpdateStatus = _s.AppUpdates.Status;
        CheckAppUpdateCommand.NotifyCanExecuteChanged();
        CheckDataUpdatesCommand.NotifyCanExecuteChanged();
        InstallAppUpdateCommand.NotifyCanExecuteChanged();
    }

    partial void OnUpdateSourceChanged(string value)
    {
        _s.Settings.UpdateSource = value;
        _s.Settings.Save();
        _s.AppUpdates.ResetSource();
    }

    partial void OnCheckUpdatesOnStartupChanged(bool value)
    {
        _s.Settings.CheckUpdatesOnStartup = value;
        _s.Settings.Save();
    }

    private string? SourceProblem() => Core.Integrity.UpdateSources.Resolve(UpdateSource) is null
        ? (string.IsNullOrWhiteSpace(UpdateSource) ? "未设置更新来源" : "更新来源格式无效：填 GitHub 仓库 owner/repo（可加 @分支），或 https 根地址")
        : null;

    [RelayCommand(CanExecute = nameof(NotUpdating))]
    private async Task CheckAppUpdateAsync()
    {
        if (SourceProblem() is { } problem)
        {
            AppUpdateStatus = problem;
            return;
        }
        await _s.AppUpdates.CheckAndPrepareAsync(promptAgain: true);
    }

    private bool CanInstallAppUpdate => NotUpdating && AvailableRelease is not null;

    [RelayCommand(CanExecute = nameof(CanInstallAppUpdate))]
    private Task InstallAppUpdateAsync() => _s.AppUpdates.InstallPreparedAsync();

    [RelayCommand(CanExecute = nameof(NotUpdating))]
    private async Task CheckDataUpdatesAsync()
    {
        if (SourceProblem() is { } problem)
        {
            DataUpdateStatus = problem;
            return;
        }
        IsUpdating = true;
        DataUpdateStatus = "正在检查更新…";
        try
        {
            var results = await _s.UpdateDataSetsAsync();
            DataUpdateStatus = string.Join("；", results.Select(r => $"{DataSetName(Core.Integrity.DataSets.KindName(r.Kind))}：{r.Message}"));
            Refresh();
        }
        catch (Exception ex)
        {
            DataUpdateStatus = "检查更新失败：" + ex.Message;
        }
        finally
        {
            IsUpdating = false;
        }
    }

    [RelayCommand]
    private void RestoreRegistryBackup(RegistryBackupRow? row)
    {
        if (row is null) return;
        var r = MessageBox.Show(
            $"用 {row.TimeText} 的备份还原以下键？\n\n{row.Record.KeyPath}\n\n备份之后新增的值会保留，被修改或删除的值恢复到备份时的状态。",
            "还原注册表备份", MessageBoxButton.OKCancel, MessageBoxImage.Question);
        if (r != MessageBoxResult.OK) return;

        try
        {
            _s.RegistryBackup.Restore(row.Record.Id);
            _s.Log.Write(null, "registry-backup", "restore", row.Record.KeyPath, 0, true, row.FileName);
            MessageBox.Show("已还原。若该键涉及启动项，请到“开机加速”页刷新查看。", "还原注册表备份", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            _s.Log.Write(null, "registry-backup", "restore", row.Record.KeyPath, 0, false, ex.Message);
            MessageBox.Show($"还原失败：{ex.Message}", "还原注册表备份", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        Refresh();
    }

    [RelayCommand]
    private void RestoreTaskBackup(TaskBackupRow? row)
    {
        if (row is null) return;
        var r = MessageBox.Show(
            $"用 {row.TimeText} 的备份重新注册计划任务？\n\n{row.TaskPath}\n\n任务已存在时不覆盖；以密码登录方式运行的任务无法自动恢复。",
            "恢复计划任务", MessageBoxButton.OKCancel, MessageBoxImage.Question);
        if (r != MessageBoxResult.OK) return;

        try
        {
            var path = _s.RegistryOps.RestoreScheduledTask(row.FileName);
            _s.Log.Write(null, "registry-backup", "restore-task", path, 0, true, row.FileName);
            MessageBox.Show($"已恢复 {path}。", "恢复计划任务", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            _s.Log.Write(null, "registry-backup", "restore-task", row.TaskPath, 0, false, ex.Message);
            MessageBox.Show($"恢复失败：{ex.Message}", "恢复计划任务", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        Refresh();
    }

    [RelayCommand]
    private void OpenBackupDir()
    {
        try { Process.Start(new ProcessStartInfo("explorer.exe", $"\"{_s.RegistryBackup.BackupDir}\"") { UseShellExecute = true }); } catch { }
    }

    [RelayCommand]
    private void ExportLog()
    {
        var dlg = new SaveFileDialog
        {
            Title = "导出操作日志",
            Filter = "CSV 文件|*.csv",
            FileName = $"FatalCleaner-操作日志-{DateTime.Now:yyyyMMdd-HHmm}.csv",
        };
        if (dlg.ShowDialog() != true) return;

        try
        {
            var ops = _s.Log.GetOperations(null, 100_000);
            var sb = new StringBuilder();
            sb.AppendLine("时间,批次,模块,动作,目标,字节数,结果,说明");
            foreach (var o in ops.OrderBy(o => o.Id))
            {
                sb.Append(Csv(Format.LocalTime(o.TsUtc))).Append(',')
                  .Append(Csv(o.BatchId)).Append(',')
                  .Append(Csv(o.ModuleId)).Append(',')
                  .Append(Csv(o.Action)).Append(',')
                  .Append(Csv(o.Target)).Append(',')
                  .Append(o.SizeBytes).Append(',')
                  .Append(o.Success ? "成功" : "失败").Append(',')
                  .Append(Csv(o.Message)).AppendLine();
            }
            // UTF-8 BOM，便于 Excel 正确识别中文
            File.WriteAllText(dlg.FileName, sb.ToString(), new UTF8Encoding(true));
            MessageBox.Show($"已导出 {ops.Count:N0} 条记录。", "导出操作日志", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"导出失败：{ex.Message}", "导出操作日志", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static string Csv(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var needQuote = s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0;
        return needQuote ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }

    [RelayCommand]
    private void OpenDataDir()
    {
        try { Process.Start(new ProcessStartInfo("explorer.exe", $"\"{AppPaths.DataDir}\"") { UseShellExecute = true }); } catch { }
    }

    [RelayCommand]
    private void OpenRulesDir()
    {
        var dir = AppPaths.UpdateDir(Core.Integrity.DataKind.Rules);
        if (!Directory.Exists(dir))
        {
            MessageBox.Show("当前使用程序内置规则，可在此页检查规则更新。", "FatalCleaner", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try { Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = true }); } catch { }
    }

    private static string CategoryName(string c) => c switch
    {
        "system" => "系统",
        "browser" => "浏览器",
        "app" => "应用",
        "dev" => "开发工具",
        _ => c,
    };
}
