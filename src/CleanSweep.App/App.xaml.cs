using System.Windows;
using System.Windows.Threading;
using CleanSweep.App.Services;
using CleanSweep.App.ViewModels;

namespace CleanSweep.App;

public partial class App : Application
{
    public static AppServices Services { get; private set; } = null!;

    private Mutex? _singleInstance;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        DispatcherUnhandledException += OnDispatcherUnhandledException;
        TaskScheduler.UnobservedTaskException += (_, args) => args.SetObserved();

        if (e.Args.Length == 1 && e.Args[0] == "--verify-portable")
        {
            Shutdown(PortableDiagnostics.Run());
            return;
        }

        // 自更新阶段二：本进程是安装目录里的旧版本（可信位置），复验下载的压缩包并解压到安装目录的暂存区，再把替换交给那里的新程序
        if (e.Args.Length >= 3 && e.Args[0] == "--apply-update")
        {
            var error = int.TryParse(e.Args[2], out var guiPid)
                ? CleanSweep.Core.Integrity.AppUpdater.StageFromInstalledExe(e.Args[1], guiPid, CurrentVersion)
                : "参数无效";
            if (error is not null) MessageBox.Show("更新未完成，现有安装未改动：" + error, "FatalCleaner 更新", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(error is null ? 0 : 1);
            return;
        }

        // 自更新阶段三：本进程是暂存区里的新版本，等旧进程退出后替换安装目录（失败全部还原），然后启动安装目录里的新版本
        if (e.Args.Length >= 4 && e.Args[0] == "--apply-update-run")
        {
            var error = int.TryParse(e.Args[2], out var guiPid) && int.TryParse(e.Args[3], out var stagerPid)
                ? CleanSweep.Core.Integrity.AppUpdater.ApplyFromStagedExe(e.Args[1], guiPid, stagerPid,
                    executableName: e.Args.Length >= 5 ? e.Args[4] : CleanSweep.Core.Integrity.AppUpdater.ExeName)
                : "参数无效";
            if (error is not null) MessageBox.Show("更新未完成：" + error, "FatalCleaner 更新", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(error is null ? 0 : 1);
            return;
        }

        // 单实例：两个实例同时清理会争抢 SQLite 与隔离区。数据目录是全机共享的（ProgramData），互斥体也必须是全机范围。
        // "以管理员身份重新启动"时旧实例正在退出，新实例等它释放互斥体（最多 5 秒）；旧实例异常退出留下的废弃互斥体同样视为拿到。
        _singleInstance = new Mutex(initiallyOwned: false, @"Global\CleanSweep.SingleInstance");
        bool acquired;
        try { acquired = _singleInstance.WaitOne(TimeSpan.FromSeconds(e.Args.Contains("--relaunched") ? 5 : 0)); }
        catch (AbandonedMutexException) { acquired = true; }
        if (!acquired)
        {
            MessageBox.Show("FatalCleaner 已在运行。", "FatalCleaner", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown(0);
            return;
        }

        try
        {
            // 首次以管理员身份运行：把普通权限时期的数据目录搬到 ProgramData（必须在打开数据库之前）
            CleanSweep.Core.Storage.AppPaths.MigrateUserDataIfNeeded();
            Services = AppServices.Create();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"初始化失败：\n{ex}", "FatalCleaner", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        var window = new MainWindow { DataContext = new ShellViewModel(Services) };
        MainWindow = window;
        window.Show();

        // 启动后的维护任务：识别半完成批次、淘汰过期隔离项。在后台线程执行，大隔离区不会卡住界面
        _ = Task.Run(RunStartupMaintenance);
        _ = ((ShellViewModel)window.DataContext).CheckUpdatesInBackgroundAsync();
    }

    private static Version CurrentVersion =>
        typeof(App).Assembly.GetName().Version is { } v ? new Version(v.Major, v.Minor, Math.Max(v.Build, 0)) : new Version(0, 0, 0);

    private void RunStartupMaintenance()
    {
        // 上次自更新留下的暂存区 / 备份目录：旧进程可能还在退出，多试几次
        try
        {
            var installDir = AppContext.BaseDirectory;
            for (var attempt = 0; attempt < 20; attempt++)
            {
                if (CleanSweep.Core.Integrity.AppUpdater.CleanupLeftovers(installDir)) break;
                Thread.Sleep(500);
            }
        }
        catch { }

        try
        {
            var unfinished = Services.Log.GetUnfinishedBatches();
            if (unfinished.Count > 0)
            {
                Dispatcher.Invoke(() => MessageBox.Show(
                    $"检测到 {unfinished.Count} 个上次未正常结束的清理批次。已移入隔离区的文件仍可在“隔离区”页面恢复。",
                    "FatalCleaner", MessageBoxButton.OK, MessageBoxImage.Information));
                foreach (var b in unfinished) Services.Log.EndBatch(b.BatchId, b.FreedBytes);
            }

            // 先核对隔离区文件系统与索引（索引未提交 / 进程崩溃留下的孤儿重新登记），再淘汰过期项
            var recovered = Services.Quarantine.Reconcile();
            if (recovered > 0) Services.Log.Write(null, "quarantine", "reconcile", null, 0, true, $"重建 {recovered} 条隔离索引");

            var purged = Services.Quarantine.PurgeExpired();
            purged += Services.Quarantine.EnforceSizeLimit();
            if (purged > 0) Services.Log.Write(null, "quarantine", "auto-purge", null, 0, true, $"淘汰 {purged} 项");

            var oldBackups = Services.RegistryBackup.PurgeOlderThan(Services.Settings.RegistryBackupRetentionDays);
            if (oldBackups > 0) Services.Log.Write(null, "registry-backup", "auto-purge", null, 0, true, $"删除 {oldBackups} 个过期备份");
        }
        catch (Exception ex)
        {
            Services.Log.Write(null, "app", "startup-maintenance", null, 0, false, ex.Message);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try { _singleInstance?.ReleaseMutex(); } catch { }
        _singleInstance?.Dispose();
        base.OnExit(e);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show($"发生未处理的错误：\n{e.Exception.Message}", "FatalCleaner", MessageBoxButton.OK, MessageBoxImage.Error);
        try { Services?.Log.Write(null, "app", "unhandled", null, 0, false, e.Exception.ToString()); } catch { }
        e.Handled = true;
    }
}
