using CleanSweep.Core.Backup;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Drivers;
using CleanSweep.Core.Environment;
using CleanSweep.Core.Popup;
using CleanSweep.Core.Repair;
using CleanSweep.Core.Integrity;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Memory;
using CleanSweep.Core.Modules;
using CleanSweep.Core.Optimize;
using CleanSweep.Core.Privacy;
using CleanSweep.Core.RegistryCleaning;
using CleanSweep.Core.Residue;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Scanning;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Startup;
using CleanSweep.Core.Storage;
using CleanSweep.Core.Uninstall;

namespace CleanSweep.App.Services;

/// <summary>组合根：把 Core 的各个服务装配起来，供视图模型使用。</summary>
public sealed class AppServices
{
    public required IEnvironmentResolver Env { get; init; }
    public required PathGuard Guard { get; init; }
    public required Whitelist Whitelist { get; init; }
    public required CleanSweepDb Db { get; init; }
    public required OperationLog Log { get; init; }
    public required Quarantine Quarantine { get; init; }
    public required CleanEngine Engine { get; init; }
    public required ScanScheduler Scheduler { get; init; }
    public required SpaceAnalyzer SpaceAnalyzer { get; init; }
    public required DuplicateFinder DuplicateFinder { get; init; }
    public required RegistryBackup RegistryBackup { get; init; }
    public required RegistryOps RegistryOps { get; init; }
    public required ElevationContext Elevation { get; init; }
    public required RestorePointService RestorePoints { get; init; }
    public required StartupManager Startup { get; init; }
    public required AppSettings Settings { get; init; }

    private AppUpdateCoordinator? _appUpdates;
    private readonly SemaphoreSlim _dataUpdateGate = new(1, 1);
    public bool IsUpdatingData => _dataUpdateGate.CurrentCount == 0;
    public Func<string?> UpdateInstallBlocker { get; set; } = () => "界面正在初始化";
    public AppUpdateCoordinator AppUpdates => _appUpdates ??= new AppUpdateCoordinator(
        CheckAppUpdateAsync, (release, progress, ct) => DownloadAppUpdateAsync(release, progress, ct),
        (release, _) =>
        {
            var text = $"新版本 {release.Version.ToString(3)} 已下载并校验完成，现在更新吗？\n\n确认后将关闭 FatalCleaner、安装更新并重新启动。请先完成当前操作；如需管理员权限，会弹出 UAC。\n\n选择“否”可稍后在设置中安装。";
            return Task.FromResult(System.Windows.MessageBox.Show(System.Windows.Application.Current.MainWindow, text,
                "新版本已准备好", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Question)
                == System.Windows.MessageBoxResult.Yes);
        },
        zip => AppUpdater.LaunchApply(AppContext.BaseDirectory.TrimEnd('\\'), zip),
        () => System.Windows.Application.Current.Shutdown(0),
        restore: RestoreAppUpdateAsync,
        installBlocker: () => _dataUpdateGate.CurrentCount == 0 ? "规则库正在更新" : UpdateInstallBlocker());

    private Task<PreparedAppUpdate?> RestoreAppUpdateAsync(CancellationToken ct)
    {
        var source = UpdateSources?.ReleaseInfoUrl;
        var version = CurrentVersion;
        return source is null ? Task.FromResult<PreparedAppUpdate?>(null)
            : Task.Run(() => new PreparedAppUpdateStore(AppPaths.AppUpdateStagingDir).Load(source, version), ct);
    }

    // M3
    public required AppInventory Inventory { get; init; }
    public required UninstallHistory UninstallHistory { get; init; }
    public required Uninstaller Uninstaller { get; init; }
    public required InstallMonitor InstallMonitor { get; init; }
    public required UninstallWatcher UninstallWatcher { get; init; }
    public required ResidueOptions ResidueOptions { get; init; }
    public AppFingerprintDb Fingerprints { get; private set; } = AppFingerprintDb.Empty();

    // M5
    public required MemoryManager Memory { get; init; }
    public required ServiceTweaks ServiceTweaks { get; init; }
    public required SystemTweaks SystemTweaks { get; init; }
    public required ContextMenuManager ContextMenus { get; init; }

    // M6
    public required DriverStore Drivers { get; init; }
    public required PopupBlocker PopupBlocker { get; init; }
    public required SystemRepair Repair { get; init; }

    public RuleLoadResult Rules { get; private set; } = new();

    public static AppServices Create()
    {
        AppPaths.EnsureCreated();

        var settings = AppSettings.Load(AppPaths.SettingsPath);
        var env = new CurrentUserEnvironmentResolver();
        var guard = new PathGuard(env);
        var whitelist = new Whitelist(AppPaths.WhitelistPath);
        var db = new CleanSweepDb(AppPaths.DbPath);
        var log = new OperationLog(db);
        var quarantine = new Quarantine(db, new QuarantineOptions { RetentionDays = settings.RetentionDays }, null, guard);
        var preActions = new ServicePreActionRunner
        {
            OnRestoreFailure = msg => log.Write(null, "engine", "restore-service", null, 0, false, msg),
        };
        var registryBackup = new RegistryBackup(db, AppPaths.RegistryBackupDir);
        if (AppPaths.MigratedFromUserDir is { } migratedFrom)
        {
            var n = registryBackup.RelocateFrom(Path.Combine(migratedFrom, "backups", "registry"));
            log.Write(null, "app", "migrate-data", migratedFrom, 0, true, $"数据目录已迁移到 {AppPaths.DataDir}，修正 {n} 条备份索引");
        }
        var registryOps = new RegistryOps(registryBackup);
        AppServices? services = null;
        var engine = new CleanEngine(guard, quarantine, log, preActions, whitelist, registryOps,
            ct => services!.CreateOrphanDirectoryScanners()[0].ScanAsync(services.CreateScanContext(), null, ct));
        var restorePoints = new RestorePointService();
        var startup = new StartupManager(env, registryBackup, restorePoints, quarantine, log)
        {
            CreateRestorePointForServices = settings.CreateRestorePoint,
        };

        var inventory = new AppInventory(env)
        {
            OnSourceError = (source, ex) => log.Write(null, "inventory", "scan", source, 0, false, ex.Message),
        };
        var history = new UninstallHistory(db);

        services = new AppServices
        {
            Env = env,
            Guard = guard,
            Whitelist = whitelist,
            Db = db,
            Log = log,
            Quarantine = quarantine,
            Engine = engine,
            Scheduler = new ScanScheduler(),
            SpaceAnalyzer = new SpaceAnalyzer(guard),
            DuplicateFinder = new DuplicateFinder(guard),
            RegistryBackup = registryBackup,
            RegistryOps = registryOps,
            Elevation = new ElevationContext(guard),
            RestorePoints = restorePoints,
            Startup = startup,
            Settings = settings,
            Inventory = inventory,
            UninstallHistory = history,
            Uninstaller = new Uninstaller(inventory, history, log),
            InstallMonitor = new InstallMonitor(inventory, env, AppPaths.MonitorDir),
            UninstallWatcher = new UninstallWatcher(inventory, history, log),
            ResidueOptions = new ResidueOptions { ScanAllUsers = settings.ResidueScanAllUsers },
            Memory = new MemoryManager(registryBackup, log),
            ServiceTweaks = new ServiceTweaks(registryBackup, restorePoints, log, AppPaths.ServiceTweakRecordsPath) { CreateRestorePoint = settings.CreateRestorePoint },
            SystemTweaks = new SystemTweaks(registryBackup, log),
            ContextMenus = new ContextMenuManager(registryBackup, log),
            Drivers = new DriverStore(registryBackup, log),
            PopupBlocker = new PopupBlocker(registryBackup, log),
            Repair = new SystemRepair(log, AppPaths.HostsBackupDir),
        };
        services.ReloadRules();
        return services;
    }

    /// <summary>按设置启动或停止弹窗拦截。</summary>
    public void ApplyPopupBlocking()
    {
        try
        {
            if (Settings.PopupBlockerEnabled && !PopupBlocker.IsRunning) PopupBlocker.Start();
            else if (!Settings.PopupBlockerEnabled && PopupBlocker.IsRunning) PopupBlocker.Stop();
        }
        catch (Exception ex)
        {
            Log.Write(null, PopupBlocker.ModuleId, "toggle", null, 0, false, ex.Message);
        }
    }

    /// <summary>三个数据集当前采用的目录与签名校验结果（设置页展示）。</summary>
    public IReadOnlyList<DataSetLocation> DataSetStatus { get; private set; } = Array.Empty<DataSetLocation>();

    /// <summary>
    /// 加载规则库、指纹库、弹窗规则：每个数据集先定位（更新目录优先，须签名校验通过且版本更高），
    /// 只加载清单列出且哈希一致的文件；校验失败的数据集一个文件都不加载。
    /// </summary>
    public void ReloadRules()
    {
        var status = new List<DataSetLocation>();
        DataSetLocation Locate(DataKind kind)
        {
            var loc = DataSets.Locate(kind, AppPaths.BundledDir(kind), AppPaths.UpdateDir(kind));
            status.Add(loc);
            if (!loc.Verdict.Ok) Log.Write(null, loc.KindName, "signature", loc.Directory, 0, false, loc.Verdict.Reason);
            return loc;
        }

        var rules = Locate(DataKind.Rules);
        Rules = new RuleLoader(Guard).LoadContents(rules.Contents);
        if (!rules.Verdict.Ok) Rules.Rejected.Add(new RuleRejection(rules.Directory, null, "签名校验失败，未加载任何规则：" + rules.Verdict.Reason));
        foreach (var r in Rules.Rejected)
            Log.Write(null, "rules", "rejected", $"{Path.GetFileName(r.SourceFile)} [{r.RuleId}]", 0, false, r.Reason);

        var fp = Locate(DataKind.Fingerprints);
        Fingerprints = AppFingerprintDb.LoadContents(fp.Contents, Guard);
        if (!fp.Verdict.Ok) Fingerprints.Rejected.Add(new RuleRejection(fp.Directory, null, "签名校验失败，未加载任何指纹：" + fp.Verdict.Reason));
        foreach (var r in Fingerprints.Rejected)
            Log.Write(null, "fingerprints", "rejected", $"{Path.GetFileName(r.SourceFile)} [{r.RuleId}]", 0, false, r.Reason);

        var popups = Locate(DataKind.Popups);
        PopupBlocker.LoadContents(popups.Contents);
        foreach (var r in PopupBlocker.Rejected)
            Log.Write(null, "popups", "rejected", $"{Path.GetFileName(r.SourceFile)} [{r.RuleId}]", 0, false, r.Reason);

        DataSetStatus = status;
    }

    /// <summary>设置里的更新来源解析结果（null 表示未设置或无效）。</summary>
    public UpdateSources? UpdateSources => Core.Integrity.UpdateSources.Resolve(Settings.UpdateSource);

    public Version CurrentVersion => typeof(AppServices).Assembly.GetName().Version is { } v ? new Version(v.Major, v.Minor, Math.Max(v.Build, 0)) : new Version(0, 0, 0);

    /// <summary>检查并安装三个数据集的在线更新，然后重新加载。返回每个数据集的结果。</summary>
    public async Task<IReadOnlyList<DataUpdateResult>> UpdateDataSetsAsync(CancellationToken ct = default)
    {
        await _dataUpdateGate.WaitAsync(ct).ConfigureAwait(false);
        try { return await UpdateDataSetsCoreAsync(ct).ConfigureAwait(false); }
        finally { _dataUpdateGate.Release(); }
    }

    private async Task<IReadOnlyList<DataUpdateResult>> UpdateDataSetsCoreAsync(CancellationToken ct)
    {
        var results = new List<DataUpdateResult>();
        var source = UpdateSources;
        if (source is null) return DataSetStatus.Select(l => new DataUpdateResult(l.Kind, false, null, "未设置更新来源")).ToList();
        var updater = new DataUpdater();
        foreach (var loc in DataSetStatus)
        {
            var current = loc.Verdict.Ok ? loc.Verdict.Version : 0;
            var r = await updater.UpdateAsync(loc.Kind, source.DataBaseUrl, current, AppPaths.UpdateDir(loc.Kind), ct).ConfigureAwait(false);
            // 主地址连不上（不是内容无效）时用镜像再试一次；镜像内容同样要过签名与哈希
            if (source.FallbackDataBaseUrl is { } mirror && UpdateSources.IsNetworkFailure(r.Message))
            {
                Log.Write(null, loc.KindName, "update", source.Display, 0, false, r.Message + "；改用备用地址");
                var m = await updater.UpdateAsync(loc.Kind, mirror, current, AppPaths.UpdateDir(loc.Kind), ct).ConfigureAwait(false);
                r = m with { Message = UpdateSources.IsNetworkFailure(m.Message) ? $"{r.Message}；备用地址：{m.Message}" : m.Message };
            }
            Log.Write(null, loc.KindName, "update", source.Display, 0, r.Updated || r.RemoteVersion is not null, r.Message);
            results.Add(r);
        }
        if (results.Any(r => r.Updated)) ReloadRules();
        return results;
    }

    /// <summary>检查程序是否有新版本（只读，不下载）。</summary>
    public async Task<AppUpdateCheck> CheckAppUpdateAsync(CancellationToken ct = default)
    {
        var source = UpdateSources;
        if (source is null) return new AppUpdateCheck(false, null, "未设置更新来源");
        var updater = new AppUpdater();
        var r = await updater.CheckAsync(source.ReleaseInfoUrl, CurrentVersion, ct).ConfigureAwait(false);
        if (source.FallbackReleaseInfoUrl is { } mirror && UpdateSources.IsNetworkFailure(r.Message))
        {
            Log.Write(null, "app", "check-update", source.Display, 0, false, r.Message + "；改用备用地址");
            var m = await updater.CheckAsync(mirror, CurrentVersion, ct).ConfigureAwait(false);
            r = UpdateSources.IsNetworkFailure(m.Message) ? m with { Message = $"{r.Message}；备用地址：{m.Message}" } : m;
        }
        Log.Write(null, "app", "check-update", source.Display, 0, r.Release is not null, r.Message);
        return r;
    }

    /// <summary>
    /// 下载新版本压缩包到数据目录（大小与哈希须与签名的发布信息一致），并把签名的发布信息存在旁边；返回压缩包路径，失败抛出异常。
    /// 解压与校验不在这里做：那是安装目录里的程序（可信位置）的事，见 AppUpdater。
    /// </summary>
    public async Task<string> DownloadAppUpdateAsync(ReleaseInfo release, IProgress<(long Done, long Total)>? progress, CancellationToken ct = default)
    {
        var source = UpdateSources?.ReleaseInfoUrl;
        var zip = await new AppUpdater().DownloadAsync(release, AppPaths.AppUpdateStagingDir, progress, ct, reuseExisting: true).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        if (source is not null) new PreparedAppUpdateStore(AppPaths.AppUpdateStagingDir).Save(source, release);
        Log.Write(null, "app", "download-update", zip, release.Size, true, release.Version.ToString(3));
        return zip;
    }

    public ScanContext CreateScanContext() => new()
    {
        Env = Env,
        Guard = Guard,
        Whitelist = Whitelist,
        Rules = Rules.Rules,
        AdvancedMode = Settings.AdvancedMode,
    };

    /// <summary>残留清理页的扫描器：规则库中 when=uninstalled 的目标 + 启发式残留扫描。</summary>
    public IScanner[] CreateResidueScanners()
    {
        IScanner rules = RuleScanner.Residue();
        // 定向扫描（从卸载页进入）：规则库扫描器的结果同样只保留该应用的条目
        if (ResidueOptions.OnlyAppName is { } only && !string.IsNullOrWhiteSpace(only))
            rules = new FilteredScanner(rules, i => NameKey.Matches(i.Group, only) || NameKey.Matches(Path.GetFileName(i.Path ?? ""), only));
        return new IScanner[]
        {
            rules,
            new ResidueScanner(Inventory, Fingerprints, UninstallHistory, ResidueOptions,
                (source, msg) => Log.Write(null, ResidueScanner.ModuleId, "scan-note", source, 0, true, msg)),
        };
    }

    public IScanner[] CreateOrphanDirectoryScanners() =>
        [new OrphanDirectoryScanner(ct => Inventory.Scan(ct), Fingerprints, UninstallHistory)];

    public IScanner[] CreateOrphanDirectoryScanners(IReadOnlyCollection<string> appNames) =>
        [new OrphanDirectoryScanner(ct => Inventory.Scan(ct), Fingerprints, UninstallHistory, appNames)];

    public IScanner[] CreateDevCacheScanners() => new IScanner[]
    {
        new DevCacheScanner(Fingerprints, Settings.DevProjectRoots.ToList()),
    };

    public IScanner[] CreateRegistryScanners() => new IScanner[]
    {
        new RegistryCleanerScanner(Inventory, UninstallHistory, null,
            (source, msg) => Log.Write(null, RegistryCleanerScanner.ModuleId, "scan-note", source, 0, false, msg)),
    };

    public IScanner[] CreatePrivacyScanners() => new IScanner[] { new PrivacyScanner() };

    /// <summary>按设置启动或停止卸载事件监听。</summary>
    public void ApplyUninstallWatching()
    {
        try
        {
            if (Settings.WatchUninstalls && !UninstallWatcher.IsRunning) UninstallWatcher.Start();
            else if (!Settings.WatchUninstalls && UninstallWatcher.IsRunning) UninstallWatcher.Stop();
        }
        catch (Exception ex)
        {
            Log.Write(null, "uninstall-watch", "toggle", null, 0, false, ex.Message);
        }
    }
}
