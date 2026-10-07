using System.Runtime.InteropServices;
using System.ServiceProcess;
using CleanSweep.Core.Backup;
using CleanSweep.Core.Model;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Optimize;

/// <summary>一条服务优化建议：做什么、有什么风险、怎么恢复。</summary>
public sealed record ServiceTweak(string ServiceName, string Title, string Description, RiskLevel Risk, string RestoreHint, string? Condition = null);

public sealed record ServiceTweakState(ServiceTweak Tweak, bool Installed, ServiceStartMode? StartMode, ServiceControllerStatus? Status, string? DisplayName, ServiceStartMode? RecordedOriginal = null)
{
    /// <summary>当前是自动启动（优化 = 改为手动）。</summary>
    public bool IsAutomatic => StartMode == ServiceStartMode.Automatic;

    /// <summary>本程序改过它，且记录了原来的启动类型：只有这种情况才提供"恢复"。</summary>
    public bool CanRestore => Installed && RecordedOriginal is not null;
}

/// <summary>
/// 服务优化项（设计文档 4.4）：每项附风险说明与恢复方式，不提供"一键全关"。"优化" = 改为手动启动（与开机加速一致，绝不设为"已禁用"），
/// 改动前导出服务键备份并尝试创建系统还原点。
/// "恢复"只把本程序改过的服务改回记录的原始启动类型：目录里不少服务在 Windows 上默认就是手动或已禁用（RemoteRegistry、Fax、wisvc…），
/// 不能因为它们"现在不是自动"就设成自动启动。
/// </summary>
public sealed class ServiceTweaks
{
    public const string ModuleId = "optimize";
    private const string ServicesKey = @"HKLM\SYSTEM\CurrentControlSet\Services";

    private sealed record TweakRecord(int OriginalStartMode, DateTime TsUtc);

    private readonly string? _recordsPath;
    private readonly object _recordsLock = new();

    public static readonly IReadOnlyList<ServiceTweak> Catalog = new[]
    {
        new ServiceTweak("SysMain", "SysMain（Superfetch / 预读取）", "把常用程序预先读进内存。机械盘上有用；固态盘上收益很小，且会持续产生磁盘读写。", RiskLevel.Confirm,
            "改回自动启动即可恢复，下次开机重新学习使用习惯。", "仅当系统盘为固态盘时建议"),
        new ServiceTweak("WSearch", "Windows Search（搜索索引）", "为开始菜单与资源管理器搜索建立索引。关闭后文件搜索退化为实时遍历，Outlook 桌面版搜索会受影响。", RiskLevel.Confirm,
            "改回自动启动，索引会重新建立（可能持续数小时）。"),
        new ServiceTweak("DiagTrack", "已连接用户体验和遥测", "向微软发送诊断与使用数据。关闭不影响功能，但 Windows 预览体验成员计划需要它。", RiskLevel.Safe,
            "改回自动启动即可。"),
        new ServiceTweak("dmwappushservice", "WAP 推送消息路由", "与遥测配套的设备管理推送。普通个人电脑不需要。", RiskLevel.Safe, "改回自动启动即可。"),
        new ServiceTweak("RemoteRegistry", "远程注册表", "允许远程用户修改本机注册表。个人电脑几乎不需要，关闭还能减少攻击面。", RiskLevel.Safe, "改回手动 / 自动即可。"),
        new ServiceTweak("Fax", "传真", "没有传真调制解调器就用不到。", RiskLevel.Safe, "改回手动即可。"),
        new ServiceTweak("WMPNetworkSvc", "Windows Media Player 网络共享", "把媒体库共享给局域网设备（DLNA）。不用媒体共享可以关闭。", RiskLevel.Safe, "改回自动启动即可。"),
        new ServiceTweak("RetailDemo", "零售演示服务", "商店样机演示模式。个人电脑不需要。", RiskLevel.Safe, "改回手动即可。"),
        new ServiceTweak("MapsBroker", "下载的地图管理器", "为地图应用管理离线地图。不用离线地图可以关闭。", RiskLevel.Safe, "改回自动启动即可。"),
        new ServiceTweak("lfsvc", "地理位置服务", "为应用提供位置信息。笔记本的“查找我的设备”与天气等应用依赖它。", RiskLevel.Confirm, "改回手动即可。"),
        new ServiceTweak("XblAuthManager", "Xbox Live 身份验证管理器", "不玩 Xbox 游戏、不用 Game Pass 可以关闭；Microsoft Store 里的游戏登录会失效。", RiskLevel.Confirm, "改回手动即可。"),
        new ServiceTweak("XblGameSave", "Xbox Live 游戏保存", "同步 Xbox 游戏存档到云端。不玩 Xbox 生态游戏可以关闭。", RiskLevel.Confirm, "改回手动即可。"),
        new ServiceTweak("XboxNetApiSvc", "Xbox Live 网络服务", "Xbox 联机功能。", RiskLevel.Confirm, "改回手动即可。"),
        new ServiceTweak("XboxGipSvc", "Xbox 配件管理服务", "管理 Xbox 手柄等配件。用 Xbox 手柄就别关。", RiskLevel.Confirm, "改回手动即可。"),
        new ServiceTweak("PhoneSvc", "电话服务", "为“手机连接”等应用管理通话状态。不用手机连接可以关闭。", RiskLevel.Safe, "改回手动即可。"),
        new ServiceTweak("WerSvc", "Windows 错误报告", "程序崩溃时收集并发送报告。关闭后崩溃时不再弹出报告对话框，也不再保留转储。", RiskLevel.Confirm, "改回手动即可。"),
        new ServiceTweak("PcaSvc", "程序兼容性助手", "监视旧程序的兼容性问题并提示。关闭后不再弹出兼容性提示。", RiskLevel.Confirm, "改回自动启动即可。"),
        new ServiceTweak("wisvc", "Windows 预览体验成员服务", "只有加入 Insider 计划才需要。", RiskLevel.Safe, "改回手动即可。"),
        new ServiceTweak("SharedAccess", "Internet 连接共享 (ICS)", "把本机网络共享给其他设备（移动热点也依赖它）。", RiskLevel.Confirm, "改回手动即可；用移动热点前需要它在运行。"),
        new ServiceTweak("SSDPSRV", "SSDP 发现", "发现局域网 UPnP 设备（智能电视、打印机）。", RiskLevel.Confirm, "改回手动即可。"),
        new ServiceTweak("upnphost", "UPnP 设备主机", "把本机作为 UPnP 设备对外提供。", RiskLevel.Confirm, "改回手动即可。"),
        new ServiceTweak("TrkWks", "分布式链接跟踪客户端", "跟踪 NTFS 卷内被移动文件的快捷方式。关闭后跨卷移动文件的快捷方式不再自动修复。", RiskLevel.Confirm, "改回自动启动即可。"),
        new ServiceTweak("Spooler", "Print Spooler（打印后台处理）", "没有打印机（含 PDF 虚拟打印机）时可以关闭，还能规避历史上多次打印服务漏洞。", RiskLevel.Confirm, "改回自动启动即可；打印或“打印到 PDF”都需要它。", "没有打印机时才建议"),
        new ServiceTweak("WbioSrvc", "Windows 生物识别", "指纹 / 面部识别登录。用 Windows Hello 就别关。", RiskLevel.High, "改回手动 / 自动即可。", "不用 Windows Hello 时才建议"),
    };

    private readonly RegistryBackup _backup;
    private readonly RestorePointService _restore;
    private readonly OperationLog _log;

    /// <param name="recordsPath">记录"本程序改过哪些服务、原来是什么启动类型"的 JSON 文件；为 null 时不记录，也就永远不提供恢复。</param>
    public ServiceTweaks(RegistryBackup backup, RestorePointService restore, OperationLog log, string? recordsPath = null)
    {
        _backup = backup;
        _restore = restore;
        _log = log;
        _recordsPath = recordsPath;
    }

    public bool CreateRestorePoint { get; set; } = true;

    /// <summary>本程序改过的服务及其原始启动类型。</summary>
    public IReadOnlyDictionary<string, ServiceStartMode> Records
    {
        get
        {
            var result = new Dictionary<string, ServiceStartMode>(StringComparer.OrdinalIgnoreCase);
            foreach (var (name, r) in LoadRecords()) result[name] = (ServiceStartMode)r.OriginalStartMode;
            return result;
        }
    }

    public static IReadOnlyList<ServiceTweakState> Query() => Query(null);

    public IReadOnlyList<ServiceTweakState> QueryStates() => Query(Records);

    public static IReadOnlyList<ServiceTweakState> Query(IReadOnlyDictionary<string, ServiceStartMode>? records)
    {
        var list = new List<ServiceTweakState>();
        foreach (var t in Catalog)
        {
            ServiceStartMode? recorded = records is not null && records.TryGetValue(t.ServiceName, out var m) ? m : null;
            try
            {
                using var sc = new ServiceController(t.ServiceName);
                var mode = sc.StartType;
                var status = sc.Status;
                list.Add(new ServiceTweakState(t, true, mode, status, sc.DisplayName, recorded));
            }
            catch
            {
                list.Add(new ServiceTweakState(t, false, null, null, null, recorded));
            }
        }
        return list;
    }

    /// <summary>
    /// manual=true 改为手动启动（优化）：只对当前为自动启动的服务，并记录原始类型；
    /// false 恢复：只对本程序改过并有记录的服务，改回记录的类型后删除记录。返回 (成功, 消息)。
    /// </summary>
    public (bool Success, string Message) SetManual(string serviceName, bool manual)
    {
        if (!Catalog.Any(c => c.ServiceName.Equals(serviceName, StringComparison.OrdinalIgnoreCase)))
            return (false, "只允许修改优化目录中列出的服务");
        try
        {
            ServiceStartMode current;
            using (var sc = new ServiceController(serviceName)) current = sc.StartType;

            uint target;
            ServiceStartMode? recordOriginal = null;
            if (manual)
            {
                if (current != ServiceStartMode.Automatic)
                    return (false, $"服务 {serviceName} 当前不是自动启动（{Describe(current)}），无需优化，也不改动它");
                target = ServiceDemandStart;
                recordOriginal = current;
            }
            else
            {
                var records = LoadRecords();
                if (!records.TryGetValue(serviceName, out var rec))
                    return (false, $"本程序没有修改过服务 {serviceName} 的记录，不改动它当前的启动类型（{Describe(current)}）。如确需更改，请使用系统的“服务”管理器");
                var original = (ServiceStartMode)rec.OriginalStartMode;
                if (original != ServiceStartMode.Automatic)
                    return (false, $"记录的原始启动类型异常（{Describe(original)}），拒绝恢复");
                target = ServiceAutoStart;
            }

            RestorePointOutcome? rp = null;
            if (CreateRestorePoint) rp = _restore.EnsureRecent("FatalCleaner：服务优化");
            _backup.Backup(RegistryPath.Combine(ServicesKey, serviceName), $"{(manual ? "优化" : "恢复")}服务 {serviceName}");
            if (recordOriginal is { } orig) SaveRecord(serviceName, new TweakRecord((int)orig, DateTime.UtcNow));
            SetStartType(serviceName, target);
            if (!manual) RemoveRecord(serviceName);
            var msg = manual ? $"服务 {serviceName} 已改为手动启动，正在运行的实例不受影响。" : $"服务 {serviceName} 已改回自动启动。";
            if (rp is not null) msg += " " + rp.Message;
            _log.Write(null, ModuleId, manual ? "service-manual" : "service-auto", serviceName, 0, true, msg);
            return (true, msg);
        }
        catch (Exception ex)
        {
            _log.Write(null, ModuleId, manual ? "service-manual" : "service-auto", serviceName, 0, false, ex.Message);
            return (false, ex.Message);
        }
    }

    private static string Describe(ServiceStartMode m) => m switch
    {
        ServiceStartMode.Automatic => "自动启动",
        ServiceStartMode.Manual => "手动启动",
        ServiceStartMode.Disabled => "已禁用",
        _ => m.ToString(),
    };

    private Dictionary<string, TweakRecord> LoadRecords()
    {
        var result = new Dictionary<string, TweakRecord>(StringComparer.OrdinalIgnoreCase);
        if (_recordsPath is null || !File.Exists(_recordsPath)) return result;
        lock (_recordsLock)
        {
            try
            {
                var loaded = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, TweakRecord>>(File.ReadAllText(_recordsPath));
                if (loaded is not null)
                    foreach (var (k, v) in loaded)
                        if (!string.IsNullOrWhiteSpace(k) && v is not null) result[k] = v;
            }
            catch { }
        }
        return result;
    }

    private void SaveRecord(string serviceName, TweakRecord record)
    {
        if (_recordsPath is null) return;
        var records = LoadRecords();
        records[serviceName] = record;
        WriteRecords(records);
    }

    private void RemoveRecord(string serviceName)
    {
        if (_recordsPath is null) return;
        var records = LoadRecords();
        if (records.Remove(serviceName)) WriteRecords(records);
    }

    private void WriteRecords(Dictionary<string, TweakRecord> records)
    {
        lock (_recordsLock)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_recordsPath!)!);
            var temp = _recordsPath + ".tmp";
            File.WriteAllText(temp, System.Text.Json.JsonSerializer.Serialize(records, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
            File.Move(temp, _recordsPath!, overwrite: true);
        }
    }

    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceChangeConfig = 0x0002;
    private const uint ServiceNoChange = 0xFFFFFFFF;
    private const uint ServiceAutoStart = 0x00000002;
    private const uint ServiceDemandStart = 0x00000003;

    private static void SetStartType(string serviceName, uint startType)
    {
        var scm = OpenSCManagerW(null, null, ScManagerConnect);
        if (scm == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "无法连接服务控制管理器");
        try
        {
            var svc = OpenServiceW(scm, serviceName, ServiceChangeConfig);
            if (svc == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), $"无法打开服务 {serviceName}");
            try
            {
                if (!ChangeServiceConfigW(svc, ServiceNoChange, startType, ServiceNoChange, null, null, IntPtr.Zero, null, null, null, null))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), $"修改服务 {serviceName} 启动类型失败");
            }
            finally { CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenServiceW(IntPtr scManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ChangeServiceConfigW(IntPtr service, uint serviceType, uint startType, uint errorControl, string? binaryPathName,
        string? loadOrderGroup, IntPtr tagId, string? dependencies, string? serviceStartName, string? password, string? displayName);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
