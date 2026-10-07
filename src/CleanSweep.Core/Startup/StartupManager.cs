using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Xml;
using CleanSweep.Core.Backup;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Environment;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Storage;
using Microsoft.Win32;

namespace CleanSweep.Core.Startup;

public sealed record StartupChangeResult(bool Success, string Message, RestorePointOutcome? RestorePoint = null);

/// <summary>
/// 开机加速（设计文档 4.1）：枚举与管理注册表 Run、启动文件夹、计划任务登录触发项、自动启动服务、UWP StartupTask。
/// 禁用只写 StartupApproved / 任务 Enabled / 服务启动类型，不删除原始项；任何注册表写入前先备份；
/// 服务改动前尝试创建系统还原点，失败时降级并提示。
/// </summary>
public sealed class StartupManager
{
    public const string ModuleId = "startup";
    public const string OwnTaskFolder = @"\CleanSweep";

    private const string ServicesKey = @"HKLM\SYSTEM\CurrentControlSet\Services";
    private const string UwpRoot = @"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData";
    private const string UwpPackages = @"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

    private const int TaskTriggerBoot = 8;
    private const int TaskTriggerLogon = 9;
    private const int TaskActionExec = 0;
    private const int TaskEnumHidden = 1;
    private const int TaskCreateOrUpdate = 6;
    private const int TaskLogonInteractiveToken = 3;
    private const int TaskLogonGroup = 4;

    private readonly IEnvironmentResolver _env;
    private readonly RegistryBackup _backup;
    private readonly RestorePointService _restore;
    private readonly Quarantine _quarantine;
    private readonly OperationLog _log;

    public StartupManager(IEnvironmentResolver env, RegistryBackup backup, RestorePointService restore, Quarantine quarantine, OperationLog log)
    {
        _env = env;
        _backup = backup;
        _restore = restore;
        _quarantine = quarantine;
        _log = log;
    }

    /// <summary>修改服务启动类型前是否创建系统还原点。</summary>
    public bool CreateRestorePointForServices { get; set; } = true;

    // =====================================================================
    // 扫描
    // =====================================================================

    public IReadOnlyList<StartupItem> Scan(bool includeMicrosoft, CancellationToken ct = default)
    {
        var impact = LoadImpact();
        var items = new List<StartupItem>();

        void Run(string source, Func<IEnumerable<StartupItem>> scan)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var i in scan())
                {
                    ct.ThrowIfCancellationRequested();
                    items.Add(i);
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _log.Write(null, ModuleId, "scan", source, 0, false, ex.Message);
            }
        }

        Run("registry", () => ScanRegistryRun(impact));
        Run("startup-folder", () => ScanStartupFolders(impact));
        Run("scheduled-tasks", () => ScanScheduledTasks(includeMicrosoft, impact));
        Run("services", () => ScanServices(includeMicrosoft, impact));
        Run("uwp", () => ScanUwp(impact));
        return items;
    }

    public (IReadOnlyList<BootRecord> Boots, string? Error) GetBootHistory(int max = 30)
    {
        var boots = BootHistory.Read(max, out var error);
        return (boots, error);
    }

    private Dictionary<string, ImpactStats> LoadImpact()
    {
        try
        {
            if (!_env.Variables.TryGetValue("LocalAppData", out var local)) return new(StringComparer.OrdinalIgnoreCase);
            return StartupInfoParser.Aggregate(StartupInfoParser.LoadDirectory(StartupInfoParser.DefaultDirectory(local)), File.Exists);
        }
        catch
        {
            return new(StringComparer.OrdinalIgnoreCase);
        }
    }

    // ---------- 注册表 Run / RunOnce ----------

    private sealed record RunKeySpec(string Key, RegistryView View, string? ApprovedKey, StartupScope Scope, StartupKind Kind, string Display);

    private static readonly RunKeySpec[] RunKeys =
    {
        new(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", RegistryView.Registry64, StartupApproved.HkcuRun, StartupScope.CurrentUser, StartupKind.RegistryRun, @"HKCU\...\CurrentVersion\Run"),
        new(@"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", RegistryView.Registry64, null, StartupScope.CurrentUser, StartupKind.RegistryRunOnce, @"HKCU\...\CurrentVersion\RunOnce"),
        new(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", RegistryView.Registry64, StartupApproved.HklmRun, StartupScope.AllUsers, StartupKind.RegistryRun, @"HKLM\...\CurrentVersion\Run"),
        new(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", RegistryView.Registry32, StartupApproved.HklmRun32, StartupScope.AllUsers, StartupKind.RegistryRun, @"HKLM\...\CurrentVersion\Run (32 位)"),
        new(@"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", RegistryView.Registry64, null, StartupScope.AllUsers, StartupKind.RegistryRunOnce, @"HKLM\...\CurrentVersion\RunOnce"),
    };

    private IEnumerable<StartupItem> ScanRegistryRun(Dictionary<string, ImpactStats> impact)
    {
        var results = new List<StartupItem>();
        foreach (var spec in RunKeys)
        {
            try
            {
                using var key = RegistryPath.Open(spec.Key, spec.View, writable: false);
                if (key is null) continue;

                var approved = ReadApproved(spec.ApprovedKey);
                foreach (var name in key.GetValueNames())
                {
                    if (string.IsNullOrEmpty(name)) continue;
                    if (key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string command || command.Length == 0) continue;

                    var data = approved.GetValueOrDefault(name);
                    var enabled = spec.ApprovedKey is null || StartupApproved.IsEnabled(data);
                    var note = spec.Kind == StartupKind.RegistryRunOnce
                        ? "仅运行一次后自动删除，不支持禁用"
                        : StartupApproved.DisabledAtUtc(data) is { } at ? $"已于 {at.ToLocalTime():yyyy-MM-dd} 禁用" : null;

                    results.Add(Build(spec.Kind, spec.Scope, name, command, spec.Display, enabled,
                        new StartupHandle(RegistryKey: spec.Key, View: spec.View, ValueName: name, ApprovedKey: spec.ApprovedKey),
                        impact, canToggle: spec.ApprovedKey is not null, canDelete: true, canDelay: spec.ApprovedKey is not null, note: note));
                }
            }
            catch (Exception ex)
            {
                _log.Write(null, ModuleId, "scan-skip", spec.Display, 0, false, ex.Message);
            }
        }
        return results;
    }

    private static Dictionary<string, byte[]> ReadApproved(string? approvedKey)
    {
        var dict = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        if (approvedKey is null) return dict;
        try
        {
            using var k = RegistryPath.Open(approvedKey, RegistryView.Registry64, writable: false);
            if (k is null) return dict;
            foreach (var name in k.GetValueNames())
            {
                if (k.GetValue(name) is byte[] b) dict[name] = b;
            }
        }
        catch
        {
        }
        return dict;
    }

    // ---------- 启动文件夹 ----------

    private IEnumerable<StartupItem> ScanStartupFolders(Dictionary<string, ImpactStats> impact)
    {
        var folders = new List<(string Dir, string ApprovedKey, StartupScope Scope)>();
        if (_env.Variables.TryGetValue("AppData", out var appData))
            folders.Add((Path.Combine(appData, @"Microsoft\Windows\Start Menu\Programs\Startup"), StartupApproved.HkcuStartupFolder, StartupScope.CurrentUser));
        if (_env.Variables.TryGetValue("ProgramData", out var programData))
            folders.Add((Path.Combine(programData, @"Microsoft\Windows\Start Menu\Programs\StartUp"), StartupApproved.HklmStartupFolder, StartupScope.AllUsers));

        var results = new List<StartupItem>();
        foreach (var (dir, approvedKey, scope) in folders)
        {
            if (!Directory.Exists(dir)) continue;
            var approved = ReadApproved(approvedKey);

            foreach (var file in Directory.EnumerateFiles(dir))
            {
                var fileName = Path.GetFileName(file);
                if (fileName.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;

                try
                {
                    string? command = file;
                    string? target = null;
                    if (fileName.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                    {
                        var (t, args) = ResolveShortcut(file);
                        target = t;
                        command = t is null ? null : (args is null ? Quote(t) : Quote(t) + " " + args);
                    }
                    else
                    {
                        target = file;
                    }

                    var data = approved.GetValueOrDefault(fileName);
                    var enabled = StartupApproved.IsEnabled(data);
                    var note = StartupApproved.DisabledAtUtc(data) is { } at ? $"已于 {at.ToLocalTime():yyyy-MM-dd} 禁用" : null;

                    results.Add(Build(StartupKind.StartupFolder, scope, Path.GetFileNameWithoutExtension(fileName), command, dir, enabled,
                        new StartupHandle(FilePath: file, ValueName: fileName, ApprovedKey: approvedKey),
                        impact, canToggle: true, canDelete: true, canDelay: target is not null, note: note));
                }
                catch (Exception ex)
                {
                    _log.Write(null, ModuleId, "scan-skip", file, 0, false, ex.Message);
                }
            }
        }
        return results;
    }

    internal static (string? Target, string? Args) ResolveShortcut(string lnkPath)
    {
        try
        {
            var t = Type.GetTypeFromProgID("WScript.Shell");
            if (t is null) return (null, null);
            dynamic shell = Activator.CreateInstance(t)!;
            dynamic sc = shell.CreateShortcut(lnkPath);
            string target = sc.TargetPath;
            string args = sc.Arguments;
            return (string.IsNullOrWhiteSpace(target) ? null : target, string.IsNullOrWhiteSpace(args) ? null : args);
        }
        catch
        {
            return (null, null);
        }
    }

    // ---------- 计划任务 ----------

    private static dynamic CreateTaskService()
    {
        var t = Type.GetTypeFromProgID("Schedule.Service") ?? throw new InvalidOperationException("任务计划程序服务不可用");
        dynamic svc = Activator.CreateInstance(t)!;
        svc.Connect();
        return svc;
    }

    private IEnumerable<StartupItem> ScanScheduledTasks(bool includeMicrosoft, Dictionary<string, ImpactStats> impact)
    {
        dynamic svc = CreateTaskService();
        var currentUser = WindowsIdentity.GetCurrent().Name;
        var results = new List<StartupItem>();

        var stack = new Stack<dynamic>();
        stack.Push(svc.GetFolder("\\"));
        while (stack.Count > 0)
        {
            dynamic folder = stack.Pop();
            string folderPath = folder.Path;
            if (!includeMicrosoft && folderPath.StartsWith(@"\Microsoft", StringComparison.OrdinalIgnoreCase)) continue;

            dynamic folders = folder.GetFolders(0);
            int fc = folders.Count;
            for (var i = 1; i <= fc; i++) stack.Push(folders.Item(i));

            dynamic tasks = folder.GetTasks(TaskEnumHidden);
            int tc = tasks.Count;
            for (var i = 1; i <= tc; i++)
            {
                dynamic task = tasks.Item(i);
                StartupItem? item = null;
                try
                {
                    item = BuildTask(task, currentUser, impact);
                }
                catch (Exception ex)
                {
                    string p = "?";
                    try { p = task.Path; } catch { }
                    _log.Write(null, ModuleId, "scan", "task " + p, 0, false, ex.Message);
                }
                if (item is not null) results.Add(item);
            }
        }
        return results;
    }

    private StartupItem? BuildTask(dynamic task, string currentUser, Dictionary<string, ImpactStats> impact)
    {
        string path = task.Path;
        dynamic def = task.Definition;

        string? triggerNote = null;
        string? delay = null;
        dynamic triggers = def.Triggers;
        int tn = triggers.Count;
        for (var i = 1; i <= tn; i++)
        {
            dynamic t = triggers.Item(i);
            int type = t.Type;
            if (type == TaskTriggerLogon) { triggerNote = "登录时"; delay = t.Delay; break; }
            if (type == TaskTriggerBoot && triggerNote is null) { triggerNote = "开机时"; delay = t.Delay; }
        }
        if (triggerNote is null) return null;

        string? exe = null, args = null;
        dynamic actions = def.Actions;
        int an = actions.Count;
        for (var i = 1; i <= an; i++)
        {
            dynamic a = actions.Item(i);
            int type = a.Type;
            if (type == TaskActionExec)
            {
                exe = a.Path;
                args = a.Arguments;
                break;
            }
        }

        bool enabled = task.Enabled;
        string? author = null;
        try { author = def.RegistrationInfo.Author; } catch { }
        string? userId = null;
        try { userId = def.Principal.UserId; } catch { }

        var scope = userId is not null && userId.Length > 0 && SameUser(userId, currentUser) ? StartupScope.CurrentUser : StartupScope.AllUsers;
        var isOwn = path.StartsWith(OwnTaskFolder + "\\", StringComparison.OrdinalIgnoreCase);

        exe = string.IsNullOrWhiteSpace(exe) ? null : System.Environment.ExpandEnvironmentVariables(exe);
        args = string.IsNullOrWhiteSpace(args) ? null : args;
        var command = exe is null ? null : (args is null ? Quote(exe) : Quote(exe) + " " + args);

        var note = triggerNote;
        if (!string.IsNullOrEmpty(delay)) note += $"，延迟 {FormatDelay(delay)}";
        if (exe is null) note += "，非可执行文件动作";
        if (isOwn) note += "。由 FatalCleaner 的“延迟启动”创建，删除即撤销延迟";

        var name = path.Substring(path.LastIndexOf('\\') + 1);
        return Build(StartupKind.ScheduledTask, scope, name, command, path, enabled,
            new StartupHandle(TaskPath: path), impact,
            canToggle: true, canDelete: isOwn, canDelay: false, note: note,
            publisherFallback: string.IsNullOrWhiteSpace(author) ? null : author);
    }

    private static bool SameUser(string a, string b)
    {
        static string Tail(string s) => s.Contains('\\') ? s[(s.LastIndexOf('\\') + 1)..] : s;
        return string.Equals(a, b, StringComparison.OrdinalIgnoreCase) || string.Equals(Tail(a), Tail(b), StringComparison.OrdinalIgnoreCase);
    }

    internal static string FormatDelay(string iso8601)
    {
        try
        {
            var ts = XmlConvert.ToTimeSpan(iso8601);
            if (ts.TotalSeconds < 60) return $"{(int)ts.TotalSeconds} 秒";
            if (ts.TotalMinutes < 60) return $"{ts.TotalMinutes:0.#} 分钟";
            return $"{ts.TotalHours:0.#} 小时";
        }
        catch
        {
            return iso8601;
        }
    }

    // ---------- 服务 ----------

    private IEnumerable<StartupItem> ScanServices(bool includeMicrosoft, Dictionary<string, ImpactStats> impact)
    {
        var results = new List<StartupItem>();
        foreach (var sc in ServiceController.GetServices())
        {
            using (sc)
            {
                // 单个服务读取失败（如无权限打开其注册表键）只跳过该服务，不影响其余
                try
                {
                    var item = BuildService(sc, includeMicrosoft, impact);
                    if (item is not null) results.Add(item);
                }
                catch (Exception ex)
                {
                    _log.Write(null, ModuleId, "scan-skip", "service " + sc.ServiceName, 0, false, ex.Message);
                }
            }
        }
        return results;
    }

    private StartupItem? BuildService(ServiceController sc, bool includeMicrosoft, Dictionary<string, ImpactStats> impact)
    {
        ServiceStartMode mode;
        try { mode = sc.StartType; } catch { return null; }
        if (mode is ServiceStartMode.Disabled or ServiceStartMode.Boot or ServiceStartMode.System) return null;

        using var key = RegistryPath.Open(RegistryPath.Combine(ServicesKey, sc.ServiceName), RegistryView.Registry64, writable: false);
        if (key is null) return null;

        var image = key.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        var delayed = key.GetValue("DelayedAutostart") is int d && d == 1;
        string? serviceDll = null;
        try
        {
            using var p = key.OpenSubKey("Parameters");
            serviceDll = p?.GetValue("ServiceDll") as string;
        }
        catch
        {
            // Parameters 子键无权限时按镜像本身判断签名
        }

        var (exe, _) = CommandLine.Split(image);
        var sigPath = CommandLine.IsHostProcess(exe) && !string.IsNullOrWhiteSpace(serviceDll)
            ? System.Environment.ExpandEnvironmentVariables(serviceDll)
            : exe;

        var sig = FileSignature.Inspect(sigPath);
        if (!includeMicrosoft && sig.IsMicrosoft) return null;

        var enabled = mode == ServiceStartMode.Automatic;
        string status;
        try { status = sc.Status == ServiceControllerStatus.Running ? "正在运行" : "已停止"; } catch { status = "状态未知"; }
        var note = mode switch
        {
            ServiceStartMode.Automatic when delayed => "自动（延迟启动）",
            ServiceStartMode.Automatic => "自动",
            ServiceStartMode.Manual => "手动（按需启动）",
            _ => mode.ToString(),
        } + "，" + status + "。禁用即改为手动启动，不会设为“已禁用”";

        var display = string.IsNullOrWhiteSpace(sc.DisplayName) ? sc.ServiceName : sc.DisplayName;
        return Build(StartupKind.Service, StartupScope.AllUsers, display, image, sc.ServiceName, enabled,
            new StartupHandle(ServiceName: sc.ServiceName), impact,
            canToggle: true, canDelete: false, canDelay: false, note: note, signaturePath: sigPath);
    }

    // ---------- UWP StartupTask ----------

    private IEnumerable<StartupItem> ScanUwp(Dictionary<string, ImpactStats> impact)
    {
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var repo = RegistryPath.Open(UwpPackages, RegistryView.Registry64, writable: false);
            if (repo is not null)
            {
                foreach (var full in repo.GetSubKeyNames())
                {
                    var pfn = ToFamilyName(full);
                    if (pfn is null || names.ContainsKey(pfn)) continue;
                    using var sub = repo.OpenSubKey(full);
                    if (sub?.GetValue("DisplayName") is string dn && dn.Length > 0 && !dn.StartsWith('@'))
                        names[pfn] = dn;
                }
            }
        }
        catch
        {
        }

        var results = new List<StartupItem>();
        using var root = RegistryPath.Open(UwpRoot, RegistryView.Registry64, writable: false);
        if (root is null) return results;

        foreach (var pfn in root.GetSubKeyNames())
        {
            try
            {
                using var pk = root.OpenSubKey(pfn);
                if (pk is null) continue;
                foreach (var taskId in pk.GetSubKeyNames())
                {
                    using var tk = pk.OpenSubKey(taskId);
                    if (tk?.GetValue("State") is not int state) continue;

                    var name = names.GetValueOrDefault(pfn) ?? pfn.Split('_')[0];
                    var isMs = pfn.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase)
                               || pfn.StartsWith("MicrosoftWindows.", StringComparison.OrdinalIgnoreCase)
                               || pfn.EndsWith("_8wekyb3d8bbwe", StringComparison.OrdinalIgnoreCase)
                               || pfn.EndsWith("_cw5n1h2txyewy", StringComparison.OrdinalIgnoreCase);

                    var enabled = state is 2 or 4;
                    var canToggle = state is 0 or 1 or 2;
                    var note = state switch
                    {
                        0 => "已禁用",
                        1 => "已由用户禁用",
                        2 => "已启用",
                        3 => "由组策略禁用，无法更改",
                        4 => "由组策略启用，无法更改",
                        _ => $"状态 {state}",
                    };

                    results.Add(Build(StartupKind.UwpStartupTask, StartupScope.CurrentUser, name, null, $"{pfn}\\{taskId}", enabled,
                        new StartupHandle(UwpKey: $@"{UwpRoot}\{pfn}\{taskId}"), impact,
                        canToggle: canToggle, canDelete: false, canDelay: false, note: note,
                        publisherFallback: isMs ? "Microsoft Corporation" : "Microsoft Store 应用", isMicrosoftOverride: isMs));
                }
            }
            catch (Exception ex)
            {
                _log.Write(null, ModuleId, "scan-skip", "uwp " + pfn, 0, false, ex.Message);
            }
        }
        return results;
    }

    internal static string? ToFamilyName(string packageFullName)
    {
        // Name_Version_Arch_ResourceId_PublisherId → Name_PublisherId
        var parts = packageFullName.Split('_');
        return parts.Length >= 2 ? parts[0] + "_" + parts[^1] : null;
    }

    // ---------- 组装 ----------

    private StartupItem Build(
        StartupKind kind, StartupScope scope, string name, string? command, string location, bool enabled, StartupHandle handle,
        Dictionary<string, ImpactStats> impact,
        bool canToggle, bool canDelete, bool canDelay, string? note = null,
        string? signaturePath = null, string? publisherFallback = null, bool? isMicrosoftOverride = null)
    {
        var (exe, args) = CommandLine.Split(command);
        var sig = FileSignature.Inspect(signaturePath ?? PayloadPath(exe, args));
        var publisher = sig.Publisher ?? publisherFallback;
        var isMs = isMicrosoftOverride ?? sig.IsMicrosoft;

        ImpactStats? stats = null;
        if (exe is not null) impact.TryGetValue(exe.ToLowerInvariant(), out stats);
        var rating = stats is null ? StartupImpact.NotMeasured : StartupInfoParser.Rate(stats.CpuMs, stats.DiskBytes);

        // 可执行文件已不存在：应用大概率已卸载，启动项成了僵尸项
        var exeMissing = exe is not null && kind != StartupKind.UwpStartupTask && !File.Exists(exe);
        var suggestion = Suggest(kind, isMs, sig.State, rating, name, exe);
        if (exeMissing)
        {
            note = note is null ? "可执行文件已不存在，应用可能已卸载" : note + "；可执行文件已不存在，应用可能已卸载";
            if (!isMs) suggestion = StartupSuggestion.RecommendDisable;
        }

        return new StartupItem
        {
            Id = RuleScanner.MakeId(kind.ToString(), location, name),
            Kind = kind,
            Scope = scope,
            Name = name,
            Command = command,
            ExePath = exe,
            Arguments = args,
            Location = location,
            Publisher = publisher,
            Signature = sig.State,
            IsMicrosoft = isMs,
            Enabled = enabled,
            CanToggle = canToggle,
            CanDelete = canDelete,
            CanDelay = canDelay && exe is not null,
            Impact = rating,
            CpuMs = stats?.CpuMs ?? 0,
            DiskBytes = stats?.DiskBytes ?? 0,
            Suggestion = suggestion,
            Note = note,
            Handle = handle,
        };
    }

    /// <summary>rundll32 xxx.dll,Entry 之类宿主进程：用载荷 DLL 判断签名。</summary>
    internal static string? PayloadPath(string? exe, string? args)
    {
        if (exe is null) return null;
        if (Path.GetFileName(exe).Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(args))
        {
            var dll = args.Split(',')[0].Trim().Trim('"');
            dll = System.Environment.ExpandEnvironmentVariables(dll);
            if (!Path.IsPathRooted(dll)) dll = Path.Combine(System.Environment.SystemDirectory, dll);
            return dll;
        }
        return exe;
    }

    private static readonly string[] KeepKeywords =
    {
        "antivirus", "security", "defender", "kaspersky", "huorong", "eset", "avast", "avg", "bitdefender", "mcafee", "norton",
        "malwarebytes", "360sd", "360tray", "realtek", "audio", "synaptics", "touchpad", "elan", "hotkey", "onedrive",
    };

    private static readonly string[] DisableKeywords =
    {
        "update", "updater", "upgrade", "helper", "assistant", "notifier", "autolaunch", "quickstart", "speedlaunch", "splash", "tray", "scheduler",
    };

    public static StartupSuggestion Suggest(StartupKind kind, bool isMicrosoft, SignatureState signature, StartupImpact impact, string name, string? exe)
    {
        if (isMicrosoft) return StartupSuggestion.Keep;

        var n = (name + " " + (exe is null ? "" : Path.GetFileNameWithoutExtension(exe))).ToLowerInvariant();
        if (KeepKeywords.Any(n.Contains)) return StartupSuggestion.Keep;
        if (signature is SignatureState.Unsigned or SignatureState.Invalid) return StartupSuggestion.RecommendDisable;
        if (DisableKeywords.Any(n.Contains)) return StartupSuggestion.RecommendDisable;
        if (impact == StartupImpact.High) return StartupSuggestion.RecommendDisable;
        return StartupSuggestion.CanDisable;
    }

    private static string Quote(string s) => s.Contains(' ') && !s.StartsWith('"') ? "\"" + s + "\"" : s;

    // =====================================================================
    // 修改
    // =====================================================================

    public StartupChangeResult SetEnabled(StartupItem item, bool enabled)
    {
        var verb = enabled ? "启用" : "禁用";
        var target = $"{item.Kind}:{item.Location}\\{item.Name}";
        RestorePointOutcome? rp = null;
        try
        {
            if (!item.CanToggle)
                return new StartupChangeResult(false, "此项不支持启用 / 禁用");

            string message;
            switch (item.Kind)
            {
                case StartupKind.RegistryRun:
                case StartupKind.StartupFolder:
                {
                    var approvedKey = item.Handle.ApprovedKey ?? throw new InvalidOperationException("缺少 StartupApproved 键");
                    var valueName = item.Handle.ValueName ?? throw new InvalidOperationException("缺少值名");
                    // 操作级备份：记录这个值修改前的状态。值原本不存在时备份的是"删除标记"，还原会把本次新建的值删掉
                    _backup.BackupValue(approvedKey, valueName, $"{verb}启动项 {item.Name}");
                    using var k = RegistryPath.Open(approvedKey, RegistryView.Registry64, writable: true, create: true)
                                  ?? throw new InvalidOperationException("无法打开 StartupApproved 键");
                    var existing = k.GetValue(valueName) as byte[];
                    k.SetValue(valueName, StartupApproved.Encode(enabled, existing), RegistryValueKind.Binary);
                    message = $"已{verb}“{item.Name}”。原启动项未删除，与任务管理器状态同步。";
                    break;
                }

                case StartupKind.ScheduledTask:
                {
                    dynamic svc = CreateTaskService();
                    dynamic task = svc.GetFolder("\\").GetTask(item.Handle.TaskPath);
                    task.Enabled = enabled;
                    message = $"已{verb}计划任务“{item.Name}”。";
                    break;
                }

                case StartupKind.Service:
                {
                    var svcName = item.Handle.ServiceName ?? throw new InvalidOperationException("缺少服务名");
                    if (CreateRestorePointForServices)
                        rp = _restore.EnsureRecent("FatalCleaner：修改服务启动类型");
                    _backup.Backup(RegistryPath.Combine(ServicesKey, svcName), $"{verb}服务 {svcName}");
                    SetServiceStartType(svcName, enabled ? ServiceAutoStart : ServiceDemandStart);
                    message = enabled
                        ? $"服务“{item.Name}”已改为自动启动。"
                        : $"服务“{item.Name}”已改为手动启动，正在运行的实例不受影响，下次开机不再自动启动。";
                    if (rp is not null) message += " " + rp.Message;
                    break;
                }

                case StartupKind.UwpStartupTask:
                {
                    var key = item.Handle.UwpKey ?? throw new InvalidOperationException("缺少 UWP 键");
                    _backup.BackupValue(key, "State", $"{verb}应用启动任务 {item.Name}");
                    using var k = RegistryPath.Open(key, RegistryView.Registry64, writable: true)
                                  ?? throw new InvalidOperationException("键已不存在");
                    k.SetValue("State", enabled ? 2 : 1, RegistryValueKind.DWord);
                    message = $"已{verb}“{item.Name}”的开机启动。";
                    break;
                }

                default:
                    return new StartupChangeResult(false, "此项不支持启用 / 禁用");
            }

            _log.Write(null, ModuleId, enabled ? "enable" : "disable", target, 0, true, message);
            return new StartupChangeResult(true, message, rp);
        }
        catch (Exception ex)
        {
            _log.Write(null, ModuleId, enabled ? "enable" : "disable", target, 0, false, ex.Message);
            return new StartupChangeResult(false, $"{verb}失败：{ex.Message}", rp);
        }
    }

    /// <summary>删除。注册表值先备份整键；启动文件夹里的文件移入隔离区；只允许删除 FatalCleaner 自建的计划任务。</summary>
    public StartupChangeResult Delete(StartupItem item)
    {
        var target = $"{item.Kind}:{item.Location}\\{item.Name}";
        try
        {
            if (!item.CanDelete)
                return new StartupChangeResult(false, "此项不支持删除，请使用禁用");

            string message;
            switch (item.Kind)
            {
                case StartupKind.RegistryRun:
                case StartupKind.RegistryRunOnce:
                {
                    var keyPath = item.Handle.RegistryKey ?? throw new InvalidOperationException("缺少注册表键");
                    var valueName = item.Handle.ValueName ?? throw new InvalidOperationException("缺少值名");
                    // 先备份 Run 值本身，再备份 StartupApproved 里对应的状态值：两条都还原才等于没删过
                    var rec = _backup.BackupValue(keyPath, valueName, $"删除启动项 {item.Name}", item.Handle.View);
                    using (var k = RegistryPath.Open(keyPath, item.Handle.View, writable: true) ?? throw new InvalidOperationException("键已不存在"))
                    {
                        k.DeleteValue(valueName, throwOnMissingValue: false);
                    }
                    RemoveApprovedValue(item.Handle.ApprovedKey, valueName, item.Name);
                    message = $"已删除“{item.Name}”。原值已备份，可在“设置 → 注册表备份”中还原（{Path.GetFileName(rec.File)}）。";
                    break;
                }

                case StartupKind.StartupFolder:
                {
                    var file = item.Handle.FilePath ?? throw new InvalidOperationException("缺少文件路径");
                    var fi = new FileInfo(file);
                    if (!fi.Exists) throw new FileNotFoundException("文件已不存在", file);
                    var entry = _quarantine.MoveIn(file, isDirectory: false, fi.Length, ModuleId, $"startup-{Guid.NewGuid():N}", item.Name);
                    RemoveApprovedValue(item.Handle.ApprovedKey, item.Handle.ValueName, item.Name);
                    message = $"已将“{Path.GetFileName(file)}”移入隔离区（{entry.ExpiresUtc.ToLocalTime():yyyy-MM-dd} 前可恢复）。";
                    break;
                }

                case StartupKind.ScheduledTask:
                {
                    var path = item.Handle.TaskPath ?? throw new InvalidOperationException("缺少任务路径");
                    if (!path.StartsWith(OwnTaskFolder + "\\", StringComparison.OrdinalIgnoreCase))
                        return new StartupChangeResult(false, "只允许删除 FatalCleaner 自建的任务，其他任务请使用禁用");
                    dynamic svc = CreateTaskService();
                    dynamic folder = svc.GetFolder(OwnTaskFolder);
                    folder.DeleteTask(path[(path.LastIndexOf('\\') + 1)..], 0);
                    message = $"已删除延迟启动任务“{item.Name}”。如需恢复原启动项，请在列表中重新启用它。";
                    break;
                }

                default:
                    return new StartupChangeResult(false, "此项不支持删除");
            }

            _log.Write(null, ModuleId, "delete", target, 0, true, message);
            return new StartupChangeResult(true, message);
        }
        catch (Exception ex)
        {
            _log.Write(null, ModuleId, "delete", target, 0, false, ex.Message);
            return new StartupChangeResult(false, $"删除失败：{ex.Message}");
        }
    }

    /// <summary>删除 StartupApproved 里的状态值（先做操作级备份，恢复 Run 值时可以一并恢复原来的启用 / 禁用状态）。</summary>
    private void RemoveApprovedValue(string? approvedKey, string? valueName, string itemName)
    {
        if (approvedKey is null || valueName is null) return;
        try
        {
            using var k = RegistryPath.Open(approvedKey, RegistryView.Registry64, writable: true);
            if (k is null || k.GetValue(valueName) is null) return;
            _backup.BackupValue(approvedKey, valueName, $"删除启动项 {itemName} 的启用状态");
            k.DeleteValue(valueName, throwOnMissingValue: false);
        }
        catch (Exception ex)
        {
            _log.Write(null, ModuleId, "delete", approvedKey + "\\" + valueName, 0, false, "清理 StartupApproved 状态失败：" + ex.Message);
        }
    }

    /// <summary>延迟启动：创建登录后延迟 N 秒的计划任务，再禁用原启动项（不删除）。</summary>
    public StartupChangeResult ConvertToDelayed(StartupItem item, int delaySeconds)
    {
        var target = $"{item.Kind}:{item.Location}\\{item.Name}";
        try
        {
            if (!item.CanDelay || item.ExePath is null)
                return new StartupChangeResult(false, "此项不支持延迟启动");
            if (!File.Exists(item.ExePath))
                return new StartupChangeResult(false, $"可执行文件不存在：{item.ExePath}");
            if (delaySeconds is < 5 or > 3600)
                return new StartupChangeResult(false, "延迟须在 5 秒到 1 小时之间");

            var identity = WindowsIdentity.GetCurrent();
            dynamic svc = CreateTaskService();
            dynamic root = svc.GetFolder("\\");
            dynamic folder;
            try { folder = root.GetFolder(OwnTaskFolder); }
            catch { folder = root.CreateFolder(OwnTaskFolder); }

            dynamic def = svc.NewTask(0);
            def.RegistrationInfo.Author = "FatalCleaner";
            def.RegistrationInfo.Description = $"由 FatalCleaner 创建：登录后延迟 {delaySeconds} 秒启动“{item.Name}”。原启动项（{item.Location}）已禁用但未删除，删除本任务后重新启用原项即可撤销。";

            dynamic settings = def.Settings;
            settings.DisallowStartIfOnBatteries = false;
            settings.StopIfGoingOnBatteries = false;
            settings.ExecutionTimeLimit = "PT0S";
            settings.StartWhenAvailable = true;
            settings.MultipleInstances = 3;

            dynamic trigger = def.Triggers.Create(TaskTriggerLogon);
            trigger.Delay = $"PT{delaySeconds}S";
            if (item.Scope == StartupScope.CurrentUser) trigger.UserId = identity.Name;

            dynamic action = def.Actions.Create(TaskActionExec);
            action.Path = item.ExePath;
            if (item.Arguments is not null) action.Arguments = item.Arguments;
            action.WorkingDirectory = Path.GetDirectoryName(item.ExePath);

            dynamic principal = def.Principal;
            principal.RunLevel = 0;
            int logonType;
            if (item.Scope == StartupScope.CurrentUser)
            {
                principal.UserId = identity.Name;
                principal.LogonType = TaskLogonInteractiveToken;
                logonType = TaskLogonInteractiveToken;
            }
            else
            {
                principal.GroupId = "S-1-5-32-545"; // BUILTIN\Users
                principal.LogonType = TaskLogonGroup;
                logonType = TaskLogonGroup;
            }

            // 任务名绑定启动项的稳定 ID：同名的 HKCU / HKLM 项、清洗后同名的项不会共用一个任务；
            // 已存在的同名任务只有确实属于这个启动项（描述里带同一标记）才允许覆盖，否则拒绝
            var marker = OwnershipMarker(item);
            def.RegistrationInfo.Description += " " + marker;
            var taskName = DelayedTaskName(item);
            bool existed = false;
            try
            {
                dynamic existing = folder.GetTask(taskName);
                existed = true;
                string desc = existing.Definition.RegistrationInfo.Description ?? "";
                if (!desc.Contains(marker, StringComparison.Ordinal))
                    return new StartupChangeResult(false, $"已存在同名任务 {OwnTaskFolder}\\{taskName}，且不属于此启动项，拒绝覆盖");
            }
            catch (System.IO.FileNotFoundException) { }
            catch (System.Runtime.InteropServices.COMException) { }

            folder.RegisterTaskDefinition(taskName, def, TaskCreateOrUpdate, null, null, logonType, null);

            var disable = SetEnabled(item, false);
            if (!disable.Success)
            {
                // 回滚：只删本次新建的任务，覆盖更新的旧任务保留（旧定义已被替换，但至少不会让该项的延迟启动凭空消失）
                if (!existed)
                {
                    try { folder.DeleteTask(taskName, 0); } catch { }
                }
                return new StartupChangeResult(false, $"已创建任务但禁用原启动项失败，已回滚：{disable.Message}");
            }

            var message = $"“{item.Name}”将在登录后 {delaySeconds} 秒启动（任务 {OwnTaskFolder}\\{taskName}）。原启动项已禁用，未删除。";
            _log.Write(null, ModuleId, "delay", target, 0, true, message);
            return new StartupChangeResult(true, message);
        }
        catch (Exception ex)
        {
            _log.Write(null, ModuleId, "delay", target, 0, false, ex.Message);
            return new StartupChangeResult(false, $"延迟启动设置失败：{ex.Message}");
        }
    }

    private static string SanitizeTaskName(string name)
    {
        var chars = name.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c).ToArray();
        var s = new string(chars).Trim();
        return s.Length > 40 ? s[..40] : s;
    }

    /// <summary>延迟任务名："Delayed - 名称 [启动项 ID 前 12 位]"。ID 由来源、位置、名称派生，不同启动项不会同名。</summary>
    internal static string DelayedTaskName(StartupItem item) =>
        $"Delayed - {SanitizeTaskName(item.Name)} [{item.Id[..Math.Min(12, item.Id.Length)]}]";

    internal static string OwnershipMarker(StartupItem item) => $"[CleanSweep:{item.Id}]";

    // ---------- 服务启动类型 ----------

    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceChangeConfig = 0x0002;
    private const uint ServiceNoChange = 0xFFFFFFFF;
    private const uint ServiceAutoStart = 0x00000002;
    private const uint ServiceDemandStart = 0x00000003;

    private static void SetServiceStartType(string serviceName, uint startType)
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
            finally
            {
                CloseServiceHandle(svc);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenServiceW(IntPtr scm, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ChangeServiceConfigW(
        IntPtr service, uint serviceType, uint startType, uint errorControl,
        string? binaryPathName, string? loadOrderGroup, IntPtr tagId, string? dependencies,
        string? serviceStartName, string? password, string? displayName);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
