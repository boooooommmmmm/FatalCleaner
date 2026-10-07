using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using CleanSweep.Core.Backup;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Storage;
using Microsoft.Win32;

namespace CleanSweep.Core.Memory;

public sealed record MemoryStatus(long TotalBytes, long AvailableBytes, long StandbyBytes, long CachedBytes, long CommitTotalBytes, long CommitLimitBytes)
{
    public long InUseBytes => TotalBytes - AvailableBytes;
    public double UsedFraction => TotalBytes <= 0 ? 0 : (double)InUseBytes / TotalBytes;
}

public sealed record ProcessInfoRow(int Pid, string Name, string? Path, long WorkingSetBytes, long PrivateBytes, double CpuPercent, bool IsProtected, string? ProtectReason, string? Publisher);

public sealed record BackgroundApp(string PackageFamilyName, string DisplayName, bool IsMicrosoft, bool Disabled, bool DisabledByUser);

/// <summary>
/// 内存与进程管理（设计文档 4.3）。不做工作集清理（EmptyWorkingSet 会引发后续页错误，反而拖慢）；
/// 待机列表清理作为可选工具提供，不宣传为"加速"。系统关键进程与受保护进程不可结束。
/// </summary>
public sealed class MemoryManager
{
    public const string ModuleId = "memory";

    private const string BackgroundAccessKey = @"HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications";

    private static readonly HashSet<string> NeverKill = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
        "dwm.exe", "fontdrvhost.exe", "sihost.exe", "ctfmon.exe", "audiodg.exe", "spoolsv.exe", "explorer.exe", "SearchHost.exe", "StartMenuExperienceHost.exe",
        "ShellExperienceHost.exe", "RuntimeBroker.exe", "taskhostw.exe", "conhost.exe", "MsMpEng.exe", "NisSrv.exe", "SecurityHealthService.exe", "WmiPrvSE.exe",
        "LsaIso.exe", "MemCompression", "Secure System", "wlanext.exe", "dllhost.exe", "TextInputHost.exe", "LogonUI.exe", "userinit.exe", "CleanSweep.exe",
    };

    private readonly RegistryBackup _backup;
    private readonly OperationLog _log;

    public MemoryManager(RegistryBackup backup, OperationLog log)
    {
        _backup = backup;
        _log = log;
    }

    // ---------- 内存状态 ----------

    public static MemoryStatus GetStatus() => GetStatus(includeStandby: true);

    public static MemoryStatus GetStatus(bool includeStandby)
    {
        var mem = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        long total = 0, avail = 0;
        if (GlobalMemoryStatusEx(ref mem))
        {
            total = (long)mem.ullTotalPhys;
            avail = (long)mem.ullAvailPhys;
        }
        long cached = 0, commitTotal = 0, commitLimit = 0;
        var pi = new PERFORMANCE_INFORMATION { cb = (uint)Marshal.SizeOf<PERFORMANCE_INFORMATION>() };
        if (GetPerformanceInfo(ref pi, pi.cb))
        {
            var page = (long)pi.PageSize;
            cached = (long)pi.SystemCache * page;
            commitTotal = (long)pi.CommitTotal * page;
            commitLimit = (long)pi.CommitLimit * page;
        }
        long standby = 0;
        try
        {
            if (!includeStandby) return new MemoryStatus(total, avail, standby, cached, commitTotal, commitLimit);
            using var searcher = new ManagementObjectSearcher("SELECT StandbyCacheNormalPriorityBytes, StandbyCacheReserveBytes, StandbyCacheCoreBytes FROM Win32_PerfFormattedData_PerfOS_Memory");
            foreach (ManagementObject o in searcher.Get())
            {
                standby = Convert.ToInt64(o["StandbyCacheNormalPriorityBytes"] ?? 0L) + Convert.ToInt64(o["StandbyCacheReserveBytes"] ?? 0L) + Convert.ToInt64(o["StandbyCacheCoreBytes"] ?? 0L);
                break;
            }
        }
        catch { }
        return new MemoryStatus(total, avail, standby, cached, commitTotal, commitLimit);
    }

    // ---------- 待机列表清理 ----------

    private const int SystemMemoryListInformation = 80;
    private const int MemoryPurgeStandbyList = 4;
    private const int MemoryPurgeLowPriorityStandbyList = 5;

    /// <summary>清空待机列表（需要管理员权限 SeProfileSingleProcessPrivilege）。返回 null 表示成功，否则为原因。</summary>
    public string? PurgeStandbyList(bool lowPriorityOnly = false)
    {
        var privilege = EnablePrivilege("SeProfileSingleProcessPrivilege");
        if (privilege is not null)
        {
            _log.Write(null, ModuleId, "purge-standby", null, 0, false, privilege);
            return privilege;
        }
        var command = lowPriorityOnly ? MemoryPurgeLowPriorityStandbyList : MemoryPurgeStandbyList;
        var buf = Marshal.AllocHGlobal(4);
        try
        {
            Marshal.WriteInt32(buf, command);
            var status = NtSetSystemInformation(SystemMemoryListInformation, buf, 4);
            if (status != 0)
            {
                var msg = $"NtSetSystemInformation 失败：0x{status:X8}（通常是权限不足）";
                _log.Write(null, ModuleId, "purge-standby", null, 0, false, msg);
                return msg;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
        _log.Write(null, ModuleId, "purge-standby", null, 0, true, lowPriorityOnly ? "低优先级待机列表" : "全部待机列表");
        return null;
    }

    private static string? EnablePrivilege(string name)
    {
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x0020 | 0x0008, out var token)) return "无法打开进程令牌";
        try
        {
            if (!LookupPrivilegeValue(null, name, out var luid)) return "未知特权 " + name;
            var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = new LUID { LowPart = (uint)(luid & 0xFFFFFFFF), HighPart = (int)(luid >> 32) }, Attributes = 0x2 };
            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return "AdjustTokenPrivileges 失败";
            var err = Marshal.GetLastWin32Error();
            if (err == 1300) return $"当前账户没有 {name}（需要管理员权限）";
            return null;
        }
        finally
        {
            CloseHandle(token);
        }
    }

    // ---------- 进程 ----------

    /// <summary>采样一次 CPU 占用（间隔 sampleMs）并列出进程。系统关键进程标记为受保护。</summary>
    public static async Task<IReadOnlyList<ProcessInfoRow>> ListProcessesAsync(int sampleMs = 800, CancellationToken ct = default)
    {
        var first = new Dictionary<int, TimeSpan>();
        Process[] procs;
        try { procs = Process.GetProcesses(); } catch { return Array.Empty<ProcessInfoRow>(); }
        foreach (var p in procs)
        {
            try { first[p.Id] = p.TotalProcessorTime; } catch { }
        }
        var sw = Stopwatch.StartNew();
        await Task.Delay(sampleMs, ct).ConfigureAwait(false);
        var elapsed = sw.Elapsed.TotalMilliseconds * System.Environment.ProcessorCount;

        var rows = new List<ProcessInfoRow>();
        var me = System.Environment.ProcessId;
        foreach (var p in procs)
        {
            try
            {
                string name = p.ProcessName + (p.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? "" : ".exe");
                string? path = null;
                try { path = p.MainModule?.FileName; } catch { }
                double cpu = 0;
                try
                {
                    if (first.TryGetValue(p.Id, out var t0)) cpu = Math.Max(0, (p.TotalProcessorTime - t0).TotalMilliseconds) / Math.Max(1, elapsed) * 100.0;
                }
                catch { }
                long ws = 0, priv = 0;
                try { ws = p.WorkingSet64; priv = p.PrivateMemorySize64; } catch { }

                var (isProtected, reason) = Protection(p, name, path, me);
                string? publisher = null;
                if (path is not null && !isProtected)
                {
                    try { publisher = Startup.FileSignature.Inspect(path).Publisher; } catch { }
                }
                rows.Add(new ProcessInfoRow(p.Id, name, path, ws, priv, Math.Round(cpu, 1), isProtected, reason, publisher));
            }
            catch { }
            finally { p.Dispose(); }
        }
        return rows.OrderByDescending(r => r.WorkingSetBytes).ToList();
    }

    private static (bool, string?) Protection(Process p, string name, string? path, int me)
    {
        if (p.Id is 0 or 4) return (true, "系统进程");
        if (p.Id == me) return (true, "FatalCleaner 自身");
        if (NeverKill.Contains(name) || NeverKill.Contains(p.ProcessName)) return (true, "系统关键进程");
        try
        {
            if (p.SessionId == 0) return (true, "服务会话进程");
        }
        catch { }
        try
        {
            if (IsProcessCritical(p.Handle, out var critical) && critical) return (true, "关键进程（结束会蓝屏）");
        }
        catch
        {
            return (true, "受保护进程（无法打开）");
        }
        if (path is not null && path.StartsWith(System.Environment.GetFolderPath(System.Environment.SpecialFolder.Windows) + "\\", StringComparison.OrdinalIgnoreCase))
            return (true, "Windows 系统组件");
        return (false, null);
    }

    /// <summary>结束进程。受保护进程拒绝；只结束该进程本身，不结束进程树。</summary>
    public string? Kill(ProcessInfoRow row)
    {
        if (row.IsProtected) return "受保护进程，拒绝结束：" + row.ProtectReason;
        try
        {
            using var p = Process.GetProcessById(row.Pid);
            // 进程 ID 可能已被复用：名字必须一致
            if (!p.ProcessName.Equals(Path.GetFileNameWithoutExtension(row.Name), StringComparison.OrdinalIgnoreCase)) return "进程已退出，ID 已被其他进程复用";
            var (isProtected, reason) = Protection(p, row.Name, row.Path, System.Environment.ProcessId);
            if (isProtected) return "受保护进程，拒绝结束：" + reason;
            p.Kill(entireProcessTree: false);
            p.WaitForExit(5000);
            _log.Write(null, ModuleId, "kill", $"{row.Name} ({row.Pid})", row.WorkingSetBytes, true);
            return null;
        }
        catch (Exception ex)
        {
            _log.Write(null, ModuleId, "kill", $"{row.Name} ({row.Pid})", 0, false, ex.Message);
            return ex.Message;
        }
    }

    // ---------- UWP 后台权限 ----------

    public static IReadOnlyList<BackgroundApp> ListBackgroundApps(InventorySnapshot inventory)
    {
        var result = new List<BackgroundApp>();
        Dictionary<string, (bool Disabled, bool ByUser)> states = new(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var root = RegistryPath.Open(BackgroundAccessKey, RegistryView.Registry64, writable: false);
            if (root is not null)
            {
                foreach (var sub in root.GetSubKeyNames())
                {
                    using var k = root.OpenSubKey(sub);
                    if (k is null) continue;
                    var disabled = k.GetValue("Disabled") is int d && d == 1;
                    var byUser = k.GetValue("DisabledByUser") is int u && u == 1;
                    states[sub] = (disabled, byUser);
                }
            }
        }
        catch { }

        foreach (var app in inventory.Apps.Where(a => a.Source == AppSource.Uwp && !a.IsSystemComponent && a.PackageFamilyName is not null))
        {
            states.TryGetValue(app.PackageFamilyName!, out var s);
            result.Add(new BackgroundApp(app.PackageFamilyName!, app.Name, app.IsMicrosoft, s.Disabled, s.ByUser));
        }
        return result.OrderBy(a => a.DisplayName, StringComparer.CurrentCultureIgnoreCase).ToList();
    }

    /// <summary>允许 / 禁止应用在后台运行（写 BackgroundAccessApplications\PFN 的 Disabled 与 DisabledByUser，写前值级备份）。</summary>
    public string? SetBackgroundAllowed(string packageFamilyName, bool allowed)
    {
        if (string.IsNullOrWhiteSpace(packageFamilyName) || packageFamilyName.IndexOfAny(new[] { '\\', '/' }) >= 0) return "包家族名非法";
        var key = RegistryPath.Combine(BackgroundAccessKey, packageFamilyName);
        try
        {
            _backup.BackupValue(key, "Disabled", $"{(allowed ? "允许" : "禁止")}后台运行 {packageFamilyName}");
            _backup.BackupValue(key, "DisabledByUser", $"{(allowed ? "允许" : "禁止")}后台运行 {packageFamilyName}");
            using var k = RegistryPath.Open(key, RegistryView.Registry64, writable: true, create: true) ?? throw new InvalidOperationException("无法打开键");
            if (allowed)
            {
                k.DeleteValue("Disabled", false);
                k.DeleteValue("DisabledByUser", false);
            }
            else
            {
                k.SetValue("Disabled", 1, RegistryValueKind.DWord);
                k.SetValue("DisabledByUser", 1, RegistryValueKind.DWord);
            }
            _log.Write(null, ModuleId, allowed ? "background-allow" : "background-deny", packageFamilyName, 0, true);
            return null;
        }
        catch (Exception ex)
        {
            _log.Write(null, ModuleId, allowed ? "background-allow" : "background-deny", packageFamilyName, 0, false, ex.Message);
            return ex.Message;
        }
    }

    // ---------- P/Invoke ----------

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PERFORMANCE_INFORMATION
    {
        public uint cb;
        public UIntPtr CommitTotal;
        public UIntPtr CommitLimit;
        public UIntPtr CommitPeak;
        public UIntPtr PhysicalTotal;
        public UIntPtr PhysicalAvailable;
        public UIntPtr SystemCache;
        public UIntPtr KernelTotal;
        public UIntPtr KernelPaged;
        public UIntPtr KernelNonpaged;
        public UIntPtr PageSize;
        public uint HandleCount;
        public uint ProcessCount;
        public uint ThreadCount;
    }

    /// <summary>与原生 LUID 一致：两个 32 位字段，不是一个 64 位整数（否则 8 字节对齐会让后面的 Attributes 错位）。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    /// <summary>DWORD PrivilegeCount + 一个 LUID_AND_ATTRIBUTES（LUID 8 字节 + DWORD），总长 16、偏移 0 / 4 / 12。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool GetPerformanceInfo(ref PERFORMANCE_INFORMATION pPerformanceInformation, uint cb);

    [DllImport("ntdll.dll")]
    private static extern int NtSetSystemInformation(int systemInformationClass, IntPtr systemInformation, uint systemInformationLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? systemName, string name, out long luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAll, ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsProcessCritical(IntPtr hProcess, out bool critical);
}
