using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using CleanSweep.Core.Backup;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Storage;
using Microsoft.Win32;

namespace CleanSweep.Core.Popup;

public sealed class PopupRuleDto
{
    public string? Id { get; set; }
    public string? Title { get; set; }
    public string? ProcessPattern { get; set; }
    public string? ClassPattern { get; set; }
    public string? TitlePattern { get; set; }
    public string? Note { get; set; }
}

public sealed class PopupRuleFileDto
{
    public int Version { get; set; } = 1;
    public List<PopupRuleDto>? Rules { get; set; }
    public List<string>? BlockableProcesses { get; set; }
}

public sealed record PopupRule(string Id, string Title, Regex Process, Regex? WindowClass, Regex? WindowTitle, string? Note);

public sealed record PopupHit(DateTime TimeUtc, string RuleId, string ProcessName, int Pid, string WindowTitle, string WindowClass);

/// <summary>
/// 弹窗拦截（设计文档 5.3）。不注入、不钩子：定时枚举顶层可见窗口，进程名 + 窗口类名 + 标题都匹配规则才发 WM_CLOSE（不结束进程）。
/// 方式二：对规则文件里明确列出的独立弹窗进程，用 IFEO 的 Debugger 值指向 systray.exe（一个立即退出的系统程序）阻止其启动，可随时恢复。
/// 规则文件随程序分发（popups/popup-rules.json），加载时校验正则；进程名必须以 .exe 结尾且不在系统关键进程名单内。
/// </summary>
public sealed class PopupBlocker : IDisposable
{
    public const string ModuleId = "popup";
    private const string IfeoKey = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

    private static readonly HashSet<string> NeverBlock = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "svchost.exe", "csrss.exe", "winlogon.exe", "wininit.exe", "services.exe", "lsass.exe", "smss.exe", "dwm.exe", "taskhostw.exe",
        "RuntimeBroker.exe", "SearchHost.exe", "StartMenuExperienceHost.exe", "ShellExperienceHost.exe", "sihost.exe", "ctfmon.exe", "conhost.exe", "cmd.exe",
        "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", "wuauclt.exe", "MsMpEng.exe", "SecurityHealthSystray.exe", "CleanSweep.exe", "FatalCleaner.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "notepad.exe", "WeChat.exe", "Weixin.exe", "QQ.exe", "DingTalk.exe", "Code.exe", "devenv.exe",
    };

    private readonly RegistryBackup _backup;
    private readonly OperationLog _log;
    private readonly List<PopupRule> _rules = new();
    private readonly HashSet<string> _blockable = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<RuleRejection> _rejected = new();
    private readonly object _lock = new();
    private readonly List<PopupHit> _recent = new();
    private readonly Dictionary<string, int> _counts = new(StringComparer.OrdinalIgnoreCase);
    private Timer? _timer;
    private readonly Dictionary<int, (string Name, DateTime At)> _pidCache = new();

    public PopupBlocker(RegistryBackup backup, OperationLog log)
    {
        _backup = backup;
        _log = log;
    }

    public IReadOnlyList<PopupRule> Rules => _rules;
    public IReadOnlyCollection<string> BlockableProcesses => _blockable;
    public IReadOnlyList<RuleRejection> Rejected => _rejected;
    public bool IsRunning => _timer is not null;

    public IReadOnlyList<PopupHit> RecentHits { get { lock (_lock) return _recent.ToList(); } }
    public IReadOnlyDictionary<string, int> Counts { get { lock (_lock) return new Dictionary<string, int>(_counts, StringComparer.OrdinalIgnoreCase); } }

    /// <summary>检测到弹窗并已发送关闭。</summary>
    public event EventHandler<PopupHit>? Closed;

    // ---------- 规则 ----------

    public void LoadDirectory(string directory)
    {
        _rules.Clear();
        _blockable.Clear();
        _rejected.Clear();
        if (!Directory.Exists(directory))
        {
            _rejected.Add(new RuleRejection(directory, null, "弹窗规则目录不存在"));
            return;
        }
        LoadFiles(Directory.EnumerateFiles(directory, "*.json", SearchOption.AllDirectories)
            .Where(f => !Path.GetFileName(f).Equals(Integrity.SignedManifest.FileName, StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>加载签名清单校验通过的文件内容（校验时读到的字节，不重读磁盘），替换当前规则。</summary>
    public void LoadContents(IEnumerable<Integrity.VerifiedFile> files)
    {
        _rules.Clear();
        _blockable.Clear();
        _rejected.Clear();
        foreach (var f in files.OrderBy(f => f.Path, StringComparer.OrdinalIgnoreCase))
        {
            try { LoadJson(f.Content, f.Path); }
            catch (Exception ex) { _rejected.Add(new RuleRejection(f.Path, null, ex.Message)); }
        }
    }

    /// <summary>按路径加载给定的文件（测试与工具用），替换当前规则。</summary>
    public void LoadFiles(IEnumerable<string> files)
    {
        _rules.Clear();
        _blockable.Clear();
        _rejected.Clear();
        foreach (var file in files.OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
        {
            try { LoadJson(File.ReadAllText(file), file); }
            catch (Exception ex) { _rejected.Add(new RuleRejection(file, null, ex.Message)); }
        }
    }

    public void LoadJson(string json, string source)
    {
        PopupRuleFileDto? dto;
        try { dto = JsonSerializer.Deserialize<PopupRuleFileDto>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true }); }
        catch (JsonException ex)
        {
            _rejected.Add(new RuleRejection(source, null, "JSON 解析失败：" + ex.Message));
            return;
        }
        foreach (var r in dto?.Rules ?? new())
        {
            if (r is null || string.IsNullOrWhiteSpace(r.Id) || string.IsNullOrWhiteSpace(r.ProcessPattern))
            {
                _rejected.Add(new RuleRejection(source, r?.Id, "缺少 id 或 processPattern"));
                continue;
            }
            if (r.ClassPattern is null && r.TitlePattern is null)
            {
                _rejected.Add(new RuleRejection(source, r.Id, "必须至少给出 classPattern 或 titlePattern，只按进程名关窗口太宽"));
                continue;
            }
            try
            {
                var opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
                var timeout = TimeSpan.FromMilliseconds(50);
                _rules.Add(new PopupRule(r.Id.Trim(), r.Title ?? r.Id, new Regex(r.ProcessPattern, opts, timeout),
                    r.ClassPattern is null ? null : new Regex(r.ClassPattern, opts, timeout),
                    r.TitlePattern is null ? null : new Regex(r.TitlePattern, opts, timeout), r.Note));
            }
            catch (ArgumentException ex)
            {
                _rejected.Add(new RuleRejection(source, r.Id, "正则无效：" + ex.Message));
            }
        }
        foreach (var p in dto?.BlockableProcesses ?? new())
        {
            if (string.IsNullOrWhiteSpace(p) || !p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || p.IndexOfAny(new[] { '\\', '/', ':', ' ', '"' }) >= 0)
            {
                _rejected.Add(new RuleRejection(source, p, "blockableProcesses 只能是 .exe 文件名"));
                continue;
            }
            if (NeverBlock.Contains(p))
            {
                _rejected.Add(new RuleRejection(source, p, "系统或常用程序不允许列为可阻止进程"));
                continue;
            }
            _blockable.Add(p.Trim());
        }
    }

    // ---------- 运行 ----------

    public void Start(TimeSpan? interval = null)
    {
        if (_timer is not null) return;
        var period = interval ?? TimeSpan.FromSeconds(2);
        _timer = new Timer(_ => Tick(), null, TimeSpan.FromSeconds(1), period);
        _log.Write(null, ModuleId, "start", null, 0, true, $"{_rules.Count} 条规则");
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
    }

    private int _ticking;

    private void Tick()
    {
        if (Interlocked.Exchange(ref _ticking, 1) == 1) return;
        try
        {
            PrunePidCache();
            foreach (var w in EnumerateTopLevelWindows())
            {
                var hit = Match(w.Pid, w.Class, w.Title);
                if (hit is null) continue;
                PostMessage(w.Handle, WmClose, IntPtr.Zero, IntPtr.Zero);
                var record = new PopupHit(DateTime.UtcNow, hit.Id, w.ProcessName, w.Pid, w.Title, w.Class);
                lock (_lock)
                {
                    _recent.Insert(0, record);
                    if (_recent.Count > 200) _recent.RemoveAt(_recent.Count - 1);
                    _counts[hit.Id] = _counts.GetValueOrDefault(hit.Id) + 1;
                }
                _log.Write(null, ModuleId, "close", $"{w.ProcessName} ({w.Pid})", 0, true, $"{hit.Id}：{w.Title}");
                Closed?.Invoke(this, record);
            }
        }
        catch (Exception ex)
        {
            _log.Write(null, ModuleId, "tick", null, 0, false, ex.Message);
        }
        finally
        {
            Interlocked.Exchange(ref _ticking, 0);
        }
    }

    /// <summary>规则匹配（供测试）：进程名匹配且类名 / 标题中给出的模式全部匹配。</summary>
    public PopupRule? Match(string processName, string windowClass, string windowTitle)
    {
        if (NeverBlock.Contains(processName)) return null;
        foreach (var r in _rules)
        {
            try
            {
                if (!r.Process.IsMatch(processName)) continue;
                if (r.WindowClass is not null && !r.WindowClass.IsMatch(windowClass)) continue;
                if (r.WindowTitle is not null && !r.WindowTitle.IsMatch(windowTitle)) continue;
                return r;
            }
            catch (RegexMatchTimeoutException) { }
        }
        return null;
    }

    private PopupRule? Match(int pid, string cls, string title)
    {
        var name = ProcessName(pid);
        return name is null ? null : Match(name, cls, title);
    }

    /// <summary>PID 会被复用，缓存只保留 30 秒；这里把过期项清掉，长时间运行不会无限增长。</summary>
    private void PrunePidCache()
    {
        lock (_pidCache)
        {
            if (_pidCache.Count < 256) return;
            var now = DateTime.UtcNow;
            foreach (var pid in _pidCache.Where(kv => (now - kv.Value.At) >= TimeSpan.FromSeconds(30)).Select(kv => kv.Key).ToList())
                _pidCache.Remove(pid);
        }
    }

    private string? ProcessName(int pid)
    {
        lock (_pidCache)
        {
            if (_pidCache.TryGetValue(pid, out var c) && (DateTime.UtcNow - c.At) < TimeSpan.FromSeconds(30)) return c.Name;
        }
        string? name = null;
        try
        {
            using var p = Process.GetProcessById(pid);
            name = p.ProcessName + ".exe";
        }
        catch { }
        if (name is not null) lock (_pidCache) _pidCache[pid] = (name, DateTime.UtcNow);
        return name;
    }

    private sealed record WindowInfo(IntPtr Handle, int Pid, string ProcessName, string Class, string Title);

    private IEnumerable<WindowInfo> EnumerateTopLevelWindows()
    {
        var list = new List<WindowInfo>();
        EnumWindows((h, _) =>
        {
            try
            {
                if (!IsWindowVisible(h)) return true;
                var titleLen = GetWindowTextLength(h);
                var title = new StringBuilder(titleLen + 1);
                GetWindowText(h, title, title.Capacity);
                var cls = new StringBuilder(256);
                GetClassName(h, cls, cls.Capacity);
                GetWindowThreadProcessId(h, out var pid);
                if (pid == 0 || pid == System.Environment.ProcessId) return true;
                list.Add(new WindowInfo(h, (int)pid, ProcessName((int)pid) ?? "", cls.ToString(), title.ToString()));
            }
            catch { }
            return true;
        }, IntPtr.Zero);
        return list;
    }

    // ---------- IFEO 阻止 ----------

    /// <summary>本程序写入的 Debugger 值的标记。</summary>
    public const string BlockMarker = "/CleanSweep-popup-block";

    /// <summary>Debugger 值是否由本程序写入（systray.exe + 标记）。</summary>
    public static bool IsOurDebugger(string? debugger) =>
        debugger is not null && debugger.Contains("systray.exe", StringComparison.OrdinalIgnoreCase) && debugger.Contains(BlockMarker, StringComparison.OrdinalIgnoreCase);

    /// <summary>已通过 IFEO 阻止的进程名（只认本程序写的 Debugger 值）。</summary>
    public static IReadOnlyList<string> ListBlocked()
    {
        var list = new List<string>();
        try
        {
            using var root = RegistryPath.Open(IfeoKey, RegistryView.Registry64, writable: false);
            if (root is null) return list;
            foreach (var sub in root.GetSubKeyNames())
            {
                using var k = root.OpenSubKey(sub);
                if (IsOurDebugger(k?.GetValue("Debugger") as string)) list.Add(sub);
            }
        }
        catch { }
        return list;
    }

    private static bool IsValidProcessName(string? p) =>
        !string.IsNullOrWhiteSpace(p) && p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && p.IndexOfAny(new[] { '\\', '/', ':', ' ', '"' }) < 0 && p.IndexOfAny(Path.GetInvalidFileNameChars()) < 0;

    /// <summary>
    /// 用 IFEO 阻止 / 恢复某个弹窗进程。阻止只接受规则文件 blockableProcesses 里列出的名字，且不覆盖别人已有的 Debugger 值；
    /// 恢复对本程序写过的任何进程都允许（规则库后来删掉了这个名字也能恢复），且只删本程序写的值。
    /// </summary>
    public (bool Success, string Message) SetBlocked(string processName, bool blocked)
    {
        if (!IsValidProcessName(processName)) return (false, "进程名非法");
        if (NeverBlock.Contains(processName)) return (false, "系统或常用程序不允许阻止");
        var key = RegistryPath.Combine(IfeoKey, processName);
        try
        {
            string? existing;
            using (var probe = RegistryPath.Open(key, RegistryView.Registry64, writable: false)) existing = probe?.GetValue("Debugger") as string;

            if (blocked)
            {
                if (!_blockable.Contains(processName)) return (false, "只允许阻止规则库中明确列出的弹窗进程");
                if (existing is not null && !IsOurDebugger(existing)) return (false, $"{processName} 已有其他程序设置的 Debugger 值（{existing}），不覆盖");
            }
            else
            {
                if (existing is null) return (true, $"{processName} 当前没有被阻止。");
                if (!IsOurDebugger(existing)) return (false, $"{processName} 的 Debugger 值不是本程序写的（{existing}），不删除");
            }

            _backup.BackupValue(key, "Debugger", $"{(blocked ? "阻止" : "恢复")}弹窗进程 {processName}");
            using var k = RegistryPath.Open(key, RegistryView.Registry64, writable: true, create: true) ?? throw new InvalidOperationException("无法打开 IFEO 键");
            if (blocked)
            {
                // systray.exe 是一个启动后立即退出的系统程序；后面的标记让 ListBlocked 能认出是本程序写的
                var systray = Path.Combine(System.Environment.SystemDirectory, "systray.exe");
                k.SetValue("Debugger", $"\"{systray}\" {BlockMarker}", RegistryValueKind.String);
            }
            else
            {
                k.DeleteValue("Debugger", false);
            }
            _log.Write(null, ModuleId, blocked ? "block" : "unblock", processName, 0, true);
            return (true, blocked ? $"已阻止 {processName} 启动。可随时恢复。" : $"已恢复 {processName}。");
        }
        catch (Exception ex)
        {
            _log.Write(null, ModuleId, blocked ? "block" : "unblock", processName, 0, false, ex.Message);
            return (false, ex.Message);
        }
    }

    public void Dispose() => Stop();

    private const uint WmClose = 0x0010;

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

    [DllImport("user32.dll")]
    private static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder text, int count);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    [DllImport("user32.dll")]
    private static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
}
