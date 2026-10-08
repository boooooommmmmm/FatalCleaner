using System.IO.Enumeration;
using System.Runtime.InteropServices;
using System.Text;
using CleanSweep.Core.Environment;
using CleanSweep.Core.Model;
using Microsoft.Win32.SafeHandles;

namespace CleanSweep.Core.Safety;

/// <summary>路径检查结论。</summary>
public sealed record PathVerdict(bool Allowed, string? Reason, string? FullPath)
{
    public static PathVerdict Ok(string full) => new(true, null, full);
    public static PathVerdict Deny(string reason, string? full = null) => new(false, reason, full);
}

/// <summary>
/// 引擎层硬性约束的实现（设计文档 6.2）。所有文件遍历与删除都必须经过这里：
/// 1. 永不跟随重解析点（Junction / 符号链接 / 挂载点 / 云端占位文件）；
/// 2. 系统保护路径与卷根目录不得作为删除目标；
/// 3. 规则路径必须以已知环境变量开头、不含 ".."、展开后不落在保护路径内。
/// </summary>
public sealed class PathGuard
{
    /// <summary>FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS：OneDrive 等云端按需文件。</summary>
    public const FileAttributes RecallOnDataAccess = (FileAttributes)0x400000;

    private static readonly string[] WindowsAllowList =
    {
        @"Temp",
        @"SystemTemp",
        @"Logs",
        @"Prefetch",
        @"Minidump",
        @"LiveKernelReports",
        @"MEMORY.DMP",
        @"Downloaded Program Files",
        @"SoftwareDistribution\Download",
        @"SoftwareDistribution\DataStore\Logs",
        @"ServiceProfiles\LocalService\AppData\Local\Temp",
        @"ServiceProfiles\NetworkService\AppData\Local\Temp",
        @"ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache",
        @"System32\LogFiles\WMI\RtBackup",
        @"System32\config\systemprofile\AppData\Local\Temp",
        @"System32\config\systemprofile\AppData\Local\Microsoft\Windows\INetCache",
        @"System32\config\systemprofile\AppData\Local\Microsoft\Windows\WER",
        @"System32\config\systemprofile\AppData\Local\Microsoft\Windows\Explorer",
        @"Microsoft.NET\Framework\v4.0.30319\Temporary ASP.NET Files",
        @"Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files",
        @"assembly\tmp",
    };

    private static readonly string[] VolumeLevelProtected =
    {
        "System Volume Information",
        "$Recycle.Bin",
        "Recovery",
        "Boot",
        "EFI",
        "bootmgr",
        "BOOTNXT",
        "hiberfil.sys",
        "pagefile.sys",
        "swapfile.sys",
        "DumpStack.log.tmp",
    };

    /// <summary>用户已知文件夹：整目录不得作为清理目标（设计文档 3.3.1：只提示不默认勾选）。子目录仍可由 high 级规则引用。</summary>
    private static readonly string[] KnownUserFolders =
    {
        "Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos", "Favorites", "Contacts", "Saved Games", "OneDrive",
    };

    /// <summary>用户配置文件内绝不允许触碰的对象（相对于对应变量）。</summary>
    private static readonly (string Var, string Relative)[] UserProtected =
    {
        ("UserProfile", "NTUSER.DAT"),
        ("UserProfile", "ntuser.dat.LOG1"),
        ("UserProfile", "ntuser.dat.LOG2"),
        ("UserProfile", "ntuser.ini"),
        ("LocalAppData", @"Microsoft\Windows\UsrClass.dat"),
        ("LocalAppData", @"Microsoft\Windows\UsrClass.dat.LOG1"),
        ("LocalAppData", @"Microsoft\Windows\UsrClass.dat.LOG2"),
        ("LocalAppData", @"Microsoft\Credentials"),
        ("LocalAppData", @"Microsoft\Vault"),
        ("AppData", @"Microsoft\Credentials"),
        ("AppData", @"Microsoft\Crypto"),
        ("AppData", @"Microsoft\Protect"),
        ("AppData", @"Microsoft\SystemCertificates"),
        ("AppData", @"Microsoft\Windows\Start Menu"),
        ("AppData", @"Microsoft\Windows\Themes"),
    };

    private readonly IEnvironmentResolver _env;

    /// <summary>护栏所用的环境变量表（目标用户的路径）。</summary>
    public IReadOnlyDictionary<string, string> EnvVariables => _env.Variables;

    /// <summary>
    /// 该路径上的删除 / 移动是否需要管理员权限：Windows、Program Files、ProgramData 之下，以及当前用户配置文件之外的其他用户目录
    /// （Users\Public 除外）。只是静态判断，用于界面把条目标成"需要管理员"，不代替真实的访问检查。
    /// </summary>
    public bool RequiresElevation(string path)
    {
        string full;
        try { full = Normalize(path); } catch { return true; }
        if (IsSameOrUnder(full, _windir)) return true;
        foreach (var root in _protectedRoots) if (IsSameOrUnder(full, root)) return true;
        var v = _env.Variables;
        if (v.GetValueOrDefault("ProgramData") is { } pd && IsSameOrUnder(full, Normalize(pd))) return true;
        if (v.GetValueOrDefault("SystemDrive") is { } sd)
        {
            var users = Normalize(Path.Combine(sd + "\\", "Users"));
            if (IsSameOrUnder(full, users))
            {
                if (v.GetValueOrDefault("Public") is { } pub && IsSameOrUnder(full, Normalize(pub))) return false;
                if (v.GetValueOrDefault("UserProfile") is { } up && IsSameOrUnder(full, Normalize(up))) return false;
                return true;
            }
        }
        return false;
    }
    private readonly string _windir;
    private readonly string[] _protectedRoots;
    private readonly string[] _tooBroadRoots;
    private readonly string[] _userProtected;
    private readonly string[] _developerProtected;

    public PathGuard(IEnvironmentResolver env)
    {
        _env = env;
        _windir = Normalize(env.Variables["Windir"]);

        var v = env.Variables;
        _developerProtected = DeveloperCachePolicy.ProtectedRoots(v).Select(Normalize)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        _protectedRoots = new[]
            {
                v.GetValueOrDefault("ProgramFiles"),
                v.GetValueOrDefault("ProgramFilesX86"),
            }
            .Where(p => !string.IsNullOrEmpty(p))
            .Select(p => Normalize(p!))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        _tooBroadRoots = new[]
            {
                v.GetValueOrDefault("UserProfile"),
                v.GetValueOrDefault("AppData"),
                v.GetValueOrDefault("LocalAppData"),
                v.GetValueOrDefault("LocalAppDataLow"),
                v.GetValueOrDefault("ProgramData"),
                v.GetValueOrDefault("Public"),
                v.GetValueOrDefault("SystemDrive") is { } sd ? Path.Combine(sd + "\\", "Users") : null,
                v.GetValueOrDefault("LocalAppData") is { } la ? Path.Combine(la, "Microsoft") : null,
                v.GetValueOrDefault("LocalAppData") is { } la2 ? Path.Combine(la2, "Packages") : null,
                v.GetValueOrDefault("LocalAppData") is { } la3 ? Path.Combine(la3, "Microsoft", "Windows") : null,
                v.GetValueOrDefault("AppData") is { } ra ? Path.Combine(ra, "Microsoft") : null,
                v.GetValueOrDefault("AppData") is { } ra2 ? Path.Combine(ra2, "Microsoft", "Windows") : null,
                v.GetValueOrDefault("ProgramData") is { } pd ? Path.Combine(pd, "Microsoft") : null,
            }
            .Concat(KnownUserFolders.Select(k => v.GetValueOrDefault("UserProfile") is { } up ? Path.Combine(up, k) : null))
            .Where(p => !string.IsNullOrEmpty(p))
            .Select(p => Normalize(p!))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        _userProtected = UserProtected
            .Where(u => v.ContainsKey(u.Var))
            .Select(u => Normalize(Path.Combine(v[u.Var], u.Relative)))
            .ToArray();
    }

    // ---------- 路径规范化 ----------

    /// <summary>绝对化并去掉尾部分隔符（卷根保留 "C:\"）。</summary>
    public static string Normalize(string path)
    {
        var full = Path.GetFullPath(path);
        return Path.TrimEndingDirectorySeparator(full);
    }

    public static bool IsVolumeRoot(string fullPath)
    {
        var root = Path.GetPathRoot(fullPath);
        return root is not null
               && string.Equals(Path.TrimEndingDirectorySeparator(root), Path.TrimEndingDirectorySeparator(fullPath), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>child 等于 parent，或位于 parent 之下。</summary>
    public static bool IsSameOrUnder(string child, string parent)
    {
        child = Normalize(child);
        parent = Normalize(parent);
        if (string.Equals(child, parent, StringComparison.OrdinalIgnoreCase)) return true;
        var parentWithSep = parent.EndsWith('\\') ? parent : parent + "\\";
        return child.StartsWith(parentWithSep, StringComparison.OrdinalIgnoreCase);
    }

    // ---------- 保护路径检查 ----------

    /// <summary>检查一个已展开的绝对路径是否允许作为清理目标。</summary>
    public PathVerdict Check(string fullPath) => CheckCore(fullPath, forRestore: false);

    /// <summary>
    /// 隔离区恢复目标的检查。恢复的文件当初是从允许清理的位置搬走的，所以 Windows 目录（允许列表外）、Program Files、
    /// 卷级保护对象、用户 hive 与凭据目录一律不接受；但"范围过大"与"包含受保护对象"两条不适用于恢复（恢复的是单个对象），
    /// 开始菜单、主题目录允许（启动文件夹里的快捷方式就是从那里隔离的）。
    /// </summary>
    public PathVerdict CheckRestoreTarget(string fullPath) => CheckCore(fullPath, forRestore: true);

    /// <summary>Active dependency repositories are not cleanup targets, even when a stale rule says safe.</summary>
    public bool IsDeveloperDataProtected(string path)
    {
        var full = Normalize(path);
        return _developerProtected.Any(p => IsSameOrUnder(full, p) || IsSameOrUnder(p, full));
    }

    private static readonly string[] RestoreAllowedUserProtected = { "Start Menu", "Themes" };

    private static bool IsSingleShortcutFile(string full)
    {
        if (!full.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) return false;
        try
        {
            var attr = File.GetAttributes(full);
            return (attr & FileAttributes.Directory) == 0 && !IsReparsePoint(attr);
        }
        catch
        {
            return false;
        }
    }

    private PathVerdict CheckCore(string fullPath, bool forRestore, bool forRuleValidation = false)
    {
        string full;
        try
        {
            full = Normalize(fullPath);
        }
        catch (Exception ex)
        {
            return PathVerdict.Deny($"路径无效：{ex.Message}");
        }

        if (!Path.IsPathFullyQualified(full) || full.StartsWith(@"\\", StringComparison.Ordinal))
            return PathVerdict.Deny("必须是本机绝对路径", full);

        if (IsVolumeRoot(full))
            return PathVerdict.Deny("不允许以卷根目录为目标", full);

        if (!forRestore && !forRuleValidation && IsDeveloperDataProtected(full))
            return PathVerdict.Deny("开发依赖或运行环境受保护，清理可能导致构建或程序失效", full);

        // 卷级保护对象：C:\System Volume Information、C:\$Recycle.Bin、C:\Recovery ...
        var root = Path.GetPathRoot(full)!;
        var rel = full.Substring(root.Length);
        var firstSeg = rel.Split('\\', 2)[0];
        if (VolumeLevelProtected.Any(p => string.Equals(p, firstSeg, StringComparison.OrdinalIgnoreCase)))
            return PathVerdict.Deny($"系统保护对象：{firstSeg}", full);

        // 范围过大的根：不允许把 %UserProfile%、%AppData% 之类整个当作目标
        foreach (var broad in _tooBroadRoots)
        {
            if (string.Equals(full, broad, StringComparison.OrdinalIgnoreCase))
                return PathVerdict.Deny(forRestore ? "不允许把对象恢复为用户目录根本身" : "目标范围过大，不允许整目录清理", full);
        }

        // Windows 目录：只有明确列出的缓存子目录可用
        if (IsSameOrUnder(full, _windir))
        {
            var allowed = WindowsAllowList.Any(a => IsSameOrUnder(full, Path.Combine(_windir, a)));
            return allowed
                ? PathVerdict.Ok(full)
                : PathVerdict.Deny("Windows 系统目录，不在允许的缓存子目录列表内", full);
        }

        foreach (var pr in _protectedRoots)
        {
            if (IsSameOrUnder(full, pr))
                return PathVerdict.Deny("Program Files 受保护", full);
        }

        foreach (var up in _userProtected)
        {
            if (forRestore && RestoreAllowedUserProtected.Any(a => up.EndsWith("\\" + a, StringComparison.OrdinalIgnoreCase))) continue;
            // 开始菜单整体受保护，但其中单个失效的 .lnk 文件允许作为清理目标（注册表清理"失效快捷方式"）；目录仍然拒绝
            if (up.EndsWith("\\Start Menu", StringComparison.OrdinalIgnoreCase) && IsSingleShortcutFile(full)) continue;
            if (IsSameOrUnder(full, up))
                return PathVerdict.Deny($"用户配置文件关键对象受保护：{Path.GetFileName(up)}", full);
        }

        if (forRestore) return PathVerdict.Ok(full);

        // 目标不得包含受保护对象：整目录清理会连带移走其中的一切（如 %UserProfile%\AppData 包含 Credentials）
        foreach (var p in _protectedRoots.Concat(_userProtected).Concat(_tooBroadRoots).Append(_windir))
        {
            if (IsSameOrUnder(p, full) && !string.Equals(p, full, StringComparison.OrdinalIgnoreCase))
                return PathVerdict.Deny($"目标包含受保护对象：{p}", full);
        }

        return PathVerdict.Ok(full);
    }

    /// <summary>校验规则文件中的原始路径（含 %变量%）。不通过则整条规则应被拒绝加载。</summary>
    public PathVerdict ValidateRulePath(string rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath))
            return PathVerdict.Deny("路径为空");

        if (!rawPath.StartsWith('%'))
            return PathVerdict.Deny("规则路径必须以已知环境变量开头");

        if (rawPath.Split('\\', '/').Any(seg => seg == ".."))
            return PathVerdict.Deny("规则路径不得包含 ..");

        if (!_env.TryExpand(rawPath, out var expanded, out var err))
            return PathVerdict.Deny(err!);

        if (expanded.Contains('%'))
            return PathVerdict.Deny("展开后仍含未解析变量");

        // Keep old signed datasets readable; each concrete target is checked again at scan/execution time.
        return CheckCore(expanded, forRestore: false, forRuleValidation: true);
    }

    // ---------- 通配目录段 ----------

    /// <summary>规则路径是否含通配目录段（如 "User Data\Profile *\Cache"、"Packages\*\TempState"）。</summary>
    public static bool HasWildcardSegment(string rawPath) => rawPath.Contains('*');

    /// <summary>
    /// 校验含通配目录段的规则路径模板。约束：通配符只能出现在环境变量之后的整段里、最后一段不能是通配段（否则整个父目录都成了目标）、
    /// 通配段只允许字母数字空格 . - _ 与 *；把通配段换成占位名后的路径必须通过 <see cref="ValidateRulePath"/>；
    /// 第一个通配段之前的静态前缀也要通过校验，只有"范围过大"一条例外（%LocalAppData%\Packages\*\TempState 这类按子目录逐个清理的模板），
    /// 且前缀不能只是一个裸变量（%LocalAppData%\*\Cache 不允许）。展开后的每个具体路径在扫描时仍要过 <see cref="Check"/>。
    /// </summary>
    public PathVerdict ValidateRuleTemplate(string rawPath, out string? expandedTemplate)
    {
        expandedTemplate = null;
        if (string.IsNullOrWhiteSpace(rawPath)) return PathVerdict.Deny("路径为空");
        var segs = rawPath.Split('\\', '/');
        if (segs[0].Contains('*')) return PathVerdict.Deny("环境变量段不得含通配符");
        if (segs[^1].Contains('*')) return PathVerdict.Deny("最后一段不得是通配段（会把整个父目录当作目标）");
        var first = Array.FindIndex(segs, s => s.Contains('*'));
        if (first < 0) return PathVerdict.Deny("路径不含通配段");
        foreach (var seg in segs.Where(s => s.Contains('*')))
        {
            if (seg.Any(c => !(char.IsLetterOrDigit(c) || c is ' ' or '.' or '-' or '_' or '*')))
                return PathVerdict.Deny($"通配段含不允许的字符：{seg}");
        }
        if (first < 2) return PathVerdict.Deny("通配段不得紧跟环境变量（前缀至少要有一级固定目录）");

        var placeholder = string.Join('\\', segs.Select(s => s.Contains('*') ? "__cleansweep_wildcard__" : s));
        var verdict = ValidateRulePath(placeholder);
        if (!verdict.Allowed) return verdict;

        var prefix = string.Join('\\', segs.Take(first));
        var prefixVerdict = ValidateRulePath(prefix);
        if (!prefixVerdict.Allowed && !(prefixVerdict.Reason?.Contains("范围过大") ?? false))
            return PathVerdict.Deny($"通配前缀被拒绝（{prefix}）：{prefixVerdict.Reason}");

        if (!_env.TryExpand(rawPath, out var expanded, out var err)) return PathVerdict.Deny(err!);
        expandedTemplate = expanded.Replace('/', '\\').TrimEnd('\\');
        return PathVerdict.Ok(expandedTemplate);
    }

    /// <summary>
    /// 把含通配段的展开模板解析成具体路径。每个通配段只匹配所在父目录的直接子目录（不递归），跳过重解析点；
    /// 最多返回 maxMatches 个。返回 (具体路径, 匹配到的通配段值，多段用 \ 连接)，不检查最终路径是否存在。
    /// </summary>
    public static IReadOnlyList<(string Path, string Match)> ExpandWildcards(string expandedTemplate, int maxMatches = 200)
    {
        var segs = expandedTemplate.Split('\\');
        var first = Array.FindIndex(segs, s => s.Contains('*'));
        if (first < 0) return new[] { (expandedTemplate, "") };
        var candidates = new List<(string Path, string Match)> { (string.Join('\\', segs.Take(first)), "") };
        var options = new EnumerationOptions { AttributesToSkip = FileAttributes.ReparsePoint, IgnoreInaccessible = true, MatchCasing = MatchCasing.CaseInsensitive };
        for (var i = first; i < segs.Length; i++)
        {
            var seg = segs[i];
            if (!seg.Contains('*'))
            {
                candidates = candidates.Select(c => (System.IO.Path.Combine(c.Path, seg), c.Match)).ToList();
                continue;
            }
            var next = new List<(string, string)>();
            foreach (var c in candidates)
            {
                if (!Directory.Exists(c.Path)) continue;
                IEnumerable<string> dirs;
                try { dirs = Directory.EnumerateDirectories(c.Path, seg, options); }
                catch { continue; }
                foreach (var d in dirs)
                {
                    var name = System.IO.Path.GetFileName(d);
                    if (name is "." or "..") continue;
                    try { if (IsReparsePoint(new DirectoryInfo(d).Attributes)) continue; } catch { continue; }
                    next.Add((d, c.Match.Length == 0 ? name : c.Match + "\\" + name));
                    if (next.Count >= maxMatches) break;
                }
                if (next.Count >= maxMatches) break;
            }
            candidates = next;
            if (candidates.Count == 0) break;
        }
        return candidates;
    }

    // ---------- 重解析点 ----------

    public static bool IsReparsePoint(FileAttributes attributes) =>
        (attributes & FileAttributes.ReparsePoint) != 0;

    public static bool IsCloudPlaceholder(FileAttributes attributes) =>
        (attributes & RecallOnDataAccess) != 0;

    /// <summary>路径本身是否为重解析点（不存在时返回 false）。</summary>
    public static bool IsReparsePoint(string path)
    {
        try
        {
            var attr = File.GetAttributes(path);
            return IsReparsePoint(attr);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>从 root 到 path 的每一级中，是否有任何一级是重解析点。用于删除前核对。</summary>
    public static bool AnyAncestorIsReparsePoint(string path, string root)
    {
        var full = Normalize(path);
        var stop = Normalize(root);
        var current = Path.GetDirectoryName(full);
        while (current is not null && IsSameOrUnder(current, stop) && !string.Equals(current, stop, StringComparison.OrdinalIgnoreCase))
        {
            if (IsReparsePoint(current)) return true;
            current = Path.GetDirectoryName(current);
        }
        return false;
    }

    // ---------- 安全遍历 ----------

    /// <summary>解析 "a;b;c" 形式的多模式。</summary>
    public static string[] ParsePatterns(string? pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern)) return new[] { "*" };
        return pattern.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    public static bool MatchesAny(string fileName, string[] patterns)
    {
        foreach (var p in patterns)
        {
            if (FileSystemName.MatchesSimpleExpression(p, fileName, ignoreCase: true)) return true;
        }
        return false;
    }

    /// <summary>
    /// 枚举目录下匹配的文件。永不进入重解析点目录，永不返回重解析点文件或云端占位文件。
    /// 无法访问的目录静默跳过。
    /// </summary>
    public IEnumerable<FileEntry> EnumerateFiles(string directory, string? pattern, bool recurse, CancellationToken ct = default)
    {
        var patterns = ParsePatterns(pattern);
        var opts = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            AttributesToSkip = 0,
            RecurseSubdirectories = false,
            ReturnSpecialDirectories = false,
        };

        var stack = new Stack<string>();
        stack.Push(directory);

        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var current = stack.Pop();

            DirectoryInfo di;
            IEnumerator<FileSystemInfo> it;
            try
            {
                di = new DirectoryInfo(current);
                if (!di.Exists) continue;
                // 包括扫描根目录本身：根目录被替换成 Junction 是清理软件典型的本地提权入口
                if (IsReparsePoint(di.Attributes)) continue;
                it = di.EnumerateFileSystemInfos("*", opts).GetEnumerator();
            }
            catch
            {
                continue;
            }

            while (true)
            {
                FileSystemInfo e;
                try
                {
                    if (!it.MoveNext()) break;
                    e = it.Current;
                }
                catch
                {
                    break;
                }

                FileAttributes attr;
                try { attr = e.Attributes; }
                catch { continue; }

                if (IsReparsePoint(attr) || IsCloudPlaceholder(attr)) continue;

                if ((attr & FileAttributes.Directory) != 0)
                {
                    if (recurse) stack.Push(e.FullName);
                    continue;
                }

                if (!MatchesAny(e.Name, patterns)) continue;

                var fi = (FileInfo)e;
                long len;
                DateTime lw;
                try
                {
                    len = fi.Length;
                    lw = fi.LastWriteTimeUtc;
                }
                catch
                {
                    continue;
                }

                yield return new FileEntry(fi.FullName, len, lw);
            }
        }
    }

    /// <summary>枚举一级子目录，跳过重解析点。</summary>
    public IEnumerable<DirectoryInfo> EnumerateDirectories(string directory)
    {
        var opts = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = 0 };
        IEnumerable<DirectoryInfo> dirs;
        try
        {
            var di = new DirectoryInfo(directory);
            if (!di.Exists) yield break;
            dirs = di.EnumerateDirectories("*", opts);
        }
        catch
        {
            yield break;
        }

        foreach (var d in dirs)
        {
            FileAttributes attr;
            try { attr = d.Attributes; }
            catch { continue; }
            if (IsReparsePoint(attr)) continue;
            yield return d;
        }
    }

    /// <summary>计算目录总大小（不跟随重解析点）。</summary>
    public (long Size, int Files, DateTime? LastWriteUtc) MeasureDirectory(string directory, CancellationToken ct = default)
    {
        var (size, count, last, _) = FingerprintDirectory(directory, ct);
        return (size, count, last);
    }

    /// <summary>
    /// 目录内容指纹：对所有文件（相对路径、大小、修改时间）排序后取 SHA-256，同时返回总大小、文件数、最新修改时间。
    /// 整目录清理前重算并比对，可以发现"同大小改内容、修改时间早于其他文件"这类总量统计看不出的变化。
    /// </summary>
    public (long Size, int Files, DateTime? LastWriteUtc, string Fingerprint) FingerprintDirectory(string directory, CancellationToken ct = default)
    {
        var root = Normalize(directory);
        long size = 0;
        int count = 0;
        DateTime? last = null;
        var lines = new List<string>();
        foreach (var f in EnumerateFiles(root, null, recurse: true, ct))
        {
            size += f.Size;
            count++;
            if (last is null || f.LastWriteUtc > last) last = f.LastWriteUtc;
            var rel = f.Path.Length > root.Length + 1 ? f.Path[(root.Length + 1)..] : f.Path;
            lines.Add(rel.ToLowerInvariant() + "\u001f" + f.Size + "\u001f" + f.LastWriteUtc.Ticks);
        }
        lines.Sort(StringComparer.Ordinal);
        var hash = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', lines)));
        return (size, count, last, Convert.ToHexString(hash));
    }

    // ---------- 真实路径解析（删除前的最终防线） ----------

    private const uint FILE_READ_ATTRIBUTES = 0x80;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, FileShare dwShareMode, IntPtr lpSecurityAttributes,
        FileMode dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle hFile, StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetLongPathNameW(string lpszShortPath, StringBuilder lpszLongPath, uint cchBuffer);

    /// <summary>
    /// 打开对象并询问内核它真正位于哪里。路径上任何一级是 Junction / 符号链接 / 挂载点，
    /// 返回值都会与传入的逻辑路径不同。打不开时返回 null。
    /// </summary>
    public static string? ResolveFinalPath(string path)
    {
        try
        {
            using var h = CreateFileW(path, FILE_READ_ATTRIBUTES, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero,
                FileMode.Open, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
            if (h.IsInvalid) return null;

            var sb = new StringBuilder(1024);
            var len = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
            if (len == 0) return null;
            if (len > sb.Capacity)
            {
                sb.EnsureCapacity((int)len + 1);
                len = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
                if (len == 0) return null;
            }

            var s = sb.ToString();
            if (s.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) s = @"\\" + s[8..];
            else if (s.StartsWith(@"\\?\", StringComparison.Ordinal)) s = s[4..];
            return s;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>把 8.3 短名展开为长名（不跟随重解析点）。失败时原样返回。</summary>
    public static string ToLongPath(string path)
    {
        try
        {
            var sb = new StringBuilder(1024);
            var len = GetLongPathNameW(path, sb, (uint)sb.Capacity);
            if (len == 0) return path;
            if (len > sb.Capacity)
            {
                sb.EnsureCapacity((int)len + 1);
                len = GetLongPathNameW(path, sb, (uint)sb.Capacity);
                if (len == 0) return path;
            }
            return sb.ToString();
        }
        catch
        {
            return path;
        }
    }

    /// <summary>逻辑路径与内核给出的真实路径是否为同一位置。任一为空视为不同。</summary>
    public static bool IsSamePhysicalPath(string logicalPath, string? finalPath)
    {
        if (string.IsNullOrEmpty(finalPath)) return false;
        try
        {
            var a = Normalize(ToLongPath(logicalPath));
            var b = Normalize(finalPath);
            return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>删除前最终核对：真实路径必须与逻辑路径一致，且真实路径本身也通过保护检查。</summary>
    public PathVerdict VerifyPhysical(string logicalPath)
    {
        var final = ResolveFinalPath(logicalPath);
        if (final is null) return PathVerdict.Deny("无法解析真实路径", logicalPath);
        if (!IsSamePhysicalPath(logicalPath, final))
            return PathVerdict.Deny($"路径经过重解析点，真实位置为 {final}", logicalPath);
        var v = Check(final);
        return v.Allowed ? PathVerdict.Ok(final) : PathVerdict.Deny($"真实路径被拒绝：{v.Reason}", final);
    }
}
