using System.Text.Json;
using CleanSweep.Core.Environment;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;

namespace CleanSweep.Core.Inventory;

/// <summary>指纹的安装检测条件。一条只填一个字段。</summary>
public sealed class FingerprintCondition
{
    /// <summary>注册表键存在。</summary>
    public string? Registry { get; set; }

    /// <summary>文件存在（可含 %变量%）。</summary>
    public string? File { get; set; }

    /// <summary>目录存在（可含 %变量%）。</summary>
    public string? Directory { get; set; }

    /// <summary>PATH 中能找到该命令（gradle、mvn、docker）。</summary>
    public string? Command { get; set; }

    /// <summary>已安装软件清单里有名字匹配的应用。</summary>
    public string? InstalledName { get; set; }

    /// <summary>已安装软件清单里有发布者匹配的应用。</summary>
    public string? InstalledPublisher { get; set; }

    /// <summary>已安装的应用商店包家族名（Name_PublisherId）。</summary>
    public string? PackageFamily { get; set; }
}

public sealed class FingerprintDetect
{
    public List<FingerprintCondition>? AnyOf { get; set; }
    public List<FingerprintCondition>? AllOf { get; set; }
}

public sealed class AppFingerprintDto
{
    public string? Id { get; set; }
    public string? App { get; set; }
    public string? Publisher { get; set; }
    public List<string>? Paths { get; set; }
    public FingerprintDetect? Detect { get; set; }
    public List<string>? Flags { get; set; }
    public List<string>? CachePaths { get; set; }
    public string? Note { get; set; }
}

public sealed class FingerprintFileDto
{
    public int Version { get; set; } = 1;
    public List<AppFingerprintDto>? Fingerprints { get; set; }
}

/// <summary>标志位。</summary>
public static class FingerprintFlags
{
    /// <summary>含登录态 / 聊天记录，清理前明确提示。</summary>
    public const string LoginState = "loginState";

    /// <summary>重装依赖此配置恢复许可证，降为"建议确认"。</summary>
    public const string License = "license";

    /// <summary>可能含游戏存档，标红。</summary>
    public const string GameSaves = "gameSaves";

    /// <summary>开发者缓存：CachePaths 可在应用仍安装时清理（"仅清缓存不清配置"）。</summary>
    public const string DevCache = "devCache";

    /// <summary>程序本体 / SDK，体积大但删除后需重新下载。</summary>
    public const string ProgramBody = "programBody";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { LoginState, License, GameSaves, DevCache, ProgramBody };
}

/// <summary>校验通过的应用指纹（设计文档 3.3.2 信号 B、7.2 App Fingerprint DB）。路径保留原始形式，按目标用户展开。</summary>
public sealed record AppFingerprint(
    string Id,
    string App,
    string? Publisher,
    IReadOnlyList<string> RawPaths,
    FingerprintDetect? Detect,
    IReadOnlySet<string> Flags,
    IReadOnlyList<string> RawCachePaths,
    string? Note,
    string SourceFile)
{
    public bool Has(string flag) => Flags.Contains(flag);

    /// <summary>按给定用户环境展开 Paths；展开失败的跳过。</summary>
    public IEnumerable<string> ExpandPaths(IEnvironmentResolver env) => Expand(RawPaths, env);

    public IEnumerable<string> ExpandCachePaths(IEnvironmentResolver env)
    {
        // Older signed fingerprints classified the entire JetBrains system directory as cache.
        // It also contains Local History. Only the dedicated rules may select its subdirectories.
        var jetBrains = env.Variables.TryGetValue("LocalAppData", out var local)
            ? Path.Combine(local, "JetBrains") : null;
        return Expand(RawCachePaths, env).Where(p => jetBrains is null
            || (!PathGuard.IsSameOrUnder(p, jetBrains) && !PathGuard.IsSameOrUnder(jetBrains, p)));
    }

    private static IEnumerable<string> Expand(IEnumerable<string> raws, IEnvironmentResolver env)
    {
        foreach (var raw in raws)
        {
            if (!env.TryExpand(raw, out var full, out _)) continue;
            string norm;
            try { norm = PathGuard.Normalize(full); } catch { continue; }
            yield return norm;
        }
    }
}

/// <summary>指纹库：加载、校验、按路径查找、安装检测。</summary>
public sealed class AppFingerprintDb
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    public List<AppFingerprint> Fingerprints { get; } = new();
    public List<RuleRejection> Rejected { get; } = new();

    public static AppFingerprintDb Empty() => new();

    /// <summary>加载目录下全部 *.json。路径经 PathGuard 校验（必须以 %变量% 开头、不含 ..、不落在保护路径），不合法整条拒绝。</summary>
    public static AppFingerprintDb LoadDirectory(string directory, PathGuard guard)
    {
        var db = new AppFingerprintDb();
        if (!Directory.Exists(directory))
        {
            db.Rejected.Add(new RuleRejection(directory, null, "指纹目录不存在"));
            return db;
        }
        return LoadFiles(Directory.EnumerateFiles(directory, "*.json", SearchOption.AllDirectories)
            .Where(f => !Path.GetFileName(f).Equals(Integrity.SignedManifest.FileName, StringComparison.OrdinalIgnoreCase)), guard);
    }

    /// <summary>加载签名清单校验通过的文件内容（校验时读到的字节，不重读磁盘）。</summary>
    public static AppFingerprintDb LoadContents(IEnumerable<Integrity.VerifiedFile> files, PathGuard guard)
    {
        var db = new AppFingerprintDb();
        foreach (var f in files.OrderBy(f => f.Path, StringComparer.OrdinalIgnoreCase)) db.LoadJson(f.Content, f.Path, guard);
        return db;
    }

    /// <summary>按路径加载给定的文件（测试与工具用）。</summary>
    public static AppFingerprintDb LoadFiles(IEnumerable<string> files, PathGuard guard)
    {
        var db = new AppFingerprintDb();
        foreach (var file in files.OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
        {
            string json;
            try { json = File.ReadAllText(file); }
            catch (Exception ex)
            {
                db.Rejected.Add(new RuleRejection(file, null, $"读取失败：{ex.Message}"));
                continue;
            }
            db.LoadJson(json, file, guard);
        }
        return db;
    }

    public static AppFingerprintDb FromJson(string json, string sourceName, PathGuard guard)
    {
        var db = new AppFingerprintDb();
        db.LoadJson(json, sourceName, guard);
        return db;
    }

    private void LoadJson(string json, string source, PathGuard guard)
    {
        FingerprintFileDto? dto;
        try { dto = JsonSerializer.Deserialize<FingerprintFileDto>(json, JsonOptions); }
        catch (JsonException ex)
        {
            Rejected.Add(new RuleRejection(source, null, $"JSON 解析失败：{ex.Message}"));
            return;
        }
        if (dto?.Fingerprints is null || dto.Fingerprints.Count == 0)
        {
            Rejected.Add(new RuleRejection(source, null, "文件中没有 fingerprints 数组"));
            return;
        }

        var seen = new HashSet<string>(Fingerprints.Select(f => f.Id), StringComparer.OrdinalIgnoreCase);
        foreach (var f in dto.Fingerprints)
        {
            if (f is null)
            {
                Rejected.Add(new RuleRejection(source, null, "指纹为 null"));
                continue;
            }
            string? reason;
            AppFingerprint? fp;
            try { (fp, reason) = Validate(f, source, guard); }
            catch (Exception ex) { fp = null; reason = $"校验异常：{ex.Message}"; }
            if (fp is null)
            {
                Rejected.Add(new RuleRejection(source, f.Id, reason!));
                continue;
            }
            if (!seen.Add(fp.Id))
            {
                Rejected.Add(new RuleRejection(source, fp.Id, "指纹 ID 重复"));
                continue;
            }
            Fingerprints.Add(fp);
        }
    }

    private static (AppFingerprint?, string?) Validate(AppFingerprintDto f, string source, PathGuard guard)
    {
        if (string.IsNullOrWhiteSpace(f.Id)) return (null, "缺少 id");
        if (string.IsNullOrWhiteSpace(f.App)) return (null, "缺少 app");
        if (f.Paths is null || f.Paths.Count == 0) return (null, "缺少 paths");

        foreach (var p in f.Paths.Concat(f.CachePaths ?? new()))
        {
            if (p is null) return (null, "路径为 null");
            var verdict = guard.ValidateRulePath(p);
            if (!verdict.Allowed) return (null, $"路径被拒绝（{p}）：{verdict.Reason}");
        }
        foreach (var c in f.CachePaths ?? new())
        {
            // 缓存路径必须位于某个主路径之下，否则"仅清缓存"会越界
            if (!f.Paths.Any(p => c.StartsWith(p, StringComparison.OrdinalIgnoreCase) || c.StartsWith(p.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)))
                return (null, $"cachePaths 必须位于 paths 之下：{c}");
        }

        var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var flag in f.Flags ?? new())
        {
            if (flag is null || !FingerprintFlags.All.Contains(flag)) return (null, $"未知 flag：{flag}");
            flags.Add(flag);
        }

        if (f.Detect is not null)
        {
            foreach (var c in (f.Detect.AnyOf ?? new()).Concat(f.Detect.AllOf ?? new()))
            {
                if (c is null) return (null, "detect 条件为 null");
                var filled = new[] { c.Registry, c.File, c.Directory, c.Command, c.InstalledName, c.InstalledPublisher, c.PackageFamily }.Count(x => !string.IsNullOrWhiteSpace(x));
                if (filled != 1) return (null, "detect 条件必须且只能填一个字段");
                if (c.Registry is not null && !RegistryDetect.IsValidKeyPath(c.Registry)) return (null, $"detect 注册表路径无效：{c.Registry}");
                if (c.Command is not null && c.Command.IndexOfAny(new[] { '\\', '/', ':', ' ' }) >= 0) return (null, $"detect command 只能是命令名：{c.Command}");
            }
        }

        return (new AppFingerprint(f.Id.Trim(), f.App.Trim(), f.Publisher?.Trim(), f.Paths.AsReadOnly(), f.Detect, flags,
            (f.CachePaths ?? new()).AsReadOnly(), f.Note, source), null);
    }

    /// <summary>按目标用户环境建立"展开路径 → 指纹"索引。</summary>
    public Dictionary<string, AppFingerprint> IndexByPath(IEnvironmentResolver env)
    {
        var map = new Dictionary<string, AppFingerprint>(StringComparer.OrdinalIgnoreCase);
        foreach (var fp in Fingerprints)
            foreach (var p in fp.ExpandPaths(env))
                map.TryAdd(p, fp);
        return map;
    }

    /// <summary>指纹对应的应用当前是否已安装。没有 detect 的指纹视为"无法判定"（返回 null）。</summary>
    public static bool? IsInstalled(AppFingerprint fp, InventorySnapshot inventory, IEnvironmentResolver env) => IsInstalled(fp, inventory, env, out _, out _);

    /// <summary>
    /// usesRegistryInventory / usesUwpInventory：检测条件里是否用到了已安装清单（installedName / installedPublisher / packageFamily）。
    /// 清单读取不可靠时，这类"未找到"不能当作已卸载的证据，调用方应降级为"无法判定"。
    /// </summary>
    public static bool? IsInstalled(AppFingerprint fp, InventorySnapshot inventory, IEnvironmentResolver env, out bool usesRegistryInventory, out bool usesUwpInventory)
    {
        usesRegistryInventory = false;
        usesUwpInventory = false;
        if (fp.Detect is null) return null;
        foreach (var c in (fp.Detect.AnyOf ?? new()).Concat(fp.Detect.AllOf ?? new()))
        {
            if (c.InstalledName is not null || c.InstalledPublisher is not null) usesRegistryInventory = true;
            if (c.PackageFamily is not null) usesUwpInventory = true;
        }
        var any = fp.Detect.AnyOf is null || fp.Detect.AnyOf.Count == 0 || fp.Detect.AnyOf.Any(c => Eval(c, inventory, env));
        var all = fp.Detect.AllOf is null || fp.Detect.AllOf.All(c => Eval(c, inventory, env));
        return any && all;
    }

    private static bool Eval(FingerprintCondition c, InventorySnapshot inv, IEnvironmentResolver env)
    {
        if (c.Registry is not null) return RegistryDetect.KeyExists(c.Registry);
        if (c.File is not null) return env.TryExpand(c.File, out var f, out _) && File.Exists(f);
        if (c.Directory is not null) return env.TryExpand(c.Directory, out var d, out _) && Directory.Exists(d);
        if (c.Command is not null) return CommandOnPath(c.Command);
        if (c.InstalledName is not null) return inv.FindByName(c.InstalledName) is not null;
        if (c.InstalledPublisher is not null) return inv.IsPublisher(c.InstalledPublisher);
        if (c.PackageFamily is not null) return inv.IsPackageFamilyInstalled(c.PackageFamily);
        return false;
    }

    internal static bool CommandOnPath(string command)
    {
        var path = System.Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrEmpty(path)) return false;
        var names = Path.HasExtension(command) ? new[] { command } : new[] { command + ".exe", command + ".cmd", command + ".bat" };
        foreach (var dir in path.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            foreach (var n in names)
            {
                try { if (File.Exists(Path.Combine(dir, n))) return true; } catch { }
            }
        }
        return false;
    }
}
