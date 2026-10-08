using CleanSweep.Core.Environment;
using CleanSweep.Core.Inventory;
using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Scanning;

namespace CleanSweep.Core.Residue;

/// <summary>
/// 开发者模式（设计文档 3.3.4）：指纹库中标记 devCache 的缓存目录（.gradle/caches、.m2/repository、.nuget/packages …）
/// 支持"仅清缓存不清配置"；项目根目录下长期未动的 node_modules；conda 环境只列出不默认勾选。
/// Docker Desktop 的 WSL 虚拟磁盘只显示体积，不提供删除。
/// </summary>
public sealed class DevCacheScanner : IScanner
{
    public const string ModuleId = "dev-cache";

    private readonly AppFingerprintDb _fingerprints;
    private readonly IReadOnlyList<string> _projectRoots;
    private readonly int _staleDays;

    public DevCacheScanner(AppFingerprintDb fingerprints, IReadOnlyList<string> projectRoots, int staleNodeModulesDays = 30)
    {
        _fingerprints = fingerprints;
        _projectRoots = projectRoots;
        _staleDays = staleNodeModulesDays;
    }

    public string Id => ModuleId;
    public string DisplayName => "开发者缓存";

    public Task<IReadOnlyList<ScanItem>> ScanAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct) =>
        Task.Run(() => Scan(ctx, progress, ct), ct);

    private IReadOnlyList<ScanItem> Scan(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        var items = new List<ScanItem>();
        long bytes = 0;

        // 1. 指纹库里的开发者缓存
        foreach (var fp in _fingerprints.Fingerprints.Where(f => f.Has(FingerprintFlags.DevCache)))
        {
            foreach (var cache in fp.ExpandCachePaths(ctx.Env))
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(cache) || PathGuard.IsReparsePoint(cache)) continue;
                if (!ctx.Guard.Check(cache).Allowed) continue;
                if (ctx.Whitelist.IsPathExcluded(cache)) continue;
                progress?.Report(new ScanProgress(Id, cache, items.Count, bytes));

                var files = ctx.Guard.EnumerateFiles(cache, null, recurse: true, ct).ToList();
                if (files.Count == 0) continue;
                var size = files.Sum(f => f.Size);
                items.Add(new ScanItem
                {
                    Id = RuleScanner.MakeId(ModuleId, fp.Id, cache),
                    ModuleId = ModuleId,
                    Group = fp.App,
                    DisplayName = Path.GetFileName(cache) + " 缓存",
                    Kind = ItemKind.FileSet,
                    Path = cache,
                    Files = files,
                    SizeBytes = size,
                    Risk = RiskLevel.Confirm,
                    Description = DeveloperCachePolicy.Warning,
                    LastWriteUtc = files.Max(f => f.LastWriteUtc),
                });
                bytes += size;
            }
        }

        // Share the exact rules, IDs, risk levels and age cutoffs with the application-cache page.
        // Do not derive a broader cache scope from legacy JetBrains fingerprints.
        var jetBrainsContext = new ScanContext
        {
            Env = ctx.Env, Guard = ctx.Guard, Whitelist = ctx.Whitelist, AdvancedMode = ctx.AdvancedMode,
            Rules = ctx.Rules.Where(r => r.Id == "jetbrains.ide").ToArray(),
        };
        var jetBrainsItems = RuleScanner.AppCache().ScanAsync(jetBrainsContext, null, ct).GetAwaiter().GetResult();
        items.AddRange(jetBrainsItems);
        bytes += jetBrainsItems.Sum(i => i.SizeBytes);

        // 2. conda 环境：用户数据，只列出
        if (ctx.Env.Variables.TryGetValue("UserProfile", out var profile))
        {
            foreach (var envsDir in new[] { Path.Combine(profile, "anaconda3", "envs"), Path.Combine(profile, "miniconda3", "envs"), Path.Combine(profile, ".conda", "envs") })
            {
                if (!Directory.Exists(envsDir)) continue;
                foreach (var env in ctx.Guard.EnumerateDirectories(envsDir))
                {
                    ct.ThrowIfCancellationRequested();
                    if (!ctx.Guard.Check(env.FullName).Allowed || ctx.Whitelist.IsPathExcluded(env.FullName)) continue;
                    var (size, count, last, fingerprint) = ctx.Guard.FingerprintDirectory(env.FullName, ct);
                    if (count == 0) continue;
                    items.Add(new ScanItem
                    {
                        Id = RuleScanner.MakeId(ModuleId, "conda", env.FullName),
                        ModuleId = ModuleId,
                        Group = "Conda 环境",
                        DisplayName = env.Name,
                        Kind = ItemKind.Directory,
                        Path = env.FullName,
                        SizeBytes = size,
                        Risk = RiskLevel.High,
                        Description = $"conda 环境（{count:N0} 个文件，最后修改 {(last ?? DateTime.UtcNow).ToLocalTime():yyyy-MM-dd}）。删除后需用 environment.yml 重建，请确认不再需要",
                        LastWriteUtc = last,
                        DirectoryFingerprint = fingerprint,
                        DirectoryFileCount = count,
                    });
                    bytes += size;
                }
            }
        }

        // 3. 项目根目录下长期未动的 node_modules
        foreach (var root in _projectRoots)
        {
            if (!Directory.Exists(root)) continue;
            foreach (var nm in FindNodeModules(ctx.Guard, root, maxDepth: 6, ct))
            {
                ct.ThrowIfCancellationRequested();
                if (!ctx.Guard.Check(nm).Allowed || ctx.Whitelist.IsPathExcluded(nm)) continue;
                progress?.Report(new ScanProgress(Id, nm, items.Count, bytes));
                var (size, count, last, fingerprint) = ctx.Guard.FingerprintDirectory(nm, ct);
                if (count == 0) continue;
                // 以项目目录（node_modules 的父目录）的活跃度为准：最近改过项目就不算闲置
                var project = Path.GetDirectoryName(nm)!;
                var projectLast = LatestWrite(project, last ?? DateTime.MinValue);
                var age = DateTime.UtcNow - projectLast;
                if (age.TotalDays < _staleDays) continue;
                items.Add(new ScanItem
                {
                    Id = RuleScanner.MakeId(ModuleId, "node_modules", nm),
                    ModuleId = ModuleId,
                    Group = $"闲置的 node_modules（项目 {_staleDays} 天以上未修改）",
                    DisplayName = Path.GetFileName(project) + "\\node_modules",
                    Kind = ItemKind.Directory,
                    Path = nm,
                    SizeBytes = size,
                    Risk = RiskLevel.Confirm,
                    Description = $"项目 {project} 最后修改 {projectLast.ToLocalTime():yyyy-MM-dd}。{count:N0} 个文件，运行 npm install 可重建",
                    LastWriteUtc = last,
                    DirectoryFingerprint = fingerprint,
                    DirectoryFileCount = count,
                });
                bytes += size;
            }
        }

        progress?.Report(new ScanProgress(Id, null, items.Count, bytes));
        return items;
    }

    private static DateTime LatestWrite(string projectDir, DateTime seed)
    {
        var latest = seed;
        try
        {
            latest = Max(latest, Directory.GetLastWriteTimeUtc(projectDir));
            foreach (var f in new DirectoryInfo(projectDir).EnumerateFiles("*", new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }))
                latest = Max(latest, f.LastWriteTimeUtc);
            foreach (var name in new[] { "src", "lib", "app", "pages", "components" })
            {
                var sub = Path.Combine(projectDir, name);
                if (Directory.Exists(sub) && !PathGuard.IsReparsePoint(sub)) latest = Max(latest, Directory.GetLastWriteTimeUtc(sub));
            }
        }
        catch { }
        return latest;
    }

    private static DateTime Max(DateTime a, DateTime b) => a >= b ? a : b;

    internal static IEnumerable<string> FindNodeModules(PathGuard guard, string root, int maxDepth, CancellationToken ct)
    {
        var stack = new Stack<(string Dir, int Depth)>();
        stack.Push((root, 0));
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (dir, depth) = stack.Pop();
            foreach (var child in guard.EnumerateDirectories(dir))
            {
                if (child.Name.Equals("node_modules", StringComparison.OrdinalIgnoreCase))
                {
                    yield return child.FullName;
                    continue; // 不进入 node_modules 内部
                }
                if (child.Name.StartsWith('.') || child.Name.Equals("bin", StringComparison.OrdinalIgnoreCase) || child.Name.Equals("obj", StringComparison.OrdinalIgnoreCase)) continue;
                if (depth + 1 < maxDepth) stack.Push((child.FullName, depth + 1));
            }
        }
    }

    /// <summary>Docker Desktop / WSL 虚拟磁盘：只报告体积。</summary>
    public static IReadOnlyList<(string Path, long Size)> DockerDisks(IEnvironmentResolver env)
    {
        var result = new List<(string, long)>();
        if (!env.Variables.TryGetValue("LocalAppData", out var local)) return result;
        foreach (var rel in new[] { @"Docker\wsl\data\ext4.vhdx", @"Docker\wsl\disk\docker_data.vhdx", @"Docker\wsl\distro\ext4.vhdx", @"Docker\wsl\main\ext4.vhdx" })
        {
            var p = Path.Combine(local, rel);
            try { if (File.Exists(p)) result.Add((p, new FileInfo(p).Length)); } catch { }
        }
        return result;
    }
}
