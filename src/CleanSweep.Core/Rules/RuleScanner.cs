using System.Security.Cryptography;
using System.Text;
using CleanSweep.Core.Model;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Scanning;

namespace CleanSweep.Core.Rules;

/// <summary>
/// 基于规则库的扫描器。一个实例负责一组 category（如 system，或 browser+app+dev）。
/// installed 目标产生"应用缓存"结果，uninstalled 目标产生"残留"结果（M3 才启用）。
/// </summary>
public sealed class RuleScanner : IScanner
{
    private readonly string[] _categories;
    private readonly RuleWhen[] _acceptWhen;

    public RuleScanner(string id, string displayName, string[] categories, RuleWhen[] acceptWhen)
    {
        Id = id;
        DisplayName = displayName;
        _categories = categories;
        _acceptWhen = acceptWhen;
    }

    public string Id { get; }
    public string DisplayName { get; }

    public static RuleScanner SystemJunk() =>
        new("system-junk", "系统垃圾清理", new[] { "system" }, new[] { RuleWhen.Always });

    public static RuleScanner AppCache() =>
        new("app-cache", "应用缓存清理", new[] { "browser", "app", "dev" }, new[] { RuleWhen.Installed, RuleWhen.Always });

    /// <summary>规则库中 when=uninstalled 的目标：应用已卸载时遗留的用户数据（M3 残留清理的规则部分）。</summary>
    public static RuleScanner Residue() =>
        new("residue-rules", "已卸载应用残留（规则库）", new[] { "browser", "app", "dev" }, new[] { RuleWhen.Uninstalled });

    public Task<IReadOnlyList<ScanItem>> ScanAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct)
    {
        var items = new List<ScanItem>();
        long bytes = 0;

        foreach (var rule in ctx.Rules.Where(r => _categories.Contains(r.Category)))
        {
            ct.ThrowIfCancellationRequested();
            if (ctx.Whitelist.IsRuleExcluded(rule.Id)) continue;

            bool? installed = null;

            foreach (var target in rule.Targets)
            {
                ct.ThrowIfCancellationRequested();
                if (!_acceptWhen.Contains(target.When)) continue;

                if (target.When != RuleWhen.Always)
                {
                    installed ??= RegistryDetect.IsInstalled(rule.Detect, ctx.Env);
                    if (target.When == RuleWhen.Installed && installed != true) continue;
                    if (target.When == RuleWhen.Uninstalled && installed != false) continue;
                }

                progress?.Report(new ScanProgress(Id, target.ExpandedPath ?? target.Command, items.Count, bytes));

                foreach (var item in BuildItems(rule, target, ctx, ct))
                {
                    items.Add(item);
                    bytes += item.SizeBytes;
                }
            }
        }

        progress?.Report(new ScanProgress(Id, null, items.Count, bytes));
        return Task.FromResult<IReadOnlyList<ScanItem>>(items);
    }

    /// <summary>含通配目录段的目标按实际存在的子目录逐个生成条目（条目名带匹配到的段，如"网页缓存（Profile 1）"），其余目标一个。</summary>
    private IEnumerable<ScanItem> BuildItems(CleanRule rule, RuleTarget target, ScanContext ctx, CancellationToken ct)
    {
        if (target.HasWildcard && target.ExpandedPath is not null)
        {
            foreach (var (path, match) in PathGuard.ExpandWildcards(target.ExpandedPath))
            {
                ct.ThrowIfCancellationRequested();
                var item = BuildItem(rule, target, ctx, ct, path, match);
                if (item is not null) yield return ApplySelectionPolicy(rule, item);
            }
            yield break;
        }
        var single = BuildItem(rule, target, ctx, ct, target.ExpandedPath, null);
        if (single is not null) yield return ApplySelectionPolicy(rule, single);
    }

    private static ScanItem ApplySelectionPolicy(CleanRule rule, ScanItem item) => rule.Category == "dev"
        ? item with { RequiresFreshSelection = true, Description = item.Description + "。" + DeveloperCachePolicy.Warning }
        : item;

    private ScanItem? BuildItem(CleanRule rule, RuleTarget target, ScanContext ctx, CancellationToken ct, string? expandedPath, string? match)
    {
        if (rule.Category == "dev")
            target = target with
            {
                Risk = target.Risk == RiskLevel.Safe ? RiskLevel.Confirm : target.Risk,
                Description = target.Description.Replace("可安全清理", "需确认后清理", StringComparison.Ordinal),
            };
        var id = MakeId(Id, rule.Id, expandedPath ?? target.Command ?? target.Kind.ToString());
        var displayName = string.IsNullOrEmpty(match) ? target.Description : $"{target.Description}（{match}）";

        switch (target.Kind)
        {
            case TargetKind.Files:
            {
                if (expandedPath is null) return null;

                // 运行期再次校验路径（防止环境变量在加载后发生变化）
                var verdict = ctx.Guard.Check(expandedPath);
                if (!verdict.Allowed) return null;

                var cutoff = target.MinAgeDays > 0 ? DateTime.UtcNow.AddDays(-target.MinAgeDays) : (DateTime?)null;
                List<FileEntry> files;

                if (File.Exists(expandedPath))
                {
                    // path 直接指向单个文件（如 %Windir%\MEMORY.DMP）
                    var fi = new FileInfo(expandedPath);
                    if (PathGuard.IsReparsePoint(fi.Attributes) || PathGuard.IsCloudPlaceholder(fi.Attributes)) return null;
                    // 单文件仍须遵守模式和排除规则，不能因目录位置被同名文件替代而扩大范围。
                    if (!PathGuard.MatchesAny(fi.Name, PathGuard.ParsePatterns(target.Pattern))) return null;
                    if (target.Exclude.Count > 0 && PathGuard.MatchesAny(fi.Name, target.Exclude.ToArray())) return null;
                    // 单文件目标与目录目标使用同一套年龄策略
                    if (cutoff is not null && fi.LastWriteTimeUtc >= cutoff) return null;
                    files = new List<FileEntry> { new(fi.FullName, fi.Length, fi.LastWriteTimeUtc) };
                }
                else if (Directory.Exists(expandedPath))
                {
                    var exclude = target.Exclude.Count > 0 ? target.Exclude.ToArray() : null;
                    files = ctx.Guard
                        .EnumerateFiles(expandedPath, target.Pattern, target.Recurse, ct)
                        .Where(f => cutoff is null || f.LastWriteUtc < cutoff)
                        .Where(f => exclude is null || !PathGuard.MatchesAny(Path.GetFileName(f.Path), exclude))
                        .ToList();
                }
                else
                {
                    return null;
                }

                if (files.Count == 0) return null;

                return new ScanItem
                {
                    Id = id,
                    ModuleId = Id,
                    RuleId = rule.Id,
                    Group = rule.App,
                    DisplayName = displayName,
                    Kind = ItemKind.FileSet,
                    Path = expandedPath,
                    Files = files,
                    SizeBytes = files.Sum(f => f.Size),
                    Risk = target.Risk,
                    Description = target.Description,
                    LastWriteUtc = files.Max(f => f.LastWriteUtc),
                    PreActions = target.PreActions,
                };
            }

            case TargetKind.Directory:
            {
                if (expandedPath is null || !Directory.Exists(expandedPath)) return null;
                if (PathGuardIsReparse(expandedPath)) return null;

                var verdict = ctx.Guard.Check(expandedPath);
                if (!verdict.Allowed) return null;

                var (size, count, last, fingerprint) = ctx.Guard.FingerprintDirectory(expandedPath, ct);

                return new ScanItem
                {
                    Id = id,
                    ModuleId = Id,
                    RuleId = rule.Id,
                    Group = rule.App,
                    DisplayName = displayName,
                    Kind = ItemKind.Directory,
                    Path = expandedPath,
                    SizeBytes = size,
                    Risk = target.Risk,
                    Description = $"{count:N0} 个文件，整个目录移入隔离区",
                    LastWriteUtc = last,
                    DirectoryFingerprint = fingerprint,
                    DirectoryFileCount = count,
                    PreActions = target.PreActions,
                };
            }

            case TargetKind.Command:
                return new ScanItem
                {
                    Id = id,
                    ModuleId = Id,
                    RuleId = rule.Id,
                    Group = rule.App,
                    DisplayName = target.Description,
                    Kind = ItemKind.Command,
                    SizeBytes = 0,
                    Risk = target.Risk,
                    Description = target.Description,
                    Command = target.Command,
                    CommandArgs = target.Args,
                    PreActions = target.PreActions,
                };

            case TargetKind.RecycleBin:
            {
                var (size, count) = Modules.RecycleBin.Query();
                if (count == 0) return null;
                return new ScanItem
                {
                    Id = id,
                    ModuleId = Id,
                    RuleId = rule.Id,
                    Group = rule.App,
                    DisplayName = target.Description,
                    Kind = ItemKind.RecycleBin,
                    SizeBytes = size,
                    Risk = target.Risk,
                    Description = $"{count:N0} 项。此操作不经过隔离区，不可恢复",
                };
            }

            default:
                return null;
        }
    }

    private static bool PathGuardIsReparse(string path) => Safety.PathGuard.IsReparsePoint(path);

    public static string MakeId(params string[] parts)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\u001f", parts).ToLowerInvariant()));
        return Convert.ToHexString(bytes.AsSpan(0, 12));
    }
}
