using System.Diagnostics;
using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Cleaning;

/// <summary>ProcessedBytes：已处理的字节数（移入隔离区 + 直接释放），用于进度显示。</summary>
public sealed record CleanProgress(string CurrentItem, int Done, int Total, long ProcessedBytes);

public sealed record CleanFailure(string ItemId, string ItemDisplayName, string? Path, string Reason,
    CleanIssueKind Kind = CleanIssueKind.Failure, int? ErrorCode = null);

/// <summary>单个条目的处理结果：成功、已不存在、跳过、失败的计数，界面据此决定该行是移除还是保留。</summary>
public sealed class ItemOutcome
{
    public int Succeeded { get; internal set; }
    public int Skipped { get; internal set; }
    public int Failed { get; internal set; }
    public int AlreadyAbsent { get; internal set; }

    /// <summary>没有失败或跳过；还需排除 Untouched，才可从列表移除。</summary>
    public bool Complete => Failed == 0 && Skipped == 0;

    /// <summary>尚未处理（取消时剩下的条目）。</summary>
    public bool Untouched => Succeeded == 0 && Skipped == 0 && Failed == 0 && AlreadyAbsent == 0;
}

public sealed class CleanReport
{
    public string BatchId { get; init; } = "";

    /// <summary>移入隔离区的字节数。同卷重命名不释放磁盘空间，到期或永久删除后才释放。</summary>
    public long QuarantinedBytes { get; set; }

    /// <summary>直接释放的字节数（清空回收站等不经隔离区的操作）。</summary>
    public long FreedBytes { get; set; }

    public long ProcessedBytes => QuarantinedBytes + FreedBytes;

    public int FilesQuarantined { get; set; }
    public int DirectoriesQuarantined { get; set; }
    public int EmptyDirectoriesRemoved { get; set; }

    /// <summary>删除的注册表值 / 键、服务、计划任务数（不经隔离区，靠备份撤销）。</summary>
    public int RegistryEntriesRemoved { get; set; }

    /// <summary>清理前已确认不存在的注册表目标数，不计入删除或失败。</summary>
    public int RegistryEntriesAlreadyAbsent { get; set; }

    /// <summary>因扫描后变化、白名单、已不存在等原因跳过的文件 / 目录数（不含正在使用的，见 <see cref="InUse"/>）。</summary>
    public int Skipped { get; set; }

    /// <summary>正在被其他程序使用而这次没动的文件 / 目录数。不算失败：关掉占用的程序后重新扫描即可。</summary>
    public int InUse { get; set; }

    /// <summary>正在使用的文件明细（路径与占用说明），界面按需展示。</summary>
    public List<CleanFailure> InUseFiles { get; } = new();

    public List<CleanFailure> Failures { get; } = new();
    public List<CleanFailure> SkippedDetails { get; } = new();
    public TimeSpan Elapsed { get; set; }

    /// <summary>是否因取消而中止。已处理的文件在隔离区，未处理的条目 Outcome 为 Untouched。</summary>
    public bool Cancelled { get; set; }

    /// <summary>每个条目 ID 的处理结果。</summary>
    public Dictionary<string, ItemOutcome> Outcomes { get; } = new(StringComparer.Ordinal);

    /// <summary>至少有一个文件 / 动作失败的项目 ID。</summary>
    public IReadOnlySet<string> FailedItemIds => Failures.Select(f => f.ItemId).ToHashSet(StringComparer.Ordinal);

    /// <summary>没有完全处理完（有失败、有跳过或未处理）的条目 ID，界面应保留这些行。</summary>
    public IReadOnlySet<string> IncompleteItemIds =>
        Outcomes.Where(kv => !kv.Value.Complete || kv.Value.Untouched).Select(kv => kv.Key).ToHashSet(StringComparer.Ordinal);

    internal ItemOutcome Outcome(ScanItem item)
    {
        if (!Outcomes.TryGetValue(item.Id, out var o)) Outcomes[item.Id] = o = new ItemOutcome();
        return o;
    }
}

/// <summary>
/// 执行清理。每个文件在删除前重新核对路径、大小、修改时间（设计文档 6.2 第 6 条），
/// 再次经过 PathGuard 与最新白名单检查，并确认从扫描根到文件的路径上没有重解析点，然后移入隔离区。
/// 取消令牌在每个文件之间检查；系统命令一旦启动不会被强杀（DISM 中途被杀会损坏组件存储），只等待其自行结束。
/// </summary>
public sealed class CleanEngine
{
    /// <summary>系统命令的等待上限。DISM 组件清理在慢盘上可达数十分钟，超过此值视为卡死并终止。</summary>
    public static readonly TimeSpan CommandTimeout = TimeSpan.FromMinutes(90);

    private readonly PathGuard _guard;
    private readonly Quarantine _quarantine;
    private readonly OperationLog _log;
    private readonly IPreActionRunner _preActions;
    private readonly Whitelist? _whitelist;
    private readonly RegistryCleaning.RegistryOps? _registry;
    private readonly Func<CancellationToken, Task<IReadOnlyList<ScanItem>>>? _orphanRecheck;
    private readonly Func<ScanItem, CancellationToken, Task<bool>>? _buildOutputRecheck;

    public CleanEngine(PathGuard guard, Quarantine quarantine, OperationLog log, IPreActionRunner preActions, Whitelist? whitelist = null, RegistryCleaning.RegistryOps? registry = null,
        Func<CancellationToken, Task<IReadOnlyList<ScanItem>>>? orphanRecheck = null,
        Func<ScanItem, CancellationToken, Task<bool>>? buildOutputRecheck = null)
    {
        _guard = guard;
        _quarantine = quarantine;
        _log = log;
        _preActions = preActions;
        _whitelist = whitelist;
        _registry = registry;
        _orphanRecheck = orphanRecheck;
        _buildOutputRecheck = buildOutputRecheck;
    }

    public async Task<CleanReport> CleanAsync(IReadOnlyList<ScanItem> items, IProgress<CleanProgress>? progress, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var batchId = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..6];
        var report = new CleanReport { BatchId = batchId };
        foreach (var item in items) report.Outcome(item);

        _log.BeginBatch(batchId, items.Select(i => i.ModuleId), items.Count);

        // 批量模式：隔离区索引与操作日志共享事务，每 500 次操作提交一次
        using var bulk = _log.BeginBulk();

        var restores = new List<IDisposable>();
        var failedActions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            IReadOnlyList<ScanItem> currentOrphans = [];
            string orphanReason = "卸载残留依据已变化或无法复核，请重新扫描";
            if (items.Any(i => i.ModuleId == Residue.OrphanDirectoryScanner.ModuleId) && _orphanRecheck is not null)
            {
                try { currentOrphans = await _orphanRecheck(ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    orphanReason = "无法复核卸载残留，已保留原文件：" + ex.Message;
                }
            }

            // 预动作去重后各执行一次。失败的动作记入 failedActions，依赖它的项目跳过
            foreach (var action in items.Where(i => !IsExcluded(i) && !ObsoleteDeveloperSelection(i)).SelectMany(i => i.PreActions).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                ct.ThrowIfCancellationRequested();
                var handle = _preActions.Run(action, out var err);
                if (handle is not null) restores.Add(handle);
                if (err is not null || handle is null)
                {
                    failedActions.Add(action);
                    _log.Write(batchId, "engine", "preAction", action, 0, false, err);
                }
                else
                {
                    _log.Write(batchId, "engine", "preAction", action, 0, true);
                }
            }

            int done = 0;
            foreach (var item in items)
            {
                ct.ThrowIfCancellationRequested();
                progress?.Report(new CleanProgress(item.DisplayName, done, items.Count, report.ProcessedBytes));

                var blocked = item.PreActions.FirstOrDefault(failedActions.Contains);
                if (ObsoleteDeveloperSelection(item))
                {
                    Skip(report, batchId, item, item.Path, "开发者缓存的安全分级已失效，请重新扫描并手动确认", CleanIssueKind.Changed);
                }
                else if (item.ModuleId == Residue.OrphanDirectoryScanner.ModuleId && !OrphanStillEligible(item, currentOrphans))
                {
                    Skip(report, batchId, item, item.Path, orphanReason, CleanIssueKind.Changed);
                }
                else if (blocked is not null)
                {
                    Fail(report, batchId, item, item.Path, $"前置动作失败（{blocked}），跳过以免破坏正在使用的文件");
                }
                else if (IsExcluded(item))
                {
                    Skip(report, batchId, item, item.Path, "项目、规则或目标路径已在白名单");
                }
                else if (item.ModuleId == Residue.BuildOutputScanner.ModuleId && !await BuildOutputStillEligible(item, ct).ConfigureAwait(false))
                {
                    Skip(report, batchId, item, item.Path, "构建依据、项目范围或进程状态已变化，或无法完成复核；请关闭构建/调试程序后重新扫描", CleanIssueKind.Changed);
                }
                else
                {
                    await Task.Run(() => CleanItem(item, batchId, report, ct), CancellationToken.None).ConfigureAwait(false);
                }
                done++;
            }

            progress?.Report(new CleanProgress("完成", done, items.Count, report.ProcessedBytes));
        }
        catch (OperationCanceledException)
        {
            report.Cancelled = true;
            _log.Write(batchId, "engine", "cancel", null, 0, true, "用户取消，已处理的文件在隔离区");
            throw new CleanCancelledException(report, ct);
        }
        finally
        {
            foreach (var r in restores)
            {
                try { r.Dispose(); } catch { /* 恢复失败已在 runner 内部处理 */ }
            }
            _log.EndBatch(batchId, report.ProcessedBytes);
            report.Elapsed = sw.Elapsed;
        }

        return report;
    }

    private bool IsExcluded(ScanItem item) => _whitelist is not null && (_whitelist.IsItemExcluded(item.Id)
        || item.RuleId is { } rule && _whitelist.IsRuleExcluded(rule)
        || item.Path is { } path && _whitelist.IsPathExcluded(path));

    private static bool ObsoleteDeveloperSelection(ScanItem item) =>
        DeveloperCachePolicy.IsDeveloperCache(item) && item.Risk == RiskLevel.Safe;

    private async Task<bool> BuildOutputStillEligible(ScanItem item, CancellationToken ct)
    {
        if (_buildOutputRecheck is null) return false;
        try { return await _buildOutputRecheck(item, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch { return false; }
    }

    private static bool OrphanStillEligible(ScanItem item, IReadOnlyList<ScanItem> current)
    {
        var fresh = current.FirstOrDefault(i => i.Id == item.Id && i.ModuleId == item.ModuleId && i.Kind == item.Kind
            && string.Equals(i.Path, item.Path, StringComparison.OrdinalIgnoreCase));
        if (fresh is null) return false;
        if (item.Kind == ItemKind.Directory) return fresh.DirectoryFileCount == 0 && fresh.SizeBytes == 0;
        if (item.Kind != ItemKind.FileSet) return false;
        var allowed = fresh.Files.Select(f => f.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return item.Files.All(f => allowed.Contains(f.Path));
    }

    private void CleanItem(ScanItem item, string batchId, CleanReport report, CancellationToken ct)
    {
        switch (item.Kind)
        {
            case ItemKind.FileSet:
                CleanFileSet(item, batchId, report, ct);
                break;
            case ItemKind.Directory:
                CleanDirectory(item, batchId, report, ct);
                break;
            case ItemKind.RecycleBin:
                CleanRecycleBin(item, batchId, report);
                break;
            case ItemKind.Command:
                RunCommand(item, batchId, report, ct);
                break;
            case ItemKind.RegistryValue:
            case ItemKind.RegistryKey:
            case ItemKind.Service:
            case ItemKind.ScheduledTask:
                CleanRegistryLike(item, batchId, report);
                break;
            default:
                Fail(report, batchId, item, item.Path, $"不支持的条目类型：{item.Kind}");
                break;
        }
    }

    /// <summary>注册表值 / 键、服务、计划任务：不经隔离区，靠删除前的备份撤销。护栏与备份都在 RegistryOps 内。</summary>
    private void CleanRegistryLike(ScanItem item, string batchId, CleanReport report)
    {
        if (_registry is null)
        {
            Fail(report, batchId, item, item.Path, "引擎未配置注册表备份，拒绝执行注册表类操作");
            return;
        }
        var target = item.Registry is { } registry
            ? registry.KeyPath + (registry.ValueName is { } valueName ? "\\" + (valueName.Length == 0 ? "（默认值）" : valueName) : "")
                + (registry.View == Microsoft.Win32.RegistryView.Registry32 ? "（32 位视图）" : registry.View == Microsoft.Win32.RegistryView.Registry64 ? "（64 位视图）" : "（默认视图）")
            : item.ServiceName ?? item.TaskPath;
        try
        {
            var reason = $"清理：{item.DisplayName}";
            string backup = item.Kind switch
            {
                ItemKind.RegistryValue => _registry.DeleteValue(item.Registry ?? throw new InvalidOperationException("缺少注册表目标"), reason, item.TargetSnapshot, item.MissingPath),
                ItemKind.RegistryKey => _registry.DeleteKey(item.Registry ?? throw new InvalidOperationException("缺少注册表目标"), reason, item.TargetSnapshot, item.MissingPath),
                ItemKind.Service => _registry.DeleteService(item.ServiceName ?? throw new InvalidOperationException("缺少服务名"), reason, item.TargetSnapshot, item.MissingPath),
                ItemKind.ScheduledTask => _registry.DeleteScheduledTask(item.TaskPath ?? throw new InvalidOperationException("缺少任务路径"), reason, item.TargetSnapshot, item.MissingPath),
                _ => throw new InvalidOperationException("类型不匹配"),
            };
            report.Outcome(item).Succeeded++;
            report.RegistryEntriesRemoved++;
            _log.Write(batchId, item.ModuleId, item.Kind switch
            {
                ItemKind.RegistryValue => "delete-value",
                ItemKind.RegistryKey => "delete-key",
                ItemKind.Service => "delete-service",
                _ => "delete-task",
            }, target, 0, true, "备份：" + backup);
        }
        catch (RegistryCleaning.RegistryTargetMissingException ex)
        {
            report.Outcome(item).AlreadyAbsent++;
            report.RegistryEntriesAlreadyAbsent++;
            report.SkippedDetails.Add(new(item.Id, item.DisplayName, target, ex.Message, CleanIssueKind.AlreadyAbsent));
            _log.Write(batchId, item.ModuleId, "already-absent", target, 0, true, ex.Message);
        }
        catch (Exception ex)
        {
            FailException(report, batchId, item, target, ex);
        }
    }

    private void CleanFileSet(ScanItem item, string batchId, CleanReport report, CancellationToken ct)
    {
        var root = item.Path;
        var touchedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var f in item.Files)
            {
                ct.ThrowIfCancellationRequested();

                // 1. 路径护栏与最新白名单
                var verdict = _guard.Check(f.Path);
                if (!verdict.Allowed)
                {
                    Fail(report, batchId, item, f.Path, $"护栏拒绝：{verdict.Reason}");
                    continue;
                }
                if (_whitelist is not null && _whitelist.IsPathExcluded(f.Path))
                {
                    Skip(report, batchId, item, f.Path, "已在白名单");
                    continue;
                }

                // 2. 二次核对：文件仍存在且未变化
                FileInfo fi;
                try
                {
                    fi = new FileInfo(f.Path);
                    if (!fi.Exists)
                    {
                        Skip(report, batchId, item, f.Path, "文件已不存在", CleanIssueKind.AlreadyAbsent);
                        continue;
                    }
                    if (fi.Length != f.Size || fi.LastWriteTimeUtc != f.LastWriteUtc)
                    {
                        Skip(report, batchId, item, f.Path, "文件在扫描后发生变化", CleanIssueKind.Changed);
                        continue;
                    }
                    if (PathGuard.IsReparsePoint(fi.Attributes) || PathGuard.IsCloudPlaceholder(fi.Attributes))
                    {
                        Skip(report, batchId, item, f.Path, "重解析点或云端占位文件");
                        continue;
                    }
                }
                catch (Exception ex)
                {
                    FailException(report, batchId, item, f.Path, ex);
                    continue;
                }

                // 3. 从扫描根到文件之间不得穿过重解析点
                if (root is not null && PathGuard.AnyAncestorIsReparsePoint(f.Path, root))
                {
                    Fail(report, batchId, item, f.Path, "路径中包含重解析点");
                    continue;
                }

                // 4. 最终防线：向内核确认真实位置与逻辑路径一致（覆盖根目录及其祖先被替换成 Junction 的情况）。
                //    隔离区的移动本身也是句柄级操作，会再次核对同一对象。
                var physical = _guard.VerifyPhysical(f.Path);
                if (!physical.Allowed)
                {
                    Fail(report, batchId, item, f.Path, physical.Reason!);
                    continue;
                }

                // 5. 移入隔离区
                try
                {
                    _quarantine.MoveIn(f.Path, isDirectory: false, f.Size, item.ModuleId, batchId, item.DisplayName);
                    report.QuarantinedBytes += f.Size;
                    report.FilesQuarantined++;
                    report.Outcome(item).Succeeded++;
                    _log.Write(batchId, item.ModuleId, "quarantine", f.Path, f.Size, true);
                    if (Path.GetDirectoryName(f.Path) is { } parent) touchedDirs.Add(parent);
                }
                catch (Exception ex) when (FileInUse.Is(ex))
                {
                    InUseSkip(report, batchId, item, f.Path);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    FailException(report, batchId, item, f.Path, ex);
                }
            }
        }
        finally
        {
            // 取消时也把已经搬空的子目录清掉，不留空壳
            if (root is not null && touchedDirs.Count > 0) RemoveEmptyDirectories(root, touchedDirs, item, batchId, report);
        }
    }

    /// <summary>
    /// 文件搬走后清掉变空的子目录（不含扫描根本身）。只用非递归删除，目录非空即失败，
    /// 因此不可能误删内容；重解析点与扫描根之外的目录一律不碰。
    /// </summary>
    private void RemoveEmptyDirectories(string root, HashSet<string> touchedDirs, ScanItem item, string batchId, CleanReport report)
    {
        var rootFull = PathGuard.Normalize(root);
        var candidates = new SortedSet<string>(Comparer<string>.Create((a, b) =>
        {
            var d = b.Count(ch => ch == Path.DirectorySeparatorChar).CompareTo(a.Count(ch => ch == Path.DirectorySeparatorChar));
            return d != 0 ? d : string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
        }));

        foreach (var dir in touchedDirs)
        {
            var current = PathGuard.Normalize(dir);
            while (PathGuard.IsSameOrUnder(current, rootFull) && !string.Equals(current, rootFull, StringComparison.OrdinalIgnoreCase))
            {
                candidates.Add(current);
                current = Path.GetDirectoryName(current) ?? rootFull;
            }
        }

        int removed = 0;
        foreach (var dir in candidates)
        {
            try
            {
                if (!Directory.Exists(dir) || PathGuard.IsReparsePoint(dir)) continue;
                if (Directory.EnumerateFileSystemEntries(dir).Any()) continue;
                Directory.Delete(dir, recursive: false);
                removed++;
            }
            catch
            {
                // 非空、被占用或无权限：保留
            }
        }

        if (removed > 0)
        {
            report.EmptyDirectoriesRemoved += removed;
            _log.Write(batchId, item.ModuleId, "remove-empty-dirs", root, 0, true, $"{removed} 个空目录");
        }
    }

    private void CleanDirectory(ScanItem item, string batchId, CleanReport report, CancellationToken ct)
    {
        if (item.Path is null) return;

        var verdict = _guard.Check(item.Path);
        if (!verdict.Allowed)
        {
            Fail(report, batchId, item, item.Path, $"护栏拒绝：{verdict.Reason}");
            return;
        }

        if (!Directory.Exists(item.Path))
        {
            Skip(report, batchId, item, item.Path, "目录已不存在", CleanIssueKind.AlreadyAbsent);
            return;
        }

        if (PathGuard.IsReparsePoint(item.Path))
        {
            Fail(report, batchId, item, item.Path, "目录本身是重解析点");
            return;
        }

        // 整目录移动会带走其中的一切：目录本身或其中任何路径在白名单里都不允许整体移动
        if (_whitelist is not null)
        {
            if (_whitelist.IsPathExcluded(item.Path))
            {
                Skip(report, batchId, item, item.Path, "目录已在白名单");
                return;
            }
            var inside = _whitelist.Paths.FirstOrDefault(p => PathGuard.IsSameOrUnder(p, item.Path));
            if (inside is not null)
            {
                Fail(report, batchId, item, item.Path, $"目录包含白名单项目，不能整体清理：{inside}");
                return;
            }
        }

        // 扫描快照核对：逐文件指纹（相对路径、大小、修改时间）与扫描时不一致就拒绝整体移动，让用户重新扫描。
        // 没有指纹的条目（旧调用方）退回总大小 + 文件数 + 最新修改时间比较。
        var (size, count, last, fingerprint) = _guard.FingerprintDirectory(item.Path, ct);
        bool changed = item.DirectoryFingerprint is not null
            ? !string.Equals(fingerprint, item.DirectoryFingerprint, StringComparison.OrdinalIgnoreCase)
            : size != item.SizeBytes || (item.DirectoryFileCount > 0 && count != item.DirectoryFileCount)
                                     || (last is not null && item.LastWriteUtc is not null && last > item.LastWriteUtc);
        if (changed)
        {
            Fail(report, batchId, item, item.Path, $"目录内容在扫描后发生变化（现为 {count:N0} 个文件），请重新扫描", CleanIssueKind.Changed);
            return;
        }

        var physical = _guard.VerifyPhysical(item.Path);
        if (!physical.Allowed)
        {
            Fail(report, batchId, item, item.Path, physical.Reason!);
            return;
        }

        ct.ThrowIfCancellationRequested();
        try
        {
            // Empty subdirectories and reparse children are not represented in the file fingerprint.
            if (item.ModuleId == Residue.OrphanDirectoryScanner.ModuleId && Directory.EnumerateFileSystemEntries(item.Path).Any())
            {
                Skip(report, batchId, item, item.Path, "空目录已出现内容，请重新扫描", CleanIssueKind.Changed);
                return;
            }
            _quarantine.MoveIn(item.Path, isDirectory: true, item.SizeBytes, item.ModuleId, batchId, item.DisplayName);
            report.QuarantinedBytes += item.SizeBytes;
            report.DirectoriesQuarantined++;
            report.Outcome(item).Succeeded++;
            _log.Write(batchId, item.ModuleId, "quarantine-dir", item.Path, item.SizeBytes, true);
        }
        catch (Exception ex) when (FileInUse.Is(ex))
        {
            InUseSkip(report, batchId, item, item.Path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            FailException(report, batchId, item, item.Path, ex);
        }
    }

    private void CleanRecycleBin(ScanItem item, string batchId, CleanReport report)
    {
        var (ok, err) = Modules.RecycleBin.Empty();
        if (ok)
        {
            report.FreedBytes += item.SizeBytes;
            report.Outcome(item).Succeeded++;
            _log.Write(batchId, item.ModuleId, "empty-recycle-bin", null, item.SizeBytes, true);
        }
        else
        {
            Fail(report, batchId, item, null, err ?? "清空回收站失败");
        }
    }

    private void RunCommand(ScanItem item, string batchId, CleanReport report, CancellationToken ct)
    {
        // 命令与参数必须精确匹配代码里固定的操作表，规则只能引用不能自定义
        if (item.Command is null || !RuleLoader.IsAllowedOperation(item.Command, item.CommandArgs))
        {
            Fail(report, batchId, item, item.Command, "命令或参数不在允许的操作表内");
            return;
        }

        var exe = Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.System), item.Command);
        if (!File.Exists(exe))
        {
            Fail(report, batchId, item, exe, "系统命令不存在");
            return;
        }

        ct.ThrowIfCancellationRequested();
        try
        {
            var psi = new ProcessStartInfo(exe, item.CommandArgs ?? "")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = false, // 不读取的重定向流会在缓冲区写满时阻塞子进程
            };
            using var p = Process.Start(psi)!;
            var stdoutTask = p.StandardOutput.ReadToEndAsync();

            // 等待命令自行结束。收到取消请求不强杀（DISM / cleanmgr 中途被杀可能损坏组件存储），
            // 只记录并在命令结束后再把取消传出去；超过上限视为卡死才终止。
            var sw = Stopwatch.StartNew();
            bool cancelNoted = false;
            while (!p.WaitForExit(500))
            {
                if (!cancelNoted && ct.IsCancellationRequested)
                {
                    cancelNoted = true;
                    _log.Write(batchId, item.ModuleId, "command", $"{item.Command} {item.CommandArgs}", 0, true, "收到取消请求，等待系统命令自行结束（不强制终止）");
                }
                if (sw.Elapsed > CommandTimeout)
                {
                    try { p.Kill(entireProcessTree: true); } catch { }
                    Fail(report, batchId, item, item.Command, $"系统命令超过 {CommandTimeout.TotalMinutes:0} 分钟未结束，已终止");
                    return;
                }
            }
            p.WaitForExit();

            string stdout;
            try { stdout = stdoutTask.Wait(5000) ? stdoutTask.Result : ""; } catch { stdout = ""; }

            var ok = p.ExitCode == 0;
            _log.Write(batchId, item.ModuleId, "command", $"{item.Command} {item.CommandArgs}", 0, ok, ok ? null : $"退出码 {p.ExitCode}：{Tail(stdout)}");
            if (ok) report.Outcome(item).Succeeded++;
            else Fail(report, batchId, item, item.Command, $"退出码 {p.ExitCode}");

            if (cancelNoted) ct.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            FailException(report, batchId, item, item.Command, ex);
        }
    }

    private void Fail(CleanReport report, string batchId, ScanItem item, string? path, string reason,
        CleanIssueKind kind = CleanIssueKind.Failure, int? errorCode = null)
    {
        reason = StripPathSuffix(reason, path);
        report.Failures.Add(new CleanFailure(item.Id, item.DisplayName, path, reason, kind, errorCode));
        report.Outcome(item).Failed++;
        _log.Write(batchId, item.ModuleId, "fail", path, 0, false, reason);
    }

    /// <summary>正在使用的文件按跳过计数，条目保留在列表里；不进 Failures，界面不为它弹失败对话框。</summary>
    private void InUseSkip(CleanReport report, string batchId, ScanItem item, string? path)
    {
        const string reason = "正在被其他程序使用，这次跳过";
        report.InUse++;
        report.InUseFiles.Add(new CleanFailure(item.Id, item.DisplayName, path, reason, CleanIssueKind.InUse));
        report.Outcome(item).Skipped++;
        _log.Write(batchId, item.ModuleId, "skip", path, 0, true, reason);
    }

    /// <summary>底层异常消息常自带"（路径）"后缀（HandleMove、.NET IO），失败明细已单独列路径，去掉重复的一份。</summary>
    internal static string StripPathSuffix(string reason, string? path)
    {
        if (string.IsNullOrEmpty(path)) return reason;
        var trimmed = reason.TrimEnd();
        foreach (var suffix in new[] { $"（{path}）", $"({path})", $"'{path}'", $"\"{path}\"" })
        {
            if (trimmed.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return trimmed[..^suffix.Length].TrimEnd(' ', '：', ':', '。', '.');
        }
        return reason;
    }

    private void Skip(CleanReport report, string batchId, ScanItem item, string? path, string reason,
        CleanIssueKind kind = CleanIssueKind.Excluded)
    {
        report.Skipped++;
        report.Outcome(item).Skipped++;
        report.SkippedDetails.Add(new(item.Id, item.DisplayName, path, reason, kind));
        _log.Write(batchId, item.ModuleId, "skip", path, 0, true, reason);
    }

    private static string Tail(string s) => s.Length <= 400 ? s.Trim() : s[^400..].Trim();

    private void FailException(CleanReport report, string batchId, ScanItem item, string? path, Exception ex) =>
        Fail(report, batchId, item, path, ex.Message, CleanIssueClassifier.FromException(ex),
            ex is System.ComponentModel.Win32Exception native ? native.NativeErrorCode : ex.HResult);
}
