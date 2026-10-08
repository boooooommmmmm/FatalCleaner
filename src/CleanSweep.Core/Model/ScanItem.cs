namespace CleanSweep.Core.Model;

/// <summary>扫描结果条目的类型。</summary>
public enum ItemKind
{
    /// <summary>一组文件（规则目标匹配到的文件集合），逐个移入隔离区。</summary>
    FileSet,

    /// <summary>整个目录，作为一个整体移入隔离区。</summary>
    Directory,

    /// <summary>系统回收站，经 Shell API 清空，不进入隔离区。</summary>
    RecycleBin,

    /// <summary>执行一条白名单内的系统命令（如 DISM 组件清理）。</summary>
    Command,

    /// <summary>删除一个注册表值。删除前做值级备份（.reg），可在设置中还原。</summary>
    RegistryValue,

    /// <summary>删除一个注册表键及其子树。删除前导出整键备份。</summary>
    RegistryKey,

    /// <summary>删除一个服务（DeleteService）。删除前导出服务键备份。</summary>
    Service,

    /// <summary>删除一个计划任务。删除前把任务 XML 存到备份目录。</summary>
    ScheduledTask,
}

/// <summary>注册表类条目的目标。</summary>
public sealed record RegistryTarget(string KeyPath, Microsoft.Win32.RegistryView View, string? ValueName);

/// <summary>扫描时捕获的单个文件快照，清理前用于二次核对（设计文档 6.2 第 6 条）。</summary>
public sealed record FileEntry(string Path, long Size, DateTime LastWriteUtc);

/// <summary>一条可供用户勾选的扫描结果。</summary>
public sealed record ScanItem
{
    /// <summary>稳定 ID，由模块 ID 与路径派生，用于白名单与去重。</summary>
    public required string Id { get; init; }

    public required string ModuleId { get; init; }

    /// <summary>界面分组，例如应用名或系统分类。</summary>
    public required string Group { get; init; }

    public required string DisplayName { get; init; }

    public ItemKind Kind { get; init; } = ItemKind.FileSet;

    /// <summary>目录类条目的目录路径，或 FileSet 的根目录。</summary>
    public string? Path { get; init; }

    public IReadOnlyList<FileEntry> Files { get; init; } = Array.Empty<FileEntry>();

    public long SizeBytes { get; init; }

    public int FileCount => Files.Count;

    public RiskLevel Risk { get; init; } = RiskLevel.Safe;

    /// <summary>每次扫描都需重新选择，不能恢复上一次的勾选（例如会影响构建的开发缓存）。</summary>
    public bool RequiresFreshSelection { get; init; }

    public string Description { get; init; } = "";

    public DateTime? LastWriteUtc { get; init; }

    /// <summary>
    /// Directory 类条目在扫描时的内容指纹（<see cref="Safety.PathGuard.FingerprintDirectory"/>）：
    /// 覆盖每个文件的相对路径、大小、修改时间。清理前重新计算并比对，任何一个文件变化都拒绝整目录移动。
    /// </summary>
    public string? DirectoryFingerprint { get; init; }

    /// <summary>Directory 类条目扫描时的文件数。</summary>
    public int DirectoryFileCount { get; init; }

    /// <summary>清理前需执行的动作，形如 "stopService:wuauserv"。</summary>
    public IReadOnlyList<string> PreActions { get; init; } = Array.Empty<string>();

    /// <summary>Kind 为 Command 时的可执行文件名（必须在命令白名单内）。</summary>
    public string? Command { get; init; }

    public string? CommandArgs { get; init; }

    /// <summary>RegistryValue / RegistryKey 类条目的目标。</summary>
    public RegistryTarget? Registry { get; init; }

    /// <summary>Service 类条目的服务名。</summary>
    public string? ServiceName { get; init; }

    /// <summary>ScheduledTask 类条目的任务路径（如 \Vendor\Task）。</summary>
    public string? TaskPath { get; init; }

    /// <summary>
    /// 注册表类条目扫描时的内容快照（<see cref="RegistryCleaning.RegistrySnapshot"/>），与目录条目的指纹对应：
    /// 删除前重新计算并比对，目标在扫描后被改写（例如软件已重新安装）就拒绝删除。为 null 表示不核对。
    /// </summary>
    public string? TargetSnapshot { get; init; }

    /// <summary>由规则库产生的条目所属的规则 ID（提权服务按规则 ID + 条目 ID 重新扫描并执行）。</summary>
    public string? RuleId { get; init; }

    /// <summary>
    /// 注册表类条目的删除依据：扫描时判定"已不存在"的程序 / 文件路径。删除前重新探测，它重新出现（软件已重装、修复）就拒绝删除。
    /// </summary>
    public string? MissingPath { get; init; }

    /// <summary>
    /// 文件类条目的内容快照：Directory 用逐文件指纹，FileSet 用文件列表（路径、大小、修改时间）的哈希。
    /// 提权服务按此核对它重新扫描到的条目与用户确认时一致，扫描后新增或变化的文件不会被带走。
    /// </summary>
    public string? ContentSnapshot()
    {
        switch (Kind)
        {
            case ItemKind.Directory:
                return DirectoryFingerprint;
            case ItemKind.FileSet:
            {
                if (Files.Count == 0) return null;
                var sb = new System.Text.StringBuilder();
                foreach (var f in Files.OrderBy(f => f.Path, StringComparer.OrdinalIgnoreCase))
                    sb.Append(f.Path.ToLowerInvariant()).Append('\u001f').Append(f.Size).Append('\u001f').Append(f.LastWriteUtc.Ticks).Append('\n');
                return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(sb.ToString())));
            }
            default:
                return null;
        }
    }

    public bool DefaultSelected => Risk == RiskLevel.Safe;

    /// <summary>不经隔离区、靠备份撤销的条目类型。</summary>
    public bool IsRegistryLike => Kind is ItemKind.RegistryValue or ItemKind.RegistryKey or ItemKind.Service or ItemKind.ScheduledTask;
}

/// <summary>扫描进度。</summary>
public sealed record ScanProgress(string ModuleId, string? CurrentPath, int ItemsFound, long BytesFound);
