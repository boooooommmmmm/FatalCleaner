using System.Text.Json;
using CleanSweep.Core.Model;

namespace CleanSweep.App.Services;

/// <summary>
/// 程序设置，JSON 持久化到数据目录的 settings.json。
/// 反序列化结果一律归一化（null 集合补空、数值夹到范围内），合法但异常的 JSON 不能让主界面初始化失败；
/// 保存采用"写临时文件 + 原子替换"，进程中断不会留下半个文件。
/// </summary>
public sealed class AppSettings
{
    private string? _file;

    /// <summary>高级模式：显示"不建议"级项目。</summary>
    public bool AdvancedMode { get; set; }

    /// <summary>隔离区保留天数。</summary>
    public int RetentionDays { get; set; } = 30;

    /// <summary>重复文件查找的默认根目录。</summary>
    public List<string> DuplicateRoots { get; set; } = new();

    /// <summary>重复文件最小体积（MB）。</summary>
    public int DuplicateMinSizeMb { get; set; } = 1;

    /// <summary>修改服务启动类型前创建系统还原点。</summary>
    public bool CreateRestorePoint { get; set; } = true;

    /// <summary>开机加速页显示微软自带的服务与计划任务。</summary>
    public bool ShowMicrosoftStartup { get; set; }

    /// <summary>注册表备份保留天数。</summary>
    public int RegistryBackupRetentionDays { get; set; } = 90;

    /// <summary>残留清理：扫描本机全部用户账户（需要管理员权限）。</summary>
    public bool ResidueScanAllUsers { get; set; }

    /// <summary>卸载后即时残留提醒：程序运行期间监听卸载事件。</summary>
    public bool WatchUninstalls { get; set; }

    /// <summary>开发者缓存页的项目根目录（查找闲置 node_modules 和有生成依据的 .NET 构建产物）。</summary>
    public List<string> DevProjectRoots { get; set; } = new();

    /// <summary>弹窗拦截：程序运行期间按规则关闭弹窗。</summary>
    public bool PopupBlockerEnabled { get; set; }

    /// <summary>
    /// 更新来源：GitHub 仓库 "owner/repo[@branch]" 或 https 根地址。规则库、指纹库、弹窗规则与程序发布信息都从这里取。
    /// 默认是官方仓库（此前默认空，导致装好后从不检查更新）；清空时恢复默认，不想检查更新请关掉"启动时在后台检查更新"。
    /// </summary>
    public string UpdateSource { get; set; } = Core.Integrity.UpdateSources.Default;

    /// <summary>启动时后台检查更新；程序包静默下载并校验后询问是否安装。</summary>
    public bool CheckUpdatesOnStartup { get; set; } = true;

    /// <summary>侧栏分组的展开状态（分组名 → 是否展开）；没记录的分组用默认值。</summary>
    public Dictionary<string, bool> NavGroupExpanded { get; set; } = new();

    /// <summary>当前用户各清理条目的上次选择，连同当时的类型和风险级别。</summary>
    public Dictionary<string, CleaningSelection> CleaningSelections { get; set; } = new();

    private static readonly string SelectionUser = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value
        ?? $"{System.Environment.UserDomainName}\\{System.Environment.UserName}";

    private static string SelectionKey(ScanItem item) => JsonSerializer.Serialize(new[] { SelectionUser, item.ModuleId, item.Id });

    public bool CleaningSelectionFor(ScanItem item)
    {
        if (CleanSweep.Core.Safety.DeveloperCachePolicy.IsDeveloperCache(item)) return false;
        return CleaningSelections.TryGetValue(SelectionKey(item), out var saved) && saved is not null
            && saved.Kind == item.Kind && saved.Risk == item.Risk ? saved.Selected : item.DefaultSelected;
    }

    public void RememberCleaningSelection(ScanItem item, bool selected) =>
        CleaningSelections[SelectionKey(item)] = new CleaningSelection(selected, item.Kind, item.Risk);

    /// <summary>硬件状态页"自动刷新"开关。</summary>
    public bool HardwareAutoRefresh { get; set; }

    public static AppSettings Load(string file)
    {
        AppSettings s = new();
        try
        {
            if (File.Exists(file))
                s = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(file)) ?? new AppSettings();
        }
        catch
        {
            s = new AppSettings();
        }
        s._file = file;
        s.Normalize();
        return s;
    }

    /// <summary>补齐 null 集合、夹紧数值范围。</summary>
    public void Normalize()
    {
        DuplicateRoots = (DuplicateRoots ?? new()).Where(r => !string.IsNullOrWhiteSpace(r)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        UpdateSource = (UpdateSource ?? "").Trim();
        if (UpdateSource.Length == 0 || UpdateSource.Equals(Core.Integrity.UpdateSources.LegacyDefault, StringComparison.OrdinalIgnoreCase))
            UpdateSource = Core.Integrity.UpdateSources.Default;
        NavGroupExpanded ??= new();
        CleaningSelections = (CleaningSelections ?? new()).Where(p => p.Value is not null
            && Enum.IsDefined(p.Value.Kind) && Enum.IsDefined(p.Value.Risk))
            .ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);
        DevProjectRoots = (DevProjectRoots ?? new()).Where(r => !string.IsNullOrWhiteSpace(r)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (RetentionDays is < 1 or > 365) RetentionDays = 30;
        if (DuplicateMinSizeMb is < 0 or > 1_000_000) DuplicateMinSizeMb = 1;
        if (RegistryBackupRetentionDays is < 7 or > 3650) RegistryBackupRetentionDays = 90;
    }

    public void Save()
    {
        if (_file is null) return;
        Normalize();
        Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
        var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
        var temp = _file + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp";
        try
        {
            File.WriteAllText(temp, json);
            File.Move(temp, _file, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
        }
    }
}

public sealed record CleaningSelection(bool Selected, ItemKind Kind, RiskLevel Risk);
