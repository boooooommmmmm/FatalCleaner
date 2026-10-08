using System.Text.RegularExpressions;
using SysEnv = System.Environment;

namespace CleanSweep.Core.Environment;

/// <summary>以当前进程用户为目标的解析器。</summary>
public sealed partial class CurrentUserEnvironmentResolver : IEnvironmentResolver
{
    private readonly Dictionary<string, string> _vars;

    public CurrentUserEnvironmentResolver()
    {
        var windir = SysEnv.GetFolderPath(SysEnv.SpecialFolder.Windows);
        var sysDrive = Path.GetPathRoot(windir)!.TrimEnd('\\');
        var localAppData = SysEnv.GetFolderPath(SysEnv.SpecialFolder.LocalApplicationData);

        _vars = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["LocalAppData"] = localAppData,
            ["AppData"] = SysEnv.GetFolderPath(SysEnv.SpecialFolder.ApplicationData),
            ["LocalAppDataLow"] = Path.Combine(SysEnv.GetFolderPath(SysEnv.SpecialFolder.UserProfile), "AppData", "LocalLow"),
            ["UserProfile"] = SysEnv.GetFolderPath(SysEnv.SpecialFolder.UserProfile),
            ["Temp"] = ResolveTemp(localAppData),
            ["Windir"] = windir,
            ["SystemRoot"] = windir,
            ["SystemDrive"] = sysDrive,
            ["ProgramData"] = SysEnv.GetFolderPath(SysEnv.SpecialFolder.CommonApplicationData),
            ["ProgramFiles"] = SysEnv.GetFolderPath(SysEnv.SpecialFolder.ProgramFiles),
            ["ProgramFilesX86"] = SysEnv.GetFolderPath(SysEnv.SpecialFolder.ProgramFilesX86),
            ["Public"] = SysEnv.GetEnvironmentVariable("PUBLIC") ?? Path.Combine(sysDrive + "\\", "Users", "Public"),
        };
        foreach (var name in Safety.DeveloperCachePolicy.EnvironmentVariables)
            if (SysEnv.GetEnvironmentVariable(name) is { Length: > 0 } value) _vars[name] = value;
    }

    /// <summary>测试用：注入自定义变量表。</summary>
    public CurrentUserEnvironmentResolver(IDictionary<string, string> variables)
    {
        _vars = new Dictionary<string, string>(variables, StringComparer.OrdinalIgnoreCase);
    }

    public IReadOnlyDictionary<string, string> Variables => _vars;

    /// <summary>
    /// TEMP 环境变量可能被用户改到任意位置（甚至 Documents）。只有最后一级目录名是 Temp / Tmp 时才采用，
    /// 否则退回到 %LocalAppData%\Temp。同时把 8.3 短名（ALICES~1）展开为长名，便于删除前的真实路径比对。
    /// </summary>
    internal static string ResolveTemp(string localAppData) => ResolveTemp(localAppData, Path.GetTempPath());

    internal static string ResolveTemp(string localAppData, string rawTempPath)
    {
        var fallback = Path.Combine(localAppData, "Temp");
        try
        {
            var temp = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rawTempPath));
            temp = Safety.PathGuard.ToLongPath(temp);
            var last = Path.GetFileName(temp);
            if (string.IsNullOrEmpty(last)) return fallback;
            if (!last.Equals("Temp", StringComparison.OrdinalIgnoreCase) && !last.Equals("Tmp", StringComparison.OrdinalIgnoreCase))
                return fallback;
            return temp;
        }
        catch
        {
            return fallback;
        }
    }

    [GeneratedRegex("%([A-Za-z0-9_]+)%")]
    private static partial Regex VarPattern();

    public bool TryExpand(string raw, out string expanded, out string? error)
    {
        string? err = null;
        expanded = VarPattern().Replace(raw, m =>
        {
            var name = m.Groups[1].Value;
            if (_vars.TryGetValue(name, out var v)) return v;
            err ??= $"未知环境变量 %{name}%";
            return m.Value;
        });
        error = err;
        return err is null;
    }
}
