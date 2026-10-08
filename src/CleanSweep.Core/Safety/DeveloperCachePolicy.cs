using CleanSweep.Core.Model;

namespace CleanSweep.Core.Safety;

/// <summary>Downloaded dependencies can still be live project inputs. Re-downloadability is not safety.</summary>
public static class DeveloperCachePolicy
{
    public const string Warning = "清理可能影响构建、离线使用或运行环境；请确认工具已退出且不再需要，每次扫描后需重新勾选。";

    public static bool IsDeveloperCache(ScanItem item) =>
        item.RequiresFreshSelection || item.ModuleId == "dev-cache"
        || item.RuleId?.StartsWith("dev.", StringComparison.OrdinalIgnoreCase) == true;

    internal static IEnumerable<string> ProtectedRoots(IReadOnlyDictionary<string, string> vars)
    {
        // Protect both current dependencies and installed tools. Parent-directory cleanup is also blocked.
        (string Variable, string Relative)[] roots =
        [
            ("UserProfile", @".nuget\packages"), ("UserProfile", @".m2\repository"),
            ("UserProfile", @".gradle\caches"), ("UserProfile", @".gradle\wrapper\dists"),
            ("UserProfile", @".gradle\native"), ("UserProfile", @".cargo\registry"),
            ("UserProfile", @".cargo\git"), ("UserProfile", @".cargo\bin"),
            ("UserProfile", @".rustup\toolchains"), ("UserProfile", @"go\pkg\mod"),
            ("UserProfile", @".templateengine\packages"), ("UserProfile", @".dotnet\tools"),
            ("UserProfile", @".dotnet\sdk"), ("UserProfile", @".dotnet\shared"),
            ("UserProfile", @".dotnet\packs"), ("UserProfile", @".bun\install\cache"),
            ("UserProfile", @".pub-cache"), ("UserProfile", @".conda\pkgs"),
            ("UserProfile", @".conda\envs"), ("UserProfile", "anaconda3"), ("UserProfile", "miniconda3"),
            ("LocalAppData", @"pnpm\store"), ("LocalAppData", @"Pub\Cache"),
            ("LocalAppData", @"deno\deps"), ("LocalAppData", @"deno\npm"),
            ("LocalAppData", @"pypoetry\Cache\virtualenvs"), ("LocalAppData", @"uv\cache"),
            ("LocalAppData", @"Cypress\Cache"), ("LocalAppData", "ms-playwright"),
            ("LocalAppData", @"Android\Sdk"), ("LocalAppData", @"Programs\Python"),
            ("AppData", "Python"), ("AppData", "npm"),
        ];
        foreach (var (variable, relative) in roots)
            if (vars.TryGetValue(variable, out var root)) yield return Path.Combine(root, relative);

        foreach (var name in EnvironmentVariables)
        {
            if (!vars.TryGetValue(name, out var value)) continue;
            foreach (var root in name is "GOPATH" or "CONDA_PKGS_DIRS" ? value.Split(';') : [value])
            {
                if (!Path.IsPathFullyQualified(root)) continue;
                string normalized;
                try { normalized = PathGuard.Normalize(root); }
                catch { continue; }
                yield return name == "GOPATH" ? Path.Combine(normalized, "pkg", "mod") : normalized;
            }
        }
    }

    // Used only as extra protection, never as authorization to clean these paths.
    internal static readonly string[] EnvironmentVariables =
        ["NUGET_PACKAGES", "GRADLE_USER_HOME", "CARGO_HOME", "RUSTUP_HOME", "GOPATH", "GOMODCACHE",
         "PUB_CACHE", "DENO_DIR", "PNPM_HOME", "UV_CACHE_DIR", "CONDA_PKGS_DIRS", "CONDA_PREFIX"];
}
