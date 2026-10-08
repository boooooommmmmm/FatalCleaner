using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Scanning;

namespace CleanSweep.Core.Residue;

/// <summary>用户指定项目中，由 MSBuild 生成清单确认的旧构建文件。始终逐文件隔离，不移动 bin/obj 整目录。</summary>
public sealed class BuildOutputScanner(IReadOnlyList<string> projectRoots) : IScanner
{
    public const string ModuleId = "build-output";
    public string Id => ModuleId;
    public string DisplayName => ".NET 项目构建产物";
    public string? Note { get; private set; }
    private readonly string[] _roots = projectRoots.ToArray();
    internal Func<BuildActivity> ReadActivity { get; init; } = BuildActivity.Read;
    private static readonly HashSet<string> SkipDirectories = new(StringComparer.OrdinalIgnoreCase)
        { "bin", "obj", "node_modules", "packages", "publish", "artifacts" };

    public Task<IReadOnlyList<ScanItem>> ScanAsync(ScanContext ctx, IProgress<ScanProgress>? progress, CancellationToken ct) =>
        Task.Run<IReadOnlyList<ScanItem>>(() =>
        {
            ct.ThrowIfCancellationRequested();
            Note = null;
            if (_roots.Length == 0)
            {
                Note = "如需查找 .NET 构建产物，请先在设置中添加项目根目录。";
                return [];
            }
            var activity = ReadActivity();
            if (activity.BuildHostRunning)
            {
                Note = "本次已跳过 .NET 构建产物：检测到 dotnet、MSBuild、编译/测试服务或开发环境进程。首版无法可靠区分其所属项目，请结束构建/调试并关闭相关程序后重新扫描。其他开发工具缓存仍正常扫描。";
                return [];
            }
            var items = new List<ScanItem>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var root in _roots)
            {
                ct.ThrowIfCancellationRequested();
                if (!CanRead(root, ctx) || !Directory.Exists(root)) continue;
                var pending = new Stack<(string Path, int Depth)>();
                pending.Push((PathGuard.Normalize(root), 0));
                while (pending.TryPop(out var next))
                {
                    ct.ThrowIfCancellationRequested();
                    if (!seen.Add(next.Path) || !CanRead(next.Path, ctx)) continue;
                    progress?.Report(new ScanProgress(Id, next.Path, items.Count, items.Sum(i => i.SizeBytes)));
                    var item = ScanProject(next.Path, ctx, activity, ct);
                    if (item is not null) items.Add(item);
                    if (next.Depth >= 6) continue;
                    foreach (var child in ctx.Guard.EnumerateDirectories(next.Path))
                        if (!child.Name.StartsWith('.') && !SkipDirectories.Contains(child.Name))
                            pending.Push((child.FullName, next.Depth + 1));
                }
            }
            progress?.Report(new ScanProgress(Id, null, items.Count, items.Sum(i => i.SizeBytes)));
            Note = $".NET 构建产物：发现 {items.Count} 个可确认的项目，仅列出至少 24 小时未修改且在生成清单内的文件。无可靠依据、白名单、目录链接和正在运行的项目会跳过。";
            return items;
        }, ct);

    /// <summary>每个项目执行前重新读取当前设置、生成依据和进程；缺失任何依据都保留文件。</summary>
    public Task<bool> StillEligibleAsync(ScanItem item, ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        if (item.ModuleId != Id || item.Kind != ItemKind.FileSet || item.Path is null || item.Files.Count == 0
            || !_roots.Any(r => CanRead(r, ctx) && PathGuard.IsSameOrUnder(item.Path, r))) return false;
        var fresh = ScanProject(item.Path, ctx, ReadActivity(), ct);
        if (fresh is null || fresh.Id != item.Id || fresh.TargetSnapshot != item.TargetSnapshot) return false;
        var files = fresh.Files.ToDictionary(f => f.Path, StringComparer.OrdinalIgnoreCase);
        return item.Files.All(f => files.TryGetValue(f.Path, out var now) && now == f);
    }, ct);

    private ScanItem? ScanProject(string projectDir, ScanContext ctx, BuildActivity activity, CancellationToken ct)
    {
        try
        {
            if (!CanRead(projectDir, ctx) || activity.Blocks(projectDir)) return null;
            // Ambiguous shared output ownership (multiple projects in one directory) is not supported.
            var projects = Directory.GetFiles(projectDir).Where(p =>
                Path.GetExtension(p).ToLowerInvariant() is ".csproj" or ".fsproj" or ".vbproj").ToArray();
            if (projects.Length != 1) return null;
            var project = projects[0];
            var projectText = ReadEvidence(project, ctx, 1024 * 1024);
            using (var xml = XmlReader.Create(new StringReader(projectText), new XmlReaderSettings
                { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1024 * 1024 }))
            {
                xml.MoveToContent();
                if (xml.LocalName != "Project") return null;
                while (xml.Read()) { ct.ThrowIfCancellationRequested(); }
            }

            var obj = Path.Combine(projectDir, "obj");
            var bin = Path.Combine(projectDir, "bin");
            var assetsText = ReadEvidence(Path.Combine(obj, "project.assets.json"), ctx, 16 * 1024 * 1024);
            using var assets = JsonDocument.Parse(assetsText);
            var restore = assets.RootElement.GetProperty("project").GetProperty("restore");
            var recordedProject = restore.GetProperty("projectPath").GetString();
            if (recordedProject is null || !Path.IsPathFullyQualified(recordedProject)
                || !string.Equals(PathGuard.Normalize(recordedProject), project, StringComparison.OrdinalIgnoreCase)) return null;

            var manifests = ctx.Guard.EnumerateFiles(obj, Path.GetFileName(project) + ".FileListAbsolute.txt", true, ct)
                .OrderBy(f => f.Path, StringComparer.OrdinalIgnoreCase).ToArray();
            if (manifests.Length == 0 || manifests.Length > 128) return null;
            var evidence = new StringBuilder(projectText).Append('\0').Append(assetsText);
            var cutoff = DateTime.UtcNow.AddDays(-1);
            var files = new Dictionary<string, FileEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (var manifest in manifests)
            {
                ct.ThrowIfCancellationRequested();
                if (manifest.LastWriteUtc >= cutoff) return null;
                var content = ReadEvidence(manifest.Path, ctx, 2 * 1024 * 1024);
                evidence.Append('\0').Append(manifest.Path).Append('\0').Append(content);
                foreach (var line in content.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    ct.ThrowIfCancellationRequested();
                    // Relative entries are resolved against the project, never the application's working directory.
                    if (line.Contains(':') && !Path.IsPathFullyQualified(line)) continue;
                    var path = Path.GetFullPath(line, projectDir);
                    if ((!Under(path, obj) && !Under(path, bin)) || !GeneratedName(path) || !CanRead(path, ctx)) continue;
                    var info = new FileInfo(path);
                    if (!info.Exists) continue;
                    if (info.LastWriteTimeUtc >= cutoff) return null;
                    files.TryAdd(path, new FileEntry(path, info.Length, info.LastWriteTimeUtc));
                }
            }
            if (files.Count == 0) return null;
            var id = RuleScanner.MakeId(Id, ".net", projectDir);
            if (ctx.Whitelist.IsItemExcluded(id)) return null;
            return new ScanItem
            {
                Id = id, ModuleId = Id, Group = ".NET 项目构建产物", DisplayName = Path.GetFileName(project),
                Path = projectDir, Kind = ItemKind.FileSet, Risk = RiskLevel.Confirm,
                Files = files.Values.OrderBy(f => f.Path, StringComparer.OrdinalIgnoreCase).ToArray(),
                SizeBytes = files.Values.Sum(f => f.Size), LastWriteUtc = files.Values.Max(f => f.LastWriteUtc),
                TargetSnapshot = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(evidence.ToString()))),
                Description = $"{files.Count:N0} 个至少 24 小时未修改、由构建清单确认的 bin/obj 文件。逐文件移入隔离区；保留源码、配置、未识别文件及生成清单。下次编译需重新生成，请先关闭构建、调试和运行中的项目。",
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException
            or JsonException or XmlException or KeyNotFoundException or InvalidOperationException or NotSupportedException)
        {
            return null;
        }
    }

    private static bool Under(string path, string root) => !string.Equals(path, root, StringComparison.OrdinalIgnoreCase)
        && PathGuard.IsSameOrUnder(path, root);

    private static bool CanRead(string path, ScanContext ctx)
    {
        try
        {
            return ctx.Guard.Check(path).Allowed && !ctx.Whitelist.IsPathExcluded(path)
                && ctx.Guard.VerifyPhysical(path).Allowed && !PathGuard.IsCloudPlaceholder(File.GetAttributes(path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        { return false; }
    }

    private static string ReadEvidence(string path, ScanContext ctx, long maxBytes)
    {
        if (!CanRead(path, ctx) || new FileInfo(path).Length > maxBytes) throw new IOException("生成依据不可读取或超过大小限制");
        // Bound the actual read as well: a concurrently growing file must not bypass the metadata limit.
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > maxBytes) throw new IOException("生成依据超过大小限制");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static bool GeneratedName(string path)
    {
        var name = Path.GetFileName(path);
        if (Path.GetExtension(name).ToLowerInvariant() is ".dll" or ".exe" or ".pdb" or ".cache" or ".resources") return true;
        return new[] { ".deps.json", ".runtimeconfig.json", ".g.cs", ".g.i.cs", ".AssemblyInfo.cs", ".AssemblyInfo.fs",
            ".AssemblyInfo.vb", ".AssemblyAttributes.cs", ".GeneratedMSBuildEditorConfig.editorconfig" }
            .Any(suffix => name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase));
    }
}

internal sealed record BuildActivity(bool BuildHostRunning, IReadOnlyList<string> Executables)
{
    public bool Blocks(string project) => BuildHostRunning || Executables.Any(p => PathGuard.IsSameOrUnder(p, project));

    public static BuildActivity Read()
    {
        var active = false;
        var paths = new List<string>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    var name = process.ProcessName;
                    // These hosts can build or run managed outputs without an executable in bin.
                    if (name.Equals("dotnet", StringComparison.OrdinalIgnoreCase)
                        || name.Equals("MSBuild", StringComparison.OrdinalIgnoreCase)
                        || name.Equals("VBCSCompiler", StringComparison.OrdinalIgnoreCase)
                        || name.Equals("devenv", StringComparison.OrdinalIgnoreCase)
                        || name.Equals("rider64", StringComparison.OrdinalIgnoreCase)
                        || name.StartsWith("testhost", StringComparison.OrdinalIgnoreCase)) active = true;
                    if (process.MainModule?.FileName is { } path) paths.Add(path);
                }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
                { /* Unrelated system processes may deny inspection; exclusive file access is also checked when moving. */ }
            }
        }
        return new BuildActivity(active, paths);
    }
}
