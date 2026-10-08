using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Model;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Scanning;

namespace CleanSweep.Core.Integrity;

public sealed record UpdateCachePreview(IReadOnlyList<ScanItem> Items, string Note);

/// <summary>只检查程序更新下载目录顶层。保留较新版本包、未知文件、暂存目录和恢复数据。</summary>
public sealed class UpdateCacheInventory(string directory, Version current, ScanContext context,
    IReadOnlyDictionary<string, byte[]>? keys = null)
{
    public const string ModuleId = "update-cache";
    private readonly string _root = PathGuard.Normalize(directory);
    private static readonly Regex AssetName = new(@"^(FatalCleaner|CleanSweep)-win-(x64|arm64)-\d+\.\d+\.\d+(\.\d+)?\.zip$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex IndexTemporary = new(@"^prepared-update\.json\.[0-9a-f]{32}\.tmp$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public UpdateCachePreview Preview(string? protectedAsset, CancellationToken ct = default)
    {
        if (!Directory.Exists(_root)) return new([], "没有程序更新缓存。");
        using var lease = UpdateCacheLock.Acquire(_root);
        return Read(protectedAsset, ct);
    }

    public async Task<CleanReport> CleanAsync(IReadOnlyList<ScanItem> selected, string? protectedAsset,
        CleanEngine engine, CancellationToken ct = default)
    {
        using var lease = UpdateCacheLock.Acquire(_root);
        var fresh = Read(protectedAsset, ct).Items.ToDictionary(i => i.Id);
        // Reject the whole request when a displayed row changed, rather than silently substituting new files.
        if (selected.Count == 0 || selected.Any(i => !fresh.TryGetValue(i.Id, out var now)
            || i.ModuleId != ModuleId || i.Kind != ItemKind.FileSet || i.Path != now.Path
            || i.TargetSnapshot != now.TargetSnapshot || i.ContentSnapshot() != now.ContentSnapshot()))
            throw new IOException("更新缓存或待安装记录已变化，请重新预览后选择。");
        return await engine.CleanAsync(selected.Select(i => fresh[i.Id]).DistinctBy(i => i.Id).ToArray(), null, ct).ConfigureAwait(false);
    }

    private UpdateCachePreview Read(string? protectedAsset, CancellationToken ct)
    {
        if (!Allowed(_root)) return new([], "更新缓存路径受保护，未列出清理项。");
        var indexPath = Path.Combine(_root, "prepared-update.json");
        string indexText = "", indexAsset = "";
        if (File.Exists(indexPath))
        {
            try
            {
                indexText = ReadMetadata(indexPath);
                using var json = JsonDocument.Parse(indexText);
                indexAsset = json.RootElement.GetProperty("Asset").GetString() ?? "";
                if (!AssetName.IsMatch(indexAsset) || !json.RootElement.TryGetProperty("Source", out var source)
                    || source.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(source.GetString()))
                    return new([], "待安装更新索引无法确认，已保留全部缓存；请先重新检查更新。");
            }
            catch (Exception ex) when (MetadataError(ex))
            { return new([], "待安装更新索引损坏或不可读取，已保留全部缓存；请先重新检查更新。"); }
        }
        var protectedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (protectedAsset is not null) protectedNames.Add(protectedAsset);
        var obsolete = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in Directory.EnumerateFiles(_root, "*" + AppUpdater.ReleaseInfoSuffix))
        {
            ct.ThrowIfCancellationRequested();
            var asset = Path.GetFileName(path)[..^AppUpdater.ReleaseInfoSuffix.Length];
            if (!AssetName.IsMatch(asset)) continue;
            try
            {
                var text = ReadMetadata(path);
                var release = ReleaseManifest.Verify(JsonSerializer.Deserialize<ReleaseInfoDto>(text), keys ?? TrustedKeys.Current, out _);
                if (release is null || !release.Asset.Equals(asset, StringComparison.OrdinalIgnoreCase)) continue;
                if (ReleaseManifest.IsNewer(release.Version, current)) protectedNames.Add(asset);
                else obsolete[asset] = text;
            }
            catch (Exception ex) when (MetadataError(ex)) { /* Unverifiable packages are retained. */ }
        }
        var indexMissing = indexAsset.Length > 0 && !File.Exists(Path.Combine(_root, indexAsset))
            && !File.Exists(Path.Combine(_root, indexAsset + AppUpdater.ReleaseInfoSuffix))
            && !File.Exists(Path.Combine(_root, indexAsset + ".part"));
        if (indexAsset.Length > 0 && !obsolete.ContainsKey(indexAsset) && !indexMissing) protectedNames.Add(indexAsset);
        var indexExpired = indexAsset.Length > 0 && !protectedNames.Contains(indexAsset)
            && (obsolete.ContainsKey(indexAsset) || indexMissing);
        var cutoff = DateTime.UtcNow.AddDays(-7);
        var items = new List<ScanItem>();
        foreach (var path in Directory.EnumerateFiles(_root))
        {
            ct.ThrowIfCancellationRequested();
            var name = Path.GetFileName(path);
            string? reason = null;
            string basis = indexText;
            if (name.Equals("prepared-update.json", StringComparison.OrdinalIgnoreCase))
            {
                if (indexExpired) { reason = "包已缺失或版本已过期的待安装索引"; basis += obsolete.GetValueOrDefault(indexAsset); }
            }
            else if (IndexTemporary.IsMatch(name)) reason = "异常退出留下的更新索引临时文件";
            else
            {
                var asset = name.EndsWith(".part", StringComparison.OrdinalIgnoreCase) ? name[..^5]
                    : name.EndsWith(AppUpdater.ReleaseInfoSuffix, StringComparison.OrdinalIgnoreCase) ? name[..^AppUpdater.ReleaseInfoSuffix.Length] : name;
                if (!AssetName.IsMatch(asset) || protectedNames.Contains(asset)) continue;
                if (name.EndsWith(".part", StringComparison.OrdinalIgnoreCase)) reason = "超过 7 天的未完成程序下载";
                else if (obsolete.TryGetValue(asset, out var metadata))
                { reason = "签名确认版本不高于当前程序的旧更新文件"; basis += metadata; }
            }
            if (reason is null || !Allowed(path)) continue;
            var fi = new FileInfo(path);
            if (fi.LastWriteTimeUtc >= cutoff) continue;
            var id = RuleScanner.MakeId(ModuleId, name, path);
            if (context.Whitelist.IsItemExcluded(id)) continue;
            items.Add(new ScanItem
            {
                Id = id, ModuleId = ModuleId, Group = "程序更新缓存", DisplayName = name, Path = path,
                Kind = ItemKind.FileSet, Risk = RiskLevel.Confirm, SizeBytes = fi.Length,
                Files = [new FileEntry(path, fi.Length, fi.LastWriteTimeUtc)], LastWriteUtc = fi.LastWriteTimeUtc,
                TargetSnapshot = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(basis))),
                Description = reason + "；移入隔离区后可恢复。",
            });
        }
        return new(items, $"发现 {items.Count} 个超过 7 天的可清理更新文件。保留待安装/较新版本包、未知文件和恢复目录。");
    }

    private bool Allowed(string path) => context.Guard.Check(path).Allowed && !context.Whitelist.IsPathExcluded(path)
        && context.Guard.VerifyPhysical(path).Allowed && !PathGuard.IsCloudPlaceholder(File.GetAttributes(path));

    private string ReadMetadata(string path)
    {
        if (!Allowed(path)) throw new IOException("元数据路径不可读取");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > 1024 * 1024) throw new IOException("元数据超过大小限制");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static bool MetadataError(Exception ex) => ex is IOException or UnauthorizedAccessException
        or JsonException or ArgumentException or InvalidOperationException or KeyNotFoundException;
}
