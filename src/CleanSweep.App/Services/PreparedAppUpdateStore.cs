using System.Text.Json;
using CleanSweep.Core.Integrity;

namespace CleanSweep.App.Services;

public sealed record PreparedAppUpdate(ReleaseInfo Release, string Zip);

/// <summary>保存来源与资产文件名；恢复时重新验签和哈希，索引不携带可执行路径。</summary>
public sealed class PreparedAppUpdateStore(string directory, IReadOnlyDictionary<string, byte[]>? keys = null)
{
    private sealed record Entry(string Source, string Asset);
    private string IndexPath => Path.Combine(directory, "prepared-update.json");

    public void Save(string source, ReleaseInfo release)
    {
        if (release.Asset != Path.GetFileName(release.Asset) || release.Asset.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new InvalidDataException("更新资产文件名无效");
        Directory.CreateDirectory(directory);
        using var cacheLock = UpdateCacheLock.Acquire(directory);
        var temporary = IndexPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporary, JsonSerializer.Serialize(new Entry(source, release.Asset)));
            File.Move(temporary, IndexPath, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public PreparedAppUpdate? Load(string source, Version current)
    {
        try
        {
            if (!Directory.Exists(directory)) return null;
            using var cacheLock = UpdateCacheLock.Acquire(directory);
            var entry = JsonSerializer.Deserialize<Entry>(File.ReadAllText(IndexPath));
            if (entry is null || entry.Source != source || string.IsNullOrWhiteSpace(entry.Asset)
                || entry.Asset != Path.GetFileName(entry.Asset) || entry.Asset.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
                || !entry.Asset.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) return null;
            var zip = Path.Combine(directory, entry.Asset);
            var dto = JsonSerializer.Deserialize<ReleaseInfoDto>(File.ReadAllText(zip + AppUpdater.ReleaseInfoSuffix));
            var release = ReleaseManifest.Verify(dto, keys ?? TrustedKeys.Current, out _);
            if (release is null || !ReleaseManifest.IsNewer(release.Version, current)
                || ReleaseManifest.VerifyPreparedAsset(release, zip, keys) is not null) return null;
            return new PreparedAppUpdate(release, zip);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or ArgumentException)
        {
            return null;
        }
    }
}
