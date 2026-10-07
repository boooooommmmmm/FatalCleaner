namespace CleanSweep.Core.Integrity;

/// <summary>随程序分发、可在线更新的三个数据集。</summary>
public enum DataKind
{
    Rules,
    Fingerprints,
    Popups,
}

/// <summary>一个数据集当前采用的目录与校验结果。</summary>
public sealed record DataSetLocation(DataKind Kind, string Directory, bool FromUpdate, ManifestVerdict Verdict)
{
    /// <summary>校验通过时可加载的文件路径；未通过为空（什么都不加载）。</summary>
    public IReadOnlyList<string> Files => Verdict.Ok ? Verdict.Files : Array.Empty<string>();

    /// <summary>校验通过时的文件内容（校验时读到的那份字节）；加载器用这份内容而不是重读磁盘。</summary>
    public IReadOnlyList<VerifiedFile> Contents => Verdict.Ok ? Verdict.Contents : Array.Empty<VerifiedFile>();
    public string KindName => DataSets.KindName(Kind);
}

/// <summary>
/// 数据集定位：优先采用已下载且签名校验通过、版本号高于内置版本的更新目录；否则采用内置目录（同样必须通过签名校验）。
/// 任一目录校验失败都不加载其中任何文件。
/// </summary>
public static class DataSets
{
    /// <summary>发布版始终以内嵌签名数据为基线，在线更新只能采用已验签且更高的版本。</summary>
    public static DataSetLocation LocateInstalled(DataKind kind, string? updateDir)
    {
        var bundled = EmbeddedDataSets.Verify(kind);
        if (updateDir is not null && Directory.Exists(updateDir))
        {
            var updated = SignedManifest.Verify(updateDir, KindName(kind), TrustedKeys.Current);
            if (updated.Ok && (!bundled.Ok || updated.Version > bundled.Version))
                return new DataSetLocation(kind, updateDir, true, updated);
        }
        return new DataSetLocation(kind, "程序内置 / " + KindName(kind), false, bundled);
    }

    public static string KindName(DataKind kind) => kind switch
    {
        DataKind.Rules => "rules",
        DataKind.Fingerprints => "fingerprints",
        DataKind.Popups => "popups",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    public static DataSetLocation Locate(DataKind kind, string bundledDir, string? updateDir, IReadOnlyDictionary<string, byte[]>? trustedKeys = null)
    {
        var keys = trustedKeys ?? TrustedKeys.Current;
        var name = KindName(kind);
        var bundled = Directory.Exists(bundledDir) ? SignedManifest.Verify(bundledDir, name, keys) : ManifestVerdict.Fail(name, "内置目录不存在");

        if (updateDir is not null && Directory.Exists(updateDir))
        {
            var updated = SignedManifest.Verify(updateDir, name, keys);
            if (updated.Ok && (!bundled.Ok || updated.Version > bundled.Version))
                return new DataSetLocation(kind, updateDir, true, updated);
        }
        return new DataSetLocation(kind, bundledDir, false, bundled);
    }
}
