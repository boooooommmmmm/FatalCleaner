using System.Text.Json;

namespace CleanSweep.Core.Integrity;

/// <summary>单文件内的原始签名数据集。直接在内存中验签，不依赖旁置文件或可写缓存。</summary>
public static class EmbeddedDataSets
{
    public static ManifestVerdict Verify(DataKind kind)
    {
        var name = DataSets.KindName(kind);
        try
        {
            byte[] Read(string file)
            {
                using var stream = typeof(EmbeddedDataSets).Assembly.GetManifestResourceStream($"CleanSweep.Data.{name}.{file}")
                    ?? throw new FileNotFoundException($"内置数据缺失：{name}/{file}");
                using var bytes = new MemoryStream();
                stream.CopyTo(bytes);
                return bytes.ToArray();
            }
            var manifest = JsonSerializer.Deserialize<ManifestDto>(Read(SignedManifest.FileName));
            return SignedManifest.VerifyContents($"内置/{name}", manifest, name, TrustedKeys.Current, Read);
        }
        catch (Exception ex) { return ManifestVerdict.Fail(name, "内置数据无法读取：" + ex.Message); }
    }
}
