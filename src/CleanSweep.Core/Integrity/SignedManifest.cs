using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CleanSweep.Core.Safety;

namespace CleanSweep.Core.Integrity;

/// <summary>manifest.json 的内容：数据集类型、版本、生成时间、每个文件的 SHA-256，以及对前四项的 ECDSA P-256 签名。</summary>
public sealed class ManifestDto
{
    [JsonPropertyName("kind")] public string? Kind { get; set; }
    [JsonPropertyName("version")] public int Version { get; set; }
    [JsonPropertyName("generated")] public string? Generated { get; set; }
    [JsonPropertyName("files")] public SortedDictionary<string, string>? Files { get; set; }
    [JsonPropertyName("keyId")] public string? KeyId { get; set; }
    [JsonPropertyName("signature")] public string? Signature { get; set; }
}

/// <summary>校验通过的文件：路径与校验时读到的内容。加载器只用这份内容，不再按路径重读（校验与读取之间没有可被替换的窗口）。</summary>
public sealed record VerifiedFile(string Path, string Content);

public sealed record ManifestVerdict(bool Ok, string? Reason, string Kind, int Version, IReadOnlyList<VerifiedFile> Contents, string? KeyId)
{
    public static ManifestVerdict Fail(string kind, string reason) => new(false, reason, kind, 0, Array.Empty<VerifiedFile>(), null);

    /// <summary>校验通过的文件路径。</summary>
    public IReadOnlyList<string> Files => Contents.Select(c => c.Path).ToList();
}

/// <summary>
/// 规则库、指纹库、弹窗规则的签名清单（设计文档 6.2 第 4 条）。加载器只加载清单里列出、哈希一致、且清单签名能用内置公钥验证的文件：
/// 目录里多出来的文件不加载，改过的文件整个数据集拒绝。文件名只允许清单目录内的相对名（不含目录分隔符与 ..）。
/// </summary>
public static class SignedManifest
{
    public const string FileName = "manifest.json";

    /// <summary>被签名的字节：固定格式的文本，与 JSON 的空白 / 顺序无关。</summary>
    public static byte[] Canonical(string kind, int version, string generated, IReadOnlyDictionary<string, string> files)
    {
        var sb = new StringBuilder();
        sb.Append("cleansweep-manifest/1\n");
        sb.Append("kind:").Append(kind).Append('\n');
        sb.Append("version:").Append(version).Append('\n');
        sb.Append("generated:").Append(generated).Append('\n');
        foreach (var (name, hash) in files.OrderBy(kv => kv.Key, StringComparer.Ordinal))
            sb.Append("file:").Append(name).Append(':').Append(hash.ToLowerInvariant()).Append('\n');
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    /// <summary>对目录下全部 *.json（manifest.json 除外）生成并写入签名清单。</summary>
    public static ManifestDto Sign(string directory, string kind, int version, ECDsa privateKey, string keyId, DateTime? nowUtc = null)
    {
        var files = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var file in Directory.EnumerateFiles(directory, "*.json", SearchOption.TopDirectoryOnly))
        {
            var name = Path.GetFileName(file);
            if (name.Equals(FileName, StringComparison.OrdinalIgnoreCase)) continue;
            files[name] = HashFile(file);
        }
        if (files.Count == 0) throw new InvalidOperationException("目录里没有可签名的 .json 文件");
        var generated = (nowUtc ?? DateTime.UtcNow).ToString("yyyy-MM-ddTHH:mm:ssZ");
        var signature = privateKey.SignData(Canonical(kind, version, generated, files), HashAlgorithmName.SHA256);
        var dto = new ManifestDto { Kind = kind, Version = version, Generated = generated, Files = files, KeyId = keyId, Signature = Convert.ToBase64String(signature) };
        File.WriteAllText(Path.Combine(directory, FileName), JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = true }));
        return dto;
    }

    public static ManifestVerdict Verify(string directory, string expectedKind, IReadOnlyDictionary<string, byte[]> trustedKeys)
    {
        var manifestPath = Path.Combine(directory, FileName);
        if (!File.Exists(manifestPath)) return ManifestVerdict.Fail(expectedKind, "缺少签名清单 manifest.json");
        ManifestDto? dto;
        try { dto = JsonSerializer.Deserialize<ManifestDto>(File.ReadAllText(manifestPath)); }
        catch (Exception ex) { return ManifestVerdict.Fail(expectedKind, "签名清单无法解析：" + ex.Message); }
        return Verify(directory, dto, expectedKind, trustedKeys);
    }

    public static ManifestVerdict Verify(string directory, ManifestDto? dto, string expectedKind, IReadOnlyDictionary<string, byte[]> trustedKeys)
        => VerifyContents(directory, dto, expectedKind, trustedKeys, name =>
        {
            var path = Path.Combine(directory, name);
            if (!File.Exists(path)) throw new FileNotFoundException($"清单列出的文件缺失：{name}");
            if (PathGuard.IsReparsePoint(new FileInfo(path).Attributes)) throw new IOException($"文件是重解析点：{name}");
            return File.ReadAllBytes(path);
        });

    /// <summary>目录与内嵌资源共用签名、文件名、哈希验证；加载器使用验签时的同一份字节。</summary>
    internal static ManifestVerdict VerifyContents(string directory, ManifestDto? dto, string expectedKind,
        IReadOnlyDictionary<string, byte[]> trustedKeys, Func<string, byte[]> readFile)
    {
        if (dto is null) return ManifestVerdict.Fail(expectedKind, "签名清单为空");
        if (!string.Equals(dto.Kind, expectedKind, StringComparison.Ordinal)) return ManifestVerdict.Fail(expectedKind, $"签名清单类型不符：{dto.Kind}");
        if (dto.Version <= 0) return ManifestVerdict.Fail(expectedKind, "签名清单版本号无效");
        if (string.IsNullOrEmpty(dto.Generated) || dto.Files is null || dto.Files.Count == 0) return ManifestVerdict.Fail(expectedKind, "签名清单不完整");
        if (dto.KeyId is null || !trustedKeys.TryGetValue(dto.KeyId, out var spki)) return ManifestVerdict.Fail(expectedKind, $"签名密钥不受信任：{dto.KeyId ?? "(无)"}");

        var sigError = VerifySignature(dto, spki);
        if (sigError is not null) return ManifestVerdict.Fail(expectedKind, sigError);

        // 读一次、算一次哈希、把同一份内容交给加载器
        var contents = new List<VerifiedFile>();
        foreach (var (name, hash) in dto.Files)
        {
            if (!IsSafeName(name)) return ManifestVerdict.Fail(expectedKind, $"清单里的文件名非法：{name}");
            var path = Path.Combine(directory, name);
            byte[] bytes;
            try { bytes = readFile(name); }
            catch (Exception ex) { return ManifestVerdict.Fail(expectedKind, $"无法读取 {name}：{ex.Message}"); }
            if (!string.Equals(HashBytes(bytes), hash, StringComparison.OrdinalIgnoreCase)) return ManifestVerdict.Fail(expectedKind, $"文件内容与清单不符（已被改动）：{name}");
            contents.Add(new VerifiedFile(path, DecodeUtf8(bytes)));
        }
        return new ManifestVerdict(true, null, dto.Kind!, dto.Version, contents, dto.KeyId);
    }

    /// <summary>只验清单签名（不看文件）。返回 null 表示通过。每次新建 ECDsa 实例，可并发调用。</summary>
    public static string? VerifySignature(ManifestDto dto, byte[] spki)
    {
        if (string.IsNullOrEmpty(dto.Kind) || dto.Version <= 0 || string.IsNullOrEmpty(dto.Generated) || dto.Files is null || dto.Files.Count == 0) return "签名清单不完整";
        byte[] signature;
        try { signature = Convert.FromBase64String(dto.Signature ?? ""); }
        catch { return "签名格式无效"; }
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(spki, out _);
            return key.VerifyData(Canonical(dto.Kind, dto.Version, dto.Generated, dto.Files), signature, HashAlgorithmName.SHA256)
                ? null : "签名验证失败（清单被改动或不是可信来源签发）";
        }
        catch (Exception ex)
        {
            return "签名验证出错：" + ex.Message;
        }
    }

    private static string DecodeUtf8(byte[] bytes) =>
        bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF ? Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3) : Encoding.UTF8.GetString(bytes);

    /// <summary>只接受清单目录内的普通文件名：不含目录分隔符、不是 . / ..、以 .json 结尾。</summary>
    public static bool IsSafeName(string name) =>
        !string.IsNullOrWhiteSpace(name) && name.IndexOfAny(new[] { '\\', '/', ':' }) < 0 && name is not ("." or "..")
        && name.IndexOfAny(Path.GetInvalidFileNameChars()) < 0 && name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
        && !name.Equals(FileName, StringComparison.OrdinalIgnoreCase);

    public static string HashFile(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
    }

    public static string HashBytes(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    /// <summary>校验 SubjectPublicKeyInfo（base64）确实是一把 ECDSA 公钥并返回其字节。</summary>
    public static byte[] PublicKeyFromBase64(string spkiBase64)
    {
        var bytes = Convert.FromBase64String(spkiBase64);
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(bytes, out _);
        return bytes;
    }
}
