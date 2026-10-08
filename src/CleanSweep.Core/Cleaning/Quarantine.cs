using System.Text.Json;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Storage;

namespace CleanSweep.Core.Cleaning;

public sealed record QuarantineEntry(
    long Id,
    string BatchId,
    string ModuleId,
    string DisplayName,
    string OriginalPath,
    string QuarantinePath,
    bool IsDirectory,
    long SizeBytes,
    DateTime QuarantinedUtc,
    DateTime ExpiresUtc,
    string? OwnerSid = null);

public sealed class QuarantineOptions
{
    /// <summary>默认保留天数（设计文档 6.1 第 3 条）。</summary>
    public int RetentionDays { get; set; } = 30;

    /// <summary>每卷体积上限：卷容量的百分比。</summary>
    public double MaxVolumeFraction { get; set; } = 0.10;

    /// <summary>每卷体积上限：绝对字节数（20 GB）。取两者较小值。</summary>
    public long MaxBytesAbsolute { get; set; } = 20L * 1024 * 1024 * 1024;
}

/// <summary>
/// 隔离区：所有删除先移入同卷的隐藏目录（重命名，零拷贝），索引在 SQLite。恢复时按原路径放回。过期或超限按时间淘汰。
///
/// 信任边界：SQLite 索引存放在用户可写目录，视为不可信输入。任何删除 / 恢复前都重新推导隔离路径并核对它确实位于
/// 本卷的隔离区批次目录之下，且路径上没有重解析点。移动一律通过 <see cref="HandleMove"/>：先打开对象核对真实路径，
/// 再用同一句柄重命名。每个隔离项旁边写一个元数据文件，索引丢失时可由 <see cref="Reconcile"/> 重建。
/// </summary>
public sealed class Quarantine
{
    public const string MetaSuffix = ".cleansweep-meta.json";

    private readonly CleanSweepDb _db;
    private readonly QuarantineOptions _options;
    private readonly Func<string, string>? _rootOverride;
    private readonly PathGuard? _guard;

    public Quarantine(CleanSweepDb db, QuarantineOptions? options = null, Func<string, string>? quarantineRootResolver = null, PathGuard? guard = null)
    {
        _db = db;
        _options = options ?? new QuarantineOptions();
        _rootOverride = quarantineRootResolver;
        _guard = guard;
    }

    public QuarantineOptions Options => _options;

    /// <summary>返回 path 所在卷的隔离区根目录，例如 C:\$CleanSweep.Quarantine。</summary>
    public string GetQuarantineRoot(string path)
    {
        if (_rootOverride is not null) return PathGuard.Normalize(_rootOverride(path));
        var root = Path.GetPathRoot(PathGuard.Normalize(path))!;
        return Path.Combine(root, AppPaths.QuarantineFolderName);
    }

    private sealed record Meta(
        string OriginalPath, string ModuleId, string BatchId, string DisplayName, bool IsDirectory, long SizeBytes,
        DateTime QuarantinedUtc, DateTime ExpiresUtc, string? OwnerSid = null);

    /// <summary>
    /// 本次移入的隔离项归属的用户 SID。提权服务替某个连接方执行时把它设成连接方的 SID（AsyncLocal，按请求隔离）；
    /// 没有设置时取当前进程用户。恢复 / 删除时服务按此做对象级授权。
    /// </summary>
    public static readonly AsyncLocal<string?> CurrentOwner = new();

    private static readonly Lazy<string?> ProcessUserSid = new(() =>
    {
        try { return System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value; } catch { return null; }
    });

    /// <summary>隔离项的对象标识：原路径 + 隔离路径 + 移入时间的哈希。界面把它随 ID 一起交给服务，服务核对自己索引里的同一条，防止两份索引的数字 ID 撞车。</summary>
    public static string ObjectKey(QuarantineEntry e) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
            e.OriginalPath.ToLowerInvariant() + "\u001f" + e.QuarantinePath.ToLowerInvariant() + "\u001f" + e.QuarantinedUtc.Ticks)));

    // ---------- 移入 ----------

    /// <summary>把文件或目录移入隔离区。同卷内为重命名。失败抛出 IOException / UnauthorizedAccessException。</summary>
    public QuarantineEntry MoveIn(string path, bool isDirectory, long sizeBytes, string moduleId, string batchId, string displayName)
    {
        var full = PathGuard.Normalize(path);
        if (_guard?.IsDeveloperDataProtected(full) == true)
            throw new IOException("开发依赖或运行环境受保护，不允许移入隔离区");
        if (!IsSafeName(batchId)) throw new ArgumentException("批次 ID 非法", nameof(batchId));
        if (!(isDirectory ? Directory.Exists(full) : File.Exists(full)))
            throw new FileNotFoundException("要隔离的对象不存在", full);

        var volumeRoot = Path.GetPathRoot(full)!;
        if (PathGuard.AnyAncestorIsReparsePoint(full, volumeRoot))
            throw new IOException($"源路径经过重解析点，拒绝移动：{full}");

        var root = GetQuarantineRoot(full);
        EnsureTrustedRoot(root);

        var batchDir = Path.Combine(root, batchId);
        Directory.CreateDirectory(batchDir);
        if (PathGuard.IsReparsePoint(batchDir))
            throw new IOException($"隔离区批次目录是重解析点，拒绝使用：{batchDir}");

        var name = $"{Guid.NewGuid():N}_{Path.GetFileName(full)}";
        var dest = Path.Combine(batchDir, name);
        var now = DateTime.UtcNow;
        var expires = now.AddDays(_options.RetentionDays);

        // 1. 先落元数据（原路径等），移动或索引失败时不会丢失"它从哪来"
        var owner = CurrentOwner.Value ?? ProcessUserSid.Value;
        var meta = new Meta(full, moduleId, batchId, displayName, isDirectory, sizeBytes, now, expires, owner);
        WriteMeta(dest, meta);

        // 2. 句柄级移动：核对源与目标目录的真实位置后再重命名
        try
        {
            HandleMove.Move(full, batchDir, name);
        }
        catch
        {
            DeleteMeta(dest);
            throw;
        }

        // 3. 写索引。失败则把对象移回原位，保持文件系统与索引一致
        long id;
        try
        {
            id = Insert(meta, dest);
        }
        catch
        {
            try
            {
                HandleMove.Move(dest, Path.GetDirectoryName(full)!, Path.GetFileName(full));
                DeleteMeta(dest);
            }
            catch
            {
                // 移回失败：元数据仍在，启动时 Reconcile 会重建索引
            }
            throw;
        }

        return new QuarantineEntry(id, batchId, moduleId, displayName, full, dest, isDirectory, sizeBytes, now, expires, owner);
    }

    private long Insert(Meta m, string quarantinePath)
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = """
            INSERT INTO quarantine_items(batch_id, module_id, display_name, original_path, quarantine_path, is_directory, size_bytes, quarantined_at, expires_at, owner_sid)
            VALUES($b, $m, $d, $o, $q, $dir, $s, $t, $e, $w);
            SELECT last_insert_rowid();
            """;
        cmd.Parameters.AddWithValue("$b", m.BatchId);
        cmd.Parameters.AddWithValue("$m", m.ModuleId);
        cmd.Parameters.AddWithValue("$d", m.DisplayName);
        cmd.Parameters.AddWithValue("$o", m.OriginalPath);
        cmd.Parameters.AddWithValue("$q", quarantinePath);
        cmd.Parameters.AddWithValue("$dir", m.IsDirectory ? 1 : 0);
        cmd.Parameters.AddWithValue("$s", m.SizeBytes);
        cmd.Parameters.AddWithValue("$t", m.QuarantinedUtc.ToString("O"));
        cmd.Parameters.AddWithValue("$e", m.ExpiresUtc.ToString("O"));
        cmd.Parameters.AddWithValue("$w", (object?)m.OwnerSid ?? DBNull.Value);
        return (long)cmd.ExecuteScalar()!;
    }

    // ---------- 恢复 ----------

    /// <summary>恢复到原路径。原路径已被占用时追加 ".restored" 后缀。</summary>
    public string Restore(long id)
    {
        var entry = Get(id) ?? throw new InvalidOperationException($"隔离项 {id} 不存在或已处理");
        var bad = ValidateQuarantinePath(entry);
        if (bad is not null) throw new InvalidOperationException(bad);

        // 隔离文件已被外部删除：把索引标记为已清除，避免条目永远残留
        bool sourceExists = entry.IsDirectory ? Directory.Exists(entry.QuarantinePath) : File.Exists(entry.QuarantinePath);
        if (!sourceExists)
        {
            DeleteMeta(entry.QuarantinePath);
            Mark(id, "purged_at");
            throw new FileNotFoundException($"隔离区中的文件已不存在，无法恢复：{entry.QuarantinePath}");
        }

        var target = PathGuard.Normalize(entry.OriginalPath);
        var parent = Path.GetDirectoryName(target) ?? throw new InvalidOperationException("原路径无父目录");

        // 索引里的原路径不可信：必须与移入时写在隔离项旁边的元数据一致，且目标位置本身要通过护栏
        // （Windows、Program Files、用户 hive 与凭据目录等永远不是合法的恢复目标）
        var meta = ReadMeta(entry.QuarantinePath);
        if (meta is null)
            throw new InvalidOperationException($"隔离项缺少元数据，无法核实原路径，拒绝恢复。可手动从隔离区目录取回：{entry.QuarantinePath}");
        if (!string.Equals(PathGuard.Normalize(meta.OriginalPath), target, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"索引记录的原路径（{target}）与隔离项元数据（{meta.OriginalPath}）不一致，拒绝恢复。");
        if (meta.IsDirectory != entry.IsDirectory)
            throw new InvalidOperationException("索引记录的对象类型与隔离项元数据不一致，拒绝恢复。");
        if (_guard is not null)
        {
            var verdict = _guard.CheckRestoreTarget(target);
            if (!verdict.Allowed)
                throw new InvalidOperationException($"恢复目标被护栏拒绝：{verdict.Reason}（{target}）");
        }

        // 原路径的父目录及其祖先在隔离期间被换成 Junction：以管理员身份写到被重定向的位置是提权入口，拒绝。
        // 先检查再创建父目录，否则 CreateDirectory 本身就会穿过链接在目标位置建目录
        var volumeRoot = Path.GetPathRoot(target)!;
        if (PathGuard.AnyAncestorIsReparsePoint(target, volumeRoot))
            throw new IOException($"原路径经过重解析点，拒绝恢复到该位置：{parent}。可手动从隔离区目录取回。");
        Directory.CreateDirectory(parent);
        if (PathGuard.IsReparsePoint(parent) || PathGuard.AnyAncestorIsReparsePoint(target, volumeRoot))
            throw new IOException($"原路径经过重解析点，拒绝恢复到该位置：{parent}。可手动从隔离区目录取回。");

        var name = Path.GetFileName(target);
        if (File.Exists(target) || Directory.Exists(target))
        {
            name = entry.IsDirectory
                ? name + ".restored"
                : Path.GetFileNameWithoutExtension(name) + ".restored" + Path.GetExtension(name);
        }

        HandleMove.Move(entry.QuarantinePath, parent, name);
        DeleteMeta(entry.QuarantinePath);
        Mark(id, "restored_at");
        return Path.Combine(parent, name);
    }

    // ---------- 永久删除 ----------

    /// <summary>永久删除一个隔离项。删除失败抛出异常且记录保留，不会把仍存在的文件标成已清除。</summary>
    public void Purge(long id)
    {
        var entry = Get(id);
        if (entry is null) return;

        var bad = ValidateQuarantinePath(entry);
        if (bad is not null) throw new InvalidOperationException(bad);

        var q = entry.QuarantinePath;
        if (entry.IsDirectory)
        {
            if (Directory.Exists(q)) DeleteTreeSafely(q);
            if (Directory.Exists(q)) throw new IOException($"删除后目录仍然存在：{q}");
        }
        else
        {
            if (File.Exists(q))
            {
                File.SetAttributes(q, FileAttributes.Normal);
                File.Delete(q);
            }
            if (File.Exists(q)) throw new IOException($"删除后文件仍然存在：{q}");
        }

        DeleteMeta(q);
        Mark(id, "purged_at");
    }

    /// <summary>删除过期项。单项失败跳过（保留记录），返回成功删除数。</summary>
    public int PurgeExpired(DateTime? nowUtc = null)
    {
        var now = nowUtc ?? DateTime.UtcNow;
        int purged = 0;
        foreach (var e in ListActive().Where(e => e.ExpiresUtc <= now))
        {
            if (PreserveDeveloperEntry(e)) continue;
            try
            {
                Purge(e.Id);
                purged++;
            }
            catch
            {
                // 被占用或路径校验失败：保留记录，下次再试
            }
        }
        return purged;
    }

    /// <summary>按卷检查体积上限，超出部分按最旧优先淘汰。</summary>
    public int EnforceSizeLimit()
    {
        int purged = 0;
        foreach (var group in ListActive().GroupBy(e => Path.GetPathRoot(e.QuarantinePath), StringComparer.OrdinalIgnoreCase))
        {
            long limit = _options.MaxBytesAbsolute;
            try
            {
                var drive = new DriveInfo(group.Key!);
                limit = Math.Min(limit, (long)(drive.TotalSize * _options.MaxVolumeFraction));
            }
            catch
            {
                // 无法读取卷信息时用绝对上限
            }

            long total = group.Sum(e => e.SizeBytes);
            foreach (var e in group.OrderBy(e => e.QuarantinedUtc))
            {
                if (total <= limit) break;
                if (PreserveDeveloperEntry(e)) continue;
                try
                {
                    Purge(e.Id);
                    total -= e.SizeBytes;
                    purged++;
                }
                catch
                {
                    // 保留记录
                }
            }
        }
        return purged;
    }

    private bool PreserveDeveloperEntry(QuarantineEntry entry) =>
        entry.ModuleId == "dev-cache" || _guard?.IsDeveloperDataProtected(entry.OriginalPath) == true;

    // ---------- 一致性 ----------

    /// <summary>
    /// 核对文件系统与索引：有元数据但索引里没有的隔离项（移动后索引未提交、进程崩溃）重新登记；
    /// 索引里有但文件已不存在的项标记为已清除；元数据孤儿删除。返回重建的条目数。
    /// </summary>
    public int Reconcile(IEnumerable<string>? quarantineRoots = null)
    {
        quarantineRoots ??= SafeDrives().Select(d => Path.Combine(d, AppPaths.QuarantineFolderName));

        var active = ListActive();
        var indexed = new HashSet<string>(active.Select(e => PathGuard.Normalize(e.QuarantinePath)), StringComparer.OrdinalIgnoreCase);

        foreach (var e in active)
        {
            // 所在卷未挂载（移动硬盘拔掉）时不能判定文件已消失，保留记录
            string root;
            try { root = GetQuarantineRoot(e.QuarantinePath); } catch { continue; }
            if (!Directory.Exists(root)) continue;

            bool exists = e.IsDirectory ? Directory.Exists(e.QuarantinePath) : File.Exists(e.QuarantinePath);
            if (!exists)
            {
                try { DeleteMeta(e.QuarantinePath); } catch { }
                Mark(e.Id, "purged_at");
            }
        }

        int recovered = 0;
        foreach (var root in quarantineRoots)
        {
            if (!Directory.Exists(root) || PathGuard.IsReparsePoint(root)) continue;
            IEnumerable<string> batchDirs;
            try { batchDirs = Directory.EnumerateDirectories(root); } catch { continue; }

            foreach (var batchDir in batchDirs)
            {
                if (PathGuard.IsReparsePoint(batchDir)) continue;
                IEnumerable<string> metas;
                try { metas = Directory.EnumerateFiles(batchDir, "*" + MetaSuffix); } catch { continue; }

                foreach (var metaFile in metas)
                {
                    var payload = metaFile[..^MetaSuffix.Length];
                    if (!File.Exists(payload) && !Directory.Exists(payload))
                    {
                        try { File.Delete(metaFile); } catch { }
                        continue;
                    }
                    if (indexed.Contains(PathGuard.Normalize(payload))) continue;

                    Meta? m;
                    try { m = JsonSerializer.Deserialize<Meta>(File.ReadAllText(metaFile)); }
                    catch { m = null; }
                    if (m is null || string.IsNullOrEmpty(m.OriginalPath)) continue;

                    try
                    {
                        Insert(m with { BatchId = Path.GetFileName(batchDir) }, payload);
                        recovered++;
                    }
                    catch
                    {
                        // 下次启动再试
                    }
                }
            }
        }
        return recovered;
    }

    private static IEnumerable<string> SafeDrives()
    {
        DriveInfo[] drives;
        try { drives = DriveInfo.GetDrives(); } catch { yield break; }
        foreach (var d in drives)
        {
            bool ok;
            try { ok = d.DriveType == DriveType.Fixed && d.IsReady; } catch { ok = false; }
            if (ok) yield return d.RootDirectory.FullName;
        }
    }

    // ---------- 校验 ----------

    /// <summary>索引里的隔离路径必须能由"本卷隔离区根 + 批次 + 文件名"重新推导出来，且路径上没有重解析点。</summary>
    internal string? ValidateQuarantinePath(QuarantineEntry e)
    {
        string q;
        try { q = PathGuard.Normalize(e.QuarantinePath); }
        catch (Exception ex) { return $"隔离路径无效：{ex.Message}"; }

        var name = Path.GetFileName(q);
        if (!IsSafeName(e.BatchId) || !IsSafeName(name)) return $"隔离项名称非法：{q}";

        var root = GetQuarantineRoot(q);
        var expected = Path.Combine(root, e.BatchId, name);
        if (!string.Equals(expected, q, StringComparison.OrdinalIgnoreCase))
            return $"隔离路径不在隔离区内，拒绝操作：{q}";

        if (PathGuard.IsReparsePoint(root) || PathGuard.IsReparsePoint(Path.Combine(root, e.BatchId)))
            return $"隔离区目录是重解析点，拒绝操作：{root}";

        return null;
    }

    private static bool IsSafeName(string s) =>
        !string.IsNullOrWhiteSpace(s) && s is not ("." or "..") && s.IndexOfAny(Path.GetInvalidFileNameChars()) < 0;

    /// <summary>
    /// 隔离区根目录必须可信（见 <see cref="ProtectedDirectory"/>）：卷根下新建的目录会继承 C:\ 的默认权限
    /// （Authenticated Users 可修改子目录），隔离区里的内容将来会被恢复到原位置，必须防止其他本地用户篡改。
    /// </summary>
    private static void EnsureTrustedRoot(string dir) => ProtectedDirectory.EnsureTrusted(dir, hidden: true);

    /// <summary>
    /// 递归删除隔离目录，自己遍历而不用 Directory.Delete(recursive)：
    /// 遇到重解析点（Junction / 符号链接）只删链接本身，绝不进入目标；只读属性先清除。
    /// </summary>
    private static void DeleteTreeSafely(string dir)
    {
        if (PathGuard.IsReparsePoint(dir))
        {
            Directory.Delete(dir, recursive: false);
            return;
        }

        var opts = new EnumerationOptions { IgnoreInaccessible = false, AttributesToSkip = 0, ReturnSpecialDirectories = false };
        foreach (var entry in new DirectoryInfo(dir).EnumerateFileSystemInfos("*", opts))
        {
            var attr = entry.Attributes;
            if ((attr & FileAttributes.ReadOnly) != 0)
            {
                try { entry.Attributes = attr & ~FileAttributes.ReadOnly; } catch { }
            }

            if ((attr & FileAttributes.Directory) != 0)
            {
                if (PathGuard.IsReparsePoint(attr)) Directory.Delete(entry.FullName, recursive: false);
                else DeleteTreeSafely(entry.FullName);
            }
            else
            {
                File.Delete(entry.FullName);
            }
        }

        var self = File.GetAttributes(dir);
        if ((self & FileAttributes.ReadOnly) != 0) File.SetAttributes(dir, self & ~FileAttributes.ReadOnly);
        Directory.Delete(dir, recursive: false);
    }

    // ---------- 元数据 ----------

    private static Meta? ReadMeta(string quarantinePath)
    {
        try
        {
            var f = quarantinePath + MetaSuffix;
            if (!File.Exists(f) || PathGuard.IsReparsePoint(f)) return null;
            return JsonSerializer.Deserialize<Meta>(File.ReadAllText(f));
        }
        catch
        {
            return null;
        }
    }

    private static void WriteMeta(string quarantinePath, Meta meta) =>
        File.WriteAllText(quarantinePath + MetaSuffix, JsonSerializer.Serialize(meta));

    private static void DeleteMeta(string quarantinePath)
    {
        var f = quarantinePath + MetaSuffix;
        try { if (File.Exists(f)) File.Delete(f); } catch { }
    }

    // ---------- 索引 ----------

    /// <summary>批量模式：恢复全部 / 清空时共享事务。</summary>
    public IDisposable BeginBulk() => _db.BeginBulk();

    public QuarantineEntry? Get(long id)
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = """
            SELECT id, batch_id, module_id, display_name, original_path, quarantine_path, is_directory, size_bytes, quarantined_at, expires_at, owner_sid
            FROM quarantine_items WHERE id=$id AND restored_at IS NULL AND purged_at IS NULL
            """;
        cmd.Parameters.AddWithValue("$id", id);
        using var r = cmd.ExecuteReader();
        return r.Read() ? ReadEntry(r) : null;
    }

    public IReadOnlyList<QuarantineEntry> ListActive()
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = """
            SELECT id, batch_id, module_id, display_name, original_path, quarantine_path, is_directory, size_bytes, quarantined_at, expires_at, owner_sid
            FROM quarantine_items WHERE restored_at IS NULL AND purged_at IS NULL ORDER BY quarantined_at DESC
            """;
        var list = new List<QuarantineEntry>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(ReadEntry(r));
        return list;
    }

    private static QuarantineEntry ReadEntry(Microsoft.Data.Sqlite.SqliteDataReader r) => new(
        r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4), r.GetString(5),
        r.GetInt64(6) != 0, r.GetInt64(7),
        DateTime.Parse(r.GetString(8), null, System.Globalization.DateTimeStyles.RoundtripKind),
        DateTime.Parse(r.GetString(9), null, System.Globalization.DateTimeStyles.RoundtripKind),
        r.IsDBNull(10) ? null : r.GetString(10));

    public long TotalActiveBytes() => ListActive().Sum(e => e.SizeBytes);

    private void Mark(long id, string column)
    {
        using var lease = _db.Open();
        using var cmd = lease.CreateCommand();
        cmd.CommandText = $"UPDATE quarantine_items SET {column}=$t WHERE id=$id";
        cmd.Parameters.AddWithValue("$t", DateTime.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("$id", id);
        cmd.ExecuteNonQuery();
    }
}
