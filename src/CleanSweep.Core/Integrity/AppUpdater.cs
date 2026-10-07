using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text.Json;
using CleanSweep.Core.Safety;

namespace CleanSweep.Core.Integrity;

/// <summary>更新来源：一个 GitHub 仓库（owner/name[@branch]）或任意 https 根地址。规则库与程序发布信息都从这里取。</summary>
/// <summary>
/// 更新来源解析结果。GitHub 仓库形式带一个备用根（jsDelivr 的 GitHub 镜像）：raw.githubusercontent.com 在部分网络里连不上，
/// 主地址网络失败时用备用地址再试一次。镜像只是搬运，签名清单与发布信息的校验不变，所以不降低信任要求。
/// </summary>
public sealed record UpdateSources(string DataBaseUrl, string ReleaseInfoUrl, string Display, string? FallbackDataBaseUrl = null, string? FallbackReleaseInfoUrl = null)
{
    /// <summary>官方仓库：设置为空时用它，用户可改成自己的仓库或 https 根地址。</summary>
    public const string Default = "boooooommmmmm/FatalCleaner";
    public const string LegacyDefault = "boooooommmmmm/Cleaner";

    public const string ReleaseInfoPath = "/release/latest.json";

    /// <summary>
    /// "owner/repo" 或 "owner/repo@branch" → raw.githubusercontent.com（备用 cdn.jsdelivr.net/gh）；以 http(s):// 开头 → 直接当根地址，无备用。
    /// 返回 null 表示格式无效；空字符串按 <see cref="Default"/> 处理。
    /// </summary>
    public static UpdateSources? Resolve(string? setting)
    {
        var s = (setting ?? "").Trim().TrimEnd('/');
        if (s.Length == 0) s = Default;
        if (s.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || s.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (DataUpdater.ValidateBaseUrl(s) is not null) return null;
            return new UpdateSources(s, s + ReleaseInfoPath, s);
        }
        var branch = "main";
        var at = s.IndexOf('@');
        if (at > 0) { branch = s[(at + 1)..]; s = s[..at]; }
        // Saved official repository settings predate the GitHub rename; retain any explicit branch.
        if (s.Equals(LegacyDefault, StringComparison.OrdinalIgnoreCase)) s = Default;
        var parts = s.Split('/');
        if (parts.Length != 2 || parts.Any(p => p.Length == 0 || p.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_' or '.')))) return null;
        if (branch.Length == 0 || branch.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_' or '.' or '/'))) return null;
        var root = $"https://raw.githubusercontent.com/{parts[0]}/{parts[1]}/{branch}";
        var mirror = $"https://cdn.jsdelivr.net/gh/{parts[0]}/{parts[1]}@{branch}";
        return new UpdateSources(root, root + ReleaseInfoPath, $"github.com/{parts[0]}/{parts[1]}@{branch}", mirror, mirror + ReleaseInfoPath);
    }

    /// <summary>检查 / 下载清单阶段的失败是否属于"连不上主地址"这一类（值得换备用地址再试），而不是内容无效。</summary>
    public static bool IsNetworkFailure(string message) =>
        message.StartsWith("获取发布信息失败", StringComparison.Ordinal)
        || message.StartsWith("获取发布信息超时", StringComparison.Ordinal)
        || message.StartsWith("下载清单失败", StringComparison.Ordinal)
        || message.StartsWith("更新超时", StringComparison.Ordinal);
}

public sealed record AppUpdateCheck(bool Available, ReleaseInfo? Release, string Message);

/// <summary>更新时需要协调的提权服务（服务进程占用着安装目录里的文件）。可替换为测试桩。</summary>
public interface IUpdateServiceControl
{
    bool IsInstalled { get; }
    bool IsRunning { get; }
    void Stop(TimeSpan timeout);
    void Start(TimeSpan timeout);
}

/// <summary>真实的 CleanSweepElevation 服务控制。停止 / 启动需要管理员权限。</summary>
public sealed class ElevationServiceControl : IUpdateServiceControl
{
    public const string ServiceName = "CleanSweepElevation";

    public static bool Exists()
    {
        try { return ServiceController.GetServices().Any(s => string.Equals(s.ServiceName, ServiceName, StringComparison.OrdinalIgnoreCase)); }
        catch { return false; }
    }

    public bool IsInstalled => Exists();

    public bool IsRunning
    {
        get
        {
            try { using var sc = new ServiceController(ServiceName); return sc.Status != ServiceControllerStatus.Stopped; }
            catch { return false; }
        }
    }

    public void Stop(TimeSpan timeout)
    {
        using var sc = new ServiceController(ServiceName);
        if (sc.Status == ServiceControllerStatus.Stopped) return;
        if (sc.Status != ServiceControllerStatus.StopPending) sc.Stop();
        sc.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
    }

    public void Start(TimeSpan timeout)
    {
        using var sc = new ServiceController(ServiceName);
        if (sc.Status == ServiceControllerStatus.Running) return;
        if (sc.Status != ServiceControllerStatus.StartPending) sc.Start();
        sc.WaitForStatus(ServiceControllerStatus.Running, timeout);
    }
}

/// <summary>
/// 程序自更新。三个阶段：
/// <list type="number">
/// <item>界面：取签名的发布信息 → 版本更高才下载压缩包到数据目录 → 流式核对 SHA-256 与大小 → 把发布信息存在压缩包旁 → 关闭自己，
/// 用<b>安装目录里的</b> CleanSweep.exe 执行 <c>--apply-update &lt;zip&gt; &lt;界面 pid&gt;</c>（安装目录不可写或装了提权服务时以管理员身份）。</item>
/// <item>安装目录里的旧程序（可信位置）：以独占写的方式打开压缩包，再次校验发布信息签名、版本只升、大小与哈希，解压到安装目录下的
/// <c>.update-stage</c>（普通用户不可写），校验其中数据集的签名，然后启动那里的新 CleanSweep.exe 执行
/// <c>--apply-update-run &lt;安装目录&gt; &lt;界面 pid&gt; &lt;本进程 pid&gt;</c>。任何一步失败都不动现有安装。</item>
/// <item>新程序（从 .update-stage 运行）：等两个旧进程退出、停提权服务，把旧版本拥有的文件（安装清单 install-files.txt 列出的 + 与新包重名的）
/// 改名到 <c>.update-backup</c>，再把新文件复制进来；任何失败按原样搬回。全程不跟随重解析点：目录枚举跳过 Junction / 符号链接，
/// 写入路径上的每一级都不能是重解析点，不在清单里的文件不动。成功后重写安装清单、恢复服务、启动新版本。</item>
/// </list>
/// </summary>
public sealed class AppUpdater
{
    public const string InstallManifestName = "install-files.txt";
    public const string StageDirName = ".update-stage";
    public const string BackupDirName = ".update-backup";
    public const string ReleaseInfoSuffix = ".release.json";
    public const string ExeName = "CleanSweep.exe";
    /// <summary>解压后的总大小上限（自包含发布约 300 MB）。</summary>
    public const long MaxExtractedBytes = 4L * 1024 * 1024 * 1024;

    private readonly HttpClient _http;
    private readonly IReadOnlyDictionary<string, byte[]> _keys;

    public AppUpdater(HttpClient? http = null, IReadOnlyDictionary<string, byte[]>? trustedKeys = null)
    {
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromMinutes(30) };
        if (!_http.DefaultRequestHeaders.Contains("User-Agent")) _http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "CleanSweep-AppUpdater/1");
        _keys = trustedKeys ?? TrustedKeys.Current;
    }

    public static readonly TimeSpan CheckTimeout = TimeSpan.FromMinutes(1);
    public static readonly TimeSpan DownloadTimeout = TimeSpan.FromMinutes(30);

    public async Task<AppUpdateCheck> CheckAsync(string releaseInfoUrl, Version current, CancellationToken outerCt = default)
    {
        using var timeout = new CancellationTokenSource(CheckTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(outerCt, timeout.Token);
        var ct = linked.Token;
        ReleaseInfoDto? dto;
        try
        {
            using var response = await _http.GetAsync(releaseInfoUrl, ct).ConfigureAwait(false);
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound) return new AppUpdateCheck(false, null, "更新来源里还没有发布信息（release/latest.json）");
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            dto = JsonSerializer.Deserialize<ReleaseInfoDto>(json);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !outerCt.IsCancellationRequested)
        {
            return new AppUpdateCheck(false, null, "获取发布信息超时");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return new AppUpdateCheck(false, null, "获取发布信息失败：" + ex.Message);
        }
        var info = ReleaseManifest.Verify(dto, _keys, out var error);
        if (info is null) return new AppUpdateCheck(false, null, "发布信息无效：" + error);
        if (!ReleaseManifest.IsNewer(info.Version, current)) return new AppUpdateCheck(false, info, $"已是最新版本（当前 {current.ToString(3)}，发布 {info.Version.ToString(3)}）");
        return new AppUpdateCheck(true, info, $"有新版本 {info.Version.ToString(3)}（{info.Size / (1024.0 * 1024):0.#} MB）");
    }

    /// <summary>
    /// 下载到 stagingRoot 下的 &lt;asset&gt;，边下边算哈希，大小与哈希都必须与签名的发布信息一致；
    /// 通过后把签名的发布信息原样写到 &lt;asset&gt;.release.json，供安装阶段独立复验。
    /// reuseExisting 为 true 时重新核对磁盘中已有包的长度和哈希，匹配则复用，并重写已验签的发布信息。
    /// </summary>
    public async Task<string> DownloadAsync(ReleaseInfo release, string stagingRoot, IProgress<(long Done, long Total)>? progress = null, CancellationToken outerCt = default,
        bool reuseExisting = false)
    {
        if (release.Source is null) throw new InvalidOperationException("发布信息缺少签名原文，无法交给安装阶段复验");
        using var timeout = new CancellationTokenSource(DownloadTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(outerCt, timeout.Token);
        var ct = linked.Token;
        Directory.CreateDirectory(stagingRoot);
        var target = Path.Combine(stagingRoot, release.Asset);
        if (reuseExisting && await Task.Run(() => ReleaseManifest.VerifyAsset(release, target) is null, ct).ConfigureAwait(false))
        {
            ct.ThrowIfCancellationRequested();
            // Rebuild the sidecar from the newly verified server metadata, never trust a cached sidecar.
            File.WriteAllText(target + ReleaseInfoSuffix, ReleaseManifest.ToJson(release.Source));
            progress?.Report((release.Size, release.Size));
            return target;
        }
        var temp = target + ".part";
        try
        {
            using var response = await _http.GetAsync(release.Url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is { } len && len != release.Size) throw new InvalidDataException($"服务器给出的大小（{len}）与发布信息不符（{release.Size}）");
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long done = 0;
            using (var input = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
            using (var output = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16))
            {
                var buffer = new byte[1 << 16];
                int n;
                while ((n = await input.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
                {
                    done += n;
                    if (done > release.Size) throw new InvalidDataException("下载的数据超过发布信息给出的大小");
                    sha.AppendData(buffer, 0, n);
                    await output.WriteAsync(buffer.AsMemory(0, n), ct).ConfigureAwait(false);
                    progress?.Report((done, release.Size));
                }
            }
            if (done != release.Size) throw new InvalidDataException($"下载不完整：{done} / {release.Size}");
            var hash = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
            if (!string.Equals(hash, release.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("压缩包哈希与签名的发布信息不符");
            File.Move(temp, target, overwrite: true);
            File.WriteAllText(target + ReleaseInfoSuffix, ReleaseManifest.ToJson(release.Source));
            return target;
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
        }
    }

    public static bool IsWritable(string dir)
    {
        try
        {
            var probe = Path.Combine(dir, ".write-probe-" + Guid.NewGuid().ToString("N")[..8]);
            using (new FileStream(probe, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose)) { }
            return true;
        }
        catch
        {
            return false;
        }
    }

    // ---------------------------------------------------------------- 阶段一（界面）：启动安装目录里的程序

    /// <summary>
    /// 用安装目录里的 CleanSweep.exe 执行安装：--apply-update "&lt;zip&gt;" &lt;当前进程 ID&gt;。
    /// 安装目录不可写、或装有提权服务（更新前要停它）时以管理员身份启动。返回 null 表示已启动（调用方应立即退出），否则为失败原因。
    /// 执行者是安装目录里已有的程序而不是下载来的程序：下载与解压都在当前用户可写的目录，那里的内容在验签之后仍可能被替换，不能作为执行对象。
    /// </summary>
    public static string? LaunchApply(string installDir, string zipPath)
    {
        var exe = Path.Combine(installDir, ExeName);
        if (!File.Exists(exe)) return "安装目录里没有 " + ExeName;
        if (!File.Exists(zipPath) || !File.Exists(zipPath + ReleaseInfoSuffix)) return "下载的压缩包或发布信息不存在";
        try
        {
            var psi = new ProcessStartInfo(exe, $"--apply-update \"{zipPath}\" {System.Environment.ProcessId}") { UseShellExecute = true, WorkingDirectory = installDir };
            if (!IsWritable(installDir) || ElevationServiceControl.Exists()) psi.Verb = "runas";
            return Process.Start(psi) is null ? "未能启动更新程序" : null;
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return "已取消提权";
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    // ---------------------------------------------------------------- 阶段二（安装目录里的旧程序）：复验、解压、交给新程序

    /// <summary>
    /// 在安装目录里的旧程序进程中执行：复验并解压到安装目录下的 .update-stage，然后启动那里的新程序做真正的替换。返回 null 表示已交接。
    /// </summary>
    public static string? StageFromInstalledExe(string zipPath, int guiPid, Version current, Action<string>? log = null)
    {
        var installDir = PathGuard.Normalize(AppContext.BaseDirectory);
        var stageDir = Path.Combine(installDir, StageDirName);
        var root = new AppUpdater().VerifyAndExtract(zipPath, stageDir, current, out var error);
        if (root is null) return error;
        log?.Invoke("已解压到 " + root);
        try
        {
            var psi = new ProcessStartInfo(Path.Combine(root, ExeName), $"--apply-update-run \"{installDir}\" {guiPid} {System.Environment.ProcessId}")
            { UseShellExecute = false, WorkingDirectory = root };
            if (Process.Start(psi) is null) return "未能启动新版本的安装程序";
        }
        catch (Exception ex)
        {
            return "启动新版本的安装程序失败：" + ex.Message;
        }
        try { File.Delete(zipPath); File.Delete(zipPath + ReleaseInfoSuffix); } catch { }
        return null;
    }

    /// <summary>
    /// 独立复验并解压：压缩包以拒绝他人写入的方式打开，先哈希后解压用的是同一个流（中途无法被替换）；发布信息签名、版本只升、大小与哈希、
    /// 压缩包条目路径、数据集签名逐项检查。stageDir 会先清空。返回新程序根目录，失败返回 null 并给出原因。
    /// </summary>
    public string? VerifyAndExtract(string zipPath, string stageDir, Version current, out string? error)
    {
        var root = VerifyAndExtractCore(zipPath, stageDir, current, out error);
        // 任何拒绝都不留下暂存内容（包括上次成功解压的旧包），后续阶段只会看到本次通过校验的包
        if (root is null) DeleteTree(stageDir);
        return root;
    }

    private string? VerifyAndExtractCore(string zipPath, string stageDir, Version current, out string? error)
    {
        error = null;
        try
        {
            ReleaseInfoDto? dto;
            try { dto = JsonSerializer.Deserialize<ReleaseInfoDto>(File.ReadAllText(zipPath + ReleaseInfoSuffix)); }
            catch (Exception ex) { error = "读取发布信息失败：" + ex.Message; return null; }
            var info = ReleaseManifest.Verify(dto, _keys, out var verifyError);
            if (info is null) { error = "发布信息无效：" + verifyError; return null; }
            if (!ReleaseManifest.IsNewer(info.Version, current)) { error = $"发布版本 {info.Version.ToString(3)} 不高于当前版本 {current.ToString(3)}，拒绝安装"; return null; }

            using var stream = new FileStream(zipPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16);
            if (stream.Length != info.Size) { error = $"压缩包大小（{stream.Length}）与发布信息不符（{info.Size}）"; return null; }
            var hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            if (!string.Equals(hash, info.Sha256, StringComparison.OrdinalIgnoreCase)) { error = "压缩包哈希与签名的发布信息不符"; return null; }
            stream.Position = 0;

            if (DeleteTree(stageDir) is { } cleanup) { error = "无法清理上次更新的暂存目录：" + cleanup; return null; }
            Directory.CreateDirectory(stageDir);
            using (var zip = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true))
            {
                long total = 0;
                foreach (var entry in zip.Entries)
                {
                    var name = entry.FullName.Replace('\\', '/');
                    if (name.Length == 0 || name.StartsWith('/') || name.Contains("../") || name.Contains("/..") || name == ".." || name.Contains(':')
                        || name.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
                    { error = $"压缩包里的路径非法：{entry.FullName}"; return null; }
                    total += entry.Length;
                    if (total > MaxExtractedBytes) { error = "压缩包解压后过大"; return null; }
                    var dest = Path.GetFullPath(Path.Combine(stageDir, name.Replace('/', '\\')));
                    if (!PathGuard.IsSameOrUnder(dest, stageDir) || string.Equals(dest, stageDir, StringComparison.OrdinalIgnoreCase))
                    { error = $"压缩包里的路径逃出暂存目录：{entry.FullName}"; return null; }
                    if (name.EndsWith('/')) { Directory.CreateDirectory(dest); continue; }
                    Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                    using var input = entry.Open();
                    using var output = new FileStream(dest, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 16);
                    input.CopyTo(output);
                }
            }

            var root = FindAppRoot(stageDir);
            if (root is null) { error = "压缩包里没有 " + ExeName; return null; }
            foreach (var kind in new[] { DataKind.Rules, DataKind.Fingerprints, DataKind.Popups })
            {
                var v = SignedManifest.Verify(Path.Combine(root, DataSets.KindName(kind)), DataSets.KindName(kind), _keys);
                if (!v.Ok) { error = $"新版本的 {DataSets.KindName(kind)} 签名校验失败：{v.Reason}"; return null; }
            }
            return root;
        }
        catch (Exception ex)
        {
            error = "解压失败：" + ex.Message;
            return null;
        }
    }

    /// <summary>压缩包可能带一层顶级目录：找到含 CleanSweep.exe 的目录。</summary>
    public static string? FindAppRoot(string stageDir)
    {
        if (File.Exists(Path.Combine(stageDir, ExeName))) return stageDir;
        foreach (var sub in Directory.EnumerateDirectories(stageDir))
            if (File.Exists(Path.Combine(sub, ExeName)) && !PathGuard.IsReparsePoint(sub)) return sub;
        return null;
    }

    // ---------------------------------------------------------------- 阶段三（.update-stage 里的新程序）：替换安装目录

    /// <summary>
    /// 在新程序进程中执行：等旧界面与阶段二进程退出，替换安装目录，启动安装目录里的新版本。返回 null 表示成功。
    /// </summary>
    public static string? ApplyFromStagedExe(string installDir, int guiPid, int stagerPid, Action<string>? log = null)
    {
        var source = PathGuard.Normalize(AppContext.BaseDirectory);
        installDir = PathGuard.Normalize(installDir);
        if (!PathGuard.IsSameOrUnder(source, Path.Combine(installDir, StageDirName)))
            return "安装程序不是从安装目录的暂存区启动的，拒绝执行";
        foreach (var pid in new[] { guiPid, stagerPid })
        {
            if (pid == System.Environment.ProcessId) continue;
            try
            {
                using var p = Process.GetProcessById(pid);
                if (!p.WaitForExit(60_000)) return $"旧进程 {pid} 在 60 秒内没有退出";
            }
            catch (ArgumentException) { /* 已退出 */ }
        }
        var error = ApplyStaged(source, installDir, new ElevationServiceControl(), log);
        if (error is not null) return error;
        try
        {
            Process.Start(new ProcessStartInfo(Path.Combine(installDir, ExeName), "--updated") { UseShellExecute = true, WorkingDirectory = installDir });
        }
        catch (Exception ex)
        {
            return "已完成替换，但启动新版本失败：" + ex.Message;
        }
        return null;
    }

    /// <summary>
    /// 把 sourceRoot（新版本，位于安装目录的暂存区或任何位置）应用到 installDir。事务式：先把旧版本拥有的文件改名到 .update-backup，
    /// 再复制新文件；任一步失败全部还原。不跟随重解析点；不在安装清单里、也不与新文件重名的文件一律不动。
    /// </summary>
    public static string? ApplyStaged(string sourceRoot, string installDir, IUpdateServiceControl? service, Action<string>? log = null)
    {
        sourceRoot = PathGuard.Normalize(sourceRoot);
        installDir = PathGuard.Normalize(installDir);
        if (string.Equals(sourceRoot, installDir, StringComparison.OrdinalIgnoreCase)) return "新版本目录与安装目录相同";
        if (!File.Exists(Path.Combine(installDir, ExeName))) return $"安装目录里没有 {ExeName}：{installDir}";
        if (!File.Exists(Path.Combine(sourceRoot, ExeName))) return $"新版本目录里没有 {ExeName}：{sourceRoot}";
        if (PathGuard.IsReparsePoint(installDir)) return "安装目录是重解析点";
        if (PathGuard.IsReparsePoint(sourceRoot)) return "新版本目录是重解析点";

        var backupDir = Path.Combine(installDir, BackupDirName);
        if (DeleteTree(backupDir) is { } cleanup) return "无法清理上次更新的备份目录：" + cleanup;

        var newFiles = EnumerateFilesNoReparse(sourceRoot).ToList();
        var newSet = new HashSet<string>(newFiles, StringComparer.OrdinalIgnoreCase);
        var owned = ReadInstallManifest(Path.Combine(installDir, InstallManifestName));
        var existing = EnumerateFilesNoReparse(installDir, StageDirName, BackupDirName).ToList();
        // 首次从没有安装清单的版本升级：安装目录里的文件全部视为旧版本拥有（与安装脚本的整目录复制一致）
        var toBackup = existing.Where(rel => owned is null || owned.Contains(rel) || newSet.Contains(rel)
                                             || string.Equals(rel, InstallManifestName, StringComparison.OrdinalIgnoreCase)).ToList();
        log?.Invoke($"新版本 {newFiles.Count} 个文件；旧版本拥有 {toBackup.Count} 个文件；保留 {existing.Count - toBackup.Count} 个非本程序文件");

        var wasRunning = false;
        if (service is { IsInstalled: true })
        {
            wasRunning = service.IsRunning;
            if (wasRunning)
            {
                try { service.Stop(TimeSpan.FromSeconds(30)); log?.Invoke("已停止提权服务"); }
                catch (Exception ex) { return "无法停止提权服务：" + ex.Message; }
            }
        }

        var moved = new List<string>();
        var placed = new List<string>();
        string? failure = null;
        try
        {
            Directory.CreateDirectory(backupDir);
            foreach (var rel in toBackup)
            {
                var to = Path.Combine(backupDir, rel);
                Directory.CreateDirectory(Path.GetDirectoryName(to)!);
                MoveWithRetry(Path.Combine(installDir, rel), to);
                moved.Add(rel);
            }
            foreach (var rel in newFiles)
            {
                var to = Path.Combine(installDir, rel);
                EnsureDirectoryNoReparse(installDir, Path.GetDirectoryName(to)!);
                if (File.Exists(to) || Directory.Exists(to)) throw new IOException($"目标位置已有对象：{rel}");
                CopyWithRetry(Path.Combine(sourceRoot, rel), to);
                placed.Add(rel);
            }
            WriteInstallManifest(Path.Combine(installDir, InstallManifestName), newFiles);
        }
        catch (Exception ex)
        {
            failure = ex.Message;
        }

        if (failure is not null)
        {
            var problems = new List<string>();
            foreach (var rel in placed)
            {
                try { File.Delete(Path.Combine(installDir, rel)); } catch (Exception ex) { problems.Add($"{rel}: {ex.Message}"); }
            }
            foreach (var rel in moved)
            {
                try { MoveWithRetry(Path.Combine(backupDir, rel), Path.Combine(installDir, rel)); }
                catch (Exception ex) { problems.Add($"{rel}: {ex.Message}"); }
            }
            if (problems.Count == 0) DeleteTree(backupDir);
            if (wasRunning) { try { service!.Start(TimeSpan.FromSeconds(30)); } catch (Exception ex) { problems.Add("重新启动提权服务: " + ex.Message); } }
            return problems.Count == 0
                ? "更新失败，已恢复原文件：" + failure
                : "更新失败：" + failure + "。恢复原文件时又出错（请重新运行安装程序修复）：" + string.Join("；", problems);
        }

        var leftover = DeleteTree(backupDir);
        if (leftover is not null) log?.Invoke("备份目录暂时无法删除（旧进程仍在退出），下次启动时清理：" + leftover);
        if (wasRunning)
        {
            try { service!.Start(TimeSpan.FromSeconds(30)); log?.Invoke("已重新启动提权服务"); }
            catch (Exception ex) { log?.Invoke("重新启动提权服务失败：" + ex.Message); }
        }
        return null;
    }

    /// <summary>新版本启动后清理更新残留（.update-stage / .update-backup）。旧进程可能仍在退出，调用方可重试。</summary>
    public static bool CleanupLeftovers(string installDir)
    {
        var ok = true;
        foreach (var name in new[] { StageDirName, BackupDirName })
        {
            var dir = Path.Combine(installDir, name);
            if (!Directory.Exists(dir)) continue;
            if (DeleteTree(dir) is not null) ok = false;
        }
        return ok;
    }

    // ---------------------------------------------------------------- 工具

    /// <summary>枚举 root 下所有文件（相对路径），不进入任何重解析点目录，也不列出重解析点文件；跳过 root 直接子目录 excludeTopDirs。</summary>
    public static IEnumerable<string> EnumerateFilesNoReparse(string root, params string[] excludeTopDirs)
    {
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
            IgnoreInaccessible = false,
            ReturnSpecialDirectories = false,
        };
        foreach (var file in Directory.EnumerateFiles(root, "*", options))
        {
            var rel = Path.GetRelativePath(root, file);
            var top = rel.Split('\\', 2)[0];
            if (excludeTopDirs.Any(e => string.Equals(e, top, StringComparison.OrdinalIgnoreCase))) continue;
            yield return rel;
        }
    }

    /// <summary>逐级创建 root 之下的目录；路径上任何一级已存在且是重解析点即拒绝。</summary>
    public static void EnsureDirectoryNoReparse(string root, string dir)
    {
        var rel = Path.GetRelativePath(root, dir);
        if (rel == "." || rel.StartsWith("..") || Path.IsPathRooted(rel)) { if (rel != ".") throw new IOException($"目录不在安装目录内：{dir}"); return; }
        var current = root;
        foreach (var seg in rel.Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, seg);
            if (Directory.Exists(current) || File.Exists(current))
            {
                if (PathGuard.IsReparsePoint(current)) throw new IOException($"路径经过重解析点，拒绝写入：{current}");
                if (File.Exists(current)) throw new IOException($"目录位置被同名文件占用：{current}");
            }
            else Directory.CreateDirectory(current);
        }
    }

    public static HashSet<string>? ReadInstallManifest(string path)
    {
        if (!File.Exists(path)) return null;
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in File.ReadAllLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            if (line.Contains("..") || Path.IsPathRooted(line) || line.Contains(':')) continue;
            set.Add(line.Replace('/', '\\'));
        }
        set.Add(InstallManifestName);
        return set;
    }

    public static void WriteInstallManifest(string path, IEnumerable<string> relativeFiles)
    {
        var lines = new List<string> { "# CleanSweep 安装清单：本程序拥有的文件。更新时只替换 / 删除这里列出的文件。" };
        lines.AddRange(relativeFiles.Where(f => !string.Equals(f, InstallManifestName, StringComparison.OrdinalIgnoreCase)).OrderBy(f => f, StringComparer.OrdinalIgnoreCase));
        File.WriteAllLines(path, lines);
    }

    /// <summary>删除目录树；目录本身是重解析点时只删链接不进入。返回 null 表示已不存在，否则为失败原因。</summary>
    public static string? DeleteTree(string dir)
    {
        try
        {
            if (!Directory.Exists(dir)) return null;
            if (PathGuard.IsReparsePoint(dir)) { Directory.Delete(dir, recursive: false); return null; }
            foreach (var sub in Directory.EnumerateDirectories(dir))
            {
                if (PathGuard.IsReparsePoint(sub)) Directory.Delete(sub, recursive: false);
                else if (DeleteTree(sub) is { } e) return e;
            }
            foreach (var f in Directory.EnumerateFiles(dir))
            {
                File.SetAttributes(f, FileAttributes.Normal);
                File.Delete(f);
            }
            Directory.Delete(dir, recursive: false);
            return null;
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    /// <summary>文件被旧进程短暂占用时的重试次数与间隔（测试可调小）。</summary>
    internal static int RetryCount = 40;
    internal static int RetryDelayMs = 250;

    private static void MoveWithRetry(string from, string to)
    {
        Exception? last = null;
        for (int attempt = 0; attempt < RetryCount; attempt++)
        {
            try { File.Move(from, to, overwrite: false); return; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                last = ex;
                Thread.Sleep(RetryDelayMs);
            }
        }
        throw new IOException($"移动 {Path.GetFileName(from)} 失败：{last!.Message}", last);
    }

    private static void CopyWithRetry(string from, string to)
    {
        Exception? last = null;
        for (int attempt = 0; attempt < RetryCount; attempt++)
        {
            try { File.Copy(from, to, overwrite: false); return; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                last = ex;
                Thread.Sleep(RetryDelayMs);
            }
        }
        throw new IOException($"复制 {Path.GetFileName(from)} 失败：{last!.Message}", last);
    }
}
