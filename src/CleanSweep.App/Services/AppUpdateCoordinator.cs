using CleanSweep.App.Helpers;
using CleanSweep.Core.Integrity;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CleanSweep.App.Services;

/// <summary>启动检查与手动更新共用：先下载验签，准备好后才询问安装。</summary>
public sealed partial class AppUpdateCoordinator : ObservableObject
{
    private readonly Func<CancellationToken, Task<AppUpdateCheck>> _check;
    private readonly Func<ReleaseInfo, IProgress<(long Done, long Total)>, CancellationToken, Task<string>> _download;
    private readonly Func<ReleaseInfo, string, Task<bool>> _confirm;
    private readonly Func<string, string?> _launch;
    private readonly Action _shutdown;
    private readonly Func<ReleaseInfo, string, Task<bool>> _validate;
    private readonly Func<CancellationToken, Task<PreparedAppUpdate?>>? _restore;
    private readonly Func<string?> _installBlocker;
    private readonly HashSet<string> _prompted = new();
    private string? _zip;
    private int _generation;
    private CancellationTokenSource? _workCancellation;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanCancel))]
    [NotifyCanExecuteChangedFor(nameof(CancelCommand))]
    private bool _isBusy;
    [ObservableProperty] private bool _isDownloading;
    [ObservableProperty] private double _downloadPercent;
    [ObservableProperty] private string _downloadProgressText = "";
    [ObservableProperty] private string _status = "";
    [ObservableProperty] private ReleaseInfo? _readyRelease;
    public bool InstallationStarted { get; private set; }
    public bool CanCancel => IsBusy && _workCancellation is { IsCancellationRequested: false } && !InstallationStarted;

    /// <summary>缓存预览与清理期间暂停更新检查、恢复和安装，保护内存中的待安装包。</summary>
    public async Task<bool> MaintainCacheAsync(Func<string?, Task> action)
    {
        if (IsBusy || InstallationStarted) return false;
        IsBusy = true;
        try { await action(ReadyRelease?.Asset); return true; }
        finally { IsBusy = false; }
    }

    public AppUpdateCoordinator(Func<CancellationToken, Task<AppUpdateCheck>> check,
        Func<ReleaseInfo, IProgress<(long Done, long Total)>, CancellationToken, Task<string>> download,
        Func<ReleaseInfo, string, Task<bool>> confirm, Func<string, string?> launch, Action shutdown,
        Func<ReleaseInfo, string, Task<bool>>? validate = null,
        Func<CancellationToken, Task<PreparedAppUpdate?>>? restore = null, Func<string?>? installBlocker = null)
    {
        _check = check; _download = download; _confirm = confirm; _launch = launch; _shutdown = shutdown;
        _validate = validate ?? ((release, zip) => Task.Run(() =>
            ReleaseManifest.VerifyPreparedAsset(release, zip) is null));
        _restore = restore;
        _installBlocker = installBlocker ?? (() => null);
    }

    [RelayCommand(CanExecute = nameof(CanCancel))]
    private void Cancel()
    {
        if (!CanCancel) return;
        Status = "正在取消更新操作…";
        _workCancellation!.Cancel();
        OnPropertyChanged(nameof(CanCancel));
        CancelCommand.NotifyCanExecuteChanged();
    }

    /// <summary>只从磁盘恢复经过校验的已下载更新，不联网、不弹安装确认。</summary>
    public async Task RestorePreparedAsync(CancellationToken ct = default)
    {
        if (_restore is null || IsBusy || InstallationStarted || ReadyRelease is not null) return;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _workCancellation = cancellation;
        IsBusy = true;
        var generation = _generation;
        try
        {
            Status = "正在核对已下载更新…";
            var prepared = await _restore(cancellation.Token);
            cancellation.Token.ThrowIfCancellationRequested();
            if (generation != _generation) return;
            if (prepared is null) { Status = ""; return; }
            if (!await _validate(prepared.Release, prepared.Zip))
            {
                if (generation == _generation) Status = "下载包已丢失或校验失败，请重新检查更新。";
                return;
            }
            cancellation.Token.ThrowIfCancellationRequested();
            if (generation != _generation) return;
            _zip = prepared.Zip;
            ReadyRelease = prepared.Release;
            Status = $"已恢复下载的版本 {prepared.Release.Version.ToString(3)}，可在设置中安装。";
        }
        catch (OperationCanceledException) { if (generation == _generation) Status = "更新操作已取消。"; }
        catch (Exception ex) { if (generation == _generation) Status = "恢复已下载更新失败：" + ex.Message; }
        finally { _workCancellation = null; IsBusy = false; }
    }

    public void ResetSource()
    {
        _generation++;
        _workCancellation?.Cancel();
        ReadyRelease = null;
        _zip = null;
        _prompted.Clear();
        Status = "更新来源已改变，请重新检查。";
    }

    public async Task CheckAndPrepareAsync(bool promptAgain = false, CancellationToken ct = default)
    {
        if (IsBusy || InstallationStarted) return;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _workCancellation = cancellation;
        ct = cancellation.Token;
        IsBusy = true;
        var generation = _generation;
        var downloading = false;
        try
        {
            ct.ThrowIfCancellationRequested();
            Status = "正在检查程序更新…";
            var result = await _check(ct);
            ct.ThrowIfCancellationRequested();
            if (generation != _generation) return;
            if (!result.Available || result.Release is not { } release)
            {
                // 没有通过验签的发布信息通常表示网络或来源失败，不能据此撤销已准备好的更新。
                if (result.Release is null && ReadyRelease is not null && _zip is not null)
                {
                    Status = result.Message + "；保留已下载更新，可在设置中安装。";
                    return;
                }
                ReadyRelease = null;
                _zip = null;
                Status = result.Message;
                return;
            }
            var cached = ReadyRelease is { } ready && Identity(ready) == Identity(release) && _zip is not null
                && await _validate(release, _zip);
            ct.ThrowIfCancellationRequested();
            if (generation != _generation) return;
            if (!cached)
            {
                ReadyRelease = null;
                _zip = null;
                Status = $"正在后台下载 {release.Version.ToString(3)}…";
                downloading = true;
                DownloadPercent = 0;
                DownloadProgressText = "下载进度：0%";
                IsDownloading = true;
                using var progress = new CoalescingProgress<(long Done, long Total)>(p =>
                {
                    if (generation == _generation && downloading && !ct.IsCancellationRequested)
                    {
                        DownloadPercent = p.Total > 0 ? Math.Clamp(p.Done * 100.0 / p.Total, 0, 100) : 0;
                        DownloadProgressText = p.Total > 0
                            ? $"下载进度：{DownloadPercent:0}% · {Math.Max(0, p.Done) / 1048576.0:0.#} / {p.Total / 1048576.0:0.#} MB"
                            : $"已下载 {Math.Max(0, p.Done) / 1048576.0:0.#} MB";
                    }
                });
                var zip = await _download(release, progress, ct);
                downloading = false;
                IsDownloading = false;
                DownloadPercent = 100;
                ct.ThrowIfCancellationRequested();
                if (generation != _generation) return;
                _zip = zip;
            }
            ReadyRelease = release;
            Status = $"新版本 {release.Version.ToString(3)} 已下载并校验，可安装。";
            if (promptAgain || !_prompted.Contains(Identity(release))) await ConfirmAndInstallAsync(generation, ct);
        }
        catch (OperationCanceledException) { if (generation == _generation) Status = "更新下载已取消，可重新检查。"; }
        catch (Exception ex) { if (generation == _generation) Status = "更新检查或下载失败：" + ex.Message; }
        finally { downloading = false; IsDownloading = false; _workCancellation = null; IsBusy = false; }
    }

    public async Task InstallPreparedAsync()
    {
        if (IsBusy || InstallationStarted || ReadyRelease is null || _zip is null) return;
        using var cancellation = new CancellationTokenSource();
        _workCancellation = cancellation;
        IsBusy = true;
        var generation = _generation;
        try { await ConfirmAndInstallAsync(generation, cancellation.Token); }
        catch (OperationCanceledException) { if (generation == _generation) Status = "更新操作已取消，可稍后安装。"; }
        catch (Exception ex) { if (generation == _generation) Status = "更新失败：" + ex.Message; }
        finally { _workCancellation = null; IsBusy = false; }
    }

    private async Task ConfirmAndInstallAsync(int generation, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var release = ReadyRelease;
        var zip = _zip;
        if (release is null || zip is null) return;
        // A previously downloaded package may have disappeared or changed while the user deferred.
        var valid = await _validate(release, zip);
        ct.ThrowIfCancellationRequested();
        if (!valid)
        {
            if (generation != _generation) return;
            ReadyRelease = null;
            _zip = null;
            Status = "下载包已丢失或校验失败，请重新检查更新。";
            return;
        }
        if (generation != _generation) return;
        if (InstallationBlocked()) return;
        _prompted.Add(Identity(release));
        var accepted = await _confirm(release, zip);
        ct.ThrowIfCancellationRequested();
        if (generation != _generation) return;
        if (!accepted) { Status = $"新版本 {release.Version.ToString(3)} 已下载，稍后可在设置中安装。"; return; }
        if (InstallationBlocked()) return;
        Status = "正在启动更新安装…";
        var error = _launch(zip);
        if (error is not null) { Status = "安装未开始：" + error; return; }
        InstallationStarted = true;
        _shutdown();
    }

    private bool InstallationBlocked()
    {
        if (_installBlocker() is not { } reason) return false;
        Status = $"更新已下载；{reason}。请等待操作结束后在设置中安装。";
        return true;
    }

    private static string Identity(ReleaseInfo release) => $"{release.Version}|{release.Asset}|{release.Sha256}|{release.Url}";
}
