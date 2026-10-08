using System.Collections.ObjectModel;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Integrity;
using CleanSweep.Core.Model;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CleanSweep.App.ViewModels;

public sealed partial class UpdateCacheRow(ScanItem item) : ObservableObject
{
    public ScanItem Item { get; } = item;
    public string Name => Item.DisplayName;
    public string Size => Format.Bytes(Item.SizeBytes);
    public string Reason => Item.Description;
    [ObservableProperty] private bool _isSelected;
}

public sealed partial class UpdateCacheViewModel : ObservableObject
{
    private readonly AppUpdateCoordinator _updates;
    private readonly Func<string?, Task<UpdateCachePreview>> _preview;
    private readonly Func<IReadOnlyList<ScanItem>, string?, Task<CleanReport>> _clean;
    private readonly Func<int, long, Task<bool>> _confirm;
    public ObservableCollection<UpdateCacheRow> Rows { get; } = [];
    [ObservableProperty] private string _status = "预览超过 7 天的旧更新包、下载片段和过期索引；清理后可从隔离区恢复。";
    private bool CanPreview => !_updates.IsBusy && !_updates.InstallationStarted;
    private bool CanClean => CanPreview && Rows.Any(r => r.IsSelected);

    public UpdateCacheViewModel(AppUpdateCoordinator updates, Func<string?, Task<UpdateCachePreview>> preview,
        Func<IReadOnlyList<ScanItem>, string?, Task<CleanReport>> clean, Func<int, long, Task<bool>> confirm)
    {
        _updates = updates; _preview = preview; _clean = clean; _confirm = confirm;
        updates.PropertyChanged += (_, _) => RefreshCommands();
    }

    private void RefreshCommands()
    {
        PreviewCommand.NotifyCanExecuteChanged();
        CleanCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand(CanExecute = nameof(CanPreview))]
    private async Task PreviewAsync()
    {
        try
        {
            if (!await _updates.MaintainCacheAsync(async protectedAsset =>
            {
                Rows.Clear();
                Status = "正在检查程序更新缓存…";
                var preview = await _preview(protectedAsset);
                foreach (var item in preview.Items)
                {
                    var row = new UpdateCacheRow(item);
                    row.PropertyChanged += (_, _) => RefreshCommands();
                    Rows.Add(row);
                }
                Status = preview.Note;
            })) Status = "更新操作进行中，请稍后预览。";
        }
        catch (Exception ex) { Status = "无法预览更新缓存：" + ex.Message; }
        finally { RefreshCommands(); }
    }

    [RelayCommand(CanExecute = nameof(CanClean))]
    private async Task CleanAsync()
    {
        var selected = Rows.Where(r => r.IsSelected).Select(r => r.Item).ToArray();
        if (selected.Length == 0) return;
        try
        {
            if (!await _updates.MaintainCacheAsync(async protectedAsset =>
            {
                if (!await _confirm(selected.Length, selected.Sum(i => i.SizeBytes))) return;
                Status = "正在复核并移入隔离区…";
                var report = await _clean(selected, protectedAsset);
                var complete = report.Outcomes.Where(p => p.Value.Complete && !p.Value.Untouched).Select(p => p.Key).ToHashSet();
                foreach (var row in Rows.Where(r => complete.Contains(r.Item.Id)).ToArray()) Rows.Remove(row);
                Status = $"{report.FilesQuarantined} 个文件移入隔离区，{Format.Bytes(report.QuarantinedBytes)}；到期或永久删除后释放空间。";
                if (report.IncompleteItemIds.Count > 0)
                    Status += $" {report.IncompleteItemIds.Count} 项未完成，已保留；请重新预览。";
            })) Status = "更新操作进行中，本次未清理。";
        }
        catch (Exception ex) { Status = "未完成缓存清理：" + ex.Message; }
        finally { RefreshCommands(); }
    }
}
