using System.Collections.Concurrent;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using CleanSweep.App.Helpers;
using CleanSweep.App.Services;
using CleanSweep.App.Views;
using CleanSweep.Core.Integrity;

namespace CleanSweep.App.Tests;

public sealed class UpdateProgressTests
{
    private static readonly ReleaseInfo Release = new(new Version(0, 23, 0), "update.zip", "https://example.com/update.zip", "hash", 10000, "", "test");

    [Fact]
    public void Burst_posts_one_callback_and_disposal_discards_queued_work()
    {
        var previous = SynchronizationContext.Current;
        var context = new QueuedContext();
        SynchronizationContext.SetSynchronizationContext(context);
        try
        {
            var delivered = new List<int>();
            using (var progress = new CoalescingProgress<int>(delivered.Add))
            {
                Parallel.For(0, 10000, i => progress.Report(i));
                progress.Report(10000);
                Assert.Single(context.Pending);
                context.Drain();
                Assert.Equal([10000], delivered);
            }
            var disposed = new CoalescingProgress<int>(delivered.Add);
            disposed.Report(42);
            disposed.Dispose();
            context.Drain();
            Assert.Equal([10000], delivered);
        }
        finally { SynchronizationContext.SetSynchronizationContext(previous); }
    }

    [Fact]
    public async Task Latest_sample_is_delivered_even_if_the_download_pauses_after_reporting()
    {
        var previous = SynchronizationContext.Current;
        var context = new QueuedContext();
        CoalescingProgress<int> progress;
        var delivered = new List<int>();
        SynchronizationContext.SetSynchronizationContext(context);
        try { progress = new CoalescingProgress<int>(delivered.Add); }
        finally { SynchronizationContext.SetSynchronizationContext(previous); }
        using (progress)
        {
            progress.Report(1);
            context.Drain();
            Assert.Equal([1], delivered);
            progress.Report(2);
            progress.Report(3);
            await context.Enqueued.WaitAsync(TimeSpan.FromSeconds(3)); // First report may leave a signal.
            if (context.Pending.IsEmpty) await context.Enqueued.WaitAsync(TimeSpan.FromSeconds(3));
            context.Drain();
            Assert.Equal([1, 3], delivered);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Progress_does_not_rewrite_sidebar_status_or_overwrite_finished_state(bool cancel)
    {
        Task? work = null;
        AppUpdateCoordinator? updates = null;
        IProgress<(long Done, long Total)>? captured = null;
        var finish = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        WpfTestHost.Run(() =>
        {
            updates = new AppUpdateCoordinator(_ => Task.FromResult(new AppUpdateCheck(true, Release, "")),
                (_, progress, _) => { captured = progress; return finish.Task; },
                (_, _) => Task.FromResult(false), _ => throw new Exception("Unexpected install"), () => { },
                (_, _) => Task.FromResult(true));
            work = updates.CheckAndPrepareAsync();
            var status = updates.Status;
            var changed = new List<string?>();
            updates.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
            for (int i = 1; i <= 5000; i++) captured!.Report((i, 10000));
            WpfTestHost.Drain();
            Assert.Equal(status, updates.Status);
            Assert.DoesNotContain(nameof(AppUpdateCoordinator.Status), changed);
            Assert.Single(changed, n => n == nameof(AppUpdateCoordinator.DownloadPercent));
            Assert.Equal(50, updates.DownloadPercent);
            Assert.Contains("50%", updates.DownloadProgressText);
            if (cancel) updates.CancelCommand.Execute(null);
            finish.SetResult("update.zip");
        });
        await work!.WaitAsync(TimeSpan.FromSeconds(5));
        WpfTestHost.Run(() =>
        {
            var status = updates!.Status;
            captured!.Report((1, 10000));
            WpfTestHost.Drain();
            Assert.Equal(status, updates.Status);
            Assert.False(updates.IsDownloading);
            Assert.False(updates.IsBusy);
            Assert.Equal(cancel, updates.ReadyRelease is null);
        });
    }

    [Fact]
    public void Real_download_area_keeps_its_size_while_indicator_and_numbers_change()
    {
        WpfTestHost.Run(() =>
        {
            var updates = new AppUpdateCoordinator(_ => throw new Exception(), (_, _, _) => throw new Exception(),
                (_, _) => throw new Exception(), _ => null, () => { }) { IsDownloading = true };
            var page = new SettingsPage { DataContext = new AppUpdatePageBindingTests.UpdatePageContext(updates) };
            ((TabControl)page.FindName("SettingsSections")).SelectedIndex = 2;
            Layout(page, 740, 900);
            var bar = Assert.Single(Descendants(page).OfType<ProgressBar>());
            var area = (StackPanel)bar.Parent;
            var height = area.ActualHeight;
            var indicator = (FrameworkElement)bar.Template.FindName("PART_Indicator", bar);
            var width = 0d;
            foreach (var percent in new[] { 1, 9, 10, 50, 99, 100 })
            {
                updates.DownloadPercent = percent;
                updates.DownloadProgressText = $"下载进度：{percent}% · {percent * 1000:N1} / 100000.0 MB";
                Layout(page, 740, 900);
                Assert.Equal(height, area.ActualHeight);
                Assert.Equal(percent, bar.Value);
                Assert.True(indicator.ActualWidth > width);
                Assert.False(indicator.HasAnimatedProperties);
                width = indicator.ActualWidth;
            }
        });
    }

    [Fact]
    public void Real_sidebar_notice_has_stable_height_and_keeps_complete_message_in_tooltip()
    {
        WpfTestHost.Run(() =>
        {
            // Load the real window content without showing a window or creating AppServices.
            var window = new MainWindow();
            var root = (FrameworkElement)window.Content;
            window.Content = null;
            var context = new NoticeContext();
            root.DataContext = context;
            Layout(root, 960, 600);
            var notice = Assert.Single(Descendants(root).OfType<TextBlock>(), t =>
                BindingOperations.GetBinding(t, TextBlock.TextProperty)?.Path.Path == "UpdateNotice");
            foreach (var text in new[] { "正在后台下载 0.23.0…", "正在后台下载… 9.9 / 62.5 MB", "正在后台下载… 1000.1 / 10000.5 MB", new string('测', 150) })
            {
                context.UpdateNotice = text;
                Layout(root, 960, 600);
                Assert.Equal(32, notice.ActualHeight);
                Assert.Equal(text, notice.ToolTip);
            }
        });
    }

    private static void Layout(FrameworkElement page, int width, int height)
    {
        WpfTestHost.Drain();
        page.Measure(new Size(width, height));
        page.Arrange(new Rect(0, 0, width, height));
        page.UpdateLayout();
        WpfTestHost.Drain();
    }
    private static IEnumerable<DependencyObject> Descendants(DependencyObject parent)
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            yield return child;
            foreach (var descendant in Descendants(child)) yield return descendant;
        }
    }
    public sealed class NoticeContext : INotifyPropertyChanged
    {
        private string _notice = "准备下载";
        public string UpdateNotice { get => _notice; set { _notice = value; PropertyChanged?.Invoke(this, new(nameof(UpdateNotice))); } }
        public event PropertyChangedEventHandler? PropertyChanged;
    }
    private sealed class QueuedContext : SynchronizationContext
    {
        public ConcurrentQueue<(SendOrPostCallback Callback, object? State)> Pending { get; } = new();
        public SemaphoreSlim Enqueued { get; } = new(0);
        public override void Post(SendOrPostCallback d, object? state) { Pending.Enqueue((d, state)); Enqueued.Release(); }
        public void Drain() { while (Pending.TryDequeue(out var work)) work.Callback(work.State); }
    }
}
