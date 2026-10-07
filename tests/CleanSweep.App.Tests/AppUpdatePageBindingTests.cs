using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using CleanSweep.App.Services;
using CleanSweep.App.Views;
using CleanSweep.Core.Integrity;

namespace CleanSweep.App.Tests;

public sealed class AppUpdatePageBindingTests
{
    [Fact]
    public async Task Settings_shows_download_progress_and_cancel_button_interrupts_work()
    {
        var release = new ReleaseInfo(new Version(0, 20, 0), "update.zip", "https://example.com/update.zip", "hash", 10, "notes", "test");
        AppUpdateCoordinator? updates = null;
        SettingsPage? page = null;
        Task? work = null;
        WpfTestHost.Run(() =>
        {
            updates = new AppUpdateCoordinator(_ => Task.FromResult(new AppUpdateCheck(true, release, "")),
                async (_, progress, ct) =>
                {
                    progress.Report((5, 10));
                    await Task.Delay(Timeout.InfiniteTimeSpan, ct);
                    return "unused.zip";
                }, (_, _) => throw new Exception("Unexpected prompt"), _ => null, () => { });
            page = new SettingsPage { DataContext = new UpdatePageContext(updates) };
            ((TabControl)page.FindName("SettingsSections")).SelectedIndex = 2;
            page.Measure(new Size(1400, 1600));
            page.Arrange(new Rect(0, 0, 1400, 1600));
            page.UpdateLayout();
            work = updates.CheckAndPrepareAsync();
            WpfTestHost.Drain();
            var controls = Descendants(page).ToArray();
            var bar = Assert.Single(controls.OfType<ProgressBar>());
            Assert.Equal(50, bar.Value);
            Assert.Equal(Visibility.Visible, ((StackPanel)bar.Parent).Visibility);
            var button = Assert.Single(controls.OfType<Button>(), b => Equals(b.Content, "取消程序更新"));
            Assert.Same(updates.CancelCommand, button.Command);
            Assert.True(button.IsEnabled);
            Assert.Equal(Visibility.Visible, button.Visibility);
            typeof(Button).GetMethod("OnClick", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(button, null);
        });
        await work!.WaitAsync(TimeSpan.FromSeconds(5));
        WpfTestHost.Run(() =>
        {
            WpfTestHost.Drain();
            Assert.False(updates!.IsBusy);
            Assert.Null(updates.ReadyRelease);
            var controls = Descendants(page!).ToArray();
            var bar = Assert.Single(controls.OfType<ProgressBar>());
            Assert.Equal(Visibility.Collapsed, ((StackPanel)bar.Parent).Visibility);
            var button = Assert.Single(controls.OfType<Button>(), b => Equals(b.Content, "取消程序更新"));
            Assert.False(button.IsEnabled);
            Assert.Equal(Visibility.Collapsed, button.Visibility);
        });
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

    public sealed record UpdatePageContext(AppUpdateCoordinator Updates);
}
