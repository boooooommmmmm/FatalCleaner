using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using CleanSweep.App.Services;
using CleanSweep.App.ViewModels;
using CleanSweep.App.Views;
using CleanSweep.Core.Cleaning;

namespace CleanSweep.App.Tests;

public sealed class UiLayoutTests
{
    [Theory]
    [InlineData(960, 600)]
    [InlineData(1240, 800)]
    public void Shell_and_settings_categories_fit_with_actions_reachable(int width, int height) => WpfTestHost.Run(() =>
    {
        var home = new QuickOptimizeViewModel((_, _, _) => Task.FromResult(new QuickOptimizeResult(
            new CleanReport { FilesQuarantined = 24, QuarantinedBytes = 512L * 1024 * 1024 },
            4L * 1024 * 1024 * 1024, 4L * 1024 * 1024 * 1024, 23.4, "仅测量", 24)));
        var window = new MainWindow();
        Assert.Equal("FatalCleaner · Windows 系统清理", window.Title);
        Assert.NotNull(window.Icon);
        var brandIcon = (Image)window.FindName("BrandIcon");
        Assert.NotNull(brandIcon.Source);
        Assert.True(brandIcon.Source.Width > 0);
        var root = (Grid)window.Content;
        window.Content = null;
        root.Background = (Brush)Application.Current.FindResource("Brush.Background");
        var shell = new ShellPreview(home, home, "一键优化");
        root.DataContext = shell;
        Layout(root, width, height);
        var brand = (TextBlock)window.FindName("BrandName");
        Assert.Equal("FatalCleaner", brand.Text);
        var brandSize = brand.DesiredSize.Width;
        brand.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
        Assert.True(brand.DesiredSize.Width <= brandSize + 1, "Brand caption is clipped");
        Assert.True(brand.TransformToAncestor(root).Transform(new Point()).X + brand.DesiredSize.Width <= 212);
        var action = Assert.Single(Descendants(root).OfType<Button>(), b => Equals(b.Content, "一键优化"));
        Assert.True(action.TransformToAncestor(root).Transform(new Point()).X >= 212);
        Assert.True(action.ActualWidth > 100);
        Save(root, $"home-{width}", width, height);
        home.OptimizeCommand.ExecuteAsync(null).GetAwaiter().GetResult();
        Layout(root, width, height);
        Save(root, $"result-{width}", width, height);

        var settings = new SettingsPage { DataContext = new SettingsPreview() };
        root.DataContext = new ShellPreview(home, settings, "设置");
        var tabs = (TabControl)settings.FindName("SettingsSections");
        Assert.Equal(3, tabs.Items.Count);
        for (var i = 0; i < tabs.Items.Count; i++)
        {
            tabs.SelectedIndex = i;
            Layout(root, width, height);
            var section = (ScrollViewer)((TabItem)tabs.Items[i]).Content;
            Assert.Equal(FontWeights.Normal, section.FontWeight);
            Assert.Equal((Brush)Application.Current.FindResource("Brush.Text"), section.Foreground);
            Assert.True(section.ViewportHeight > 200);
            Assert.Equal(0, section.ScrollableWidth);
            var controls = Descendants(section).OfType<Button>().Where(b => b.Visibility == Visibility.Visible).ToArray();
            Assert.NotEmpty(controls);
            foreach (var button in controls)
            {
                var position = button.TransformToAncestor(section).Transform(new Point());
                Assert.True(position.X >= -1 && position.X + button.ActualWidth <= section.ActualWidth + 1,
                    $"Clipped action: {button.Content} at {position.X}, width {button.ActualWidth}, section {section.ActualWidth}");
            }
            Save(root, $"settings-{i}-{width}", width, height);
        }
    });

    [Fact]
    public void Primary_button_caption_inherits_white_foreground() => WpfTestHost.Run(() =>
    {
        var button = new Button { Content = "开始扫描", Style = (Style)Application.Current.FindResource("Button.Primary") };
        Layout(button, 140, 40);
        var caption = Assert.Single(Descendants(button).OfType<TextBlock>());
        Assert.Equal(Colors.White, ((SolidColorBrush)caption.Foreground).Color);
    });

    [Fact]
    public void Slim_scrollbars_keep_page_commands_and_track_values_connected() => WpfTestHost.Run(() =>
    {
        var viewer = new ScrollViewer { Content = new Border { Width = 2000, Height = 2000 },
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto };
        Layout(viewer, 300, 200);
        var bars = Descendants(viewer).OfType<ScrollBar>().ToArray();
        var vertical = Assert.Single(bars, b => b.Orientation == Orientation.Vertical);
        var horizontal = Assert.Single(bars, b => b.Orientation == Orientation.Horizontal);
        Assert.True(vertical.Maximum > 0 && horizontal.Maximum > 0);
        ScrollBar.PageDownCommand.Execute(null, vertical);
        ScrollBar.PageRightCommand.Execute(null, horizontal);
        Layout(viewer, 300, 200);
        Assert.True(viewer.VerticalOffset > 0 && viewer.HorizontalOffset > 0);
        foreach (var bar in bars)
        {
            var track = (Track)bar.Template.FindName("PART_Track", bar);
            Assert.Equal(bar.Value, track.Value);
            Assert.True(track.Thumb.ActualWidth > 0 && track.Thumb.ActualHeight > 0);
        }
    });

    [Theory]
    [InlineData(740, 560)]
    [InlineData(1000, 760)]
    public void Process_table_and_background_permissions_have_separate_full_width_sections(int width, int height) => WpfTestHost.Run(() =>
    {
        var page = new MemoryPage { DataContext = new MemoryPreview() };
        Layout(page, width, height);
        var tabs = Assert.Single(Descendants(page).OfType<TabControl>());
        Assert.Equal(2, tabs.Items.Count);
        var processes = Assert.Single(Descendants(page).OfType<ListView>());
        Assert.True(processes.ActualWidth > width - 70);
        Assert.Equal(ScrollBarVisibility.Auto, ScrollViewer.GetHorizontalScrollBarVisibility(processes));
        Save(page, $"memory-{width}", width, height);
        tabs.SelectedIndex = 1;
        Layout(page, width, height);
        Assert.Contains(Descendants(page).OfType<CheckBox>(), b => Equals(b.Content, "显示微软应用"));
    });

    public sealed class ShellPreview
    {
        public ShellPreview(QuickOptimizeViewModel home, object page, string title)
        {
            Home = home;
            FeaturedItems = [new NavItem { Title = "一键优化", Glyph = "\uE80F", Page = home, IsSelected = title == "一键优化" }];
            PinnedItems = [new NavItem { Title = "隔离区", Glyph = "\uE7A7", Page = new object() },
                new NavItem { Title = "设置", Glyph = "\uE713", Page = new object(), IsSelected = title == "设置" }];
            Groups = [new NavGroup { Title = "清理", IsExpanded = true }, new NavGroup { Title = "空间", IsExpanded = true },
                new NavGroup { Title = "优化" }, new NavGroup { Title = "管理" }];
            foreach (var name in new[] { "系统清理", "应用缓存", "残留清理", "僵尸目录", "开发者缓存", "注册表清理", "隐私清理" })
                Groups[0].Items.Add(new NavItem { Title = name, Glyph = "\uE74D", Page = new object() });
            foreach (var name in new[] { "空间分析", "重复文件", "文件粉碎" })
                Groups[1].Items.Add(new NavItem { Title = name, Glyph = "\uE8C8", Page = new object() });
            Selected = new NavItem { Title = title, Glyph = "", Page = page };
        }
        public QuickOptimizeViewModel Home { get; }
        public NavItem[] FeaturedItems { get; }
        public NavItem[] PinnedItems { get; }
        public NavGroup[] Groups { get; }
        public NavItem Selected { get; }
        public string Version => "v0.22.0";
        public object Elevation => new { IsElevated = true, StatusText = "以管理员身份运行" };
        public string? UpdateNotice => null;
    }

    public sealed class SettingsPreview
    {
        public bool AdvancedMode { get; set; }
        public int RetentionDays { get; set; } = 30;
        public bool WatchUninstalls { get; set; } = true;
        public bool ResidueScanAllUsers { get; set; }
        public bool IsElevated => true;
        public bool CreateRestorePoint { get; set; } = true;
        public bool CheckUpdatesOnStartup { get; set; } = true;
        public string WatchStatus => "卸载完成后提醒预览残留，确认后再清理。";
        public string RestorePointStatus => "操作前尝试创建系统还原点";
        public string BackupSummary => "暂无注册表备份";
        public string RulesSummary => "75 条清理规则";
        public string DataSetSummary => "规则库、软件指纹与弹窗规则已加载";
        public string AppVersionText => "当前版本 0.22.0";
        public string UpdateSource { get; set; } = "boooooommmmmm/FatalCleaner";
        public string DataDir => @"C:\Users\示例用户\.cleansweep";
        public string[] DevProjectRoots => [];
        public string[] WhitelistPaths => [];
        public string[] WhitelistItems => [];
        public string[] RegistryBackups => [];
        public string[] TaskBackups => [];
        public string[] RecentBatches => [];
        public string[] RejectedRules => [];
        public object Updates => new { IsDownloading = false, IsBusy = false };
    }

    public sealed class MemoryPreview
    {
        public string MemoryText => "已用 12.0 GB / 总计 32.0 GB";
        public string StandbyText => "待机缓存 4.2 GB · 可用内存 20.0 GB";
        public int UsedPercent => 38;
        public bool IsBusy => false;
        public object[] Processes => [new { Name = "示例应用", Pid = 1024, MemoryText = "256 MB", CpuText = "0.2%", Publisher = "示例发布者", CanKill = false }];
        public object[] BackgroundApps => [];
        public bool ShowMicrosoftBackground { get; set; }
    }

    private static void Layout(FrameworkElement element, int width, int height)
    {
        element.Measure(new Size(width, height));
        element.Arrange(new Rect(0, 0, width, height));
        element.UpdateLayout();
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

    private static void Save(Visual view, string name, int width, int height)
    {
        var dir = Environment.GetEnvironmentVariable("CLEANSWEEP_UI_ARTIFACTS");
        if (string.IsNullOrWhiteSpace(dir)) return;
        Directory.CreateDirectory(dir);
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(view);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var file = File.Create(Path.Combine(dir, name + ".png"));
        encoder.Save(file);
    }
}
