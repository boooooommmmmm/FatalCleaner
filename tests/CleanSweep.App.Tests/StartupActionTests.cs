using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using CleanSweep.App.ViewModels;
using CleanSweep.App.Views;
using CleanSweep.Core.Startup;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace CleanSweep.App.Tests;

public sealed class StartupActionTests
{
    [Theory]
    [InlineData(740)]
    [InlineData(1000)]
    public void Disable_is_visible_without_recommendations_and_busy_state_blocks_it(int width) => WpfTestHost.Run(() =>
    {
        var row = Row(true);
        var requests = new List<bool>();
        row.ToggleRequested += (_, enabled) => requests.Add(enabled);
        var model = new Preview(row);
        var page = new StartupPage { DataContext = model };
        Layout(page, width);
        var button = Assert.Single(Descendants(page).OfType<Button>(), b => Equals(b.Content, "禁用"));
        Assert.True(button.IsEnabled);
        var point = button.TransformToAncestor(page).Transform(new Point());
        Assert.True(point.X >= 0 && point.X + button.ActualWidth <= width);
        Assert.True(point.Y >= 0 && point.Y + button.ActualHeight <= 600);
        var list = Assert.Single(Descendants(page).OfType<ListView>());
        Assert.Equal(ScrollBarVisibility.Auto, ScrollViewer.GetHorizontalScrollBarVisibility(list));
        var container = (ListViewItem)list.ItemContainerGenerator.ContainerFromItem(row);
        var enabledBackground = container.Background;
        var disableBackground = button.Background;
        container.IsSelected = true;
        Layout(page, width);
        Assert.Equal(enabledBackground, container.Background);
        Save(page, width);

        Assert.Same(row.ToggleCommand, button.Command);
        Assert.True(button.Command.CanExecute(button.CommandParameter));
        button.Command.Execute(button.CommandParameter);
        Layout(page, width);
        Assert.Equal(new[] { false }, requests);
        Assert.Equal("启用", button.Content);
        Assert.NotEqual(enabledBackground, container.Background);
        Assert.NotEqual(disableBackground, button.Background);
        Assert.Contains(Descendants(page).OfType<TextBlock>(), b => b.Text == "已禁用");
        // Existing operation failure/cancel path restores the display without another request.
        row.SetEnabledSilently(true);
        Layout(page, width);
        Assert.Equal("禁用", button.Content);
        Assert.Equal(enabledBackground, container.Background);
        Assert.Equal(disableBackground, button.Background);
        Assert.Single(requests);
        model.IsBusy = true;
        Layout(page, width);
        Assert.False(button.IsEnabled);
        model.IsBusy = false;
        Layout(page, width);
        Assert.True(button.IsEnabled);
    });

    [Fact]
    public void Restricted_row_keeps_a_visible_disabled_action() => WpfTestHost.Run(() =>
    {
        var row = Row(true, canToggle: false);
        var page = new StartupPage { DataContext = new Preview(row) };
        Layout(page, 740);
        var button = Assert.Single(Descendants(page).OfType<Button>(), b => Equals(b.Content, "禁用"));
        Assert.False(button.IsEnabled);
        Assert.Equal(Visibility.Visible, button.Visibility);
        Assert.Equal("受策略限制", button.ToolTip);
        Assert.True(ToolTipService.GetShowOnDisabled(button));
        row.ToggleCommand.Execute(null);
        Assert.True(row.Enabled);
    });

    [Fact]
    public void Service_action_describes_start_type_and_uses_existing_request_path()
    {
        var row = Row(true, kind: StartupKind.Service);
        var requests = new List<bool>();
        row.ToggleRequested += (_, enabled) => requests.Add(enabled);
        Assert.Equal("改为手动", row.ToggleText);
        row.ToggleCommand.Execute(null);
        Assert.Equal("设为自动", row.ToggleText);
        Assert.Equal(new[] { false }, requests);
        row.SetEnabledSilently(true);
        Assert.Equal("改为手动", row.ToggleText);
        Assert.Single(requests);
    }

    private static StartupRow Row(bool enabled, bool canToggle = true, StartupKind kind = StartupKind.RegistryRun) => new(new StartupItem
    {
        Id = "preview", Kind = kind, Scope = StartupScope.CurrentUser, Name = "示例启动项",
        Location = "测试数据，不访问系统", Handle = new StartupHandle(), Enabled = enabled,
        CanToggle = canToggle, Note = canToggle ? null : "受策略限制", Suggestion = StartupSuggestion.CanDisable
    });

    public sealed class Preview : ObservableObject
    {
        private bool _isBusy;
        public Preview(StartupRow row)
        {
            Rows.Add(row);
            Rows.Add(Row(false));
            Rows.Add(Row(false, kind: StartupKind.Service));
            View = CollectionViewSource.GetDefaultView(Rows);
            View.GroupDescriptions.Add(new PropertyGroupDescription(nameof(StartupRow.KindText)));
        }
        public bool IsBusy { get => _isBusy; set => SetProperty(ref _isBusy, value); }
        public ObservableCollection<StartupRow> Rows { get; } = new();
        public System.ComponentModel.ICollectionView View { get; }
        public ObservableCollection<BootBar> Boots { get; } = new();
        public string BootSummary => "最近一次开机 23.4 秒";
        public string Summary => "3 项，其中 1 项已启用";
        public string Status => "微软自带的服务与计划任务默认隐藏。";
        public int RecommendCount => 0;
        public bool ShowMicrosoft { get; set; }
        public IRelayCommand RefreshCommand { get; } = new RelayCommand(() => { });
        public IRelayCommand DisableRecommendedCommand { get; } = new RelayCommand(() => { });
        public IRelayCommand OpenLocationCommand { get; } = new RelayCommand(() => { });
        public IRelayCommand DelayCommand { get; } = new RelayCommand(() => { });
        public IRelayCommand DeleteCommand { get; } = new RelayCommand(() => { });
    }

    private static void Layout(FrameworkElement page, int width)
    {
        page.Measure(new Size(width, 600));
        page.Arrange(new Rect(0, 0, width, 600));
        page.UpdateLayout();
        WpfTestHost.Drain();
    }

    private static IEnumerable<DependencyObject> Descendants(DependencyObject root)
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            yield return child;
            foreach (var descendant in Descendants(child)) yield return descendant;
        }
    }

    private static void Save(FrameworkElement page, int width)
    {
        var directory = Environment.GetEnvironmentVariable("CLEANSWEEP_UI_ARTIFACTS");
        if (string.IsNullOrEmpty(directory)) return;
        Directory.CreateDirectory(directory);
        var bitmap = new RenderTargetBitmap(width, 600, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(page);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var output = File.Create(Path.Combine(directory, $"startup-{width}.png"));
        encoder.Save(output);
    }
}
