using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using CleanSweep.App.Services;
using CleanSweep.App.ViewModels;
using CleanSweep.App.Views;
using CleanSweep.Core.Cleaning;

namespace CleanSweep.App.Tests;

public sealed class QuickOptimizePresentationTests
{
    private static QuickOptimizeResult Result() => new(new CleanReport { FilesQuarantined = 4, QuarantinedBytes = 4096 },
        8000, 7000, 23, "仅测量", 4);
    private sealed class Clock : TimeProvider
    {
        public TimeSpan Elapsed { get; set; }
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Elapsed.Ticks;
    }

    [Fact]
    public async Task Fast_completion_finishes_the_presentation_before_revealing_real_results()
    {
        var clock = new Clock();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        TimeSpan? requested = null;
        IProgress<QuickOptimizeProgress>? late = null;
        QuickOptimizeViewModel? vm = null;
        Task? work = null;
        WpfTestHost.Run(() =>
        {
            vm = new QuickOptimizeViewModel((_, progress, _) => { late = progress; clock.Elapsed = TimeSpan.FromMilliseconds(200); return Task.FromResult(Result()); },
                minimumPresentation: TimeSpan.FromSeconds(3), animationsEnabled: () => true, clock: clock,
                presentationDelay: (duration, _) => { requested = duration; return gate.Task; });
            work = vm.OptimizeCommand.ExecuteAsync(null);
            Assert.Equal(TimeSpan.FromMilliseconds(2800), requested);
            Assert.True(vm.IsBusy);
            Assert.True(vm.IsPresenting);
            Assert.False(vm.HasResult);
            Assert.Equal("立即查看结果", vm.CancelButtonText);
            Assert.Equal(100, vm.Progress);
            Assert.True(double.IsNaN(vm.FreedBytes));
            Assert.Contains("处理已结束", vm.Headline);
            late!.Report(new("过时扫描", "过时扫描", 12));
            WpfTestHost.Drain();
            Assert.Equal("结果展示", vm.Stage);
            gate.SetResult();
        });
        await work!.WaitAsync(TimeSpan.FromSeconds(5));
        WpfTestHost.Run(() =>
        {
            Assert.False(vm!.IsBusy);
            Assert.False(vm.IsPresenting);
            Assert.True(vm.HasResult);
            Assert.True(vm.ShowCompletionEffect);
            Assert.Equal(4, vm.ProcessedFiles);
            Assert.Equal(4096, vm.QuarantinedBytes);
            Assert.Equal(0, vm.FreedBytes);
            Assert.Equal(-1000, vm.MemoryDelta);
        });
    }

    [Fact]
    public async Task Skip_button_reveals_results_instead_of_cancelling_already_completed_work()
    {
        QuickOptimizeViewModel? vm = null;
        Task? work = null;
        WpfTestHost.Run(() =>
        {
            vm = new QuickOptimizeViewModel((_, _, _) => Task.FromResult(Result()),
                minimumPresentation: TimeSpan.FromSeconds(3), animationsEnabled: () => true,
                presentationDelay: (_, ct) => Task.Delay(Timeout.InfiniteTimeSpan, ct));
            var page = new QuickOptimizePage { DataContext = vm };
            page.Measure(new Size(960, 720));
            page.Arrange(new Rect(0, 0, 960, 720));
            work = vm.OptimizeCommand.ExecuteAsync(null);
            WpfTestHost.Drain();
            var skip = Assert.Single(Descendants(page).OfType<Button>(), b => Equals(b.Content, "立即查看结果"));
            Assert.True(skip.IsEnabled);
            Assert.Same(vm.OptimizeCancelCommand, skip.Command);
            skip.Command!.Execute(null);
        });
        await work!.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(vm!.HasResult);
        Assert.False(vm.IsBusy);
        Assert.Equal(4, vm.ProcessedFiles);
        Assert.Equal("整理完成", vm.Headline);
    }

    [Theory]
    [InlineData(4, true, false)]
    [InlineData(0, false, false)]
    [InlineData(0, true, true)]
    public async Task Long_tasks_reduced_motion_and_cancelled_reports_have_no_artificial_wait(int elapsed, bool animate, bool cancelled)
    {
        var clock = new Clock();
        var result = Result();
        result.Report.Cancelled = cancelled;
        var vm = new QuickOptimizeViewModel((_, _, _) => { clock.Elapsed = TimeSpan.FromSeconds(elapsed); return Task.FromResult(result); },
            minimumPresentation: TimeSpan.FromSeconds(3), animationsEnabled: () => animate, clock: clock,
            presentationDelay: (_, _) => throw new Exception("Must not wait"));
        await vm.OptimizeCommand.ExecuteAsync(null);
        Assert.True(vm.HasResult);
        Assert.False(vm.IsPresenting);
        Assert.Equal(4, vm.ProcessedFiles);
        Assert.Equal(!cancelled, vm.ShowCompletionEffect);
    }

    [Fact]
    public async Task Failure_is_shown_immediately_and_empty_result_does_not_claim_a_gain()
    {
        var failed = new QuickOptimizeViewModel((_, _, _) => throw new InvalidOperationException("failure"),
            minimumPresentation: TimeSpan.FromSeconds(3), animationsEnabled: () => true,
            presentationDelay: (_, _) => throw new Exception("Must not wait"));
        await failed.OptimizeCommand.ExecuteAsync(null);
        Assert.False(failed.HasResult);
        Assert.False(failed.ShowCompletionEffect);
        Assert.Equal("failure", failed.Detail);
        var empty = new QuickOptimizeViewModel((_, _, _) => Task.FromResult(new QuickOptimizeResult(new CleanReport(), null, null, null, "", 0)));
        await empty.OptimizeCommand.ExecuteAsync(null);
        Assert.Contains("暂无需要处理", empty.Headline);
        Assert.Equal(0, empty.FreedBytes);
        Assert.False(empty.ShowCompletionEffect);
    }

    [Fact]
    public void Completion_effect_and_card_reveal_attach_to_the_real_visual_tree()
    {
        WpfTestHost.Run(() =>
        {
            using var source = new HwndSource(new HwndSourceParameters("CleanSweep completion animation test")
            { Width = 960, Height = 720, WindowStyle = unchecked((int)0x80000000) });
            var vm = new QuickOptimizeViewModel((_, _, _) => Task.FromResult(Result()));
            var page = new QuickOptimizePage { DataContext = vm };
            source.RootVisual = page;
            page.Measure(new Size(960, 720));
            page.Arrange(new Rect(0, 0, 960, 720));
            WpfTestHost.Drain();
            vm.OptimizeCommand.ExecuteAsync(null).GetAwaiter().GetResult();
            WpfTestHost.Drain();
            var halo = (System.Windows.Shapes.Ellipse)page.FindName("CompletionHalo");
            Assert.Equal(SystemParameters.ClientAreaAnimation && halo.IsVisible, halo.HasAnimatedProperties);
            var cards = Assert.Single(Descendants(page).OfType<System.Windows.Controls.Primitives.UniformGrid>());
            Assert.Equal(SystemParameters.ClientAreaAnimation && cards.IsVisible, cards.HasAnimatedProperties);
            vm.HasResult = false;
            vm.ShowCompletionEffect = false;
            WpfTestHost.Drain();
            // WPF removes clocks on the next animation tick; pump a frame without blocking the UI.
            var frame = new DispatcherFrame();
            var tick = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(80) };
            tick.Tick += (_, _) => { tick.Stop(); frame.Continue = false; };
            tick.Start();
            Dispatcher.PushFrame(frame);
            Assert.False(halo.HasAnimatedProperties);
            Assert.False(cards.HasAnimatedProperties);
            source.RootVisual = null;
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
}
