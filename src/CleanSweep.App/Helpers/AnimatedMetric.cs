using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;

namespace CleanSweep.App.Helpers;

/// <summary>只对真实测量值做显示插值；未知值显示破折号，不生成估计收益。</summary>
public sealed class AnimatedMetric : TextBlock
{
    public static readonly DependencyProperty ValueProperty = DependencyProperty.Register(nameof(Value), typeof(double), typeof(AnimatedMetric),
        new PropertyMetadata(double.NaN, OnValueChanged));
    public static readonly DependencyProperty KindProperty = DependencyProperty.Register(nameof(Kind), typeof(string), typeof(AnimatedMetric),
        new PropertyMetadata("bytes", (d, _) => ((AnimatedMetric)d).RenderValue()));
    public static readonly DependencyProperty DelayMillisecondsProperty = DependencyProperty.Register(nameof(DelayMilliseconds), typeof(double), typeof(AnimatedMetric),
        new PropertyMetadata(0d, OnValueChanged), value => value is double d && double.IsFinite(d) && d >= 0);
    private static readonly DependencyProperty DisplayValueProperty = DependencyProperty.Register(nameof(DisplayValue), typeof(double), typeof(AnimatedMetric),
        new PropertyMetadata(0d, (d, _) => ((AnimatedMetric)d).RenderValue()));
    public double Value { get => (double)GetValue(ValueProperty); set => SetValue(ValueProperty, value); }
    public string Kind { get => (string)GetValue(KindProperty); set => SetValue(KindProperty, value); }
    public double DelayMilliseconds { get => (double)GetValue(DelayMillisecondsProperty); set => SetValue(DelayMillisecondsProperty, value); }
    private double DisplayValue { get => (double)GetValue(DisplayValueProperty); set => SetValue(DisplayValueProperty, value); }

    public AnimatedMetric()
    {
        Text = "—";
        Loaded += (_, _) => Refresh();
        Unloaded += (_, _) => { BeginAnimation(DisplayValueProperty, null); };
    }
    private static void OnValueChanged(DependencyObject d, DependencyPropertyChangedEventArgs e) => ((AnimatedMetric)d).Refresh();
    private void Refresh()
    {
        BeginAnimation(DisplayValueProperty, null);
        if (!double.IsFinite(Value)) { Text = "—"; return; }
        if (!IsLoaded || !SystemParameters.ClientAreaAnimation) { DisplayValue = Value; RenderValue(); return; }
        DisplayValue = Value;
        var animation = new DoubleAnimationUsingKeyFrames { FillBehavior = FillBehavior.Stop };
        animation.KeyFrames.Add(new LinearDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.Zero)));
        if (DelayMilliseconds > 0)
            animation.KeyFrames.Add(new LinearDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(DelayMilliseconds))));
        animation.KeyFrames.Add(new EasingDoubleKeyFrame(Value, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(DelayMilliseconds + 650)))
        { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });
        BeginAnimation(DisplayValueProperty, animation);
    }
    private void RenderValue()
    {
        if (!double.IsFinite(Value)) { Text = "—"; return; }
        var value = DisplayValue;
        Text = Kind switch
        {
            "count" => Math.Max(0, value).ToString("N0"),
            "seconds" => Math.Max(0, value).ToString("0.0") + " 秒",
            "signedBytes" => (value < 0 ? "−" : value > 0 ? "+" : "") + Format.Bytes((long)Math.Abs(value)),
            _ => Format.Bytes((long)Math.Max(0, value)),
        };
    }
}
