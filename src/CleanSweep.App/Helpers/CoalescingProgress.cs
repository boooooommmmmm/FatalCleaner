namespace CleanSweep.App.Helpers;

/// <summary>合并后台高频进度；最多保留一个待处理回调，界面忙时只显示最新值。</summary>
internal sealed class CoalescingProgress<T> : IProgress<T>, IDisposable
{
    private readonly object _gate = new();
    private readonly SynchronizationContext _context = SynchronizationContext.Current ?? new SynchronizationContext();
    private readonly Action<T> _handler;
    private readonly Timer _timer;
    private T _latest = default!;
    private bool _hasValue, _posted, _started, _disposed;

    public CoalescingProgress(Action<T> handler)
    {
        _handler = handler;
        _timer = new Timer(_ => PostLatest(), null, TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(100));
    }

    public void Report(T value)
    {
        lock (_gate)
        {
            if (_disposed) return;
            _latest = value;
            _hasValue = true;
            if (_started) return;
            _started = true;
            PostLatest(); // 第一条及时显示，后续每 100ms 合并一次。
        }
    }

    private void PostLatest()
    {
        lock (_gate)
        {
            if (_disposed || _posted || !_hasValue) return;
            _posted = true;
            _context.Post(_ => Deliver(), null);
        }
    }

    private void Deliver()
    {
        T value;
        lock (_gate)
        {
            _posted = false;
            if (_disposed || !_hasValue) return;
            value = _latest;
            _hasValue = false;
        }
        _handler(value);
    }

    public void Dispose()
    {
        lock (_gate) { _disposed = true; _hasValue = false; }
        _timer.Dispose();
    }
}
