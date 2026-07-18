using System.Collections.Concurrent;
using System.Runtime.Versioning;

namespace NetShaper.Core.Traffic;

/// <summary>
/// Dedicated high-priority sampling loop (own thread-pool long-running task).
/// Produces snapshots continuously; UI only consumes the latest.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TrafficSampleEngine : IDisposable
{
    private readonly WindowsTrafficSampler _sampler;
    private readonly bool _ownsSampler;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;
    private readonly object _latestGate = new();
    private TrafficSnapshot? _latest;
    private int _generation;
    private int _dropped;
    private volatile bool _preferEStats = true;
    private volatile bool _includeConnections = true;
    private double _intervalSeconds = 1.0;

    public event Action<TrafficSnapshot>? SnapshotReady;

    public WindowsTrafficSampler Sampler => _sampler;
    public int Generation => Volatile.Read(ref _generation);
    public int DroppedOverlaps => Volatile.Read(ref _dropped);
    public bool IsRunning => _loop is { IsCompleted: false };

    public double IntervalSeconds
    {
        get => _intervalSeconds;
        set => _intervalSeconds = Math.Clamp(value, 0.4, 10);
    }

    public bool PreferEStats
    {
        get => _preferEStats;
        set => _preferEStats = value;
    }

    public bool IncludeConnections
    {
        get => _includeConnections;
        set => _includeConnections = value;
    }

    public TrafficSampleEngine(WindowsTrafficSampler? sampler = null)
    {
        _ownsSampler = sampler is null;
        _sampler = sampler ?? new WindowsTrafficSampler();
    }

    public void Start()
    {
        if (_loop is { IsCompleted: false }) return;
        _loop = Task.Factory.StartNew(
            Loop,
            _cts.Token,
            TaskCreationOptions.LongRunning | TaskCreationOptions.DenyChildAttach,
            TaskScheduler.Default);
    }

    public void Stop()
    {
        try { _cts.Cancel(); } catch { /* */ }
        try { _loop?.Wait(1500); } catch { /* */ }
    }

    /// <summary>Latest snapshot (may be null until first complete sample).</summary>
    public TrafficSnapshot? TryGetLatest()
    {
        lock (_latestGate) return _latest;
    }

    private int _kickPending;

    /// <summary>Request an immediate sample (coalesced — at most one extra in flight).</summary>
    public void Kick()
    {
        if (Interlocked.CompareExchange(ref _kickPending, 1, 0) != 0)
            return;
        _ = Task.Run(() =>
        {
            try
            {
                if (_cts.IsCancellationRequested) return;
                PublishOne();
            }
            catch { /* ignore */ }
            finally
            {
                Interlocked.Exchange(ref _kickPending, 0);
            }
        });
    }

    private void Loop()
    {
        // Warm-up: two samples so rates have a previous point
        try
        {
            PublishOne();
            Thread.Sleep(400);
            if (!_cts.IsCancellationRequested)
                PublishOne();
        }
        catch { /* first sample best-effort */ }

        while (!_cts.IsCancellationRequested)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                PublishOne();
            }
            catch
            {
                // keep loop alive
            }

            var target = TimeSpan.FromSeconds(_intervalSeconds);
            var remaining = target - sw.Elapsed;
            if (remaining > TimeSpan.Zero)
                SleepInterruptible(remaining, _cts.Token);
        }
    }

    private void PublishOne()
    {
        _sampler.PreferEStats = _preferEStats;
        var snap = _sampler.Sample(includeConnections: _includeConnections);
        Interlocked.Increment(ref _generation);
        lock (_latestGate)
            _latest = snap;

        var handlers = SnapshotReady;
        if (handlers is null) return;
        // Fan-out: each subscriber gets the snapshot; don't let one stall others
        foreach (Action<TrafficSnapshot> h in handlers.GetInvocationList())
        {
            try { h(snap); }
            catch { /* subscriber fault */ }
        }
    }

    private static void SleepInterruptible(TimeSpan total, CancellationToken ct)
    {
        var end = DateTime.UtcNow + total;
        while (DateTime.UtcNow < end)
        {
            if (ct.IsCancellationRequested) return;
            var left = end - DateTime.UtcNow;
            if (left <= TimeSpan.Zero) return;
            var ms = (int)Math.Min(50, Math.Max(1, left.TotalMilliseconds));
            Thread.Sleep(ms);
        }
    }

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
        if (_ownsSampler)
            _sampler.Dispose();
    }
}

/// <summary>Shared ParallelOptions for traffic sampling / DNS enrich.</summary>
public static class ParallelOpts
{
    public static ParallelOptions Default { get; } = new()
    {
        MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount, 2, 8),
    };

    public static ParallelOptions Light { get; } = new()
    {
        MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount / 2, 2, 4),
    };
}
