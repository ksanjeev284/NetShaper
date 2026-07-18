using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using NetShaper.Core.Policy;

namespace NetShaper.Core.Shaping.WinDivert;

/// <summary>
/// Packet-level rate limiter using WinDivert (optional dependency).
/// Diverts outbound IPv4 TCP/UDP, maps to process, delays reinject via token bucket.
/// Requires Administrator + WinDivert.dll/sys installed (see scripts/install-windivert.ps1).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WinDivertShaper : IDisposable
{
    private readonly ConnectionOwnerIndex _owners = new();
    private readonly ConcurrentDictionary<int, PidLimit> _pidLimits = new();
    private readonly ConcurrentDictionary<Guid, RuleBucket> _ruleBuckets = new();
    private IntPtr _handle = IntPtr.Zero;
    private IntPtr _addrBuf = IntPtr.Zero;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _disposed;
    private PolicyDocument? _doc;

    public bool IsRunning => _handle != IntPtr.Zero && _loop is { IsCompleted: false };
    public string Status { get; private set; } = "stopped";
    public long PacketsHandled { get; private set; }
    public long PacketsDelayed { get; private set; }
    public long BytesShaped { get; private set; }

    private sealed class PidLimit
    {
        public Guid RuleId;
        public long BytesPerSec;
    }

    private sealed class RuleBucket
    {
        public double Tokens;
        public double Capacity;
        public double FillPerSec;
        public DateTime Last = DateTime.UtcNow;
        public readonly object Gate = new();

        public void Configure(long bytesPerSec)
        {
            FillPerSec = Math.Max(1, bytesPerSec);
            Capacity = FillPerSec * 1.25; // 1.25s burst
            if (Tokens <= 0 || Tokens > Capacity) Tokens = Capacity * 0.5;
        }

        public int WaitMsFor(int packetBytes)
        {
            lock (Gate)
            {
                var now = DateTime.UtcNow;
                var dt = (now - Last).TotalSeconds;
                if (dt > 0)
                {
                    Tokens = Math.Min(Capacity, Tokens + FillPerSec * dt);
                    Last = now;
                }
                if (Tokens >= packetBytes)
                {
                    Tokens -= packetBytes;
                    return 0;
                }
                var need = packetBytes - Tokens;
                Tokens = 0;
                var sec = need / FillPerSec;
                return (int)Math.Clamp(sec * 1000, 1, 500); // cap delay 500ms per packet
            }
        }
    }

    public static string Probe()
    {
        if (!WinDivertNative.TryLoad())
            return "unavailable: " + (WinDivertNative.LoadError ?? "unknown");
        return "ready: " + (WinDivertNative.LoadedPath ?? "WinDivert.dll");
    }

    public void UpdatePolicy(PolicyDocument doc)
    {
        _doc = doc;
        RebuildPidMap();
    }

    public void Start(PolicyDocument doc)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (IsRunning) { UpdatePolicy(doc); return; }
        if (!WinDivertNative.TryLoad())
            throw new InvalidOperationException(WinDivertNative.LoadError);

        _doc = doc;
        RebuildPidMap();
        _owners.Refresh();

        // Outbound IPv4 traffic only for performance
        const string filter = "outbound and ip and (tcp or udp)";
        _handle = WinDivertNative.Open(filter, WinDivertNative.WINDIVERT_LAYER_NETWORK, 0, 0);
        if (_handle == IntPtr.Zero || _handle == new IntPtr(-1))
            throw new InvalidOperationException(
                "WinDivertOpen failed (need Administrator and WinDivert64.sys loaded). " +
                "Run scripts\\install-windivert.ps1 as admin.");

        _addrBuf = Marshal.AllocHGlobal(WinDivertNative.AddressSize);
        _cts = new CancellationTokenSource();
        _loop = Task.Run(() => Loop(_cts.Token));
        Status = "running";
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { /* ignore */ }
        try
        {
            if (_handle != IntPtr.Zero && _handle != new IntPtr(-1))
                WinDivertNative.Close(_handle);
        }
        catch { /* ignore */ }
        _handle = IntPtr.Zero;
        try { _loop?.Wait(2000); } catch { /* ignore */ }
        _loop = null;
        if (_addrBuf != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(_addrBuf);
            _addrBuf = IntPtr.Zero;
        }
        Status = "stopped";
    }

    private void RebuildPidMap()
    {
        _pidLimits.Clear();
        if (_doc is null || !_doc.LimiterEnabled) return;

        foreach (var rule in _doc.Rules.Where(r =>
                     r.Enabled && r.Kind == RuleKind.Limit && r.IsActiveNow() &&
                     r.LimitBytesPerSec is > 0))
        {
            var filter = _doc.Filters.FirstOrDefault(f => f.Id == rule.FilterId);
            if (filter is null) continue;
            var bps = rule.LimitBytesPerSec!.Value;
            _ruleBuckets.GetOrAdd(rule.Id, _ => new RuleBucket()).Configure(bps);

            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    var path = SafePath(p);
                    var name = SafeName(p);
                    var ctx = new FilterMatcher.Context
                    {
                        ProcessId = p.Id,
                        ProcessName = name,
                        ExecutablePath = path,
                    };
                    if (FilterMatcher.MatchesFilter(filter, ctx))
                    {
                        _pidLimits[p.Id] = new PidLimit
                        {
                            RuleId = rule.Id,
                            BytesPerSec = bps,
                        };
                    }
                }
                catch { /* access */ }
                finally { p.Dispose(); }
            }
        }
    }

    private void Loop(CancellationToken ct)
    {
        var packet = new byte[0xFFFF];
        var lastMap = DateTime.UtcNow;
        var lastOwners = DateTime.UtcNow;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (DateTime.UtcNow - lastMap > TimeSpan.FromSeconds(2))
                {
                    RebuildPidMap();
                    lastMap = DateTime.UtcNow;
                }
                if (DateTime.UtcNow - lastOwners > TimeSpan.FromMilliseconds(800))
                {
                    _owners.Refresh();
                    lastOwners = DateTime.UtcNow;
                }

                if (!WinDivertNative.Recv(_handle, packet, out var len, _addrBuf) || len <= 0)
                {
                    Thread.Sleep(1);
                    continue;
                }

                PacketsHandled++;
                if (!TryParseIpv4(packet, len, out var proto, out var srcIp, out var dstIp,
                        out var srcPort, out var dstPort))
                {
                    WinDivertNative.Send(_handle, packet, len, _addrBuf);
                    continue;
                }

                var outbound = true; // filter is outbound
                var pid = _owners.Lookup(proto, srcIp, srcPort, dstIp, dstPort, outbound);
                if (pid is int p && _pidLimits.TryGetValue(p, out var lim) &&
                    _ruleBuckets.TryGetValue(lim.RuleId, out var bucket))
                {
                    var wait = bucket.WaitMsFor(len);
                    if (wait > 0)
                    {
                        PacketsDelayed++;
                        Thread.Sleep(wait);
                    }
                    BytesShaped += len;
                }

                WinDivertNative.Send(_handle, packet, len, _addrBuf);
            }
            catch (Exception ex)
            {
                Status = "error: " + ex.Message;
                Thread.Sleep(50);
            }
        }
        Status = "stopped";
    }

    private static bool TryParseIpv4(byte[] buf, int len, out int proto, out string srcIp, out string dstIp,
        out int srcPort, out int dstPort)
    {
        proto = 0; srcIp = dstIp = ""; srcPort = dstPort = 0;
        if (len < 20) return false;
        var verIhl = buf[0];
        if ((verIhl >> 4) != 4) return false;
        var ihl = (verIhl & 0x0F) * 4;
        if (len < ihl + 4) return false;
        proto = buf[9];
        srcIp = new IPAddress(buf.AsSpan(12, 4).ToArray()).ToString();
        dstIp = new IPAddress(buf.AsSpan(16, 4).ToArray()).ToString();
        if (proto is 6 or 17) // TCP/UDP
        {
            srcPort = (buf[ihl] << 8) | buf[ihl + 1];
            dstPort = (buf[ihl + 2] << 8) | buf[ihl + 3];
        }
        return true;
    }

    private static string SafeName(Process p)
    {
        try { return p.ProcessName; } catch { return "?"; }
    }

    private static string? SafePath(Process p)
    {
        try { return p.MainModule?.FileName; } catch { return null; }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }
}
