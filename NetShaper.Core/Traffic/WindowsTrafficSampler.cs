using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace NetShaper.Core.Traffic;

/// <summary>
/// Traffic sampler: TCP/UDP tables + TCP EStats for per-connection/process rates and bytes.
/// Internals are multi-threaded (parallel table reads, PID resolve, EStats).
/// Per-app rates require successful EStats enable (typically Administrator).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsTrafficSampler : IDisposable
{
    private readonly ConcurrentDictionary<int, (long sent, long recv, long tsTicks)> _lastProc = new();
    private readonly ConcurrentDictionary<string, (long sent, long recv, long tsTicks)> _lastConn = new();
    private readonly ConcurrentDictionary<int, (string name, string? path, long tsTicks)> _procCache = new();
    private readonly ConcurrentDictionary<string, byte> _estatsEnabled = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _estatsFailed = new(StringComparer.Ordinal);
    private readonly ServiceProcessMap _services = new();
    private long _ifaceSent, _ifaceRecv, _ifaceTs;
    private readonly object _ifaceGate = new();
    private readonly ConcurrentDictionary<int, (long inn, long outt)> _sessionBytes = new();
    private long _lastSampleTicks;
    private bool _disposed;
    private int _estatsOk;
    private int _estatsFail;
    private int _sampleCount;
    private readonly object _sampleGate = new(); // one Sample at a time per instance

    public bool PreferEStats { get; set; } = true;
    /// <summary>Max TCP rows to newly enable EStats on per sample.</summary>
    public int MaxEStatsPerSample { get; set; } = 120;
    /// <summary>Parallelism for EStats / PID resolve (auto-clamped).</summary>
    public int DegreeOfParallelism { get; set; } = Math.Clamp(Environment.ProcessorCount, 2, 8);

    /// <summary>True after at least one successful EStats byte read this process lifetime.</summary>
    public bool EStatsWorking => _estatsOk > 0;

    /// <summary>Human-readable sampler health for UI.</summary>
    public string StatusText
    {
        get
        {
            var elev = IsProcessElevated();
            if (!PreferEStats)
                return "Per-app rates: EStats disabled in settings";
            if (EStatsWorking)
                return $"Per-app rates: EStats OK (reads={_estatsOk})";
            if (_sampleCount < 2)
                return "Per-app rates: warming up…";
            // NIC-share works without admin — always usable for Top Talkers
            if (!elev)
                return "Per-app rates: NIC-share (run as Admin for precise EStats)";
            if (_estatsFail > 0 && _estatsOk == 0)
                return $"Per-app rates: NIC-share (EStats fail={_estatsFail})";
            return "Per-app rates: NIC-share / waiting for TCP…";
        }
    }

    public static bool IsProcessElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            var p = new WindowsPrincipal(id);
            return p.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    public TrafficSnapshot Sample(bool includeConnections = true)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        // Serialize samples on this instance (engine guarantees single caller; lock is safety)
        lock (_sampleGate)
            return SampleCore(includeConnections);
    }

    private TrafficSnapshot SampleCore(bool includeConnections)
    {
        _sampleCount++;
        var now = DateTime.UtcNow;
        var nowTicks = now.Ticks;
        var dop = new ParallelOptions
        {
            MaxDegreeOfParallelism = Math.Clamp(DegreeOfParallelism, 2, 16),
        };

        // Service map refresh on background occasionally (non-blocking when fresh)
        if (_sampleCount == 1 || _sampleCount % 4 == 0)
            _services.EnsureFresh();

        // 1) Parallel socket table reads (TCP4/6 + UDP4/6)
        var connections = includeConnections
            ? EnumerateConnectionsParallel()
            : new List<ConnectionInfo>();

        // 2) Parallel PID resolve for unique owners
        var pids = connections.Select(c => c.ProcessId).Where(p => p >= 0).Distinct().ToArray();
        var byPid = new ConcurrentDictionary<int, ProcessTraffic>();
        Parallel.ForEach(pids, dop, pid =>
        {
            var (name, path) = ResolveProcess(pid, nowTicks);
            byPid[pid] = new ProcessTraffic
            {
                ProcessId = pid,
                ProcessName = name,
                ExecutablePath = path,
                ServiceNames = _services.GetServices(pid),
            };
        });

        foreach (var c in connections)
        {
            if (byPid.TryGetValue(c.ProcessId, out var pt))
            {
                c.ProcessName = pt.ProcessName;
                c.ServiceNames = pt.ServiceNames;
            }
        }

        // 3) Parallel EStats on established IPv4 TCP
        if (PreferEStats)
            ApplyEStatsParallel(connections, nowTicks, dop);

        // 4) Aggregate connection → process (single-threaded, cheap)
        foreach (var c in connections)
        {
            if (!byPid.TryGetValue(c.ProcessId, out var pt)) continue;
            pt.ConnectionCount++;
            if (c.State is "Established")
                pt.EstablishedCount++;
            pt.BytesSent += c.BytesSent;
            pt.BytesRecv += c.BytesRecv;
            pt.BitsPerSecOut += c.BitsPerSecOut;
            pt.BitsPerSecIn += c.BitsPerSecIn;
        }

        // 5) Process-level rate from EStats byte counters (delta)
        foreach (var pt in byPid.Values)
        {
            if (pt.BitsPerSecOut > 0 || pt.BitsPerSecIn > 0)
            {
                _lastProc[pt.ProcessId] = (pt.BytesSent, pt.BytesRecv, nowTicks);
                continue;
            }
            if (pt.BytesSent == 0 && pt.BytesRecv == 0) continue;
            if (_lastProc.TryGetValue(pt.ProcessId, out var prev))
            {
                var dtE = TimeSpan.FromTicks(nowTicks - prev.tsTicks).TotalSeconds;
                if (dtE > 0.2 && dtE < 30)
                {
                    var dOut = pt.BytesSent - prev.sent;
                    var dIn = pt.BytesRecv - prev.recv;
                    if (dOut >= 0) pt.BitsPerSecOut = dOut * 8.0 / dtE;
                    if (dIn >= 0) pt.BitsPerSecIn = dIn * 8.0 / dtE;
                }
            }
            _lastProc[pt.ProcessId] = (pt.BytesSent, pt.BytesRecv, nowTicks);
        }

        if (_lastProc.Count > 600)
        {
            var live = byPid.Keys.ToHashSet();
            foreach (var k in _lastProc.Keys)
                if (!live.Contains(k)) _lastProc.TryRemove(k, out _);
        }

        // 6) Interface totals
        var (bpsIn, bpsOut) = SampleInterfaceRates(nowTicks);

        // 7) NIC-share attribution when EStats empty/weak — so Top Talkers always has rates
        double appIn = byPid.Values.Sum(p => p.BitsPerSecIn);
        double appOut = byPid.Values.Sum(p => p.BitsPerSecOut);
        bool estatsStrong = EStatsWorking && (appIn + appOut) > Math.Max(8000, (bpsIn + bpsOut) * 0.15);
        string rateMode;
        if (estatsStrong)
        {
            rateMode = "EStats";
            foreach (var pt in byPid.Values) pt.RateSource = "EStats";
        }
        else
        {
            rateMode = EStatsWorking ? "Mixed" : "NIC-share";
            ApplyNicShareRates(byPid.Values, connections, bpsIn, bpsOut, rateMode);
        }

        // 8) Session data totals (for ↓ data / ↑ data columns)
        double dtSec = 1.0;
        if (_lastSampleTicks > 0)
        {
            dtSec = TimeSpan.FromTicks(nowTicks - _lastSampleTicks).TotalSeconds;
            if (dtSec < 0.2) dtSec = 0.2;
            if (dtSec > 10) dtSec = 10;
        }
        _lastSampleTicks = nowTicks;

        foreach (var pt in byPid.Values)
        {
            var addIn = (long)Math.Max(0, pt.BitsPerSecIn * dtSec / 8.0);
            var addOut = (long)Math.Max(0, pt.BitsPerSecOut * dtSec / 8.0);
            _sessionBytes.AddOrUpdate(pt.ProcessId,
                _ => (addIn, addOut),
                (_, prev) => (prev.inn + addIn, prev.outt + addOut));
            if (_sessionBytes.TryGetValue(pt.ProcessId, out var sess))
            {
                pt.SessionBytesIn = sess.inn;
                pt.SessionBytesOut = sess.outt;
            }
            pt.RefreshDisplayStrings();
        }

        // Prune session map
        if (_sessionBytes.Count > 400)
        {
            var live = byPid.Keys.ToHashSet();
            foreach (var k in _sessionBytes.Keys)
                if (!live.Contains(k)) _sessionBytes.TryRemove(k, out _);
        }

        // Materialize connection display strings
        Parallel.ForEach(connections, dop, c => c.RefreshDisplayStrings());

        var processes = byPid.Values
            .Where(p => p.ProcessId > 0)
            .Where(p => p.ConnectionCount > 0 || p.BitsPerSecIn > 0 || p.BitsPerSecOut > 0
                        || p.BytesSent > 0 || p.BytesRecv > 0 || p.SessionBytesIn > 0 || p.SessionBytesOut > 0)
            .OrderByDescending(p => p.BitsPerSecIn + p.BitsPerSecOut)
            .ThenByDescending(p => p.DataBytesIn + p.DataBytesOut)
            .ThenByDescending(p => p.ConnectionCount)
            .Take(120)
            .ToList();

        List<ConnectionInfo> topConns = connections
            .OrderByDescending(c => c.BitsPerSecIn + c.BitsPerSecOut)
            .ThenByDescending(c => c.BytesSent + c.BytesRecv)
            .Take(500)
            .ToList();

        return new TrafficSnapshot
        {
            Timestamp = DateTimeOffset.UtcNow,
            Processes = processes,
            Connections = topConns,
            TotalBitsPerSecIn = (long)bpsIn,
            TotalBitsPerSecOut = (long)bpsOut,
            SamplerStatus = StatusText + $" · {rateMode} · mt={dop.MaxDegreeOfParallelism}",
            EStatsWorking = EStatsWorking,
            IsElevated = IsProcessElevated(),
            RateMode = rateMode,
        };
    }

    /// <summary>
    /// Split interface rates across processes by connection weight (works without admin / EStats).
    /// Weight: Established TCP=8, other TCP=2, UDP open=1; boost non-loopback remotes.
    /// </summary>
    private static void ApplyNicShareRates(
        ICollection<ProcessTraffic> processes,
        List<ConnectionInfo> connections,
        double bpsIn,
        double bpsOut,
        string mode)
    {
        if (bpsIn + bpsOut < 500) return; // idle link — leave zeros

        var weights = new Dictionary<int, double>();
        foreach (var c in connections)
        {
            if (c.ProcessId <= 0) continue;
            double w = c.Protocol switch
            {
                "TCP" or "TCP6" when c.State is "Established" => 8,
                "TCP" or "TCP6" when c.State is "CloseWait" or "FinWait1" or "FinWait2" => 3,
                "TCP" or "TCP6" => 1.5,
                "UDP" or "UDP6" => 1,
                _ => 1,
            };
            // Prefer real remote peers over localhost
            if (c.RemoteEndPoint.Contains("127.0.0.1") || c.RemoteEndPoint.Contains("[::1]") ||
                c.RemoteEndPoint is "*:*")
                w *= 0.15;
            else if (c.State is "Established")
                w *= 1.5;

            weights[c.ProcessId] = weights.GetValueOrDefault(c.ProcessId) + w;
        }

        double sum = weights.Values.Sum();
        if (sum <= 0) return;

        foreach (var pt in processes)
        {
            if (!weights.TryGetValue(pt.ProcessId, out var w) || w <= 0) continue;
            var share = w / sum;
            // Fill only missing sides so partial EStats still helps
            if (pt.BitsPerSecIn < 1)
                pt.BitsPerSecIn = bpsIn * share;
            if (pt.BitsPerSecOut < 1)
                pt.BitsPerSecOut = bpsOut * share;
            pt.RateSource = mode;
        }
    }

    private (double bpsIn, double bpsOut) SampleInterfaceRates(long nowTicks)
    {
        long totalIn = 0, totalOut = 0;
        try
        {
            var nics = NetworkInterface.GetAllNetworkInterfaces();
            var bagIn = new long[nics.Length];
            var bagOut = new long[nics.Length];
            Parallel.For(0, nics.Length, ParallelOpts.Light, i =>
            {
                try
                {
                    var ni = nics[i];
                    if (ni.OperationalStatus != OperationalStatus.Up) return;
                    if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback
                        or NetworkInterfaceType.Tunnel) return;
                    var stats = ni.GetIPStatistics();
                    if (stats.BytesReceived > 0) bagIn[i] = stats.BytesReceived;
                    if (stats.BytesSent > 0) bagOut[i] = stats.BytesSent;
                }
                catch { /* per-adapter */ }
            });
            for (int i = 0; i < nics.Length; i++)
            {
                totalIn += bagIn[i];
                totalOut += bagOut[i];
            }
        }
        catch { /* ignore */ }

        double bpsIn = 0, bpsOut = 0;
        lock (_ifaceGate)
        {
            if (_ifaceTs > 0)
            {
                var dt = TimeSpan.FromTicks(nowTicks - _ifaceTs).TotalSeconds;
                if (dt > 0.15 && dt < 60)
                {
                    var dIn = totalIn - _ifaceRecv;
                    var dOut = totalOut - _ifaceSent;
                    if (dIn >= 0) bpsIn = dIn * 8.0 / dt;
                    if (dOut >= 0) bpsOut = dOut * 8.0 / dt;
                }
            }
            _ifaceSent = totalOut;
            _ifaceRecv = totalIn;
            _ifaceTs = nowTicks;
        }
        return (bpsIn, bpsOut);
    }

    private void ApplyEStatsParallel(List<ConnectionInfo> connections, long nowTicks, ParallelOptions dop)
    {
        var candidates = connections
            .Where(c => c.IsIpv4Tcp &&
                        c.State is "Established" or "CloseWait" or "FinWait1" or "FinWait2")
            .ToArray();
        if (candidates.Length == 0) return;

        int newlyEnabled = 0;
        int maxNew = MaxEStatsPerSample;

        Parallel.ForEach(candidates, dop, c =>
        {
            var key = $"{c.LocalAddrV4:X8}:{c.LocalPortNet:X8}:{c.RemoteAddrV4:X8}:{c.RemotePortNet:X8}";
            if (_estatsFailed.ContainsKey(key)) return;

            try
            {
                if (!_estatsEnabled.ContainsKey(key))
                {
                    // Cap brand-new enables (shared counter)
                    var n = Interlocked.Increment(ref newlyEnabled);
                    if (n > maxNew)
                    {
                        Interlocked.Decrement(ref newlyEnabled);
                        return;
                    }
                    if (!EnableDataEstats(c))
                    {
                        Interlocked.Increment(ref _estatsFail);
                        if (_estatsFail > 40 && _estatsOk == 0 && _sampleCount > 3)
                            _estatsFailed.TryAdd(key, 0);
                        return;
                    }
                    _estatsEnabled[key] = 0;
                }

                if (!TryReadDataEstats(c, out var sent, out var recv))
                {
                    _estatsEnabled.TryRemove(key, out _);
                    if (!EnableDataEstats(c) || !TryReadDataEstats(c, out sent, out recv))
                    {
                        Interlocked.Increment(ref _estatsFail);
                        return;
                    }
                    _estatsEnabled[key] = 0;
                }

                Interlocked.Increment(ref _estatsOk);
                c.BytesSent = sent;
                c.BytesRecv = recv;

                if (_lastConn.TryGetValue(key, out var prev))
                {
                    var dt = TimeSpan.FromTicks(nowTicks - prev.tsTicks).TotalSeconds;
                    if (dt > 0.15 && dt < 30)
                    {
                        var dOut = sent - prev.sent;
                        var dIn = recv - prev.recv;
                        if (dOut >= 0) c.BitsPerSecOut = dOut * 8.0 / dt;
                        if (dIn >= 0) c.BitsPerSecIn = dIn * 8.0 / dt;
                    }
                }
                _lastConn[key] = (sent, recv, nowTicks);
            }
            catch
            {
                Interlocked.Increment(ref _estatsFail);
            }
        });

        if (_estatsEnabled.Count > 2500)
        {
            _estatsEnabled.Clear();
            _estatsFailed.Clear();
        }
        if (_lastConn.Count > 2500)
        {
            var cutoff = nowTicks - TimeSpan.FromMinutes(5).Ticks;
            foreach (var kv in _lastConn)
                if (kv.Value.tsTicks < cutoff)
                    _lastConn.TryRemove(kv.Key, out _);
        }
    }

    private (string name, string? path) ResolveProcess(int pid, long nowTicks)
    {
        if (_procCache.TryGetValue(pid, out var cached) &&
            TimeSpan.FromTicks(nowTicks - cached.tsTicks).TotalSeconds < 30)
            return (cached.name, cached.path);

        string name = pid == 0 ? "System Idle" : $"pid:{pid}";
        string? path = null;
        if (pid > 0)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                name = SafeName(p);
                path = SafePath(p);
            }
            catch { /* exited / access */ }
        }

        _procCache[pid] = (name, path, nowTicks);
        if (_procCache.Count > 800)
        {
            var cutoff = nowTicks - TimeSpan.FromMinutes(2).Ticks;
            int removed = 0;
            foreach (var kv in _procCache)
            {
                if (kv.Value.tsTicks < cutoff && _procCache.TryRemove(kv.Key, out _))
                    if (++removed >= 200) break;
            }
        }
        return (name, path);
    }

    private static bool EnableDataEstats(ConnectionInfo c)
    {
        var row = ToRow(c);
        var rw = new TCP_ESTATS_DATA_RW_v0 { EnableCollection = 1 };
        var st = SetPerTcpConnectionEStats(
            ref row,
            TCP_ESTATS_TYPE.TcpConnectionEstatsData,
            ref rw,
            0,
            (uint)Marshal.SizeOf<TCP_ESTATS_DATA_RW_v0>(),
            0);
        return st == 0;
    }

    private static bool TryReadDataEstats(ConnectionInfo c, out long sent, out long recv)
    {
        sent = 0;
        recv = 0;
        var row = ToRow(c);
        var rodSize = Marshal.SizeOf<TCP_ESTATS_DATA_ROD_v0>();
        var rodPtr = Marshal.AllocHGlobal(rodSize);
        try
        {
            // Zero buffer so partial fills don't garbage
            for (int i = 0; i < rodSize; i++) Marshal.WriteByte(rodPtr, i, 0);

            var st = GetPerTcpConnectionEStats(
                ref row,
                TCP_ESTATS_TYPE.TcpConnectionEstatsData,
                IntPtr.Zero, 0, 0,
                IntPtr.Zero, 0, 0,
                rodPtr, 0, (uint)rodSize);
            if (st != 0) return false;

            var data = Marshal.PtrToStructure<TCP_ESTATS_DATA_ROD_v0>(rodPtr);
            // Prefer cumulative totals when "current" is zero (stack variants)
            sent = (long)(data.DataBytesOut != 0 ? data.DataBytesOut : data.DataBytesOutTotal);
            recv = (long)(data.DataBytesIn != 0 ? data.DataBytesIn : data.DataBytesInTotal);
            // ThruBytes are often more reliable for established flows
            if (sent == 0 && data.ThruBytesAcked > 0) sent = (long)data.ThruBytesAcked;
            if (recv == 0 && data.ThruBytesReceived > 0) recv = (long)data.ThruBytesReceived;
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(rodPtr);
        }
    }

    private static MIB_TCPROW ToRow(ConnectionInfo c) => new()
    {
        // Use real state when known; EStats is picky on some builds
        state = c.TcpStateCode != 0 ? c.TcpStateCode : 5u,
        localAddr = c.LocalAddrV4,
        localPort = c.LocalPortNet,
        remoteAddr = c.RemoteAddrV4,
        remotePort = c.RemotePortNet,
    };

    private static string SafeName(Process p)
    {
        try { return p.ProcessName; } catch { return "?"; }
    }

    private static string? SafePath(Process p)
    {
        try { return p.MainModule?.FileName; } catch { return null; }
    }

    private static List<ConnectionInfo> EnumerateConnectionsParallel()
    {
        // Four independent IP Helper queries in parallel
        var t4 = Task.Run(() => ReadTcpTable(AF_INET));
        var t6 = Task.Run(() => ReadTcpTable(AF_INET6));
        var u4 = Task.Run(() => ReadUdpTable(AF_INET));
        var u6 = Task.Run(() => ReadUdpTable(AF_INET6));
        Task.WaitAll(t4, t6, u4, u6);
        var list = new List<ConnectionInfo>(
            t4.Result.Count + t6.Result.Count + u4.Result.Count + u6.Result.Count);
        list.AddRange(t4.Result);
        list.AddRange(t6.Result);
        list.AddRange(u4.Result);
        list.AddRange(u6.Result);
        return list;
    }

    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        public uint localPort;
        public uint owningPid;
    }

    private enum TCP_ESTATS_TYPE
    {
        TcpConnectionEstatsData = 1,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TCP_ESTATS_DATA_RW_v0
    {
        public byte EnableCollection; // BOOLEAN
    }

    /// <summary>Matches iphlpapi TCP_ESTATS_DATA_ROD_v0 layout.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct TCP_ESTATS_DATA_ROD_v0
    {
        public ulong DataBytesOut;
        public ulong DataBytesIn;
        public ulong DataBytesOutTotal;
        public ulong DataBytesInTotal;
        public ulong SegsOut;
        public ulong SegsIn;
        public uint SoftErrorReason;
        public uint SndUna;
        public uint SndNxt;
        public uint SndMax;
        public ulong ThruBytesAcked;
        public uint RcvNxt;
        public ulong ThruBytesReceived;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SetPerTcpConnectionEStats(
        ref MIB_TCPROW row, TCP_ESTATS_TYPE estatsType,
        ref TCP_ESTATS_DATA_RW_v0 rw, uint rwVersion, uint rwSize, uint offset);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetPerTcpConnectionEStats(
        ref MIB_TCPROW row, TCP_ESTATS_TYPE estatsType,
        IntPtr rw, uint rwVersion, uint rwSize,
        IntPtr ros, uint rosVersion, uint rosSize,
        IntPtr rod, uint rodVersion, uint rodSize);

    private static List<ConnectionInfo> ReadTcpTable(int family)
    {
        var result = new List<ConnectionInfo>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, family, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size <= 0) return result;
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buf, ref size, true, family, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                return result;

            int num = Marshal.ReadInt32(buf);
            // MIB_TCPTABLE_OWNER_PID: dwNumEntries (4) then packed rows (no x64 padding)
            IntPtr rowPtr = buf + 4;

            int rowSize = family == AF_INET
                ? Marshal.SizeOf<MIB_TCPROW_OWNER_PID>()
                : 56; // MIB_TCP6ROW_OWNER_PID

            for (int i = 0; i < num; i++)
            {
                if (family == AF_INET)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    result.Add(new ConnectionInfo
                    {
                        ProcessId = (int)row.owningPid,
                        Protocol = "TCP",
                        LocalEndPoint = $"{ToIp(row.localAddr)}:{Ntohs(row.localPort)}",
                        RemoteEndPoint = $"{ToIp(row.remoteAddr)}:{Ntohs(row.remotePort)}",
                        State = TcpStateName(row.state),
                        TcpStateCode = row.state,
                        LocalAddrV4 = row.localAddr,
                        RemoteAddrV4 = row.remoteAddr,
                        LocalPortNet = row.localPort,
                        RemotePortNet = row.remotePort,
                        IsIpv4Tcp = true,
                    });
                    rowPtr += rowSize;
                }
                else
                {
                    // MIB_TCP6ROW_OWNER_PID: State(4)+LocalAddr(16)+dwLocalScopeId(4)+dwLocalPort(4)
                    // +RemoteAddr(16)+dwRemoteScopeId(4)+dwRemotePort(4)+OwningPid(4) = 56
                    uint state = (uint)Marshal.ReadInt32(rowPtr);
                    uint localPort = (uint)Marshal.ReadInt32(rowPtr + 24);
                    uint remotePort = (uint)Marshal.ReadInt32(rowPtr + 48);
                    int pid = Marshal.ReadInt32(rowPtr + 52);
                    string localIp = ReadIpv6(rowPtr + 4);
                    string remoteIp = ReadIpv6(rowPtr + 28);
                    result.Add(new ConnectionInfo
                    {
                        ProcessId = pid,
                        Protocol = "TCP6",
                        LocalEndPoint = $"[{localIp}]:{Ntohs(localPort)}",
                        RemoteEndPoint = $"[{remoteIp}]:{Ntohs(remotePort)}",
                        State = TcpStateName(state),
                        TcpStateCode = state,
                    });
                    rowPtr += rowSize;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
        return result;
    }

    private static string ReadIpv6(IntPtr p)
    {
        var b = new byte[16];
        Marshal.Copy(p, b, 0, 16);
        try { return new IPAddress(b).ToString(); }
        catch { return "v6"; }
    }

    private static List<ConnectionInfo> ReadUdpTable(int family)
    {
        var result = new List<ConnectionInfo>();
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, true, family, UDP_TABLE_OWNER_PID, 0);
        if (size <= 0) return result;
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(buf, ref size, true, family, UDP_TABLE_OWNER_PID, 0) != 0)
                return result;
            int num = Marshal.ReadInt32(buf);
            IntPtr rowPtr = buf + 4;
            int rowSize = family == AF_INET ? Marshal.SizeOf<MIB_UDPROW_OWNER_PID>() : 28;
            for (int i = 0; i < num; i++)
            {
                if (family == AF_INET)
                {
                    var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                    result.Add(new ConnectionInfo
                    {
                        ProcessId = (int)row.owningPid,
                        Protocol = "UDP",
                        LocalEndPoint = $"{ToIp(row.localAddr)}:{Ntohs(row.localPort)}",
                        RemoteEndPoint = "*:*",
                        State = "Open",
                    });
                    rowPtr += rowSize;
                }
                else
                {
                    // localAddr 16 + scope 4 + port 4 + pid 4 = 28
                    int pid = Marshal.ReadInt32(rowPtr + 24);
                    uint localPort = (uint)Marshal.ReadInt32(rowPtr + 20);
                    string lip = ReadIpv6(rowPtr);
                    result.Add(new ConnectionInfo
                    {
                        ProcessId = pid,
                        Protocol = "UDP6",
                        LocalEndPoint = $"[{lip}]:{Ntohs(localPort)}",
                        RemoteEndPoint = "*:*",
                        State = "Open",
                    });
                    rowPtr += rowSize;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
        return result;
    }

    private static string ToIp(uint addr)
    {
        var b = BitConverter.GetBytes(addr);
        return new IPAddress(b).ToString();
    }

    private static int Ntohs(uint portNet)
    {
        var p = (ushort)(portNet & 0xFFFF);
        return (ushort)((p >> 8) | (p << 8));
    }

    private static string TcpStateName(uint state) => state switch
    {
        1 => "Closed",
        2 => "Listen",
        3 => "SynSent",
        4 => "SynRcvd",
        5 => "Established",
        6 => "FinWait1",
        7 => "FinWait2",
        8 => "CloseWait",
        9 => "Closing",
        10 => "LastAck",
        11 => "TimeWait",
        12 => "DeleteTCB",
        _ => state.ToString(),
    };

    public void Dispose() => _disposed = true;
}
