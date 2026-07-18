using System.Diagnostics;
using System.Runtime.Versioning;
using NetShaper.Core.Driver;
using NetShaper.Core.Policy;
using NetShaper.Core.Shaping.WinDivert;
using NetShaper.Core.Traffic;
using NetShaper.Core.Wfp;

namespace NetShaper.Core.Shaping;

/// <summary>
/// Complete usermode bandwidth limiter for NetShaper.
/// Layers:
///  1) Windows NetQos throttle (admin)
///  2) Soft/Aggressive measured enforcement (WFP pulse / kill conns)
///  3) Packet mode: optional WinDivert delay reinject (smooth)
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BandwidthShaper : IDisposable
{
    private readonly QosEnforcer _qos = new();
    private readonly WinDivertShaper _packet = new();
    private readonly NetShaperDriverClient _driver = new();
    private DateTime _lastDriverPush = DateTime.MinValue;
    private readonly Dictionary<Guid, TokenBucket> _buckets = new();
    private readonly Dictionary<Guid, LimitLiveStatus> _status = new();
    private WfpFilterEngine? _pulseEngine;
    private readonly Dictionary<string, DateTime> _pulseUntil = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<Guid, DateTime> _lastSoftAction = new();
    private DateTime _lastQosSync = DateTime.MinValue;
    private bool _disposed;

    public WinDivertShaper Packet => _packet;
    public NetShaperDriverClient Driver => _driver;
    public string PacketProbe => WinDivertShaper.Probe();
    public TimeSpan SoftActionCooldown { get; set; } = TimeSpan.FromSeconds(2);

    public QosEnforcer Qos => _qos;
    public TimeSpan QosResyncInterval { get; set; } = TimeSpan.FromSeconds(45);
    public double SoftOvershootRatio { get; set; } = 1.05; // 5% headroom before soft action
    public int SoftKillMaxConns { get; set; } = 2;
    public int AggressiveKillMaxConns { get; set; } = 32;
    public TimeSpan PulseBlockDuration { get; set; } = TimeSpan.FromMilliseconds(800);

    public sealed class LimitLiveStatus
    {
        public Guid RuleId { get; set; }
        public string FilterName { get; set; } = "";
        public long LimitBytesPerSec { get; set; }
        public long MeasuredBitsPerSec { get; set; }
        public bool ScheduleActive { get; set; }
        public bool OverLimit { get; set; }
        public string Action { get; set; } = "—";
        public int MatchedProcesses { get; set; }
        public string ProcessSummary { get; set; } = "";
    }

    public sealed class TickResult
    {
        public IReadOnlyList<LimitLiveStatus> Statuses { get; init; } = Array.Empty<LimitLiveStatus>();
        public bool QosSynced { get; init; }
        public int SoftActions { get; init; }
        public int KilledConnections { get; init; }
        public IReadOnlyList<string> Messages { get; init; } = Array.Empty<string>();
        public string Summary =>
            $"shaper statuses={Statuses.Count} over={Statuses.Count(s => s.OverLimit)} " +
            $"qosSync={QosSynced} soft={SoftActions} killed={KilledConnections}";
    }

    private sealed class TokenBucket
    {
        public double Tokens; // bytes
        public double Capacity;
        public double FillPerSec; // bytes/sec
        public DateTime Last = DateTime.UtcNow;

        public void Configure(long bytesPerSec)
        {
            FillPerSec = bytesPerSec;
            Capacity = Math.Max(bytesPerSec * 1.5, 64 * 1024); // 1.5s burst
            Tokens = Math.Min(Tokens, Capacity);
            if (Tokens <= 0) Tokens = Capacity * 0.5;
        }

        public void Refill()
        {
            var now = DateTime.UtcNow;
            var dt = (now - Last).TotalSeconds;
            if (dt <= 0) return;
            Tokens = Math.Min(Capacity, Tokens + FillPerSec * dt);
            Last = now;
        }

        /// <summary>Consume measured bytes; returns true if still within budget after consume.</summary>
        public bool TryConsume(double bytes)
        {
            Refill();
            if (bytes <= 0) return true;
            if (Tokens >= bytes)
            {
                Tokens -= bytes;
                return true;
            }
            Tokens = 0;
            return false;
        }
    }

    public IReadOnlyList<LimitLiveStatus> LastStatuses => _status.Values.ToList();

    /// <summary>
    /// Run one shaping tick. Call every ~1s from GUI/service with a traffic sample.
    /// </summary>
    public TickResult Tick(PolicyDocument doc, TrafficSnapshot snap, bool isElevated,
        IReadOnlyList<ConnectionInfo>? connections = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var messages = new List<string>();
        int soft = 0, killed = 0;
        bool qosSynced = false;

        var mode = doc.LimiterEnabled ? doc.ShaperMode : BandwidthShaperMode.Off;
        if (mode == BandwidthShaperMode.Off)
        {
            try { _packet.Stop(); } catch { /* ignore */ }
            // Drop kernel PID limits so traffic is not rate-limited while UI shaper is off
            try
            {
                if (NetShaperDriverClient.IsDevicePresent() && _driver.TryOpen())
                {
                    _driver.ClearLimits();
                    _driver.SetEnabled(false);
                    _lastDriverPush = DateTime.MinValue;
                }
            }
            catch { /* ignore */ }
            _status.Clear();
            return new TickResult { Messages = new[] { "Shaper off" } };
        }

        // Optional first-party callout driver: push limits when present
        if (isElevated && NetShaperDriverClient.IsDevicePresent() &&
            DateTime.UtcNow - _lastDriverPush > TimeSpan.FromSeconds(5))
        {
            try
            {
                _driver.SetEnabled(true);
                if (_driver.PushLimitsFromPolicy(doc))
                {
                    _lastDriverPush = DateTime.UtcNow;
                    messages.Add("driver: limits pushed — " + _driver.StatusText());
                }
            }
            catch (Exception ex)
            {
                messages.Add("driver: " + ex.Message);
            }
        }

        // Packet mode: start/update WinDivert engine
        if (mode == BandwidthShaperMode.Packet)
        {
            try
            {
                if (isElevated)
                {
                    if (!_packet.IsRunning)
                        _packet.Start(doc);
                    else
                        _packet.UpdatePolicy(doc);
                    messages.Add(
                        $"packet: {_packet.Status} handled={_packet.PacketsHandled} delayed={_packet.PacketsDelayed}");
                }
                else
                {
                    messages.Add("packet mode needs Administrator");
                }
            }
            catch (Exception ex)
            {
                messages.Add("packet start failed: " + ex.Message + " · falling back to Soft actions");
                mode = BandwidthShaperMode.Soft;
            }
        }
        else
        {
            try { if (_packet.IsRunning) _packet.Stop(); } catch { /* ignore */ }
        }

        // Periodic QoS sync for Qos/Soft/Aggressive/Packet when elevated
        if (isElevated && mode >= BandwidthShaperMode.Qos &&
            DateTime.UtcNow - _lastQosSync > QosResyncInterval)
        {
            try
            {
                var r = _qos.Apply(doc);
                _lastQosSync = DateTime.UtcNow;
                qosSynced = true;
                messages.Add($"QoS resync: {r.AppliedCount} policies");
                if (r.Errors.Count > 0)
                    messages.AddRange(r.Errors.Take(3).Select(e => "QoS: " + e));
            }
            catch (Exception ex)
            {
                messages.Add("QoS resync failed: " + ex.Message);
            }
        }

        var activeRuleIds = new HashSet<Guid>();
        var dt = Math.Max(0.2, 1.0); // approximate interval; refined by bucket wall clock
        // Better: use bucket.Last for refill; for measured bytes use rate * assumed 1s
        // We'll use measured bits/s from snapshot directly for Over detection,
        // and token bucket for soft pulse hysteresis.

        foreach (var rule in doc.Rules.Where(r => r.Enabled && r.Kind == RuleKind.Limit && r.IsActiveNow()))
        {
            if (rule.LimitBytesPerSec is null or <= 0) continue;
            var filter = doc.Filters.FirstOrDefault(f => f.Id == rule.FilterId);
            if (filter is null) continue;

            activeRuleIds.Add(rule.Id);
            if (!_buckets.TryGetValue(rule.Id, out var bucket))
            {
                bucket = new TokenBucket();
                _buckets[rule.Id] = bucket;
            }
            bucket.Configure(rule.LimitBytesPerSec.Value);

            var matched = snap.Processes
                .Where(p => FilterMatcher.MatchesFilter(filter, new FilterMatcher.Context
                {
                    ProcessId = p.ProcessId,
                    ProcessName = p.ProcessName,
                    ExecutablePath = p.ExecutablePath,
                }))
                .ToList();

            double measuredBits = 0;
            foreach (var p in matched)
            {
                measuredBits += rule.Direction switch
                {
                    TrafficDirection.In => p.BitsPerSecIn,
                    TrafficDirection.Out => p.BitsPerSecOut,
                    _ => p.BitsPerSecIn + p.BitsPerSecOut,
                };
            }

            var limitBits = rule.LimitBytesPerSec.Value * 8.0;
            var over = measuredBits > limitBits * SoftOvershootRatio;

            // Token: consume measured bytes for ~1 second sample
            var measuredBytesPerSec = measuredBits / 8.0;
            bucket.Refill();
            var withinBudget = bucket.TryConsume(measuredBytesPerSec * 0.95);

            var action = "ok";
            if (over || !withinBudget)
            {
                action = "over";
                var canAct = !_lastSoftAction.TryGetValue(rule.Id, out var lastAct) ||
                             DateTime.UtcNow - lastAct >= SoftActionCooldown;
                if (mode == BandwidthShaperMode.Soft && canAct)
                {
                    var k = SoftEnforce(matched, connections, isElevated, rule, filter, messages);
                    killed += k;
                    soft++;
                    _lastSoftAction[rule.Id] = DateTime.UtcNow;
                    action = k > 0 || isElevated ? "soft-pulse" : "over (need admin)";
                }
                else if (mode == BandwidthShaperMode.Soft)
                {
                    action = "over (cooling)";
                }
                else if (mode == BandwidthShaperMode.Aggressive && canAct)
                {
                    var k = AggressiveEnforce(matched, connections, messages);
                    killed += k;
                    soft++;
                    _lastSoftAction[rule.Id] = DateTime.UtcNow;
                    action = k > 0 ? "kill-conns" : "over";
                }
                else if (mode == BandwidthShaperMode.Aggressive)
                {
                    action = "over (cooling)";
                }
                else if (mode == BandwidthShaperMode.Packet)
                {
                    action = _packet.IsRunning ? "packet-shape" : "packet-offline";
                }
                else if (mode == BandwidthShaperMode.Qos)
                {
                    action = "over (QoS only)";
                }
            }
            else if (mode == BandwidthShaperMode.Packet && _packet.IsRunning)
            {
                action = "packet-ok";
            }

            _status[rule.Id] = new LimitLiveStatus
            {
                RuleId = rule.Id,
                FilterName = filter.Name,
                LimitBytesPerSec = rule.LimitBytesPerSec.Value,
                MeasuredBitsPerSec = (long)measuredBits,
                ScheduleActive = true,
                OverLimit = over || !withinBudget,
                Action = action,
                MatchedProcesses = matched.Count,
                ProcessSummary = string.Join(", ", matched.Take(4).Select(m => m.ProcessName)),
            };
        }

        // prune
        foreach (var id in _status.Keys.Where(k => !activeRuleIds.Contains(k)).ToList())
            _status.Remove(id);
        foreach (var id in _buckets.Keys.Where(k => !activeRuleIds.Contains(k)).ToList())
            _buckets.Remove(id);

        ExpirePulses();

        return new TickResult
        {
            Statuses = _status.Values.OrderByDescending(s => s.OverLimit).ThenBy(s => s.FilterName).ToList(),
            QosSynced = qosSynced,
            SoftActions = soft,
            KilledConnections = killed,
            Messages = messages,
        };
    }

    /// <summary>Force immediate QoS apply (admin).</summary>
    public QosApplyResult ApplyQosNow(PolicyDocument doc)
    {
        var r = _qos.Apply(doc);
        _lastQosSync = DateTime.UtcNow;
        return r;
    }

    private int SoftEnforce(
        List<ProcessTraffic> matched,
        IReadOnlyList<ConnectionInfo>? connections,
        bool isElevated,
        Rule rule,
        Filter filter,
        List<string> messages)
    {
        int killed = 0;
        // 1) Light connection trim
        if (connections is not null)
        {
            foreach (var p in matched)
            {
                var conns = connections
                    .Where(c => c.ProcessId == p.ProcessId && c.IsIpv4Tcp && c.State == "Established")
                    .Take(SoftKillMaxConns)
                    .ToList();
                foreach (var c in conns)
                {
                    if (ConnectionKiller.TryKill(c, out _))
                        killed++;
                }
            }
        }

        // 2) Short WFP block pulse on app path (elevated)
        if (isElevated)
        {
            foreach (var p in matched)
            {
                var path = p.ExecutablePath;
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) continue;
                try
                {
                    PulseBlock(path, rule.Direction);
                    messages.Add($"pulse-block {Path.GetFileName(path)}");
                }
                catch (Exception ex)
                {
                    messages.Add($"pulse fail {p.ProcessName}: {ex.Message}");
                }
            }
        }

        return killed;
    }

    private int AggressiveEnforce(
        List<ProcessTraffic> matched,
        IReadOnlyList<ConnectionInfo>? connections,
        List<string> messages)
    {
        if (connections is null) return 0;
        int killed = 0;
        foreach (var p in matched)
        {
            var conns = connections
                .Where(c => c.ProcessId == p.ProcessId && c.IsIpv4Tcp &&
                            c.State is "Established" or "CloseWait" or "FinWait1" or "FinWait2")
                .Take(AggressiveKillMaxConns)
                .ToList();
            foreach (var c in conns)
            {
                if (ConnectionKiller.TryKill(c, out _))
                    killed++;
            }
            if (conns.Count > 0)
                messages.Add($"aggressive kill {p.ProcessName}×{conns.Count}");
        }
        return killed;
    }

    private void PulseBlock(string appPath, TrafficDirection dir)
    {
        _pulseEngine ??= new WfpFilterEngine(WfpSessionMode.Dynamic);
        _pulseEngine.Open();
        // Avoid stacking endless filters: if already pulsed recently, skip re-add
        if (_pulseUntil.TryGetValue(appPath, out var until) && until > DateTime.UtcNow)
            return;

        _pulseEngine.AddAppRule(appPath, block: true, dir, tag: "shape-pulse", weight: 11);
        _pulseUntil[appPath] = DateTime.UtcNow + PulseBlockDuration;
    }

    private void ExpirePulses()
    {
        var now = DateTime.UtcNow;
        var expired = _pulseUntil.Where(kv => kv.Value <= now).Select(kv => kv.Key).ToList();
        if (expired.Count == 0) return;

        // Dynamic engine: clear all our filters on pulse engine and drop map
        // (pulse engine only holds pulse filters)
        try
        {
            _pulseEngine?.ClearOurFilters();
        }
        catch { /* ignore */ }
        foreach (var k in expired)
            _pulseUntil.Remove(k);
        // keep non-expired; re-add still active pulses
        var still = _pulseUntil.Where(kv => kv.Value > now).Select(kv => kv.Key).ToList();
        foreach (var path in still)
        {
            try
            {
                _pulseEngine ??= new WfpFilterEngine(WfpSessionMode.Dynamic);
                _pulseEngine.Open();
                _pulseEngine.AddAppRule(path, block: true, TrafficDirection.Both, tag: "shape-pulse", weight: 11);
            }
            catch { /* ignore */ }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            _pulseEngine?.ClearOurFilters();
            _pulseEngine?.Dispose();
        }
        catch { /* ignore */ }
        _pulseEngine = null;
        try { _packet.Dispose(); } catch { /* ignore */ }
        try { _driver.Dispose(); } catch { /* ignore */ }
    }
}
