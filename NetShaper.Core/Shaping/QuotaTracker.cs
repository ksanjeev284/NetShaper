using System.Text.Json;
using NetShaper.Core.Policy;
using NetShaper.Core.Traffic;

namespace NetShaper.Core.Shaping;

/// <summary>
/// Accumulates per-rule byte usage from traffic samples and can request blocks when over quota.
/// </summary>
public sealed class QuotaTracker
{
    private static readonly string StateDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "NetShaper");
    private static readonly string StatePath = Path.Combine(StateDir, "quota-usage.json");

    private readonly Dictionary<Guid, QuotaEntry> _usage = new();
    private readonly Dictionary<int, (long sent, long recv)> _lastPidBytes = new();

    public QuotaTracker()
    {
        Load();
    }

    public sealed class QuotaEntry
    {
        public Guid RuleId { get; set; }
        public long BytesUsed { get; set; }
        public DateTimeOffset UpdatedUtc { get; set; } = DateTimeOffset.UtcNow;
        public DateTimeOffset PeriodStartUtc { get; set; } = DateTimeOffset.UtcNow;
    }

    public sealed record QuotaStatus(
        Guid RuleId,
        string FilterName,
        long CeilingBytes,
        long UsedBytes,
        double Percent,
        bool Exceeded,
        bool ActiveNow);

    public IReadOnlyList<QuotaStatus> GetStatuses(PolicyDocument doc)
    {
        if (!doc.QuotaEnabled) return Array.Empty<QuotaStatus>();
        var list = new List<QuotaStatus>();
        foreach (var rule in doc.Rules.Where(r => r.Kind == RuleKind.Quota))
        {
            if (rule.QuotaBytes is null or <= 0) continue;
            var filter = doc.Filters.FirstOrDefault(f => f.Id == rule.FilterId);
            var used = _usage.TryGetValue(rule.Id, out var e) ? e.BytesUsed : 0;
            var ceil = rule.QuotaBytes.Value;
            list.Add(new QuotaStatus(
                rule.Id,
                filter?.Name ?? "?",
                ceil,
                used,
                ceil > 0 ? 100.0 * used / ceil : 0,
                used >= ceil,
                rule.IsActiveNow()));
        }
        return list;
    }

    /// <summary>Fold a snapshot into usage for matching quota rules. Returns rule IDs that just exceeded.</summary>
    public List<Guid> Accumulate(PolicyDocument doc, TrafficSnapshot snap)
    {
        var newlyExceeded = new List<Guid>();
        if (!doc.QuotaEnabled) return newlyExceeded;

        foreach (var rule in doc.Rules.Where(r => r.Kind == RuleKind.Quota && r.IsActiveNow()))
        {
            if (rule.QuotaBytes is null or <= 0) continue;
            var filter = doc.Filters.FirstOrDefault(f => f.Id == rule.FilterId);
            if (filter is null) continue;

            long delta = 0;
            foreach (var pt in snap.Processes)
            {
                var ctx = new FilterMatcher.Context
                {
                    ProcessId = pt.ProcessId,
                    ProcessName = pt.ProcessName,
                    ExecutablePath = pt.ExecutablePath,
                };
                if (!FilterMatcher.MatchesFilter(filter, ctx)) continue;

                var sent = pt.BytesSent;
                var recv = pt.BytesRecv;
                if (_lastPidBytes.TryGetValue(pt.ProcessId, out var prev))
                {
                    var dOut = Math.Max(0, sent - prev.sent);
                    var dIn = Math.Max(0, recv - prev.recv);
                    delta += rule.Direction switch
                    {
                        TrafficDirection.In => dIn,
                        TrafficDirection.Out => dOut,
                        _ => dIn + dOut,
                    };
                }
                _lastPidBytes[pt.ProcessId] = (sent, recv);
            }

            if (delta <= 0) continue;

            if (!_usage.TryGetValue(rule.Id, out var entry))
            {
                entry = new QuotaEntry { RuleId = rule.Id };
                _usage[rule.Id] = entry;
            }
            var before = entry.BytesUsed;
            entry.BytesUsed += delta;
            entry.UpdatedUtc = DateTimeOffset.UtcNow;
            if (before < rule.QuotaBytes && entry.BytesUsed >= rule.QuotaBytes)
                newlyExceeded.Add(rule.Id);
        }

        Save();
        return newlyExceeded;
    }

    public void Reset(Guid? ruleId = null)
    {
        if (ruleId is Guid id)
            _usage.Remove(id);
        else
            _usage.Clear();
        Save();
    }

    public void ResetAll()
    {
        _usage.Clear();
        Save();
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(StatePath)) return;
            var list = JsonSerializer.Deserialize<List<QuotaEntry>>(File.ReadAllText(StatePath));
            if (list is null) return;
            foreach (var e in list)
                _usage[e.RuleId] = e;
        }
        catch { /* ignore */ }
    }

    private void Save()
    {
        try
        {
            Directory.CreateDirectory(StateDir);
            File.WriteAllText(StatePath, JsonSerializer.Serialize(_usage.Values.ToList(),
                new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { /* ignore */ }
    }
}
