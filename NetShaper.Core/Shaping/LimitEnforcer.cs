using NetShaper.Core.Policy;

namespace NetShaper.Core.Shaping;

/// <summary>
/// Lists active limit rules. Enforcement is <see cref="BandwidthShaper"/> (QoS + soft/aggressive).
/// </summary>
public sealed class LimitEnforcer
{
    public sealed record ActiveLimit(
        Guid RuleId,
        Guid FilterId,
        string FilterName,
        long BytesPerSec,
        TrafficDirection Direction,
        bool ScheduleActive,
        IReadOnlyList<string> MatcherSummary);

    public IReadOnlyList<ActiveLimit> GetActiveLimits(PolicyDocument doc)
    {
        if (!doc.LimiterEnabled)
            return Array.Empty<ActiveLimit>();

        var list = new List<ActiveLimit>();
        foreach (var rule in doc.Rules.Where(r => r.Enabled && r.Kind == RuleKind.Limit))
        {
            if (rule.LimitBytesPerSec is null or <= 0) continue;
            var filter = doc.Filters.FirstOrDefault(f => f.Id == rule.FilterId);
            if (filter == null) continue;
            list.Add(new ActiveLimit(
                rule.Id,
                filter.Id,
                filter.Name,
                rule.LimitBytesPerSec.Value,
                rule.Direction,
                rule.IsActiveNow(),
                filter.Matchers.Select(DescribeMatcher).ToList()));
        }
        return list;
    }

    public string ExplainGap(PolicyDocument? doc = null)
    {
        var mode = doc?.ShaperMode ?? BandwidthShaperMode.Soft;
        return mode switch
        {
            BandwidthShaperMode.Off =>
                "Shaper is Off — limits are stored only. Set mode to QoS/Soft/Aggressive in Settings.",
            BandwidthShaperMode.Qos =>
                "Mode QoS: Windows NetQos throttle (admin Apply QoS / auto resync). No connection kill.",
            BandwidthShaperMode.Soft =>
                "Mode Soft: NetQos (admin) + when measured rate exceeds limit, short WFP block pulse and light connection trim.",
            BandwidthShaperMode.Aggressive =>
                "Mode Aggressive: NetQos (admin) + kill established TCP when over limit to force backoff.",
            BandwidthShaperMode.Packet =>
                "Mode Packet: WinDivert packet delay (admin + install-windivert.ps1). Falls back if DLL missing.",
            _ => "Bandwidth shaper active.",
        };
    }

    private static string DescribeMatcher(Matcher m) => m.Kind switch
    {
        MatcherKind.AppPathEquals => $"path=={m.StringValue}",
        MatcherKind.AppPathContains => $"path*={m.StringValue}",
        MatcherKind.ProcessIdEquals => $"pid={m.UIntValue}",
        MatcherKind.RemotePortInRange => $"rport={m.PortFrom}-{m.PortTo}",
        MatcherKind.LocalPortInRange => $"lport={m.PortFrom}-{m.PortTo}",
        MatcherKind.DomainEquals => $"domain={m.StringValue}",
        MatcherKind.IsInternet => "zone:internet",
        MatcherKind.IsLocalNetwork => "zone:local",
        _ => m.Kind.ToString(),
    };
}
