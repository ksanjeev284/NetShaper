using System.Runtime.Versioning;
using NetShaper.Core.Dns;
using NetShaper.Core.Policy;
using NetShaper.Core.Traffic;
using NetShaper.Core.Wfp;

namespace NetShaper.Core.Shaping;

/// <summary>
/// One-shot apply of WFP + QoS from policy. Used by GUI, CLI, and Service.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PolicyEnforcer
{
    private readonly QosEnforcer _qos = new();
    private readonly QuotaTracker _quota = new();
    private readonly BandwidthShaper _shaper = new();

    public QosEnforcer Qos => _qos;
    public QuotaTracker Quota => _quota;
    public BandwidthShaper Shaper => _shaper;
    public DnsCache? Dns { get; set; }

    public sealed record EnforceResult(
        int WfpPathGroups,
        int WfpFilters,
        int QosPolicies,
        IReadOnlyList<string> Errors,
        string Summary);

    public EnforceResult ApplyAll(PolicyDocument doc, bool persistWfp, bool applyWfp = true, bool applyQos = true)
    {
        var errors = new List<string>();
        int wfpGroups = 0, wfpFilters = 0, qosCount = 0;

        // Schedule-aware: clone-ish view — disabled schedule rules treated as disabled for enforcement
        var effective = CloneWithSchedule(doc);

        if (applyWfp)
        {
            try
            {
                var mode = persistWfp ? WfpSessionMode.Persistent : WfpSessionMode.Dynamic;
                using var eng = new WfpFilterEngine(mode) { Dns = Dns ?? FilterMatcher.SharedDns };
                eng.Open();
                wfpGroups = eng.ApplyPolicy(effective);
                wfpFilters = eng.ActiveFilterCount;
            }
            catch (Exception ex)
            {
                errors.Add("WFP: " + ex.Message);
            }
        }

        if (applyQos && effective.LimiterEnabled && effective.ShaperMode != BandwidthShaperMode.Off)
        {
            try
            {
                // Prefer shaper's QoS path so resync timestamps stay consistent
                var r = _shaper.ApplyQosNow(effective);
                qosCount = r.AppliedCount;
                errors.AddRange(r.Errors.Select(e => "QoS: " + e));
            }
            catch (Exception ex)
            {
                try
                {
                    var r = _qos.Apply(effective);
                    qosCount = r.AppliedCount;
                    errors.AddRange(r.Errors.Select(e => "QoS: " + e));
                }
                catch (Exception ex2)
                {
                    errors.Add("QoS: " + ex.Message + " / " + ex2.Message);
                }
            }
        }

        var summary =
            $"WFP groups={wfpGroups} filters={wfpFilters}; QoS policies={qosCount}" +
            (errors.Count > 0 ? $"; warnings={errors.Count}" : " — ok");
        return new EnforceResult(wfpGroups, wfpFilters, qosCount, errors, summary);
    }

    /// <summary>Update quota counters; if exceeded, add temporary block rules into a working doc and re-apply WFP path blocks for those apps.</summary>
    public List<Guid> TickQuota(PolicyDocument doc, TrafficSnapshot snap, bool autoBlockViaPolicy)
    {
        var exceeded = _quota.Accumulate(doc, snap);
        if (!autoBlockViaPolicy || exceeded.Count == 0) return exceeded;

        foreach (var ruleId in exceeded)
        {
            var rule = doc.Rules.FirstOrDefault(r => r.Id == ruleId);
            if (rule is null) continue;
            var filter = doc.Filters.FirstOrDefault(f => f.Id == rule.FilterId);
            if (filter is null) continue;
            var path = FilterMatcher.ExtractAppPathContains(filter);
            if (path is null) continue;
            // Ensure a block exists for this path
            var already = doc.Rules.Any(r =>
                r.Kind == RuleKind.Block &&
                r.Notes == $"auto-quota:{ruleId:N}");
            if (already) continue;
            var br = PolicyEditor.AddBlock(doc, path, rule.Direction);
            br.Notes = $"auto-quota:{ruleId:N}";
        }
        return exceeded;
    }

    private static PolicyDocument CloneWithSchedule(PolicyDocument doc)
    {
        // Shallow: zero out Enabled on rules whose schedule is inactive
        var copy = new PolicyDocument
        {
            Version = doc.Version,
            LimiterEnabled = doc.LimiterEnabled,
            FirewallEnabled = doc.FirewallEnabled,
            PriorityEnabled = doc.PriorityEnabled,
            StatsEnabled = doc.StatsEnabled,
            QuotaEnabled = doc.QuotaEnabled,
            ScheduleEnabled = doc.ScheduleEnabled,
            LockdownEnabled = doc.LockdownEnabled,
            AskModeEnabled = doc.AskModeEnabled,
            AskIgnoreSystemProcesses = doc.AskIgnoreSystemProcesses,
            AskIncludeListeners = doc.AskIncludeListeners,
            DnsEnabled = doc.DnsEnabled,
            ShaperMode = doc.ShaperMode,
            Filters = doc.Filters,
            Rules = doc.Rules.Select(r =>
            {
                if (!doc.ScheduleEnabled || r.Schedule is null || !r.Schedule.Enabled)
                    return r;
                if (r.IsActiveNow()) return r;
                return new Rule
                {
                    Id = r.Id,
                    FilterId = r.FilterId,
                    Kind = r.Kind,
                    Direction = r.Direction,
                    Enabled = false,
                    Weight = r.Weight,
                    LimitBytesPerSec = r.LimitBytesPerSec,
                    Priority = r.Priority,
                    QuotaBytes = r.QuotaBytes,
                    Schedule = r.Schedule,
                    Notes = r.Notes,
                    CreatedUtc = r.CreatedUtc,
                    UpdatedUtc = r.UpdatedUtc,
                };
            }).ToList(),
        };
        return copy;
    }
}
