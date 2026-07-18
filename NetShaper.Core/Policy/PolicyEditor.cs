namespace NetShaper.Core.Policy;

/// <summary>
/// Shared helpers for CLI/GUI to mutate policy.
/// </summary>
public static class PolicyEditor
{
    public static Rule AddBlock(PolicyDocument doc, string pathOrContains, TrafficDirection dir = TrafficDirection.Both)
    {
        var isFull = IsFullPath(pathOrContains);
        doc.FirewallEnabled = true;
        var filter = new Filter
        {
            Name = isFull ? $"block:{Path.GetFileName(pathOrContains)}" : $"block:*{pathOrContains}*",
            Matchers =
            {
                new Matcher
                {
                    Kind = isFull ? MatcherKind.AppPathEquals : MatcherKind.AppPathContains,
                    StringValue = pathOrContains,
                },
            },
        };
        var rule = new Rule
        {
            FilterId = filter.Id,
            Kind = RuleKind.Block,
            Direction = dir,
            Enabled = true,
        };
        doc.Filters.Add(filter);
        doc.Rules.Add(rule);
        return rule;
    }

    public static Rule AddAllow(PolicyDocument doc, string pathOrContains, TrafficDirection dir = TrafficDirection.Both)
    {
        var isFull = IsFullPath(pathOrContains);
        doc.FirewallEnabled = true;
        var filter = new Filter
        {
            Name = isFull ? $"allow:{Path.GetFileName(pathOrContains)}" : $"allow:*{pathOrContains}*",
            Matchers =
            {
                new Matcher
                {
                    Kind = isFull ? MatcherKind.AppPathEquals : MatcherKind.AppPathContains,
                    StringValue = pathOrContains,
                },
            },
        };
        var rule = new Rule
        {
            FilterId = filter.Id,
            Kind = RuleKind.Allow,
            Direction = dir,
            Enabled = true,
        };
        doc.Filters.Add(filter);
        doc.Rules.Add(rule);
        return rule;
    }

    public static Rule AddLimit(PolicyDocument doc, string pathContains, long kbps, TrafficDirection dir = TrafficDirection.Both)
    {
        if (kbps <= 0) throw new ArgumentOutOfRangeException(nameof(kbps));
        doc.LimiterEnabled = true;
        var filter = new Filter
        {
            Name = $"limit:*{pathContains}*",
            Matchers = { new Matcher { Kind = MatcherKind.AppPathContains, StringValue = pathContains } },
        };
        var rule = new Rule
        {
            FilterId = filter.Id,
            Kind = RuleKind.Limit,
            Direction = dir,
            Enabled = true,
            LimitBytesPerSec = KbpsToBytesPerSec(kbps),
        };
        doc.Filters.Add(filter);
        doc.Rules.Add(rule);
        return rule;
    }

    public static Rule AddPriority(PolicyDocument doc, string pathContains, PriorityBand band, TrafficDirection dir = TrafficDirection.Both)
    {
        doc.PriorityEnabled = true;
        var filter = new Filter
        {
            Name = $"priority:*{pathContains}*",
            Matchers = { new Matcher { Kind = MatcherKind.AppPathContains, StringValue = pathContains } },
        };
        var rule = new Rule
        {
            FilterId = filter.Id,
            Kind = RuleKind.Priority,
            Direction = dir,
            Enabled = true,
            Priority = band,
        };
        doc.Filters.Add(filter);
        doc.Rules.Add(rule);
        return rule;
    }

    public static Rule AddQuota(PolicyDocument doc, string pathContains, long quotaBytes, TrafficDirection dir = TrafficDirection.Both)
    {
        if (quotaBytes <= 0) throw new ArgumentOutOfRangeException(nameof(quotaBytes));
        var filter = new Filter
        {
            Name = $"quota:*{pathContains}*",
            Matchers = { new Matcher { Kind = MatcherKind.AppPathContains, StringValue = pathContains } },
        };
        var rule = new Rule
        {
            FilterId = filter.Id,
            Kind = RuleKind.Quota,
            Direction = dir,
            Enabled = true,
            QuotaBytes = quotaBytes,
        };
        doc.Filters.Add(filter);
        doc.Rules.Add(rule);
        return rule;
    }

    /// <summary>
    /// Adds an extra matcher to the filter bound to a rule (stored; WFP currently uses app-path only).
    /// </summary>
    public static bool AddMatcherToRule(PolicyDocument doc, Guid ruleId, Matcher matcher)
    {
        var rule = doc.Rules.FirstOrDefault(r => r.Id == ruleId);
        if (rule is null) return false;
        var filter = doc.Filters.FirstOrDefault(f => f.Id == rule.FilterId);
        if (filter is null || filter.IsZone) return false;
        filter.Matchers.Add(matcher);
        filter.UpdatedUtc = DateTimeOffset.UtcNow;
        rule.UpdatedUtc = DateTimeOffset.UtcNow;
        return true;
    }

    public static bool SetRuleEnabled(PolicyDocument doc, Guid ruleId, bool enabled)
    {
        var rule = doc.Rules.FirstOrDefault(r => r.Id == ruleId);
        if (rule is null) return false;
        rule.Enabled = enabled;
        rule.UpdatedUtc = DateTimeOffset.UtcNow;
        return true;
    }

    public static bool ToggleRuleEnabled(PolicyDocument doc, Guid ruleId)
    {
        var rule = doc.Rules.FirstOrDefault(r => r.Id == ruleId);
        if (rule is null) return false;
        rule.Enabled = !rule.Enabled;
        rule.UpdatedUtc = DateTimeOffset.UtcNow;
        return true;
    }

    public static bool UpdateLimitKbps(PolicyDocument doc, Guid ruleId, long kbps)
    {
        if (kbps <= 0) throw new ArgumentOutOfRangeException(nameof(kbps));
        var rule = doc.Rules.FirstOrDefault(r => r.Id == ruleId);
        if (rule is null || rule.Kind != RuleKind.Limit) return false;
        rule.LimitBytesPerSec = KbpsToBytesPerSec(kbps);
        rule.UpdatedUtc = DateTimeOffset.UtcNow;
        doc.LimiterEnabled = true;
        return true;
    }

    public static bool UpdateDirection(PolicyDocument doc, Guid ruleId, TrafficDirection dir)
    {
        var rule = doc.Rules.FirstOrDefault(r => r.Id == ruleId);
        if (rule is null) return false;
        rule.Direction = dir;
        rule.UpdatedUtc = DateTimeOffset.UtcNow;
        return true;
    }

    public static bool UpdatePriority(PolicyDocument doc, Guid ruleId, PriorityBand band)
    {
        var rule = doc.Rules.FirstOrDefault(r => r.Id == ruleId);
        if (rule is null || rule.Kind != RuleKind.Priority) return false;
        rule.Priority = band;
        rule.UpdatedUtc = DateTimeOffset.UtcNow;
        return true;
    }

    public static bool UpdateQuotaBytes(PolicyDocument doc, Guid ruleId, long quotaBytes)
    {
        if (quotaBytes <= 0) throw new ArgumentOutOfRangeException(nameof(quotaBytes));
        var rule = doc.Rules.FirstOrDefault(r => r.Id == ruleId);
        if (rule is null || rule.Kind != RuleKind.Quota) return false;
        rule.QuotaBytes = quotaBytes;
        rule.UpdatedUtc = DateTimeOffset.UtcNow;
        return true;
    }

    public static bool SetSchedule(PolicyDocument doc, Guid ruleId, RuleSchedule? schedule)
    {
        var rule = doc.Rules.FirstOrDefault(r => r.Id == ruleId);
        if (rule is null) return false;
        rule.Schedule = schedule;
        rule.UpdatedUtc = DateTimeOffset.UtcNow;
        return true;
    }

    public static bool SetNotes(PolicyDocument doc, Guid ruleId, string? notes)
    {
        var rule = doc.Rules.FirstOrDefault(r => r.Id == ruleId);
        if (rule is null) return false;
        rule.Notes = notes;
        rule.UpdatedUtc = DateTimeOffset.UtcNow;
        return true;
    }

    public static Rule AddDomainBlock(PolicyDocument doc, string domain, TrafficDirection dir = TrafficDirection.Both)
    {
        if (string.IsNullOrWhiteSpace(domain)) throw new ArgumentException("domain");
        domain = domain.Trim().TrimEnd('.');
        doc.FirewallEnabled = true;
        var filter = new Filter
        {
            Name = $"block-domain:{domain}",
            Matchers = { new Matcher { Kind = MatcherKind.DomainEquals, StringValue = domain } },
        };
        var rule = new Rule
        {
            FilterId = filter.Id,
            Kind = RuleKind.Block,
            Direction = dir,
            Enabled = true,
            Notes = "domain",
        };
        doc.Filters.Add(filter);
        doc.Rules.Add(rule);
        return rule;
    }

    public static Rule AddDomainAllow(PolicyDocument doc, string domain, TrafficDirection dir = TrafficDirection.Both)
    {
        if (string.IsNullOrWhiteSpace(domain)) throw new ArgumentException("domain");
        domain = domain.Trim().TrimEnd('.');
        doc.FirewallEnabled = true;
        var filter = new Filter
        {
            Name = $"allow-domain:{domain}",
            Matchers = { new Matcher { Kind = MatcherKind.DomainEquals, StringValue = domain } },
        };
        var rule = new Rule
        {
            FilterId = filter.Id,
            Kind = RuleKind.Allow,
            Direction = dir,
            Enabled = true,
            Notes = "domain",
        };
        doc.Filters.Add(filter);
        doc.Rules.Add(rule);
        return rule;
    }

    public static Rule AddIgnoreLimits(PolicyDocument doc, string pathContains, TrafficDirection dir = TrafficDirection.Both)
    {
        var filter = new Filter
        {
            Name = $"ignore-limits:*{pathContains}*",
            Matchers = { new Matcher { Kind = MatcherKind.AppPathContains, StringValue = pathContains } },
        };
        var rule = new Rule
        {
            FilterId = filter.Id,
            Kind = RuleKind.IgnoreLimits,
            Direction = dir,
            Enabled = true,
        };
        doc.Filters.Add(filter);
        doc.Rules.Add(rule);
        return rule;
    }

    public static int RemoveRulesMatching(PolicyDocument doc, string query, RuleKind? kind = null)
    {
        var q = query ?? "";
        var candidates = doc.Filters
            .Where(f => !f.IsZone)
            .Where(f => f.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                        f.Matchers.Any(m => (m.StringValue ?? "").Contains(q, StringComparison.OrdinalIgnoreCase)))
            .Select(f => f.Id)
            .ToHashSet();

        var removed = doc.Rules.RemoveAll(r =>
            candidates.Contains(r.FilterId) && (kind is null || r.Kind == kind));
        var used = doc.Rules.Select(r => r.FilterId).ToHashSet();
        doc.Filters.RemoveAll(f => !f.IsZone && !used.Contains(f.Id) && candidates.Contains(f.Id));
        return removed;
    }

    /// <summary>CLI-style unblock: remove matching Block rules only.</summary>
    public static int Unblock(PolicyDocument doc, string query) =>
        RemoveRulesMatching(doc, query, RuleKind.Block);

    public static int RemoveRuleById(PolicyDocument doc, Guid ruleId)
    {
        var rule = doc.Rules.FirstOrDefault(r => r.Id == ruleId);
        if (rule is null) return 0;
        doc.Rules.Remove(rule);
        if (doc.Rules.All(r => r.FilterId != rule.FilterId))
        {
            var f = doc.Filters.FirstOrDefault(x => x.Id == rule.FilterId);
            if (f is not null && !f.IsZone)
                doc.Filters.Remove(f);
        }
        return 1;
    }

    public static string ToJson(PolicyDocument doc) =>
        System.Text.Json.JsonSerializer.Serialize(doc, new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
            Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
        });

    public static long KbpsToBytesPerSec(long kbps) => kbps * 1000 / 8;

    public static long BytesPerSecToKbps(long bytesPerSec) => bytesPerSec * 8 / 1000;

    private static bool IsFullPath(string pathOrContains) =>
        Path.IsPathRooted(pathOrContains) && File.Exists(pathOrContains);
}
