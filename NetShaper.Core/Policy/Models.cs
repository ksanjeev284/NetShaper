namespace NetShaper.Core.Policy;

/// <summary>
/// NetShaper policy model: filters and rules with independent schema and identifiers.
/// </summary>

public enum TrafficDirection
{
    In = 1,
    Out = 2,
    Both = 3,
}

public enum RuleKind
{
    Limit,
    Priority,
    Quota,
    Block,
    Allow,
    IgnoreLimits,
    IgnoreAccounting,
}

public enum PriorityBand
{
    Lowest = 0,
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
}

public enum MatcherKind
{
    AppPathEquals,
    AppPathContains,
    ProcessIdEquals,
    ProtocolEquals,
    LocalPortInRange,
    RemotePortInRange,
    LocalAddressInRange,
    RemoteAddressInRange,
    DomainEquals,
    TagEquals,
    UserSidEquals,
    IsInternet,
    IsLocalNetwork,
    IsLoopback,
    IsForward,
}

public sealed class Matcher
{
    public MatcherKind Kind { get; set; }
    public bool Match { get; set; } = true;
    public string? StringValue { get; set; }
    public ulong? UIntValue { get; set; }
    public ushort? PortFrom { get; set; }
    public ushort? PortTo { get; set; }
    public string? Cidr { get; set; }
}

/// <summary>Local-time window when a rule is considered active.</summary>
public sealed class RuleSchedule
{
    public bool Enabled { get; set; }

    /// <summary>Start time inclusive, "HH:mm" local (24h). Null = midnight.</summary>
    public string? StartLocal { get; set; }

    /// <summary>End time exclusive, "HH:mm" local. Null = end of day. Supports overnight windows.</summary>
    public string? EndLocal { get; set; }

    /// <summary>Days of week (0=Sunday … 6=Saturday). Empty/null = every day.</summary>
    public List<int>? DaysOfWeek { get; set; }

    public bool IsActiveAt(DateTime localNow)
    {
        if (!Enabled) return true;

        if (DaysOfWeek is { Count: > 0 } days && !days.Contains((int)localNow.DayOfWeek))
            return false;

        var start = ParseHm(StartLocal) ?? TimeSpan.Zero;
        var end = ParseHm(EndLocal) ?? new TimeSpan(24, 0, 0);
        var t = localNow.TimeOfDay;

        if (end <= start)
        {
            // Overnight: e.g. 22:00–06:00
            return t >= start || t < end;
        }
        return t >= start && t < end;
    }

    private static TimeSpan? ParseHm(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        if (TimeSpan.TryParse(s, out var ts)) return ts;
        var parts = s.Split(':');
        if (parts.Length >= 2 &&
            int.TryParse(parts[0], out var h) &&
            int.TryParse(parts[1], out var m))
            return new TimeSpan(h, m, 0);
        return null;
    }
}

public sealed class Filter
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public int Weight { get; set; }
    public bool IsZone { get; set; }
    public List<Matcher> Matchers { get; set; } = new();
    public List<Guid> BaseFilterIds { get; set; } = new();
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedUtc { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class Rule
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid FilterId { get; set; }
    public RuleKind Kind { get; set; }
    public TrafficDirection Direction { get; set; } = TrafficDirection.Both;
    public bool Enabled { get; set; } = true;
    public int Weight { get; set; }

    /// <summary>Bytes/sec for Limit rules (per direction when not Both).</summary>
    public long? LimitBytesPerSec { get; set; }

    public PriorityBand? Priority { get; set; }

    /// <summary>Quota ceiling in bytes.</summary>
    public long? QuotaBytes { get; set; }

    /// <summary>Optional local-time schedule; when inactive the rule is skipped for enforcement.</summary>
    public RuleSchedule? Schedule { get; set; }

    /// <summary>User note shown in UI.</summary>
    public string? Notes { get; set; }

    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedUtc { get; set; } = DateTimeOffset.UtcNow;

    public bool IsActiveNow(DateTime? localNow = null) =>
        Enabled && (Schedule is null || Schedule.IsActiveAt(localNow ?? DateTime.Now));
}

/// <summary>
/// How limit rules are enforced (usermode engines; optional WinDivert for packet mode).
/// </summary>
public enum BandwidthShaperMode
{
    /// <summary>Store limits only; no enforcement.</summary>
    Off = 0,
    /// <summary>Windows Policy-based QoS throttle (New-NetQosPolicy). Needs admin.</summary>
    Qos = 1,
    /// <summary>QoS + soft pulse: when over measured rate, temporarily block via WFP and/or trim connections.</summary>
    Soft = 2,
    /// <summary>QoS + aggressive: kill established connections when over limit to force backoff.</summary>
    Aggressive = 3,
    /// <summary>Packet-level delay via optional WinDivert (install separately). Best smoothness.</summary>
    Packet = 4,
}

public sealed class PolicyDocument
{
    public int Version { get; set; } = 4;
    public bool LimiterEnabled { get; set; } = true;
    public bool FirewallEnabled { get; set; }
    public bool PriorityEnabled { get; set; } = true;
    public bool StatsEnabled { get; set; } = true;
    public bool QuotaEnabled { get; set; } = true;
    public bool ScheduleEnabled { get; set; } = true;

    /// <summary>Bandwidth limit enforcement engine.</summary>
    public BandwidthShaperMode ShaperMode { get; set; } = BandwidthShaperMode.Soft;

    /// <summary>
    /// When true, Apply WFP installs a catch-all outbound block and only Allow rules (and optional system allowlist) may pass.
    /// </summary>
    public bool LockdownEnabled { get; set; }

    /// <summary>
    /// Interactive firewall: prompt when a new app starts networking without a matching Block/Allow rule.
    /// </summary>
    public bool AskModeEnabled { get; set; }

    /// <summary>Skip common Windows system processes in Ask mode.</summary>
    public bool AskIgnoreSystemProcesses { get; set; } = true;

    /// <summary>Also prompt on Listen/UDP (not only Established outbound TCP).</summary>
    public bool AskIncludeListeners { get; set; }

    /// <summary>Enrich connections with hostnames and resolve domain matchers.</summary>
    public bool DnsEnabled { get; set; } = true;

    public List<Filter> Filters { get; set; } = new();
    public List<Rule> Rules { get; set; } = new();

    public static PolicyDocument CreateDefaults()
    {
        var any = new Filter { Name = "Any", Matchers = { } };
        var internet = new Filter
        {
            Name = "Internet",
            IsZone = true,
            Matchers = { new Matcher { Kind = MatcherKind.IsInternet } },
        };
        var local = new Filter
        {
            Name = "LocalNetwork",
            IsZone = true,
            Matchers = { new Matcher { Kind = MatcherKind.IsLocalNetwork } },
        };
        return new PolicyDocument
        {
            Filters = { any, internet, local },
        };
    }
}
