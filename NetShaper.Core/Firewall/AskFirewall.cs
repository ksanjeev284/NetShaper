using System.Diagnostics;
using NetShaper.Core.Policy;
using NetShaper.Core.Traffic;

namespace NetShaper.Core.Firewall;

public enum AskDecisionKind
{
    AllowAlways,
    BlockAlways,
    AllowOnce,
    BlockOnce,
    Skip, // don't ask again this session for this key
}

public sealed class AskRequest
{
    public required string Key { get; init; } // path or process name
    public required string ProcessName { get; init; }
    public required int ProcessId { get; init; }
    public string? ExecutablePath { get; init; }
    public string SampleRemote { get; init; } = "";
    public string SampleLocal { get; init; } = "";
    public string Protocol { get; init; } = "";
    public int ConnectionCount { get; init; }
    public DateTimeOffset FirstSeen { get; init; } = DateTimeOffset.Now;
}

public sealed class AskDecision
{
    public required string Key { get; init; }
    public AskDecisionKind Kind { get; init; }
    public DateTimeOffset DecidedAt { get; init; } = DateTimeOffset.Now;
    public int? ProcessId { get; init; } // for Once + process lifetime
}

/// <summary>
/// Detects apps that start networking without a policy Block/Allow rule (interactive Ask mode).
/// Usermode: first packets may already flow until a Block decision is applied via WFP.
/// </summary>
public sealed class AskFirewallMonitor
{
    private static readonly HashSet<string> SystemNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "smss", "csrss", "wininit", "services", "lsass", "svchost",
        "fontdrvhost", "dwm", "winlogon", "Memory Compression", "WmiPrvSE", "sihost", "taskhostw",
        "RuntimeBroker", "SearchHost", "StartMenuExperienceHost", "ShellExperienceHost",
        "SecurityHealthService", "MsMpEng", "NisSrv", "smartscreen", "ctfmon", "conhost",
        "dllhost", "backgroundTaskHost", "ApplicationFrameHost", "SystemSettings",
        "SearchIndexer", "spoolsv", "explorer", // explorer optional — still skip by default
    };

    private readonly Dictionary<string, AskDecision> _session = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _pendingKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public IReadOnlyDictionary<string, AskDecision> SessionDecisions
    {
        get { lock (_gate) return new Dictionary<string, AskDecision>(_session, StringComparer.OrdinalIgnoreCase); }
    }

    public void ClearSession()
    {
        lock (_gate)
        {
            _session.Clear();
            _pendingKeys.Clear();
        }
    }

    public void Remember(AskDecision decision)
    {
        lock (_gate)
        {
            _session[decision.Key] = decision;
            _pendingKeys.Remove(decision.Key);
        }
    }

    public void MarkPending(string key)
    {
        lock (_gate) _pendingKeys.Add(key);
    }

    public void ClearPending(string key)
    {
        lock (_gate) _pendingKeys.Remove(key);
    }

    /// <summary>Returns new AskRequests not already decided or pending.</summary>
    public List<AskRequest> FindNewAsks(PolicyDocument doc, TrafficSnapshot snap)
    {
        if (!doc.AskModeEnabled) return new List<AskRequest>();

        var results = new List<AskRequest>();
        var byPid = snap.Connections
            .GroupBy(c => c.ProcessId)
            .ToDictionary(g => g.Key, g => g.ToList());

        foreach (var pt in snap.Processes)
        {
            if (!byPid.TryGetValue(pt.ProcessId, out var conns) || conns.Count == 0)
                continue;

            if (!doc.AskIncludeListeners)
            {
                conns = conns.Where(c =>
                    c.State is "Established" or "SynSent" or "SynRcvd" ||
                    (c.Protocol.StartsWith("TCP", StringComparison.OrdinalIgnoreCase) &&
                     c.RemoteEndPoint is not ("*:*" or ""))).ToList();
                if (conns.Count == 0) continue;
            }

            var key = MakeKey(pt);
            if (string.IsNullOrWhiteSpace(key)) continue;

            if (doc.AskIgnoreSystemProcesses && IsSystemProcess(pt))
                continue;

            lock (_gate)
            {
                if (_session.ContainsKey(key) || _pendingKeys.Contains(key))
                    continue;
            }

            if (HasMatchingFirewallRule(doc, pt))
                continue;

            var sample = conns.FirstOrDefault(c => c.State == "Established") ?? conns[0];
            results.Add(new AskRequest
            {
                Key = key,
                ProcessName = pt.ProcessName,
                ProcessId = pt.ProcessId,
                ExecutablePath = pt.ExecutablePath,
                SampleRemote = sample.RemoteEndPoint,
                SampleLocal = sample.LocalEndPoint,
                Protocol = sample.Protocol,
                ConnectionCount = conns.Count,
            });
        }

        return results;
    }

    public static string MakeKey(ProcessTraffic pt)
    {
        if (!string.IsNullOrWhiteSpace(pt.ExecutablePath))
            return Path.GetFullPath(pt.ExecutablePath);
        return pt.ProcessName;
    }

    public static bool IsSystemProcess(ProcessTraffic pt)
    {
        if (SystemNames.Contains(pt.ProcessName)) return true;
        var path = pt.ExecutablePath ?? "";
        if (path.Contains(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\Windows\SystemApps\", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    public static bool HasMatchingFirewallRule(PolicyDocument doc, ProcessTraffic pt)
    {
        var ctx = new FilterMatcher.Context
        {
            ProcessId = pt.ProcessId,
            ProcessName = pt.ProcessName,
            ExecutablePath = pt.ExecutablePath,
        };

        foreach (var rule in doc.Rules.Where(r =>
                     r.Enabled && r.IsActiveNow() && r.Kind is RuleKind.Block or RuleKind.Allow))
        {
            var filter = doc.Filters.FirstOrDefault(f => f.Id == rule.FilterId);
            if (filter is null) continue;
            if (FilterMatcher.MatchesFilter(filter, ctx))
                return true;
        }
        return false;
    }

    /// <summary>Drop Once decisions whose process has exited.</summary>
    public void PruneDeadProcesses()
    {
        lock (_gate)
        {
            var dead = new List<string>();
            foreach (var (key, d) in _session)
            {
                if (d.Kind is not (AskDecisionKind.AllowOnce or AskDecisionKind.BlockOnce))
                    continue;
                if (d.ProcessId is int pid)
                {
                    try
                    {
                        using var p = Process.GetProcessById(pid);
                        if (!p.HasExited) continue;
                    }
                    catch
                    {
                        // gone
                    }
                    dead.Add(key);
                }
            }
            foreach (var k in dead)
                _session.Remove(k);
        }
    }
}
