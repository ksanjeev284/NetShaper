using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using NetShaper.Core.Policy;

namespace NetShaper.Core.Shaping;

/// <summary>
/// Applies Limit/Priority rules via Windows Policy-based QoS (NetQos).
/// Requires Administrator. Uses PowerShell New-NetQosPolicy / Remove-NetQosPolicy.
/// Uses documented Windows Policy-based QoS (New-NetQosPolicy).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class QosEnforcer
{
    public const string PolicyNamePrefix = "NetShaper-";

    private static readonly string StateDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "NetShaper");
    private static readonly string StatePath = Path.Combine(StateDir, "qos-policies.json");

    public sealed record AppliedQos(
        Guid RuleId,
        string PolicyName,
        string AppMatch,
        long? ThrottleBitsPerSec,
        int? Dscp,
        string Detail);

    public IReadOnlyList<AppliedQos> LastApplied { get; private set; } = Array.Empty<AppliedQos>();

    /// <summary>Sync NetQos policies to match current document limit/priority rules that are active now.</summary>
    public QosApplyResult Apply(PolicyDocument doc)
    {
        var desired = new List<AppliedQos>();
        var errors = new List<string>();

        // Clear our previous policies first for clean rebuild
        ClearOurPolicies(errors);

        if (doc.LimiterEnabled)
        {
            foreach (var rule in doc.Rules.Where(r => r.Kind == RuleKind.Limit && r.IsActiveNow()))
            {
                if (rule.LimitBytesPerSec is null or <= 0) continue;
                var filter = doc.Filters.FirstOrDefault(f => f.Id == rule.FilterId);
                if (filter is null) continue;
                if (!TryResolveAppMatch(filter, out var appMatch))
                {
                    errors.Add($"Limit {filter.Name}: no app path matcher for QoS.");
                    continue;
                }

                var bits = rule.LimitBytesPerSec.Value * 8;
                // Direction: NetQos throttle is bidirectional for AppPath; still create policy
                var name = PolicyNamePrefix + "L-" + rule.Id.ToString("N")[..12];
                var ps = BuildNewThrottlePolicy(name, appMatch, bits);
                if (RunPowerShell(ps, out var err))
                {
                    desired.Add(new AppliedQos(rule.Id, name, appMatch, bits, null,
                        $"{bits / 1000.0:0} kbps throttle → {appMatch}"));
                }
                else
                {
                    errors.Add($"Limit {filter.Name}: {err}");
                }
            }
        }

        if (doc.PriorityEnabled)
        {
            foreach (var rule in doc.Rules.Where(r => r.Kind == RuleKind.Priority && r.IsActiveNow()))
            {
                var filter = doc.Filters.FirstOrDefault(f => f.Id == rule.FilterId);
                if (filter is null) continue;
                if (!TryResolveAppMatch(filter, out var appMatch))
                {
                    errors.Add($"Priority {filter.Name}: no app path matcher.");
                    continue;
                }
                var dscp = MapDscp(rule.Priority ?? PriorityBand.Normal);
                var name = PolicyNamePrefix + "P-" + rule.Id.ToString("N")[..12];
                var ps = BuildNewDscpPolicy(name, appMatch, dscp);
                if (RunPowerShell(ps, out var err))
                {
                    desired.Add(new AppliedQos(rule.Id, name, appMatch, null, dscp,
                        $"DSCP {dscp} ({rule.Priority}) → {appMatch}"));
                }
                else
                {
                    errors.Add($"Priority {filter.Name}: {err}");
                }
            }
        }

        LastApplied = desired;
        SaveState(desired.Select(d => d.PolicyName).ToList());
        return new QosApplyResult(desired.Count, errors);
    }

    public int ClearOurPolicies(List<string>? errors = null)
    {
        var names = LoadState();
        // Also discover any NetShaper-* via Get-NetQosPolicy
        try
        {
            if (RunPowerShell(
                    "Get-NetQosPolicy | Where-Object { $_.Name -like 'NetShaper-*' } | Select-Object -ExpandProperty Name",
                    out var output, out _))
            {
                foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (line.StartsWith(PolicyNamePrefix, StringComparison.OrdinalIgnoreCase) &&
                        !names.Contains(line, StringComparer.OrdinalIgnoreCase))
                        names.Add(line);
                }
            }
        }
        catch { /* ignore discovery failures */ }

        int removed = 0;
        foreach (var name in names.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var safe = name.Replace("'", "''");
            if (RunPowerShell($"Remove-NetQosPolicy -Name '{safe}' -Confirm:$false -ErrorAction SilentlyContinue", out var err))
                removed++;
            else
                errors?.Add($"Remove {name}: {err}");
        }
        SaveState(new List<string>());
        LastApplied = Array.Empty<AppliedQos>();
        return removed;
    }

    public string StatusText()
    {
        var names = LoadState();
        var sb = new StringBuilder();
        sb.AppendLine($"Tracked QoS policies: {names.Count}");
        foreach (var n in names)
            sb.AppendLine("  " + n);
        foreach (var a in LastApplied)
            sb.AppendLine("  " + a.Detail);
        return sb.ToString().TrimEnd();
    }

    private static string BuildNewThrottlePolicy(string name, string appMatch, long bitsPerSec)
    {
        var n = name.Replace("'", "''");
        var app = appMatch.Replace("'", "''");
        // AppPathNameMatchCondition expects file name like chrome.exe
        return $"""
            New-NetQosPolicy -Name '{n}' -AppPathNameMatchCondition '{app}' `
              -IPProtocolMatchCondition Both -NetworkProfile All `
              -ThrottleRateActionBitsPerSecond {bitsPerSec} -ErrorAction Stop | Out-Null
            """;
    }

    private static string BuildNewDscpPolicy(string name, string appMatch, int dscp)
    {
        var n = name.Replace("'", "''");
        var app = appMatch.Replace("'", "''");
        return $"""
            New-NetQosPolicy -Name '{n}' -AppPathNameMatchCondition '{app}' `
              -IPProtocolMatchCondition Both -NetworkProfile All `
              -DSCPAction {dscp} -ErrorAction Stop | Out-Null
            """;
    }

    private static int MapDscp(PriorityBand band) => band switch
    {
        PriorityBand.Critical => 46, // EF
        PriorityBand.High => 34,     // AF41
        PriorityBand.Normal => 0,
        PriorityBand.Low => 8,
        PriorityBand.Lowest => 0,
        _ => 0,
    };

    private static bool TryResolveAppMatch(Filter filter, out string appMatch)
    {
        appMatch = "";
        foreach (var m in filter.Matchers)
        {
            if (m.Kind == MatcherKind.AppPathEquals && !string.IsNullOrWhiteSpace(m.StringValue))
            {
                appMatch = Path.GetFileName(m.StringValue);
                return !string.IsNullOrWhiteSpace(appMatch);
            }
            if (m.Kind == MatcherKind.AppPathContains && !string.IsNullOrWhiteSpace(m.StringValue))
            {
                var frag = m.StringValue!;
                // Prefer live process path
                foreach (var p in Process.GetProcesses())
                {
                    try
                    {
                        var path = p.MainModule?.FileName;
                        if (path != null &&
                            (path.Contains(frag, StringComparison.OrdinalIgnoreCase) ||
                             p.ProcessName.Contains(frag, StringComparison.OrdinalIgnoreCase)))
                        {
                            appMatch = Path.GetFileName(path);
                            return true;
                        }
                    }
                    catch { /* access denied */ }
                    finally { p.Dispose(); }
                }
                // Fallback: treat fragment as exe stem
                appMatch = frag.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    ? Path.GetFileName(frag)
                    : frag + ".exe";
                return true;
            }
        }
        return false;
    }

    private static bool RunPowerShell(string script, out string error) =>
        RunPowerShell(script, out _, out error);

    private static bool RunPowerShell(string script, out string stdout, out string error)
    {
        stdout = "";
        error = "";
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -",
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is null)
            {
                error = "Failed to start PowerShell.";
                return false;
            }
            p.StandardInput.WriteLine(script);
            p.StandardInput.Close();
            stdout = p.StandardOutput.ReadToEnd();
            var stderr = p.StandardError.ReadToEnd();
            p.WaitForExit(60_000);
            if (p.ExitCode != 0)
            {
                error = string.IsNullOrWhiteSpace(stderr) ? $"exit {p.ExitCode}: {stdout}" : stderr.Trim();
                // Soft success if policy already exists
                if (error.Contains("already exists", StringComparison.OrdinalIgnoreCase))
                    return true;
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static List<string> LoadState()
    {
        try
        {
            if (!File.Exists(StatePath)) return new List<string>();
            return JsonSerializer.Deserialize<List<string>>(File.ReadAllText(StatePath)) ?? new();
        }
        catch { return new List<string>(); }
    }

    private static void SaveState(List<string> names)
    {
        try
        {
            Directory.CreateDirectory(StateDir);
            File.WriteAllText(StatePath, JsonSerializer.Serialize(names, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { /* ignore */ }
    }
}

public sealed record QosApplyResult(int AppliedCount, IReadOnlyList<string> Errors);
