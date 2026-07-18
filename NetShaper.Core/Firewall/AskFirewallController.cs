using System.Runtime.Versioning;
using NetShaper.Core.Policy;
using NetShaper.Core.Wfp;

namespace NetShaper.Core.Firewall;

/// <summary>
/// Applies Ask decisions to policy and optional WFP.
/// Keeps a long-lived dynamic WFP session for Once rules.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AskFirewallController : IDisposable
{
    private WfpFilterEngine? _tempEngine;
    private bool _disposed;

    public bool PreferPersistentPolicyWfp { get; set; }

    public sealed record ApplyResult(bool PolicyChanged, bool WfpApplied, string Message);

    public ApplyResult ApplyDecision(
        PolicyDocument doc,
        AskRequest request,
        AskDecisionKind kind,
        bool isElevated,
        AskFirewallMonitor monitor)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        switch (kind)
        {
            case AskDecisionKind.AllowAlways:
            {
                var path = request.ExecutablePath is { Length: > 0 } p ? p : request.ProcessName;
                PolicyEditor.AddAllow(doc, path, TrafficDirection.Both);
                monitor.Remember(new AskDecision { Key = request.Key, Kind = kind, ProcessId = request.ProcessId });
                var wfp = TryWfp(path, block: false, isElevated, permanent: true);
                return new ApplyResult(true, wfp, $"Allow always: {request.ProcessName}");
            }
            case AskDecisionKind.BlockAlways:
            {
                var path = request.ExecutablePath is { Length: > 0 } p ? p : request.ProcessName;
                PolicyEditor.AddBlock(doc, path, TrafficDirection.Both);
                monitor.Remember(new AskDecision { Key = request.Key, Kind = kind, ProcessId = request.ProcessId });
                var wfp = TryWfp(path, block: true, isElevated, permanent: true);
                return new ApplyResult(true, wfp, $"Block always: {request.ProcessName}");
            }
            case AskDecisionKind.AllowOnce:
            {
                monitor.Remember(new AskDecision
                {
                    Key = request.Key,
                    Kind = kind,
                    ProcessId = request.ProcessId,
                });
                var wfp = false;
                if (!string.IsNullOrWhiteSpace(request.ExecutablePath) && File.Exists(request.ExecutablePath))
                    wfp = TryWfp(request.ExecutablePath!, block: false, isElevated, permanent: false);
                return new ApplyResult(false, wfp, $"Allow once (session): {request.ProcessName}");
            }
            case AskDecisionKind.BlockOnce:
            {
                monitor.Remember(new AskDecision
                {
                    Key = request.Key,
                    Kind = kind,
                    ProcessId = request.ProcessId,
                });
                var wfp = false;
                if (!string.IsNullOrWhiteSpace(request.ExecutablePath) && File.Exists(request.ExecutablePath))
                    wfp = TryWfp(request.ExecutablePath!, block: true, isElevated, permanent: false);
                return new ApplyResult(false, wfp, $"Block once (session): {request.ProcessName}");
            }
            case AskDecisionKind.Skip:
            {
                monitor.Remember(new AskDecision { Key = request.Key, Kind = kind, ProcessId = request.ProcessId });
                return new ApplyResult(false, false, $"Skipped prompts for: {request.ProcessName}");
            }
            default:
                return new ApplyResult(false, false, "Unknown decision");
        }
    }

    private bool TryWfp(string path, bool block, bool isElevated, bool permanent)
    {
        if (!isElevated) return false;
        if (!Path.IsPathRooted(path) || !File.Exists(path)) return false;
        try
        {
            if (permanent)
            {
                // Full policy re-apply is done by GUI after save; still add immediate rule
                using var eng = new WfpFilterEngine(
                    PreferPersistentPolicyWfp ? WfpSessionMode.Persistent : WfpSessionMode.Dynamic);
                eng.Open();
                eng.AddAppRule(path, block, TrafficDirection.Both, tag: permanent ? "perm" : "once",
                    weight: block ? 10UL : 14UL);
                return true;
            }

            _tempEngine ??= new WfpFilterEngine(WfpSessionMode.Dynamic);
            _tempEngine.Open();
            _tempEngine.AddAppRule(path, block, TrafficDirection.Both, tag: "once", weight: block ? 10UL : 14UL);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _tempEngine?.Dispose(); } catch { /* ignore */ }
        _tempEngine = null;
    }
}
