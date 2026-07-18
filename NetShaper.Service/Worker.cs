using System.Runtime.Versioning;
using System.Security.Principal;
using NetShaper.Core.Api;
using NetShaper.Core.Dns;
using NetShaper.Core.Policy;
using NetShaper.Core.Shaping;
using NetShaper.Core.Stats;
using NetShaper.Core.Traffic;

namespace NetShaper.Service;

/// <summary>
/// Hosted worker: traffic sample, bandwidth shaper tick, quota, WFP+QoS on policy change.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class Worker : BackgroundService
{
    private readonly ILogger<Worker> _log;
    private readonly PolicyStore _store = new();
    private readonly WindowsTrafficSampler _sampler = new();
    private readonly PolicyEnforcer _enforcer = new();
    private readonly StatsStore _stats = new();
    private readonly DnsCache _dns = new();
    private LocalApiServer? _api;
    private RemoteApiServer? _remoteApi;
    private DateTime _lastPolicyWrite = DateTime.MinValue;

    public Worker(ILogger<Worker> log) => _log = log;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var policy = _store.LoadOrCreate();
        _log.LogInformation(
            "NetShaper service starting. Policy={Path} filters={F} rules={R} shaper={S}",
            _store.FilePath, policy.Filters.Count, policy.Rules.Count, policy.ShaperMode);

        FilterMatcher.SharedDns = _dns;
        _enforcer.Dns = _dns;
        if (policy.DnsEnabled)
        {
            _dns.StartBackground();
            _dns.RefreshFromSystemDnsCache();
        }

        TryStartApi();
        TryEnforce(policy, force: true);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var snap = _sampler.Sample(includeConnections: true);
                _log.LogInformation(
                    "Traffic: apps={N} down={D:F0}bps up={U:F0}bps",
                    snap.Processes.Count, snap.TotalBitsPerSecIn, snap.TotalBitsPerSecOut);

                policy = _store.LoadOrCreate();
                if (policy.StatsEnabled)
                {
                    try { _stats.Record(snap, includeProcesses: true); }
                    catch (Exception ex) { _log.LogWarning(ex, "Stats record failed"); }
                }

                if (policy.DnsEnabled)
                {
                    foreach (var c in snap.Connections)
                        _dns.ObserveRemoteEndPoint(c.RemoteEndPoint);
                }
                var write = File.Exists(_store.FilePath)
                    ? File.GetLastWriteTimeUtc(_store.FilePath)
                    : DateTime.MinValue;
                if (write > _lastPolicyWrite)
                    TryEnforce(policy, force: true);

                var elevated = IsElevated();
                if (policy.LimiterEnabled && policy.ShaperMode != BandwidthShaperMode.Off)
                {
                    var tick = _enforcer.Shaper.Tick(policy, snap, elevated, snap.Connections);
                    if (tick.SoftActions > 0 || tick.KilledConnections > 0 || tick.QosSynced)
                        _log.LogInformation("Shaper: {Summary}", tick.Summary);
                    foreach (var m in tick.Messages.Take(5))
                        _log.LogDebug("{Msg}", m);
                }

                var exceeded = _enforcer.TickQuota(policy, snap, autoBlockViaPolicy: true);
                if (exceeded.Count > 0)
                {
                    _store.Save(policy);
                    _log.LogWarning("Quota exceeded for {Count} rule(s); auto-block rules added", exceeded.Count);
                    TryEnforce(policy, force: true);
                }
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Worker loop error");
            }

            await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
        }
    }

    private void TryStartApi()
    {
        try
        {
            var apiSettings = ApiSettings.Load();
            var services = new ApiServices
            {
                PolicyStore = _store,
                Sampler = _sampler,
                Enforcer = _enforcer,
                Stats = _stats,
                Dns = _dns,
            };

            if (apiSettings.Enabled)
            {
                _api = new LocalApiServer(services, apiSettings);
                _api.Start();
                _log.LogInformation("Local API listening at {Url}", apiSettings.BaseUrl);
            }
            else
            {
                _log.LogInformation("Local API disabled");
            }

            if (apiSettings.RemoteEnabled)
            {
                CertificateManager.EnsurePki(apiSettings.RemoteHostName);
                _remoteApi = new RemoteApiServer(services, apiSettings);
                _remoteApi.Start();
                _log.LogInformation("Remote mTLS API on port {Port} (certs under ProgramData\\NetShaper\\certs)",
                    apiSettings.RemotePort);
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "API failed to start");
        }
    }

    private void TryEnforce(PolicyDocument policy, bool force)
    {
        try
        {
            if (force)
                _lastPolicyWrite = File.Exists(_store.FilePath)
                    ? File.GetLastWriteTimeUtc(_store.FilePath)
                    : DateTime.UtcNow;

            var r = _enforcer.ApplyAll(policy, persistWfp: true, applyWfp: true, applyQos: true);
            _log.LogInformation("Enforce: {Summary}", r.Summary);
            foreach (var e in r.Errors)
                _log.LogWarning("{Err}", e);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Enforce skipped — run service as Administrator / LocalSystem");
        }
    }

    private static bool IsElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    public override void Dispose()
    {
        try { _enforcer.Shaper.Dispose(); } catch { /* ignore */ }
        try { _stats.Dispose(); } catch { /* ignore */ }
        try { _dns.StopBackground(); } catch { /* ignore */ }
        try { _api?.Dispose(); } catch { /* ignore */ }
        try { _remoteApi?.Dispose(); } catch { /* ignore */ }
        _sampler.Dispose();
        base.Dispose();
    }
}
