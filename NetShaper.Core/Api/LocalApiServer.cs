using System.Net;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetShaper.Core.Dns;
using NetShaper.Core.Policy;
using NetShaper.Core.Security;
using NetShaper.Core.Shaping;
using NetShaper.Core.Stats;
using NetShaper.Core.Traffic;
using NetShaper.Core.Wfp;

namespace NetShaper.Core.Api;

/// <summary>
/// Localhost HTTP JSON API for automation and scripting.
/// Auth: header X-NetShaper-Key or Authorization: Bearer &lt;key&gt;.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LocalApiServer : IDisposable
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly ApiServices _svc;
    private HttpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _disposed;

    public ApiSettings Settings { get; private set; }
    public bool IsRunning => _listener?.IsListening == true;
    public string? LastError { get; private set; }

    public LocalApiServer(ApiServices services, ApiSettings? settings = null)
    {
        _svc = services;
        Settings = settings ?? ApiSettings.Load();
        Settings.EnsureKey();
    }

    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        Stop();
        Settings.EnsureKey();
        if (!Settings.AllowNonLocal && Settings.Host is not ("127.0.0.1" or "localhost" or "::1"))
            Settings.Host = "127.0.0.1";

        var prefix = $"http://{Settings.Host}:{Settings.Port}/";
        _listener = new HttpListener();
        _listener.Prefixes.Add(prefix);
        try
        {
            _listener.Start();
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            throw;
        }

        LastError = null;
        _cts = new CancellationTokenSource();
        _loop = Task.Run(() => AcceptLoop(_cts.Token));
        Settings.Enabled = true;
        Settings.Save();
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { /* ignore */ }
        try
        {
            if (_listener?.IsListening == true)
                _listener.Stop();
        }
        catch { /* ignore */ }
        try { _listener?.Close(); } catch { /* ignore */ }
        _listener = null;
        try { _loop?.Wait(1500); } catch { /* ignore */ }
        _loop = null;
        _cts?.Dispose();
        _cts = null;
    }

    private async Task AcceptLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener is { IsListening: true })
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await _listener.GetContextAsync().WaitAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch (HttpListenerException) { break; }
            catch
            {
                await Task.Delay(50, ct).ConfigureAwait(false);
                continue;
            }

            _ = Task.Run(() => Handle(ctx), ct);
        }
    }

    private void Handle(HttpListenerContext ctx)
    {
        try
        {
            if (!Authorize(ctx.Request))
            {
                Write(ctx, 401, new { error = "unauthorized", hint = "Send X-NetShaper-Key header" });
                return;
            }

            // Host process user must have RemoteApi (when ACL enabled)
            var acl = new AccessControlStore().Load();
            if (acl.Enabled && !AccessChecker.Has(AccessRight.RemoteApi, acl))
            {
                Write(ctx, 403, new { error = "forbidden", detail = "Host user lacks RemoteApi right", current = AccessChecker.DescribeCurrent(acl) });
                return;
            }

            var path = ctx.Request.Url?.AbsolutePath.TrimEnd('/').ToLowerInvariant() ?? "";
            var method = ctx.Request.HttpMethod.ToUpperInvariant();

            var needControl = method is "POST" or "PUT" or "DELETE" ||
                              path.Contains("apply-", StringComparison.Ordinal);
            var needMonitor = method == "GET";
            if (acl.Enabled)
            {
                if (needControl && !AccessChecker.Has(AccessRight.Control, acl))
                {
                    Write(ctx, 403, new { error = "forbidden", detail = "requires Control right" });
                    return;
                }
                if (needMonitor && !AccessChecker.Has(AccessRight.Monitor, acl) && !AccessChecker.Has(AccessRight.Control, acl))
                {
                    Write(ctx, 403, new { error = "forbidden", detail = "requires Monitor right" });
                    return;
                }
            }

            if (path is "" or "/api" or "/api/v1")
            {
                Write(ctx, 200, new
                {
                    name = "NetShaper API",
                    version = "1",
                    endpoints = new[]
                    {
                        "GET /api/v1/health", "GET /api/v1/status", "GET /api/v1/policy",
                        "GET /api/v1/rules", "POST /api/v1/block", "POST /api/v1/allow",
                        "POST /api/v1/limit", "POST /api/v1/block-domain", "DELETE /api/v1/rules/{id}",
                        "POST /api/v1/apply-wfp", "POST /api/v1/apply-qos", "POST /api/v1/apply-all",
                        "GET /api/v1/traffic", "GET /api/v1/stats", "GET /api/v1/dns",
                    },
                });
                return;
            }

            switch (path)
            {
                case "/api/v1/health" when method == "GET":
                    Write(ctx, 200, new { ok = true, time = DateTimeOffset.UtcNow });
                    return;
                case "/api/v1/status" when method == "GET":
                    Write(ctx, 200, BuildStatus());
                    return;
                case "/api/v1/access" when method == "GET":
                {
                    var doc = new AccessControlStore().Load();
                    Write(ctx, 200, new
                    {
                        current = AccessChecker.DescribeCurrent(doc),
                        rights = AccessChecker.GetRights(doc).ToString(),
                        doc.Enabled,
                        doc.AdministratorsFullAccess,
                        entries = doc.Entries,
                    });
                    return;
                }
                case "/api/v1/policy" when method == "GET":
                    Write(ctx, 200, _svc.PolicyStore.LoadOrCreate());
                    return;
                case "/api/v1/policy" when method is "PUT" or "POST":
                {
                    var doc = ReadBody<PolicyDocument>(ctx);
                    if (doc is null) { Write(ctx, 400, new { error = "invalid policy json" }); return; }
                    _svc.PolicyStore.Save(doc);
                    Write(ctx, 200, new { ok = true, rules = doc.Rules.Count });
                    return;
                }
                case "/api/v1/rules" when method == "GET":
                {
                    var doc = _svc.PolicyStore.LoadOrCreate();
                    Write(ctx, 200, doc.Rules.Select(r =>
                    {
                        var f = doc.Filters.FirstOrDefault(x => x.Id == r.FilterId);
                        return new
                        {
                            r.Id,
                            kind = r.Kind.ToString(),
                            filter = f?.Name,
                            r.Direction,
                            r.Enabled,
                            r.LimitBytesPerSec,
                            r.Priority,
                            r.QuotaBytes,
                            active = r.IsActiveNow(),
                        };
                    }));
                    return;
                }
                case "/api/v1/block" when method == "POST":
                {
                    var body = ReadBody<PathBody>(ctx);
                    if (body?.Path is null) { Write(ctx, 400, new { error = "path required" }); return; }
                    var doc = _svc.PolicyStore.LoadOrCreate();
                    var rule = PolicyEditor.AddBlock(doc, body.Path, ParseDir(body.Dir));
                    _svc.PolicyStore.Save(doc);
                    Write(ctx, 200, new { ok = true, ruleId = rule.Id });
                    return;
                }
                case "/api/v1/allow" when method == "POST":
                {
                    var body = ReadBody<PathBody>(ctx);
                    if (body?.Path is null) { Write(ctx, 400, new { error = "path required" }); return; }
                    var doc = _svc.PolicyStore.LoadOrCreate();
                    var rule = PolicyEditor.AddAllow(doc, body.Path, ParseDir(body.Dir));
                    _svc.PolicyStore.Save(doc);
                    Write(ctx, 200, new { ok = true, ruleId = rule.Id });
                    return;
                }
                case "/api/v1/limit" when method == "POST":
                {
                    var body = ReadBody<LimitBody>(ctx);
                    if (body?.Path is null || body.Kbps is null or <= 0)
                    {
                        Write(ctx, 400, new { error = "path and kbps required" });
                        return;
                    }
                    var doc = _svc.PolicyStore.LoadOrCreate();
                    var rule = PolicyEditor.AddLimit(doc, body.Path, body.Kbps.Value, ParseDir(body.Dir));
                    _svc.PolicyStore.Save(doc);
                    Write(ctx, 200, new { ok = true, ruleId = rule.Id });
                    return;
                }
                case "/api/v1/block-domain" when method == "POST":
                {
                    var body = ReadBody<DomainBody>(ctx);
                    if (body?.Domain is null) { Write(ctx, 400, new { error = "domain required" }); return; }
                    var doc = _svc.PolicyStore.LoadOrCreate();
                    doc.DnsEnabled = true;
                    var rule = PolicyEditor.AddDomainBlock(doc, body.Domain, ParseDir(body.Dir));
                    _svc.PolicyStore.Save(doc);
                    Write(ctx, 200, new { ok = true, ruleId = rule.Id });
                    return;
                }
                case "/api/v1/apply-wfp" when method == "POST":
                    Write(ctx, 200, Apply(wfp: true, qos: false));
                    return;
                case "/api/v1/apply-qos" when method == "POST":
                    Write(ctx, 200, Apply(wfp: false, qos: true));
                    return;
                case "/api/v1/apply-all" when method == "POST":
                    Write(ctx, 200, Apply(wfp: true, qos: true));
                    return;
                case "/api/v1/traffic" when method == "GET":
                {
                    if (_svc.Sampler is null)
                    {
                        Write(ctx, 503, new { error = "sampler not available" });
                        return;
                    }
                    var snap = _svc.Sampler.Sample(includeConnections: true);
                    Write(ctx, 200, new
                    {
                        snap.Timestamp,
                        snap.TotalBitsPerSecIn,
                        snap.TotalBitsPerSecOut,
                        processes = snap.Processes.Take(50),
                        connections = snap.Connections.Take(100),
                    });
                    return;
                }
                case "/api/v1/stats" when method == "GET":
                {
                    if (_svc.Stats is null)
                    {
                        Write(ctx, 503, new { error = "stats not available" });
                        return;
                    }
                    Write(ctx, 200, _svc.Stats.GetInfo());
                    return;
                }
                case "/api/v1/dns" when method == "GET":
                {
                    var dns = _svc.Dns ?? FilterMatcher.SharedDns;
                    if (dns is null)
                    {
                        Write(ctx, 503, new { error = "dns not available" });
                        return;
                    }
                    Write(ctx, 200, new { hosts = dns.CountHosts, ips = dns.CountIps, entries = dns.Snapshot(100) });
                    return;
                }
            }

            // DELETE /api/v1/rules/{guid}
            if (method == "DELETE" && path.StartsWith("/api/v1/rules/", StringComparison.Ordinal))
            {
                var idStr = path["/api/v1/rules/".Length..];
                if (!Guid.TryParse(idStr, out var id))
                {
                    Write(ctx, 400, new { error = "invalid rule id" });
                    return;
                }
                var doc = _svc.PolicyStore.LoadOrCreate();
                var n = PolicyEditor.RemoveRuleById(doc, id);
                _svc.PolicyStore.Save(doc);
                Write(ctx, 200, new { ok = n > 0, removed = n });
                return;
            }

            Write(ctx, 404, new { error = "not found", path });
        }
        catch (Exception ex)
        {
            try { Write(ctx, 500, new { error = ex.Message }); } catch { /* ignore */ }
        }
    }

    private object Apply(bool wfp, bool qos)
    {
        if (!IsElevated())
            return new { ok = false, error = "API host process is not elevated; WFP/QoS may fail" };

        var doc = _svc.PolicyStore.LoadOrCreate();
        var enforcer = _svc.Enforcer ?? new PolicyEnforcer { Dns = _svc.Dns };
        var r = enforcer.ApplyAll(doc, persistWfp: true, applyWfp: wfp, applyQos: qos);
        return new
        {
            ok = r.Errors.Count == 0,
            r.Summary,
            r.WfpPathGroups,
            r.WfpFilters,
            r.QosPolicies,
            errors = r.Errors,
        };
    }

    private object BuildStatus()
    {
        var doc = _svc.PolicyStore.LoadOrCreate();
        return new
        {
            elevated = IsElevated(),
            api = new { Settings.Host, Settings.Port, running = IsRunning },
            policy = new
            {
                path = _svc.PolicyStore.FilePath,
                rules = doc.Rules.Count,
                filters = doc.Filters.Count,
                doc.FirewallEnabled,
                doc.LimiterEnabled,
                doc.ShaperMode,
                doc.AskModeEnabled,
                doc.LockdownEnabled,
                doc.DnsEnabled,
                doc.StatsEnabled,
            },
        };
    }

    private bool Authorize(HttpListenerRequest req)
    {
        var key = Settings.ApiKey;
        if (string.IsNullOrEmpty(key)) return false;

        var h = req.Headers["X-NetShaper-Key"];
        if (!string.IsNullOrEmpty(h) && FixedEquals(h, key)) return true;

        var auth = req.Headers["Authorization"];
        if (!string.IsNullOrEmpty(auth) && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var token = auth["Bearer ".Length..].Trim();
            if (FixedEquals(token, key)) return true;
        }

        // query ?key= for simple scripts (less secure)
        var q = req.QueryString["key"];
        if (!string.IsNullOrEmpty(q) && FixedEquals(q, key)) return true;

        return false;
    }

    private static bool FixedEquals(string a, string b)
    {
        var ba = Encoding.UTF8.GetBytes(a);
        var bb = Encoding.UTF8.GetBytes(b);
        return ba.Length == bb.Length &&
               System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ba, bb);
    }

    private static T? ReadBody<T>(HttpListenerContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding);
        var json = reader.ReadToEnd();
        if (string.IsNullOrWhiteSpace(json)) return default;
        return JsonSerializer.Deserialize<T>(json, JsonOpts);
    }

    private static void Write(HttpListenerContext ctx, int code, object body)
    {
        var json = JsonSerializer.Serialize(body, JsonOpts);
        var bytes = Encoding.UTF8.GetBytes(json);
        ctx.Response.StatusCode = code;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        ctx.Response.ContentLength64 = bytes.Length;
        ctx.Response.Headers["Access-Control-Allow-Origin"] = "null";
        ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
        ctx.Response.OutputStream.Close();
    }

    private static TrafficDirection ParseDir(string? dir)
    {
        if (string.IsNullOrWhiteSpace(dir)) return TrafficDirection.Both;
        return Enum.TryParse<TrafficDirection>(dir, true, out var d) ? d : TrafficDirection.Both;
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

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }

    private sealed class PathBody
    {
        public string? Path { get; set; }
        public string? Dir { get; set; }
    }

    private sealed class LimitBody
    {
        public string? Path { get; set; }
        public long? Kbps { get; set; }
        public string? Dir { get; set; }
    }

    private sealed class DomainBody
    {
        public string? Domain { get; set; }
        public string? Dir { get; set; }
    }
}

/// <summary>Dependencies injected into the API host.</summary>
public sealed class ApiServices
{
    public required PolicyStore PolicyStore { get; init; }
    public WindowsTrafficSampler? Sampler { get; init; }
    public PolicyEnforcer? Enforcer { get; init; }
    public StatsStore? Stats { get; init; }
    public DnsCache? Dns { get; init; }
}
