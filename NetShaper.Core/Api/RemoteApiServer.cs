using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetShaper.Core.Policy;
using NetShaper.Core.Security;
using NetShaper.Core.Shaping;
using NetShaper.Core.Wfp;

namespace NetShaper.Core.Api;

/// <summary>
/// Multi-client remote API over TLS with mandatory client certificates (mTLS).
/// Also requires API key header for defense in depth.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RemoteApiServer : IDisposable
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly ApiServices _svc;
    private readonly ConcurrentDictionary<string, ClientSession> _sessions = new();
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private X509Certificate2? _serverCert;
    private bool _disposed;

    public ApiSettings Settings { get; private set; }
    public bool IsRunning => _listener != null;
    public string? LastError { get; private set; }
    public int ActiveClients => _sessions.Count;
    public IReadOnlyCollection<ClientSession> Sessions => _sessions.Values.ToList();

    public sealed class ClientSession
    {
        public string Id { get; init; } = Guid.NewGuid().ToString("N")[..12];
        public string ClientName { get; set; } = "";
        public string Thumbprint { get; set; } = "";
        public string RemoteEndPoint { get; set; } = "";
        public DateTimeOffset ConnectedUtc { get; set; } = DateTimeOffset.UtcNow;
        public DateTimeOffset LastRequestUtc { get; set; } = DateTimeOffset.UtcNow;
        public int RequestCount { get; set; }
    }

    public RemoteApiServer(ApiServices services, ApiSettings? settings = null)
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
        CertificateManager.EnsurePki(Settings.RemoteHostName);
        _serverCert = CertificateManager.LoadServerCertificate();

        var port = Settings.RemotePort > 0 ? Settings.RemotePort : 8742;
        var ip = Settings.AllowNonLocal ? IPAddress.Any : IPAddress.Loopback;
        _listener = new TcpListener(ip, port);
        _listener.Start();
        LastError = null;
        _cts = new CancellationTokenSource();
        _loop = Task.Run(() => AcceptLoop(_cts.Token));
        Settings.RemoteEnabled = true;
        Settings.RemotePort = port;
        Settings.Save();
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { /* ignore */ }
        try { _listener?.Stop(); } catch { /* ignore */ }
        _listener = null;
        try { _loop?.Wait(2000); } catch { /* ignore */ }
        _loop = null;
        _cts?.Dispose();
        _cts = null;
        _sessions.Clear();
        _serverCert?.Dispose();
        _serverCert = null;
    }

    private async Task AcceptLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener != null)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch { await Task.Delay(50, ct).ConfigureAwait(false); continue; }

            _ = Task.Run(() => HandleClient(client, ct), ct);
        }
    }

    private async Task HandleClient(TcpClient tcp, CancellationToken ct)
    {
        ClientSession? session = null;
        try
        {
            using (tcp)
            using (var net = tcp.GetStream())
            using (var ssl = new SslStream(net, false, ValidateClientCertificate))
            {
                await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = _serverCert,
                    ClientCertificateRequired = true,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                }, ct).ConfigureAwait(false);

                var clientCert = ssl.RemoteCertificate as X509Certificate2
                    ?? (ssl.RemoteCertificate != null ? new X509Certificate2(ssl.RemoteCertificate) : null);

                if (!CertificateManager.IsClientAuthorized(clientCert))
                {
                    await WriteHttp(ssl, 403, new { error = "client certificate not authorized" }, ct)
                        .ConfigureAwait(false);
                    return;
                }

                session = new ClientSession
                {
                    ClientName = clientCert?.GetNameInfo(X509NameType.SimpleName, false) ?? "client",
                    Thumbprint = clientCert?.Thumbprint ?? "",
                    RemoteEndPoint = tcp.Client.RemoteEndPoint?.ToString() ?? "",
                };
                _sessions[session.Id] = session;

                // Keep-alive style: handle sequential HTTP requests on connection
                while (!ct.IsCancellationRequested && tcp.Connected)
                {
                    var req = await ReadHttpRequest(ssl, ct).ConfigureAwait(false);
                    if (req is null) break;
                    session.LastRequestUtc = DateTimeOffset.UtcNow;
                    session.RequestCount++;
                    await Dispatch(ssl, req, session, ct).ConfigureAwait(false);
                    if (!req.KeepAlive) break;
                }
            }
        }
        catch
        {
            // connection dropped
        }
        finally
        {
            if (session != null)
                _sessions.TryRemove(session.Id, out _);
        }
    }

    private bool ValidateClientCertificate(object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors)
    {
        if (cert is null) return false;
        using var c2 = new X509Certificate2(cert);
        // Accept if issued by our CA and not revoked in manifest
        try
        {
            using var ca = CertificateManager.LoadCaCertificate();
            using var ch = new X509Chain();
            ch.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            ch.ChainPolicy.CustomTrustStore.Add(ca);
            ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            if (!ch.Build(c2)) return false;
            return CertificateManager.IsClientAuthorized(c2);
        }
        catch { return false; }
    }

    private async Task Dispatch(SslStream ssl, HttpRequest req, ClientSession session, CancellationToken ct)
    {
        try
        {
            if (!AuthorizeKey(req))
            {
                await WriteHttp(ssl, 401, new { error = "unauthorized", hint = "X-NetShaper-Key" }, ct)
                    .ConfigureAwait(false);
                return;
            }

            var acl = new AccessControlStore().Load();
            if (acl.Enabled && !AccessChecker.Has(AccessRight.RemoteApi, acl))
            {
                await WriteHttp(ssl, 403, new { error = "host user lacks RemoteApi" }, ct).ConfigureAwait(false);
                return;
            }

            var path = req.Path.TrimEnd('/').ToLowerInvariant();
            var method = req.Method.ToUpperInvariant();

            if (path is "" or "/api" or "/api/v1")
            {
                await WriteHttp(ssl, 200, new
                {
                    name = "NetShaper Remote API",
                    transport = "mTLS",
                    client = session.ClientName,
                    activeClients = ActiveClients,
                }, ct).ConfigureAwait(false);
                return;
            }

            // Reuse same route surface as local API for familiarity
            object body;
            int code = 200;
            switch (path)
            {
                case "/api/v1/health" when method == "GET":
                    body = new { ok = true, time = DateTimeOffset.UtcNow, client = session.ClientName };
                    break;
                case "/api/v1/status" when method == "GET":
                    body = BuildStatus(session);
                    break;
                case "/api/v1/sessions" when method == "GET":
                    body = Sessions.Select(s => new
                    {
                        s.Id, s.ClientName, s.Thumbprint, s.RemoteEndPoint,
                        s.ConnectedUtc, s.LastRequestUtc, s.RequestCount,
                    });
                    break;
                case "/api/v1/policy" when method == "GET":
                    Require(acl, AccessRight.Monitor);
                    body = _svc.PolicyStore.LoadOrCreate();
                    break;
                case "/api/v1/policy" when method is "PUT" or "POST":
                {
                    Require(acl, AccessRight.Control);
                    var doc = JsonSerializer.Deserialize<PolicyDocument>(req.Body, JsonOpts);
                    if (doc is null) { code = 400; body = new { error = "invalid policy" }; break; }
                    _svc.PolicyStore.Save(doc);
                    body = new { ok = true, rules = doc.Rules.Count };
                    break;
                }
                case "/api/v1/rules" when method == "GET":
                {
                    Require(acl, AccessRight.Monitor);
                    var doc = _svc.PolicyStore.LoadOrCreate();
                    body = doc.Rules.Select(r =>
                    {
                        var f = doc.Filters.FirstOrDefault(x => x.Id == r.FilterId);
                        return new { r.Id, kind = r.Kind.ToString(), filter = f?.Name, r.Enabled, r.Direction };
                    });
                    break;
                }
                case "/api/v1/block" when method == "POST":
                {
                    Require(acl, AccessRight.Control);
                    var b = JsonSerializer.Deserialize<PathBody>(req.Body, JsonOpts);
                    if (b?.Path is null) { code = 400; body = new { error = "path required" }; break; }
                    var doc = _svc.PolicyStore.LoadOrCreate();
                    var rule = PolicyEditor.AddBlock(doc, b.Path, ParseDir(b.Dir));
                    _svc.PolicyStore.Save(doc);
                    body = new { ok = true, ruleId = rule.Id };
                    break;
                }
                case "/api/v1/allow" when method == "POST":
                {
                    Require(acl, AccessRight.Control);
                    var b = JsonSerializer.Deserialize<PathBody>(req.Body, JsonOpts);
                    if (b?.Path is null) { code = 400; body = new { error = "path required" }; break; }
                    var doc = _svc.PolicyStore.LoadOrCreate();
                    var rule = PolicyEditor.AddAllow(doc, b.Path, ParseDir(b.Dir));
                    _svc.PolicyStore.Save(doc);
                    body = new { ok = true, ruleId = rule.Id };
                    break;
                }
                case "/api/v1/limit" when method == "POST":
                {
                    Require(acl, AccessRight.Control);
                    var b = JsonSerializer.Deserialize<LimitBody>(req.Body, JsonOpts);
                    if (b?.Path is null || b.Kbps is null or <= 0)
                    { code = 400; body = new { error = "path and kbps required" }; break; }
                    var doc = _svc.PolicyStore.LoadOrCreate();
                    var rule = PolicyEditor.AddLimit(doc, b.Path, b.Kbps.Value, ParseDir(b.Dir));
                    _svc.PolicyStore.Save(doc);
                    body = new { ok = true, ruleId = rule.Id };
                    break;
                }
                case "/api/v1/apply-all" when method == "POST":
                case "/api/v1/apply-wfp" when method == "POST":
                case "/api/v1/apply-qos" when method == "POST":
                {
                    Require(acl, AccessRight.Control);
                    var wfp = path.Contains("wfp") || path.Contains("all");
                    var qos = path.Contains("qos") || path.Contains("all");
                    body = Apply(wfp, qos);
                    break;
                }
                case "/api/v1/traffic" when method == "GET":
                {
                    Require(acl, AccessRight.Monitor);
                    if (_svc.Sampler is null) { code = 503; body = new { error = "no sampler" }; break; }
                    var snap = _svc.Sampler.Sample(true);
                    body = new
                    {
                        snap.Timestamp,
                        snap.TotalBitsPerSecIn,
                        snap.TotalBitsPerSecOut,
                        processes = snap.Processes.Take(40),
                        connections = snap.Connections.Take(80),
                    };
                    break;
                }
                case "/api/v1/clients" when method == "GET":
                    Require(acl, AccessRight.Control);
                    body = CertificateManager.LoadClients();
                    break;
                default:
                    if (method == "DELETE" && path.StartsWith("/api/v1/rules/"))
                    {
                        Require(acl, AccessRight.Control);
                        if (!Guid.TryParse(path["/api/v1/rules/".Length..], out var id))
                        { code = 400; body = new { error = "bad id" }; break; }
                        var doc = _svc.PolicyStore.LoadOrCreate();
                        var n = PolicyEditor.RemoveRuleById(doc, id);
                        _svc.PolicyStore.Save(doc);
                        body = new { ok = n > 0, removed = n };
                        break;
                    }
                    code = 404;
                    body = new { error = "not found", path };
                    break;
            }

            await WriteHttp(ssl, code, body, ct).ConfigureAwait(false);
        }
        catch (UnauthorizedAccessException ex)
        {
            await WriteHttp(ssl, 403, new { error = ex.Message }, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await WriteHttp(ssl, 500, new { error = ex.Message }, ct).ConfigureAwait(false);
        }
    }

    private static void Require(AccessControlDocument acl, AccessRight need)
    {
        if (acl.Enabled) AccessChecker.Require(need, acl);
    }

    private object Apply(bool wfp, bool qos)
    {
        var doc = _svc.PolicyStore.LoadOrCreate();
        var enforcer = _svc.Enforcer ?? new PolicyEnforcer { Dns = _svc.Dns };
        var r = enforcer.ApplyAll(doc, persistWfp: true, applyWfp: wfp, applyQos: qos);
        return new { ok = r.Errors.Count == 0, r.Summary, errors = r.Errors };
    }

    private object BuildStatus(ClientSession session)
    {
        var doc = _svc.PolicyStore.LoadOrCreate();
        return new
        {
            remote = true,
            mtls = true,
            client = session.ClientName,
            activeClients = ActiveClients,
            elevated = IsElevated(),
            policy = new
            {
                rules = doc.Rules.Count,
                doc.ShaperMode,
                doc.FirewallEnabled,
                doc.LimiterEnabled,
            },
        };
    }

    private bool AuthorizeKey(HttpRequest req)
    {
        if (req.Headers.TryGetValue("X-NetShaper-Key", out var k) && FixedEquals(k, Settings.ApiKey))
            return true;
        if (req.Headers.TryGetValue("Authorization", out var auth) &&
            auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) &&
            FixedEquals(auth["Bearer ".Length..].Trim(), Settings.ApiKey))
            return true;
        return false;
    }

    private static bool FixedEquals(string a, string b)
    {
        var ba = Encoding.UTF8.GetBytes(a);
        var bb = Encoding.UTF8.GetBytes(b);
        return ba.Length == bb.Length &&
               System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ba, bb);
    }

    private static TrafficDirection ParseDir(string? dir) =>
        Enum.TryParse<TrafficDirection>(dir, true, out var d) ? d : TrafficDirection.Both;

    private static bool IsElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private sealed class HttpRequest
    {
        public string Method { get; set; } = "GET";
        public string Path { get; set; } = "/";
        public Dictionary<string, string> Headers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public string Body { get; set; } = "";
        public bool KeepAlive { get; set; }
    }

    private sealed class PathBody { public string? Path { get; set; } public string? Dir { get; set; } }
    private sealed class LimitBody { public string? Path { get; set; } public long? Kbps { get; set; } public string? Dir { get; set; } }

    private static async Task<HttpRequest?> ReadHttpRequest(Stream stream, CancellationToken ct)
    {
        // Read headers
        var ms = new MemoryStream();
        var buf = new byte[1];
        var headerEnd = false;
        while (!headerEnd)
        {
            var n = await stream.ReadAsync(buf.AsMemory(0, 1), ct).ConfigureAwait(false);
            if (n == 0) return null;
            ms.WriteByte(buf[0]);
            if (ms.Length >= 4)
            {
                var a = ms.GetBuffer();
                var len = (int)ms.Length;
                if (a[len - 4] == '\r' && a[len - 3] == '\n' && a[len - 2] == '\r' && a[len - 1] == '\n')
                    headerEnd = true;
            }
            if (ms.Length > 64 * 1024) return null;
        }

        var headerText = Encoding.ASCII.GetString(ms.GetBuffer(), 0, (int)ms.Length);
        var lines = headerText.Split("\r\n", StringSplitOptions.None);
        if (lines.Length == 0) return null;
        var parts = lines[0].Split(' ');
        if (parts.Length < 2) return null;
        var req = new HttpRequest
        {
            Method = parts[0],
            Path = parts[1].Split('?')[0],
        };
        for (int i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrEmpty(line)) break;
            var c = line.IndexOf(':');
            if (c > 0)
                req.Headers[line[..c].Trim()] = line[(c + 1)..].Trim();
        }
        req.KeepAlive = req.Headers.TryGetValue("Connection", out var conn) &&
                        conn.Equals("keep-alive", StringComparison.OrdinalIgnoreCase);

        var contentLength = 0;
        if (req.Headers.TryGetValue("Content-Length", out var cl))
            int.TryParse(cl, out contentLength);
        if (contentLength > 0)
        {
            if (contentLength > 4 * 1024 * 1024) contentLength = 4 * 1024 * 1024;
            var bodyBuf = new byte[contentLength];
            var read = 0;
            while (read < contentLength)
            {
                var n = await stream.ReadAsync(bodyBuf.AsMemory(read, contentLength - read), ct)
                    .ConfigureAwait(false);
                if (n == 0) break;
                read += n;
            }
            req.Body = Encoding.UTF8.GetString(bodyBuf, 0, read);
        }
        return req;
    }

    private static async Task WriteHttp(Stream stream, int code, object body, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(body, JsonOpts);
        var bytes = Encoding.UTF8.GetBytes(json);
        var reason = code switch
        {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Error",
            _ => "OK",
        };
        var header =
            $"HTTP/1.1 {code} {reason}\r\n" +
            "Content-Type: application/json; charset=utf-8\r\n" +
            $"Content-Length: {bytes.Length}\r\n" +
            "Connection: keep-alive\r\n\r\n";
        var hb = Encoding.ASCII.GetBytes(header);
        await stream.WriteAsync(hb, ct).ConfigureAwait(false);
        await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }
}
