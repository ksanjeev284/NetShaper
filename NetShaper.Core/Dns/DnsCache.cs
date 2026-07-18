using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace NetShaper.Core.Dns;

public sealed class DnsEntry
{
    public string Host { get; set; } = "";
    public string Ip { get; set; } = "";
    public DateTimeOffset UpdatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Source { get; set; } = ""; // cache | reverse | resolve
}

/// <summary>
/// In-memory + optional disk DNS/IP map for domain filters and UI hostnames.
/// </summary>
public sealed class DnsCache
{
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _hostToIps =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _ipToHosts =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _updated = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<string> _reverseQueue = new();
    private readonly ConcurrentDictionary<string, byte> _reverseQueued = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _persistGate = new();
    private CancellationTokenSource? _cts;
    private Task? _worker;

    private static string PersistPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "NetShaper", "dns-cache.json");

    public int CountHosts => _hostToIps.Count;
    public int CountIps => _ipToHosts.Count;
    public bool ReverseLookupEnabled { get; set; } = true;
    public int MaxReverseQueue { get; set; } = 200;

    public void StartBackground()
    {
        if (_worker != null) return;
        LoadPersist();
        _cts = new CancellationTokenSource();
        _worker = Task.Run(() => WorkerLoop(_cts.Token));
    }

    public void StopBackground()
    {
        try { _cts?.Cancel(); } catch { /* ignore */ }
        try { _worker?.Wait(2000); } catch { /* ignore */ }
        _worker = null;
        SavePersist();
    }

    public void Add(string host, string ip, string source)
    {
        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(ip)) return;
        host = host.Trim().TrimEnd('.');
        ip = ip.Trim();
        if (!IPAddress.TryParse(ip, out _)) return;

        var ips = _hostToIps.GetOrAdd(host, _ => new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase));
        ips[ip] = 0;
        var hosts = _ipToHosts.GetOrAdd(ip, _ => new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase));
        hosts[host] = 0;
        _updated[ip] = DateTimeOffset.UtcNow;
        _updated["h:" + host] = DateTimeOffset.UtcNow;
    }

    public IReadOnlyList<string> GetIpsForHost(string hostOrDomain)
    {
        if (string.IsNullOrWhiteSpace(hostOrDomain)) return Array.Empty<string>();
        var q = hostOrDomain.Trim().TrimEnd('.');
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (_hostToIps.TryGetValue(q, out var exact))
            foreach (var ip in exact.Keys) set.Add(ip);

        // suffix match: domain.com matches a.b.domain.com
        foreach (var kv in _hostToIps)
        {
            if (kv.Key.Equals(q, StringComparison.OrdinalIgnoreCase) ||
                kv.Key.EndsWith("." + q, StringComparison.OrdinalIgnoreCase))
            {
                foreach (var ip in kv.Value.Keys) set.Add(ip);
            }
        }
        return set.ToList();
    }

    public IReadOnlyList<string> GetHostsForIp(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return Array.Empty<string>();
        return _ipToHosts.TryGetValue(ip.Trim(), out var h) ? h.Keys.ToList() : Array.Empty<string>();
    }

    public string? BestHostForIp(string ip)
    {
        var hosts = GetHostsForIp(ip);
        return hosts.OrderBy(h => h.Length).FirstOrDefault();
    }

    public string? ResolveHostHint(string? remoteEndPoint)
    {
        if (!TryParseIp(remoteEndPoint, out var ip)) return null;
        return BestHostForIp(ip);
    }

    public bool DomainMatches(string domainPattern, string? remoteEndPoint, string? hostHint = null)
    {
        if (string.IsNullOrWhiteSpace(domainPattern)) return false;
        var d = domainPattern.Trim().TrimEnd('.');

        if (!string.IsNullOrEmpty(hostHint) && HostMatchesDomain(hostHint, d))
            return true;

        if (remoteEndPoint != null && remoteEndPoint.Contains(d, StringComparison.OrdinalIgnoreCase))
            return true;

        if (!TryParseIp(remoteEndPoint, out var ip)) return false;
        foreach (var h in GetHostsForIp(ip))
            if (HostMatchesDomain(h, d)) return true;

        // Also: if remote IP is one of the domain's resolved IPs
        foreach (var mapped in GetIpsForHost(d))
            if (mapped.Equals(ip, StringComparison.OrdinalIgnoreCase)) return true;

        return false;
    }

    public static bool HostMatchesDomain(string host, string domain)
    {
        host = host.Trim().TrimEnd('.');
        domain = domain.Trim().TrimEnd('.');
        return host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
               host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);
    }

    public void ObserveRemoteEndPoint(string? remoteEndPoint)
    {
        if (!TryParseIp(remoteEndPoint, out var ip)) return;
        if (IPAddress.TryParse(ip, out var addr))
        {
            if (IPAddress.IsLoopback(addr)) return;
            if (addr.AddressFamily == AddressFamily.InterNetwork)
            {
                var b = addr.GetAddressBytes();
                if (b[0] == 10 || b[0] == 127 || (b[0] == 192 && b[1] == 168) ||
                    (b[0] == 172 && b[1] >= 16 && b[1] <= 31))
                    return; // skip reverse on private by default for noise
            }
        }
        if (_ipToHosts.ContainsKey(ip)) return;
        if (!ReverseLookupEnabled) return;
        if (_reverseQueued.Count >= MaxReverseQueue) return;
        if (_reverseQueued.TryAdd(ip, 0))
            _reverseQueue.Enqueue(ip);
    }

    public void RefreshFromSystemDnsCache()
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                foreach (var (host, ip) in WindowsDnsCacheReader.ReadCache())
                    Add(host, ip, "cache");
            }
        }
        catch
        {
            // dnsapi may fail on some builds
        }
    }

    public async Task ResolveHostAsync(string host, CancellationToken ct = default)
    {
        try
        {
            var entry = await System.Net.Dns.GetHostEntryAsync(host, ct).ConfigureAwait(false);
            foreach (var a in entry.AddressList)
                Add(host, a.ToString(), "resolve");
        }
        catch
        {
            // NXDOMAIN etc.
        }
    }

    public IReadOnlyList<DnsEntry> Snapshot(int max = 500)
    {
        var list = new List<DnsEntry>();
        foreach (var kv in _ipToHosts.Take(max * 2))
        {
            foreach (var h in kv.Value.Keys)
            {
                list.Add(new DnsEntry
                {
                    Ip = kv.Key,
                    Host = h,
                    UpdatedUtc = _updated.TryGetValue(kv.Key, out var t) ? t : DateTimeOffset.UtcNow,
                    Source = "map",
                });
                if (list.Count >= max) return list;
            }
        }
        return list.OrderByDescending(e => e.UpdatedUtc).ToList();
    }

    public void Clear()
    {
        _hostToIps.Clear();
        _ipToHosts.Clear();
        _updated.Clear();
        while (_reverseQueue.TryDequeue(out _)) { }
        _reverseQueued.Clear();
    }

    private async Task WorkerLoop(CancellationToken ct)
    {
        var lastCache = DateTime.MinValue;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (DateTime.UtcNow - lastCache > TimeSpan.FromSeconds(30))
                {
                    RefreshFromSystemDnsCache();
                    lastCache = DateTime.UtcNow;
                    SavePersist();
                }

                // drain reverse queue
                for (int i = 0; i < 5 && _reverseQueue.TryDequeue(out var ip); i++)
                {
                    _reverseQueued.TryRemove(ip, out _);
                    try
                    {
                        var entry = await System.Net.Dns.GetHostEntryAsync(ip, ct).ConfigureAwait(false);
                        var name = entry.HostName;
                        if (!string.IsNullOrWhiteSpace(name))
                            Add(name, ip, "reverse");
                    }
                    catch
                    {
                        // no PTR
                    }
                    await Task.Delay(50, ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { break; }
            catch { /* continue */ }

            try { await Task.Delay(500, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    private void LoadPersist()
    {
        try
        {
            if (!File.Exists(PersistPath)) return;
            var list = JsonSerializer.Deserialize<List<DnsEntry>>(File.ReadAllText(PersistPath));
            if (list is null) return;
            foreach (var e in list.Take(2000))
                Add(e.Host, e.Ip, e.Source);
        }
        catch { /* ignore */ }
    }

    private void SavePersist()
    {
        try
        {
            lock (_persistGate)
            {
                var dir = Path.GetDirectoryName(PersistPath)!;
                Directory.CreateDirectory(dir);
                var list = Snapshot(1500);
                File.WriteAllText(PersistPath, JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true }));
            }
        }
        catch { /* ignore */ }
    }

    public static bool TryParseIp(string? endpoint, out string ip)
    {
        ip = "";
        if (string.IsNullOrWhiteSpace(endpoint) || endpoint is "*:*") return false;
        if (endpoint.StartsWith('['))
        {
            var close = endpoint.IndexOf(']');
            if (close < 1) return false;
            ip = endpoint[1..close];
            return IPAddress.TryParse(ip, out _);
        }
        var idx = endpoint.LastIndexOf(':');
        var candidate = idx > 0 ? endpoint[..idx] : endpoint;
        if (!IPAddress.TryParse(candidate, out _)) return false;
        ip = candidate;
        return true;
    }
}
