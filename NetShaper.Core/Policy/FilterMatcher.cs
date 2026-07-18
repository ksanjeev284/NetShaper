using System.Net;
using System.Net.Sockets;
using NetShaper.Core.Dns;

namespace NetShaper.Core.Policy;

/// <summary>Evaluates filter matchers against process/connection context.</summary>
public static class FilterMatcher
{
    /// <summary>Optional global DNS map used for DomainEquals (set by GUI/service).</summary>
    public static DnsCache? SharedDns { get; set; }

    public sealed class Context
    {
        public int ProcessId { get; init; }
        public string ProcessName { get; init; } = "";
        public string? ExecutablePath { get; init; }
        public string? Protocol { get; init; }
        public string? LocalEndPoint { get; init; }
        public string? RemoteEndPoint { get; init; }
        public string? RemoteHostHint { get; init; }
    }

    public static bool MatchesFilter(Filter filter, Context ctx)
    {
        if (filter.Matchers.Count == 0)
            return true; // "Any"

        foreach (var m in filter.Matchers)
        {
            var hit = Evaluate(m, ctx);
            if (m.Match ? !hit : hit)
                return false;
        }
        return true;
    }

    public static bool Evaluate(Matcher m, Context ctx) => m.Kind switch
    {
        MatcherKind.AppPathEquals =>
            !string.IsNullOrEmpty(ctx.ExecutablePath) &&
            string.Equals(ctx.ExecutablePath, m.StringValue, StringComparison.OrdinalIgnoreCase),

        MatcherKind.AppPathContains =>
            (!string.IsNullOrEmpty(ctx.ExecutablePath) &&
             ctx.ExecutablePath.Contains(m.StringValue ?? "", StringComparison.OrdinalIgnoreCase)) ||
            ctx.ProcessName.Contains(m.StringValue ?? "", StringComparison.OrdinalIgnoreCase),

        MatcherKind.ProcessIdEquals =>
            m.UIntValue is ulong pid && (ulong)ctx.ProcessId == pid,

        MatcherKind.ProtocolEquals =>
            !string.IsNullOrEmpty(ctx.Protocol) &&
            ctx.Protocol.Equals(m.StringValue, StringComparison.OrdinalIgnoreCase),

        MatcherKind.LocalPortInRange => PortInRange(ctx.LocalEndPoint, m.PortFrom, m.PortTo),
        MatcherKind.RemotePortInRange => PortInRange(ctx.RemoteEndPoint, m.PortFrom, m.PortTo),

        MatcherKind.LocalAddressInRange => AddrInCidr(ctx.LocalEndPoint, m.Cidr ?? m.StringValue),
        MatcherKind.RemoteAddressInRange => AddrInCidr(ctx.RemoteEndPoint, m.Cidr ?? m.StringValue),

        MatcherKind.DomainEquals =>
            !string.IsNullOrEmpty(m.StringValue) &&
            (SharedDns?.DomainMatches(m.StringValue!, ctx.RemoteEndPoint, ctx.RemoteHostHint) == true ||
             (ctx.RemoteHostHint?.Contains(m.StringValue!, StringComparison.OrdinalIgnoreCase) ?? false) ||
             (ctx.RemoteEndPoint?.Contains(m.StringValue!, StringComparison.OrdinalIgnoreCase) ?? false)),

        MatcherKind.IsLoopback => IsLoopback(ctx.RemoteEndPoint) || IsLoopback(ctx.LocalEndPoint),
        MatcherKind.IsLocalNetwork => IsPrivate(ctx.RemoteEndPoint),
        MatcherKind.IsInternet => !IsLoopback(ctx.RemoteEndPoint) && !IsPrivate(ctx.RemoteEndPoint) &&
                                  !string.IsNullOrEmpty(ctx.RemoteEndPoint) && ctx.RemoteEndPoint != "*:*",

        // Not evaluated without more context — treat as match so rule isn't silently dead
        MatcherKind.TagEquals => true,
        MatcherKind.UserSidEquals => true,
        MatcherKind.IsForward => false,
        _ => true,
    };

    public static string? ExtractAppPathContains(Filter filter)
    {
        foreach (var m in filter.Matchers)
        {
            if (m.Kind is MatcherKind.AppPathContains or MatcherKind.AppPathEquals &&
                !string.IsNullOrWhiteSpace(m.StringValue))
                return m.StringValue;
        }
        return null;
    }

    public static string? ExtractExeFileName(Filter filter)
    {
        var path = ExtractAppPathContains(filter);
        if (path is null) return null;
        if (path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            return Path.GetFileName(path);
        // path contains fragment → QoS needs exe name; caller may resolve from live processes
        return path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? Path.GetFileName(path)
            : path + (path.Contains('.') ? "" : ".exe");
    }

    private static bool PortInRange(string? endpoint, ushort? from, ushort? to)
    {
        if (from is null || !TryParseEndPoint(endpoint, out _, out var port)) return false;
        var a = from.Value;
        var b = to ?? from.Value;
        if (b < a) (a, b) = (b, a);
        return port >= a && port <= b;
    }

    private static bool AddrInCidr(string? endpoint, string? cidr)
    {
        if (string.IsNullOrWhiteSpace(cidr) || !TryParseEndPoint(endpoint, out var addr, out _))
            return false;
        if (!cidr.Contains('/'))
            return addr.ToString().Equals(cidr, StringComparison.OrdinalIgnoreCase) ||
                   addr.ToString().StartsWith(cidr, StringComparison.OrdinalIgnoreCase);

        var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var net) ||
            !int.TryParse(parts[1], out var prefix))
            return false;
        return IsInSubnet(addr, net, prefix);
    }

    private static bool IsInSubnet(IPAddress address, IPAddress network, int prefixLength)
    {
        var addrBytes = address.GetAddressBytes();
        var netBytes = network.GetAddressBytes();
        if (addrBytes.Length != netBytes.Length) return false;
        int full = prefixLength / 8;
        int rem = prefixLength % 8;
        for (int i = 0; i < full; i++)
            if (addrBytes[i] != netBytes[i]) return false;
        if (rem == 0) return true;
        int mask = (byte)~(0xFF >> rem);
        return (addrBytes[full] & mask) == (netBytes[full] & mask);
    }

    private static bool IsLoopback(string? endpoint)
    {
        if (!TryParseEndPoint(endpoint, out var addr, out _)) return false;
        return IPAddress.IsLoopback(addr);
    }

    private static bool IsPrivate(string? endpoint)
    {
        if (!TryParseEndPoint(endpoint, out var addr, out _)) return false;
        if (IPAddress.IsLoopback(addr)) return true;
        if (addr.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = addr.GetAddressBytes();
        if (b[0] == 10) return true;
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
        if (b[0] == 192 && b[1] == 168) return true;
        if (b[0] == 169 && b[1] == 254) return true;
        return false;
    }

    public static bool TryParseEndPoint(string? ep, out IPAddress address, out int port)
    {
        address = IPAddress.None;
        port = 0;
        if (string.IsNullOrWhiteSpace(ep) || ep is "*:*") return false;

        // [v6]:port simplified
        if (ep.StartsWith('['))
        {
            var close = ep.IndexOf(']');
            if (close < 0) return false;
            if (!IPAddress.TryParse(ep[1..close], out address!)) return false;
            if (ep.Length > close + 2 && ep[close + 1] == ':')
                int.TryParse(ep[(close + 2)..], out port);
            return true;
        }

        var idx = ep.LastIndexOf(':');
        if (idx <= 0) return IPAddress.TryParse(ep, out address!);
        if (!IPAddress.TryParse(ep[..idx], out address!)) return false;
        int.TryParse(ep[(idx + 1)..], out port);
        return true;
    }
}
