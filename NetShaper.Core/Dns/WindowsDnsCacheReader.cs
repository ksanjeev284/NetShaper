using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NetShaper.Core.Dns;

/// <summary>
/// Read Windows DNS client cache names via dnsapi, resolve to A/AAAA with System.Net.Dns.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WindowsDnsCacheReader
{
    public static IReadOnlyList<(string Host, string Ip)> ReadCache()
    {
        var hosts = ReadCacheHostNames();
        var enriched = new List<(string, string)>();
        foreach (var host in hosts.Distinct(StringComparer.OrdinalIgnoreCase).Take(250))
        {
            try
            {
                // Prefer cached OS resolution when possible
                var addrs = System.Net.Dns.GetHostAddresses(host);
                foreach (var a in addrs)
                {
                    if (a.AddressFamily is System.Net.Sockets.AddressFamily.InterNetwork
                        or System.Net.Sockets.AddressFamily.InterNetworkV6)
                        enriched.Add((host, a.ToString()));
                }
            }
            catch
            {
                // skip NXDOMAIN / temporary failures
            }
        }
        return enriched;
    }

    public static IReadOnlyList<string> ReadCacheHostNames()
    {
        var results = new List<string>();
        if (DnsGetCacheDataTable(out var pEntry) == 0 && pEntry != IntPtr.Zero)
        {
            try
            {
                var ptr = pEntry;
                var guard = 0;
                while (ptr != IntPtr.Zero && guard++ < 2000)
                {
                    var entry = Marshal.PtrToStructure<DNS_CACHE_ENTRY>(ptr);
                    var name = Marshal.PtrToStringUni(entry.pszName);
                    if (!string.IsNullOrWhiteSpace(name) && !name.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase))
                        results.Add(name!.TrimEnd('.'));
                    ptr = entry.pNext;
                }
            }
            finally
            {
                try { DnsFree(pEntry, DNS_FREE_TYPE.DnsFreeFlat); } catch { /* ignore */ }
            }
        }
        return results;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DNS_CACHE_ENTRY
    {
        public IntPtr pNext;
        public IntPtr pszName;
        public ushort wType;
        public ushort wDataLength;
        public uint dwFlags;
    }

    private enum DNS_FREE_TYPE
    {
        DnsFreeFlat = 0,
    }

    [DllImport("dnsapi.dll", EntryPoint = "DnsGetCacheDataTable", CharSet = CharSet.Unicode)]
    private static extern int DnsGetCacheDataTable(out IntPtr ppEntry);

    [DllImport("dnsapi.dll")]
    private static extern void DnsFree(IntPtr pData, DNS_FREE_TYPE freeType);
}
