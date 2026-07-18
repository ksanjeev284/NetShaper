using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NetShaper.Core.Shaping.WinDivert;

/// <summary>Map 5-tuple → owning PID via IP Helper TCP/UDP tables.</summary>
[SupportedOSPlatform("windows")]
public sealed class ConnectionOwnerIndex
{
    private readonly Dictionary<string, int> _map = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private DateTime _lastRefresh = DateTime.MinValue;

    public void RefreshIfStale(TimeSpan maxAge)
    {
        if (DateTime.UtcNow - _lastRefresh < maxAge) return;
        Refresh();
    }

    public void Refresh()
    {
        lock (_gate)
        {
            _map.Clear();
            foreach (var row in ReadTcpRows(AF_INET))
            {
                // Outbound view: local=our, remote=peer
                _map[Key(6, row.LocalIp, row.LocalPort, row.RemoteIp, row.RemotePort)] = row.Pid;
                // Inbound reverse
                _map[Key(6, row.RemoteIp, row.RemotePort, row.LocalIp, row.LocalPort)] = row.Pid;
            }
            foreach (var row in ReadUdpRows(AF_INET))
            {
                _map[Key(17, row.LocalIp, row.LocalPort, "0.0.0.0", 0)] = row.Pid;
            }
            _lastRefresh = DateTime.UtcNow;
        }
    }

    public int? Lookup(int proto, string srcIp, int srcPort, string dstIp, int dstPort, bool outbound)
    {
        lock (_gate)
        {
            // For outbound packet: src=local, dst=remote
            if (outbound)
            {
                if (_map.TryGetValue(Key(proto, srcIp, srcPort, dstIp, dstPort), out var pid))
                    return pid;
            }
            else
            {
                // inbound: dst=local
                if (_map.TryGetValue(Key(proto, dstIp, dstPort, srcIp, srcPort), out var pid))
                    return pid;
            }
            // UDP often only local port
            if (proto == 17)
            {
                var localIp = outbound ? srcIp : dstIp;
                var localPort = outbound ? srcPort : dstPort;
                if (_map.TryGetValue(Key(17, localIp, localPort, "0.0.0.0", 0), out var pid))
                    return pid;
            }
            return null;
        }
    }

    private static string Key(int proto, string a, int ap, string b, int bp) =>
        $"{proto}|{a}|{ap}|{b}|{bp}";

    private readonly record struct Row(int Pid, string LocalIp, int LocalPort, string RemoteIp, int RemotePort);

    private static List<Row> ReadTcpRows(int family)
    {
        var list = new List<Row>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, family, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size <= 0) return list;
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buf, ref size, true, family, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                return list;
            int num = Marshal.ReadInt32(buf);
            var ptr = buf + 4;
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            for (int i = 0; i < num; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(ptr);
                list.Add(new Row(
                    (int)row.owningPid,
                    ToIp(row.localAddr),
                    Ntohs(row.localPort),
                    ToIp(row.remoteAddr),
                    Ntohs(row.remotePort)));
                ptr += rowSize;
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return list;
    }

    private static List<Row> ReadUdpRows(int family)
    {
        var list = new List<Row>();
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, true, family, UDP_TABLE_OWNER_PID, 0);
        if (size <= 0) return list;
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(buf, ref size, true, family, UDP_TABLE_OWNER_PID, 0) != 0)
                return list;
            int num = Marshal.ReadInt32(buf);
            var ptr = buf + 4;
            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
            for (int i = 0; i < num; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(ptr);
                list.Add(new Row((int)row.owningPid, ToIp(row.localAddr), Ntohs(row.localPort), "0.0.0.0", 0));
                ptr += rowSize;
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return list;
    }

    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state, localAddr, localPort, remoteAddr, remotePort, owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr, localPort, owningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr p, ref int s, bool sort, int af, int cls, uint r);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr p, ref int s, bool sort, int af, int cls, uint r);

    private static string ToIp(uint addr) => new IPAddress(BitConverter.GetBytes(addr)).ToString();

    private static int Ntohs(uint portNet)
    {
        var p = (ushort)(portNet & 0xFFFF);
        return (ushort)((p >> 8) | (p << 8));
    }
}
