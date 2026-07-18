using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NetShaper.Core.Traffic;

/// <summary>Force-close TCP connections via SetTcpEntry (documented IP Helper).</summary>
[SupportedOSPlatform("windows")]
public static class ConnectionKiller
{
    private const int MIB_TCP_STATE_DELETE_TCB = 12;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SetTcpEntry(ref MIB_TCPROW pTcpRow);

    public static bool TryKill(ConnectionInfo c, out string error)
    {
        error = "";
        if (!c.IsIpv4Tcp)
        {
            error = "Only IPv4 TCP connections can be killed via SetTcpEntry.";
            return false;
        }
        if (c.State is "Listen" or "Closed")
        {
            error = "Cannot kill listen/closed sockets this way.";
            return false;
        }

        var row = new MIB_TCPROW
        {
            state = MIB_TCP_STATE_DELETE_TCB,
            localAddr = c.LocalAddrV4,
            localPort = c.LocalPortNet,
            remoteAddr = c.RemoteAddrV4,
            remotePort = c.RemotePortNet,
        };
        var st = SetTcpEntry(ref row);
        if (st != 0)
        {
            error = $"SetTcpEntry failed (0x{st:X}). Try running as Administrator.";
            return false;
        }
        return true;
    }

    public static int KillMatching(IEnumerable<ConnectionInfo> connections, Func<ConnectionInfo, bool> predicate)
    {
        int n = 0;
        foreach (var c in connections.Where(predicate))
        {
            if (TryKill(c, out _))
                n++;
        }
        return n;
    }
}
