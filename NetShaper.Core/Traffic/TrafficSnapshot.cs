namespace NetShaper.Core.Traffic;

public sealed class ProcessTraffic
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string? ExecutablePath { get; set; }
    /// <summary>Windows service name(s) when this PID hosts service(s).</summary>
    public string? ServiceNames { get; set; }
    public long BytesSent { get; set; }
    public long BytesRecv { get; set; }
    /// <summary>Session totals attributed this NetShaper run (always grows with traffic).</summary>
    public long SessionBytesIn { get; set; }
    public long SessionBytesOut { get; set; }
    public double BitsPerSecOut { get; set; }
    public double BitsPerSecIn { get; set; }
    public int ConnectionCount { get; set; }
    public int EstablishedCount { get; set; }
    /// <summary>How rates were computed: EStats, NIC-share, Mixed.</summary>
    public string RateSource { get; set; } = "";

    /// <summary>UI label: process + optional service names.</summary>
    public string DisplayName =>
        string.IsNullOrEmpty(ServiceNames) ? ProcessName : $"{ProcessName}  [{ServiceNames}]";

    /// <summary>Prefer EStats totals; fall back to session attribution so columns never stay empty.</summary>
    public long DataBytesIn => BytesRecv > 0 ? BytesRecv : SessionBytesIn;
    public long DataBytesOut => BytesSent > 0 ? BytesSent : SessionBytesOut;

    // Materialized strings (set at sample time) — reliable for DataGrid binding
    public string RateInDisplay { get; set; } = "0 b/s";
    public string RateOutDisplay { get; set; } = "0 b/s";
    public string DataInDisplay { get; set; } = "0 B";
    public string DataOutDisplay { get; set; } = "0 B";

    public void RefreshDisplayStrings()
    {
        RateInDisplay = FormatRate(BitsPerSecIn);
        RateOutDisplay = FormatRate(BitsPerSecOut);
        DataInDisplay = FormatBytes(DataBytesIn);
        DataOutDisplay = FormatBytes(DataBytesOut);
    }

    public static string FormatRate(double bitsPerSec)
    {
        if (bitsPerSec < 0) bitsPerSec = 0;
        double v = bitsPerSec;
        string[] u = ["b/s", "Kb/s", "Mb/s", "Gb/s"];
        int i = 0;
        while (v >= 1000 && i < u.Length - 1) { v /= 1000; i++; }
        return i == 0 ? $"{v:0} {u[i]}" : $"{v:0.0} {u[i]}";
    }

    public static string FormatBytes(long bytes)
    {
        if (bytes < 0) bytes = 0;
        double v = bytes;
        string[] u = ["B", "KB", "MB", "GB", "TB"];
        int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return i == 0 ? $"{v:0} {u[i]}" : $"{v:0.0} {u[i]}";
    }
}

public sealed class ConnectionInfo
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "";
    public string? ServiceNames { get; set; }
    public string Protocol { get; set; } = "";
    public string LocalEndPoint { get; set; } = "";
    public string RemoteEndPoint { get; set; } = "";
    public string State { get; set; } = "";
    /// <summary>Resolved remote hostname from DnsCache when available.</summary>
    public string? RemoteHost { get; set; }

    public string DisplayName =>
        string.IsNullOrEmpty(ServiceNames) ? ProcessName : $"{ProcessName}  [{ServiceNames}]";
    public long BytesSent { get; set; }
    public long BytesRecv { get; set; }
    public double BitsPerSecOut { get; set; }
    public double BitsPerSecIn { get; set; }

    // Raw fields for kill / EStats
    public uint LocalAddrV4 { get; set; }
    public uint RemoteAddrV4 { get; set; }
    public uint LocalPortNet { get; set; }
    public uint RemotePortNet { get; set; }
    public bool IsIpv4Tcp { get; set; }
    /// <summary>MIB_TCP_STATE code (5 = Established).</summary>
    public uint TcpStateCode { get; set; }

    public string RateInDisplay { get; set; } = "0 b/s";
    public string RateOutDisplay { get; set; } = "0 b/s";
    public string DataInDisplay { get; set; } = "0 B";
    public string DataOutDisplay { get; set; } = "0 B";

    public void RefreshDisplayStrings()
    {
        RateInDisplay = ProcessTraffic.FormatRate(BitsPerSecIn);
        RateOutDisplay = ProcessTraffic.FormatRate(BitsPerSecOut);
        DataInDisplay = ProcessTraffic.FormatBytes(BytesRecv);
        DataOutDisplay = ProcessTraffic.FormatBytes(BytesSent);
    }
}

public sealed class TrafficSnapshot
{
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public IReadOnlyList<ProcessTraffic> Processes { get; set; } = Array.Empty<ProcessTraffic>();
    public IReadOnlyList<ConnectionInfo> Connections { get; set; } = Array.Empty<ConnectionInfo>();
    public long TotalBitsPerSecIn { get; set; }
    public long TotalBitsPerSecOut { get; set; }
    public string SamplerStatus { get; set; } = "";
    public bool EStatsWorking { get; set; }
    public bool IsElevated { get; set; }
    /// <summary>EStats | NIC-share | Mixed</summary>
    public string RateMode { get; set; } = "";
}
