using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using NetShaper.Core.Policy;

namespace NetShaper.Core.Driver;

/// <summary>
/// Usermode client for NetShaperCallout.sys.
/// Opens \\.\NetShaperCallout — fails gracefully if driver not installed.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class NetShaperDriverClient : IDisposable
{
    public const string DevicePath = @"\\.\NetShaperCallout";

    private IntPtr _handle = InvalidHandle;
    private bool _disposed;
    private static readonly IntPtr InvalidHandle = new(-1);

    public bool IsOpen => _handle != IntPtr.Zero && _handle != InvalidHandle;
    public string? LastError { get; private set; }

    public static bool IsDevicePresent()
    {
        var h = CreateFileW(DevicePath, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h == InvalidHandle || h == IntPtr.Zero) return false;
        CloseHandle(h);
        return true;
    }

    public bool TryOpen()
    {
        if (IsOpen) return true;
        _handle = CreateFileW(DevicePath, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (_handle == InvalidHandle || _handle == IntPtr.Zero)
        {
            LastError = "Driver device not available (install NetShaperCallout.sys).";
            _handle = InvalidHandle;
            return false;
        }
        LastError = null;
        return true;
    }

    public NsVersionInfo? GetVersion()
    {
        if (!TryOpen()) return null;
        var buf = new byte[Marshal.SizeOf<NsVersionInfo>()];
        if (!DeviceIoControl(_handle, IOCTL_NS_GET_VERSION, null, 0, buf, buf.Length, out var ret, IntPtr.Zero) ||
            ret < 16)
        {
            LastError = "IOCTL_NS_GET_VERSION failed";
            return null;
        }
        return BytesToStruct<NsVersionInfo>(buf);
    }

    public NsDriverStats? GetStats()
    {
        if (!TryOpen()) return null;
        var buf = new byte[Marshal.SizeOf<NsDriverStats>()];
        if (!DeviceIoControl(_handle, IOCTL_NS_GET_STATS, null, 0, buf, buf.Length, out var ret, IntPtr.Zero) ||
            ret < Marshal.SizeOf<NsDriverStats>())
        {
            LastError = "IOCTL_NS_GET_STATS failed";
            return null;
        }
        return BytesToStruct<NsDriverStats>(buf);
    }

    public bool SetEnabled(bool enabled)
    {
        if (!TryOpen()) return false;
        var body = BitConverter.GetBytes(enabled ? 1u : 0u);
        return DeviceIoControl(_handle, IOCTL_NS_SET_ENABLED, body, body.Length, null, 0, out _, IntPtr.Zero);
    }

    public bool ClearLimits()
    {
        if (!TryOpen()) return false;
        return DeviceIoControl(_handle, IOCTL_NS_CLEAR_LIMITS, null, 0, null, 0, out _, IntPtr.Zero);
    }

    /// <summary>Push resolved PID limits (fast path for callout classify).</summary>
    public bool PushLimitsFromPolicy(PolicyDocument doc)
    {
        if (!TryOpen()) return false;

        var pidEntries = new List<(int Pid, uint Dir, ulong Bps)>();
        foreach (var rule in doc.Rules.Where(r =>
                     r.Enabled && r.Kind == RuleKind.Limit && r.IsActiveNow() &&
                     r.LimitBytesPerSec is > 0))
        {
            var filter = doc.Filters.FirstOrDefault(f => f.Id == rule.FilterId);
            if (filter is null) continue;
            var bps = (ulong)rule.LimitBytesPerSec!.Value;
            var dir = (uint)rule.Direction;

            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    string? path = null;
                    try { path = p.MainModule?.FileName; } catch { /* denied */ }
                    var ctx = new FilterMatcher.Context
                    {
                        ProcessId = p.Id,
                        ProcessName = p.ProcessName,
                        ExecutablePath = path,
                    };
                    if (FilterMatcher.MatchesFilter(filter, ctx))
                        pidEntries.Add((p.Id, dir, bps));
                }
                catch { /* ignore */ }
                finally { p.Dispose(); }
                if (pidEntries.Count >= 128) break;
            }
            if (pidEntries.Count >= 128) break;
        }

        // Also send path table for diagnostics / future ALE app-id matching
        _ = PushPathLimits(doc);

        // Build NS_PID_LIMIT_TABLE
        const int max = 128;
        var count = Math.Min(pidEntries.Count, max);
        // pack=1: Count(4)+Reserved(4)+ entries * (4+4+8+4+4=24)
        var entrySize = 24;
        var buf = new byte[8 + entrySize * count];
        BitConverter.GetBytes((uint)count).CopyTo(buf, 0);
        for (int i = 0; i < count; i++)
        {
            var o = 8 + i * entrySize;
            var e = pidEntries[i];
            BitConverter.GetBytes((uint)e.Pid).CopyTo(buf, o);
            BitConverter.GetBytes(e.Dir).CopyTo(buf, o + 4);
            BitConverter.GetBytes(e.Bps).CopyTo(buf, o + 8);
            // flags + reserved zero
        }

        if (!DeviceIoControl(_handle, IOCTL_NS_SET_PID_LIMITS, buf, buf.Length, null, 0, out _, IntPtr.Zero))
        {
            LastError = "IOCTL_NS_SET_PID_LIMITS failed (old driver? rebuild callout 2.0)";
            return false;
        }
        return true;
    }

    private bool PushPathLimits(PolicyDocument doc)
    {
        var entries = new List<(string Frag, ulong Bps, uint Dir)>();
        foreach (var rule in doc.Rules.Where(r =>
                     r.Enabled && r.Kind == RuleKind.Limit && r.IsActiveNow() &&
                     r.LimitBytesPerSec is > 0))
        {
            var filter = doc.Filters.FirstOrDefault(f => f.Id == rule.FilterId);
            var frag = filter?.Matchers
                .FirstOrDefault(m => m.Kind is MatcherKind.AppPathContains or MatcherKind.AppPathEquals)
                ?.StringValue;
            if (string.IsNullOrWhiteSpace(frag)) continue;
            entries.Add((frag!, (ulong)rule.LimitBytesPerSec!.Value, (uint)rule.Direction));
            if (entries.Count >= 64) break;
        }

        // Path entry: 260*2 WCHAR + 8 + 4 + 4 = 536
        const int pathEntrySize = 260 * 2 + 16;
        var count = entries.Count;
        var buf = new byte[8 + pathEntrySize * count];
        BitConverter.GetBytes((uint)count).CopyTo(buf, 0);
        for (int i = 0; i < count; i++)
        {
            var o = 8 + i * pathEntrySize;
            var chars = entries[i].Frag.PadRight(260, '\0').ToCharArray();
            Buffer.BlockCopy(chars, 0, buf, o, 260 * 2);
            BitConverter.GetBytes(entries[i].Bps).CopyTo(buf, o + 520);
            BitConverter.GetBytes(entries[i].Dir).CopyTo(buf, o + 528);
        }
        return DeviceIoControl(_handle, IOCTL_NS_SET_LIMITS, buf, buf.Length, null, 0, out _, IntPtr.Zero);
    }

    public string StatusText()
    {
        if (!IsDevicePresent())
            return "Driver: not installed";
        if (!TryOpen())
            return "Driver: present but open failed — " + LastError;
        var v = GetVersion();
        var s = GetStats();
        if (v is null) return "Driver: open ok, version ioctl failed";
        var flags = v.Value.Flags;
        return
            $"Driver: v{v.Value.DriverVersion:X8} api={v.Value.ApiVersion} " +
            $"callout={((flags & 1) != 0)} classify={((flags & 2) != 0)} " +
            $"enabled={s?.Enabled} pidLimits={s?.ActiveLimits} " +
            $"pkts={s?.PacketsSeen} blocked={s?.PacketsDelayed} bytes={s?.BytesSeen}";
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (IsOpen)
        {
            CloseHandle(_handle);
            _handle = InvalidHandle;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
    public struct NsVersionInfo
    {
        public uint DriverVersion;
        public uint ApiVersion;
        public uint Flags;
        public uint Reserved;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string BuildStamp;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct NsDriverStats
    {
        public ulong FlowsTracked;
        public ulong PacketsSeen;
        public ulong PacketsDelayed;
        public ulong BytesSeen;
        public ulong BytesLimited;
        public uint ActiveLimits;
        public uint Enabled;
    }

    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 1;
    private const uint FILE_SHARE_WRITE = 2;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_DEVICE_NETSHAPER = 0x9C40;
    private static uint CTL(uint code) =>
        (FILE_DEVICE_NETSHAPER << 16) | (code << 2);

    private static readonly uint IOCTL_NS_GET_VERSION = CTL(0x800);
    private static readonly uint IOCTL_NS_GET_STATS = CTL(0x801);
    private static readonly uint IOCTL_NS_SET_LIMITS = CTL(0x802);
    private static readonly uint IOCTL_NS_CLEAR_LIMITS = CTL(0x803);
    private static readonly uint IOCTL_NS_SET_ENABLED = CTL(0x804);
    private static readonly uint IOCTL_NS_SET_PID_LIMITS = CTL(0x805);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share,
        IntPtr sec, uint disp, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(IntPtr h, uint code,
        byte[]? inBuf, int inLen, byte[]? outBuf, int outLen, out int ret, IntPtr ovl);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);

    private static T BytesToStruct<T>(byte[] bytes) where T : struct
    {
        var h = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try { return Marshal.PtrToStructure<T>(h.AddrOfPinnedObject())!; }
        finally { h.Free(); }
    }
}
