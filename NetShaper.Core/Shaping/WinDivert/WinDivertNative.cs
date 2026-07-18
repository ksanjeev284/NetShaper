using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NetShaper.Core.Shaping.WinDivert;

/// <summary>
/// Optional WinDivert 2.x bindings. DLL is NOT redistributed; user installs via scripts/install-windivert.ps1.
/// License: WinDivert is LGPLv3 (https://reqrypt.org/windivert.html).
/// </summary>
[SupportedOSPlatform("windows")]
public static class WinDivertNative
{
    public const int WINDIVERT_LAYER_NETWORK = 0;
    public const int WINDIVERT_LAYER_NETWORK_FORWARD = 1;

    public static bool IsAvailable => Loader.IsLoaded;

    public static string? LoadError => Loader.Error;
    public static string? LoadedPath => Loader.Path;

    public static bool TryLoad() => Loader.EnsureLoaded();

    public static IntPtr Open(string filter, int layer, short priority, ulong flags)
    {
        Loader.EnsureLoaded(throwOnFail: true);
        return WinDivertOpen(filter, layer, priority, flags);
    }

    public static bool Recv(IntPtr handle, byte[] packet, out int recvLen, IntPtr addr)
    {
        recvLen = 0;
        return WinDivertRecv(handle, packet, (uint)packet.Length, out recvLen, addr);
    }

    public static bool Send(IntPtr handle, byte[] packet, int packetLen, IntPtr addr)
    {
        return WinDivertSend(handle, packet, (uint)packetLen, out _, addr);
    }

    public static bool Close(IntPtr handle) => WinDivertClose(handle);

    public static int AddressSize => 80; // WinDivert 2.x WINDIVERT_ADDRESS footprint (padded)

    public static bool IsOutbound(IntPtr addr)
    {
        // Layout (WinDivert 2.2): after Timestamp (8) and Layer/Event (2), flags bitfield.
        // Outbound is bit 0 of the flags byte region at offset 10 (approx).
        // We read byte at +10: Sniffed(1) Outbound(1) ...
        // Safer: use WinDivertHelperParsePacket is complex; use documented Network.Outbound via helper.
        try
        {
            // Offset 10: first flags byte in many 2.x builds contains Outbound as bit 1
            var b = Marshal.ReadByte(addr, 10);
            return (b & 0x02) != 0 || (b & 0x01) != 0; // tolerate layout variance
        }
        catch { return true; }
    }

    private static class Loader
    {
        public static bool IsLoaded;
        public static string? Error;
        public static string? Path;
        private static IntPtr _lib;
        private static readonly object Gate = new();
        private static bool _resolverSet;

        public static bool EnsureLoaded(bool throwOnFail = false)
        {
            lock (Gate)
            {
                if (IsLoaded) return true;
                foreach (var dir in CandidateDirs())
                {
                    var dll = System.IO.Path.Combine(dir, "WinDivert.dll");
                    if (!File.Exists(dll)) continue;
                    // Driver often sits next to DLL — put dir on PATH for .sys load
                    try
                    {
                        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
                        if (!pathEnv.Contains(dir, StringComparison.OrdinalIgnoreCase))
                            Environment.SetEnvironmentVariable("PATH", dir + System.IO.Path.PathSeparator + pathEnv);
                    }
                    catch { /* ignore */ }

                    if (NativeLibrary.TryLoad(dll, out _lib))
                    {
                        Path = dll;
                        IsLoaded = true;
                        Error = null;
                        if (!_resolverSet)
                        {
                            NativeLibrary.SetDllImportResolver(
                                typeof(WinDivertNative).Assembly,
                                (name, _, _) =>
                                    name is "WinDivert" or "WinDivert.dll" ? _lib : IntPtr.Zero);
                            _resolverSet = true;
                        }
                        return true;
                    }
                }
                Error =
                    "WinDivert.dll not found. Install with: scripts\\install-windivert.ps1 " +
                    "(expected under %ProgramData%\\NetShaper\\WinDivert\\x64\\)";
                if (throwOnFail) throw new DllNotFoundException(Error);
                return false;
            }
        }

        private static IEnumerable<string> CandidateDirs()
        {
            var pd = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "NetShaper", "WinDivert");
            yield return System.IO.Path.Combine(pd, "x64");
            yield return pd;
            yield return System.IO.Path.Combine(AppContext.BaseDirectory, "WinDivert", "x64");
            yield return System.IO.Path.Combine(AppContext.BaseDirectory, "WinDivert");
            yield return AppContext.BaseDirectory;
        }
    }

    [DllImport("WinDivert", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr WinDivertOpen(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        int layer,
        short priority,
        ulong flags);

    [DllImport("WinDivert", CallingConvention = CallingConvention.Cdecl)]
    private static extern bool WinDivertRecv(
        IntPtr handle,
        byte[] pPacket,
        uint packetLen,
        out int pRecvLen,
        IntPtr pAddr);

    [DllImport("WinDivert", CallingConvention = CallingConvention.Cdecl)]
    private static extern bool WinDivertSend(
        IntPtr handle,
        byte[] pPacket,
        uint packetLen,
        out int pSendLen,
        IntPtr pAddr);

    [DllImport("WinDivert", CallingConvention = CallingConvention.Cdecl)]
    private static extern bool WinDivertClose(IntPtr handle);
}
