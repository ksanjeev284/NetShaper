using System.Runtime.Versioning;
using System.ServiceProcess;

namespace NetShaper.Core.Traffic;

/// <summary>
/// Maps Windows service PIDs → service names (incl. multi-service svchost).
/// Refreshed on an interval; cheap relative to full process walk.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ServiceProcessMap
{
    private readonly object _gate = new();
    private Dictionary<int, string> _byPid = new();
    private DateTime _lastRefresh = DateTime.MinValue;
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromSeconds(8);

    public void EnsureFresh(bool force = false)
    {
        if (!force && DateTime.UtcNow - _lastRefresh < RefreshInterval)
            return;
        try
        {
            var services = ServiceController.GetServices();
            var bag = new System.Collections.Concurrent.ConcurrentBag<(int pid, string name)>();
            Parallel.ForEach(services, ParallelOpts.Light, sc =>
            {
                try
                {
                    if (sc.Status is not ServiceControllerStatus.Running
                        and not ServiceControllerStatus.StartPending)
                        return;
                    var pid = TryGetServiceProcessId(sc);
                    if (pid > 0)
                        bag.Add((pid, sc.ServiceName));
                }
                catch { /* access */ }
                finally { sc.Dispose(); }
            });

            var map = new Dictionary<int, List<string>>();
            foreach (var (pid, name) in bag)
            {
                if (!map.TryGetValue(pid, out var list))
                    map[pid] = list = new List<string>();
                list.Add(name);
            }

            var flat = new Dictionary<int, string>(map.Count);
            foreach (var (pid, names) in map)
            {
                names.Sort(StringComparer.OrdinalIgnoreCase);
                flat[pid] = names.Count <= 3
                    ? string.Join(", ", names)
                    : string.Join(", ", names.Take(3)) + $", +{names.Count - 3}";
            }

            lock (_gate)
            {
                _byPid = flat;
                _lastRefresh = DateTime.UtcNow;
            }
        }
        catch
        {
            _lastRefresh = DateTime.UtcNow;
        }
    }

    public string? GetServices(int pid)
    {
        lock (_gate)
            return _byPid.TryGetValue(pid, out var s) ? s : null;
    }

    public IReadOnlyDictionary<int, string> Snapshot()
    {
        lock (_gate) return new Dictionary<int, string>(_byPid);
    }

    /// <summary>
    /// Query service process id via QueryServiceStatusEx (SC_STATUS_PROCESS_INFO).
    /// </summary>
    private static int TryGetServiceProcessId(ServiceController sc)
    {
        try
        {
            // ServiceController has no ProcessId property on .NET Framework classic,
            // but on .NET Core / 5+ some builds add it via extension — use P/Invoke.
            return NativeServicePid.GetProcessId(sc.ServiceName);
        }
        catch { return 0; }
    }
}

[SupportedOSPlatform("windows")]
internal static class NativeServicePid
{
    private const uint SERVICE_QUERY_STATUS = 0x0004;
    private const uint SC_STATUS_PROCESS_INFO = 0;

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
        public uint dwProcessId;
        public uint dwServiceFlags;
    }

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern IntPtr OpenService(IntPtr hSC, string name, uint access);

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(IntPtr hService, uint infoLevel, IntPtr buf, uint bufSize, out uint bytesNeeded);

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr h);

    public static int GetProcessId(string serviceName)
    {
        var scm = OpenSCManager(null, null, 1 /* SC_MANAGER_CONNECT */);
        if (scm == IntPtr.Zero) return 0;
        try
        {
            var svc = OpenService(scm, serviceName, SERVICE_QUERY_STATUS);
            if (svc == IntPtr.Zero) return 0;
            try
            {
                var size = System.Runtime.InteropServices.Marshal.SizeOf<SERVICE_STATUS_PROCESS>();
                var buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
                try
                {
                    if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, buf, (uint)size, out _))
                        return 0;
                    var st = System.Runtime.InteropServices.Marshal.PtrToStructure<SERVICE_STATUS_PROCESS>(buf);
                    return (int)st.dwProcessId;
                }
                finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(buf); }
            }
            finally { CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }
}
