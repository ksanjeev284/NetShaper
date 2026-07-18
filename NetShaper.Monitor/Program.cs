using System.Runtime.Versioning;
using NetShaper.Core.Traffic;

[SupportedOSPlatform("windows")]
static class Program
{
    static int Main(string[] args)
    {
        Console.Title = "NetShaper Monitor (P0)";
        Console.WriteLine("NetShaper P0 — connection monitor (no driver)");
        Console.WriteLine("Refresh every 1s. Ctrl+C to exit.\n");

        using var sampler = new WindowsTrafficSampler();
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        while (!cts.IsCancellationRequested)
        {
            try
            {
                var snap = sampler.Sample(includeConnections: true);
                if (!Console.IsOutputRedirected)
                {
                    try { Console.Clear(); } catch { /* redirected / no console */ }
                }
                else
                {
                    Console.WriteLine(); // separator when piped
                }
                Console.WriteLine($"NetShaper Monitor  {snap.Timestamp:HH:mm:ss}   " +
                                  $"WAN-ish total  ↓ {FormatRate(snap.TotalBitsPerSecIn)}  ↑ {FormatRate(snap.TotalBitsPerSecOut)}");
                Console.WriteLine(new string('-', 100));
                Console.WriteLine($"{"PID",6} {"Name",-24} {"Conns",5}  Path");
                foreach (var p in snap.Processes.Take(20))
                {
                    var path = p.ExecutablePath ?? "";
                    if (path.Length > 50) path = "..." + path[^47..];
                    Console.WriteLine($"{p.ProcessId,6} {Trim(p.ProcessName, 24),-24} {p.ConnectionCount,5}  {path}");
                }

                Console.WriteLine();
                Console.WriteLine($"{"Proto",-5} {"PID",6} {"Name",-16} {"Local",-22} {"Remote",-22} State");
                foreach (var c in snap.Connections
                             .Where(c => c.State is "Established" or "Listen")
                             .Take(30))
                {
                    Console.WriteLine($"{c.Protocol,-5} {c.ProcessId,6} {Trim(c.ProcessName, 16),-16} " +
                                      $"{Trim(c.LocalEndPoint, 22),-22} {Trim(c.RemoteEndPoint, 22),-22} {c.State}");
                }

                Console.WriteLine("\nNext: per-process rates (ETW/WFP) · policy engine · limit rules");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Sample error: " + ex.Message);
            }

            try { Task.Delay(1000, cts.Token).Wait(cts.Token); }
            catch (OperationCanceledException) { break; }
        }

        return 0;
    }

    static string FormatRate(long bitsPerSec)
    {
        double v = bitsPerSec;
        string[] u = ["b/s", "Kb/s", "Mb/s", "Gb/s"];
        int i = 0;
        while (v >= 1000 && i < u.Length - 1) { v /= 1000; i++; }
        return $"{v,7:0.0} {u[i]}";
    }

    static string Trim(string s, int n) =>
        s.Length <= n ? s : s[..(n - 1)] + "…";
}
