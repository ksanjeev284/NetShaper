using System.Runtime.Versioning;
using System.Security.Principal;
using NetShaper.Core.Api;
using NetShaper.Core.Dns;
using NetShaper.Core.Policy;
using NetShaper.Core.Security;
using NetShaper.Core.Shaping;
using NetShaper.Core.Stats;
using NetShaper.Core.Traffic;
using NetShaper.Core.Wfp;

[assembly: SupportedOSPlatform("windows")]

static class Program
{
    static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintHelp();
            return 1;
        }

        var cmd = args[0].ToLowerInvariant();
        // access commands always allowed so admins can fix lockouts
        if (cmd != "access" && cmd != "help" && cmd != "-h" && cmd != "--help")
        {
            try
            {
                var need = cmd is "list" or "limits" or "quotas" or "stats" or "dns" or "wfp-status" or "policy" or "shaper" or "api" or "driver" or "certs" or "sample" or "live"
                    ? AccessRight.Monitor
                    : AccessRight.Control;
                // read-only api get is monitor; mutating needs control
                if (cmd == "api" && args.Length > 1 && args[1] is "get" or "show" or "status" or "rget")
                    need = AccessRight.Monitor;
                if (cmd == "api" && args.Length > 1 && args[1] is "enable" or "disable" or "remote-enable" or "remote-disable" or "post" or "rpost")
                    need = AccessRight.Control;
                if (cmd == "certs" && args.Length > 1 &&
                    args[1] is "issue" or "revoke" or "ensure" or "rotate" or "reset" or "export")
                    need = AccessRight.Control;
                if (cmd == "driver" && args.Length > 1 && args[1] is "push" or "clear" or "enable" or "disable")
                    need = AccessRight.Control;
                if (cmd is "policy" && args.Length > 1 && args[1] is "show")
                    need = AccessRight.Monitor;
                AccessChecker.Require(need);
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 5;
            }
        }

        var store = new PolicyStore();
        return cmd switch
        {
            "policy" => CmdPolicy(store, args.Skip(1).ToArray()),
            "limit" => CmdLimit(store, args.Skip(1).ToArray()),
            "block" => CmdBlock(store, args.Skip(1).ToArray()),
            "allow" => CmdAllow(store, args.Skip(1).ToArray()),
            "block-domain" => CmdBlockDomain(store, args.Skip(1).ToArray()),
            "allow-domain" => CmdAllowDomain(store, args.Skip(1).ToArray()),
            "dns" => CmdDns(args.Skip(1).ToArray()),
            "api" => CmdApi(args.Skip(1).ToArray()),
            "certs" => CmdCerts(args.Skip(1).ToArray()),
            "driver" => CmdDriver(args.Skip(1).ToArray()),
            "access" => CmdAccess(args.Skip(1).ToArray()),
            "unblock" => CmdUnblock(store, args.Skip(1).ToArray()),
            "enable" => CmdEnable(store, args.Skip(1).ToArray(), enabled: true),
            "disable" => CmdEnable(store, args.Skip(1).ToArray(), enabled: false),
            "list" => CmdList(store),
            "sample" or "live" => CmdSample(args.Skip(1).ToArray()),
            "limits" => CmdLimits(store),
            "shaper" => CmdShaper(store, args.Skip(1).ToArray()),
            "stats" => CmdStats(args.Skip(1).ToArray()),
            "quotas" => CmdQuotas(store),
            "apply-wfp" => CmdApplyWfp(store, args.Skip(1).ToArray()),
            "apply-qos" => CmdApplyQos(store),
            "apply-all" => CmdApplyAll(store, args.Skip(1).ToArray()),
            "clear-wfp" => CmdClearWfp(args.Skip(1).ToArray()),
            "clear-qos" => CmdClearQos(),
            "wfp-status" => CmdWfpStatus(args.Skip(1).ToArray()),
            "export" => CmdExport(store, args.Skip(1).ToArray()),
            "import" => CmdImport(store, args.Skip(1).ToArray()),
            _ => HelpFail(),
        };
    }

    static int HelpFail()
    {
        PrintHelp();
        return 1;
    }

    static void PrintHelp()
    {
        Console.WriteLine("""
            NetShaper CLI (free open source)

              list | limits | quotas
              sample [seconds]   live rates + data (admin recommended)
              shaper [off|qos|soft|aggressive|packet|probe] get/set shaper / probe WinDivert
              stats [info|top|export-system <file>|purge]
              policy show|init
              limit <pathContains> <kbps> [--dir both]      store limit; shaper enforces
              block|allow <path|fragment> [--dir both]
              block-domain|allow-domain <domain>
              dns [refresh|list]
              api show|enable|disable|remote-enable|get|rget|post|rpost ...
              certs status|ensure|issue|export|rotate|reset|list|revoke
              driver status|push|clear|enable|disable
              access show|enable|disable|add <principal> <rights>|remove <principal>
              unblock|enable|disable <substring>
              apply-wfp [--persist]                         ADMIN: WFP block/allow
              apply-qos                                     ADMIN: NetQos throttle/DSCP
              apply-all [--persist]                         ADMIN: WFP + QoS
              clear-wfp [--persist] | clear-qos
              wfp-status [--persist]
              export <file.json> | import <file.json>

            Policy: %ProgramData%\NetShaper\policy.json
            """);
    }

    static int CmdList(PolicyStore store)
    {
        var doc = store.LoadOrCreate();
        Console.WriteLine($"Policy v{doc.Version}  limiter={doc.LimiterEnabled} fw={doc.FirewallEnabled}");
        Console.WriteLine($"Filters ({doc.Filters.Count}):");
        foreach (var f in doc.Filters)
            Console.WriteLine($"  [{f.Id:N}] {f.Name} matchers={f.Matchers.Count} zone={f.IsZone}");
        Console.WriteLine($"Rules ({doc.Rules.Count}):");
        foreach (var r in doc.Rules)
            Console.WriteLine(
                $"  [{r.Id:N}] {r.Kind,-6} filter={r.FilterId:N} dir={r.Direction} " +
                $"limitBps={r.LimitBytesPerSec} enabled={r.Enabled}");
        return 0;
    }

    static int CmdSample(string[] args)
    {
        var seconds = 2.0;
        if (args.Length > 0 && double.TryParse(args[0], out var s) && s > 0 && s < 60)
            seconds = s;

        using var sampler = new WindowsTrafficSampler { PreferEStats = true };
        Console.WriteLine("Sampling traffic (TCP EStats for per-app rates — Admin recommended)...");
        Console.WriteLine("Elevated: " + WindowsTrafficSampler.IsProcessElevated());

        // Warm-up
        _ = sampler.Sample(true);
        Thread.Sleep(TimeSpan.FromSeconds(Math.Max(0.8, seconds)));
        var snap = sampler.Sample(true);

        Console.WriteLine(snap.SamplerStatus);
        Console.WriteLine(
            $"System  ↓ {ProcessTraffic.FormatRate(snap.TotalBitsPerSecIn)}  " +
            $"↑ {ProcessTraffic.FormatRate(snap.TotalBitsPerSecOut)}  " +
            $"apps={snap.Processes.Count} conns={snap.Connections.Count} estats={snap.EStatsWorking}");
        Console.WriteLine();
        Console.WriteLine($"{"PID",6} {"Process / Service",-36} {"↓ rate",10} {"↑ rate",10} {"↓ data",10} {"↑ data",10} {"Cn",4}");
        foreach (var p in snap.Processes.Take(25))
        {
            Console.WriteLine(
                $"{p.ProcessId,6} {Truncate(p.DisplayName, 36),-36} " +
                $"{p.RateInDisplay,10} {p.RateOutDisplay,10} " +
                $"{p.DataInDisplay,10} {p.DataOutDisplay,10} {p.ConnectionCount,4}");
        }

        var hot = snap.Connections.Where(c => c.BitsPerSecIn + c.BitsPerSecOut > 1000).Take(15).ToList();
        if (hot.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("Active connections:");
            foreach (var c in hot)
                Console.WriteLine(
                    $"  {c.ProcessName,-16} {c.Protocol,-5} ↓{c.RateInDisplay} ↑{c.RateOutDisplay}  " +
                    $"{c.RemoteEndPoint}  data↓{c.DataInDisplay}");
        }

        if (!snap.EStatsWorking)
        {
            Console.WriteLine();
            Console.WriteLine("NOTE: Per-app rates need Administrator so TCP EStats can enable.");
            Console.WriteLine("      System ↓/↑ still work from interface counters.");
            return 4;
        }
        return 0;
    }

    static string Truncate(string s, int n) =>
        s.Length <= n ? s : s[..(n - 1)] + "…";

    static int CmdLimits(PolicyStore store)
    {
        var doc = store.LoadOrCreate();
        var enforcer = new LimitEnforcer();
        var limits = enforcer.GetActiveLimits(doc);
        if (limits.Count == 0)
        {
            Console.WriteLine("No active limit rules.");
        }
        else
        {
            foreach (var l in limits)
            {
                var kbps = l.BytesPerSec * 8 / 1000.0;
                Console.WriteLine($"{l.FilterName,-32} {kbps,8:0} kbps  {l.Direction}  schedOK={l.ScheduleActive}  [{string.Join("; ", l.MatcherSummary)}]");
            }
        }
        Console.WriteLine();
        Console.WriteLine(enforcer.ExplainGap());
        return 0;
    }

    static int CmdQuotas(PolicyStore store)
    {
        var doc = store.LoadOrCreate();
        var q = new QuotaTracker();
        var list = q.GetStatuses(doc);
        if (list.Count == 0)
        {
            Console.WriteLine("No quota rules.");
            return 0;
        }
        foreach (var s in list)
        {
            Console.WriteLine(
                $"{s.FilterName,-32} {s.UsedBytes,12} / {s.CeilingBytes,-12} ({s.Percent:0.0}%) " +
                $"exceeded={s.Exceeded} active={s.ActiveNow}");
        }
        return 0;
    }

    static int CmdStats(string[] args)
    {
        using var stats = new StatsStore();
        var cmd = args.Length > 0 ? args[0].ToLowerInvariant() : "info";
        switch (cmd)
        {
            case "info":
            {
                var i = stats.GetInfo();
                Console.WriteLine($"Path: {i.Path}");
                Console.WriteLine($"Size: {i.FileBytes} bytes");
                Console.WriteLine($"Samples: {i.SampleCount}");
                Console.WriteLine($"Process samples: {i.ProcessSampleCount}");
                Console.WriteLine($"App total rows: {i.AppTotalRows}");
                Console.WriteLine($"Range: {i.OldestTs} .. {i.NewestTs}");
                Console.WriteLine($"RetentionDays: {i.RetentionDays}");
                return 0;
            }
            case "top":
            {
                var to = DateTimeOffset.UtcNow;
                var from = to.AddHours(-24);
                foreach (var a in stats.QueryTopApps(from, to, 20))
                    Console.WriteLine($"{a.Name,-28} in={a.BytesIn,12} out={a.BytesOut,12}");
                return 0;
            }
            case "export-system":
            {
                if (args.Length < 2) { Console.WriteLine("stats export-system <file.csv>"); return 1; }
                var to = DateTimeOffset.UtcNow;
                File.WriteAllText(args[1], stats.ExportSystemCsv(to.AddDays(-7), to));
                Console.WriteLine("Wrote " + args[1]);
                return 0;
            }
            case "purge":
                stats.PurgeOlderThan(stats.RetentionDays);
                Console.WriteLine("Purged older than " + stats.RetentionDays + " days");
                return 0;
            default:
                Console.WriteLine("stats info|top|export-system <file>|purge");
                return 1;
        }
    }

    static int CmdShaper(PolicyStore store, string[] args)
    {
        var doc = store.LoadOrCreate();
        if (args.Length == 0)
        {
            Console.WriteLine($"ShaperMode={doc.ShaperMode}  LimiterEnabled={doc.LimiterEnabled}");
            Console.WriteLine(new LimitEnforcer().ExplainGap(doc));
            Console.WriteLine("Set: shaper off|qos|soft|aggressive");
            return 0;
        }
        var m = args[0].ToLowerInvariant() switch
        {
            "off" or "0" => BandwidthShaperMode.Off,
            "qos" or "1" => BandwidthShaperMode.Qos,
            "soft" or "2" => BandwidthShaperMode.Soft,
            "aggressive" or "agg" or "3" => BandwidthShaperMode.Aggressive,
            "packet" or "windivert" or "4" => BandwidthShaperMode.Packet,
            "probe" => null,
            _ => (BandwidthShaperMode?)null,
        };
        if (args[0].Equals("probe", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine(new PolicyEnforcer().Shaper.PacketProbe);
            Console.WriteLine("Install: powershell -ExecutionPolicy Bypass -File scripts\\install-windivert.ps1");
            return 0;
        }
        if (m is null)
        {
            Console.WriteLine("Usage: shaper [off|qos|soft|aggressive|packet|probe]");
            return 1;
        }
        doc.ShaperMode = m.Value;
        if (m.Value != BandwidthShaperMode.Off)
            doc.LimiterEnabled = true;
        store.Save(doc);
        Console.WriteLine($"ShaperMode={doc.ShaperMode}");
        Console.WriteLine(new LimitEnforcer().ExplainGap(doc));
        if (m.Value == BandwidthShaperMode.Packet)
            Console.WriteLine(new PolicyEnforcer().Shaper.PacketProbe);
        return 0;
    }

    static int CmdApplyQos(PolicyStore store)
    {
        if (!IsAdmin())
        {
            Console.Error.WriteLine("apply-qos requires Administrator.");
            return 2;
        }
        var doc = store.LoadOrCreate();
        var eng = new PolicyEnforcer();
        var r = eng.ApplyAll(doc, persistWfp: true, applyWfp: false, applyQos: true);
        Console.WriteLine(r.Summary);
        foreach (var e in r.Errors) Console.WriteLine("  " + e);
        return r.Errors.Count > 0 ? 3 : 0;
    }

    static int CmdApplyAll(PolicyStore store, string[] args)
    {
        if (!IsAdmin())
        {
            Console.Error.WriteLine("apply-all requires Administrator.");
            return 2;
        }
        var persist = args.Any(a => a is "--persist" or "-p");
        var doc = store.LoadOrCreate();
        var eng = new PolicyEnforcer();
        var r = eng.ApplyAll(doc, persistWfp: persist || true, applyWfp: true, applyQos: true);
        Console.WriteLine(r.Summary);
        foreach (var e in r.Errors) Console.WriteLine("  " + e);
        return 0;
    }

    static int CmdClearQos()
    {
        if (!IsAdmin())
        {
            Console.Error.WriteLine("clear-qos requires Administrator.");
            return 2;
        }
        var errors = new List<string>();
        var n = new QosEnforcer().ClearOurPolicies(errors);
        Console.WriteLine($"Cleared ≈{n} NetShaper QoS policies.");
        foreach (var e in errors) Console.WriteLine("  " + e);
        return 0;
    }

    static int CmdExport(PolicyStore store, string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("export <file.json>");
            return 1;
        }
        store.ExportTo(args[0]);
        Console.WriteLine("Exported to " + args[0]);
        return 0;
    }

    static int CmdImport(PolicyStore store, string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("import <file.json>");
            return 1;
        }
        store.ImportFrom(args[0], replace: true);
        Console.WriteLine("Imported from " + args[0]);
        return 0;
    }

    static int CmdPolicy(PolicyStore store, string[] args)
    {
        if (args.Length == 0) { Console.WriteLine("policy show|init"); return 1; }
        switch (args[0].ToLowerInvariant())
        {
            case "show":
                Console.WriteLine(File.Exists(store.FilePath) ? File.ReadAllText(store.FilePath) : "(missing)");
                return 0;
            case "init":
                store.Save(PolicyDocument.CreateDefaults());
                Console.WriteLine("Wrote " + store.FilePath);
                return 0;
            default:
                return 1;
        }
    }

    static int CmdLimit(PolicyStore store, string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("limit <appPathContains> <kbps> [--dir both]");
            return 1;
        }
        if (!long.TryParse(args[1], out var kbps) || kbps <= 0)
        {
            Console.WriteLine("kbps must be positive");
            return 1;
        }
        var dir = ParseDir(args);
        var doc = store.LoadOrCreate();
        PolicyEditor.AddLimit(doc, args[0], kbps, dir);
        store.Save(doc);
        Console.WriteLine($"Stored limit {kbps} kbps on '{args[0]}'.");
        Console.WriteLine(new LimitEnforcer().ExplainGap());
        return 0;
    }

    static int CmdBlock(PolicyStore store, string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("block <pathContains|fullPath> [--dir both]");
            return 1;
        }
        var target = args[0];
        var dir = ParseDir(args);
        var doc = store.LoadOrCreate();
        PolicyEditor.AddBlock(doc, target, dir);
        store.Save(doc);
        Console.WriteLine($"Stored BLOCK on '{target}'.");
        Console.WriteLine("Enforce:  apply-wfp           (until process exits)");
        Console.WriteLine("Persist:  apply-wfp --persist (survives until clear-wfp --persist)");
        return 0;
    }

    static int CmdAllow(PolicyStore store, string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("allow <pathContains|fullPath> [--dir both]");
            return 1;
        }
        var target = args[0];
        var dir = ParseDir(args);
        var doc = store.LoadOrCreate();
        PolicyEditor.AddAllow(doc, target, dir);
        store.Save(doc);
        Console.WriteLine($"Stored ALLOW on '{target}'.");
        Console.WriteLine("Enforce:  apply-wfp [--persist]");
        return 0;
    }

    static int CmdBlockDomain(PolicyStore store, string[] args)
    {
        if (args.Length < 1) { Console.WriteLine("block-domain <domain>"); return 1; }
        var doc = store.LoadOrCreate();
        doc.DnsEnabled = true;
        PolicyEditor.AddDomainBlock(doc, args[0], ParseDir(args));
        store.Save(doc);
        Console.WriteLine($"Stored BLOCK domain '{args[0]}'. Apply WFP resolves IPs.");
        return 0;
    }

    static int CmdAllowDomain(PolicyStore store, string[] args)
    {
        if (args.Length < 1) { Console.WriteLine("allow-domain <domain>"); return 1; }
        var doc = store.LoadOrCreate();
        doc.DnsEnabled = true;
        PolicyEditor.AddDomainAllow(doc, args[0], ParseDir(args));
        store.Save(doc);
        Console.WriteLine($"Stored ALLOW domain '{args[0]}'. Apply WFP resolves IPs.");
        return 0;
    }

    static int CmdDns(string[] args)
    {
        var cache = new DnsCache();
        var sub = args.Length > 0 ? args[0].ToLowerInvariant() : "list";
        if (sub is "refresh" or "list")
        {
            cache.RefreshFromSystemDnsCache();
            Console.WriteLine($"hosts={cache.CountHosts} ips={cache.CountIps}");
            foreach (var e in cache.Snapshot(40))
                Console.WriteLine($"{e.Host,-40} {e.Ip}");
            return 0;
        }
        Console.WriteLine("dns [refresh|list]");
        return 1;
    }

    static int CmdAccess(string[] args)
    {
        try
        {
            var store = new AccessControlStore();
            var doc = store.Load();
            if (args.Length == 0 || args[0] is "show" or "status")
            {
                Console.WriteLine(AccessChecker.DescribeCurrent(doc));
                Console.WriteLine($"Enabled={doc.Enabled}  AdminsFull={doc.AdministratorsFullAccess}");
                Console.WriteLine($"File={store.FilePath}");
                foreach (var e in doc.Entries)
                    Console.WriteLine($"  {e.Principal,-32} {e.Allowed,-20} sid={e.Sid} {e.Note}");
                return 0;
            }
            switch (args[0].ToLowerInvariant())
            {
                case "enable":
                    EnsureSelfHasControl(doc);
                    doc.Enabled = true;
                    store.Save(doc);
                    Console.WriteLine("ACL enabled.");
                    return 0;
                case "disable":
                    if (!AccessChecker.IsLocalAdmin(System.Security.Principal.WindowsIdentity.GetCurrent()) &&
                        !AccessChecker.Has(AccessRight.Control, doc))
                    {
                        Console.Error.WriteLine("Only Control users or Administrators can disable ACL.");
                        return 5;
                    }
                    doc.Enabled = false;
                    store.Save(doc);
                    Console.WriteLine("ACL disabled (open access).");
                    return 0;
                case "add":
                {
                    if (args.Length < 3)
                    {
                        Console.WriteLine("access add <principal> <Monitor|Control|RemoteApi|All>[,...]");
                        return 1;
                    }
                    EnsureSelfHasControl(doc);
                    var rights = ParseRights(args[2]);
                    var principal = args[1];
                    var sid = AccessChecker.TryResolveSid(principal);
                    doc.Entries.RemoveAll(e =>
                        e.Principal.Equals(principal, StringComparison.OrdinalIgnoreCase) ||
                        (!string.IsNullOrEmpty(sid) && e.Sid == sid));
                    doc.Entries.Add(new AccessEntry
                    {
                        Principal = principal,
                        Sid = sid,
                        Allowed = rights,
                    });
                    store.Save(doc);
                    Console.WriteLine($"Added {principal} → {rights} sid={sid}");
                    return 0;
                }
                case "remove":
                {
                    if (args.Length < 2) { Console.WriteLine("access remove <principal>"); return 1; }
                    EnsureSelfHasControl(doc);
                    var n = doc.Entries.RemoveAll(e =>
                        e.Principal.Equals(args[1], StringComparison.OrdinalIgnoreCase));
                    store.Save(doc);
                    Console.WriteLine($"Removed {n} entr(y/ies).");
                    return 0;
                }
                default:
                    Console.WriteLine("access show|enable|disable|add <principal> <rights>|remove <principal>");
                    return 1;
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 5;
        }
    }

    static void EnsureSelfHasControl(AccessControlDocument doc)
    {
        // When enabling or editing, if ACL already on require Control; if off, require admin or allow anyone
        if (doc.Enabled && !AccessChecker.Has(AccessRight.Control, doc) &&
            !AccessChecker.IsLocalAdmin(System.Security.Principal.WindowsIdentity.GetCurrent()))
            throw new UnauthorizedAccessException("Requires Control right to modify ACL.");
        // When turning on first time with empty list, inject current user as All
        if (doc.Entries.Count == 0)
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            doc.Entries.Add(new AccessEntry
            {
                Principal = id.Name ?? Environment.UserName,
                Sid = id.User?.Value,
                Allowed = AccessRight.All,
                Note = "auto-added on ACL setup",
            });
        }
    }

    static AccessRight ParseRights(string s)
    {
        AccessRight r = AccessRight.None;
        foreach (var part in s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.Equals("All", StringComparison.OrdinalIgnoreCase)) return AccessRight.All;
            if (Enum.TryParse<AccessRight>(part, true, out var p)) r |= p;
        }
        return r == AccessRight.None ? AccessRight.Monitor : r;
    }

    static int CmdApi(string[] args)
    {
        var s = ApiSettings.Load();
        s.EnsureKey();
        if (args.Length == 0 || args[0] is "show" or "status")
        {
            Console.WriteLine($"Local:   Enabled={s.Enabled}  {s.BaseUrl}/api/v1");
            Console.WriteLine($"Remote:  Enabled={s.RemoteEnabled}  {s.RemoteBaseUrl}/api/v1  (mTLS)");
            Console.WriteLine($"Key:     {s.ApiKey}");
            Console.WriteLine($"File:    {ApiSettings.FilePath}");
            Console.WriteLine($"Certs:   {CertificateManager.CertsDir}");
            return 0;
        }
        switch (args[0].ToLowerInvariant())
        {
            case "enable":
                s.Enabled = true; s.Save();
                Console.WriteLine("Local API enabled. Restart host.");
                return 0;
            case "disable":
                s.Enabled = false; s.Save();
                Console.WriteLine("Local API disabled.");
                return 0;
            case "remote-enable":
                s.RemoteEnabled = true;
                if (args.Length > 1 && int.TryParse(args[1], out var p)) s.RemotePort = p;
                s.Save();
                CertificateManager.EnsurePki(s.RemoteHostName);
                Console.WriteLine($"Remote mTLS enabled on port {s.RemotePort}. Restart host. Issue client: certs issue <name>");
                return 0;
            case "remote-disable":
                s.RemoteEnabled = false; s.Save();
                Console.WriteLine("Remote API disabled.");
                return 0;
            case "get":
            {
                if (args.Length < 2) { Console.WriteLine("api get <path>"); return 1; }
                using var c = new ApiClient(s.BaseUrl, s.ApiKey);
                Console.WriteLine(c.GetAsync(args[1]).GetAwaiter().GetResult());
                return 0;
            }
            case "post":
            {
                if (args.Length < 2) { Console.WriteLine("api post <path> [json]"); return 1; }
                object? body = args.Length >= 3
                    ? System.Text.Json.JsonSerializer.Deserialize<object>(args[2]) : null;
                using var c = new ApiClient(s.BaseUrl, s.ApiKey);
                Console.WriteLine(c.PostAsync(args[1], body).GetAwaiter().GetResult());
                return 0;
            }
            case "rget":
            {
                if (args.Length < 3) { Console.WriteLine("api rget <clientName> <path> [host]"); return 1; }
                var host = args.Length >= 4 ? args[3] : s.RemoteHostName;
                var pfx = Path.Combine(CertificateManager.ClientsDir, args[1] + ".pfx");
                using var c = ApiClient.CreateRemote(host, s.RemotePort, s.ApiKey, pfx);
                Console.WriteLine(c.GetAsync(args[2]).GetAwaiter().GetResult());
                return 0;
            }
            case "rpost":
            {
                if (args.Length < 3) { Console.WriteLine("api rpost <clientName> <path> [json] [host]"); return 1; }
                var host = args.Length >= 5 ? args[4] : s.RemoteHostName;
                object? body = args.Length >= 4
                    ? System.Text.Json.JsonSerializer.Deserialize<object>(args[3]) : null;
                var pfx = Path.Combine(CertificateManager.ClientsDir, args[1] + ".pfx");
                using var c = ApiClient.CreateRemote(host, s.RemotePort, s.ApiKey, pfx);
                Console.WriteLine(c.PostAsync(args[2], body).GetAwaiter().GetResult());
                return 0;
            }
            default:
                Console.WriteLine("api show|enable|disable|remote-enable|remote-disable|get|post|rget|rpost");
                return 1;
        }
    }

    static int CmdCerts(string[] args)
    {
        if (args.Length == 0 || args[0] is "list" or "status")
        {
            Console.WriteLine("PKI ready:     " + CertificateManager.HasPki);
            Console.WriteLine("Dir:           " + CertificateManager.CertsDir);
            Console.WriteLine("Password via:  " + CertificateManager.PasswordSource);
            if (CertificateManager.IsUsingLegacyDevPassword)
                Console.WriteLine("WARNING: using legacy dev password — run: certs rotate <newPassword>");
            if (args.Length == 0 || args[0] is "status")
            {
                // Do not print password unless --show-password
                if (args.Any(a => a is "--show-password" or "-p"))
                    Console.WriteLine("PFX password:  " + CertificateManager.PfxPassword);
                else
                    Console.WriteLine("PFX password:  (hidden; pass --show-password or read pki-password.txt)");
            }
            foreach (var c in CertificateManager.LoadClients())
                Console.WriteLine($"  {c.Name,-20} revoked={c.Revoked} tp={c.Thumbprint}");
            return 0;
        }
        switch (args[0].ToLowerInvariant())
        {
            case "ensure":
            {
                string? server = null;
                for (int i = 1; i < args.Length - 1; i++)
                    if (args[i] == "--server") server = args[i + 1];
                CertificateManager.EnsurePki(server);
                Console.WriteLine("CA + server cert ready: " + CertificateManager.CertsDir);
                Console.WriteLine("Password source: " + CertificateManager.PasswordSource);
                if (CertificateManager.IsUsingLegacyDevPassword)
                    Console.WriteLine("WARNING: legacy password — run: certs rotate <newPassword>");
                else if (!args.Any(a => a == "--quiet"))
                    Console.WriteLine("PFX password: " + CertificateManager.PfxPassword);
                return 0;
            }
            case "issue":
            {
                if (args.Length < 2) { Console.WriteLine("certs issue <name>"); return 1; }
                CertificateManager.EnsurePki();
                var (_, path) = CertificateManager.IssueClientCertificate(args[1]);
                Console.WriteLine("Issued " + path);
                Console.WriteLine("Password source: " + CertificateManager.PasswordSource);
                Console.WriteLine("PFX password: " + CertificateManager.PfxPassword);
                return 0;
            }
            case "export":
            {
                // certs export <name> <out.pfx> <oneTimePassword>
                if (args.Length < 4)
                {
                    Console.WriteLine("certs export <clientName> <out.pfx> <oneTimePassword>");
                    return 1;
                }
                var dest = CertificateManager.ExportClientWithPassword(args[1], args[2], args[3]);
                Console.WriteLine("Exported " + dest + " (one-time password you provided)");
                return 0;
            }
            case "rotate":
            {
                if (args.Length < 2)
                {
                    Console.WriteLine("certs rotate <newPassword> [oldPassword]");
                    Console.WriteLine("  Re-encrypts CA, server, and all client PFX files.");
                    return 1;
                }
                string? old = args.Length >= 3 ? args[2] : null;
                try
                {
                    var n = CertificateManager.RotatePassword(args[1], old);
                    Console.WriteLine($"Rotated password on {n} PFX file(s).");
                    Console.WriteLine("Password file: " + CertificateManager.PasswordFilePath);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(ex.Message);
                    return 3;
                }
                return 0;
            }
            case "reset":
            {
                // Destructive: wipe PKI and create new CA + strong password
                if (!args.Any(a => a is "--yes" or "-y"))
                {
                    Console.WriteLine("This DELETES the CA and all client certs.");
                    Console.WriteLine("Re-run: certs reset --yes [--server NAME]");
                    return 1;
                }
                string? server = null;
                for (int i = 1; i < args.Length - 1; i++)
                    if (args[i] == "--server") server = args[i + 1];
                CertificateManager.ResetPki(server, generateNewPassword: true);
                Console.WriteLine("PKI reset. New password: " + CertificateManager.PfxPassword);
                Console.WriteLine("Re-issue clients: certs issue <name>");
                return 0;
            }
            case "revoke":
            {
                if (args.Length < 2) { Console.WriteLine("certs revoke <name|thumbprint>"); return 1; }
                CertificateManager.RevokeClient(args[1]);
                Console.WriteLine("Revoked " + args[1]);
                return 0;
            }
            default:
                Console.WriteLine("certs status|ensure|issue <name>|export <name> <out.pfx> <pass>|rotate <newPass>|reset --yes|list|revoke");
                return 1;
        }
    }

    static int CmdDriver(string[] args)
    {
        using var d = new NetShaper.Core.Driver.NetShaperDriverClient();
        var sub = args.Length > 0 ? args[0].ToLowerInvariant() : "status";
        switch (sub)
        {
            case "status":
                Console.WriteLine(d.StatusText());
                Console.WriteLine("Build: see driver\\README.md  Install: scripts\\install-driver-testsign.ps1");
                return 0;
            case "push":
            {
                var store = new PolicyStore();
                var doc = store.LoadOrCreate();
                d.SetEnabled(true);
                if (!d.PushLimitsFromPolicy(doc))
                {
                    Console.Error.WriteLine(d.LastError ?? "push failed");
                    return 3;
                }
                Console.WriteLine("Limits pushed. " + d.StatusText());
                return 0;
            }
            case "clear":
                if (!d.ClearLimits())
                {
                    Console.Error.WriteLine(d.LastError ?? "clear failed");
                    return 3;
                }
                Console.WriteLine("Limits cleared. " + d.StatusText());
                return 0;
            case "enable":
                if (!d.SetEnabled(true))
                {
                    Console.Error.WriteLine(d.LastError ?? "enable failed");
                    return 3;
                }
                Console.WriteLine(d.StatusText());
                return 0;
            case "disable":
                if (!d.SetEnabled(false))
                {
                    Console.Error.WriteLine(d.LastError ?? "disable failed");
                    return 3;
                }
                Console.WriteLine(d.StatusText());
                return 0;
            default:
                Console.WriteLine("driver status|push|clear|enable|disable");
                return 1;
        }
    }

    static int CmdUnblock(PolicyStore store, string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("unblock <substring matching filter name or path>");
            return 1;
        }
        var q = args[0];
        var doc = store.LoadOrCreate();
        var removedRules = PolicyEditor.Unblock(doc, q);
        store.Save(doc);
        Console.WriteLine($"Removed {removedRules} block rule(s). Run clear-wfp / apply-wfp to sync engine.");
        return 0;
    }

    static int CmdEnable(PolicyStore store, string[] args, bool enabled)
    {
        if (args.Length < 1)
        {
            Console.WriteLine((enabled ? "enable" : "disable") + " <substring>");
            return 1;
        }
        var q = args[0];
        var doc = store.LoadOrCreate();
        var filterIds = doc.Filters
            .Where(f => f.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                        f.Matchers.Any(m => (m.StringValue ?? "").Contains(q, StringComparison.OrdinalIgnoreCase)))
            .Select(f => f.Id)
            .ToHashSet();
        var n = 0;
        foreach (var r in doc.Rules.Where(r => filterIds.Contains(r.FilterId)))
        {
            r.Enabled = enabled;
            r.UpdatedUtc = DateTimeOffset.UtcNow;
            n++;
        }
        store.Save(doc);
        Console.WriteLine($"{(enabled ? "Enabled" : "Disabled")} {n} rule(s) matching '{q}'.");
        return 0;
    }

    static int CmdApplyWfp(PolicyStore store, string[] args)
    {
        if (!IsAdmin())
        {
            Console.Error.WriteLine("apply-wfp requires Administrator elevation.");
            return 2;
        }
        var persist = args.Any(a => a is "--persist" or "-p");
        var mode = persist ? WfpSessionMode.Persistent : WfpSessionMode.Dynamic;
        var doc = store.LoadOrCreate();
        var dns = new DnsCache();
        if (doc.DnsEnabled)
        {
            dns.RefreshFromSystemDnsCache();
            FilterMatcher.SharedDns = dns;
        }
        using var engine = new WfpFilterEngine(mode) { Dns = dns };
        try
        {
            var n = engine.ApplyPolicy(doc);
            Console.WriteLine(
                $"WFP applied ({mode}): {n} path group(s), {engine.ActiveFilterCount} layer filter(s).");
            if (n == 0)
                Console.WriteLine("No block/allow app-path rules matched. Example: block notepad");
            if (mode == WfpSessionMode.Dynamic)
                Console.WriteLine("Dynamic mode: filters removed when this process exits. Use --persist or the Windows service for durability.");
            else
                Console.WriteLine("Persistent mode: filters remain until clear-wfp --persist (or reboot-safe until deleted).");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("WFP failed: " + ex.Message);
            return 3;
        }
    }

    static int CmdClearWfp(string[] args)
    {
        if (!IsAdmin())
        {
            Console.Error.WriteLine("clear-wfp requires Administrator.");
            return 2;
        }
        var persist = args.Any(a => a is "--persist" or "-p");
        var mode = persist ? WfpSessionMode.Persistent : WfpSessionMode.Dynamic;
        using var engine = new WfpFilterEngine(mode);
        try
        {
            var n = engine.ClearOurFilters();
            Console.WriteLine($"Cleared NetShaper WFP filters ({mode}), removed≈{n}.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("clear-wfp failed: " + ex.Message);
            return 3;
        }
    }

    static int CmdWfpStatus(string[] args)
    {
        if (!IsAdmin())
        {
            Console.Error.WriteLine("wfp-status requires Administrator to open the engine.");
            return 2;
        }
        var persist = args.Any(a => a is "--persist" or "-p");
        using var engine = new WfpFilterEngine(persist ? WfpSessionMode.Persistent : WfpSessionMode.Dynamic);
        try
        {
            var s = engine.GetStatus();
            Console.WriteLine($"Mode: {s.Mode}");
            Console.WriteLine($"Tracked keys: {s.TrackedFilterKeys}");
            Console.WriteLine($"State file: {s.StateFile}");
            Console.WriteLine($"Provider: {s.ProviderKey}");
            Console.WriteLine($"Sublayer: {s.SublayerKey}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 3;
        }
    }

    static TrafficDirection ParseDir(string[] args)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (args[i] == "--dir" && Enum.TryParse<TrafficDirection>(args[i + 1], true, out var d))
                return d;
        return TrafficDirection.Both;
    }

    static bool IsAdmin()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}
