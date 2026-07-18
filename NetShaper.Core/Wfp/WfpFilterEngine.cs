using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using NetShaper.Core.Dns;
using NetShaper.Core.Policy;

namespace NetShaper.Core.Wfp;

public enum WfpSessionMode
{
    /// <summary>Filters die when this process exits (safe for experiments).</summary>
    Dynamic,
    /// <summary>Filters survive process exit until explicitly deleted.</summary>
    Persistent,
}

/// <summary>
/// Usermode WFP allow/block via fwpuclnt (documented APIs).
/// P1 block/allow only — rate limits are P2/P3.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WfpFilterEngine : IDisposable
{
    public const string ProviderName = "NetShaper";
    public static readonly Guid ProviderKey = new("A7B2C3D4-E5F6-7890-ABCD-EF1234567890");
    public static readonly Guid SublayerKey = new("B8C3D4E5-F6A7-8901-BCDE-F12345678901");

    private static readonly string StateDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "NetShaper");
    private static readonly string FilterStatePath = Path.Combine(StateDir, "wfp-filters.json");

    private IntPtr _engine;
    private readonly List<Guid> _filterKeys = new();
    private readonly WfpSessionMode _mode;
    private bool _disposed;

    public WfpFilterEngine(WfpSessionMode mode = WfpSessionMode.Dynamic) => _mode = mode;

    public bool IsOpen => _engine != IntPtr.Zero;
    public int ActiveFilterCount => _filterKeys.Count;
    public WfpSessionMode Mode => _mode;

    public void Open()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_engine != IntPtr.Zero) return;

        var session = new FWPM_SESSION0
        {
            displayData = new FWPM_DISPLAY_DATA0
            {
                name = ProviderName + " Session",
                description = _mode == WfpSessionMode.Dynamic
                    ? "NetShaper dynamic session"
                    : "NetShaper persistent session",
            },
            flags = _mode == WfpSessionMode.Dynamic ? FWPM_SESSION_FLAG_DYNAMIC : 0,
        };

        Check(FwpmEngineOpen0(null, RPC_C_AUTHN_DEFAULT, IntPtr.Zero, ref session, out _engine),
            "FwpmEngineOpen0");
        EnsureProviderAndSublayer();
        LoadKnownKeys();
    }

    private void EnsureProviderAndSublayer()
    {
        var provider = new FWPM_PROVIDER0
        {
            providerKey = ProviderKey,
            displayData = new FWPM_DISPLAY_DATA0
            {
                name = ProviderName,
                description = "NetShaper WFP provider",
            },
            flags = _mode == WfpSessionMode.Persistent ? FWPM_PROVIDER_FLAG_PERSISTENT : 0,
        };
        var st = FwpmProviderAdd0(_engine, ref provider, IntPtr.Zero);
        if (st != 0 && st != FWP_E_ALREADY_EXISTS)
            throw new Win32Exception((int)st, "FwpmProviderAdd0");

        var pk = ProviderKey;
        var pkHandle = GCHandle.Alloc(pk, GCHandleType.Pinned);
        try
        {
            var sublayer = new FWPM_SUBLAYER0
            {
                subLayerKey = SublayerKey,
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = ProviderName + " Sublayer",
                    description = "NetShaper rules",
                },
                flags = _mode == WfpSessionMode.Persistent ? FWPM_SUBLAYER_FLAG_PERSISTENT : 0,
                providerKey = pkHandle.AddrOfPinnedObject(),
                weight = 0x8000,
            };
            st = FwpmSubLayerAdd0(_engine, ref sublayer, IntPtr.Zero);
            if (st != 0 && st != FWP_E_ALREADY_EXISTS)
                throw new Win32Exception((int)st, "FwpmSubLayerAdd0");
        }
        finally
        {
            pkHandle.Free();
        }
    }

    /// <summary>Optional DNS map for domain → IP WFP rules.</summary>
    public DnsCache? Dns { get; set; }

    /// <summary>Install block/allow filters. Returns number of path/domain groups processed.</summary>
    public int ApplyPolicy(PolicyDocument doc)
    {
        Open();
        ClearOurFilters();

        int groups = 0;
        // In lockdown: catch-all block first (low weight), then allows (high weight), then explicit blocks.
        if (doc.LockdownEnabled && doc.FirewallEnabled)
        {
            AddCatchAllBlock(TrafficDirection.Out, "lockdown-default-out", weight: 1);
            AddCatchAllBlock(TrafficDirection.In, "lockdown-default-in", weight: 1);
            groups++;
        }

        foreach (var rule in doc.Rules.Where(r => r.Enabled && r.Kind is RuleKind.Block or RuleKind.Allow))
        {
            // Schedules already applied by PolicyEnforcer via Enabled=false
            var filter = doc.Filters.FirstOrDefault(f => f.Id == rule.FilterId);
            if (filter == null) continue;

            var paths = ResolvePaths(filter).ToList();
            var remoteIps = ResolveRemoteIps(filter).ToList();
            if (paths.Count == 0 && remoteIps.Count == 0) continue;
            groups++;

            // Allow must outrank lockdown catch-all; blocks mid-weight
            ulong w = rule.Kind == RuleKind.Allow ? 15UL : 8UL;
            foreach (var path in paths)
            {
                try
                {
                    AddAppPathFilter(path, rule.Kind == RuleKind.Block, rule.Direction, filter.Name, w);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"WFP skip {path}: {ex.Message}");
                }
            }

            foreach (var ip in remoteIps.Take(64))
            {
                try
                {
                    AddRemoteIpFilter(ip, rule.Kind == RuleKind.Block, rule.Direction, filter.Name, w);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"WFP skip IP {ip}: {ex.Message}");
                }
            }
        }

        SaveKnownKeys();
        return groups;
    }

    private IEnumerable<string> ResolveRemoteIps(Filter filter)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in filter.Matchers)
        {
            if (m.Kind == MatcherKind.RemoteAddressInRange)
            {
                var cidr = m.Cidr ?? m.StringValue;
                if (!string.IsNullOrWhiteSpace(cidr) && !cidr.Contains('/'))
                    set.Add(cidr.Trim());
            }
            else if (m.Kind == MatcherKind.DomainEquals && !string.IsNullOrWhiteSpace(m.StringValue))
            {
                var domain = m.StringValue!.Trim().TrimEnd('.');
                // Prefer live DNS cache
                if (Dns != null)
                {
                    foreach (var ip in Dns.GetIpsForHost(domain))
                        set.Add(ip);
                }
                // Always try system resolve for apply-time freshness
                try
                {
                    foreach (var a in System.Net.Dns.GetHostAddresses(domain))
                    {
                        if (a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                        {
                            set.Add(a.ToString());
                            Dns?.Add(domain, a.ToString(), "resolve");
                        }
                    }
                }
                catch { /* NXDOMAIN */ }
            }
        }
        return set;
    }

    public WfpStatus GetStatus()
    {
        Open();
        // Re-sync from disk + try delete-probe count
        LoadKnownKeys();
        return new WfpStatus
        {
            Mode = _mode,
            TrackedFilterKeys = _filterKeys.Count,
            StateFile = FilterStatePath,
            ProviderKey = ProviderKey,
            SublayerKey = SublayerKey,
        };
    }

    private static IEnumerable<string> ResolvePaths(Filter filter)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in filter.Matchers)
        {
            if (m.Kind == MatcherKind.AppPathEquals && !string.IsNullOrWhiteSpace(m.StringValue))
            {
                if (File.Exists(m.StringValue))
                    set.Add(Path.GetFullPath(m.StringValue));
            }
            else if (m.Kind == MatcherKind.AppPathContains && !string.IsNullOrWhiteSpace(m.StringValue))
            {
                var frag = m.StringValue!;
                foreach (var p in Process.GetProcesses())
                {
                    try
                    {
                        var path = p.MainModule?.FileName;
                        if (path != null && path.Contains(frag, StringComparison.OrdinalIgnoreCase))
                            set.Add(path);
                    }
                    catch { /* access denied */ }
                    finally { p.Dispose(); }
                }
            }
        }
        return set;
    }

    /// <summary>
    /// Add a single app allow/block without clearing existing filters (Ask once / incremental).
    /// Display name prefix "NetShaper: ask-" is used so re-apply still owns cleanup via enum-delete.
    /// </summary>
    public void AddAppRule(string appPath, bool block, TrafficDirection dir = TrafficDirection.Both,
        string? tag = null, ulong weight = 12)
    {
        Open();
        if (!File.Exists(appPath))
            throw new FileNotFoundException("App path for WFP rule not found", appPath);
        var name = "ask-" + (tag ?? (block ? "block" : "allow")) + "-" + Path.GetFileName(appPath);
        AddAppPathFilter(appPath, block, dir, name, weight);
        SaveKnownKeys();
    }

    private void AddAppPathFilter(string appPath, bool block, TrafficDirection dir, string name, ulong weight = 0)
    {
        if (dir is TrafficDirection.Out or TrafficDirection.Both)
        {
            AddAtLayer(appPath, block, FWPM_LAYER_ALE_AUTH_CONNECT_V4, name + " out-v4", weight);
            AddAtLayer(appPath, block, FWPM_LAYER_ALE_AUTH_CONNECT_V6, name + " out-v6", weight);
        }
        if (dir is TrafficDirection.In or TrafficDirection.Both)
        {
            AddAtLayer(appPath, block, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, name + " in-v4", weight);
            AddAtLayer(appPath, block, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, name + " in-v6", weight);
        }
    }

    private void AddRemoteIpFilter(string ip, bool block, TrafficDirection dir, string name, ulong weight)
    {
        if (!IPAddress.TryParse(ip, out var addr)) return;
        if (dir is TrafficDirection.Out or TrafficDirection.Both)
        {
            if (addr.AddressFamily == AddressFamily.InterNetwork)
                AddRemoteIpAtLayer(addr, block, FWPM_LAYER_ALE_AUTH_CONNECT_V4, name + " dip-out-v4", weight);
            else if (addr.AddressFamily == AddressFamily.InterNetworkV6)
                AddRemoteIpAtLayer(addr, block, FWPM_LAYER_ALE_AUTH_CONNECT_V6, name + " dip-out-v6", weight);
        }
        if (dir is TrafficDirection.In or TrafficDirection.Both)
        {
            if (addr.AddressFamily == AddressFamily.InterNetwork)
                AddRemoteIpAtLayer(addr, block, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, name + " dip-in-v4", weight);
            else if (addr.AddressFamily == AddressFamily.InterNetworkV6)
                AddRemoteIpAtLayer(addr, block, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, name + " dip-in-v6", weight);
        }
    }

    private void AddRemoteIpAtLayer(IPAddress addr, bool block, Guid layerKey, string displayName, ulong weight)
    {
        var providerKey = ProviderKey;
        var pkHandle = GCHandle.Alloc(providerKey, GCHandleType.Pinned);
        GCHandle condHandle = default;
        GCHandle dataHandle = default;
        try
        {
            FWPM_FILTER_CONDITION0 cond;
            if (addr.AddressFamily == AddressFamily.InterNetwork)
            {
                var bytes = addr.GetAddressBytes();
                var host = BitConverter.ToUInt32(bytes, 0);
                var data = new FWP_V4_ADDR_AND_MASK { addr = host, mask = 0xFFFFFFFF };
                dataHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
                cond = new FWPM_FILTER_CONDITION0
                {
                    fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType = FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0
                    {
                        type = FWP_V4_ADDR_MASK,
                        ptr = dataHandle.AddrOfPinnedObject(),
                    },
                };
            }
            else
            {
                var bytes = addr.GetAddressBytes(); // 16
                var data = new FWP_V6_ADDR_AND_MASK
                {
                    addr = new byte[16],
                    mask = new byte[16],
                };
                Buffer.BlockCopy(bytes, 0, data.addr, 0, 16);
                for (int i = 0; i < 16; i++) data.mask[i] = 0xFF;
                dataHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
                cond = new FWPM_FILTER_CONDITION0
                {
                    fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType = FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0
                    {
                        type = FWP_V6_ADDR_MASK,
                        ptr = dataHandle.AddrOfPinnedObject(),
                    },
                };
            }
            condHandle = GCHandle.Alloc(cond, GCHandleType.Pinned);
            var filterKey = Guid.NewGuid();
            var filter = new FWPM_FILTER0
            {
                filterKey = filterKey,
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = "NetShaper: " + displayName,
                    description = addr.ToString(),
                },
                flags = _mode == WfpSessionMode.Persistent ? FWPM_FILTER_FLAG_PERSISTENT : 0,
                providerKey = pkHandle.AddrOfPinnedObject(),
                layerKey = layerKey,
                subLayerKey = SublayerKey,
                weight = weight == 0 ? new FWP_VALUE0 { type = FWP_EMPTY } : MakeWeight(weight),
                numFilterConditions = 1,
                filterCondition = condHandle.AddrOfPinnedObject(),
                action = new FWPM_ACTION0
                {
                    type = block ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT,
                },
            };
            Check(FwpmFilterAdd0(_engine, ref filter, IntPtr.Zero, out _), "FwpmFilterAdd0 remote-ip");
            _filterKeys.Add(filterKey);
        }
        finally
        {
            if (condHandle.IsAllocated) condHandle.Free();
            if (dataHandle.IsAllocated) dataHandle.Free();
            pkHandle.Free();
        }
    }

    /// <summary>Match-all block (no conditions) for lockdown mode.</summary>
    private void AddCatchAllBlock(TrafficDirection dir, string name, ulong weight)
    {
        if (dir is TrafficDirection.Out or TrafficDirection.Both)
        {
            AddMatchAllAtLayer(true, FWPM_LAYER_ALE_AUTH_CONNECT_V4, name + " out-v4", weight);
            AddMatchAllAtLayer(true, FWPM_LAYER_ALE_AUTH_CONNECT_V6, name + " out-v6", weight);
        }
        if (dir is TrafficDirection.In or TrafficDirection.Both)
        {
            AddMatchAllAtLayer(true, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, name + " in-v4", weight);
            AddMatchAllAtLayer(true, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, name + " in-v6", weight);
        }
    }

    private void AddMatchAllAtLayer(bool block, Guid layerKey, string displayName, ulong weight)
    {
        var providerKey = ProviderKey;
        var pkHandle = GCHandle.Alloc(providerKey, GCHandleType.Pinned);
        try
        {
            var filterKey = Guid.NewGuid();
            var filter = new FWPM_FILTER0
            {
                filterKey = filterKey,
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = "NetShaper: " + displayName,
                    description = "catch-all",
                },
                flags = _mode == WfpSessionMode.Persistent ? FWPM_FILTER_FLAG_PERSISTENT : 0,
                providerKey = pkHandle.AddrOfPinnedObject(),
                layerKey = layerKey,
                subLayerKey = SublayerKey,
                weight = MakeWeight(weight),
                numFilterConditions = 0,
                filterCondition = IntPtr.Zero,
                action = new FWPM_ACTION0
                {
                    type = block ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT,
                },
            };
            Check(FwpmFilterAdd0(_engine, ref filter, IntPtr.Zero, out _), "FwpmFilterAdd0 match-all");
            _filterKeys.Add(filterKey);
        }
        finally
        {
            pkHandle.Free();
        }
    }

    private void AddAtLayer(string appPath, bool block, Guid layerKey, string displayName, ulong weight = 0)
    {
        Check(FwpmGetAppIdFromFileName0(appPath, out var appIdBlob), "FwpmGetAppIdFromFileName0 " + appPath);
        var providerKey = ProviderKey;
        var pkHandle = GCHandle.Alloc(providerKey, GCHandleType.Pinned);
        try
        {
            var cond = new FWPM_FILTER_CONDITION0
            {
                fieldKey = FWPM_CONDITION_ALE_APP_ID,
                matchType = FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_BYTE_BLOB_TYPE,
                    ptr = appIdBlob,
                },
            };
            var condHandle = GCHandle.Alloc(cond, GCHandleType.Pinned);
            try
            {
                var filterKey = Guid.NewGuid();
                var filter = new FWPM_FILTER0
                {
                    filterKey = filterKey,
                    displayData = new FWPM_DISPLAY_DATA0
                    {
                        name = "NetShaper: " + displayName,
                        description = appPath,
                    },
                    flags = _mode == WfpSessionMode.Persistent ? FWPM_FILTER_FLAG_PERSISTENT : 0,
                    providerKey = pkHandle.AddrOfPinnedObject(),
                    layerKey = layerKey,
                    subLayerKey = SublayerKey,
                    weight = weight == 0 ? new FWP_VALUE0 { type = FWP_EMPTY } : MakeWeight(weight),
                    numFilterConditions = 1,
                    filterCondition = condHandle.AddrOfPinnedObject(),
                    action = new FWPM_ACTION0
                    {
                        type = block ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT,
                    },
                };

                Check(FwpmFilterAdd0(_engine, ref filter, IntPtr.Zero, out _), "FwpmFilterAdd0");
                _filterKeys.Add(filterKey);
            }
            finally
            {
                condHandle.Free();
            }
        }
        finally
        {
            pkHandle.Free();
            FwpmFreeMemory0(ref appIdBlob);
        }
    }

    private static FWP_VALUE0 MakeWeight(ulong w)
    {
        // FWP_UINT8 = 1 … FWP_UINT64 = 8; use UINT64 in low bytes of union
        return new FWP_VALUE0 { type = FWP_UINT64, uint64 = w };
    }

    public int ClearOurFilters()
    {
        Open();
        LoadKnownKeys();
        int removed = 0;
        foreach (var key in _filterKeys.ToArray())
        {
            var k = key;
            var st = FwpmFilterDeleteByKey0(_engine, ref k);
            if (st == 0 || st == FWP_E_FILTER_NOT_FOUND)
            {
                removed++;
                _filterKeys.Remove(key);
            }
        }
        // Also enum-delete by provider display name prefix as safety net
        removed += EnumDeleteNetShaperFilters();
        _filterKeys.Clear();
        SaveKnownKeys();
        return removed;
    }

    private int EnumDeleteNetShaperFilters()
    {
        int removed = 0;
        var st = FwpmFilterCreateEnumHandle0(_engine, IntPtr.Zero, out var enumHandle);
        if (st != 0) return 0;
        try
        {
            while (true)
            {
                st = FwpmFilterEnum0(_engine, enumHandle, 32, out var entries, out var count);
                if (st != 0 || count == 0 || entries == IntPtr.Zero) break;

                try
                {
                    for (uint i = 0; i < count; i++)
                    {
                        var ptr = Marshal.ReadIntPtr(entries, (int)(i * IntPtr.Size));
                        if (ptr == IntPtr.Zero) continue;
                        var f = Marshal.PtrToStructure<FWPM_FILTER0>(ptr);
                        var name = f.displayData.name ?? "";
                        if (!name.StartsWith("NetShaper:", StringComparison.Ordinal))
                            continue;
                        var key = f.filterKey;
                        if (FwpmFilterDeleteByKey0(_engine, ref key) == 0)
                            removed++;
                    }
                }
                finally
                {
                    FwpmFreeMemory0(ref entries);
                }
                if (count < 32) break;
            }
        }
        finally
        {
            FwpmFilterDestroyEnumHandle0(_engine, enumHandle);
        }
        return removed;
    }

    private void LoadKnownKeys()
    {
        try
        {
            if (!File.Exists(FilterStatePath)) return;
            var json = File.ReadAllText(FilterStatePath);
            var keys = JsonSerializer.Deserialize<List<Guid>>(json);
            if (keys == null) return;
            foreach (var k in keys)
                if (!_filterKeys.Contains(k))
                    _filterKeys.Add(k);
        }
        catch { /* ignore corrupt state */ }
    }

    private void SaveKnownKeys()
    {
        try
        {
            Directory.CreateDirectory(StateDir);
            File.WriteAllText(FilterStatePath, JsonSerializer.Serialize(_filterKeys));
        }
        catch { /* ignore */ }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            // Persistent filters intentionally survive Dispose.
            // Dynamic filters are removed by BFE when session closes.
            if (_engine != IntPtr.Zero)
            {
                if (_mode == WfpSessionMode.Dynamic)
                    ClearOurFilters();
                else
                    SaveKnownKeys();

                FwpmEngineClose0(_engine);
                _engine = IntPtr.Zero;
            }
        }
        catch { /* best effort */ }
    }

    private static void Check(uint status, string op)
    {
        if (status != 0)
            throw new Win32Exception((int)status, op + " failed (0x" + status.ToString("X") + ")");
    }

    #region Native

    private const uint RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF;
    private const uint FWPM_SESSION_FLAG_DYNAMIC = 1;
    private const uint FWPM_PROVIDER_FLAG_PERSISTENT = 0x00000001;
    private const uint FWPM_SUBLAYER_FLAG_PERSISTENT = 0x00000001;
    private const uint FWPM_FILTER_FLAG_PERSISTENT = 0x00000001;
    private const uint FWP_E_ALREADY_EXISTS = 0x80320016;
    private const uint FWP_E_FILTER_NOT_FOUND = 0x80320003;
    private const ushort FWP_EMPTY = 0;
    private const ushort FWP_UINT64 = 8;
    private const ushort FWP_BYTE_BLOB_TYPE = 12;
    private const ushort FWP_V4_ADDR_MASK = 0x100;
    private const ushort FWP_V6_ADDR_MASK = 0x101;
    private const uint FWP_MATCH_EQUAL = 0;
    private const uint FWP_ACTION_BLOCK = 0x00001001;
    private const uint FWP_ACTION_PERMIT = 0x00001002;

    private static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e21");
    private static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    private static readonly Guid FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 = new("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
    private static readonly Guid FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 = new("a3b42c97-9f04-4672-b87e-cee9c483257f");
    private static readonly Guid FWPM_CONDITION_ALE_APP_ID = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
    private static readonly Guid FWPM_CONDITION_IP_REMOTE_ADDRESS = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_V4_ADDR_AND_MASK
    {
        public uint addr;
        public uint mask;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_V6_ADDR_AND_MASK
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] addr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] mask;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FWPM_DISPLAY_DATA0
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? name;
        [MarshalAs(UnmanagedType.LPWStr)] public string? description;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FWPM_SESSION0
    {
        public Guid sessionKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public uint txnWaitTimeoutInMSec;
        public uint processId;
        public IntPtr sid;
        [MarshalAs(UnmanagedType.LPWStr)] public string? username;
        [MarshalAs(UnmanagedType.Bool)] public bool kernelMode;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_BYTE_BLOB
    {
        public uint size;
        public IntPtr data;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FWPM_PROVIDER0
    {
        public Guid providerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public FWP_BYTE_BLOB providerData;
        [MarshalAs(UnmanagedType.LPWStr)] public string? serviceName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_SUBLAYER0
    {
        public Guid subLayerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public ushort weight;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_VALUE0
    {
        public ushort type;
        private ushort pad0, pad1, pad2;
        public ulong uint64;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_CONDITION_VALUE0
    {
        public ushort type;
        private ushort pad0, pad1, pad2;
        public IntPtr ptr;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_FILTER_CONDITION0
    {
        public Guid fieldKey;
        public uint matchType;
        public FWP_CONDITION_VALUE0 conditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_ACTION0
    {
        public uint type;
        public Guid filterType;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_FILTER0
    {
        public Guid filterKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public Guid layerKey;
        public Guid subLayerKey;
        public FWP_VALUE0 weight;
        public uint numFilterConditions;
        public IntPtr filterCondition;
        public FWPM_ACTION0 action;
        public ulong rawContext;
        public IntPtr reserved;
        public ulong filterId;
        public FWP_VALUE0 effectiveWeight;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmEngineOpen0(string? serverName, uint authnService, IntPtr authIdentity,
        ref FWPM_SESSION0 session, out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmProviderAdd0(IntPtr engine, ref FWPM_PROVIDER0 provider, IntPtr sd);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerAdd0(IntPtr engine, ref FWPM_SUBLAYER0 subLayer, IntPtr sd);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterAdd0(IntPtr engine, ref FWPM_FILTER0 filter, IntPtr sd, out ulong id);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, IntPtr enumTemplate, out IntPtr enumHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterEnum0(IntPtr engine, IntPtr enumHandle, uint numEntriesRequested,
        out IntPtr entries, out uint numEntriesReturned);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr enumHandle);

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);

    [DllImport("fwpuclnt.dll")]
    private static extern void FwpmFreeMemory0(ref IntPtr p);

    #endregion
}

public sealed class WfpStatus
{
    public WfpSessionMode Mode { get; set; }
    public int TrackedFilterKeys { get; set; }
    public string StateFile { get; set; } = "";
    public Guid ProviderKey { get; set; }
    public Guid SublayerKey { get; set; }
}
