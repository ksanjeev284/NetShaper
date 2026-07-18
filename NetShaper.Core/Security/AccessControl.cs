using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetShaper.Core.Security;

// Windows identity APIs only

/// <summary>Local access rights: Monitor, Control, RemoteApi.</summary>
[Flags]
public enum AccessRight
{
    None = 0,
    /// <summary>View traffic, policy, stats, DNS (read-only).</summary>
    Monitor = 1,
    /// <summary>Change policy, apply WFP/QoS, ask decisions, kill connections.</summary>
    Control = 2,
    /// <summary>Use local HTTP API (with key). Requires Monitor or Control as needed per call.</summary>
    RemoteApi = 4,
    All = Monitor | Control | RemoteApi,
}

public sealed class AccessEntry
{
    /// <summary>Windows account name, e.g. DOMAIN\user or .\User or SID string.</summary>
    public string Principal { get; set; } = "";
    public string? Sid { get; set; }
    public AccessRight Allowed { get; set; } = AccessRight.Monitor;
    public string? Note { get; set; }
}

public sealed class AccessControlDocument
{
    public int Version { get; set; } = 1;
    /// <summary>When false, ACL is not enforced (open access).</summary>
    public bool Enabled { get; set; }
    /// <summary>Local Administrators always get All when true (recommended).</summary>
    public bool AdministratorsFullAccess { get; set; } = true;
    public List<AccessEntry> Entries { get; set; } = new();
}

/// <summary>Persists ACL under ProgramData\NetShaper\access-control.json.</summary>
public sealed class AccessControlStore
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public string FilePath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "NetShaper", "access-control.json");

    public AccessControlDocument Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<AccessControlDocument>(File.ReadAllText(FilePath), JsonOpts)
                       ?? new AccessControlDocument();
        }
        catch { /* ignore */ }
        return new AccessControlDocument();
    }

    public void Save(AccessControlDocument doc)
    {
        var dir = Path.GetDirectoryName(FilePath)!;
        Directory.CreateDirectory(dir);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(doc, JsonOpts));
    }
}

/// <summary>Evaluate rights for the current Windows user (or a given identity).</summary>
[SupportedOSPlatform("windows")]
public static class AccessChecker
{
    public static AccessRight GetRights(AccessControlDocument? doc = null, WindowsIdentity? identity = null)
    {
        doc ??= new AccessControlStore().Load();
        identity ??= WindowsIdentity.GetCurrent();

        if (!doc.Enabled || doc.Entries.Count == 0)
            return AccessRight.All;

        if (doc.AdministratorsFullAccess && IsLocalAdmin(identity))
            return AccessRight.All;

        AccessRight rights = AccessRight.None;
        var userSid = identity.User?.Value ?? "";
        var name = identity.Name ?? "";

        foreach (var e in doc.Entries)
        {
            if (Matches(e, name, userSid, identity))
                rights |= e.Allowed;
        }

        // Also match group SIDs in token against entry SIDs
        if (identity.Groups != null)
        {
            foreach (var g in identity.Groups)
            {
                var gSid = g.Value;
                foreach (var e in doc.Entries)
                {
                    if (!string.IsNullOrEmpty(e.Sid) &&
                        e.Sid.Equals(gSid, StringComparison.OrdinalIgnoreCase))
                        rights |= e.Allowed;
                    else if (!string.IsNullOrEmpty(e.Principal) && PrincipalIsGroupName(e.Principal, g))
                        rights |= e.Allowed;
                }
            }
        }

        return rights;
    }

    public static bool Has(AccessRight need, AccessControlDocument? doc = null, WindowsIdentity? identity = null)
        => (GetRights(doc, identity) & need) == need;

    public static void Require(AccessRight need, AccessControlDocument? doc = null)
    {
        if (!Has(need, doc))
            throw new UnauthorizedAccessException(
                $"Access denied: requires {need}. Current rights: {GetRights(doc)}. " +
                $"Edit %ProgramData%\\NetShaper\\access-control.json or Settings → Access.");
    }

    public static string DescribeCurrent(AccessControlDocument? doc = null)
    {
        doc ??= new AccessControlStore().Load();
        using var id = WindowsIdentity.GetCurrent();
        var r = GetRights(doc, id);
        return $"User={id.Name}  ACL={(doc.Enabled ? "on" : "off")}  Rights={r}  Admin={IsLocalAdmin(id)}";
    }

    public static bool IsLocalAdmin(WindowsIdentity identity)
    {
        try
        {
            var p = new WindowsPrincipal(identity);
            return p.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    public static string? TryResolveSid(string principal)
    {
        try
        {
            if (principal.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
                return principal;
            var nt = new NTAccount(principal);
            var sid = (SecurityIdentifier)nt.Translate(typeof(SecurityIdentifier));
            return sid.Value;
        }
        catch { return null; }
    }

    public static string? TryResolveName(string sid)
    {
        try
        {
            var s = new SecurityIdentifier(sid);
            var nt = (NTAccount)s.Translate(typeof(NTAccount));
            return nt.Value;
        }
        catch { return null; }
    }

    private static bool Matches(AccessEntry e, string userName, string userSid, WindowsIdentity identity)
    {
        if (!string.IsNullOrEmpty(e.Sid) && e.Sid.Equals(userSid, StringComparison.OrdinalIgnoreCase))
            return true;
        if (!string.IsNullOrEmpty(e.Principal))
        {
            if (userName.Equals(e.Principal, StringComparison.OrdinalIgnoreCase))
                return true;
            // DOMAIN\user vs user
            var shortUser = userName.Contains('\\') ? userName.Split('\\')[^1] : userName;
            var shortP = e.Principal.Contains('\\') ? e.Principal.Split('\\')[^1] : e.Principal;
            if (shortUser.Equals(shortP, StringComparison.OrdinalIgnoreCase) &&
                (e.Principal.StartsWith(".\\") || !e.Principal.Contains('\\')))
                return true;
        }
        return false;
    }

    private static bool PrincipalIsGroupName(string principal, IdentityReference g)
    {
        try
        {
            var name = g.Translate(typeof(NTAccount)).Value;
            return name.Equals(principal, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
}
