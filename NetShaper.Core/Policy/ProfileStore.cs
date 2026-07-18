using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetShaper.Core.Policy;

/// <summary>Named policy profiles under ProgramData\NetShaper\profiles\.</summary>
public sealed class ProfileStore
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
    };

    public string RootDir { get; }
    public string IndexPath { get; }
    public string ProfilesDir { get; }

    public ProfileStore()
    {
        RootDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "NetShaper");
        ProfilesDir = Path.Combine(RootDir, "profiles");
        IndexPath = Path.Combine(RootDir, "profiles-index.json");
        Directory.CreateDirectory(ProfilesDir);
    }

    public sealed class Index
    {
        public string ActiveProfile { get; set; } = "default";
        public List<string> Profiles { get; set; } = new() { "default" };
    }

    public Index LoadIndex()
    {
        if (!File.Exists(IndexPath))
        {
            var idx = new Index();
            SaveIndex(idx);
            // Ensure default file exists by copying main policy if present
            EnsureProfileFile("default");
            return idx;
        }
        try
        {
            return JsonSerializer.Deserialize<Index>(File.ReadAllText(IndexPath), JsonOpts)
                   ?? new Index();
        }
        catch
        {
            return new Index();
        }
    }

    public void SaveIndex(Index idx)
    {
        Directory.CreateDirectory(RootDir);
        File.WriteAllText(IndexPath, JsonSerializer.Serialize(idx, JsonOpts));
    }

    public string ProfilePath(string name)
    {
        var safe = Sanitize(name);
        return Path.Combine(ProfilesDir, safe + ".json");
    }

    public IReadOnlyList<string> ListProfiles()
    {
        var idx = LoadIndex();
        var fromDisk = Directory.Exists(ProfilesDir)
            ? Directory.GetFiles(ProfilesDir, "*.json")
                .Select(f => Path.GetFileNameWithoutExtension(f)!)
                .ToList()
            : new List<string>();
        foreach (var p in fromDisk)
            if (!idx.Profiles.Contains(p, StringComparer.OrdinalIgnoreCase))
                idx.Profiles.Add(p);
        if (idx.Profiles.Count == 0)
            idx.Profiles.Add("default");
        SaveIndex(idx);
        return idx.Profiles.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public string GetActiveName() => LoadIndex().ActiveProfile;

    public PolicyDocument LoadActive()
    {
        var name = GetActiveName();
        return LoadProfile(name);
    }

    public PolicyDocument LoadProfile(string name)
    {
        var path = ProfilePath(name);
        if (!File.Exists(path))
        {
            // migrate from legacy policy.json once
            var legacy = Path.Combine(RootDir, "policy.json");
            if (name.Equals("default", StringComparison.OrdinalIgnoreCase) && File.Exists(legacy))
            {
                File.Copy(legacy, path, overwrite: false);
            }
            else
            {
                var doc = PolicyDocument.CreateDefaults();
                SaveProfile(name, doc);
                return doc;
            }
        }
        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<PolicyDocument>(json, JsonOpts)
               ?? PolicyDocument.CreateDefaults();
    }

    public void SaveProfile(string name, PolicyDocument doc)
    {
        var path = ProfilePath(name);
        Directory.CreateDirectory(ProfilesDir);
        doc.Filters.ForEach(f => f.UpdatedUtc = DateTimeOffset.UtcNow);
        File.WriteAllText(path, JsonSerializer.Serialize(doc, JsonOpts));

        // Keep legacy policy.json in sync when active is default (CLI/service compat)
        var idx = LoadIndex();
        if (name.Equals(idx.ActiveProfile, StringComparison.OrdinalIgnoreCase))
        {
            var legacy = Path.Combine(RootDir, "policy.json");
            File.WriteAllText(legacy, JsonSerializer.Serialize(doc, JsonOpts));
        }

        if (!idx.Profiles.Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            idx.Profiles.Add(Sanitize(name));
            SaveIndex(idx);
        }
    }

    public void SetActive(string name)
    {
        var idx = LoadIndex();
        var safe = Sanitize(name);
        EnsureProfileFile(safe);
        idx.ActiveProfile = safe;
        if (!idx.Profiles.Contains(safe, StringComparer.OrdinalIgnoreCase))
            idx.Profiles.Add(safe);
        SaveIndex(idx);
        // Sync legacy path for service/cli
        var doc = LoadProfile(safe);
        File.WriteAllText(Path.Combine(RootDir, "policy.json"), JsonSerializer.Serialize(doc, JsonOpts));
    }

    public void CreateProfile(string name, bool cloneActive)
    {
        var safe = Sanitize(name);
        if (string.IsNullOrWhiteSpace(safe))
            throw new ArgumentException("Invalid profile name");
        var doc = cloneActive ? LoadActive() : PolicyDocument.CreateDefaults();
        // New IDs not required — clone is fine for starting point
        SaveProfile(safe, doc);
        var idx = LoadIndex();
        if (!idx.Profiles.Contains(safe, StringComparer.OrdinalIgnoreCase))
        {
            idx.Profiles.Add(safe);
            SaveIndex(idx);
        }
    }

    public void DeleteProfile(string name)
    {
        var safe = Sanitize(name);
        if (safe.Equals("default", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Cannot delete the default profile.");
        var path = ProfilePath(safe);
        if (File.Exists(path)) File.Delete(path);
        var idx = LoadIndex();
        idx.Profiles.RemoveAll(p => p.Equals(safe, StringComparison.OrdinalIgnoreCase));
        if (idx.ActiveProfile.Equals(safe, StringComparison.OrdinalIgnoreCase))
            idx.ActiveProfile = "default";
        SaveIndex(idx);
        SetActive(idx.ActiveProfile);
    }

    public void RenameProfile(string oldName, string newName)
    {
        var a = Sanitize(oldName);
        var b = Sanitize(newName);
        if (a.Equals("default", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Cannot rename default.");
        if (string.IsNullOrWhiteSpace(b))
            throw new ArgumentException("Invalid name");
        var src = ProfilePath(a);
        var dst = ProfilePath(b);
        if (!File.Exists(src)) throw new FileNotFoundException(src);
        if (File.Exists(dst)) throw new IOException("Target profile already exists.");
        File.Move(src, dst);
        var idx = LoadIndex();
        idx.Profiles.RemoveAll(p => p.Equals(a, StringComparison.OrdinalIgnoreCase));
        if (!idx.Profiles.Contains(b, StringComparer.OrdinalIgnoreCase))
            idx.Profiles.Add(b);
        if (idx.ActiveProfile.Equals(a, StringComparison.OrdinalIgnoreCase))
            idx.ActiveProfile = b;
        SaveIndex(idx);
    }

    private void EnsureProfileFile(string name)
    {
        var path = ProfilePath(name);
        if (File.Exists(path)) return;
        var legacy = Path.Combine(RootDir, "policy.json");
        if (name.Equals("default", StringComparison.OrdinalIgnoreCase) && File.Exists(legacy))
            File.Copy(legacy, path);
        else
            SaveProfile(name, PolicyDocument.CreateDefaults());
    }

    private static string Sanitize(string name)
    {
        var s = (name ?? "").Trim();
        foreach (var c in Path.GetInvalidFileNameChars())
            s = s.Replace(c, '_');
        return string.IsNullOrWhiteSpace(s) ? "default" : s;
    }
}
