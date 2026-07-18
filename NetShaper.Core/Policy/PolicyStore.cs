using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetShaper.Core.Policy;

/// <summary>
/// Unified policy access for CLI, Service, API, and tools.
/// Always reads/writes the <see cref="ProfileStore"/> active profile and mirrors to policy.json
/// so GUI profiles and automation stay in sync.
/// </summary>
public sealed class PolicyStore
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly ProfileStore _profiles = new();

    /// <summary>Legacy path still mirrored for older scripts; active profile is authoritative.</summary>
    public string FilePath { get; }

    public string ActiveProfileName => _profiles.GetActiveName();

    public PolicyStore(string? filePath = null)
    {
        // Optional explicit path bypasses profiles (tests / import tools)
        if (!string.IsNullOrWhiteSpace(filePath))
        {
            FilePath = filePath;
            _useProfiles = false;
            var dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
        }
        else
        {
            _useProfiles = true;
            FilePath = Path.Combine(_profiles.RootDir, "policy.json");
            Directory.CreateDirectory(_profiles.RootDir);
        }
    }

    private readonly bool _useProfiles = true;

    public PolicyDocument LoadOrCreate()
    {
        if (_useProfiles)
            return _profiles.LoadActive();

        if (!File.Exists(FilePath))
        {
            var doc = PolicyDocument.CreateDefaults();
            Save(doc);
            return doc;
        }
        var json = File.ReadAllText(FilePath);
        return JsonSerializer.Deserialize<PolicyDocument>(json, JsonOpts)
               ?? PolicyDocument.CreateDefaults();
    }

    public void Save(PolicyDocument doc)
    {
        if (_useProfiles)
        {
            _profiles.SaveProfile(_profiles.GetActiveName(), doc);
            return;
        }

        doc.Filters.ForEach(f => f.UpdatedUtc = DateTimeOffset.UtcNow);
        var json = JsonSerializer.Serialize(doc, JsonOpts);
        File.WriteAllText(FilePath, json);
    }

    public void ExportTo(string path)
    {
        var doc = LoadOrCreate();
        var json = JsonSerializer.Serialize(doc, JsonOpts);
        File.WriteAllText(path, json);
    }

    public PolicyDocument ImportFrom(string path, bool replace = true)
    {
        var json = File.ReadAllText(path);
        var doc = JsonSerializer.Deserialize<PolicyDocument>(json, JsonOpts)
                  ?? throw new InvalidDataException("Invalid policy JSON");
        if (replace)
            Save(doc);
        return doc;
    }

    public string ReadRaw() =>
        File.Exists(FilePath)
            ? File.ReadAllText(FilePath)
            : PolicyEditor.ToJson(PolicyDocument.CreateDefaults());
}
