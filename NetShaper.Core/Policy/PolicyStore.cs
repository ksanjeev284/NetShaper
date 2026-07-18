using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetShaper.Core.Policy;

public sealed class PolicyStore
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
    };

    public string FilePath { get; }

    public PolicyStore(string? filePath = null)
    {
        var root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "NetShaper");
        Directory.CreateDirectory(root);
        FilePath = filePath ?? Path.Combine(root, "policy.json");
    }

    public PolicyDocument LoadOrCreate()
    {
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
        File.Exists(FilePath) ? File.ReadAllText(FilePath) : PolicyEditor.ToJson(PolicyDocument.CreateDefaults());
}
