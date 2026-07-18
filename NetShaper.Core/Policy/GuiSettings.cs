using System.Text.Json;

namespace NetShaper.Core.Policy;

/// <summary>Persisted GUI preferences (not traffic policy).</summary>
public sealed class GuiSettings
{
    public string Theme { get; set; } = "Dark"; // Dark | Light
    public bool StartWithWindows { get; set; }
    public bool StartMinimized { get; set; }
    public bool TrayEnabled { get; set; } = true;
    public bool ToastsEnabled { get; set; } = true;
    public bool Topmost { get; set; }
    public bool EStats { get; set; } = true;
    public bool AutoApply { get; set; }
    public bool PersistWfp { get; set; }
    public bool QuotaAutoBlock { get; set; } = true;
    public double RefreshSeconds { get; set; } = 1.5;
    public bool CompactMode { get; set; }
    public long AlertBitsPerSec { get; set; } // 0 = off; toast when system total exceeds
    public List<string> PinnedProcessNames { get; set; } = new();
    public string? LastProfile { get; set; }
    public int StatsRetentionDays { get; set; } = 30;
    public bool StatsRecordProcesses { get; set; } = true;

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };
    private static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "NetShaper", "gui-settings.json");

    public static GuiSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<GuiSettings>(File.ReadAllText(FilePath), JsonOpts)
                       ?? new GuiSettings();
        }
        catch { /* ignore */ }
        return new GuiSettings();
    }

    public void Save()
    {
        try
        {
            var dir = Path.GetDirectoryName(FilePath)!;
            Directory.CreateDirectory(dir);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, JsonOpts));
        }
        catch { /* ignore */ }
    }
}
