using System.Text.Json;

namespace NetShaper.Core.Logging;

public enum ActivityLevel
{
    Info,
    Success,
    Warn,
    Error,
}

public sealed class ActivityEntry
{
    public DateTimeOffset Time { get; set; } = DateTimeOffset.Now;
    public ActivityLevel Level { get; set; }
    public string Message { get; set; } = "";
    public string? Detail { get; set; }
}

/// <summary>In-memory + optional disk activity log for the GUI.</summary>
public sealed class ActivityLog
{
    private readonly int _capacity;
    private readonly LinkedList<ActivityEntry> _entries = new();
    private readonly object _gate = new();
    private readonly string _path;

    public event Action<ActivityEntry>? EntryAdded;

    public ActivityLog(int capacity = 500)
    {
        _capacity = capacity;
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "NetShaper");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "activity.log.jsonl");
    }

    public IReadOnlyList<ActivityEntry> Snapshot()
    {
        lock (_gate) return _entries.ToList();
    }

    public void Info(string msg, string? detail = null) => Add(ActivityLevel.Info, msg, detail);
    public void Success(string msg, string? detail = null) => Add(ActivityLevel.Success, msg, detail);
    public void Warn(string msg, string? detail = null) => Add(ActivityLevel.Warn, msg, detail);
    public void Error(string msg, string? detail = null) => Add(ActivityLevel.Error, msg, detail);

    public void Add(ActivityLevel level, string message, string? detail = null)
    {
        var e = new ActivityEntry
        {
            Time = DateTimeOffset.Now,
            Level = level,
            Message = message,
            Detail = detail,
        };
        lock (_gate)
        {
            _entries.AddFirst(e);
            while (_entries.Count > _capacity)
                _entries.RemoveLast();
        }
        try
        {
            File.AppendAllText(_path, JsonSerializer.Serialize(e) + Environment.NewLine);
        }
        catch { /* ignore disk errors */ }
        EntryAdded?.Invoke(e);
    }

    public void ClearMemory()
    {
        lock (_gate) _entries.Clear();
    }

    public string ExportText()
    {
        lock (_gate)
        {
            return string.Join(Environment.NewLine,
                _entries.Select(e =>
                    $"{e.Time:yyyy-MM-dd HH:mm:ss} [{e.Level}] {e.Message}" +
                    (e.Detail is null ? "" : " — " + e.Detail)));
        }
    }
}
