namespace NetShaper.Core.Traffic;

/// <summary>Per-process rate ring buffers for sparklines.</summary>
public sealed class ProcessRateHistory
{
    private readonly int _capacity;
    private readonly Dictionary<int, Queue<(double inn, double outt)>> _byPid = new();

    public ProcessRateHistory(int capacity = 40) => _capacity = Math.Max(8, capacity);

    public void Record(IEnumerable<ProcessTraffic> processes)
    {
        var seen = new HashSet<int>();
        foreach (var p in processes)
        {
            seen.Add(p.ProcessId);
            if (!_byPid.TryGetValue(p.ProcessId, out var q))
            {
                q = new Queue<(double, double)>(_capacity);
                _byPid[p.ProcessId] = q;
            }
            q.Enqueue((p.BitsPerSecIn, p.BitsPerSecOut));
            while (q.Count > _capacity) q.Dequeue();
        }
        // prune dead
        foreach (var pid in _byPid.Keys.Where(k => !seen.Contains(k)).ToList())
            if (_byPid[pid].Count == 0 || !seen.Contains(pid))
            {
                // keep briefly — drop if not seen this sample
                _byPid.Remove(pid);
            }
    }

    public IReadOnlyList<(double inn, double outt)> Get(int pid) =>
        _byPid.TryGetValue(pid, out var q) ? q.ToList() : Array.Empty<(double, double)>();
}
