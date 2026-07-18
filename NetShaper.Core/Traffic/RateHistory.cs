namespace NetShaper.Core.Traffic;

/// <summary>Ring buffer of system-wide rate samples for GUI charts.</summary>
public sealed class RateHistory
{
    private readonly int _capacity;
    private readonly Queue<Sample> _samples;

    public RateHistory(int capacity = 120)
    {
        _capacity = Math.Max(10, capacity);
        _samples = new Queue<Sample>(_capacity);
    }

    public readonly record struct Sample(DateTimeOffset Time, long BitsIn, long BitsOut);

    public int Count => _samples.Count;
    public IReadOnlyList<Sample> Samples => _samples.ToList();

    public void Add(long bitsIn, long bitsOut)
    {
        _samples.Enqueue(new Sample(DateTimeOffset.Now, bitsIn, bitsOut));
        while (_samples.Count > _capacity)
            _samples.Dequeue();
    }

    public (long maxIn, long maxOut) MaxBits()
    {
        long mi = 1, mo = 1;
        foreach (var s in _samples)
        {
            if (s.BitsIn > mi) mi = s.BitsIn;
            if (s.BitsOut > mo) mo = s.BitsOut;
        }
        return (mi, mo);
    }
}
