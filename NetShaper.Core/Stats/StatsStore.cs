using System.Globalization;
using System.Text;
using Microsoft.Data.Sqlite;
using NetShaper.Core.Traffic;

namespace NetShaper.Core.Stats;

/// <summary>
/// Persistent traffic history (SQLite).
/// Path: %ProgramData%\NetShaper\stats.db
/// </summary>
public sealed class StatsStore : IDisposable
{
    private string _dbPath;
    private readonly object _gate = new();
    private SqliteConnection? _conn;
    private bool _disposed;
    private bool _readOnly;
    private DateTime _lastProcessWrite = DateTime.MinValue;
    private DateTime _lastPurge = DateTime.MinValue;

    public string DbPath => _dbPath;
    public bool IsAvailable => _conn is not null && !_readOnly;
    public int RetentionDays { get; set; } = 30;
    /// <summary>How often to write per-process rows (system totals every sample).</summary>
    public TimeSpan ProcessSampleInterval { get; set; } = TimeSpan.FromSeconds(10);
    public int TopProcessesPerSample { get; set; } = 15;

    public StatsStore(string? dbPath = null)
    {
        // Prefer ProgramData; fall back to LocalAppData if not writable (non-admin / locked ACL)
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(dbPath))
            candidates.Add(dbPath);
        else
        {
            candidates.Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "NetShaper", "stats.db"));
            candidates.Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "NetShaper", "stats.db"));
        }

        Exception? last = null;
        foreach (var path in candidates)
        {
            try
            {
                var dir = Path.GetDirectoryName(path)!;
                Directory.CreateDirectory(dir);
                _dbPath = path;
                Open();
                EnsureSchema();
                // Prove write works (ProgramData can open RO after admin created DB)
                using (var probe = _conn!.CreateCommand())
                {
                    probe.CommandText = "CREATE TABLE IF NOT EXISTS _write_probe(x INTEGER); DROP TABLE IF EXISTS _write_probe;";
                    probe.ExecuteNonQuery();
                }
                _readOnly = false;
                return;
            }
            catch (Exception ex)
            {
                last = ex;
                try { _conn?.Dispose(); } catch { /* */ }
                _conn = null;
            }
        }

        // Last resort: memory DB so GUI still starts
        _dbPath = ":memory:";
        try
        {
            Open();
            EnsureSchema();
            _readOnly = false;
        }
        catch
        {
            _readOnly = true;
            _conn = null;
            _dbPath = candidates[0] + " (unavailable: " + (last?.Message ?? "error") + ")";
        }
    }

    private void Open()
    {
        _conn = new SqliteConnection($"Data Source={_dbPath}");
        _conn.Open();
        using var cmd = _conn.CreateCommand();
        // DELETE journal avoids extra -wal files when ProgramData is semi-locked
        cmd.CommandText = "PRAGMA journal_mode=DELETE; PRAGMA synchronous=NORMAL;";
        cmd.ExecuteNonQuery();
    }

    private void EnsureSchema()
    {
        Exec("""
            CREATE TABLE IF NOT EXISTS samples (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT NOT NULL,
              bits_in INTEGER NOT NULL,
              bits_out INTEGER NOT NULL,
              app_count INTEGER NOT NULL,
              conn_count INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_samples_ts ON samples(ts);

            CREATE TABLE IF NOT EXISTS process_samples (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT NOT NULL,
              pid INTEGER NOT NULL,
              name TEXT NOT NULL,
              path TEXT,
              bits_in INTEGER NOT NULL,
              bits_out INTEGER NOT NULL,
              conns INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_proc_ts ON process_samples(ts);
            CREATE INDEX IF NOT EXISTS ix_proc_name_ts ON process_samples(name, ts);

            CREATE TABLE IF NOT EXISTS app_totals (
              name TEXT NOT NULL,
              day TEXT NOT NULL,
              bytes_in INTEGER NOT NULL DEFAULT 0,
              bytes_out INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY (name, day)
            );

            CREATE TABLE IF NOT EXISTS meta (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            """);
        SetMeta("schema_version", "1");
    }

    public void Record(TrafficSnapshot snap, bool includeProcesses = true)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_conn is null || _readOnly) return;
        lock (_gate)
        {
            if (_conn is null) return;
            var ts = snap.Timestamp.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
            using var tx = _conn.BeginTransaction();
            using (var cmd = _conn.CreateCommand())
            {
                cmd.Transaction = tx;
                cmd.CommandText =
                    "INSERT INTO samples(ts, bits_in, bits_out, app_count, conn_count) VALUES ($ts,$bi,$bo,$a,$c)";
                cmd.Parameters.AddWithValue("$ts", ts);
                cmd.Parameters.AddWithValue("$bi", snap.TotalBitsPerSecIn);
                cmd.Parameters.AddWithValue("$bo", snap.TotalBitsPerSecOut);
                cmd.Parameters.AddWithValue("$a", snap.Processes.Count);
                cmd.Parameters.AddWithValue("$c", snap.Connections.Count);
                cmd.ExecuteNonQuery();
            }

            var now = DateTime.UtcNow;
            if (includeProcesses && now - _lastProcessWrite >= ProcessSampleInterval)
            {
                _lastProcessWrite = now;
                var top = snap.Processes
                    .OrderByDescending(p => p.BitsPerSecIn + p.BitsPerSecOut)
                    .Take(TopProcessesPerSample)
                    .ToList();

                // Assume ~ProcessSampleInterval seconds of traffic for byte totals
                var intervalSec = Math.Max(1.0, ProcessSampleInterval.TotalSeconds);
                var day = now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

                foreach (var p in top)
                {
                    using var cmd = _conn.CreateCommand();
                    cmd.Transaction = tx;
                    cmd.CommandText = """
                        INSERT INTO process_samples(ts, pid, name, path, bits_in, bits_out, conns)
                        VALUES ($ts,$pid,$name,$path,$bi,$bo,$c)
                        """;
                    cmd.Parameters.AddWithValue("$ts", ts);
                    cmd.Parameters.AddWithValue("$pid", p.ProcessId);
                    cmd.Parameters.AddWithValue("$name", p.ProcessName);
                    cmd.Parameters.AddWithValue("$path", (object?)p.ExecutablePath ?? DBNull.Value);
                    cmd.Parameters.AddWithValue("$bi", (long)p.BitsPerSecIn);
                    cmd.Parameters.AddWithValue("$bo", (long)p.BitsPerSecOut);
                    cmd.Parameters.AddWithValue("$c", p.ConnectionCount);
                    cmd.ExecuteNonQuery();

                    var bin = (long)(p.BitsPerSecIn / 8.0 * intervalSec);
                    var bout = (long)(p.BitsPerSecOut / 8.0 * intervalSec);
                    using var up = _conn.CreateCommand();
                    up.Transaction = tx;
                    up.CommandText = """
                        INSERT INTO app_totals(name, day, bytes_in, bytes_out) VALUES ($n,$d,$bi,$bo)
                        ON CONFLICT(name, day) DO UPDATE SET
                          bytes_in = bytes_in + excluded.bytes_in,
                          bytes_out = bytes_out + excluded.bytes_out
                        """;
                    up.Parameters.AddWithValue("$n", p.ProcessName);
                    up.Parameters.AddWithValue("$d", day);
                    up.Parameters.AddWithValue("$bi", bin);
                    up.Parameters.AddWithValue("$bo", bout);
                    up.ExecuteNonQuery();
                }
            }

            tx.Commit();

            if (now - _lastPurge > TimeSpan.FromHours(6))
            {
                _lastPurge = now;
                try { PurgeOlderThan(RetentionDays); } catch { /* ignore purge errors */ }
            }
        }
    }

    public void PurgeOlderThan(int days)
    {
        if (_conn is null) return;
        if (days < 1) days = 1;
        var cutoff = DateTime.UtcNow.AddDays(-days).ToString("o", CultureInfo.InvariantCulture);
        var dayCut = DateTime.UtcNow.AddDays(-days).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        lock (_gate)
        {
            if (_conn is null) return;
            Exec($"DELETE FROM samples WHERE ts < '{cutoff.Replace("'", "''")}'");
            Exec($"DELETE FROM process_samples WHERE ts < '{cutoff.Replace("'", "''")}'");
            Exec($"DELETE FROM app_totals WHERE day < '{dayCut}'");
        }
    }

    public void ClearAll()
    {
        if (_conn is null) return;
        lock (_gate)
        {
            if (_conn is null) return;
            Exec("DELETE FROM samples; DELETE FROM process_samples; DELETE FROM app_totals;");
            Exec("VACUUM;");
        }
    }

    public StatsDbInfo GetInfo()
    {
        lock (_gate)
        {
            if (_conn is null)
                return new StatsDbInfo(0, 0, 0, null, null, 0, _dbPath ?? "(none)", RetentionDays);
            long samples = ScalarLong("SELECT COUNT(*) FROM samples");
            long procs = ScalarLong("SELECT COUNT(*) FROM process_samples");
            long apps = ScalarLong("SELECT COUNT(*) FROM app_totals");
            string? minTs = ScalarString("SELECT MIN(ts) FROM samples");
            string? maxTs = ScalarString("SELECT MAX(ts) FROM samples");
            long size = 0;
            try { if (_dbPath is not ":memory:" and not null) size = new FileInfo(_dbPath).Length; } catch { /* ignore */ }
            return new StatsDbInfo(samples, procs, apps, minTs, maxTs, size, _dbPath ?? "(none)", RetentionDays);
        }
    }

    public IReadOnlyList<SystemSamplePoint> QuerySystem(DateTimeOffset from, DateTimeOffset to, int maxPoints = 600)
    {
        lock (_gate)
        {
            if (_conn is null) return Array.Empty<SystemSamplePoint>();
            var fromS = from.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
            var toS = to.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                SELECT ts, bits_in, bits_out, app_count, conn_count
                FROM samples WHERE ts >= $f AND ts <= $t ORDER BY ts
                """;
            cmd.Parameters.AddWithValue("$f", fromS);
            cmd.Parameters.AddWithValue("$t", toS);
            var list = new List<SystemSamplePoint>();
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                list.Add(new SystemSamplePoint(
                    DateTimeOffset.Parse(r.GetString(0), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                    r.GetInt64(1), r.GetInt64(2), r.GetInt32(3), r.GetInt32(4)));
            }
            return Downsample(list, maxPoints);
        }
    }

    public IReadOnlyList<AppTotalRow> QueryTopApps(DateTimeOffset from, DateTimeOffset to, int limit = 30)
    {
        // Prefer daily rollup when range spans days; else aggregate process_samples
        var span = to - from;
        lock (_gate)
        {
            if (_conn is null) return Array.Empty<AppTotalRow>();
            if (span.TotalHours >= 20)
            {
                var fromD = from.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                var toD = to.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = """
                    SELECT name, SUM(bytes_in), SUM(bytes_out)
                    FROM app_totals WHERE day >= $f AND day <= $t
                    GROUP BY name
                    ORDER BY (SUM(bytes_in)+SUM(bytes_out)) DESC
                    LIMIT $lim
                    """;
                cmd.Parameters.AddWithValue("$f", fromD);
                cmd.Parameters.AddWithValue("$t", toD);
                cmd.Parameters.AddWithValue("$lim", limit);
                return ReadAppTotals(cmd);
            }
            else
            {
                var fromS = from.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
                var toS = to.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
                // Approximate bytes from rate samples * 10s average interval
                using var cmd = _conn.CreateCommand();
                cmd.CommandText = """
                    SELECT name,
                      CAST(SUM(bits_in) / 8.0 * 10 AS INTEGER),
                      CAST(SUM(bits_out) / 8.0 * 10 AS INTEGER)
                    FROM process_samples WHERE ts >= $f AND ts <= $t
                    GROUP BY name
                    ORDER BY (SUM(bits_in)+SUM(bits_out)) DESC
                    LIMIT $lim
                    """;
                cmd.Parameters.AddWithValue("$f", fromS);
                cmd.Parameters.AddWithValue("$t", toS);
                cmd.Parameters.AddWithValue("$lim", limit);
                return ReadAppTotals(cmd);
            }
        }
    }

    public IReadOnlyList<AppRatePoint> QueryAppRates(string processName, DateTimeOffset from, DateTimeOffset to, int maxPoints = 400)
    {
        lock (_gate)
        {
            if (_conn is null) return Array.Empty<AppRatePoint>();
            var fromS = from.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
            var toS = to.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
            using var cmd = _conn.CreateCommand();
            cmd.CommandText = """
                SELECT ts, SUM(bits_in), SUM(bits_out)
                FROM process_samples
                WHERE name = $n AND ts >= $f AND ts <= $t
                GROUP BY ts ORDER BY ts
                """;
            cmd.Parameters.AddWithValue("$n", processName);
            cmd.Parameters.AddWithValue("$f", fromS);
            cmd.Parameters.AddWithValue("$t", toS);
            var list = new List<AppRatePoint>();
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                list.Add(new AppRatePoint(
                    DateTimeOffset.Parse(r.GetString(0), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                    r.GetInt64(1), r.GetInt64(2)));
            }
            if (list.Count <= maxPoints) return list;
            // downsample
            var step = (double)list.Count / maxPoints;
            var outList = new List<AppRatePoint>(maxPoints);
            for (int i = 0; i < maxPoints; i++)
                outList.Add(list[(int)(i * step)]);
            return outList;
        }
    }

    public string ExportSystemCsv(DateTimeOffset from, DateTimeOffset to)
    {
        var pts = QuerySystem(from, to, maxPoints: 100_000);
        var sb = new StringBuilder();
        sb.AppendLine("timestamp_utc,bits_in,bits_out,app_count,conn_count");
        foreach (var p in pts)
            sb.AppendLine($"{p.Time:o},{p.BitsIn},{p.BitsOut},{p.AppCount},{p.ConnCount}");
        return sb.ToString();
    }

    public string ExportTopAppsCsv(DateTimeOffset from, DateTimeOffset to)
    {
        var rows = QueryTopApps(from, to, 500);
        var sb = new StringBuilder();
        sb.AppendLine("process,bytes_in,bytes_out,bytes_total");
        foreach (var r in rows)
            sb.AppendLine($"\"{r.Name.Replace("\"", "\"\"")}\",{r.BytesIn},{r.BytesOut},{r.BytesIn + r.BytesOut}");
        return sb.ToString();
    }

    private static List<AppTotalRow> ReadAppTotals(SqliteCommand cmd)
    {
        var list = new List<AppTotalRow>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
            list.Add(new AppTotalRow(r.GetString(0), r.GetInt64(1), r.GetInt64(2)));
        return list;
    }

    private static IReadOnlyList<SystemSamplePoint> Downsample(List<SystemSamplePoint> list, int maxPoints)
    {
        if (list.Count <= maxPoints) return list;
        var step = (double)list.Count / maxPoints;
        var outList = new List<SystemSamplePoint>(maxPoints);
        for (int i = 0; i < maxPoints; i++)
            outList.Add(list[(int)(i * step)]);
        return outList;
    }

    private void Exec(string sql)
    {
        using var cmd = _conn!.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private long ScalarLong(string sql)
    {
        using var cmd = _conn!.CreateCommand();
        cmd.CommandText = sql;
        var o = cmd.ExecuteScalar();
        return o is long l ? l : Convert.ToInt64(o);
    }

    private string? ScalarString(string sql)
    {
        using var cmd = _conn!.CreateCommand();
        cmd.CommandText = sql;
        return cmd.ExecuteScalar()?.ToString();
    }

    private void SetMeta(string key, string value)
    {
        using var cmd = _conn!.CreateCommand();
        cmd.CommandText = """
            INSERT INTO meta(key, value) VALUES ($k,$v)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """;
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$v", value);
        cmd.ExecuteNonQuery();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        lock (_gate)
        {
            _conn?.Dispose();
            _conn = null;
        }
    }
}

public sealed record StatsDbInfo(
    long SampleCount,
    long ProcessSampleCount,
    long AppTotalRows,
    string? OldestTs,
    string? NewestTs,
    long FileBytes,
    string Path,
    int RetentionDays);

public sealed record SystemSamplePoint(
    DateTimeOffset Time,
    long BitsIn,
    long BitsOut,
    int AppCount,
    int ConnCount);

public sealed record AppTotalRow(string Name, long BytesIn, long BytesOut);

public sealed record AppRatePoint(DateTimeOffset Time, long BitsIn, long BitsOut);
