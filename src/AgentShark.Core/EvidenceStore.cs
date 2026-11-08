using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace AgentShark.Core;

/// <summary>A bounded, indexed durable log. All SQL identifiers are internal constants.</summary>
public sealed class EvidenceStore : IDisposable
{
    public string DataDirectory => _options.DataDirectory;
    public static EvidenceStore OpenForServer(EngineOptions options)
    {
        try { return new(options); }
        catch (StoreInUseException)
        {
            return new(options with { DataDirectory = Path.Combine(options.DataDirectory, "instances", Guid.NewGuid().ToString("N")) });
        }
    }
    private readonly SqliteConnection _connection;
    private readonly object _gate = new();
    private readonly EngineOptions _options;
    private readonly FileStream _lease;
    private SqliteTransaction? _transaction;
    private int _pendingWrites;
    private long _batchStarted;

    private SqliteCommand CreateCommand()
    {
        var command = _connection.CreateCommand();
        command.Transaction = _transaction;
        return command;
    }

    private void Flush()
    {
        var transaction = _transaction;
        if (transaction == null) return;
        _transaction = null; _pendingWrites = 0;
        try { transaction.Commit(); }
        finally { transaction.Dispose(); }
    }

    public EvidenceStore(EngineOptions options)
    {
        _options = options;
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(options.DataDirectory);
        else Directory.CreateDirectory(options.DataDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try { _lease = new FileStream(Path.Combine(options.DataDirectory, "engine.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException ex) when ((ex.HResult & 0xffff) is 11 or 32 or 33) { throw new StoreInUseException("Evidence directory is already owned by another server instance.", ex); }
        _connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Path.Combine(options.DataDirectory, "evidence.sqlite"), Pooling = false }.ToString());
        try { _connection.Open(); }
        catch { _lease.Dispose(); _connection.Dispose(); throw; }
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(Path.Combine(options.DataDirectory, "evidence.sqlite"), UnixFileMode.UserRead | UnixFileMode.UserWrite);
        Execute("PRAGMA auto_vacuum=FULL; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
        Execute("""
            CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY, state TEXT NOT NULL, json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS records(seq INTEGER PRIMARY KEY AUTOINCREMENT, observation TEXT NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
                kind TEXT NOT NULL, id TEXT NOT NULL, connection_id TEXT, protocol TEXT, severity TEXT, status INTEGER, json TEXT NOT NULL,
                UNIQUE(observation,kind,id));
            CREATE INDEX IF NOT EXISTS records_query ON records(observation,kind,seq);
            CREATE INDEX IF NOT EXISTS records_connection ON records(observation,connection_id,kind,seq);
            PRAGMA user_version=1;
            """);
        foreach (var observation in ListObservations().Where(o => o.State == ObservationState.Running))
            Save(observation with { State = ObservationState.Interrupted, EndedAt = DateTimeOffset.UtcNow, StopReason = "server_restarted" });
    }

    private void Execute(string sql)
    {
        using var command = CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    public bool HasCapacity()
    {
        lock (_gate)
        {
            using var command = CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM observations";
            return (long)command.ExecuteScalar()! < _options.MaxStoredObservations && StorageBytes() < _options.MaxStorageBytes;
        }
    }

    public long StorageBytes()
    {
        lock (_gate) return Directory.EnumerateFiles(_options.DataDirectory, "evidence.sqlite*").Sum(f => new FileInfo(f).Length);
    }

    public void Save(ObservationInfo info)
    {
        lock (_gate)
        {
            Flush();
            using var command = CreateCommand();
            command.CommandText = "INSERT INTO observations(id,state,json) VALUES($id,$state,$json) ON CONFLICT(id) DO UPDATE SET state=$state,json=$json";
            command.Parameters.AddWithValue("$id", info.Id);
            command.Parameters.AddWithValue("$state", info.State.ToString());
            command.Parameters.AddWithValue("$json", JsonSerializer.Serialize(info, JsonDefaults.Options));
            command.ExecuteNonQuery();
        }
    }

    public ObservationInfo Get(string id)
    {
        lock (_gate)
        {
            using var command = CreateCommand();
            command.CommandText = "SELECT json FROM observations WHERE id=$id";
            command.Parameters.AddWithValue("$id", id);
            return command.ExecuteScalar() is string json ? JsonSerializer.Deserialize<ObservationInfo>(json, JsonDefaults.Options)! : throw new KeyNotFoundException("Observation not found.");
        }
    }

    public IReadOnlyList<ObservationInfo> ListObservations()
    {
        lock (_gate)
        {
            using var command = CreateCommand();
            command.CommandText = "SELECT json FROM observations ORDER BY rowid DESC LIMIT 1000";
            using var reader = command.ExecuteReader();
            var result = new List<ObservationInfo>();
            while (reader.Read()) result.Add(JsonSerializer.Deserialize<ObservationInfo>(reader.GetString(0), JsonDefaults.Options)!);
            return result;
        }
    }

    public void Put(string observation, EvidenceRecord record) => Put(observation, "evidence", record.Id, record.ConnectionId, null, record.Severity, null, record);
    public void Put(string observation, ConnectionRecord record) => Put(observation, "connection", record.Id, record.Id, record.Protocol, null, null, record);
    public void Put(string observation, ExchangeRecord record) => Put(observation, "exchange", record.Id, record.ConnectionId, record.Protocol, null, record.StatusCode, record);

    private void Put<T>(string observation, string kind, string id, string? connection, string? protocol, string? severity, int? status, T record)
    {
        lock (_gate)
        {
            if (_transaction == null)
            {
                _transaction = _connection.BeginTransaction(); _batchStarted = Environment.TickCount64;
            }
            using var command = CreateCommand();
            command.CommandText = """
                INSERT INTO records(observation,kind,id,connection_id,protocol,severity,status,json)
                VALUES($o,$k,$id,$c,$p,$s,$status,$j)
                ON CONFLICT(observation,kind,id) DO UPDATE SET protocol=$p,severity=$s,status=$status,json=$j;
                """;
            command.Parameters.AddWithValue("$o", observation);
            command.Parameters.AddWithValue("$k", kind);
            command.Parameters.AddWithValue("$id", id);
            command.Parameters.AddWithValue("$c", (object?)connection ?? DBNull.Value);
            command.Parameters.AddWithValue("$p", (object?)protocol ?? DBNull.Value);
            command.Parameters.AddWithValue("$s", (object?)severity ?? DBNull.Value);
            command.Parameters.AddWithValue("$status", (object?)status ?? DBNull.Value);
            command.Parameters.AddWithValue("$j", JsonSerializer.Serialize(record, JsonDefaults.Options));
            command.ExecuteNonQuery();
            if (++_pendingWrites >= 128 || Environment.TickCount64 - _batchStarted >= 100) Flush();
        }
    }

    public RecordPage<T> Query<T>(string observation, string kind, RecordQuery query)
    {
        query.Validate();
        lock (_gate)
        {
            var info = Get(observation);
            using var command = CreateCommand();
            command.CommandText = "SELECT seq,json FROM records WHERE observation=$o AND kind=$k AND seq>$after";
            command.Parameters.AddWithValue("$o", observation);
            command.Parameters.AddWithValue("$k", kind);
            command.Parameters.AddWithValue("$after", query.After);
            void Filter(string column, object? value)
            {
                if (value == null) return;
                command.CommandText += $" AND {column}=${column}";
                command.Parameters.AddWithValue($"${column}", value);
            }
            Filter("connection_id", query.ConnectionId);
            Filter("protocol", query.Protocol?.ToLowerInvariant());
            Filter("severity", query.Severity?.ToLowerInvariant());
            Filter("status", query.StatusCode);
            command.CommandText += " ORDER BY seq LIMIT $limit";
            command.Parameters.AddWithValue("$limit", query.Limit + 1);
            using var reader = command.ExecuteReader();
            var items = new List<T>();
            long cursor = 0;
            while (reader.Read())
            {
                if (items.Count == query.Limit) return new(items, cursor, info.State == ObservationState.Running);
                cursor = reader.GetInt64(0);
                items.Add(JsonSerializer.Deserialize<T>(reader.GetString(1), JsonDefaults.Options)!);
            }
            return new(items, null, info.State == ObservationState.Running);
        }
    }

    public EvidenceRecord Evidence(string observation, string id, bool includePayload)
    {
        lock (_gate)
        {
            _ = Get(observation);
            using var command = CreateCommand();
            command.CommandText = "SELECT json FROM records WHERE observation=$o AND kind='evidence' AND id=$id";
            command.Parameters.AddWithValue("$o", observation);
            command.Parameters.AddWithValue("$id", id);
            if (command.ExecuteScalar() is not string json) throw new KeyNotFoundException("Evidence not found.");
            var result = JsonSerializer.Deserialize<EvidenceRecord>(json, JsonDefaults.Options)!;
            return includePayload ? result : result with { PayloadBase64 = null };
        }
    }

    public IReadOnlyList<ComparisonMetric> Compare(string before, string after)
    {
        lock (_gate)
        {
            _ = Get(before); _ = Get(after);
            Dictionary<string, long> Counts(string id)
            {
                using var command = CreateCommand();
                command.CommandText = "SELECT kind || ':' || COALESCE(protocol,severity,'unknown') || ':' || COALESCE(CAST(status AS TEXT),''), COUNT(*) FROM records WHERE observation=$o GROUP BY 1";
                command.Parameters.AddWithValue("$o", id);
                using var reader = command.ExecuteReader();
                var counts = new Dictionary<string, long>();
                while (reader.Read()) counts[reader.GetString(0)] = reader.GetInt64(1);
                return counts;
            }
            var a = Counts(before); var b = Counts(after);
            return a.Keys.Union(b.Keys).Order().Take(200).Select(k => new ComparisonMetric(k, a.GetValueOrDefault(k), b.GetValueOrDefault(k), b.GetValueOrDefault(k) - a.GetValueOrDefault(k))).ToArray();
        }
    }

    public void Delete(string id)
    {
        lock (_gate)
        {
            if (Get(id).State == ObservationState.Running) throw new InvalidOperationException("Stop the observation before deleting it.");
            Flush();
            using var command = CreateCommand();
            command.CommandText = "DELETE FROM observations WHERE id=$id";
            command.Parameters.AddWithValue("$id", id);
            command.ExecuteNonQuery();
            Execute("PRAGMA wal_checkpoint(TRUNCATE);");
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            try { Flush(); }
            finally { _connection.Dispose(); _lease.Dispose(); }
        }
    }
}

public sealed class StoreInUseException(string message, Exception inner) : IOException(message, inner);
