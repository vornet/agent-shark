using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Net.Sockets;
using AgentShark.Core.Capture;
using AgentShark.Core.Protocols;
using AgentShark.Core.Proxy;

namespace AgentShark.Core;

public sealed class ObservationEngine : IAsyncDisposable
{
    private readonly EngineOptions _options;
    private readonly EvidenceStore _store;
    private readonly SemaphoreSlim _lifecycle = new(1, 1);
    private readonly ConcurrentDictionary<string, ActiveObservation> _active = [];
    private bool _disposed;

    private sealed class ActiveObservation(ObservationInfo info, ObservationRequest request)
    {
        public readonly object Gate = new();
        public ObservationInfo Info = info;
        public readonly ObservationRequest Request = request;
        public readonly CancellationTokenSource Stop = new(TimeSpan.FromSeconds(request.DurationSeconds));
        public Task Work = Task.CompletedTask;
        public NativeCapture? Capture;
        public ObservationProxy? Proxy;
        public FileStream? Input;
        public long Excluded;
        public long LastStorageCheck;
    }

    public ObservationEngine(EngineOptions options, EvidenceStore store)
    {
        if (options.MaxConcurrentObservations is < 1 or > 32 || options.MaxStoredObservations < 1 || options.MaxFlows is < 1 or > 65536 || options.MaxStreamBytes is < 1024 or > 4 * 1024 * 1024 || options.MaxBodyBytes is < 0 or > 65536)
            throw new ArgumentException("Invalid engine resource limits.");
        _options = options; _store = store;
    }

    public CapabilityReport Capabilities()
    {
        IReadOnlyList<CaptureInterface> interfaces = []; string? error = null;
        try { interfaces = NativeCapture.Interfaces(); }
        catch (Exception ex) when (ex is DllNotFoundException or TypeInitializationException or InvalidOperationException or SharpPcap.PcapException)
        { error = "Native capture unavailable. Install Npcap on Windows or libpcap on Linux/macOS, and grant capture access. " + ex.GetType().Name; }
        return new(ProductVersion.Current, RuntimeInformation.OSDescription, error == null, interfaces, error,
            ["capture", "import", "proxy"], ["ethernet", "vlan", "ipv4", "ipv6", "tcp", "udp", "icmp", "icmpv6", "dns/udp", "http/1.0", "http/1.1", "tls-client-hello"],
            ["Passive capture does not decrypt TLS. Explicit proxy TLS interception requires target-app trust of the returned temporary CA.",
             "Proxy supports HTTP/1 and CONNECT. HTTP/2, HTTP/3, WebSocket frame decoding, passive TLS decryption and IP fragment reassembly are not supported. TCP generations are separated only when a new opening SYN is observed.",
             "Process filtering uses best-effort Windows socket snapshots and may miss short-lived sockets; other platforms support interface/filter selection.",
             "Packet timestamps reflect the capture point. Retransmission indicators do not prove network loss. Cross-direction packet reordering can affect request matching.",
             _options.ImportRoots.Length == 0 ? "Capture-file imports are disabled until ImportRoots is configured." : "Capture-file imports are restricted to configured ImportRoots; symbolic links are rejected.",
             "Payload retention is opt-in. Headers are allowlisted and URL queries/userinfo are removed; retained bodies/raw bytes can contain secrets."], _store.DataDirectory);
    }

    public async Task<StartResult> StartAsync(ObservationRequest request, CancellationToken cancellationToken = default)
    {
        request.Validate();
        await _lifecycle.WaitAsync(cancellationToken);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_active.Count >= _options.MaxConcurrentObservations) throw new InvalidOperationException("Concurrent observation limit reached. Stop an observation first.");
            if (!_store.HasCapacity()) throw new InvalidOperationException("Evidence storage limit reached. Delete completed observations before starting another.");
            string id = "obs_" + Guid.NewGuid().ToString("N");
            var info = new ObservationInfo(id, request.Mode, ObservationState.Running, DateTimeOffset.UtcNow, null, 0, 0, 0, null, request.RetainPayloads,
                ["Live results are provisional until the observation completes.", request.Mode == ObservationMode.Proxy ? "Only traffic explicitly routed through this proxy is observed; connections are closed after one HTTP exchange." : "Capture coverage depends on the selected interface/filter. Encrypted application payload is not decoded.",
                 request.ProcessId != null ? "Process selection is best-effort socket-snapshot correlation; unmatched packets are excluded." : "No process-specific capture selection was requested."]);
            var active = new ActiveObservation(info, request);
            try
            {
                if (request.Mode == ObservationMode.Import)
                {
                    var path = ValidateImportPath(request.ImportPath!);
                    active.Input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, FileOptions.Asynchronous | FileOptions.SequentialScan);
                    if (active.Input.Length > request.MaxBytes * 2 + 4 * 1024 * 1024) throw new ArgumentException("Import file exceeds the observation input limit. Increase maxBytes or provide a smaller capture.");
                }
                if (request.Mode == ObservationMode.Capture) active.Capture = new(request.InterfaceId!, request.CaptureFilter);
                _store.Save(info);
                if (request.Mode == ObservationMode.Proxy)
                    active.Proxy = new(id, request, _options, _store, bytes => Account(active, bytes, false), () => AccountProxyRequest(active));
                _active[id] = active;
                active.Work = Task.Run(() => Run(active));
                return new(info, active.Proxy?.Connection);
            }
            catch
            {
                active.Input?.Dispose(); active.Capture?.Dispose();
                if (active.Proxy != null) await active.Proxy.DisposeAsync();
                active.Stop.Dispose();
                _store.Save(info with { State = ObservationState.Failed, EndedAt = DateTimeOffset.UtcNow, StopReason = "startup_failed" });
                throw;
            }
        }
        finally { _lifecycle.Release(); }
    }

    private string ValidateImportPath(string path)
    {
        string full = Path.GetFullPath(path);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        string? trustedRoot = _options.ImportRoots.Select(root => Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)))
            .Where(root => full.StartsWith(root + Path.DirectorySeparatorChar, comparison)).OrderByDescending(root => root.Length).FirstOrDefault();
        if (trustedRoot == null)
            throw new ArgumentException("Import path is outside configured ImportRoots.");
        // The administrator-selected root may live below a platform alias such as macOS /var.
        // Reject links in the untrusted relative path, not in ancestors of that trusted root.
        for (FileSystemInfo? item = new FileInfo(full); item != null && item.FullName.Length > trustedRoot.Length; item = item is FileInfo file ? file.Directory : ((DirectoryInfo)item).Parent)
            if ((item.Attributes & FileAttributes.ReparsePoint) != 0) throw new ArgumentException("Symbolic links and reparse points are not allowed for capture imports.");
        return full;
    }

    private bool Account(ActiveObservation active, int bytes, bool packet)
    {
        lock (active.Gate)
        {
            if (active.Stop.IsCancellationRequested) return false;
            string? reason = active.Info.Bytes + bytes > active.Request.MaxBytes ? "byte_limit" : packet && active.Info.Packets >= active.Request.MaxPackets ? "packet_limit" : null;
            if (active.Info.Bytes - active.LastStorageCheck >= 1024 * 1024)
            {
                active.LastStorageCheck = active.Info.Bytes;
                if (_store.StorageBytes() >= _options.MaxStorageBytes) reason = "storage_limit";
            }
            if (reason != null)
            {
                active.Info = active.Info with { StopReason = reason };
                active.Stop.Cancel(); return false;
            }
            active.Info = active.Info with { Bytes = active.Info.Bytes + bytes, Packets = active.Info.Packets + (packet ? 1 : 0) };
            return true;
        }
    }

    private bool AccountProxyRequest(ActiveObservation active)
    {
        lock (active.Gate)
        {
            if (active.Stop.IsCancellationRequested) return false;
            if (active.Info.ProxyRequests >= active.Request.MaxProxyRequests)
            {
                active.Info = active.Info with { StopReason = "proxy_request_limit" }; active.Stop.Cancel(); return false;
            }
            active.Info = active.Info with { ProxyRequests = active.Info.ProxyRequests + 1 };
            return true;
        }
    }

    private async Task Run(ActiveObservation active)
    {
        var analyzer = new TrafficAnalyzer(active.Info.Id, active.Request, _options, _store);
        WindowsProcessCorrelator? correlator = OperatingSystem.IsWindows() && active.Request.ProcessId != null ? new() : null;
        var state = ObservationState.Completed;
        try
        {
            if (active.Proxy != null) await active.Proxy.RunAsync(active.Stop.Token);
            else
            {
                var packets = active.Input != null ? CaptureReader.ReadAsync(active.Input, active.Stop.Token) : active.Capture!.ReadAsync(active.Stop.Token);
                await foreach (var packet in packets.WithCancellation(active.Stop.Token))
                {
                    if (!Account(active, packet.Data.Length, true)) break;
                    if (active.Request.ProcessId is int pid && OperatingSystem.IsWindows())
                    {
                        DecodedPacket? decoded;
                        try { decoded = PacketDecoder.Decode(packet); } catch (InvalidDataException) { active.Excluded++; continue; }
                        if (decoded == null || !correlator!.Matches(decoded, pid)) { active.Excluded++; continue; }
                    }
                    analyzer.Process(packet, active.Request.ProcessId, active.Request.ProcessId != null ? "socket_snapshot_best_effort" : "unknown");
                    if (active.Info.Packets % 100 == 0) { lock (active.Gate) _store.Save(active.Info); }
                }
            }
        }
        catch (OperationCanceledException) when (active.Stop.IsCancellationRequested) { }
        catch (Exception ex) when (ex is InvalidDataException or IOException or SharpPcap.PcapException or SocketException or InvalidOperationException or OverflowException or ArgumentException)
        {
            state = ObservationState.Failed;
            _store.Put(active.Info.Id, new EvidenceRecord("observation_error", null, DateTimeOffset.UtcNow, "observation_failed", "error", "Observation could not complete.", new() { ["errorType"] = ex.GetType().Name, ["detail"] = ex is InvalidDataException ? Privacy.Clip(ex.Message, 512) : "Inspect backend availability and input configuration." }));
        }
        finally
        {
            try
            {
                analyzer.Finish();
                if (active.Capture != null)
                {
                    lock (active.Gate) active.Info = active.Info with { DroppedPackets = active.Capture.Dropped };
                    active.Capture.Dispose();
                }
                if (active.Proxy != null) await active.Proxy.DisposeAsync();
                if (active.Input != null) await active.Input.DisposeAsync();
                if (active.Excluded > 0) _store.Put(active.Info.Id, new EvidenceRecord("process_coverage", null, DateTimeOffset.UtcNow, "process_selection", "warning", "Packets without a matching process socket snapshot were excluded.", new() { ["excludedPackets"] = active.Excluded.ToString() }));
            }
            finally
            {
                lock (active.Gate)
                {
                    active.Info = active.Info with { State = state, EndedAt = DateTimeOffset.UtcNow, StopReason = active.Info.StopReason ?? (state == ObservationState.Failed ? "backend_error" : active.Stop.IsCancellationRequested ? "duration_limit" : "input_exhausted") };
                    _store.Save(active.Info);
                }
                lock (active.Gate) active.Stop.Dispose();
                _active.TryRemove(active.Info.Id, out _);
            }
        }
    }

    public ObservationInfo Status(string id)
    {
        if (_active.TryGetValue(id, out var active)) { lock (active.Gate) return active.Info; }
        return _store.Get(id);
    }

    public IReadOnlyList<ObservationInfo> List() => _store.ListObservations().Select(o => Status(o.Id)).ToArray();

    public async Task<ObservationInfo> StopAsync(string id, CancellationToken ct = default)
    {
        if (_active.TryGetValue(id, out var active))
        {
            lock (active.Gate)
            {
                if (active.Info.State == ObservationState.Running)
                {
                    active.Info = active.Info with { StopReason = active.Info.StopReason ?? "requested" };
                    active.Stop.Cancel();
                }
            }
            await active.Work.WaitAsync(ct);
        }
        return Status(id);
    }

    public RecordPage<ConnectionRecord> Connections(string id, RecordQuery query) => _store.Query<ConnectionRecord>(id, "connection", query);
    public RecordPage<ExchangeRecord> Exchanges(string id, RecordQuery query, bool includePayloads = false)
    {
        query.Validate();
        if (includePayloads && query.Limit > 20) query = query with { Limit = 20 };
        var page = _store.Query<ExchangeRecord>(id, "exchange", query);
        return includePayloads ? page : page with { Items = page.Items.Select(e => e with { RequestBody = null, ResponseBody = null }).ToArray() };
    }
    public RecordPage<EvidenceRecord> Events(string id, RecordQuery query)
    {
        var page = _store.Query<EvidenceRecord>(id, "evidence", query);
        return page with { Items = page.Items.Select(e => e with { PayloadBase64 = null }).ToArray() };
    }
    public EvidenceRecord Evidence(string id, string evidenceId, bool includePayload) => _store.Evidence(id, evidenceId, includePayload);
    public ComparisonResult Compare(string before, string after) => new(before, after, Status(before).State == ObservationState.Running || Status(after).State == ObservationState.Running,
        _store.Compare(before, after), ["Counts reflect each observation's duration, visibility and collection mode; differences do not establish causation."]);
    public void Delete(string id) => _store.Delete(id);

    public async ValueTask DisposeAsync()
    {
        await _lifecycle.WaitAsync();
        try
        {
            if (_disposed) return;
            _disposed = true;
            var observations = _active.Values.ToArray();
            foreach (var active in observations)
            {
                lock (active.Gate)
                {
                    if (active.Info.State != ObservationState.Running) continue;
                    active.Info = active.Info with { StopReason = "server_shutdown" }; active.Stop.Cancel();
                }
            }
            await Task.WhenAll(observations.Select(a => a.Work));
        }
        finally { _lifecycle.Release(); }
    }
}
