using System.Text.Json;
using System.Text.Json.Serialization;
using System.ComponentModel;

namespace AgentShark.Core;

public static class JsonDefaults
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };
}

[JsonConverter(typeof(JsonStringEnumConverter<ObservationState>))]
public enum ObservationState { Running, Completed, Failed, Interrupted }
[JsonConverter(typeof(JsonStringEnumConverter<ObservationMode>))]
public enum ObservationMode { Capture, Import, Proxy }

public sealed record ObservationRequest
{
    [Description("capture for passive interface traffic, import for an existing capture file, proxy for explicitly routed HTTP/HTTPS traffic.")]
    public ObservationMode Mode { get; init; } = ObservationMode.Capture;
    [Description("Exact capture interface ID from get_capabilities; required in capture mode.")]
    public string? InterfaceId { get; init; }
    [Description("Optional Berkeley Packet Filter applied by the native capture library; not an application-level query.")]
    public string? CaptureFilter { get; init; }
    [Description("Absolute PCAP/PCAPNG path within configured import roots; required in import mode.")]
    public string? ImportPath { get; init; }
    [Description("Maximum observation duration, 1..3600 seconds; defaults to 60.")]
    public int DurationSeconds { get; init; } = 60;
    [Description("Maximum collected packets for capture/import, 1..1000000; defaults to 100000.")]
    public int MaxPackets { get; init; } = 100_000;
    [Description("Maximum forwarded HTTP exchanges or CONNECT tunnels in proxy mode, 1..100000; defaults to 10000.")]
    public int MaxProxyRequests { get; init; } = 10_000;
    [Description("Maximum collected bytes, 1024..1073741824; defaults to 64 MiB. Proxy counters measure application/tunnel bytes, not link-layer packets.")]
    public long MaxBytes { get; init; } = 64 * 1024 * 1024;
    [Description("Optional Windows process selection using best-effort socket ownership snapshots; capture mode only.")]
    public int? ProcessId { get; init; }
    [Description("Explicitly allow bounded bodies/raw packet prefixes to be stored. Default false. Retained data may contain credentials and personal information.")]
    public bool RetainPayloads { get; init; }
    [Description("Explicitly terminate target-app TLS in proxy mode. Requires the target app to trust the returned temporary CA. Default false; no system trust changes.")]
    public bool InterceptTls { get; init; }
    [Description("Required in proxy mode: 1..100 exact hostnames/IPs without scheme, ports or wildcards. Authorizes all valid ports at each destination.")]
    public string[] AllowedHosts { get; init; } = [];

    public void Validate()
    {
        if (!Enum.IsDefined(Mode)) throw new ArgumentException("Unknown observation mode.");
        if (DurationSeconds is < 1 or > 3600) throw new ArgumentException("durationSeconds must be 1..3600.");
        if (MaxPackets is < 1 or > 1_000_000) throw new ArgumentException("maxPackets must be 1..1000000.");
        if (MaxProxyRequests is < 1 or > 100_000) throw new ArgumentException("maxProxyRequests must be 1..100000.");
        if (MaxBytes is < 1024 or > 1024L * 1024 * 1024) throw new ArgumentException("maxBytes must be 1024..1073741824.");
        if (CaptureFilter?.Length > 4096) throw new ArgumentException("Capture filter is too long.");
        if (ProcessId is <= 0) throw new ArgumentException("processId must be positive.");
        if (Mode == ObservationMode.Capture && string.IsNullOrWhiteSpace(InterfaceId)) throw new ArgumentException("interfaceId is required.");
        if (Mode == ObservationMode.Import && string.IsNullOrWhiteSpace(ImportPath)) throw new ArgumentException("importPath is required.");
        if (ProcessId != null && Mode != ObservationMode.Capture) throw new ArgumentException("Process filtering is only available for live capture.");
        if (ProcessId != null && !OperatingSystem.IsWindows()) throw new ArgumentException("Process correlation is currently supported on Windows only.");
        if (AllowedHosts == null) throw new ArgumentException("allowedHosts cannot be null.");
        if (Mode == ObservationMode.Proxy && (AllowedHosts.Length is < 1 or > 100 || AllowedHosts.Any(h => string.IsNullOrWhiteSpace(h) || Uri.CheckHostName(h) == UriHostNameType.Unknown)))
            throw new ArgumentException("Proxy mode requires 1..100 exact allowed hostnames or IP addresses (without ports or wildcards).");
        if (InterceptTls && Mode != ObservationMode.Proxy) throw new ArgumentException("TLS interception is available only in proxy mode.");
    }
}

public sealed record ObservationInfo(string Id, ObservationMode Mode, ObservationState State,
    DateTimeOffset StartedAt, DateTimeOffset? EndedAt, long Packets, long Bytes,
    long DroppedPackets, string? StopReason, bool RetainPayloads, string[] Limitations, long ProxyRequests = 0);

public sealed record ProxyConnectionInfo(string Url, string Username, string Password, string? CaCertificatePem);
public sealed record StartResult(ObservationInfo Observation, ProxyConnectionInfo? Proxy);
public sealed record NetworkEndpoint(string Address, int Port)
{
    public override string ToString() => Address.Contains(':') ? $"[{Address}]:{Port}" : $"{Address}:{Port}";
}
public sealed record ConnectionRecord(string Id, string Protocol, NetworkEndpoint A, NetworkEndpoint B,
    DateTimeOffset FirstSeen, DateTimeOffset LastSeen, long Packets, long Bytes, int? ProcessId,
    string Attribution, bool? Encrypted, string[] EvidenceIds);
public sealed record ExchangeRecord(string Id, string ConnectionId, string Protocol, string Method,
    string Target, int? StatusCode, DateTimeOffset StartedAt, double? DurationMs,
    Dictionary<string, string> RequestHeaders, Dictionary<string, string> ResponseHeaders,
    string? RequestBody, string? ResponseBody, string Completeness, string[] EvidenceIds);
public sealed record EvidenceRecord(string Id, string? ConnectionId, DateTimeOffset Timestamp,
    string Kind, string Severity, string Summary, Dictionary<string, string> Fields, string? PayloadBase64 = null);
public sealed record RecordPage<T>(IReadOnlyList<T> Items, long? NextCursor, bool Provisional);
public sealed record RecordQuery(long After = 0, int Limit = 50, string? ConnectionId = null,
    string? Protocol = null, string? Severity = null, int? StatusCode = null)
{
    public void Validate()
    {
        if (After < 0 || Limit is < 1 or > 200) throw new ArgumentException("after must be nonnegative and limit must be 1..200.");
        if (ConnectionId?.Length > 128 || Protocol?.Length > 64 || Severity?.Length > 32) throw new ArgumentException("Query value is too long.");
    }
}
public sealed record CaptureInterface(string Id, string Description);
public sealed record CapabilityReport(string Version, string OperatingSystem, bool NativeCaptureAvailable,
    IReadOnlyList<CaptureInterface> Interfaces, string? CaptureError, string[] Modes, string[] Protocols, string[] Limitations, string? EvidenceDirectory = null);
public sealed record ComparisonMetric(string Key, long Before, long After, long Delta);
public sealed record ComparisonResult(string BeforeId, string AfterId, bool Provisional, IReadOnlyList<ComparisonMetric> Metrics, string[] Limitations);

public sealed record EngineOptions
{
    public string DataDirectory { get; init; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AgentShark");
    public string[] ImportRoots { get; init; } = [];
    public int MaxConcurrentObservations { get; init; } = 4;
    public int MaxStoredObservations { get; init; } = 100;
    public long MaxStorageBytes { get; init; } = 2L * 1024 * 1024 * 1024;
    public int MaxFlows { get; init; } = 4096;
    public int MaxStreamBytes { get; init; } = 256 * 1024;
    public int MaxBodyBytes { get; init; } = 16 * 1024;
    public string? UpstreamCaPem { get; init; }
}
