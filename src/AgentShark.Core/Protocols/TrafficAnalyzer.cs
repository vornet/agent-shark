using System.Security.Cryptography;
using System.Text;
using AgentShark.Core.Capture;

namespace AgentShark.Core.Protocols;

public sealed class TrafficAnalyzer(string observation, ObservationRequest request, EngineOptions options, EvidenceStore store)
{
    private readonly Dictionary<string, Flow> _flows = [];
    private long _packetNumber;
    private sealed class Direction(int limit)
    {
        public readonly TcpReassembler Tcp = new(limit);
        public readonly MemoryStream Buffer = new();
        public bool Disabled;
        public readonly List<string> Evidence = [];
    }
    private sealed class Flow(ConnectionRecord record, int limit)
    {
        public ConnectionRecord Record = record;
        public readonly Direction Forward = new(limit), Reverse = new(limit);
        public readonly Queue<ExchangeRecord> Requests = [];
        public uint? InitialSequence;
    }

    public void Process(CapturedPacket packet, int? processId = null, string attribution = "unknown")
    {
        var evidenceId = $"pkt_{++_packetNumber}";
        DecodedPacket? decoded;
        try { decoded = PacketDecoder.Decode(packet); }
        catch (InvalidDataException ex) { Event(null, packet.Timestamp, "decode_incomplete", "warning", ex.Message, [], evidenceId); return; }
        if (decoded == null) return;
        string left = decoded.Source.ToString(), right = decoded.Destination.ToString();
        string key = string.CompareOrdinal(left, right) < 0 ? $"{decoded.Protocol}|{left}|{right}" : $"{decoded.Protocol}|{right}|{left}";
        bool syn = decoded.Protocol == "tcp" && (decoded.TcpFlags & 0x12) == 2;
        if (syn && _flows.TryGetValue(key, out var previous) && previous.InitialSequence != decoded.Sequence)
        {
            FinishFlow(previous); _flows.Remove(key);
        }
        if (!_flows.TryGetValue(key, out var flow))
        {
            if (_flows.Count >= options.MaxFlows) { Event(null, packet.Timestamp, "flow_limit", "warning", "Flow limit reached; additional flows are not decoded.", [], evidenceId); return; }
            string id = "conn_" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(key + "|" + _packetNumber)))[..20];
            flow = new(new(id, decoded.Protocol, decoded.Source, decoded.Destination, packet.Timestamp, packet.Timestamp, 0, 0, processId, attribution, null, [evidenceId]), options.MaxStreamBytes);
            if (syn) flow.InitialSequence = decoded.Sequence;
            _flows.Add(key, flow);
        }
        flow.Record = flow.Record with { LastSeen = packet.Timestamp, Packets = flow.Record.Packets + 1, Bytes = flow.Record.Bytes + packet.Data.Length };
        var fields = new Dictionary<string, string> { ["source"] = left, ["destination"] = right, ["protocol"] = decoded.Protocol, ["capturedBytes"] = packet.Data.Length.ToString(), ["originalBytes"] = packet.OriginalLength.ToString(), ["linkType"] = packet.LinkType.ToString(), ["truncated"] = decoded.Truncated.ToString() };
        store.Put(observation, new EvidenceRecord(evidenceId, flow.Record.Id, packet.Timestamp, "packet", decoded.Truncated ? "warning" : "info", $"{decoded.Protocol.ToUpperInvariant()} {left} → {right}", fields,
            request.RetainPayloads ? Convert.ToBase64String(packet.Data.AsSpan(0, Math.Min(packet.Data.Length, options.MaxBodyBytes))) : null));
        try
        {
            if (decoded.Protocol is "icmp" or "icmpv6")
            {
                var icmp = IcmpDecoder.Decode(decoded.Payload, decoded.Protocol == "icmpv6");
                flow.Record = flow.Record with { Encrypted = false };
                Event(flow.Record.Id, packet.Timestamp, decoded.Protocol, icmp["isError"] == "True" ? "warning" : "info", icmp["description"], icmp, evidenceId + "_icmp");
            }
            if (decoded.Protocol == "udp" && (decoded.Source.Port == 53 || decoded.Destination.Port == 53))
            {
                var dns = DnsDecoder.Decode(decoded.Payload);
                flow.Record = flow.Record with { Encrypted = false };
                Event(flow.Record.Id, packet.Timestamp, "dns", dns["responseCode"] == "0" ? "info" : "warning", "DNS message", dns, evidenceId + "_dns");
            }
            if (decoded.Protocol == "tcp")
            {
                var direction = decoded.Source == flow.Record.A ? flow.Forward : flow.Reverse;
                if ((decoded.TcpFlags & 2) != 0) direction.Tcp.Start(decoded.Sequence + 1);
                if ((decoded.TcpFlags & 4) != 0) Event(flow.Record.Id, packet.Timestamp, "tcp_reset", "warning", "TCP reset observed; this alone does not establish the application cause.", [], evidenceId + "_reset");
                if (!direction.Disabled)
                {
                    if (direction.Evidence.Count < 64) direction.Evidence.Add(evidenceId);
                    var contiguous = direction.Tcp.Push(decoded.Sequence + ((decoded.TcpFlags & 2) != 0 ? 1u : 0), decoded.Payload, out var anomaly);
                    if (anomaly != null) Event(flow.Record.Id, packet.Timestamp, anomaly, "warning", "TCP sequence anomaly observed; capture loss and offloading can affect interpretation.", [], evidenceId + "_tcp");
                    if (direction.Buffer.Length + contiguous.Length > options.MaxStreamBytes) throw new InvalidDataException("Application stream buffer limit exceeded.");
                    direction.Buffer.Write(contiguous);
                    DecodeStream(flow, direction, packet.Timestamp, evidenceId, (decoded.TcpFlags & 5) != 0);
                }
            }
        }
        catch (InvalidDataException ex)
        {
            if (decoded.Protocol == "tcp") (decoded.Source == flow.Record.A ? flow.Forward : flow.Reverse).Disabled = true;
            Event(flow.Record.Id, packet.Timestamp, "decode_incomplete", "warning", ex.Message, [], evidenceId + "_decode");
        }
        store.Put(observation, flow.Record);
    }

    private void DecodeStream(Flow flow, Direction direction, DateTimeOffset time, string evidence, bool closed)
    {
        var data = direction.Buffer.ToArray();
        if (data.Length == 0) return;
        if (data.Length >= 5 && data[0] == 23 && data[1] == 3 && data[2] <= 4)
        {
            flow.Record = flow.Record with { Encrypted = true };
            Event(flow.Record.Id, time, "tls", "info", "TLS application-data record observed without a decoded handshake.", new() { ["decryption"] = "unavailable" }, evidence + "_tls");
            direction.Disabled = true; direction.Buffer.SetLength(0); return;
        }
        if (data[0] == 22 && data.Length >= 3 && data[1] == 3)
        {
            flow.Record = flow.Record with { Encrypted = true };
            var tls = TlsDecoder.ClientHello(data);
            if (tls != null) { Event(flow.Record.Id, time, "tls", "info", "TLS handshake metadata; application payload is encrypted.", tls, evidence + "_tls"); direction.Disabled = true; direction.Buffer.SetLength(0); }
            return;
        }
        if (data.Length < 8 && !closed) return;
        if (!Http1Decoder.LooksLikeHttp(data)) { direction.Disabled = true; direction.Buffer.SetLength(0); return; }
        flow.Record = flow.Record with { Encrypted = false };
        while (data.Length > 0)
        {
            bool isHead = flow.Requests.TryPeek(out var pending) && pending.Method == "HEAD";
            var message = Http1Decoder.TryRead(data, options.MaxStreamBytes, closed, isHead);
            if (message == null) break;
            if (message.Status == null)
            {
                if (flow.Requests.Count >= 128) throw new InvalidDataException("Outstanding HTTP request limit exceeded.");
                string target = message.Target;
                if (target.StartsWith('/') && message.Headers.TryGetValue("host", out var host)) target = "http://" + host + target;
                var exchange = new ExchangeRecord("http_" + evidence + "_" + flow.Requests.Count, flow.Record.Id, "http", message.Method, Privacy.Target(target), null, time, null,
                    Privacy.Headers(message.Headers), [], Http1Decoder.BodyPreview(message.Body, message.Headers, request.RetainPayloads, options.MaxBodyBytes), null, "awaiting_response", [.. direction.Evidence]);
                flow.Requests.Enqueue(exchange); store.Put(observation, exchange);
            }
            else if (message.Status is >= 100 and < 200 && message.Status != 101) { /* Interim responses do not consume a request. */ }
            else if (flow.Requests.TryDequeue(out var exchange))
            {
                store.Put(observation, exchange with
                {
                    StatusCode = message.Status,
                    DurationMs = Math.Max(0, (time - exchange.StartedAt).TotalMilliseconds),
                    ResponseHeaders = Privacy.Headers(message.Headers),
                    ResponseBody = Http1Decoder.BodyPreview(message.Body, message.Headers, request.RetainPayloads, options.MaxBodyBytes),
                    Completeness = "complete",
                    EvidenceIds = [.. exchange.EvidenceIds, .. direction.Evidence]
                });
            }
            else Event(flow.Record.Id, time, "unmatched_http_response", "warning", "HTTP response has no observed request.", new() { ["status"] = message.Status.ToString()! }, evidence + "_unmatched");
            data = data[message.Consumed..];
            direction.Evidence.Clear();
            if (data.Length > 0) direction.Evidence.Add(evidence);
            if (message.Status == 101) { direction.Disabled = true; data = []; break; }
        }
        direction.Buffer.SetLength(0); direction.Buffer.Write(data);
    }

    public void Finish()
    {
        foreach (var flow in _flows.Values) FinishFlow(flow);
    }

    private void FinishFlow(Flow flow)
    {
        foreach (var direction in new[] { flow.Forward, flow.Reverse })
        {
            if (direction.Tcp.HasGap || (!direction.Disabled && direction.Buffer.Length > 0))
                Event(flow.Record.Id, flow.Record.LastSeen, "incomplete_stream", "warning", "Observation ended with missing or undecoded stream bytes.", [], "end_" + Guid.NewGuid().ToString("N"));
            direction.Buffer.Dispose();
        }
        foreach (var exchange in flow.Requests) store.Put(observation, exchange with { Completeness = "response_not_observed" });
    }

    private void Event(string? connection, DateTimeOffset timestamp, string kind, string severity, string summary, Dictionary<string, string> fields, string id) =>
        store.Put(observation, new EvidenceRecord(id, connection, timestamp, kind, severity, summary, fields));
}
