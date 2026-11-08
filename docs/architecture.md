# Architecture

AgentShark is a headless .NET 10 network-observation engine with an MCP stdio adapter. It has no interactive command interface, review UI or embedded model. Deterministic local analysis supplies evidence; the consuming agent investigates and explains it.

## Projects

- `AgentShark.Core`: managed capture-file parsing, native capture adapter, protocol analysis, socket correlation, authenticated forward proxy, observation lifecycle and SQLite evidence storage.
- `AgentShark.Server`: official C# MCP SDK host and eleven typed tools. Protocol messages exclusively use stdout; diagnostics use stderr.
- `AgentShark.Tests`: generated traffic, adversarial parser inputs, persistence/privacy/lifecycle checks, real HTTP/TLS proxy sessions, actual stdio MCP-client interoperation and optional isolated native loopback capture.

## Lifecycle

`start_observation` validates scope and limits, acquires a concurrency slot, initializes the selected backend and returns only once capture/proxy is ready. Import analysis runs asynchronously. Session cancellation belongs to the engine, not the lifetime of the initiating MCP request. Initialization itself observes the caller's cancellation token.

Running observations produce provisional records. Stop waits for backend shutdown and analysis finalization. Finished sessions remain queryable after restart when the same directory is selected. A restarted exclusive store marks previously running sessions interrupted. One process owns each data directory; concurrent server launches select isolated `instances/<id>` directories when the configured root is already in use. Capabilities report the actual directory. Histories and storage quotas are per store, not machine-wide.

## Capture and decoding

Live capture uses SharpPcap with a 1,024-packet bounded callback queue, 65,535-byte snapshot length and a supplied BPF filter. It does not enable promiscuous mode. Import reading uses managed code and does not require native capture libraries. PCAP byte orders and microsecond/nanosecond timestamps are supported. PCAPNG supports section byte-order changes, multiple interface definitions, timestamp resolution/offset and enhanced packet blocks. Timestamp-less/deprecated packet blocks are rejected; unknown nonpacket metadata blocks are skipped.

Supported link formats: Ethernet with bounded VLAN nesting, BSD/null loopback, raw IP, Linux cooked v1/v2. IPv4 and IPv6 extension headers are validated with bounded nesting. IP fragments and jumbograms are reported unsupported. Checksums are not used to reject packets because local capture may occur before checksum offload completion.

Each bidirectional TCP flow owns independent sequence reassemblers and application buffers. New opening SYNs distinguish connection generations when observed; captures beginning midstream cannot always distinguish tuple reuse. Out-of-order segments are buffered within limits, retransmitted prefixes suppressed and sequence wraparound handled. Ambiguous overlaps and loss can affect reconstruction; diagnostics do not establish which bytes a remote application accepted. Flows are not evicted silently when limits are reached.

HTTP/1 exchanges use bounded framing, reject conflicting content-length/transfer-encoding, support chunked messages and match responses to queued requests. Interim responses do not consume requests. Request/response evidence lists retain up to 64 contributing packet references per direction; pipelined messages may share a packet reference. Messages spanning more packets can have partial reference lists. End-of-observation alone does not prove a close-delimited response completed. FIN/RST is required to complete an unframed captured response. Protocol upgrades end HTTP decoding.

DNS over UDP exposes question, response-code, truncation and selected answer metadata with bounded name decompression. ICMP/ICMPv6 expose type, code and relevant MTU/error information. Process-filtered sessions can exclude ICMP because socket tables do not attribute those packets to application owners. TLS decoding exposes single-record ClientHello metadata when available; encrypted records are never represented as plaintext requests. Fragmented TLS handshakes can yield limited metadata. The connection encryption field is null when unknown, rather than asserting plaintext.

## Explicit proxy

The proxy uses a per-observation listener, credential, exact destination allowlist, connection limit and deadline. Each connection handles one HTTP exchange and closes. HTTP/1 request bodies are bounded to the stream limit; responses are relayed incrementally and previews are bounded. The tool does not promise transparent application behavior: connection closure, HTTP/1 selection and buffering can alter timing and pooling. Use passive capture when transport fidelity matters.

CONNECT either relays an encrypted tunnel or, if explicitly enabled, terminates TLS with a scoped generated certificate and forwards HTTP/1 upstream with certificate verification. HTTP/2-only clients, gRPC, WebSocket relay, client-certificate forwarding and certificate-pinned applications are outside this implementation's proxy support. `Expect` requests are rejected rather than risking an upload deadlock. Encoded/binary bodies are not decoded into text previews.

## Persistence and queries

SQLite WAL mode stores observation snapshots and typed evidence, connection and exchange records. Writes are batched in transactions of up to 128 records, with a 100 ms elapsed threshold checked on subsequent writes. Queries on the owning connection can see the pending batch. Metadata snapshots, session finalization, deletion and orderly disposal flush pending writes. An abrupt process failure can lose the last uncommitted batch, and interrupted-session counters are approximate. Parameterized queries have a stable sequence cursor and bounded pages. Updates preserve their insertion sequence, so live pagination is not a change feed: repeat from the beginning after completion. Comparisons report grouped counts, not causal diagnoses or rate-normalized differences.

Default limits: 4 active observations, 100 retained observations, 2 GiB storage, 4,096 active flows per session, 256 KiB per stream/message, 16 KiB payload previews and 16 concurrent proxy clients. Sessions default to 60 seconds, 100,000 packets, 10,000 proxy requests and 64 MiB collected bytes. In proxy mode packet counters remain zero; `proxyRequests` counts forwarded exchanges/tunnels. Proxy byte counters count received HTTP request bytes and relayed response bytes or bidirectional tunnel bytes, not link-layer bytes.
