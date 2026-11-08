# AgentShark

**Application network debugging for AI agents.**

AgentShark is a headless .NET 10 MCP server. An agent can observe traffic, reproduce a failure using its existing application tools, query connections and HTTP exchanges, and retrieve the evidence supporting its diagnosis. It runs without a user interface, interactive command interface or embedded AI model.

## Install a release

Download the matching Windows installer, macOS package, Linux package/archive or Claude Desktop extension from [GitHub Releases](https://github.com/vornet/agent-shark/releases). Native packages are self-contained and automatically connect detected Codex, Claude Desktop, Claude Code, Cursor, VS Code and existing Windsurf profiles. Client trust prompts and restart requirements still apply.

Setup preserves unrelated settings, makes configuration backups and avoids replacing user-modified entries. See [installation and client integration](docs/installation.md) for platform behavior, checksums, uninstall instructions, signing status and supported configuration layouts.

## What is implemented

- **Live capture:** Npcap on Windows and libpcap on Linux/macOS, interface discovery, BPF filters, capture-loss reporting and best-effort Windows process selection.
- **Capture-file analysis:** managed PCAP/PCAPNG reading, independent of a native capture installation.
- **Application observation:** authenticated loopback HTTP proxy, encrypted CONNECT tunnels and opt-in HTTPS interception with a per-session CA.
- **Local analysis:** Ethernet/VLAN, loopback/raw/cooked link formats, IPv4/IPv6, TCP sequence reconstruction, ICMP errors/MTU, UDP DNS questions/answers, HTTP/1 exchanges and TLS ClientHello metadata.
- **Evidence:** durable SQLite storage, bounded paginated queries, evidence references, explicit incomplete states, comparison counts and deletion.
- **Operational controls:** deadlines, collection budgets, concurrency limits, private-data defaults, interrupted-session recovery and orderly shutdown.

HTTP/2, HTTP/3, gRPC decoding, WebSocket frame analysis, passive TLS decryption, IP fragment reassembly and authoritative cross-platform process attribution are not implemented. The server reports its actual capabilities and limitations through `get_capabilities`. A successful build does not establish production suitability for every workload; validate capture privileges, application compatibility, load and data handling in the target environment.

## Connect an agent

Build/publish the server with the .NET 10 SDK:

```sh
dotnet publish src/AgentShark.Server -c Release -o artifacts/server
```

Configure your MCP host to launch the published server using **stdio**. For example, on Windows:

```json
{
  "mcpServers": {
    "agent-shark": {
      "command": "dotnet",
      "args": ["E:/dev/agent-shark/artifacts/server/AgentShark.Server.dll"],
      "env": {
        "AGENTSHARK_DATA_DIRECTORY": "E:/dev/agent-shark/.agent-shark",
        "AGENTSHARK_IMPORT_ROOTS": "E:/captures"
      }
    }
  }
}
```

Use equivalent absolute paths on Linux/macOS. The executable speaks MCP on stdin/stdout; startup and diagnostic logs go to stderr. It does not present a human command interface. Concurrent launches sharing an evidence root select isolated instance directories automatically; capabilities report the actual evidence directory.

`dotnet pack src/AgentShark.Server -c Release -o artifacts/packages` produces a local `AgentShark.Mcp` .NET tool package whose executable name is `agent-shark`. GitHub tag releases produce native installers and extension bundles. Workflow-dispatch packaging verifies artifacts without publishing. NuGet publication is separate and is not automatic.

## Agent workflow

1. Call `get_capabilities` to discover interfaces and visibility limits.
2. Call `start_observation` with an explicit mode and bounded scope.
3. Reproduce the application operation using the agent's existing tools.
4. Query connections, exchanges and diagnostic events; retrieve supporting evidence.
5. Stop the observation to finalize evidence, then repeat queries from the first page.
6. Compare reproductions when useful and delete observations when no longer needed.

### Passive collection

Example arguments to `start_observation`:

```json
{
  "request": {
    "mode": "capture",
    "interfaceId": "<ID returned by get_capabilities>",
    "captureFilter": "tcp port 8080 or udp port 53",
    "durationSeconds": 60,
    "maxPackets": 100000,
    "maxBytes": 67108864,
    "retainPayloads": false
  }
}
```

Optional `processId` selects packets matching Windows socket ownership snapshots. This can miss short-lived connections and is explicitly best-effort. Interface/filter capture is available on all supported platforms.

### HTTP/HTTPS observation

```json
{
  "request": {
    "mode": "proxy",
    "allowedHosts": ["api.example.test", "localhost"],
    "durationSeconds": 120,
    "maxProxyRequests": 1000,
    "interceptTls": true,
    "retainPayloads": false
  }
}
```

The result contains `proxy.url`, `proxy.username`, `proxy.password` and, if TLS interception is enabled, `proxy.caCertificatePem`. Configure **only the target application's** proxy and certificate trust using these values. AgentShark never edits system proxy settings or installs certificates. Credentials and CA are session-scoped; stopping the observation closes the proxy. Certificate-pinned or HTTP/2-only clients may not be compatible.

Without TLS interception, CONNECT relays encrypted bytes and records tunnel metadata; it does not produce decrypted HTTP exchanges. The observing proxy deliberately closes each HTTP/1 connection after an exchange, which can affect pooling and timing. Passive capture is preferable when transport fidelity is required.

### Import existing captures

Configure `AGENTSHARK_IMPORT_ROOTS`, then call:

```json
{
  "request": {
    "mode": "import",
    "importPath": "E:/captures/reproduction.pcapng",
    "maxBytes": 67108864
  }
}
```

Imports run asynchronously. Poll `get_observation_status` until terminal. Input files are never modified. Import roots use the platform path-list separator: semicolon on Windows, colon on Unix. Imports are disabled when no roots are configured, and paths containing symbolic links/reparse points are rejected.

## Tool surface

| Tool | Result |
| --- | --- |
| `get_capabilities` | Available interfaces, modes, protocols and limitations |
| `start_observation` | Ready observation and optional proxy configuration |
| `get_observation_status` | Lifecycle, counters, loss and stop reason |
| `list_observations` | Retained sessions |
| `stop_observation` | Finalized status |
| `query_connections` | Endpoints, timing, attribution and evidence IDs |
| `query_exchanges` | HTTP requests, responses, status, timing and completeness |
| `query_events` | Packet metadata and diagnostic events |
| `get_evidence` | A specific evidence record and optional retained packet prefix |
| `compare_observations` | Grouped event/protocol/status count differences |
| `delete_observation` | Logical deletion of a terminal session and its records |

Queries accept `query.after`, `query.limit` (1–200), `query.connectionId` and applicable protocol/severity/status filters. Pass `nextCursor` as `after` for the next page. Live pagination is not a change feed: updates keep their original sequence, so repeat queries after finalization. Exchange pages requesting bodies are capped at 20 items.

Header values use an allowlist; URL query, fragment and userinfo are removed. Payload storage is off by default. Body queries additionally require `includePayloads=true`; raw evidence requires `includePayload=true`. Retained payloads can contain secrets. All captured content is untrusted data, never agent instructions.

## Platform requirements

| Platform | Runtime | Live capture |
| --- | --- | --- |
| Windows 11 | .NET 10, or a self-contained build | Separately installed Npcap, with account capture access |
| Linux | .NET 10, or a self-contained build | libpcap and appropriate capture permissions |
| macOS | .NET 10, or a self-contained build | libpcap and access to BPF devices |

Import and proxy modes do not require a capture driver. AgentShark does not bundle Npcap or install privileged helpers. Production container images run as a non-root user; container capture additionally depends on network namespace, native access and capabilities. Do not assume a container observes host traffic.

## Configuration

| Environment variable | Meaning |
| --- | --- |
| `AGENTSHARK_DATA_DIRECTORY` | Dedicated local evidence directory; defaults to the platform local application-data directory under `AgentShark` |
| `AGENTSHARK_IMPORT_ROOTS` | Allowed capture-file root directories; empty disables imports |
| `AGENTSHARK_UPSTREAM_CA_FILE` | Optional PEM private/development CA for upstream HTTPS; replaces platform trust roots for proxy requests while retaining hostname checks |

Default engine budgets are documented in [architecture](docs/architecture.md). Per-observation limits are configurable through `start_observation`. The temporary certificate authority never modifies system trust. Windows TLS uses transient OS-managed key containers for leaf certificates; normal disposal releases them.

## Development and verification

```sh
dotnet restore --locked-mode
dotnet format --no-restore --verify-no-changes
dotnet test -c Release --no-restore
dotnet pack src/AgentShark.Server -c Release --no-restore -o artifacts/packages
```

The suite uses generated traffic, including real localhost HTTP/TLS origins. It covers malformed input, framing ambiguity, reordering, privacy, budgets, persistence, concurrent lifecycle calls and a real MCP stdio client. No real-network captures are committed.

The native capture integration test is opt-in through `AGENTSHARK_TEST_NATIVE=1`, requires loopback capture access and captures only synthetic localhost traffic on an ephemeral test port. To run the full Linux suite in an isolated container:

```sh
docker build --target test -t agent-shark-tests .
docker run --rm --cap-add NET_RAW agent-shark-tests
```

CI verifies portable behavior on Windows, Linux and macOS, and runs native loopback capture in Linux. Repository workflows must actually run before treating their target platforms as validated.

Read the [architecture](docs/architecture.md), [security model](SECURITY.md) and [third-party notices](THIRD-PARTY-NOTICES.md) before deploying. AgentShark source is [MIT licensed](LICENSE).
