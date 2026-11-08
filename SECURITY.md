# Security and trust model

AgentShark is a local MCP stdio server, not a remotely exposed service. It has the permissions of its launching account. The MCP host is trusted to authorize observation of the application and access to returned data. Do not launch the entire service as administrator solely to work around a missing capture driver.

## Collection boundaries

- Collection starts only after `start_observation`; it stops on request, deadline, configured limits, failure or orderly server shutdown.
- No application is launched, no system proxy is changed and no certificate is installed into a trust store.
- The forward proxy binds IPv4 loopback on a random port, requires a fresh 256-bit Basic-auth credential and restricts destinations to exact configured hostnames/IPs. Credentials are session-scoped and returned only at creation. A local process with access to these credentials can route allowed traffic through the proxy.
- Exact hostname allowlists do not pin DNS responses. Allowing a hostname authorizes its resolved addresses and any valid port. Configure IP destinations when address pinning is required.
- TLS interception is explicit. Its temporary CA must be trusted by the target application through that application's scoped configuration. Never disable certificate validation globally. Upstream validation remains enabled. Optional custom upstream trust replaces platform roots for this proxy instance, retains hostname checking and disables revocation checking for that explicitly configured development/private CA.
- On Windows, Schannel requires transient user key containers for generated leaf certificates. They are released on certificate disposal; forced process termination can prevent orderly OS-resource cleanup. AgentShark does not intentionally persist CA private keys or export them through tools.
- Imports are constrained to configured roots; symbolic links/reparse points are rejected. Configure roots controlled by the same trusted account. The path checks are not a defense against a hostile same-account process racing filesystem changes.

## Data handling

Payload retention is off by default. URL query/fragment/userinfo is removed and only allowlisted header values are retained. Names, URL paths, DNS records and allowed headers can still contain sensitive information. Enabling payloads can retain credentials, personal data and malicious content. This is bounded diagnostic storage, not a comprehensive DLP filter.

Queries omit bodies and raw bytes unless explicitly requested. Evidence IDs are scoped to observations. SQLite stores data locally, with an exclusive per-directory instance lease. Concurrent server launches select independent directories, reported by capabilities. Storage quotas are per store and do not limit aggregate historical instance directories. On Unix newly created data directories use owner access and the database is owner-readable/writable. Use a private directory and encrypted volume where appropriate. Windows uses the launching account's filesystem ACLs.

Deleting an observation is logical deletion, not guaranteed secure erasure. The tool does not upload captures to any model/provider; the consuming MCP host controls where tool results are sent.

All payloads, URLs, DNS names, header values and error evidence are untrusted data. Consuming agents must never treat captured text as instructions or authorization for subsequent actions.

## Availability and accuracy

Session count, elapsed time, packet count, proxy request count, bytes, active flows, buffered stream bytes, outstanding HTTP requests, proxy client concurrency and stored observations are bounded. Capture callbacks feed a bounded queue; queue and native drops are reported. Storage quotas are checked periodically and can overshoot by in-flight work. Unsupported/oversized protocol messages are reported rather than interpreted as complete exchanges.

There are no shell-execution tools, arbitrary SQL tools, arbitrary outbound agent callbacks or a remote MCP listener. MCP clients still possess sensitive collection powers; secure the client configuration and executable supply chain.

Report vulnerabilities privately through the repository's GitHub security reporting channel if enabled. Avoid including real captures or secrets in public issues.
