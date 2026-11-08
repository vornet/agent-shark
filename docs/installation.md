# Installation and client integration

Release installers are self-contained: no .NET SDK/runtime installation is required. Download an artifact for the machine's operating system and architecture from the repository's GitHub Releases page. Compare its SHA-256 digest with `SHA256SUMS.txt` or its adjacent `.sha256` file.

## Native packages

Windows `-setup.exe` installs per user under `%LOCALAPPDATA%\Programs\AgentShark`. The default checked task connects detected profiles. Standard uninstall removes unchanged managed MCP entries and installed program files; evidence and configuration backups remain. Npcap is not bundled. Proxy and import modes work without it.

macOS `.pkg` installs under `/usr/local/lib/agent-shark`. Its postinstall runs client setup as the active desktop user, never as root. With no active desktop user, registration is deferred. To remove the system installation, use its `uninstall.sh` with system-install permissions; stored evidence/backups remain.

Linux `.deb` installs under `/opt/agent-shark`. An installation invoked through sudo can configure the invoking desktop user; root/headless installation defers integration. Use the distribution package manager for removal. Portable `.tar.gz` archives include `install.sh` for per-user setup without sudo, and an uninstall script in the installed directory.

The native installers are unsigned/unnotarized. SHA-256 checksums and GitHub provenance do not replace an OS publisher certificate. Organization-managed clients may disallow local servers regardless of installation success.

## Client configuration

The setup utility discovers existing profile directories, adds only `agent-shark`, makes backups before edits and records ownership fingerprints. It preserves unrelated JSON/TOML properties and comments. Invalid configuration, symlinked paths, preexisting unmanaged entries and user-modified managed entries are left unchanged and reported. Uninstallation removes an entry only if it still matches its recorded fingerprint. Backups can contain secrets from other client configuration: they stay in the user's private setup directory.

| Client ID | Configuration |
| --- | --- |
| `codex` | `$CODEX_HOME/config.toml`, otherwise `~/.codex/config.toml` |
| `claude-desktop` | Platform application-data `Claude/claude_desktop_config.json` |
| `claude-code` | `~/.claude.json`, user-level `mcpServers` |
| `cursor` | `~/.cursor/mcp.json` |
| `vscode` | Platform application-data `Code/User/mcp.json`, default profile `servers` |
| `windsurf` | Existing `~/.codeium/windsurf/mcp_config.json` profiles |

These target documented local configuration formats. Registration does not bypass client restart, server trust, account eligibility or administrator restrictions. Separate VS Code named profiles, portable application configurations, remote/SSH hosts and future renamed client formats may need explicit configuration. Windsurf support targets the existing profile layout rather than assuming compatibility with successor products.

The installed `setup/AgentShark.Setup` executable (`.exe` on Windows) supports:

```text
detect
integrate --clients detected
integrate --clients codex,claude-desktop,cursor --dry-run
integrate --clients all
remove --clients all
```

The default sibling `server/AgentShark.Server` executable is used; `--server` can select another absolute executable path. `--home` selects an isolated profile home for testing or deliberate profile management. Native packages run integration automatically for detected profiles. Close/restart clients around configuration changes to avoid competing writes. Review `last-report.json` and backups in the platform local-data `AgentShark/setup` directory for conflicts.

Each configured client type receives an independent evidence root. If multiple server processes of the same client run concurrently, additional processes select unique `instances/<id>` evidence directories; `get_capabilities.evidenceDirectory` reports the actual directory. Evidence history and storage limits apply per directory, not across every running client instance. Concurrent-instance directories are retained for explicit later examination/removal; there is no machine-wide automatic retention sweep.

Claude Desktop `.mcpb` bundles provide an alternative native extension flow, with a default app-specific evidence directory. Match the asset architecture and use either the extension or JSON registration for the same Claude Desktop profile. Client extension trust prompts are expected.

## Format references

- [Codex MCP configuration](https://developers.openai.com/codex/mcp/)
- [Local Claude Desktop MCP configuration](https://modelcontextprotocol.io/docs/develop/connect-local-servers)
- [Claude Desktop extensions](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop)
- [Claude Code MCP scopes](https://code.claude.com/docs/en/mcp)
- [Cursor global MCP configuration](https://prod.cursor.com/help/customization/mcp)
- [VS Code MCP configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)
- [Windsurf profile configuration](https://learn.microsoft.com/en-us/azure/developer/azure-mcp-server/get-started/tools/windsurf)

## Release engineering

`scripts/package.py` builds native packages and extension bundles for six runtime identifiers. `scripts/smoke-release.py` verifies self-contained startup, isolated client integration/idempotence/removal and a real MCP session. Windows additionally exercises its actual installer/uninstaller; release jobs install and test macOS/Debian packages on their matching runners. Windows ARM64 is cross-built on x64 and is not execution-smoked there.

Tag-triggered GitHub Actions require source version/tag agreement, all matrix tests and package checks, checksum verification and provenance generation before publishing. Workflow-dispatch builds verify packages without publishing. Release publishing credentials come only from the workflow's scoped GitHub token. OS vendor signing/notarization credentials are not configured for this release.
