# Third-party components

AgentShark source is MIT licensed. Its dependencies retain their own licenses.
The exact dependency graph and versions are recorded in each project's `packages.lock.json`.

| Component | License | Project |
| --- | --- | --- |
| MCP C# SDK | Apache-2.0 | https://github.com/modelcontextprotocol/csharp-sdk |
| SharpPcap | MIT | https://github.com/dotpcap/sharppcap |
| PacketDotNet (transitive through SharpPcap) | MPL-2.0 | https://github.com/dotpcap/packetnet |
| Microsoft .NET libraries and Microsoft.Data.Sqlite | MIT | https://github.com/dotnet |
| SQLitePCLRaw | Apache-2.0 | https://github.com/ericsink/SQLitePCL.raw |
| SQLite | Public domain | https://sqlite.org/copyright.html |
| Tomlyn (setup utility) | BSD-2-Clause | https://github.com/xoofx/Tomlyn |
| xUnit, test SDK, test adapters and coverage collector | See their package licenses | Development/test dependencies only |

No PacketDotNet source files are modified by this project. Package license metadata is retained in the dependency packages. Review the package graph and upstream license texts when redistributing a release.

Npcap is an optional, separately installed Windows capture dependency. AgentShark does not bundle its driver or installer. Npcap's usage and redistribution terms are separate: https://npcap.com/oem/.
Linux/macOS live capture uses the platform's libpcap installation, under its upstream license.
